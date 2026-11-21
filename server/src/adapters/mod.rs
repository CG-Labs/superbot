//! The only contract between the server and a harness (Claude Code, Codex, Pi, Hermes).
//! Each adapter builds a command line (with the files it needs and how to stop what it
//! leaves running) and maps the harness's JSON lines to `AgentEvent`s. The command
//! runs here or on the Bot owner's machine (`machines::job`, ADR 0036); either way the
//! lines come back here, so adapters never run anywhere but botd.

mod claude;
mod codex;
mod hermes;
mod pi;
pub mod install;
pub mod version;

use crate::machines::job;
use crate::machines::wire::{JobCleanup, JobEvent, JobFile, JobRequest};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::sync::{mpsc, watch};

pub enum AgentEvent {
    /// Harness session to resume next time.
    Session(String),
    /// Streaming piece of the current text block.
    TextDelta(String),
    /// A finished text block: one chat bubble.
    Text(String),
    /// The agent started using a tool.
    Tool { name: String, detail: String },
    /// A tool call finished without an error, so the harness really ran it. A call the
    /// harness rejects before its hook (bad arguments, an unknown name) ends in an error.
    ToolRan { name: String },
    Error(String),
    /// Model tokens the harness says it used (ADR 0050). A run may report several, one
    /// per model or turn; the runner adds them up. A harness that says nothing: unknown.
    Usage(Usage),
}

/// Tokens one model used, as Anthropic and Hermes count them: `input` is the prompt
/// tokens not read from or written to the cache, so all four add up to the total.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// As the harness named it. None: it didn't say.
    pub model: Option<String>,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.input.saturating_add(self.output).saturating_add(self.cache_read).saturating_add(self.cache_write)
    }

    /// A count from harness JSON: a whole number of tokens, else 0.
    pub fn count(v: &Value) -> u64 {
        v.as_u64().unwrap_or(0)
    }
}

pub struct RunInput {
    pub prompt: String,
    /// Bot identity, rules, and memory. Rebuilt every run.
    pub system: String,
    /// None = start a new harness session.
    pub session_id: Option<String>,
    pub cwd: PathBuf,
    /// The model provider, for harnesses that take one (`supports_provider`).
    pub provider: Option<String>,
    /// The tiers file's endpoints that `provider` and `fallback` name (ADR 0076). Their
    /// keys are in `env`, but reach the harness only through the adapter's `env`.
    pub endpoints: Vec<crate::tiers::Endpoint>,
    /// What to try, in order, when the provider fails. None: the harness's own
    /// settings. Some: exactly these, and no other provider.
    pub fallback: Option<Vec<crate::tiers::Fallback>>,
    pub model: Option<String>,
    /// Reasoning effort, in the harness's own words (e.g. "high").
    pub effort: Option<String>,
    pub env: HashMap<String, String>,
    /// A private folder for this Bot's harness files, which the run writes.
    pub state_dir: PathBuf,
    /// Where the files the adapter writes go (its settings, the approval gate). The same
    /// as `state_dir`, except with per-user accounts, where the run can't change them.
    pub config_dir: PathBuf,
    /// Set in ask mode: the harness must run `command` before every tool call.
    pub guard: Option<Guard>,
    /// With per-user accounts (ADR 0037): the account the harness runs as on this
    /// server. None: botd's. Runs on the owner's machine never use it.
    pub run_as: Option<crate::accounts::RunAs>,
    /// Set when the policy turns on the harness's own sandbox (ADR 0055) and it can
    /// start where the run happens. Only adapters with `has_sandbox` use it.
    pub sandbox: Option<Sandbox>,
}

/// The harness's own sandbox: its shell commands write only to `cwd`, the temp
/// folders, and `writable`, and keep the network, including botd's API (`BOT_API`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sandbox {
    /// Folders outside `cwd` the run writes to: its memory and facts files' folders and
    /// package caches. Each exists where the run happens.
    pub writable: Vec<PathBuf>,
}

/// `host:port` of botd's API as the run reaches it, for a sandbox that only lets
/// commands reach hosts it is told about.
pub fn api_host(input: &RunInput) -> Option<String> {
    let rest = input.env.get("BOT_API")?.strip_prefix("http://")?.trim_end_matches('/');
    (!rest.is_empty() && !rest.contains(['/', '@', '?', '#'])).then(|| rest.to_string())
}

/// The approval gate, as each adapter installs it in its harness's own hook format.
/// The hook command exits 0 to allow, or 2 with a reason on stderr (and a
/// PreToolUse deny on stdout) to block.
#[derive(Clone)]
pub struct Guard {
    /// Shell command, e.g. `'/usr/local/bin/botctl' hook claude`.
    pub command: String,
    /// Hook timeout for the harness. Longer than `wait`, so a slow answer never fails open.
    pub timeout_secs: u64,
    /// Longest the server lets one approval wait.
    pub wait: std::time::Duration,
}

/// Server secrets the harness (and everything it runs) must not inherit, or a Bot
/// could approve its own actions, read what botd seals, or copy the license key or
/// forge Stripe's webhook or call Stripe's API.
pub(crate) const SECRET_ENV: [&str; 12] = [
    "AUTH_PASSWORD",
    "AUTH_PASSWORD_FILE",
    "SUPERBOT_PASSWORD",
    "SUPERBOT_TOKEN",
    "SUPERBOT_MASTER_KEY",
    "SUPERBOT_MASTER_KEY_FILE",
    "LICENSE_KEY",
    "LICENSE_KEY_FILE",
    "STRIPE_WEBHOOK_SECRET",
    "STRIPE_WEBHOOK_SECRET_FILE",
    "STRIPE_SECRET_KEY",
    "STRIPE_SECRET_KEY_FILE",
];

/// `SECRET_ENV`, `secrets::SERVER_SECRETS` (and their `_FILE`), every `SSO_*` setting:
/// sign-in config, including client secrets (ADR 0014), and each Bot's own notification
/// webhook URL (ADR 0061).
pub(crate) fn secret_env() -> Vec<String> {
    let mut names: Vec<String> = SECRET_ENV.map(String::from).into();
    for k in crate::secrets::SERVER_SECRETS {
        names.extend([k.to_string(), format!("{k}_FILE")]);
    }
    let ours = |k: &String| k.starts_with("SSO_") || k.starts_with(crate::secrets::BOT_WEBHOOK_PREFIX);
    names.extend(std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).filter(ours));
    names
}

pub(crate) fn strip_secret_env(cmd: &mut std::process::Command) {
    for k in secret_env() {
        cmd.env_remove(k);
    }
}

/// How jobs start on this server: botd's environment, without its secrets.
pub fn local_host() -> job::Host {
    job::Host { clear_env: false, remove: secret_env(), env: BTreeMap::new(), user: None }
}

pub trait Adapter: Send + Sync {
    fn bin(&self) -> &'static str;
    /// Command-line arguments. May emit events up front (e.g. a session id it chose).
    fn args(&mut self, input: &RunInput, out: &mut Vec<AgentEvent>) -> Vec<String>;
    /// Map one JSON line from the harness to zero or more events.
    fn on_event(&mut self, e: &Value, out: &mut Vec<AgentEvent>);
    /// Models this harness can run here, with their reasoning efforts. Blocking.
    fn models(&self) -> Vec<ModelOption>;
    /// Whether it uses `RunInput::provider`. Tiers may name a provider only for these.
    fn supports_provider(&self) -> bool {
        false
    }
    /// Whether `error` says the harness won't resume its session with this run's
    /// settings, as when the owner's tier moved the Bot to another route. The run then
    /// starts a fresh session rather than run on the old route.
    fn resume_refused(&self, _error: &str) -> bool {
        false
    }
    /// Environment the harness needs on top of `input.env`.
    fn env(&self, _input: &RunInput) -> Vec<(String, String)> {
        Vec::new()
    }
    /// Text for the harness's stdin. None = no stdin.
    fn stdin(&self, _input: &RunInput) -> Option<String> {
        None
    }
    /// Files the harness needs before it starts (its settings, the approval gate),
    /// written private where the run happens. Paths are inside `input.config_dir`.
    fn files(&self, _input: &RunInput) -> Vec<(PathBuf, String)> {
        Vec::new()
    }
    /// Stops harness processes that outlive the CLI (e.g. a daemon it started), so a
    /// stopped run really stops. Runs before and after every run.
    fn cleanup(&self, _input: &RunInput) -> Option<JobCleanup> {
        None
    }
    /// What to tell the user when `cleanup` failed, and why.
    fn cleanup_failed(&self, _input: &RunInput, why: &str) -> String {
        why.to_string()
    }
    /// The tool name its events use for shell commands.
    fn shell_tool(&self) -> &'static str;
    /// Whether every call of `tool` (as its events name it) that runs went through the
    /// hook first, as tested against the real CLI (ADR 0063). Ask mode stops a run that
    /// runs one without calling the hook (`arms_canary`).
    fn hooks_tool(&self, tool: &str) -> bool {
        tool.eq_ignore_ascii_case(self.shell_tool())
    }
    /// Whether the harness has a sandbox of its own that `RunInput::sandbox` turns on.
    fn has_sandbox(&self) -> bool {
        false
    }
    /// What its sandbox needs from the host beyond user namespaces, of `sandbox::PROGRAMS`.
    fn sandbox_needs(&self) -> &'static [&'static str] {
        &[]
    }
    /// The longest hook timeout the harness accepts, if it caps it.
    fn max_hook_secs(&self) -> Option<u64> {
        None
    }
    /// The oldest release that runs the hook as `args` installs it, as `--version`
    /// names it. A guarded run on an older one (or one whose version can't be read) is
    /// refused before it starts (ADR 0059). None: every release does.
    fn hooks_since(&self) -> Option<&'static str> {
        None
    }
    /// What logs the harness in, run at a terminal as the account its runs use.
    fn login_args(&self) -> Option<&'static [&'static str]> {
        None
    }
    /// How the harness logs in on a user's machine (ADR 0042), if it has a login there.
    fn machine_login(&self) -> Option<MachineLogin> {
        None
    }
}

/// A harness's login on a user's machine: the agent runs `args` in a terminal there,
/// with HOME its Bots' HOME, and checks `files` to tell whether it's logged in.
#[derive(Clone, Copy, Debug)]
pub struct MachineLogin {
    pub args: &'static [&'static str],
    /// Where the login saves its credentials, relative to HOME.
    pub files: &'static [&'static str],
    /// Secrets that make a login unneeded: a run with one of them is never refused.
    pub keys: &'static [&'static str],
}

#[derive(Clone, serde::Serialize)]
pub struct ModelOption {
    /// Empty: the harness takes any model name, typed by the user, with these efforts.
    pub id: String,
    pub label: String,
    /// Efforts this model accepts. Empty = no effort setting.
    pub efforts: Vec<String>,
    /// Other names the harness accepts for this model (e.g. "opus").
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

/// Model lists, cached for 10 minutes per harness (listing can take a second).
pub fn models(name: &str) -> Vec<ModelOption> {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    type Cache = HashMap<String, (Instant, Vec<ModelOption>)>;
    static CACHE: Mutex<Option<Cache>> = Mutex::new(None);
    if let Some((at, list)) = CACHE.lock().unwrap().get_or_insert_default().get(name)
        && at.elapsed() < Duration::from_secs(600)
        && !list.is_empty()
    {
        return list.clone();
    }
    let list = get(name).map(|a| a.models()).unwrap_or_default();
    CACHE.lock().unwrap().get_or_insert_default().insert(name.into(), (Instant::now(), list.clone()));
    list
}

/// Runs a command and returns its stdout, or "" if it fails.
pub fn output(bin: &str, args: &[&str]) -> String {
    std::process::Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// To add a harness: write one adapter file and list it here.
pub const NAMES: [&str; 4] = ["claude", "codex", "pi", "hermes"];

/// Whether `e` shows the harness running a call its hook must have seen first: a shell
/// call starting, or a call of a hooked tool finishing without an error. A guarded run
/// that shows one and never calls the hook isn't enforcing approvals (ADR 0007, 0063).
/// Only calls that ran count: a harness checks a call's arguments before its hook, so
/// a call it rejects (an edit of a file not read yet) never reaches the hook.
pub fn arms_canary(a: &dyn Adapter, e: &AgentEvent) -> bool {
    match e {
        AgentEvent::Tool { name, .. } => name.eq_ignore_ascii_case(a.shell_tool()),
        AgentEvent::ToolRan { name } => a.hooks_tool(name),
        _ => false,
    }
}

pub fn get(name: &str) -> Option<Box<dyn Adapter>> {
    match name {
        "claude" => Some(Box::new(claude::Claude::default())),
        "codex" => Some(Box::new(codex::Codex::default())),
        "pi" => Some(Box::new(pi::Pi)),
        "hermes" => Some(Box::new(hermes::Hermes::default())),
        _ => None,
    }
}

/// Harnesses whose CLI is on PATH. Remembered for a few seconds: views ask for
/// every Bot, and each check starts a shell per harness.
pub fn installed() -> Vec<&'static str> {
    static CACHE: std::sync::Mutex<Option<(std::time::Instant, Vec<&'static str>)>> = std::sync::Mutex::new(None);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, list)) = cache.as_ref().filter(|(at, _)| at.elapsed() < std::time::Duration::from_secs(5)) {
        return list.clone();
    }
    let list = find_installed();
    *cache = Some((std::time::Instant::now(), list.clone()));
    list
}

fn find_installed() -> Vec<&'static str> {
    NAMES
        .into_iter()
        .filter(|n| {
            let bin = get(n).unwrap().bin();
            std::process::Command::new("sh")
                .args(["-c", &format!("command -v {bin}")])
                .stdout(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
        .collect()
}

/// Why a run was cut short.
pub type AbortReason = Option<&'static str>;

/// Resolves once `abort` fires; never if its sender is gone without firing.
pub async fn aborted(mut abort: watch::Receiver<AbortReason>) {
    if abort.wait_for(|r| r.is_some()).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// The command for one run: what the adapter asks for, with no ids yet. Paths are as
/// `input` names them. Events the adapter emits up front go to `out`.
pub fn job_for(adapter: &mut dyn Adapter, input: &RunInput, out: &mut Vec<AgentEvent>) -> JobRequest {
    let args = adapter.args(input, out);
    let mut env: BTreeMap<String, String> = input.env.clone().into_iter().collect();
    // A tier endpoint's key reaches the harness only as its adapter hands it over (ADR 0076).
    for e in &input.endpoints {
        env.remove(&e.key_secret);
    }
    env.extend(adapter.env(input));
    let path = |p: &std::path::Path| p.display().to_string();
    JobRequest {
        protocol: crate::machines::wire::PROTOCOL,
        job_id: String::new(),
        bot_id: String::new(),
        owner_id: String::new(),
        for_user: None,
        message_id: 0,
        bin: adapter.bin().into(),
        args,
        env,
        cwd: path(&input.cwd),
        stdin: adapter.stdin(input),
        files: adapter.files(input).into_iter().map(|(p, body)| JobFile { path: path(&p), body }).collect(),
        cleanup: adapter.cleanup(input),
        collect: Vec::new(),
    }
}

/// Runs the harness on this server, calling `emit` for every event, until it exits or
/// `abort` fires. With `input.run_as`, it starts as that account.
pub async fn run(adapter: Box<dyn Adapter>, input: RunInput, abort: watch::Receiver<AbortReason>, emit: impl FnMut(AgentEvent)) {
    let host = local_host();
    let stop = abort.clone();
    let run_as = input.run_as.clone();
    run_on(adapter, input, abort, emit, |job, tx| async move {
        let job = match &run_as {
            Some(r) => match r.prepare(job) {
                Ok(job) => job,
                Err(message) => {
                    let _ = tx.send(JobEvent::Error { message }).await;
                    return;
                }
            },
            None => job,
        };
        job::run(&host, &job, aborted(stop), &tx).await
    })
    .await
}

/// Runs the harness wherever `exec` runs a job, and turns what comes back into events.
/// `exec` sends the job's events to its sender and returns when the job is over.
pub async fn run_on<F, Fut>(mut adapter: Box<dyn Adapter>, input: RunInput, abort: watch::Receiver<AbortReason>, mut emit: impl FnMut(AgentEvent), exec: F)
where
    F: FnOnce(JobRequest, mpsc::Sender<JobEvent>) -> Fut,
    Fut: Future<Output = ()>,
{
    let mut out = Vec::new();
    let job = job_for(adapter.as_mut(), &input, &mut out);
    // An adapter that couldn't set up must not run.
    let failed = out.iter().any(|e| matches!(e, AgentEvent::Error(_)));
    out.drain(..).for_each(&mut emit);
    if failed {
        return;
    }
    let bin = job.bin.clone();
    let (tx, mut rx) = mpsc::channel(256);
    let consume = async {
        let mut saw_error = false;
        while let Some(ev) = rx.recv().await {
            match ev {
                JobEvent::Line { line } => {
                    let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
                    adapter.on_event(&v, &mut out);
                    for e in out.drain(..) {
                        saw_error |= matches!(e, AgentEvent::Error(_));
                        emit(e);
                    }
                }
                JobEvent::Cleanup { why } => emit(AgentEvent::Error(adapter.cleanup_failed(&input, &why))),
                JobEvent::Error { message } => {
                    saw_error = true;
                    emit(AgentEvent::Error(message));
                }
                JobEvent::Exit { success, status, stderr, .. } => {
                    if !success && !saw_error && abort.borrow().is_none() {
                        emit(AgentEvent::Error(if stderr.is_empty() { format!("{bin} exited with {status}") } else { stderr }));
                    }
                }
                JobEvent::Started | JobEvent::Ping => {}
            }
        }
    };
    tokio::join!(exec(job, tx), consume);
}

/// Runs the adapter's cleanup here now, as a run would before it starts.
#[cfg(test)]
pub async fn stop_leftovers(adapter: &dyn Adapter, input: &RunInput) -> Result<(), String> {
    match adapter.cleanup(input) {
        None => Ok(()),
        Some(c) => job::cleanup(&local_host(), &c).await.map_err(|why| adapter.cleanup_failed(input, &why)),
    }
}

/// One short line describing a tool call, for the "working" status.
pub fn describe(input: &Value) -> String {
    let v = ["command", "cmd", "file_path", "path", "url", "query", "pattern", "description"]
        .iter()
        .find_map(|k| input.get(*k));
    let s = match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" "),
        _ => String::new(),
    };
    short(&s)
}

pub fn short(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(120).collect()
}

pub fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

pub fn new_uuid() -> String {
    let mut b = crate::random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(dir: &std::path::Path, run_as: Option<crate::accounts::RunAs>) -> RunInput {
        RunInput {
            prompt: "hi".into(),
            system: "You are Ada.".into(),
            session_id: None,
            cwd: dir.to_path_buf(),
            provider: None,
            endpoints: Vec::new(),
            fallback: None,
            model: None,
            effort: None,
            env: HashMap::from([("PATH".into(), "/opt/superbot/bin:/usr/bin:/bin".into())]),
            state_dir: dir.join("state"),
            config_dir: dir.join("state"),
            guard: Some(Guard { command: "'/opt/bin/botctl' hook x".into(), timeout_secs: 300, wait: std::time::Duration::from_secs(240) }),
            run_as,
            sandbox: None,
        }
    }

    fn run_as(sudo: &str) -> crate::accounts::RunAs {
        crate::accounts::RunAs { sudo: sudo.into(), runner: "/opt/superbot/bin/superbot-run".into(), account: "sb-u-u1".into(), settings: "/srv/superbot/users/u1/settings".into(), teammate: None }
    }

    #[test]
    fn harness_files_go_only_where_botd_keeps_them() {
        // With per-user accounts that's a folder the run reads and can't change.
        let dir = std::env::temp_dir();
        let mut i = input(&dir, None);
        i.config_dir = dir.join("settings/b1");
        let mut wrote = Vec::new();
        for name in crate::accounts::HARNESSES {
            let job = job_for(get(name).unwrap().as_mut(), &i, &mut Vec::new());
            for f in &job.files {
                assert!(std::path::Path::new(&f.path).starts_with(&i.config_dir), "{name}: {}", f.path);
                wrote.push(name);
            }
            if let Some(c) = &job.cleanup {
                assert!(std::path::Path::new(&c.when_exists).starts_with(&i.state_dir), "{name}: the run's own state");
            }
        }
        assert_eq!(wrote, ["pi", "hermes"], "Pi's approval gate and Hermes's managed config");
        for name in crate::accounts::LOGINS {
            assert!(get(name).unwrap().login_args().is_some(), "an admin logs {name} in as each user");
        }
    }

    #[test]
    fn jobs_for_a_machine_never_go_through_this_servers_accounts() {
        let dir = std::env::temp_dir();
        let job = job_for(get("claude").unwrap().as_mut(), &input(&dir, Some(run_as("/usr/bin/sudo"))), &mut Vec::new());
        assert_eq!(job.bin, "claude");
        assert!(!job.args.iter().any(|a| a.contains("sudo") || a.contains("sb-u-")), "{:?}", job.args);
        assert!(!job.env.contains_key("SUPERBOT_PATH"));
    }

    #[tokio::test]
    async fn local_runs_start_as_the_owners_account() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::db::temp_path("run-as");
        let sudo = dir.join("sudo");
        let seen = dir.join("seen");
        let script = format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho \"PATH=$SUPERBOT_PATH\" >> '{0}'\n", seen.display());
        std::fs::write(&sudo, script).unwrap();
        std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (_tx, abort) = watch::channel(None);
        let mut errors = Vec::new();
        let input = input(&dir, Some(run_as(sudo.to_str().unwrap())));
        run(get("claude").unwrap(), input, abort, |e| {
            if let AgentEvent::Error(m) = e {
                errors.push(m)
            }
        })
        .await;
        assert!(errors.is_empty(), "{errors:?}");
        let seen = std::fs::read_to_string(&seen).unwrap();
        let lines: Vec<&str> = seen.lines().collect();
        assert_eq!(lines[..7], ["-n", "-E", "-u", "sb-u-u1", "--", "/opt/superbot/bin/superbot-run", "claude"], "{seen}");
        assert!(lines.contains(&"--settings"), "the approval gate goes through: {seen}");
        assert_eq!(lines.last(), Some(&"PATH=/opt/superbot/bin:/usr/bin:/bin"));
    }

    #[test]
    fn machines_know_every_harness() {
        for name in super::NAMES {
            let bin = super::get(name).unwrap().bin();
            assert_eq!(crate::machines::wire::harness_bin(bin), Some(bin), "{name}");
        }
    }

    #[test]
    fn server_secrets_are_stripped_from_harnesses() {
        let mut cmd = std::process::Command::new("true");
        super::strip_secret_env(&mut cmd);
        let removed: Vec<_> = cmd.get_envs().filter(|(_, v)| v.is_none()).map(|(k, _)| k.to_string_lossy().into_owned()).collect();
        for k in ["AUTH_PASSWORD", "SUPERBOT_MASTER_KEY_FILE", "LINODE_TOKEN", "LINODE_TOKEN_FILE", "INCUS_CLIENT_KEY", "INCUS_CLIENT_KEY_FILE", "TURNSTILE_SECRET", "TURNSTILE_SECRET_FILE", "LICENSE_KEY", "LICENSE_KEY_FILE", "STRIPE_WEBHOOK_SECRET", "STRIPE_WEBHOOK_SECRET_FILE", "STRIPE_SECRET_KEY", "STRIPE_SECRET_KEY_FILE", "SMTP_PASSWORD", "SMTP_PASSWORD_FILE", "NOTIFY_WEBHOOK_URL", "NOTIFY_WEBHOOK_SECRET_FILE"] {
            assert!(removed.iter().any(|r| r == k), "{k}");
        }
    }

    fn sandboxed(dir: &std::path::Path) -> RunInput {
        let mut i = input(dir, None);
        i.env.insert("BOT_API".into(), "http://127.0.0.1:3000".into());
        i.sandbox = Some(Sandbox { writable: vec!["/data/bots/b1".into(), "/home/superbot/.npm".into()] });
        i
    }

    #[test]
    fn codex_runs_in_workspace_write_only_when_sandboxed() {
        let dir = std::env::temp_dir();
        let open = get("codex").unwrap().args(&input(&dir, None), &mut Vec::new());
        assert!(open.iter().any(|a| a == "--dangerously-bypass-approvals-and-sandbox"));
        assert!(!open.iter().any(|a| a.starts_with("sandbox_mode")));
        let mut i = sandboxed(&dir);
        for resumed in [false, true] {
            i.session_id = resumed.then(|| "t1".into());
            let a = get("codex").unwrap().args(&i, &mut Vec::new());
            assert!(!a.iter().any(|a| a.starts_with("--dangerously-bypass-approvals")), "{a:?}");
            for c in [
                "sandbox_mode=\"workspace-write\"",
                "approval_policy=\"never\"",
                "sandbox_workspace_write.network_access=true",
                r#"sandbox_workspace_write.writable_roots=["/data/bots/b1","/home/superbot/.npm"]"#,
            ] {
                let at = a.iter().position(|x| x == c).unwrap_or_else(|| panic!("{c} in {a:?}"));
                assert_eq!(a[at - 1], "-c");
            }
            // The approval hook stays: the sandbox is on top of approvals, not instead.
            assert!(a.iter().any(|x| x.starts_with("hooks.PreToolUse")));
            let end = a.iter().position(|x| x == "--").unwrap();
            assert!(a.iter().position(|x| x.starts_with("sandbox_mode")).unwrap() < end);
        }
        i.sandbox = Some(Sandbox::default());
        let a = get("codex").unwrap().args(&i, &mut Vec::new());
        assert!(!a.iter().any(|x| x.contains("writable_roots")), "no empty list");
    }

    #[test]
    fn claude_turns_on_its_sandbox_with_the_hook() {
        let dir = std::env::temp_dir();
        let settings = |i: &RunInput| {
            let a = get("claude").unwrap().args(i, &mut Vec::new());
            a.iter().position(|x| x == "--settings").map(|at| serde_json::from_str::<Value>(&a[at + 1]).unwrap())
        };
        assert!(settings(&input(&dir, None)).unwrap().get("sandbox").is_none());
        let mut i = sandboxed(&dir);
        let s = settings(&i).unwrap();
        assert_eq!(s["disableAllHooks"], false);
        assert!(s["hooks"]["PreToolUse"].is_array());
        assert_eq!(
            s["sandbox"],
            serde_json::json!({
                "enabled": true,
                "allowUnsandboxedCommands": false,
                "filesystem": { "allowWrite": ["/data/bots/b1", "/home/superbot/.npm"] },
                "network": { "allowedDomains": ["127.0.0.1:3000"] },
            })
        );
        // Bypass mode: no hook, the sandbox still holds.
        i.guard = None;
        let s = settings(&i).unwrap();
        assert!(s.get("hooks").is_none() && s["sandbox"]["enabled"] == true);
        i.sandbox = None;
        assert!(settings(&i).is_none());
    }

    #[test]
    fn only_harnesses_with_a_sandbox_say_so() {
        for (name, has) in [("claude", true), ("codex", true), ("pi", false), ("hermes", false)] {
            assert_eq!(get(name).unwrap().has_sandbox(), has, "{name}");
        }
    }

    #[test]
    fn the_canary_arms_on_shell_calls_and_on_hooked_calls_that_ran() {
        let start = |n: &str| AgentEvent::Tool { name: n.into(), detail: String::new() };
        let ran = |n: &str| AgentEvent::ToolRan { name: n.into() };
        for (harness, shell, other) in [("claude", "Bash", "Write"), ("codex", "shell", "file_change"), ("pi", "bash", "write"), ("hermes", "terminal", "write_file")] {
            let a = get(harness).unwrap();
            assert!(arms_canary(&*a, &start(shell)) && arms_canary(&*a, &ran(shell)), "{harness}");
            // A call may be refused before the hook, so only one that ran counts.
            assert!(!arms_canary(&*a, &start(other)), "{harness}");
            assert!(arms_canary(&*a, &ran(other)), "{harness}");
            assert!(!arms_canary(&*a, &AgentEvent::Text("hi".into())), "{harness}");
        }
        let codex = get("codex").unwrap();
        assert!(arms_canary(&*codex, &ran("mcp_tool_call")));
        for hosted_or_untested in ["web_search", "todo_list", "collab_tool_call"] {
            assert!(!arms_canary(&*codex, &ran(hosted_or_untested)), "{hosted_or_untested}");
        }
    }

    #[test]
    fn the_api_host_is_only_a_plain_local_address() {
        let mut i = input(&std::env::temp_dir(), None);
        for (api, host) in [
            ("http://127.0.0.1:3000", Some("127.0.0.1:3000")),
            ("http://127.0.0.1:41234/", Some("127.0.0.1:41234")),
            ("https://bots.example", None),
            ("http://u:p@127.0.0.1:1", None),
            ("http://127.0.0.1:1/x", None),
            ("http://", None),
        ] {
            i.env.insert("BOT_API".into(), api.into());
            assert_eq!(api_host(&i).as_deref(), host, "{api}");
        }
    }
}
