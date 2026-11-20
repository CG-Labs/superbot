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
    Error(String),
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
    pub model: Option<String>,
    /// Reasoning effort, in the harness's own words (e.g. "high").
    pub effort: Option<String>,
    pub env: HashMap<String, String>,
    /// A private folder for this Bot's harness files.
    pub state_dir: PathBuf,
    /// Set in ask mode: the harness must run `command` before every tool call.
    pub guard: Option<Guard>,
    /// With per-user accounts (ADR 0037): the account the harness runs as on this
    /// server. None: botd's. Runs on the owner's machine never use it.
    pub run_as: Option<crate::accounts::RunAs>,
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
/// forge Stripe's webhook.
pub(crate) const SECRET_ENV: [&str; 10] = [
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
];

/// `SECRET_ENV`, `secrets::SERVER_SECRETS` (and their `_FILE`), and every `SSO_*`
/// setting: sign-in config, including client secrets (ADR 0014).
pub(crate) fn secret_env() -> Vec<String> {
    let mut names: Vec<String> = SECRET_ENV.map(String::from).into();
    for k in crate::secrets::SERVER_SECRETS {
        names.extend([k.to_string(), format!("{k}_FILE")]);
    }
    names.extend(std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).filter(|k| k.starts_with("SSO_")));
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

pub trait Adapter: Send {
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
    /// Environment the harness needs on top of `input.env`.
    fn env(&self, _input: &RunInput) -> Vec<(String, String)> {
        Vec::new()
    }
    /// Text for the harness's stdin. None = no stdin.
    fn stdin(&self, _input: &RunInput) -> Option<String> {
        None
    }
    /// Files the harness needs before it starts (its settings, the approval gate),
    /// written private where the run happens. Paths are inside `input.state_dir`.
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
    /// The tool name its events use for shell commands. Ask mode stops a run that uses it
    /// without calling the hook, since that harness isn't enforcing approvals.
    fn shell_tool(&self) -> &'static str;
    /// The longest hook timeout the harness accepts, if it caps it.
    fn max_hook_secs(&self) -> Option<u64> {
        None
    }
    /// What logs the harness in, run at a terminal as the account its runs use.
    fn login_args(&self) -> Option<&'static [&'static str]> {
        None
    }
    /// How the harness logs in on a user's machine (ADR 0041), if it has a login there.
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

pub fn get(name: &str) -> Option<Box<dyn Adapter>> {
    match name {
        "claude" => Some(Box::new(claude::Claude::default())),
        "codex" => Some(Box::new(codex::Codex)),
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
    env.extend(adapter.env(input));
    let path = |p: &std::path::Path| p.display().to_string();
    JobRequest {
        protocol: crate::machines::wire::PROTOCOL,
        job_id: String::new(),
        bot_id: String::new(),
        owner_id: String::new(),
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
            Some(r) => r.wrap(job),
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
            model: None,
            effort: None,
            env: HashMap::from([("PATH".into(), "/opt/superbot/bin:/usr/bin:/bin".into())]),
            state_dir: dir.join("state"),
            guard: Some(Guard { command: "'/opt/bin/botctl' hook x".into(), timeout_secs: 300, wait: std::time::Duration::from_secs(240) }),
            run_as,
        }
    }

    fn run_as(sudo: &str) -> crate::accounts::RunAs {
        crate::accounts::RunAs { sudo: sudo.into(), runner: "/opt/superbot/bin/superbot-run".into(), account: "sb-u-u1".into() }
    }

    #[test]
    fn isolated_harnesses_need_nothing_botd_writes() {
        // botd writes job files and runs cleanups as itself, where a per-user account can't follow.
        let dir = std::env::temp_dir();
        for name in crate::accounts::HARNESSES {
            let job = job_for(get(name).unwrap().as_mut(), &input(&dir, None), &mut Vec::new());
            assert!(job.files.is_empty() && job.cleanup.is_none(), "{name}");
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
        for k in ["AUTH_PASSWORD", "SUPERBOT_MASTER_KEY_FILE", "LINODE_TOKEN", "LINODE_TOKEN_FILE", "TURNSTILE_SECRET", "TURNSTILE_SECRET_FILE", "LICENSE_KEY", "LICENSE_KEY_FILE", "STRIPE_WEBHOOK_SECRET", "STRIPE_WEBHOOK_SECRET_FILE"] {
            assert!(removed.iter().any(|r| r == k), "{k}");
        }
    }
}
