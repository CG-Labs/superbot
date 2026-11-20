//! The only contract between the server and a harness (Claude Code, Codex, Pi, Hermes).
//! Each adapter builds a command line and maps the harness's JSON lines to `AgentEvent`s.
//! Spawning, streaming, stopping, and exit handling are shared here.

mod claude;
mod codex;
mod hermes;
mod pi;

use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;

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
    /// With per-user accounts (ADR 0037): the account the harness runs as. None: botd's.
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
/// could approve its own actions or read what botd seals.
pub(crate) const SECRET_ENV: [&str; 6] =
    ["AUTH_PASSWORD", "AUTH_PASSWORD_FILE", "SUPERBOT_PASSWORD", "SUPERBOT_TOKEN", "SUPERBOT_MASTER_KEY", "SUPERBOT_MASTER_KEY_FILE"];

/// `SECRET_ENV`, `secrets::SERVER_SECRETS` (and their `_FILE`), and every `SSO_*`
/// setting: sign-in config, including client secrets (ADR 0014).
pub(crate) fn strip_secret_env(cmd: &mut std::process::Command) {
    for k in SECRET_ENV {
        cmd.env_remove(k);
    }
    for k in crate::secrets::SERVER_SECRETS {
        cmd.env_remove(k);
        cmd.env_remove(format!("{k}_FILE"));
    }
    for (k, _) in std::env::vars_os() {
        if k.to_str().is_some_and(|k| k.starts_with("SSO_")) {
            cmd.env_remove(k);
        }
    }
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
    /// Stops harness processes that outlive the CLI (e.g. a daemon it started), so a
    /// stopped run really stops. Runs before and after every run. Blocking.
    fn stop_leftovers(&self, _input: &RunInput) -> Result<(), String> {
        Ok(())
    }
    /// The tool name its events use for shell commands. Ask mode stops a run that uses it
    /// without calling the hook, since that harness isn't enforcing approvals.
    fn shell_tool(&self) -> &'static str;
    /// The longest hook timeout the harness accepts, if it caps it.
    fn max_hook_secs(&self) -> Option<u64> {
        None
    }
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

/// Runs the harness, calling `emit` for every event, until it exits or `abort` fires.
pub async fn run(adapter: Box<dyn Adapter>, input: RunInput, mut abort: watch::Receiver<AbortReason>, mut emit: impl FnMut(AgentEvent)) {
    // A turn left running from before would keep going beside this one.
    let (mut adapter, input, before) = stop_leftovers(adapter, input).await;
    if let Err(e) = before {
        return emit(AgentEvent::Error(e));
    }
    run_child(adapter.as_mut(), &input, &mut abort, &mut emit).await;
    if let (_, _, Err(e)) = stop_leftovers(adapter, input).await {
        emit(AgentEvent::Error(e));
    }
}

async fn stop_leftovers(adapter: Box<dyn Adapter>, input: RunInput) -> (Box<dyn Adapter>, RunInput, Result<(), String>) {
    let task = tokio::task::spawn_blocking(move || {
        let done = adapter.stop_leftovers(&input);
        (adapter, input, done)
    });
    task.await.expect("stop_leftovers panicked")
}

async fn run_child(adapter: &mut dyn Adapter, input: &RunInput, abort: &mut watch::Receiver<AbortReason>, mut emit: impl FnMut(AgentEvent)) {
    let mut out = Vec::new();
    let args = adapter.args(input, &mut out);
    // An adapter that couldn't set up (e.g. write its approval gate) must not run.
    let failed = out.iter().any(|e| matches!(e, AgentEvent::Error(_)));
    out.drain(..).for_each(&mut emit);
    if failed {
        return;
    }
    let stdin = adapter.stdin(input);

    let argv: Vec<std::ffi::OsString> = match &input.run_as {
        Some(r) => r.argv(adapter.bin(), args),
        None => std::iter::once(adapter.bin().into()).chain(args.into_iter().map(Into::into)).collect(),
    };
    let mut cmd = Command::new(&argv[0]);
    strip_secret_env(cmd.as_std_mut());
    // sudo resets PATH; superbot-run puts this one back.
    if input.run_as.is_some()
        && let Some(path) = input.env.get("PATH")
    {
        cmd.env("SUPERBOT_PATH", path);
    }
    let mut child = match cmd
        .args(&argv[1..])
        .current_dir(&input.cwd)
        .envs(&input.env)
        .envs(adapter.env(input))
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0) // own group, so stop kills the whole tree
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return emit(AgentEvent::Error(format!("Couldn't start {}: {e}", adapter.bin()))),
    };
    let pid = child.id();
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = pipe.write_all(text.as_bytes()).await;
        });
    }

    let mut stderr = child.stderr.take().unwrap();
    let stderr_task = tokio::spawn(async move {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s).await;
        s
    });

    // JSON lines. Split only on "\n": some harnesses put U+2028 inside JSON strings.
    let mut lines = BufReader::new(child.stdout.take().unwrap()).split(b'\n');
    let mut saw_error = false;
    let mut aborted = false;
    loop {
        tokio::select! {
            line = lines.next_segment() => match line {
                Ok(Some(bytes)) => {
                    let Ok(v) = serde_json::from_slice::<Value>(&bytes) else { continue };
                    adapter.on_event(&v, &mut out);
                    for e in out.drain(..) {
                        saw_error |= matches!(e, AgentEvent::Error(_));
                        emit(e);
                    }
                }
                _ => break,
            },
            _ = abort.wait_for(|r| r.is_some()), if !aborted => {
                aborted = true;
                if let Some(pid) = pid {
                    kill_group(pid, "TERM");
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        kill_group(pid, "KILL");
                    });
                }
            }
        }
    }
    let status = child.wait().await;
    let stderr = stderr_task.await.unwrap_or_default();
    let ok = status.as_ref().is_ok_and(|s| s.success());
    if !ok && !saw_error && !aborted {
        let tail: Vec<&str> = stderr.trim().lines().rev().take(3).collect();
        let msg = tail.into_iter().rev().collect::<Vec<_>>().join("\n");
        emit(AgentEvent::Error(if msg.is_empty() {
            format!("{} exited with {}", adapter.bin(), status.map(|s| s.to_string()).unwrap_or_default())
        } else {
            msg
        }));
    }
}

fn kill_group(pid: u32, signal: &str) {
    let _ = std::process::Command::new("kill")
        .args([format!("-{signal}"), "--".into(), format!("-{pid}")])
        .stderr(Stdio::null())
        .status();
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
    #[test]
    fn server_secrets_are_stripped_from_harnesses() {
        let mut cmd = std::process::Command::new("true");
        super::strip_secret_env(&mut cmd);
        let removed: Vec<_> = cmd.get_envs().filter(|(_, v)| v.is_none()).map(|(k, _)| k.to_string_lossy().into_owned()).collect();
        for k in ["AUTH_PASSWORD", "SUPERBOT_MASTER_KEY_FILE", "LINODE_TOKEN", "LINODE_TOKEN_FILE", "TURNSTILE_SECRET", "TURNSTILE_SECRET_FILE"] {
            assert!(removed.iter().any(|r| r == k), "{k}");
        }
    }
}
