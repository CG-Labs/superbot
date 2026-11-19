//! End to end: the real `botd` and `botctl` drive a stub `hermes` CLI that speaks Hermes's
//! stream-json and runs the `pre_tool_call` hook from its managed config the way Hermes
//! does (stdin JSON, exit 2 blocks). No network, no real Hermes, no credentials.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "e2e-password";

/// One `hermes` call per run. `$STUB/tool` is the command the "model" wants to run;
/// `$STUB/skip-hook` makes it run the tool without the hook, like a Hermes that ignores hooks.
const STUB: &str = r#"#!/bin/sh
stub=$(dirname "$0")
printf '%s|%s\n' "$*" "$HERMES_HOME" >>"$stub/calls.log"
if [ "$1" = gateway ]; then
  rm -f "$HERMES_HOME/gateway.pid"
  exit 0
fi
cat >"$stub/prompt.txt"
env >"$stub/env.txt"
mkdir -p "$HERMES_HOME" && echo '{"pid": 1}' >"$HERMES_HOME/gateway.pid"
tool=$(cat "$stub/tool")
printf '{"type":"system","subtype":"init","model":"stub","session_id":""}\n'
printf '{"type":"text","text":"On it."}\n'
if [ -e "$stub/skip-hook" ]; then
  printf '{"type":"tool_use","name":"terminal","input":{"command":"%s"}}\n' "$tool"
  sleep 30
  exit 0
fi
hook=$(sed -n 's/.*"command":"\([^"]*\)".*/\1/p' "$HERMES_MANAGED_DIR/config.yaml")
payload=$(printf '{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"%s"},"session_id":"local-stub1","cwd":"/opt/hermes/hermes-agent"}' "$tool")
if [ -n "$hook" ] && printf '%s' "$payload" | eval "$hook" 2>"$stub/hook.err"; then
  printf '{"type":"tool_use","name":"terminal","tool_call_id":"c1","input":{"command":"%s"}}\n' "$tool"
  printf '{"type":"tool_result","name":"terminal","tool_call_id":"c1","output":"ok","is_error":false}\n'
  text="Ran it."
else
  text="Blocked: $(head -c 300 "$stub/hook.err" | tr -d '"\\\n')"
fi
printf '{"type":"result","session_id":"local-stub1","exit_code":0,"text":"%s"}\n' "$text"
"#;

struct Botd {
    child: Child,
    port: u16,
    dir: PathBuf,
    stub: PathBuf,
}

impl Drop for Botd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start() -> Botd {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("botd-hermes-e2e-{}-{}", std::process::id(), free_port()));
    let stub = dir.join("stub");
    for d in ["data", "workspace", "home", "stub"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    std::fs::write(stub.join("hermes"), STUB).unwrap();
    std::fs::set_permissions(stub.join("hermes"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_botd"))
        .env_clear()
        .env("PATH", format!("{}:{}", stub.display(), std::env::var("PATH").unwrap_or_default()))
        .env("HOME", dir.join("home"))
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("AUTH_PASSWORD", PASSWORD)
        .env("SUPERBOT_MASTER_KEY", "ab".repeat(32))
        .env("DATA_DIR", dir.join("data"))
        .env("WORKSPACE_DIR", dir.join("workspace"))
        .env("DEFAULT_HARNESS", "hermes")
        .env("SCREENS", "off")
        .env("E2E_INHERITED_TOKEN", "inherited-e2e-value")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start botd");
    let b = Botd { child, port, dir, stub };
    wait_for("botd to start", || (http(&b, "GET", "/healthz", "").0 == 200).then_some(()));
    b
}

fn http(b: &Botd, method: &str, path: &str, body: &str) -> (u16, String) {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", b.port)) else { return (0, String::new()) };
    let auth = base64(format!("e2e:{PASSWORD}").as_bytes());
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{}\r\nAuthorization: Basic {auth}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        b.port,
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut res = String::new();
    let _ = s.read_to_string(&mut res);
    let (head, body) = res.split_once("\r\n\r\n").unwrap_or((&res, ""));
    (head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0), body.to_string())
}

fn get(b: &Botd, path: &str) -> Value {
    let (code, body) = http(b, "GET", path, "");
    assert_eq!(code, 200, "GET {path}: {body}");
    serde_json::from_str(&body).unwrap()
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

fn wait_for<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Sends `text` and waits for the Bot's replies, the last containing `last`. The Bot shows
/// as idle a moment before its closing message, so idle alone doesn't mean it's done.
fn ask(b: &Botd, bot: &str, text: &str, last: &str, mut on_pending: impl FnMut(&Value)) -> Value {
    let before = get(b, &format!("/api/bots/{bot}/messages")).as_array().unwrap().len();
    let (code, body) = http(b, "POST", &format!("/api/bots/{bot}/messages"), &json!({ "text": text }).to_string());
    assert_eq!(code, 202, "{body}");
    wait_for(&format!("a reply with {last:?}"), || {
        for a in get(b, "/api/approvals?status=pending").as_array().unwrap() {
            on_pending(a);
        }
        let msgs = get(b, &format!("/api/bots/{bot}/messages"));
        let fresh: Vec<Value> = msgs.as_array().unwrap()[before..].iter().filter(|m| m["role"] == "bot").cloned().collect();
        let done = !get(b, "/api/state")["bots"].as_array().unwrap().iter().any(|x| x["id"] == bot && x["working"] == true);
        let ended = fresh.last().is_some_and(|m| m["text"].as_str().unwrap_or_default().contains(last));
        (done && ended).then(|| json!(fresh))
    })
}

fn texts(replies: &Value) -> String {
    replies.as_array().unwrap().iter().map(|m| m["text"].as_str().unwrap_or_default()).collect::<Vec<_>>().join("\n")
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

#[test]
fn hermes_runs_behind_the_approval_gate() {
    let b = start();
    let bots = get(&b, "/api/bots");
    let bot = bots.as_array().unwrap()[0].clone();
    assert_eq!(bot["harness"], "hermes");
    let id = bot["id"].as_str().unwrap().to_string();
    let (code, _) = http(&b, "PUT", "/api/secrets/E2E_GITHUB_TOKEN", r#"{"value":"ghp-e2e-secret-value"}"#);
    assert_eq!(code, 200);

    // A risky command waits for a person; approving lets it run.
    std::fs::write(b.stub.join("tool"), "git push origin main").unwrap();
    let mut seen = None;
    let replies = ask(&b, &id, "push it", "Ran it.", |a| {
        if seen.is_none() {
            seen = Some(a.clone());
            let (code, body) = http(&b, "POST", &format!("/api/approvals/{}/approve", a["id"].as_str().unwrap()), "{}");
            assert_eq!(code, 200, "{body}");
        }
    });
    let a = seen.expect("an approval was requested");
    assert_eq!((a["harness"].as_str(), a["tool"].as_str(), a["class"].as_str()), (Some("hermes"), Some("terminal"), Some("git_push")));
    assert_eq!(a["subject"], "git push origin main");
    assert_eq!(texts(&replies), "On it.\nRan it.");

    let calls = read(&b.stub.join("calls.log"));
    let home = b.dir.join("data/bots").join(&id).join("hermes");
    let canonical_home = std::fs::canonicalize(b.dir.join("data")).unwrap().join("bots").join(&id).join("hermes");
    let first = calls.lines().next().unwrap();
    assert!(first.starts_with("chat --oneshot --query-file - --format stream-json --source tool --yolo|"), "{first}");
    assert!(!first.contains("--resume"), "{first}");
    assert!(first.ends_with(&*canonical_home.to_string_lossy()) || first.ends_with(&*home.to_string_lossy()), "{first}");
    assert!(calls.lines().nth(1).unwrap().starts_with("gateway stop --yes|"), "the daemon is stopped after the run: {calls}");
    assert_eq!(read(&b.stub.join("prompt.txt")), "push it", "the prompt goes on stdin");

    let env = read(&b.stub.join("env.txt"));
    for want in ["HERMES_ACCEPT_HOOKS=1", "E2E_GITHUB_TOKEN=ghp-e2e-secret-value", "BOT_TOKEN="] {
        assert!(env.lines().any(|l| l.starts_with(want)), "missing {want}");
    }
    assert!(env.lines().any(|l| l.starts_with("HERMES_EPHEMERAL_SYSTEM_PROMPT=") && l.len() > 40), "system prompt");
    for banned in ["AUTH_PASSWORD=", "SUPERBOT_MASTER_KEY="] {
        assert!(!env.lines().any(|l| l.starts_with(banned)), "{banned} leaked to the harness");
    }
    let managed_dir = env.lines().find_map(|l| l.strip_prefix("HERMES_MANAGED_DIR=")).unwrap().to_string();
    let config: Value = serde_json::from_str(&read(&Path::new(&managed_dir).join("config.yaml"))).unwrap();
    let hook = &config["hooks"]["pre_tool_call"][0];
    assert_eq!((hook["fail_closed"].as_bool(), hook["timeout"].as_u64()), (Some(true), Some(300)));
    assert!(hook["command"].as_str().unwrap().contains("hook hermes --cwd '"), "{hook}");
    assert_eq!(config["memory"]["memory_enabled"], false);
    let passthrough = config["terminal"]["env_passthrough"].as_array().unwrap();
    for name in ["BOT_TOKEN", "E2E_GITHUB_TOKEN", "E2E_INHERITED_TOKEN"] {
        assert!(passthrough.contains(&json!(name)), "{name} missing from {passthrough:?}");
    }
    for name in ["AUTH_PASSWORD", "SUPERBOT_MASTER_KEY"] {
        assert!(!passthrough.contains(&json!(name)), "{name} listed in {passthrough:?}");
    }
    assert!(!read(&Path::new(&managed_dir).join("config.yaml")).contains("ghp-e2e-secret-value"), "names only, never values");
    assert!(!read(&Path::new(&managed_dir).join("config.yaml")).contains("inherited-e2e-value"), "names only, never values");

    // The hook checks paths from the Bot's workspace, not the folder Hermes runs hooks in.
    std::fs::write(b.stub.join("tool"), "rm -rf build").unwrap();
    let replies = ask(&b, &id, "clean up", "Ran it.", |a| panic!("asked for a workspace-local delete: {a}"));
    assert_eq!(texts(&replies), "On it.\nRan it.");
    assert!(read(&b.stub.join("calls.log")).contains("--resume local-stub1"), "the session resumes");

    // Denied: the tool doesn't run and the agent is told why.
    std::fs::write(b.stub.join("tool"), "git push --force").unwrap();
    let replies = ask(&b, &id, "force push", "Blocked: ", |a| {
        let _ = http(&b, "POST", &format!("/api/approvals/{}/deny", a["id"].as_str().unwrap()), "{}");
    });
    let t = texts(&replies);
    assert!(t.contains("Blocked: ") && t.contains("denied"), "{t}");

    // A Hermes that skips the hook is stopped, and its daemon too.
    std::fs::write(b.stub.join("skip-hook"), "").unwrap();
    std::fs::write(b.stub.join("tool"), "ls").unwrap();
    let start = Instant::now();
    let replies = ask(&b, &id, "list files", "approval gate", |a| panic!("no hook should have run: {a}"));
    assert!(texts(&replies).contains("without checking SuperBot's approval gate"), "{}", texts(&replies));
    assert!(start.elapsed() < Duration::from_secs(20), "stopped by the canary, not the stub's sleep");
    assert!(read(&b.stub.join("calls.log")).trim_end().lines().last().unwrap().starts_with("gateway stop --yes|"));
}
