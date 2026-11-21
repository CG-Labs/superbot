//! What the harness tests share: a fake model that Claude Code, Codex, Pi and Hermes Agent
//! each reach through their own custom-endpoint setting, and a throwaway `botd` set up for
//! one harness (ADR 0057). Used by `harness_e2e` (approvals) and `harness_footprint`
//! (resource use, ADR 0070).
#![allow(dead_code)]

use axum::body::Bytes;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const PASSWORD: &str = "e2e-password";
pub const MODEL: &str = "e2e-model";
pub const KEY: &str = "e2e-key";
/// How the prompt names the one command the fake model runs.
pub const RUN: (&str, &str) = ("E2E-RUN<<", ">>");
/// How the prompt names one tool and its arguments: `E2E-TOOL<<name>><<json>>`. A
/// JSON string is a freeform tool's text; `namespace/tool` is a tool in a namespace.
pub const TOOL: (&str, &str) = ("E2E-TOOL<<", ">>");
/// The fake model's reply once the command's result is back.
pub const DONE: &str = "E2E-DONE";

// ---------------------------------------------------------------------------------
// The fake model: Anthropic Messages (Claude Code), OpenAI Responses (Codex), and
// OpenAI Chat Completions (Pi, Hermes Agent). Stateless: each request carries the whole
// conversation, so it reads the newest prompt's command and whether a result came back.

pub struct FakeModel {
    pub port: u16,
    /// Model calls answered so far (requests that can carry a turn, not `/models`).
    pub calls: Arc<AtomicU64>,
    /// How long each model call takes, in milliseconds: 0 by default. A delay holds a run
    /// open the way a real model's latency does, so its processes can be measured.
    pub delay_ms: Arc<AtomicU64>,
}

impl FakeModel {
    pub fn set_delay(&self, d: Duration) {
        self.delay_ms.store(d.as_millis() as u64, Ordering::SeqCst);
    }
}

pub enum Reply {
    Text(String),
    Call { name: String, args: Value },
}

/// What a request holds, whatever its format: prompts, tool results, and tools.
pub enum Turn {
    User(String),
    Result(String),
}

pub fn fake_model() -> FakeModel {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let ids = Arc::new(AtomicU64::new(1));
    let (calls, delay_ms) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let (c, d) = (calls.clone(), delay_ms.clone());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.block_on(async move {
            let app = axum::Router::new().fallback(move |m: Method, u: Uri, b: Bytes| {
                let (ids, calls, delay) = (ids.clone(), c.clone(), d.clone());
                async move {
                    if m == Method::POST {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(delay.load(Ordering::SeqCst))).await;
                    }
                    serve(&m, u.path(), &b, &ids)
                }
            });
            axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app).await.unwrap();
        });
    });
    FakeModel { port, calls, delay_ms }
}

pub fn serve(method: &Method, path: &str, body: &[u8], ids: &AtomicU64) -> Response {
    let req: Value = serde_json::from_slice(body).unwrap_or_default();
    let id = ids.fetch_add(1, Ordering::SeqCst);
    let stream = req["stream"].as_bool() == Some(true);
    match (method.as_str(), path) {
        ("GET", p) if p.ends_with("/models") => json_response(json!({ "object": "list", "data": [{ "id": MODEL, "object": "model", "owned_by": "e2e" }] })),
        ("POST", p) if p.ends_with("/messages/count_tokens") => json_response(json!({ "input_tokens": 1 })),
        ("POST", p) if p.ends_with("/messages") => anthropic(decide(anthropic_turns(&req), anthropic_tools(&req)), stream, id),
        ("POST", p) if p.ends_with("/responses") => responses(decide(responses_turns(&req), responses_tools(&req)), stream, id),
        ("POST", p) if p.ends_with("/chat/completions") => chat(decide(chat_turns(&req), chat_tools(&req)), stream, id),
        _ => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

pub fn json_response(v: Value) -> Response {
    ([("content-type", "application/json")], v.to_string()).into_response()
}

pub fn sse(events: Vec<(Option<&str>, Value)>, done: bool) -> Response {
    let mut out = String::new();
    for (name, data) in events {
        if let Some(n) = name {
            out.push_str(&format!("event: {n}\n"));
        }
        out.push_str(&format!("data: {data}\n\n"));
    }
    if done {
        out.push_str("data: [DONE]\n\n");
    }
    ([("content-type", "text/event-stream"), ("cache-control", "no-cache")], out).into_response()
}

/// Text of a string, or of the `text` parts of an array of content blocks.
pub fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts.iter().map(|p| p["text"].as_str().map(String::from).unwrap_or_else(|| text_of(&p["content"]))).collect::<Vec<_>>().join("\n"),
        Value::Null => String::new(),
        v => v.to_string(),
    }
}

pub fn decide(turns: Vec<Turn>, tools: Vec<(String, Value)>) -> Reply {
    // Side requests (titles, summaries) offer no tools.
    if tools.is_empty() {
        return Reply::Text("ok".into());
    }
    let (mut want, mut result) = (None, None);
    for t in turns {
        match t {
            Turn::User(s) => {
                if let Some(w) = want_of(&s) {
                    (want, result) = (Some(w), None);
                }
            }
            Turn::Result(r) if want.is_some() => result = Some(r),
            Turn::Result(_) => {}
        }
    }
    match (want, result) {
        (Some(_), Some(r)) => Reply::Text(format!("{DONE} {}", r.chars().take(600).collect::<String>())),
        (Some(Want::Tool(name, args)), None) => {
            let offered = name.split('/').next().unwrap_or_default();
            match tools.iter().any(|(n, _)| n == offered) {
                true => Reply::Call { name, args },
                false => Reply::Text(format!("E2E-NO-TOOL {name} among {:?}", tools.iter().map(|t| &t.0).collect::<Vec<_>>())),
            }
        }
        (Some(Want::Run(c)), None) => {
            let shell = ["Bash", "exec_command", "bash", "terminal", "shell"].iter().find_map(|n| tools.iter().find(|(name, _)| name == n));
            match shell {
                Some((name, params)) => {
                    let command = &params["properties"]["command"];
                    let args = match command["type"].as_str() {
                        // Older Codex's `shell` takes argv.
                        Some("array") => json!({ "command": ["bash", "-lc", c] }),
                        _ if command.is_object() => json!({ "command": c }),
                        _ => json!({ "cmd": c }),
                    };
                    Reply::Call { name: name.clone(), args }
                }
                None => Reply::Text(format!("E2E-NO-SHELL-TOOL among {:?}", tools.iter().map(|t| &t.0).collect::<Vec<_>>())),
            }
        }
        (None, _) => Reply::Text("E2E-NO-COMMAND".into()),
    }
}

/// What a prompt asks for: a shell command, or one named tool with its arguments.
pub enum Want {
    Run(String),
    Tool(String, Value),
}

/// The last request in a prompt.
pub fn want_of(s: &str) -> Option<Want> {
    let after = |tag: &str| s.rfind(tag).map(|i| &s[i + tag.len()..]);
    if s.rfind(TOOL.0) > s.rfind(RUN.0) {
        let (name, rest) = after(TOOL.0)?.split_once(TOOL.1)?;
        let args = rest.strip_prefix("<<")?.split_once(TOOL.1)?.0;
        return Some(Want::Tool(name.into(), serde_json::from_str(args).ok()?));
    }
    after(RUN.0)?.split_once(RUN.1).map(|(c, _)| Want::Run(c.into()))
}

pub fn anthropic_turns(req: &Value) -> Vec<Turn> {
    let mut turns = Vec::new();
    for m in req["messages"].as_array().into_iter().flatten().filter(|m| m["role"] == "user") {
        match &m["content"] {
            Value::Array(blocks) => {
                for b in blocks {
                    match b["type"].as_str() {
                        Some("tool_result") => turns.push(Turn::Result(text_of(&b["content"]))),
                        Some("text") => turns.push(Turn::User(text_of(&b["text"]))),
                        _ => {}
                    }
                }
            }
            c => turns.push(Turn::User(text_of(c))),
        }
    }
    turns
}

pub fn anthropic_tools(req: &Value) -> Vec<(String, Value)> {
    req["tools"].as_array().into_iter().flatten().filter_map(|t| Some((t["name"].as_str()?.to_string(), t["input_schema"].clone()))).collect()
}

pub fn anthropic(reply: Reply, stream: bool, id: u64) -> Response {
    let (block, stop) = match &reply {
        Reply::Text(t) => (json!({ "type": "text", "text": t }), "end_turn"),
        Reply::Call { name, args } => (json!({ "type": "tool_use", "id": format!("toolu_e2e{id}"), "name": name, "input": args }), "tool_use"),
    };
    let usage = json!({ "input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0 });
    let message = json!({ "id": format!("msg_e2e{id}"), "type": "message", "role": "assistant", "model": MODEL, "stop_reason": stop, "stop_sequence": null, "usage": usage });
    if !stream {
        let mut m = message;
        m["content"] = json!([block]);
        return json_response(m);
    }
    let mut start = message;
    start["content"] = json!([]);
    start["stop_reason"] = Value::Null;
    let (open, delta) = match reply {
        Reply::Text(t) => (json!({ "type": "text", "text": "" }), json!({ "type": "text_delta", "text": t })),
        Reply::Call { name, args } => (
            json!({ "type": "tool_use", "id": format!("toolu_e2e{id}"), "name": name, "input": {} }),
            json!({ "type": "input_json_delta", "partial_json": args.to_string() }),
        ),
    };
    sse(
        vec![
            (Some("message_start"), json!({ "type": "message_start", "message": start })),
            (Some("content_block_start"), json!({ "type": "content_block_start", "index": 0, "content_block": open })),
            (Some("content_block_delta"), json!({ "type": "content_block_delta", "index": 0, "delta": delta })),
            (Some("content_block_stop"), json!({ "type": "content_block_stop", "index": 0 })),
            (Some("message_delta"), json!({ "type": "message_delta", "delta": { "stop_reason": stop, "stop_sequence": null }, "usage": { "output_tokens": 5 } })),
            (Some("message_stop"), json!({ "type": "message_stop" })),
        ],
        false,
    )
}

pub fn responses_turns(req: &Value) -> Vec<Turn> {
    let mut turns = Vec::new();
    for item in req["input"].as_array().into_iter().flatten() {
        match item["type"].as_str() {
            Some("function_call_output") | Some("custom_tool_call_output") => turns.push(Turn::Result(text_of(&item["output"]))),
            Some("message") | None if item["role"] == "user" => turns.push(Turn::User(text_of(&item["content"]))),
            _ => {}
        }
    }
    turns
}

pub fn responses_tools(req: &Value) -> Vec<(String, Value)> {
    req["tools"].as_array().into_iter().flatten().filter_map(|t| Some((t["name"].as_str()?.to_string(), t["parameters"].clone()))).collect()
}

pub fn responses(reply: Reply, stream: bool, id: u64) -> Response {
    let item = match reply {
        Reply::Text(t) => json!({ "type": "message", "id": format!("msg_e2e{id}"), "role": "assistant", "status": "completed", "content": [{ "type": "output_text", "text": t, "annotations": [] }] }),
        // Freeform tools (Codex's `apply_patch`) take text, not JSON.
        Reply::Call { name, args: Value::String(input) } => {
            json!({ "type": "custom_tool_call", "id": format!("ctc_e2e{id}"), "call_id": format!("call_e2e{id}"), "name": name, "input": input, "status": "completed" })
        }
        Reply::Call { name, args } => {
            let mut call = json!({ "type": "function_call", "id": format!("fc_e2e{id}"), "call_id": format!("call_e2e{id}"), "name": name, "arguments": args.to_string(), "status": "completed" });
            // Codex offers each MCP server's tools in a namespace.
            if let Some((ns, tool)) = name.split_once('/') {
                (call["namespace"], call["name"]) = (json!(ns), json!(tool));
            }
            call
        }
    };
    let usage = json!({ "input_tokens": 10, "input_tokens_details": { "cached_tokens": 0 }, "output_tokens": 5, "output_tokens_details": { "reasoning_tokens": 0 }, "total_tokens": 15 });
    let done = json!({ "id": format!("resp_e2e{id}"), "object": "response", "status": "completed", "model": MODEL, "output": [item.clone()], "usage": usage });
    if !stream {
        return json_response(done);
    }
    sse(
        vec![
            (Some("response.created"), json!({ "type": "response.created", "response": { "id": format!("resp_e2e{id}"), "status": "in_progress", "output": [] } })),
            (Some("response.output_item.added"), json!({ "type": "response.output_item.added", "output_index": 0, "item": item })),
            (Some("response.output_item.done"), json!({ "type": "response.output_item.done", "output_index": 0, "item": item })),
            (Some("response.completed"), json!({ "type": "response.completed", "response": done })),
        ],
        false,
    )
}

pub fn chat_turns(req: &Value) -> Vec<Turn> {
    let mut turns = Vec::new();
    for m in req["messages"].as_array().into_iter().flatten() {
        match m["role"].as_str() {
            Some("tool") => turns.push(Turn::Result(text_of(&m["content"]))),
            Some("user") => turns.push(Turn::User(text_of(&m["content"]))),
            _ => {}
        }
    }
    turns
}

pub fn chat_tools(req: &Value) -> Vec<(String, Value)> {
    req["tools"].as_array().into_iter().flatten().filter_map(|t| Some((t["function"]["name"].as_str()?.to_string(), t["function"]["parameters"].clone()))).collect()
}

pub fn chat(reply: Reply, stream: bool, id: u64) -> Response {
    let usage = json!({ "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 });
    let chunk = |choices: Value| json!({ "id": format!("chatcmpl-e2e{id}"), "object": "chat.completion.chunk", "created": 0, "model": MODEL, "choices": choices });
    let (message, finish) = match &reply {
        Reply::Text(t) => (json!({ "role": "assistant", "content": t }), "stop"),
        Reply::Call { name, args } => (
            json!({ "role": "assistant", "content": null, "tool_calls": [{ "id": format!("call_e2e{id}"), "type": "function", "function": { "name": name, "arguments": args.to_string() } }] }),
            "tool_calls",
        ),
    };
    if !stream {
        return json_response(json!({
            "id": format!("chatcmpl-e2e{id}"), "object": "chat.completion", "created": 0, "model": MODEL,
            "choices": [{ "index": 0, "message": message, "finish_reason": finish }], "usage": usage,
        }));
    }
    let delta = match reply {
        Reply::Text(t) => json!({ "role": "assistant", "content": t }),
        Reply::Call { name, args } => json!({ "role": "assistant", "tool_calls": [{
            "index": 0, "id": format!("call_e2e{id}"), "type": "function", "function": { "name": name, "arguments": args.to_string() },
        }] }),
    };
    let mut last = chunk(json!([]));
    last["usage"] = usage;
    sse(
        vec![
            (None, chunk(json!([{ "index": 0, "delta": delta, "finish_reason": null }]))),
            (None, chunk(json!([{ "index": 0, "delta": {}, "finish_reason": finish }]))),
            (None, last),
        ],
        true,
    )
}

// ---------------------------------------------------------------------------------
// botd, set up for one harness.

pub struct Botd {
    pub child: Child,
    pub port: u16,
    pub dir: PathBuf,
    pub model: Option<FakeModel>,
}

impl Drop for Botd {
    fn drop(&mut self) {
        stop(&mut self.child, &self.dir);
        if std::thread::panicking() {
            eprintln!("--- botd log ({}) ---\n{}", self.dir.display(), tail(&read(&self.dir.join("botd.log")), 80));
            eprintln!("(kept {} for a look)", self.dir.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// Stops botd as a service manager would, so a test that fails mid-run leaves no agent
/// running on the operator's login: on TERM botd stops each run's process group and
/// Hermes's daemon. Whatever is left after that (botd itself, a run's group, a daemon it
/// had no time to stop) is killed.
pub fn stop(child: &mut Child, dir: &Path) {
    let pid = child.id() as i32;
    // SAFETY: signals the botd this test started.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    exit_or_kill(child, Duration::from_secs(20));
    // botd leads its own session (see `start`); runs get their own groups, not sessions.
    for p in in_session(pid) {
        // SAFETY: a process left in the session of the botd this test started.
        unsafe { libc::kill(p, libc::SIGKILL) };
    }
    // Hermes's daemon starts its own session; ask it to stop as botd would.
    for pidfile in find(dir, "gateway.pid", 8) {
        let stopping = Command::new("hermes")
            .args(["gateway", "stop", "--yes"])
            .env("HERMES_HOME", pidfile.parent().unwrap())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(mut c) = stopping {
            exit_or_kill(&mut c, Duration::from_secs(30));
        }
    }
}

pub fn exit_or_kill(child: &mut Child, limit: Duration) {
    let start = Instant::now();
    while child.try_wait().ok().flatten().is_none() && start.elapsed() < limit {
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Processes in session `sid`, from /proc (none where there is no /proc).
pub fn in_session(sid: i32) -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
    entries
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            // After the command's closing paren: state, ppid, pgrp, session.
            let stat = read(&PathBuf::from(format!("/proc/{pid}/stat")));
            stat.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().nth(3)?.parse::<i32>().ok()) == Some(sid)
        })
        .collect()
}

/// Files named `name` under `dir`, at most `depth` folders down.
pub fn find(dir: &Path, name: &str, depth: usize) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut found = Vec::new();
    for e in entries.flatten() {
        let (path, Ok(kind)) = (e.path(), e.file_type()) else { continue };
        if kind.is_dir() && depth > 0 {
            found.extend(find(&path, name, depth - 1));
        } else if kind.is_file() && e.file_name() == name {
            found.push(path);
        }
    }
    found
}

pub fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

pub fn real() -> bool {
    std::env::var("SUPERBOT_E2E_MODEL").is_ok_and(|m| m == "real")
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

pub fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(bin)).find(|f| f.is_file()))
}

/// Whether to run `harness`: listed (or no list), and its CLI on PATH. Missing is a
/// failure under `SUPERBOT_E2E_REQUIRE=1`.
pub fn wanted(harness: &str, bin: &str) -> bool {
    if let Ok(list) = std::env::var("SUPERBOT_E2E_HARNESSES")
        && !list.split(',').any(|h| h.trim() == harness)
    {
        println!("SKIP {harness}: not in SUPERBOT_E2E_HARNESSES");
        return false;
    }
    if which(bin).is_none() {
        assert!(std::env::var("SUPERBOT_E2E_REQUIRE").as_deref() != Ok("1"), "`{bin}` isn't on PATH");
        println!("SKIP {harness}: `{bin}` isn't on PATH");
        return false;
    }
    println!("RUN  {harness}: {}, {} model", which(bin).unwrap().display(), if real() { "real" } else { "fake" });
    true
}

/// Variables a harness login or provider may need in real mode; botd's own settings
/// never pass, so a server's `.env` can't reach this throwaway botd.
pub const REAL_ENV_PREFIXES: [&str; 16] = [
    "ANTHROPIC_", "CLAUDE_", "OPENAI_", "CODEX_", "PI_", "HERMES_", "SUPERBOT_HERMES_", "OPENROUTER_", "NOUS_", "GEMINI_", "GOOGLE_", "XAI_",
    "DEEPSEEK_", "MISTRAL_", "GROQ_", "AWS_",
];
pub const REAL_ENV: [&str; 11] = ["HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "SHELL"];

/// `unhooked`: botd's own `botctl hook` allows every call without asking botd, as a
/// hook that doesn't reach the gate would; the rest of `botctl` is the real one.
pub fn start(harness: &str, unhooked: bool) -> Botd {
    let dir = std::env::temp_dir().join(format!("botd-harness-e2e-{harness}-{}-{}", std::process::id(), free_port()));
    for d in ["data", "workspace", "home", "proof"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let port = free_port();
    // botd runs the `botctl` next to it.
    let botd = if unhooked {
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for (from, to) in [(env!("CARGO_BIN_EXE_botd"), "botd"), (env!("CARGO_BIN_EXE_botctl"), "botctl.real"), (env!("CARGO_BIN_EXE_superbot-run"), "superbot-run")] {
            std::fs::copy(from, bin.join(to)).unwrap();
        }
        let stub = "#!/bin/sh\nif [ \"$1\" = hook ]; then cat >/dev/null; exit 0; fi\nexec \"$(dirname \"$0\")/botctl.real\" \"$@\"\n";
        std::fs::write(bin.join("botctl"), stub).unwrap();
        std::fs::set_permissions(bin.join("botctl"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        bin.join("botd")
    } else {
        PathBuf::from(env!("CARGO_BIN_EXE_botd"))
    };
    let mut cmd = Command::new(botd);
    cmd.env_clear().current_dir(&dir).env("PATH", std::env::var("PATH").unwrap_or_default());
    let model = if real() {
        for (k, v) in std::env::vars() {
            if REAL_ENV.contains(&k.as_str()) || REAL_ENV_PREFIXES.iter().any(|p| k.starts_with(p)) {
                cmd.env(k, v);
            }
        }
        for k in std::env::var("SUPERBOT_E2E_PASS_ENV").unwrap_or_default().split(',').map(str::trim).filter(|k| !k.is_empty()) {
            if let Ok(v) = std::env::var(k) {
                cmd.env(k, v);
            }
        }
        None
    } else {
        let m = fake_model();
        let home = dir.join("home");
        cmd.env("HOME", &home).env("LANG", "C.UTF-8");
        fake_login(harness, &home, m.port, &mut cmd);
        Some(m)
    };
    let log = std::fs::File::create(dir.join("botd.log")).unwrap();
    // Its own session, so `stop` can find what its runs leave behind.
    // SAFETY: setsid is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let child = cmd
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("AUTH_PASSWORD", PASSWORD)
        .env("SUPERBOT_MASTER_KEY", "ab".repeat(32))
        .env("DATA_DIR", dir.join("data"))
        .env("WORKSPACE_DIR", dir.join("workspace"))
        .env("DEFAULT_HARNESS", harness)
        .env("SCREENS", "off")
        .env("TESTING_MODE", "on")
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("start botd");
    let b = Botd { child, port, dir, model };
    wait_for("botd to start", Duration::from_secs(30), || (http(&b, "GET", "/healthz", "").0 == 200).then_some(()));
    b
}

/// Points `harness` at the fake model through its own custom-endpoint setting, with a
/// dummy key: the same settings an operator would use for a self-hosted model.
pub fn fake_login(harness: &str, home: &Path, port: u16, cmd: &mut Command) {
    let base = format!("http://127.0.0.1:{port}");
    match harness {
        "claude" => {
            cmd.env("ANTHROPIC_BASE_URL", &base)
                .env("ANTHROPIC_API_KEY", KEY)
                .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
                .env("DISABLE_AUTOUPDATER", "1");
        }
        "codex" => {
            std::fs::create_dir_all(home.join(".codex")).unwrap();
            let config = format!(
                "model = \"{MODEL}\"\nmodel_provider = \"e2e\"\n\n[model_providers.e2e]\nname = \"e2e\"\nbase_url = \"{base}/v1\"\nwire_api = \"responses\"\nenv_key = \"E2E_MODEL_KEY\"\nrequest_max_retries = 0\nstream_max_retries = 0\n"
            );
            // An MCP server with one tool, so MCP calls go through the hook too.
            std::fs::write(home.join("e2e-mcp.py"), MCP_SERVER).unwrap();
            let config = format!("{config}\n[mcp_servers.e2e]\ncommand = \"python3\"\nargs = [{:?}]\n", home.join("e2e-mcp.py").display().to_string());
            std::fs::write(home.join(".codex/config.toml"), config).unwrap();
            cmd.env("E2E_MODEL_KEY", KEY);
        }
        "pi" => {
            let agent = home.join(".pi/agent");
            std::fs::create_dir_all(&agent).unwrap();
            let models = json!({ "providers": { "e2e": { "baseUrl": format!("{base}/v1"), "api": "openai-completions", "apiKey": KEY, "models": [{ "id": MODEL, "name": "E2E" }] } } });
            std::fs::write(agent.join("models.json"), models.to_string()).unwrap();
            std::fs::write(agent.join("settings.json"), json!({ "defaultProvider": "e2e", "defaultModel": MODEL }).to_string()).unwrap();
            cmd.env("PI_OFFLINE", "1").env("PI_SKIP_VERSION_CHECK", "1").env("PI_TELEMETRY", "0");
        }
        "hermes" => {
            cmd.env("SUPERBOT_HERMES_PROVIDER", "custom").env("SUPERBOT_HERMES_BASE_URL", format!("{base}/v1")).env("OPENAI_API_KEY", KEY);
        }
        h => panic!("no fake login for {h}"),
    }
}

/// A stdio MCP server whose one tool, `touch`, creates the file it's given.
pub const MCP_SERVER: &str = r#"import json, pathlib, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if "id" not in m:
        continue
    method, r = m.get("method"), {}
    if method == "initialize":
        r = {"protocolVersion": m["params"].get("protocolVersion", "2025-06-18"), "capabilities": {"tools": {}}, "serverInfo": {"name": "e2e", "version": "1"}}
    elif method == "tools/list":
        schema = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
        r = {"tools": [{"name": "touch", "description": "Creates an empty file.", "inputSchema": schema}]}
    elif method == "tools/call":
        path = m["params"]["arguments"]["path"]
        pathlib.Path(path).touch()
        r = {"content": [{"type": "text", "text": "touched " + path}]}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}) + "\n")
    sys.stdout.flush()
"#;

pub fn http(b: &Botd, method: &str, path: &str, body: &str) -> (u16, String) {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", b.port)) else { return (0, String::new()) };
    use base64::Engine;
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("e2e:{PASSWORD}"));
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

pub fn call(b: &Botd, method: &str, path: &str, body: Value) -> Value {
    let (code, text) = http(b, method, path, &if body.is_null() { String::new() } else { body.to_string() });
    assert!((200..300).contains(&code), "{method} {path}: {code} {text}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

pub fn wait_for<T>(what: &str, limit: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(start.elapsed() < limit, "timed out after {limit:?} waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

pub fn details(e: &Value) -> Value {
    match &e["details"] {
        Value::String(s) => serde_json::from_str(s).unwrap_or_default(),
        d => d.clone(),
    }
}

pub fn audit(b: &Botd, action: &str) -> Vec<Value> {
    call(b, "GET", &format!("/api/audit?action={action}&limit=200"), Value::Null)["events"].as_array().cloned().unwrap_or_default()
}

/// One run: what the Bot replied, how it ended, and the approvals it asked for.
pub struct Run {
    pub text: String,
    pub result: String,
    pub approvals: Vec<Value>,
}

/// Sends `prompt`, answers each approval with `decide` ("approve" or "deny"), and waits
/// for `bot.run_finished` for this message. Each approval is held open a moment first,
/// and `held` checks the call hasn't happened while the run waits on it.
pub fn run(b: &Botd, bot: &str, prompt: &str, decide: Option<&str>, held: &dyn Fn()) -> Run {
    let before = call(b, "GET", &format!("/api/bots/{bot}/messages"), Value::Null).as_array().unwrap().len();
    let msg = call(b, "POST", &format!("/api/bots/{bot}/messages"), json!({ "text": prompt }));
    let id = msg["id"].clone();
    let mut approvals: Vec<Value> = Vec::new();
    let limit = Duration::from_secs(if real() { 300 } else { 120 });
    let done = || audit(b, "bot.run_finished").into_iter().map(|e| details(&e)).find(|d| d["messageId"] == id);
    let finished = wait_for("the run to finish", limit, || {
        for a in call(b, "GET", "/api/approvals?status=pending", Value::Null).as_array().cloned().unwrap_or_default() {
            if a["botId"] != bot || approvals.iter().any(|x| x["id"] == a["id"]) {
                continue;
            }
            if let Some(d) = decide {
                std::thread::sleep(Duration::from_secs(2));
                assert!(done().is_none(), "the run finished while an approval was pending: {a}");
                held();
                call(b, "POST", &format!("/api/approvals/{}/{d}", a["id"].as_str().unwrap()), json!({}));
            }
            approvals.push(a);
        }
        done()
    });
    let msgs = call(b, "GET", &format!("/api/bots/{bot}/messages"), Value::Null);
    let text = msgs.as_array().unwrap()[before..].iter().filter(|m| m["role"] == "bot").map(|m| m["text"].as_str().unwrap_or_default()).collect::<Vec<_>>().join("\n");
    Run { text, result: finished["result"].as_str().unwrap_or_default().to_string(), approvals }
}

pub fn prompt(cmd: &str) -> String {
    if real() {
        format!(
            "This is an automated test of an approval gate. Use your shell tool to run exactly this command, once, unchanged: `{cmd}`\n\
             Run nothing else. If it is blocked or fails, don't retry or try another way; reply with what happened."
        )
    } else {
        format!("{}{cmd}{}", RUN.0, RUN.1)
    }
}
