//! Approvals end to end through each real harness CLI (approvals follow-up 1, ADR 0056):
//! the real `botd` and `botctl` run Claude Code, Codex, Pi, and Hermes Agent with the hook
//! each adapter installs, and four calls go through it: an allowed one runs, one a deny
//! rule blocks never runs, and two `git push`es wait for a person, then run once approved
//! or fail once denied.
//!
//! By default the model is a fake (`FakeModel`) that each CLI reaches through its own
//! custom-endpoint setting, so everything but the model is real and no login is needed.
//! `SUPERBOT_E2E_MODEL=real` uses the harnesses' own logins and models instead
//! (`deploy/harness-e2e.sh` on a server). Ignored by `cargo test`; the `harness-e2e`
//! workflow installs the pinned CLIs (`deploy/install-harness-clis.sh`) and runs them
//! with `--ignored`.
//!
//! - `SUPERBOT_E2E_HARNESSES`: which to run (default: all).
//! - `SUPERBOT_E2E_REQUIRE=1`: a missing CLI fails instead of being skipped.
//! - `SUPERBOT_E2E_PASS_ENV`: in real mode, extra variables to hand to botd by name.
//! - `SUPERBOT_E2E_BOT_MODEL`: in real mode, the Bot's model (else the harness's default).

use axum::body::Bytes;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PASSWORD: &str = "e2e-password";
const MODEL: &str = "e2e-model";
const KEY: &str = "e2e-key";
/// How the prompt names the one command the fake model runs.
const RUN: (&str, &str) = ("E2E-RUN<<", ">>");
/// The fake model's reply once the command's result is back.
const DONE: &str = "E2E-DONE";

// ---------------------------------------------------------------------------------
// The fake model: Anthropic Messages (Claude Code), OpenAI Responses (Codex), and
// OpenAI Chat Completions (Pi, Hermes Agent). Stateless: each request carries the whole
// conversation, so it reads the newest prompt's command and whether a result came back.

struct FakeModel {
    port: u16,
}

enum Reply {
    Text(String),
    Call { name: String, args: Value },
}

/// What a request holds, whatever its format: prompts, tool results, and tools.
enum Turn {
    User(String),
    Result(String),
}

fn fake_model() -> FakeModel {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let ids = Arc::new(AtomicU64::new(1));
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.block_on(async move {
            let app = axum::Router::new().fallback(move |m: Method, u: Uri, b: Bytes| {
                let ids = ids.clone();
                async move { serve(&m, u.path(), &b, &ids) }
            });
            axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app).await.unwrap();
        });
    });
    FakeModel { port }
}

fn serve(method: &Method, path: &str, body: &[u8], ids: &AtomicU64) -> Response {
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

fn json_response(v: Value) -> Response {
    ([("content-type", "application/json")], v.to_string()).into_response()
}

fn sse(events: Vec<(Option<&str>, Value)>, done: bool) -> Response {
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
fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts.iter().map(|p| p["text"].as_str().map(String::from).unwrap_or_else(|| text_of(&p["content"]))).collect::<Vec<_>>().join("\n"),
        Value::Null => String::new(),
        v => v.to_string(),
    }
}

fn decide(turns: Vec<Turn>, tools: Vec<(String, Value)>) -> Reply {
    // Side requests (titles, summaries) offer no tools.
    if tools.is_empty() {
        return Reply::Text("ok".into());
    }
    let (mut cmd, mut result) = (None, None);
    for t in turns {
        match t {
            Turn::User(s) => {
                if let Some(c) = s.rfind(RUN.0).and_then(|i| s[i + RUN.0.len()..].split_once(RUN.1)).map(|(c, _)| c.to_string()) {
                    (cmd, result) = (Some(c), None);
                }
            }
            Turn::Result(r) if cmd.is_some() => result = Some(r),
            Turn::Result(_) => {}
        }
    }
    match (cmd, result) {
        (Some(_), Some(r)) => Reply::Text(format!("{DONE} {}", r.chars().take(600).collect::<String>())),
        (Some(c), None) => {
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

fn anthropic_turns(req: &Value) -> Vec<Turn> {
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

fn anthropic_tools(req: &Value) -> Vec<(String, Value)> {
    req["tools"].as_array().into_iter().flatten().filter_map(|t| Some((t["name"].as_str()?.to_string(), t["input_schema"].clone()))).collect()
}

fn anthropic(reply: Reply, stream: bool, id: u64) -> Response {
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

fn responses_turns(req: &Value) -> Vec<Turn> {
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

fn responses_tools(req: &Value) -> Vec<(String, Value)> {
    req["tools"].as_array().into_iter().flatten().filter_map(|t| Some((t["name"].as_str()?.to_string(), t["parameters"].clone()))).collect()
}

fn responses(reply: Reply, stream: bool, id: u64) -> Response {
    let item = match reply {
        Reply::Text(t) => json!({ "type": "message", "id": format!("msg_e2e{id}"), "role": "assistant", "status": "completed", "content": [{ "type": "output_text", "text": t, "annotations": [] }] }),
        Reply::Call { name, args } => json!({ "type": "function_call", "id": format!("fc_e2e{id}"), "call_id": format!("call_e2e{id}"), "name": name, "arguments": args.to_string(), "status": "completed" }),
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

fn chat_turns(req: &Value) -> Vec<Turn> {
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

fn chat_tools(req: &Value) -> Vec<(String, Value)> {
    req["tools"].as_array().into_iter().flatten().filter_map(|t| Some((t["function"]["name"].as_str()?.to_string(), t["function"]["parameters"].clone()))).collect()
}

fn chat(reply: Reply, stream: bool, id: u64) -> Response {
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

struct Botd {
    child: Child,
    port: u16,
    dir: PathBuf,
    _model: Option<FakeModel>,
}

impl Drop for Botd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!("--- botd log ({}) ---\n{}", self.dir.display(), tail(&read(&self.dir.join("botd.log")), 80));
            eprintln!("(kept {} for a look)", self.dir.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

fn real() -> bool {
    std::env::var("SUPERBOT_E2E_MODEL").is_ok_and(|m| m == "real")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(bin)).find(|f| f.is_file()))
}

/// Whether to run `harness`: listed (or no list), and its CLI on PATH. Missing is a
/// failure under `SUPERBOT_E2E_REQUIRE=1`.
fn wanted(harness: &str, bin: &str) -> bool {
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
const REAL_ENV_PREFIXES: [&str; 16] = [
    "ANTHROPIC_", "CLAUDE_", "OPENAI_", "CODEX_", "PI_", "HERMES_", "SUPERBOT_HERMES_", "OPENROUTER_", "NOUS_", "GEMINI_", "GOOGLE_", "XAI_",
    "DEEPSEEK_", "MISTRAL_", "GROQ_", "AWS_",
];
const REAL_ENV: [&str; 11] = ["HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "SHELL"];

fn start(harness: &str) -> Botd {
    let dir = std::env::temp_dir().join(format!("botd-harness-e2e-{harness}-{}-{}", std::process::id(), free_port()));
    for d in ["data", "workspace", "home", "proof"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_botd"));
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
    let child = cmd
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("AUTH_PASSWORD", PASSWORD)
        .env("SUPERBOT_MASTER_KEY", "ab".repeat(32))
        .env("DATA_DIR", dir.join("data"))
        .env("WORKSPACE_DIR", dir.join("workspace"))
        .env("DEFAULT_HARNESS", harness)
        .env("SCREENS", "off")
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("start botd");
    let b = Botd { child, port, dir, _model: model };
    wait_for("botd to start", Duration::from_secs(30), || (http(&b, "GET", "/healthz", "").0 == 200).then_some(()));
    b
}

/// Points `harness` at the fake model through its own custom-endpoint setting, with a
/// dummy key: the same settings an operator would use for a self-hosted model.
fn fake_login(harness: &str, home: &Path, port: u16, cmd: &mut Command) {
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
            // Each Bot's Hermes builds its runtime from uv's cache; share the installer's.
            if let Ok(cache) = std::env::var("UV_CACHE_DIR") {
                cmd.env("UV_CACHE_DIR", cache);
            } else if let Some(h) = std::env::var_os("HOME") {
                cmd.env("UV_CACHE_DIR", PathBuf::from(h).join(".cache/uv"));
            }
            cmd.env("SUPERBOT_HERMES_PROVIDER", "custom").env("SUPERBOT_HERMES_BASE_URL", format!("{base}/v1")).env("OPENAI_API_KEY", KEY);
        }
        h => panic!("no fake login for {h}"),
    }
}

fn http(b: &Botd, method: &str, path: &str, body: &str) -> (u16, String) {
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

fn call(b: &Botd, method: &str, path: &str, body: Value) -> Value {
    let (code, text) = http(b, method, path, &if body.is_null() { String::new() } else { body.to_string() });
    assert!((200..300).contains(&code), "{method} {path}: {code} {text}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

fn wait_for<T>(what: &str, limit: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(start.elapsed() < limit, "timed out after {limit:?} waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn details(e: &Value) -> Value {
    match &e["details"] {
        Value::String(s) => serde_json::from_str(s).unwrap_or_default(),
        d => d.clone(),
    }
}

fn audit(b: &Botd, action: &str) -> Vec<Value> {
    call(b, "GET", &format!("/api/audit?action={action}&limit=200"), Value::Null)["events"].as_array().cloned().unwrap_or_default()
}

/// One run: what the Bot replied, how it ended, and the approvals it asked for.
struct Run {
    text: String,
    result: String,
    approvals: Vec<Value>,
}

/// Sends `prompt`, answers each approval with `decide` ("approve" or "deny"), and waits
/// for `bot.run_finished` for this message.
fn run(b: &Botd, bot: &str, prompt: &str, decide: Option<&str>) -> Run {
    let before = call(b, "GET", &format!("/api/bots/{bot}/messages"), Value::Null).as_array().unwrap().len();
    let msg = call(b, "POST", &format!("/api/bots/{bot}/messages"), json!({ "text": prompt }));
    let id = msg["id"].clone();
    let mut approvals: Vec<Value> = Vec::new();
    let limit = Duration::from_secs(if real() { 300 } else { 120 });
    let finished = wait_for("the run to finish", limit, || {
        for a in call(b, "GET", "/api/approvals?status=pending", Value::Null).as_array().cloned().unwrap_or_default() {
            if a["botId"] != bot || approvals.iter().any(|x| x["id"] == a["id"]) {
                continue;
            }
            if let Some(d) = decide {
                call(b, "POST", &format!("/api/approvals/{}/{d}", a["id"].as_str().unwrap()), json!({}));
            }
            approvals.push(a);
        }
        audit(b, "bot.run_finished").into_iter().map(|e| details(&e)).find(|d| d["messageId"] == id)
    });
    let msgs = call(b, "GET", &format!("/api/bots/{bot}/messages"), Value::Null);
    let text = msgs.as_array().unwrap()[before..].iter().filter(|m| m["role"] == "bot").map(|m| m["text"].as_str().unwrap_or_default()).collect::<Vec<_>>().join("\n");
    Run { text, result: finished["result"].as_str().unwrap_or_default().to_string(), approvals }
}

fn prompt(cmd: &str) -> String {
    if real() {
        format!(
            "This is an automated test of an approval gate. Use your shell tool to run exactly this command, once, unchanged: `{cmd}`\n\
             Run nothing else. If it is blocked or fails, don't retry or try another way; reply with what happened."
        )
    } else {
        format!("{}{cmd}{}", RUN.0, RUN.1)
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git").current_dir(dir).args(["-c", "user.name=e2e", "-c", "user.email=e2e@example.invalid", "-c", "init.defaultBranch=main"]).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn has_ref(remote: &Path, name: &str) -> bool {
    Command::new("git").arg("-C").arg(remote).args(["rev-parse", "--verify", "--quiet", &format!("refs/heads/{name}")]).stdout(std::process::Stdio::null()).status().unwrap().success()
}

/// The four calls, in one Bot's session (each prompt resumes it).
fn approvals_hold(harness: &str, bin: &str) {
    if !wanted(harness, bin) {
        return;
    }
    let b = start(harness);
    let bot = call(&b, "GET", "/api/bots", Value::Null)[0].clone();
    assert_eq!(bot["harness"], harness);
    let id = bot["id"].as_str().unwrap().to_string();
    assert_eq!(call(&b, "GET", "/api/policy", Value::Null)["policy"]["mode"], "ask", "a fresh install asks");
    // The sandbox (ADR 0055) is another layer and depends on the host; keep it out of
    // the way of the pushes to a folder outside the workspace.
    call(&b, "PUT", "/api/policy", json!({ "sandbox": false }));
    call(&b, "POST", "/api/policy/rules", json!({ "action": "deny", "tool": "shell", "pattern": "*e2e-forbidden*" }));
    // Hermes refuses a session without a model, and the fake endpoint has no default.
    let model = if real() { std::env::var("SUPERBOT_E2E_BOT_MODEL").ok().filter(|m| !m.is_empty()) } else { (harness == "hermes").then(|| MODEL.to_string()) };
    if let Some(m) = model {
        call(&b, "PATCH", &format!("/api/bots/{id}"), json!({ "model": m }));
    }
    let proof = std::fs::canonicalize(b.dir.join("proof")).unwrap();
    git(&proof, &["init", "-q", "--bare", "remote.git"]);
    git(&proof, &["init", "-q", "repo"]);
    let repo = proof.join("repo");
    std::fs::write(repo.join("README"), "e2e\n").unwrap();
    git(&repo, &["add", "README"]);
    git(&repo, &["commit", "-q", "-m", "e2e"]);
    git(&repo, &["remote", "add", "origin", "../remote.git"]);
    let remote = proof.join("remote.git");
    let pass = |what: &str| println!("PASS {harness}: {what}");

    // Allowed: no class, no rule. It runs, through the hook (the canary would stop a
    // shell call that skipped it).
    let marker = proof.join("allowed.marker");
    let r = run(&b, &id, &prompt(&format!("touch {}", marker.display())), None);
    assert!(r.approvals.is_empty(), "{harness}: an allowed call asked: {:?}", r.approvals);
    assert_ne!(r.result, "unguarded", "{harness} ran a shell command without the hook: {}", r.text);
    assert!(marker.exists(), "{harness}: the allowed command didn't run (result {}): {}", r.result, r.text);
    if !real() {
        assert!(r.text.contains(DONE), "{harness}: no reply after the command: {}", r.text);
    }
    pass("an allowed call runs without asking");

    // Blocked by policy: a deny rule, decided at once. The command never runs and the
    // agent is told why.
    let forbidden = proof.join("e2e-forbidden.marker");
    let r = run(&b, &id, &prompt(&format!("touch {}", forbidden.display())), None);
    assert!(r.approvals.is_empty(), "{harness}: a denied call asked: {:?}", r.approvals);
    assert!(!forbidden.exists(), "{harness}: a call the policy denies ran: {}", r.text);
    let denied = audit(&b, "policy.denied").into_iter().map(|e| details(&e)).find(|d| d["subject"].as_str().unwrap_or_default().contains("e2e-forbidden"));
    let denied = denied.unwrap_or_else(|| panic!("{harness}: the hook never sent the denied call (result {}): {}", r.result, r.text));
    assert_eq!(denied["harness"], harness);
    if !real() {
        assert!(r.text.contains(DONE) && r.text.contains("deny rule"), "{harness}: the agent wasn't told why: {}", r.text);
    }
    pass("a call the policy denies is blocked at once");

    // Needs approval: waits, then runs once approved.
    let push = |branch: &str| format!("git -C {} push origin HEAD:refs/heads/{branch}", repo.display());
    let r = run(&b, &id, &prompt(&push("e2e-approved")), Some("approve"));
    let [a] = r.approvals.as_slice() else { panic!("{harness}: wanted one approval, got {:?} (result {}): {}", r.approvals, r.result, r.text) };
    assert_eq!((a["harness"].as_str(), a["class"].as_str()), (Some(harness), Some("git_push")), "{a}");
    assert!(has_ref(&remote, "e2e-approved"), "{harness}: approved, but the push didn't happen (result {}): {}", r.result, r.text);
    if !real() {
        assert!(r.text.contains(DONE), "{harness}: no reply after the push: {}", r.text);
    }
    pass("a call that needs approval waits, and runs once approved");

    // Needs approval: waits, then fails once denied.
    let r = run(&b, &id, &prompt(&push("e2e-denied")), Some("deny"));
    let [a] = r.approvals.as_slice() else { panic!("{harness}: wanted one approval, got {:?} (result {}): {}", r.approvals, r.result, r.text) };
    assert_eq!(a["class"], "git_push", "{a}");
    assert!(!has_ref(&remote, "e2e-denied"), "{harness}: denied, but the push happened: {}", r.text);
    if !real() {
        assert!(r.text.contains(DONE) && r.text.to_lowercase().contains("denied"), "{harness}: the agent wasn't told: {}", r.text);
    }
    pass("a call that needs approval waits, and fails once denied");
}

#[test]
#[ignore = "needs the Claude Code CLI; see the harness-e2e workflow"]
fn claude_code_hooks_hold() {
    approvals_hold("claude", "claude");
}

#[test]
#[ignore = "needs the Codex CLI; see the harness-e2e workflow"]
fn codex_hooks_hold() {
    approvals_hold("codex", "codex");
}

#[test]
#[ignore = "needs the Pi CLI; see the harness-e2e workflow"]
fn pi_hooks_hold() {
    approvals_hold("pi", "pi");
}

#[test]
#[ignore = "needs the Hermes Agent CLI; see the harness-e2e workflow"]
fn hermes_hooks_hold() {
    approvals_hold("hermes", "hermes");
}

#[test]
fn the_fake_model_reads_each_format() {
    let tools = || vec![("Read".to_string(), json!({})), ("Bash".to_string(), json!({ "properties": { "command": {} } }))];
    let call_of = |r: Reply| match r {
        Reply::Call { name, args } => (name, args),
        Reply::Text(t) => panic!("{t}"),
    };
    // Newest prompt wins; a result after it ends the turn; an older result doesn't.
    let turns = vec![Turn::User("E2E-RUN<<ls>>".into()), Turn::Result("x".into()), Turn::User("then E2E-RUN<<git push>> please".into())];
    assert_eq!(call_of(decide(turns, tools())), ("Bash".into(), json!({ "command": "git push" })));
    let Reply::Text(t) = decide(vec![Turn::User("E2E-RUN<<ls>>".into()), Turn::Result("blocked: denied".into())], tools()) else { panic!() };
    assert_eq!(t, "E2E-DONE blocked: denied");
    let Reply::Text(t) = decide(vec![Turn::User("E2E-RUN<<ls>>".into())], vec![]) else { panic!() };
    assert_eq!(t, "ok", "side requests without tools get plain text");
    // Codex's exec_command takes `cmd`.
    let codex = vec![("exec_command".to_string(), json!({ "properties": { "cmd": {} } }))];
    assert_eq!(call_of(decide(vec![Turn::User("E2E-RUN<<ls>>".into())], codex)).1, json!({ "cmd": "ls" }));
    // Each format's conversation.
    let a = json!({ "messages": [{ "role": "user", "content": "E2E-RUN<<ls>>" }, { "role": "assistant", "content": [] },
        { "role": "user", "content": [{ "type": "tool_result", "content": [{ "type": "text", "text": "out" }] }] }] });
    assert!(matches!(anthropic_turns(&a).as_slice(), [Turn::User(_), Turn::Result(r)] if r == "out"));
    let r = json!({ "input": [{ "type": "message", "role": "user", "content": [{ "type": "input_text", "text": "E2E-RUN<<ls>>" }] },
        { "type": "function_call", "name": "exec_command" }, { "type": "function_call_output", "output": "out" }] });
    assert!(matches!(responses_turns(&r).as_slice(), [Turn::User(u), Turn::Result(o)] if u.contains("E2E-RUN") && o == "out"));
    let c = json!({ "messages": [{ "role": "system", "content": "E2E-RUN<<no>>" }, { "role": "user", "content": "E2E-RUN<<ls>>" }, { "role": "tool", "content": "out" }] });
    assert!(matches!(chat_turns(&c).as_slice(), [Turn::User(_), Turn::Result(o)] if o == "out"));
}
