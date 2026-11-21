//! End to end (ADR 0079): the real `botd` on the shipped example tiers gives new Bots on a
//! managed plan Hermes Agent, though `DEFAULT_HARNESS` is claude; refuses their runs, and
//! says why, while Hermes isn't installed; and moves older Bots only when an admin asks.
//! Without a tiers file nothing changes. A stub `hermes`; no network, no credentials.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "e2e-password";

const STUB: &str = r#"#!/bin/sh
[ "$1" = gateway ] && exit 0
cat >/dev/null
printf '%s\n' '{"type":"result","session_id":"s1","exit_code":0,"text":"Hermes ran."}'
"#;

struct Botd {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Botd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Botd {
    fn stub(&self) -> PathBuf {
        self.dir.join("stub")
    }

    fn log(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join(name)).unwrap_or_default()
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start(tiers: bool) -> Botd {
    let dir = std::env::temp_dir().join(format!("botd-managed-default-{}-{}", std::process::id(), free_port()));
    for d in ["data", "workspace", "home", "stub"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_botd"));
    cmd.env_clear()
        .env("PATH", format!("{}:{}", dir.join("stub").display(), std::env::var("PATH").unwrap_or_default()))
        .env("HOME", dir.join("home"))
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("AUTH_PASSWORD", PASSWORD)
        .env("SUPERBOT_MASTER_KEY", "ab".repeat(32))
        .env("DATA_DIR", dir.join("data"))
        .env("WORKSPACE_DIR", dir.join("workspace"))
        .env("DEFAULT_HARNESS", "claude")
        .env("SCREENS", "off")
        .env("TESTING_MODE", "on")
        .stdout(std::fs::File::create(dir.join("stdout.log")).unwrap())
        .stderr(std::fs::File::create(dir.join("stderr.log")).unwrap())
        .stdin(Stdio::null());
    if tiers {
        cmd.env("TIERS_FILE", concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/tiers.example.json"));
    }
    let b = Botd { child: cmd.spawn().expect("start botd"), port, dir };
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

fn call(b: &Botd, method: &str, path: &str, body: Value, want: u16) -> Value {
    let (code, res) = http(b, method, path, &body.to_string());
    assert_eq!(code, want, "{method} {path}: {res}");
    serde_json::from_str(&res).unwrap_or(Value::Null)
}

fn get(b: &Botd, path: &str) -> Value {
    call(b, "GET", path, Value::Null, 200)
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

/// Sends a message and waits for the Bot's reply.
fn ask(b: &Botd, bot: &str) -> String {
    let path = format!("/api/bots/{bot}/messages");
    let before = get(b, &path).as_array().unwrap().len();
    call(b, "POST", &path, json!({ "text": "go" }), 202);
    wait_for("a reply", || {
        let msgs = get(b, &path);
        let reply = msgs.as_array().unwrap()[before..].iter().find(|m| m["role"] == "bot").cloned()?;
        let idle = !get(b, "/api/state")["bots"].as_array().unwrap().iter().any(|x| x["id"] == bot && x["working"] == true);
        idle.then(|| reply["text"].as_str().unwrap_or_default().to_string())
    })
}

fn audit(b: &Botd, q: &str) -> Vec<Value> {
    get(b, &format!("/api/audit?{q}&limit=100"))["events"].as_array().cloned().unwrap_or_default()
}

fn primary(b: &Botd) -> Value {
    get(b, "/api/bots").as_array().unwrap()[0].clone()
}

fn on_system_path(bin: &str) -> bool {
    std::env::var("PATH").unwrap_or_default().split(':').any(|d| std::path::Path::new(d).join(bin).is_file())
}

#[test]
fn self_host_keeps_default_harness() {
    let b = start(false);
    assert_eq!(primary(&b)["harness"], "claude");
    assert_eq!(get(&b, "/api/state")["defaultHarness"], "claude");
    assert_eq!(call(&b, "POST", "/api/bots", json!({ "name": "New" }), 201)["harness"], "claude");
    call(&b, "POST", "/api/tiers/self-host/move-bots", json!({}), 400);
    assert!(!b.log("stdout.log").contains("New Bots:"), "nothing to say without managed tiers");
}

#[test]
fn managed_plans_default_to_hermes() {
    use std::os::unix::fs::PermissionsExt;
    let b = start(true);
    let stdout = b.log("stdout.log");
    assert!(stdout.contains("New Bots: hermes on the starter, pro, max plans; claude on open tiers (DEFAULT_HARNESS)"), "{stdout}");

    // The operator is on the default plan, starter: the first Bot runs on Hermes.
    let bot = primary(&b);
    assert_eq!(bot["harness"], "hermes");
    let id = bot["id"].as_str().unwrap().to_string();
    assert_eq!(get(&b, "/api/state")["defaultHarness"], "hermes");
    let started = &audit(&b, "action=server.started")[0]["details"];
    assert_eq!((started["tierHarnesses"]["pro"].as_str(), started["tierHarnesses"]["self-host"].as_str()), (Some("hermes"), None));

    // Not installed: refused up front, and why.
    if !on_system_path("hermes") {
        assert!(b.log("stderr.log").contains("hermes, which isn't installed on this server"), "{}", b.log("stderr.log"));
        let said = ask(&b, &id);
        assert!(said.contains("hermes isn't installed on this server"), "{said}");
        let refused = audit(&b, &format!("action=bot.run_refused&bot={id}"));
        assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["tier"].as_str()), (Some("harness_missing"), Some("starter")));
    }
    // Installed: it runs.
    std::fs::write(b.stub().join("hermes"), STUB).unwrap();
    std::fs::set_permissions(b.stub().join("hermes"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(ask(&b, &id), "Hermes ran.");

    // On the open tier, the server's default.
    call(&b, "PATCH", "/api/users/operator", json!({ "tier": "self-host" }), 200);
    assert_eq!(get(&b, "/api/state")["defaultHarness"], "claude");
    let older = call(&b, "POST", "/api/bots", json!({ "name": "Older" }), 201);
    assert_eq!(older["harness"], "claude");
    let older = older["id"].as_str().unwrap().to_string();

    // Back on starter, that Bot keeps Claude until an admin moves it.
    call(&b, "PATCH", "/api/users/operator", json!({ "tier": null }), 200);
    let harness = |id: &str| get(&b, "/api/bots").as_array().unwrap().iter().find(|x| x["id"] == id).unwrap()["harness"].clone();
    assert_eq!(harness(&older), "claude");
    let dry = call(&b, "POST", "/api/tiers/starter/move-bots", json!({ "dryRun": true }), 200);
    assert_eq!(dry["moved"], json!([{ "id": older, "name": "Older", "owner": "operator", "from": "claude" }]));
    assert_eq!(harness(&older), "claude");
    let done = call(&b, "POST", "/api/tiers/starter/move-bots", json!({}), 200);
    assert_eq!(done["moved"].as_array().unwrap().len(), 1);
    assert_eq!(harness(&older), "hermes");
    let moved = audit(&b, "action=tier.bots_moved");
    assert_eq!((moved[0]["details"]["to"].as_str(), moved[0]["details"]["moved"].as_u64()), (Some("hermes"), Some(1)));
    assert_eq!(ask(&b, &older), "Hermes ran.");
}
