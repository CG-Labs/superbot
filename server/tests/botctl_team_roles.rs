//! End to end (ADR 0311): a team's owner signs in with `botctl login` and, with the real
//! `botctl team` commands against the real `botd`, lists the roles they may give, gives
//! and takes one in their team, and decides their team's requests for roles. The server
//! admins' `botctl role` commands refuse them and point at `botctl team`; a plain member
//! is refused `botctl team requests`. Decisions are audited as the team's.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "e2e-password";

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

fn start() -> Botd {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dir = std::env::temp_dir().join(format!("botd-team-roles-{}-{port}", std::process::id()));
    for d in ["data", "workspace", "home"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let child = Command::new(env!("CARGO_BIN_EXE_botd"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
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
        .stdin(Stdio::null())
        .spawn()
        .expect("start botd");
    let mut b = Botd { child, port, dir };
    let deadline = Instant::now() + Duration::from_secs(30);
    while http(&b, "GET", "/healthz", "").0 != 200 {
        assert!(b.child.try_wait().unwrap().is_none() && Instant::now() < deadline, "botd didn't start:\n{}", b.log());
        std::thread::sleep(Duration::from_millis(50));
    }
    b
}

impl Botd {
    fn log(&self) -> String {
        ["stdout.log", "stderr.log"].map(|f| std::fs::read_to_string(self.dir.join(f)).unwrap_or_default()).join("\n")
    }
}

/// One request with the break-glass password, as a server admin.
fn http(b: &Botd, method: &str, path: &str, body: &str) -> (u16, String) {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", b.port)) else { return (0, String::new()) };
    use base64::Engine;
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("superbot:{PASSWORD}"));
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

fn admin(b: &Botd, method: &str, path: &str, body: Value) -> Value {
    let (code, text) = http(b, method, path, &body.to_string());
    assert!((200..300).contains(&code), "{method} {path}: {code} {text}");
    serde_json::from_str(&text).unwrap()
}

/// What `botctl` printed on stdout, or on stderr when it failed, and whether it succeeded.
fn botctl(b: &Botd, token: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_botctl"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("BOT_API", format!("http://127.0.0.1:{}", b.port))
        .env("SUPERBOT_TOKEN", token)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run botctl");
    let ok = out.status.success();
    (ok, String::from_utf8_lossy(if ok { &out.stdout } else { &out.stderr }).trim().to_string())
}

fn ok(b: &Botd, token: &str, args: &[&str]) -> String {
    let (ok, out) = botctl(b, token, args);
    assert!(ok, "botctl {args:?}: {out}");
    out
}

fn refused(b: &Botd, token: &str, args: &[&str]) -> String {
    let (ok, out) = botctl(b, token, args);
    assert!(!ok, "botctl {args:?} should fail: {out}");
    out
}

/// Makes a member and signs them in with `botctl login` and a one-time code from an admin.
/// Returns their id and session token.
fn person(b: &Botd, email: &str) -> (String, String) {
    let id = admin(b, "POST", "/api/users", json!({ "email": email, "role": "member" }))["id"].as_str().unwrap().to_string();
    let code = admin(b, "POST", &format!("/api/users/{id}/login-codes"), json!({}))["code"].as_str().unwrap().to_string();
    let out = ok(b, "", &["login", &code]);
    let token = out.split("export SUPERBOT_TOKEN=").nth(1).and_then(|t| t.split_whitespace().next()).unwrap_or_else(|| panic!("no token in: {out}"));
    (id, token.to_string())
}

/// The request id `botctl role request` printed, in "(rq...)".
fn request_id(said: &str) -> String {
    said.split('(').nth(1).and_then(|s| s.split(')').next()).unwrap_or_else(|| panic!("no request id in: {said}")).to_string()
}

fn audited(b: &Botd, action: &str) -> Vec<Value> {
    let v = admin(b, "GET", &format!("/api/audit?action={action}&limit=50"), Value::Null);
    v["events"].as_array().cloned().unwrap_or_default()
}

fn details(e: &Value) -> Value {
    match &e["details"] {
        Value::String(s) => serde_json::from_str(s).unwrap_or_default(),
        d => d.clone(),
    }
}

#[test]
fn a_team_owner_gives_roles_and_decides_requests_with_botctl() {
    let b = start();
    let (olu_id, olu) = person(&b, "olu@example.com");
    let (_, ada) = person(&b, "ada@example.com");
    let (_, bea) = person(&b, "bea@example.com");
    let team = admin(&b, "POST", "/api/teams", json!({ "name": "Ops", "owner": "olu@example.com" }));
    let team_id = team["id"].as_str().unwrap().to_string();
    for who in ["ada@example.com", "bea@example.com"] {
        admin(&b, "PUT", &format!("/api/teams/{team_id}/members/{who}"), json!({ "role": "member" }));
    }
    admin(&b, "POST", "/api/roles", json!({ "name": "Team helpdesk", "permissions": ["users.manage", "audit.view"] }));
    admin(&b, "POST", "/api/roles", json!({ "name": "On-call", "permissions": ["machines.manage"], "maxDays": 1, "requestable": true }));
    admin(&b, "POST", "/api/roles", json!({ "name": "Auditor", "permissions": ["audit.view"] }));

    // The owner sees only roles that add something in a team, with what they add there.
    let roles = ok(&b, &olu, &["team", "roles"]);
    assert_eq!(roles, "Roles you may give in Ops:\n  On-call: machines.manage (time-bound: give it --for at most 1 day)\n  Team helpdesk: users.manage", "{roles}");
    assert!(ok(&b, &ada, &["team", "roles"]).starts_with("Only Ops's owners and admins"));

    // Gives a role in the team and takes it away, without a server admin.
    let given = ok(&b, &olu, &["team", "role", "assign", "Team helpdesk", "ada@example.com", "--reason", "Onboarding week"]);
    assert_eq!(given, "ada@example.com has Team helpdesk in Ops. There it gives: users.manage.");
    let assigned = &audited(&b, "role.assigned")[0];
    let d = details(assigned);
    assert_eq!((assigned["actorId"].as_str(), d["via"].as_str(), d["team"].as_str(), d["reason"].as_str()), (Some(olu_id.as_str()), Some("team"), Some(team_id.as_str()), Some("Onboarding week")), "{assigned}");
    assert!(refused(&b, &olu, &["team", "role", "assign", "Team helpdesk", "olu@example.com"]).contains("(HTTP 409)"), "never to themselves");
    assert!(refused(&b, &olu, &["team", "role", "assign", "Auditor", "bea@example.com"]).contains("(HTTP 409)"), "Auditor adds nothing in a team");
    assert!(refused(&b, &olu, &["team", "role", "assign", "On-call", "bea@example.com", "--for", "2d"]).contains("(HTTP 400)"), "beyond its limit");
    assert_eq!(ok(&b, &olu, &["team", "role", "unassign", "ada@example.com"]), "Taken away from ada@example.com in Ops.");

    // The server admins' commands refuse them, and say what to use instead.
    let e = refused(&b, &olu, &["role", "assign", "Team helpdesk", "bea@example.com", "--team", &team_id]);
    assert!(e.contains("(HTTP 403)") && e.ends_with("In your own team, as one of its owners or admins: botctl team role assign <role> <user>"), "{e}");
    let e = refused(&b, &olu, &["role", "requests"]);
    assert!(e.ends_with("botctl team requests"), "{e}");

    // Teammates ask; the owner sees the team's requests and decides them.
    let ada_q = request_id(&ok(&b, &ada, &["role", "request", "On-call", "--team", "--for", "8h", "--reason", "Incident 42"]));
    let bea_q = request_id(&ok(&b, &bea, &["role", "request", "On-call", "--team", "--for", "4h", "--reason", "Cover"]));
    assert!(ok(&b, &olu, &["team", "roles"]).ends_with("2 requests wait for a decision: botctl team requests"));
    let pending: Value = serde_json::from_str(&ok(&b, &olu, &["team", "requests"])).unwrap();
    assert_eq!((pending["team"]["name"].as_str(), pending["pending"].as_i64(), pending["requests"].as_array().map(Vec::len)), (Some("Ops"), Some(2), Some(2)), "{pending}");
    assert!(refused(&b, &ada, &["team", "requests"]).contains("(HTTP 403)"), "a plain member decides nothing");
    assert!(refused(&b, &ada, &["team", "deny", &bea_q]).contains("(HTTP 403)"));

    let approved = ok(&b, &olu, &["team", "approve", &ada_q, "--for", "2h", "--note", "Two is enough"]);
    assert!(approved.starts_with("Approved. ada@example.com has On-call in Ops until "), "{approved}");
    let denied = ok(&b, &olu, &["team", "deny", &bea_q, "--note", "Ada has it"]);
    assert_eq!(denied, "Denied bea@example.com's request for On-call in Ops.");
    assert!(refused(&b, &olu, &["team", "approve", &bea_q]).contains("(HTTP 409)"), "decided already");
    let all: Value = serde_json::from_str(&ok(&b, &olu, &["team", "requests", "all"])).unwrap();
    assert_eq!((all["pending"].as_i64(), all["requests"].as_array().map(Vec::len)), (Some(0), Some(2)), "{all}");

    let a = &audited(&b, "role.request_approved")[0];
    let d = details(a);
    assert_eq!((a["actorId"].as_str(), d["via"].as_str(), d["hours"].as_i64(), d["requestedHours"].as_i64(), d["note"].as_str()), (Some(olu_id.as_str()), Some("team"), Some(2), Some(8), Some("Two is enough")), "{a}");
    let denied = &audited(&b, "role.request_denied")[0];
    let d = details(denied);
    assert_eq!((denied["actorId"].as_str(), d["via"].as_str(), d["note"].as_str()), (Some(olu_id.as_str()), Some("team"), Some("Ada has it")), "{denied}");
}
