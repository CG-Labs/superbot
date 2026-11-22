//! End to end (ADR 0104, SOC 2 CC7.2-1): the real `botd` notices a burst of failed
//! sign-ins from one IP and a sign-in that works right after it, writes each as an
//! `auth.suspicious_sign_in` audit event, and counts both in `/metrics` under the names
//! the shipped Prometheus rules alert on. Bad settings stop it from starting.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "e2e-password";

struct Botd {
    child: Child,
    port: u16,
    metrics: u16,
    dir: PathBuf,
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

fn spawn(name: &str, vars: &[(&str, &str)]) -> Botd {
    let (port, metrics) = (free_port(), free_port());
    let dir = std::env::temp_dir().join(format!("botd-signin-{name}-{}-{port}", std::process::id()));
    for d in ["data", "workspace", "home"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_botd"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir.join("home"))
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("AUTH_PASSWORD", PASSWORD)
        .env("SUPERBOT_MASTER_KEY", "ab".repeat(32))
        .env("DATA_DIR", dir.join("data"))
        .env("WORKSPACE_DIR", dir.join("workspace"))
        .env("SCREENS", "off")
        .env("TESTING_MODE", "on")
        .env("METRICS_LISTEN", format!("127.0.0.1:{metrics}"))
        .stdout(std::fs::File::create(dir.join("stdout.log")).unwrap())
        .stderr(std::fs::File::create(dir.join("stderr.log")).unwrap())
        .stdin(Stdio::null());
    for (k, v) in vars {
        cmd.env(k, v);
    }
    Botd { child: cmd.spawn().expect("start botd"), port, metrics, dir }
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

/// One request; `from` is the client IP botd is told by a proxy on loopback.
fn http(port: u16, method: &str, path: &str, auth: Option<&str>, from: Option<&str>, body: &str) -> (u16, String) {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else { return (0, String::new()) };
    let auth = auth.map(|a| format!("Authorization: {a}\r\n")).unwrap_or_default();
    let from = from.map(|ip| format!("X-Forwarded-For: {ip}\r\n")).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n{auth}{from}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut res = String::new();
    let _ = s.read_to_string(&mut res);
    let (head, body) = res.split_once("\r\n\r\n").unwrap_or((&res, ""));
    (head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0), body.to_string())
}

fn basic() -> String {
    use base64::Engine;
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("e2e:{PASSWORD}")))
}

impl Botd {
    fn log(&self) -> String {
        ["stdout.log", "stderr.log"].map(|f| std::fs::read_to_string(self.dir.join(f)).unwrap_or_default()).join("\n")
    }

    fn login(&self, from: &str, body: serde_json::Value) -> u16 {
        http(self.port, "POST", "/api/auth/login", None, Some(from), &body.to_string()).0
    }

    fn detections(&self) -> Vec<serde_json::Value> {
        let (code, body) = http(self.port, "GET", "/api/audit?action=auth.suspicious_sign_in", Some(&basic()), None, "");
        assert_eq!(code, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let mut list = v["events"].as_array().cloned().unwrap_or_default();
        list.reverse();
        list
    }

    fn metrics(&self) -> String {
        let (code, body) = http(self.metrics, "GET", "/metrics", None, None, "");
        assert_eq!(code, 200, "{body}");
        body
    }
}

fn start(name: &str, vars: &[(&str, &str)]) -> Botd {
    let b = spawn(name, vars);
    wait_for("botd to start", || (http(b.port, "GET", "/healthz", None, None, "").0 == 200).then_some(()));
    b
}

#[test]
fn botd_reports_a_burst_and_the_sign_in_after_it_in_the_audit_log_and_metrics() {
    let b = start("burst", &[("SIGNIN_ALERT_IP_FAILURES", "3")]);
    assert!(b.log().contains("Sign-in alerts: on: 3 failed sign-ins from one IP or 5 at one account within 15 minutes"), "{}", b.log());

    for i in 0..3 {
        assert_eq!(b.login("203.0.113.7", serde_json::json!({ "code": format!("sbc_{i:064x}") })), 401);
    }
    let found = b.detections();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0]["ip"].as_str(), found[0]["details"]["pattern"].as_str(), found[0]["details"]["failures"].as_i64()), (Some("203.0.113.7"), Some("ip_failures"), Some(3)));

    // The owner's password from that IP: someone got in right after the guesses.
    assert_eq!(b.login("203.0.113.7", serde_json::json!({ "password": PASSWORD })), 200);
    let found = b.detections();
    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!((found[1]["targetId"].as_str(), found[1]["details"]["pattern"].as_str(), found[1]["details"]["scope"].as_str()), (Some("operator"), Some("success_after_failures"), Some("ip")));

    let out = b.metrics();
    for line in [
        r#"superbot_signin_failures_total{method="code"} 3"#,
        r#"superbot_signin_suspicious_total{pattern="ip_failures"} 1"#,
        r#"superbot_signin_suspicious_total{pattern="success_after_failures"} 1"#,
        r#"superbot_signin_suspicious_total{pattern="account_failures"} 0"#,
    ] {
        assert!(out.lines().any(|l| l == line), "missing {line} in:\n{out}");
    }
    assert!(!out.contains("203.0.113"), "no IP is a label");

    // Every series the shipped rules alert on is one botd exports, with labels it uses.
    let rules = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../deploy/prometheus/superbot-signin.rules.yml")).unwrap();
    let exprs: Vec<&str> = rules.lines().filter(|l| l.trim_start().starts_with("expr:")).collect();
    assert_eq!(exprs.len(), 5, "{exprs:?}");
    for line in exprs {
        let at = line.find("superbot_signin_").unwrap_or_else(|| panic!("no sign-in metric in {line}"));
        let name: String = line[at..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        assert!(out.contains(&format!("# TYPE {name} counter")), "the rules use {name}, which botd doesn't export");
        if let Some((_, rest)) = line.split_once("pattern=\"") {
            let p = rest.split('"').next().unwrap();
            assert!(out.contains(&format!("{name}{{pattern=\"{p}\"}}")), "the rules use {name} pattern {p}, which botd doesn't export");
        }
    }
}

#[test]
fn off_starts_and_says_so() {
    let b = start("off", &[("SIGNIN_ALERTS", "off")]);
    assert!(b.log().contains("Sign-in alerts: off (SIGNIN_ALERTS=off)"), "{}", b.log());
    for i in 0..12 {
        b.login("203.0.113.7", serde_json::json!({ "code": format!("sbc_{i:064x}") }));
    }
    assert!(b.detections().is_empty());
}

#[test]
fn bad_settings_stop_botd_and_name_the_setting() {
    for (k, v) in [("SIGNIN_ALERTS", "sometimes"), ("SIGNIN_ALERT_IP_FAILURES", "1"), ("SIGNIN_ALERT_WINDOW", "3d"), ("SIGNIN_ALERT_NEW_IP", "bots")] {
        let mut b = spawn("bad", &[(k, v)]);
        let status = wait_for("botd to exit", || b.child.try_wait().unwrap());
        assert!(!status.success(), "{k}={v} started");
        let log = b.log();
        assert!(log.contains("Sign-in alerts:") && log.contains(k), "{k}={v}: {log}");
    }
}
