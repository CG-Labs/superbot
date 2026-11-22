//! End to end (ADR 0097): the real `botd` refuses to start when a model provider would
//! be reached over plain `http://` outside this computer, from the tiers file or from
//! `SUPERBOT_HERMES_BASE_URL`, and says which provider and file. Loopback still starts.
//! No harness, no network beyond 127.0.0.1.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn tiers(base_url: &str) -> String {
    format!(
        r#"{{"providers":{{"lan-model":{{"protocol":"openai-chat","baseUrl":"{base_url}","keySecret":"TIER_LAN_KEY"}}}},
            "tiers":[{{"name":"pro","routes":[{{"harness":"hermes","provider":"lan-model","model":"m"}}]}},{{"name":"self-host","routes":"any"}}]}}"#
    )
}

/// Starts botd with `tiers` as its tiers file (if any) and `extra` in its environment.
fn start(tiers: Option<&str>, extra: &[(&str, &str)]) -> Botd {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("botd-provider-https-{}-{port}", std::process::id()));
    for d in ["data", "workspace", "home"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_botd"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir.join("home"))
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("AUTH_PASSWORD", "e2e-password")
        .env("SUPERBOT_MASTER_KEY", "ab".repeat(32))
        .env("DATA_DIR", dir.join("data"))
        .env("WORKSPACE_DIR", dir.join("workspace"))
        .env("DEFAULT_HARNESS", "claude")
        .env("SCREENS", "off")
        .env("TESTING_MODE", "on")
        .stdout(std::fs::File::create(dir.join("stdout.log")).unwrap())
        .stderr(std::fs::File::create(dir.join("stderr.log")).unwrap())
        .stdin(Stdio::null());
    if let Some(t) = tiers {
        let path = dir.join("tiers.json");
        std::fs::write(&path, t).unwrap();
        cmd.env("TIERS_FILE", &path);
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    Botd { child: cmd.spawn().expect("start botd"), port, dir }
}

impl Botd {
    fn log(&self) -> String {
        ["stdout.log", "stderr.log"].map(|f| std::fs::read_to_string(self.dir.join(f)).unwrap_or_default()).join("\n")
    }

    fn tiers_file(&self) -> String {
        self.dir.join("tiers.json").display().to_string()
    }

    /// The exit status, once botd has exited by itself.
    fn exits(&mut self) -> ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(start.elapsed() < Duration::from_secs(30), "botd kept running:\n{}", self.log());
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Whether `/healthz` answers 200 before botd exits or 30 s pass.
    fn healthy(&mut self) -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(30) {
            if self.child.try_wait().unwrap().is_some() {
                return false;
            }
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", self.port)) {
                let _ = s.write_all(format!("GET /healthz HTTP/1.0\r\nHost: 127.0.0.1:{}\r\n\r\n", self.port).as_bytes());
                let mut res = String::new();
                let _ = s.read_to_string(&mut res);
                if res.split_whitespace().nth(1) == Some("200") {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }
}

#[test]
fn a_tiers_file_with_a_public_http_provider_is_refused() {
    let mut b = start(Some(&tiers("http://models.example.com/v1")), &[]);
    assert!(!b.exits().success());
    let log = b.log();
    let want = format!("Tiers: TIERS_FILE {}: provider \"lan-model\": baseUrl \"http://models.example.com/v1\" must use https://", b.tiers_file());
    assert!(log.contains(&want) && log.contains("ADR 0097"), "{log}");
}

#[test]
fn a_tiers_file_with_a_private_network_http_provider_is_refused() {
    let mut b = start(Some(&tiers("http://10.0.0.7:8000/v1")), &[]);
    assert!(!b.exits().success());
    assert!(b.log().contains("provider \"lan-model\": baseUrl \"http://10.0.0.7:8000/v1\" must use https://"), "{}", b.log());
}

#[test]
fn https_and_loopback_providers_start() {
    for url in ["https://models.example.com/v1", "http://127.0.0.1:11434/v1", "http://localhost:11434/v1", "http://[::1]:11434/v1"] {
        let mut b = start(Some(&tiers(url)), &[]);
        assert!(b.healthy(), "{url}:\n{}", b.log());
    }
}

#[test]
fn a_public_http_hermes_base_url_is_refused() {
    let mut b = start(None, &[("SUPERBOT_HERMES_BASE_URL", "http://models.example.com/v1")]);
    assert!(!b.exits().success());
    assert!(b.log().contains("SUPERBOT_HERMES_BASE_URL (http://models.example.com) must use https://"), "{}", b.log());
    let mut b = start(None, &[("SUPERBOT_HERMES_BASE_URL", "http://127.0.0.1:8080/v1")]);
    assert!(b.healthy(), "{}", b.log());
}
