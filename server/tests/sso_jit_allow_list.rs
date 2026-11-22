//! End to end (ADR 0103, SOC 2 CC6.2-1): the real `botd` refuses to start when an SSO
//! provider makes accounts just in time without a list of who may have one, and names
//! the provider and the setting. With the list, or without just in time, it starts.
//! The IdPs are never contacted: their settings are checked before botd listens.

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

const T1: &str = "11111111-1111-1111-1111-111111111111";

/// Settings for one provider of each type, with the id named after the type.
fn provider(ty: &str) -> Vec<(String, String)> {
    let up = ty.to_ascii_uppercase();
    let mut v = vec![("SSO_PROVIDERS".to_string(), ty.to_string()), (format!("SSO_{up}_TYPE"), ty.to_string()), (format!("SSO_{up}_CLIENT_ID"), "c1".to_string())];
    let more: &[(&str, &str)] = match ty {
        "entra" => &[("TENANT", T1)],
        "oidc" => &[("ISSUER", "https://idp.example.com")],
        "saml" => &[("ISSUER", "https://sso.example.com/realms/superbot"), ("IDP_ALIAS", "adfs"), ("IDP_ENTITY_ID", "http://adfs.example.com/adfs/services/trust")],
        "apple" => &[("TEAM_ID", "TEAM123456"), ("KEY_ID", "KEY1234567")],
        _ => &[],
    };
    v.extend(more.iter().map(|(k, val)| (format!("SSO_{up}_{k}"), val.to_string())));
    v
}

fn start(vars: &[(String, String)]) -> Botd {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("botd-sso-jit-{}-{port}", std::process::id()));
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
        .env("SSO_PUBLIC_URL", "https://bot.example.com")
        .stdout(std::fs::File::create(dir.join("stdout.log")).unwrap())
        .stderr(std::fs::File::create(dir.join("stderr.log")).unwrap())
        .stdin(Stdio::null());
    for (k, v) in vars {
        cmd.env(k, v);
    }
    Botd { child: cmd.spawn().expect("start botd"), port, dir }
}

impl Botd {
    fn log(&self) -> String {
        ["stdout.log", "stderr.log"].map(|f| std::fs::read_to_string(self.dir.join(f)).unwrap_or_default()).join("\n")
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
        let deadline = Instant::now() + Duration::from_secs(30);
        while let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) {
            if self.child.try_wait().unwrap().is_some() {
                return false;
            }
            if let Ok(mut s) = TcpStream::connect_timeout(&([127, 0, 0, 1], self.port).into(), left) {
                let _ = s.set_read_timeout(Some(left));
                let _ = s.set_write_timeout(Some(left));
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

fn with(ty: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let up = ty.to_ascii_uppercase();
    let mut v = provider(ty);
    v.extend(extra.iter().map(|(k, val)| (format!("SSO_{up}_{k}"), val.to_string())));
    v
}

/// Each type, its allow-list setting, and a value for it.
const ALLOW_LISTS: [(&str, &str, &str); 5] =
    [("oidc", "ALLOWED_DOMAINS", "example.com"), ("saml", "ALLOWED_DOMAINS", "example.com"), ("google", "HOSTED_DOMAINS", "example.com"), ("apple", "ALLOWED_DOMAINS", "example.com"), ("github", "ALLOWED_ORGS", "acme")];

#[test]
fn just_in_time_without_an_allow_list_is_refused_for_every_type() {
    for (ty, list, _) in ALLOW_LISTS {
        let up = ty.to_ascii_uppercase();
        let mut b = start(&with(ty, &[("JIT_ROLE", "member")]));
        assert!(!b.exits().success(), "{ty}");
        let log = b.log();
        assert!(log.contains(&format!("SSO: SSO_{up}_JIT_ROLE without SSO_{up}_{list}")), "{ty}:\n{log}");
    }
    let mut b = start(&with("entra", &[("JIT_ROLE", "member"), ("TENANT", "organizations")]));
    assert!(!b.exits().success());
    assert!(b.log().contains("SSO_ENTRA_ALLOWED_TENANTS"), "{}", b.log());
}

#[test]
fn just_in_time_with_an_allow_list_starts() {
    for (ty, list, value) in ALLOW_LISTS {
        let mut b = start(&with(ty, &[("JIT_ROLE", "member"), (list, value)]));
        assert!(b.healthy(), "{ty}:\n{}", b.log());
        assert!(b.log().contains("just-in-time sign-up member"), "{ty}:\n{}", b.log());
    }
    let mut b = start(&with("entra", &[("JIT_ROLE", "member")]));
    assert!(b.healthy(), "entra pinned to one tenant:\n{}", b.log());
    let mut b = start(&with("entra", &[("JIT_ROLE", "member"), ("TENANT", "organizations"), ("ALLOWED_TENANTS", T1)]));
    assert!(b.healthy(), "entra with ALLOWED_TENANTS:\n{}", b.log());
}

#[test]
fn without_just_in_time_no_allow_list_is_needed() {
    for ty in ["oidc", "saml"] {
        let mut b = start(&provider(ty));
        assert!(b.healthy(), "{ty}:\n{}", b.log());
    }
}
