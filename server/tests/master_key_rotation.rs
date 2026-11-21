//! End to end (ADR 0096): the real `botd` rotates its master key the way the operator
//! guide says. Save a secret under key A in a key file; move that file aside as the
//! previous key, put key B in its place, restart: botd seals everything again under B,
//! records `secret.master_key_rotated`, and from then on starts with B alone and refuses A.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "e2e-password";
const SECRET: &str = "e2e-rotated-secret-value-0123456789";

struct Botd {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Botd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn random_key() -> [u8; 32] {
    XChaCha20Poly1305::generate_key(&mut OsRng).into()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn write_key(path: &Path, bytes: [u8; 32]) {
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    writeln!(f, "{}", B64.encode(bytes)).unwrap();
}

fn spawn(dir: &Path, previous: Option<&Path>, log: &str) -> Botd {
    let port = free_port();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_botd"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir.join("home"))
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("AUTH_PASSWORD", PASSWORD)
        .env("SUPERBOT_MASTER_KEY_FILE", dir.join("keys/master.key"))
        .env("DATA_DIR", dir.join("data"))
        .env("WORKSPACE_DIR", dir.join("workspace"))
        .env("SCREENS", "off")
        .env("TESTING_MODE", "on")
        .stdout(std::fs::File::create(dir.join(format!("{log}.out"))).unwrap())
        .stderr(std::fs::File::create(dir.join(format!("{log}.err"))).unwrap())
        .stdin(Stdio::null());
    if let Some(p) = previous {
        cmd.env("SUPERBOT_MASTER_KEY_PREVIOUS_FILE", p);
    }
    Botd { child: cmd.spawn().expect("start botd"), port, dir: dir.to_path_buf() }
}

fn start(dir: &Path, previous: Option<&Path>, log: &str) -> Botd {
    let b = spawn(dir, previous, log);
    wait_for("botd to start", || (http(&b, "GET", "/healthz", "").0 == 200).then_some(()));
    b
}

/// Starts botd and expects it to refuse: it exits non-zero before serving. Its log.
fn refused(dir: &Path, previous: Option<&Path>, log: &str) -> String {
    let mut b = spawn(dir, previous, log);
    let status = wait_for("botd to exit", || b.child.try_wait().unwrap());
    assert!(!status.success());
    std::fs::read_to_string(b.dir.join(format!("{log}.out"))).unwrap() + &std::fs::read_to_string(b.dir.join(format!("{log}.err"))).unwrap()
}

fn http(b: &Botd, method: &str, path: &str, body: &str) -> (u16, String) {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", b.port)) else { return (0, String::new()) };
    let auth = B64.encode(format!("e2e:{PASSWORD}"));
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
    let (code, res) = http(b, "GET", path, "");
    assert_eq!(code, 200, "GET {path}: {res}");
    serde_json::from_str(&res).unwrap()
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

/// The saved secret as it is in the database, opened with `key` the way botd seals it (ADR 0010).
fn stored_secret(dir: &Path, key: [u8; 32]) -> Option<String> {
    let c = rusqlite::Connection::open(dir.join("data/app.sqlite")).unwrap();
    let sealed: String = c.query_row("SELECT value FROM secrets WHERE name = 'E2E_TOKEN'", [], |r| r.get(0)).unwrap();
    let raw = B64.decode(sealed.strip_prefix("sb1:").unwrap()).unwrap();
    let (nonce, ct) = raw.split_at(24);
    let plain = XChaCha20Poly1305::new(Key::from_slice(&key)).decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: b"superbot/secrets/E2E_TOKEN" }).ok()?;
    Some(String::from_utf8(plain).unwrap())
}

#[test]
fn botd_rotates_its_master_key_from_a_previous_key_file() {
    let dir = std::env::temp_dir().join(format!("botd-key-rotation-{}-{}", std::process::id(), free_port()));
    for d in ["data", "workspace", "home", "keys"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let (a, b) = (random_key(), random_key());
    let key = dir.join("keys/master.key");
    let previous = dir.join("keys/master.key.previous");
    write_key(&key, a);

    let botd = start(&dir, None, "first");
    let (code, res) = http(&botd, "PUT", "/api/secrets/E2E_TOKEN", &json!({ "value": SECRET }).to_string());
    assert_eq!(code, 200, "{res}");
    drop(botd);
    assert_eq!(stored_secret(&dir, a).as_deref(), Some(SECRET));

    // The guide's steps: the old key becomes the previous key, a new one takes its place.
    std::fs::rename(&key, &previous).unwrap();
    write_key(&key, b);
    let botd = start(&dir, Some(&previous), "rotate");
    let out = std::fs::read_to_string(dir.join("rotate.out")).unwrap();
    assert!(out.contains("Master key rotated from") && out.contains("sealed 1 values again"), "{out}");
    let events = get(&botd, "/api/audit?action=secret.master_key_rotated&limit=10")["events"].as_array().cloned().unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["details"]["resealed"], 1);
    assert_eq!((events[0]["actorKind"].as_str(), events[0]["actorId"].as_str()), (Some("system"), Some("secrets")));
    let listed = get(&botd, "/api/secrets")["secrets"].as_array().cloned().unwrap();
    assert!(listed.iter().any(|s| s["name"] == "E2E_TOKEN"), "{listed:?}");
    drop(botd);
    assert_eq!(stored_secret(&dir, b).as_deref(), Some(SECRET), "the value survives, sealed under the new key");
    assert_eq!(stored_secret(&dir, a), None, "and the old key no longer opens it");

    // Left set by mistake: nothing happens again, and botd says to remove it.
    let botd = start(&dir, Some(&previous), "again");
    let out = std::fs::read_to_string(dir.join("again.out")).unwrap() + &std::fs::read_to_string(dir.join("again.err")).unwrap();
    assert!(out.contains("nothing to rotate"), "{out}");
    assert_eq!(get(&botd, "/api/audit?action=secret.master_key_rotated&limit=10")["events"].as_array().unwrap().len(), 1);
    drop(botd);

    // The new key alone works; the old key alone is refused.
    std::fs::remove_file(&previous).unwrap();
    drop(start(&dir, None, "after"));
    write_key(&key, a);
    let log = refused(&dir, None, "old");
    assert!(log.contains("wrong key"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
