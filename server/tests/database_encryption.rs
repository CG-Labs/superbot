//! End to end (ADR 0116): the real `botd` with its database encrypted at rest. A server
//! that kept a plain database (`SUPERBOT_DATABASE_ENCRYPTION=off`) opts in with `required`:
//! botd encrypts it at start, keeps a plain copy, and loses nothing. `botd database`, which
//! superbot-backup and superbot-restore use, copies and reads it with the master key, and
//! a wrong key is refused.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "e2e-password";

struct Botd {
    child: Child,
    port: u16,
}

impl Drop for Botd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn write_key(path: &Path) {
    let _ = std::fs::remove_file(path);
    let key: [u8; 32] = XChaCha20Poly1305::generate_key(&mut OsRng).into();
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    writeln!(f, "{}", B64.encode(key)).unwrap();
}

fn botd(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_botd"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir.join("home"))
        .env("SUPERBOT_MASTER_KEY_FILE", dir.join("keys/master.key"))
        .stdin(Stdio::null());
    cmd
}

fn spawn(dir: &Path, policy: &str, log: &str) -> Botd {
    let port = free_port();
    let mut cmd = botd(dir);
    cmd.env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("AUTH_PASSWORD", PASSWORD)
        .env("DATA_DIR", dir.join("data"))
        .env("WORKSPACE_DIR", dir.join("workspace"))
        .env("SCREENS", "off")
        .env("TESTING_MODE", "on")
        .env("SUPERBOT_DATABASE_ENCRYPTION", policy)
        .stdout(std::fs::File::create(dir.join(format!("{log}.out"))).unwrap())
        .stderr(std::fs::File::create(dir.join(format!("{log}.err"))).unwrap());
    Botd { child: cmd.spawn().expect("start botd"), port }
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

fn http(port: u16, method: &str, path: &str, body: &str) -> (u16, String) {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return (0, String::new());
    };
    let auth = B64.encode(format!("e2e:{PASSWORD}"));
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Basic {auth}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut res = String::new();
    let _ = s.read_to_string(&mut res);
    let (head, body) = res.split_once("\r\n\r\n").unwrap_or((&res, ""));
    (head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0), body.to_string())
}

fn start(dir: &Path, policy: &str, log: &str) -> (Botd, String) {
    let b = spawn(dir, policy, log);
    wait_for("botd to start", || (http(b.port, "GET", "/healthz", "").0 == 200).then_some(()));
    let out = std::fs::read_to_string(dir.join(format!("{log}.out"))).unwrap() + &std::fs::read_to_string(dir.join(format!("{log}.err"))).unwrap();
    (b, out)
}

fn get(port: u16, path: &str) -> Value {
    let (code, res) = http(port, "GET", path, "");
    assert_eq!(code, 200, "GET {path}: {res}");
    serde_json::from_str(&res).unwrap()
}

fn database(dir: &Path, args: &[&str]) -> Output {
    botd(dir).arg("database").args(args).output().unwrap()
}

fn plain(path: &Path) -> bool {
    std::fs::read(path).unwrap().starts_with(b"SQLite format 3\0")
}

#[test]
fn a_plain_database_is_encrypted_on_opting_in_and_read_with_the_master_key() {
    let dir: PathBuf = std::env::temp_dir().join(format!("botd-db-encryption-{}-{}", std::process::id(), free_port()));
    for d in ["data", "workspace", "home", "keys"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    write_key(&dir.join("keys/master.key"));
    let db = dir.join("data/app.sqlite");

    // Plain by choice: botd says so, and the file is ordinary SQLite.
    let (b, out) = start(&dir, "off", "off");
    assert!(out.contains("Database encryption: plain by choice"), "{out}");
    let (code, res) = http(b.port, "POST", "/api/bots", r#"{"name":"KeepMe"}"#);
    assert_eq!(code, 201, "{res}");
    assert_eq!(get(b.port, "/api/database")["encrypted"], false);
    drop(b);
    assert!(plain(&db));

    // auto leaves an existing plain database plain, and warns.
    let (b, out) = start(&dir, "auto", "auto");
    assert!(out.contains("WARNING: The database isn't encrypted"), "{out}");
    drop(b);
    assert!(plain(&db));

    // required encrypts it, keeping a plain copy, and every row survives.
    let (b, out) = start(&dir, "required", "required");
    assert!(out.contains("encrypted the plain database on this start, keeping a plain copy in app.sqlite-plain-"), "{out}");
    let v = get(b.port, "/api/database");
    assert_eq!((v["encrypted"].as_bool(), v["cipher"].as_str(), v["plainCopies"].as_array().map(Vec::len)), (Some(true), Some("sqlcipher"), Some(1)), "{v}");
    let copy = dir.join("data").join(v["plainCopies"][0]["name"].as_str().unwrap());
    assert!(get(b.port, "/api/bots").to_string().contains("KeepMe"));
    let ev = get(b.port, "/api/audit?action=server.database_encryption_changed&limit=10")["events"].as_array().cloned().unwrap();
    assert_eq!(ev[0]["details"]["migrated"].as_str(), copy.file_name().unwrap().to_str(), "{ev:?}");
    let mut second = spawn(&dir, "required", "second");
    let status = wait_for("the second botd to exit", || second.child.try_wait().unwrap());
    assert!(!status.success());
    let log = std::fs::read_to_string(dir.join("second.out")).unwrap() + &std::fs::read_to_string(dir.join("second.err")).unwrap();
    assert!(log.contains("another botd is using this DATA_DIR"), "{log}");
    drop(b);
    assert!(!plain(&db) && plain(&copy));

    // superbot-backup's copy and superbot-restore's reads, with the master key.
    let snap = dir.join("snapshot.sqlite");
    let out = database(&dir, &["backup", db.to_str().unwrap(), snap.to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    assert!(!plain(&snap), "the copy stays encrypted");
    let out = database(&dir, &["query", snap.to_str().unwrap(), "SELECT name FROM bots WHERE name = 'KeepMe'"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "KeepMe\n", "{out:?}");
    let out = database(&dir, &["status", copy.to_str().unwrap()]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "plain\n");
    let out = database(&dir, &["status", snap.to_str().unwrap()]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "encrypted\n");

    // Another key opens neither, and botd refuses to start with it.
    write_key(&dir.join("keys/master.key"));
    let out = database(&dir, &["query", snap.to_str().unwrap(), "SELECT 1"]);
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("wrong key"), "{out:?}");
    let mut b = spawn(&dir, "required", "wrong");
    let status = wait_for("botd to exit", || b.child.try_wait().unwrap());
    assert!(!status.success());
    let log = std::fs::read_to_string(dir.join("wrong.out")).unwrap() + &std::fs::read_to_string(dir.join("wrong.err")).unwrap();
    assert!(log.contains("doesn't open the encrypted database (wrong key)"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
