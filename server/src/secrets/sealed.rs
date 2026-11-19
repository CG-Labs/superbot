//! Encryption at rest: the master-key cipher, sealed database fields, and the
//! encrypted secret store (SQLite table `secrets`).
//!
//! A sealed value is `sb1:` + base64(24-byte random nonce || XChaCha20-Poly1305
//! ciphertext and tag). The associated data names where the value lives
//! (`secrets/<NAME>`, `approvals.input/<id>`), so a ciphertext copied to another row
//! or name fails to open instead of being read as that row's value.

use super::key::MasterKey;
use super::{redact, Error, Secret, SecretStore};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroizing;

pub const PREFIX: &str = "sb1:";
const NONCE: usize = 24;
const TAG: usize = 16;
/// Settings row holding a sealed known value, to tell a wrong key from a right one.
const KEY_CHECK: &str = "secrets_key_check";
const KEY_CHECK_PLAIN: &[u8] = b"superbot master key check";

pub struct Cipher(XChaCha20Poly1305);

fn aad(context: &str) -> String {
    format!("superbot/{context}")
}

impl Cipher {
    pub fn new(key: &MasterKey) -> Cipher {
        Cipher(XChaCha20Poly1305::new(Key::from_slice(key.bytes())))
    }

    pub fn seal(&self, context: &str, plain: &[u8]) -> String {
        let mut out = crate::random_bytes(NONCE);
        let aad = aad(context);
        let ct = self.0.encrypt(XNonce::from_slice(&out), Payload { msg: plain, aad: aad.as_bytes() }).expect("XChaCha20-Poly1305 seals any input");
        out.extend(ct);
        format!("{PREFIX}{}", B64.encode(out))
    }

    pub fn open(&self, context: &str, sealed: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        let raw = sealed.strip_prefix(PREFIX).and_then(|b| B64.decode(b).ok()).filter(|r| r.len() >= NONCE + TAG);
        let raw = raw.ok_or_else(|| Error::Store(format!("{context} is not a sealed value")))?;
        let (nonce, ct) = raw.split_at(NONCE);
        let aad = aad(context);
        self.0
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: aad.as_bytes() })
            .map(Zeroizing::new)
            .map_err(|_| Error::Store(format!("{context} doesn't decrypt: wrong master key, or the value was changed or moved")))
    }

    pub fn open_text(&self, context: &str, sealed: &str) -> Result<Secret, Error> {
        let bytes = self.open(context, sealed)?;
        std::str::from_utf8(&bytes).map(Secret::new).map_err(|_| Error::Store(format!("{context} is not text")))
    }
}

pub fn is_sealed(s: &str) -> bool {
    s.starts_with(PREFIX)
}

static CIPHER: OnceLock<Arc<Cipher>> = OnceLock::new();

/// The cipher for database fields. Set once at startup by `secrets::init`.
pub fn cipher() -> Arc<Cipher> {
    #[cfg(test)]
    return CIPHER.get_or_init(|| Arc::new(Cipher::new(&MasterKey::generate()))).clone();
    #[cfg(not(test))]
    CIPHER.get().expect("secrets::init runs before the database is used").clone()
}

pub fn install(c: Cipher) -> Result<Arc<Cipher>, String> {
    CIPHER.set(Arc::new(c)).map_err(|_| "the master key cipher was already set".to_string())?;
    Ok(cipher())
}

pub fn approval_context(id: &str) -> String {
    format!("approvals.input/{id}")
}

/// Seals a database field, e.g. an approval's tool input.
pub fn seal_field(context: &str, plain: &str) -> String {
    cipher().seal(context, plain.as_bytes())
}

/// Opens a sealed field. Plaintext (from before sealing) passes through. None if it doesn't open.
pub fn open_field(context: &str, stored: &str) -> Option<String> {
    if !is_sealed(stored) {
        return Some(stored.to_string());
    }
    cipher().open_text(context, stored).ok().map(|s| s.expose().to_string())
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS secrets (
  name TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);";

/// A connection of its own to the database (WAL allows several), with the `secrets` table.
pub fn connect(path: &Path) -> Result<Connection, String> {
    let c = Connection::open(path).map_err(|e| e.to_string())?;
    c.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
    Ok(c)
}

#[derive(Debug, Default)]
pub struct Bootstrap {
    pub created: bool,
    /// Plaintext approval inputs sealed this time.
    pub sealed: usize,
    /// Sealed values dropped by SUPERBOT_FORGET_SEALED=1.
    pub discarded: usize,
}

pub const MISSING_KEY: &str = "the database holds encrypted values but no master key was found. \
     Restore the key (SUPERBOT_MASTER_KEY or SUPERBOT_MASTER_KEY_FILE; see deploy/README.md). \
     If it is lost for good, start once with SUPERBOT_FORGET_SEALED=1 to drop the encrypted values and make a new key.";

const WRONG_KEY: &str = "the master key doesn't open this database's encrypted values (wrong key). \
     Use the key this database was sealed with; see deploy/README.md.";

fn key_check(c: &Connection) -> rusqlite::Result<Option<String>> {
    c.query_row("SELECT value FROM settings WHERE key = ?", [KEY_CHECK], |r| r.get(0)).optional()
}

/// Any sealed value, with the context it was sealed under.
fn any_sealed(c: &Connection) -> rusqlite::Result<Option<(String, String)>> {
    let secret = c.query_row("SELECT name, value FROM secrets LIMIT 1", [], |r| Ok((format!("secrets/{}", r.get::<_, String>(0)?), r.get(1)?))).optional()?;
    if secret.is_some() {
        return Ok(secret);
    }
    c.query_row("SELECT id, input FROM approvals WHERE input LIKE 'sb1:%' LIMIT 1", [], |r| Ok((approval_context(&r.get::<_, String>(0)?), r.get(1)?)))
        .optional()
}

/// Drops every sealed value. Approval inputs keep a marker; everything else about them stays.
fn discard(c: &Connection) -> rusqlite::Result<usize> {
    let tx = c.unchecked_transaction()?;
    let mut n = tx.execute("DELETE FROM secrets", [])?;
    n += tx.execute("UPDATE approvals SET input = '{\"sealed\":\"discarded\"}' WHERE input LIKE 'sb1:%'", [])?;
    tx.execute("DELETE FROM settings WHERE key = ?", [KEY_CHECK])?;
    tx.commit()?;
    Ok(n)
}

/// Seals approval inputs saved in plaintext by versions before this one. Each row is
/// redacted, then sealed under its own id. Rows already sealed are skipped, so this is
/// safe to run on every start; one transaction, so a crash leaves all or nothing.
fn seal_plaintext(c: &Connection, cipher: &Cipher) -> rusqlite::Result<usize> {
    let tx = c.unchecked_transaction()?;
    let rows: Vec<(String, String)> = {
        let mut s = tx.prepare("SELECT id, input FROM approvals WHERE input NOT LIKE 'sb1:%'")?;
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?
    };
    for (id, input) in &rows {
        let sealed = cipher.seal(&approval_context(id), redact::text(input).as_bytes());
        tx.execute("UPDATE approvals SET input = ? WHERE id = ?", params![sealed, id])?;
    }
    tx.commit()?;
    Ok(rows.len())
}

/// Startup checks, in order: optionally forget sealed values; find or make the key
/// (refusing to make one when sealed values exist); prove the key opens what's
/// sealed; seal leftover plaintext.
pub fn bootstrap(
    c: &Connection,
    found: Option<MasterKey>,
    create: impl FnOnce() -> Result<MasterKey, String>,
    forget: bool,
) -> Result<(Cipher, Bootstrap), String> {
    let db = |e: rusqlite::Error| format!("database: {e}");
    let mut b = Bootstrap::default();
    if forget {
        b.discarded = discard(c).map_err(db)?;
    }
    let check = key_check(c).map_err(db)?;
    let sealed = any_sealed(c).map_err(db)?;
    let key = match found {
        Some(k) => k,
        None if check.is_some() || sealed.is_some() => return Err(MISSING_KEY.into()),
        None => {
            b.created = true;
            create()?
        }
    };
    let cipher = Cipher::new(&key);
    match (check, sealed) {
        (Some(v), _) => {
            if cipher.open("key-check", &v).ok().is_none_or(|p| p.as_slice() != KEY_CHECK_PLAIN) {
                return Err(WRONG_KEY.into());
            }
        }
        (None, sealed) => {
            if let Some((context, v)) = sealed
                && cipher.open(&context, &v).is_err()
            {
                return Err(WRONG_KEY.into());
            }
            c.execute("INSERT INTO settings (key, value) VALUES (?, ?)", params![KEY_CHECK, cipher.seal("key-check", KEY_CHECK_PLAIN)]).map_err(db)?;
        }
    }
    b.sealed = seal_plaintext(c, &cipher).map_err(db)?;
    Ok((cipher, b))
}

/// Secrets the operator stores through the API or `botctl secret set`, encrypted in SQLite.
pub struct SealedStore {
    c: Mutex<Connection>,
    cipher: Arc<Cipher>,
}

fn context(name: &str) -> String {
    format!("secrets/{name}")
}

impl SealedStore {
    pub fn new(c: Connection, cipher: Arc<Cipher>) -> SealedStore {
        SealedStore { c: Mutex::new(c), cipher }
    }

    fn c(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.c.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn store_err(e: rusqlite::Error) -> Error {
    Error::Store(e.to_string())
}

impl SecretStore for SealedStore {
    fn kind(&self) -> &'static str {
        "sealed"
    }

    fn get(&self, name: &str) -> Result<Option<Secret>, Error> {
        let v: Option<String> = self.c().query_row("SELECT value FROM secrets WHERE name = ?", [name], |r| r.get(0)).optional().map_err(store_err)?;
        v.map(|v| self.cipher.open_text(&context(name), &v)).transpose()
    }

    fn names(&self) -> Result<Vec<String>, Error> {
        let c = self.c();
        let mut s = c.prepare("SELECT name FROM secrets ORDER BY name").map_err(store_err)?;
        s.query_map([], |r| r.get(0)).map_err(store_err)?.collect::<rusqlite::Result<_>>().map_err(store_err)
    }

    fn writable(&self) -> bool {
        true
    }

    fn put(&self, name: &str, value: &str) -> Result<(), Error> {
        let sealed = self.cipher.seal(&context(name), value.as_bytes());
        let now = crate::db::now();
        self.c()
            .execute(
                "INSERT INTO secrets (name, value, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(name) DO UPDATE SET value = ?2, updated_at = ?3",
                params![name, sealed, now],
            )
            .map_err(store_err)?;
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<bool, Error> {
        Ok(self.c().execute("DELETE FROM secrets WHERE name = ?", [name]).map_err(store_err)? == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{now, Db};
    use serde_json::json;

    fn fresh() -> (std::path::PathBuf, Db, Connection) {
        let path = crate::db::temp_path("sealed").join("app.sqlite");
        let db = Db::open(&path).unwrap();
        let c = connect(&path).unwrap();
        (path, db, c)
    }

    fn no_key() -> Result<MasterKey, String> {
        panic!("no key should be made here")
    }

    #[test]
    fn round_trip_and_tamper_detection() {
        let k = MasterKey::generate();
        let c = Cipher::new(&k);
        let a = c.seal("secrets/X", b"hello");
        let b = c.seal("secrets/X", b"hello");
        assert!(a.starts_with(PREFIX) && !a.contains("hello"));
        assert_ne!(a, b, "a fresh nonce every time");
        assert_eq!(c.open("secrets/X", &a).unwrap().as_slice(), b"hello");
        assert!(c.open("secrets/Y", &a).is_err(), "bound to its name");
        assert!(Cipher::new(&MasterKey::generate()).open("secrets/X", &a).is_err(), "wrong key");
        let mut raw = B64.decode(&a[PREFIX.len()..]).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(c.open("secrets/X", &format!("{PREFIX}{}", B64.encode(&raw))).is_err(), "tampered");
        for junk in ["", "sb1:", "sb1:!!!", "plain text", &format!("{PREFIX}{}", B64.encode([0u8; 39]))] {
            assert!(c.open("secrets/X", junk).is_err(), "{junk}");
        }
        assert_eq!(c.open_text("secrets/X", &a).unwrap().expose(), "hello");
    }

    #[test]
    fn store_keeps_only_ciphertext_on_disk() {
        let (path, _db, c) = fresh();
        let (cipher, b) = bootstrap(&c, None, || Ok(MasterKey::generate()), false).unwrap();
        assert!(b.created);
        let store = SealedStore::new(c, Arc::new(cipher));
        let value = format!("sk-live-{}", crate::random_hex(16));
        store.put("OPENAI_API_KEY", &value).unwrap();
        store.put("OPENAI_API_KEY", &value).unwrap();
        store.put("B_TOKEN", "second").unwrap();
        assert_eq!(store.get("OPENAI_API_KEY").unwrap().unwrap().expose(), value);
        assert!(store.get("NOPE").unwrap().is_none());
        assert_eq!(store.names().unwrap(), ["B_TOKEN", "OPENAI_API_KEY"]);
        drop(store);
        let raw = std::fs::read(&path).unwrap();
        let wal = std::fs::read(path.with_extension("sqlite-wal")).unwrap_or_default();
        let has = |hay: &[u8]| hay.windows(value.len()).any(|w| w == value.as_bytes());
        assert!(!has(&raw) && !has(&wal), "plaintext never reaches the database file");
    }

    #[test]
    fn delete_reports_whether_it_existed() {
        let (_, _db, c) = fresh();
        let (cipher, _) = bootstrap(&c, None, || Ok(MasterKey::generate()), false).unwrap();
        let store = SealedStore::new(c, Arc::new(cipher));
        store.put("X_TOKEN", "v").unwrap();
        assert!(store.delete("X_TOKEN").unwrap());
        assert!(!store.delete("X_TOKEN").unwrap());
    }

    #[test]
    fn plaintext_approvals_from_older_versions_are_sealed_once() {
        let (path, db, c) = fresh();
        let bot = db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let secret = format!("ghp_{}", crate::random_hex(16));
        let input = json!({ "file_path": "/w/.env", "content": format!("TOKEN={secret}\n") }).to_string();
        // Rows as an older botd wrote them: plaintext input.
        let raw = Connection::open(&path).unwrap();
        for id in ["old1", "old2"] {
            raw.execute(
                "INSERT INTO approvals (id, bot_id, harness, tool, kind, subject, input, class, reason, status, created_at, expires_at)
                 VALUES (?, ?, 'claude', 'Write', 'file', '/w/.env', ?, 'file_delete', 'r', 'denied', ?, ?)",
                params![id, bot.id, input, now(), now()],
            )
            .unwrap();
        }
        redact::register(&secret);
        let key = MasterKey::generate();
        let key_bytes = *key.bytes();
        let (cipher, b) = bootstrap(&c, Some(key), no_key, false).unwrap();
        assert_eq!(b.sealed, 2);
        let stored: String = raw.query_row("SELECT input FROM approvals WHERE id = 'old1'", [], |r| r.get(0)).unwrap();
        assert!(is_sealed(&stored));
        let opened = cipher.open_text(&approval_context("old1"), &stored).unwrap();
        let v: serde_json::Value = serde_json::from_str(opened.expose()).unwrap();
        assert_eq!(v["file_path"], "/w/.env", "no data lost");
        assert_eq!(v["content"], "TOKEN=[redacted]\n", "known secrets redacted before sealing");
        assert!(cipher.open(&approval_context("old2"), &stored).is_err(), "bound to its row");

        // Upgrading again (or restarting) changes nothing.
        let again = MasterKey::parse(&B64.encode(key_bytes)).unwrap();
        let (_, b) = bootstrap(&c, Some(again), no_key, false).unwrap();
        assert_eq!(b.sealed, 0);
        let after: String = raw.query_row("SELECT input FROM approvals WHERE id = 'old1'", [], |r| r.get(0)).unwrap();
        assert_eq!(after, stored);
        redact::forget(&secret);
    }

    #[test]
    fn a_wrong_or_missing_key_refuses_to_start() {
        let (_, _db, c) = fresh();
        let key = MasterKey::generate();
        let copy = MasterKey::parse(&key.base64()).unwrap();
        bootstrap(&c, Some(key), no_key, false).unwrap();
        assert_eq!(bootstrap(&c, Some(MasterKey::generate()), no_key, false).err().unwrap(), WRONG_KEY);
        assert_eq!(bootstrap(&c, None, no_key, false).err().unwrap(), MISSING_KEY);
        assert!(bootstrap(&c, Some(copy), no_key, false).is_ok());
    }

    #[test]
    fn a_wrong_key_is_caught_even_without_the_check_row() {
        let (_, _db, c) = fresh();
        let (cipher, _) = bootstrap(&c, Some(MasterKey::generate()), no_key, false).unwrap();
        SealedStore::new(connect_again(&c), Arc::new(cipher)).put("X_TOKEN", "v").unwrap();
        c.execute("DELETE FROM settings WHERE key = ?", [KEY_CHECK]).unwrap();
        assert_eq!(bootstrap(&c, Some(MasterKey::generate()), no_key, false).err().unwrap(), WRONG_KEY);
    }

    fn connect_again(c: &Connection) -> Connection {
        Connection::open(c.path().unwrap()).unwrap()
    }

    #[test]
    fn forgetting_drops_sealed_values_and_starts_over() {
        let (_, db, c) = fresh();
        let bot = db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let (cipher, _) = bootstrap(&c, Some(MasterKey::generate()), no_key, false).unwrap();
        let cipher = Arc::new(cipher);
        SealedStore::new(connect_again(&c), cipher.clone()).put("X_TOKEN", "v").unwrap();
        let sealed = cipher.seal(&approval_context("a1"), b"{}");
        c.execute(
            "INSERT INTO approvals (id, bot_id, harness, tool, kind, subject, input, class, reason, status, created_at, expires_at)
             VALUES ('a1', ?, 'claude', 'Bash', 'shell', 'ls', ?, '', 'r', 'denied', 0, 0)",
            params![bot.id, sealed],
        )
        .unwrap();
        let (fresh_cipher, b) = bootstrap(&c, None, || Ok(MasterKey::generate()), true).unwrap();
        assert!(b.created);
        assert_eq!(b.discarded, 2);
        let input: String = c.query_row("SELECT input FROM approvals WHERE id = 'a1'", [], |r| r.get(0)).unwrap();
        assert_eq!(fresh_cipher.open_text(&approval_context("a1"), &input).unwrap().expose(), r#"{"sealed":"discarded"}"#);
        let n: i64 = c.query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
    }
}
