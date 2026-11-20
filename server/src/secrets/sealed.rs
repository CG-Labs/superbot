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
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
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

/// The AEAD, and a root for keys derived from the master key.
pub struct Cipher(XChaCha20Poly1305, Zeroizing<[u8; 32]>);

fn aad(context: &str) -> String {
    format!("superbot/{context}")
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Zeroizing<[u8; 32]> {
    use aws_lc_rs::hmac;
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(tag.as_ref());
    out
}

impl Cipher {
    pub fn new(key: &MasterKey) -> Cipher {
        Cipher(XChaCha20Poly1305::new(Key::from_slice(key.bytes())), hmac_sha256(key.bytes(), b"superbot/derive"))
    }

    /// 32 bytes for `purpose` (e.g. the machine CA's key, ADR 0031), derived from the
    /// master key with HMAC-SHA256. As safe as the master key and kept nowhere else;
    /// a new master key means new derived keys.
    pub fn derive(&self, purpose: &str) -> Zeroizing<[u8; 32]> {
        hmac_sha256(&self.1[..], purpose.as_bytes())
    }

    pub fn seal(&self, context: &str, plain: &[u8]) -> String {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let aad = aad(context);
        let ct = self.0.encrypt(&nonce, Payload { msg: plain, aad: aad.as_bytes() }).expect("XChaCha20-Poly1305 seals any input");
        let mut out = nonce.to_vec();
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
);
CREATE TABLE IF NOT EXISTS user_secrets (
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, name)
);";

/// A connection of its own to the database (WAL allows several), with the `secrets` table.
pub fn connect(path: &Path) -> Result<Connection, String> {
    let c = Connection::open(path).map_err(|e| e.to_string())?;
    // Overwrite freed space with zeros, so replaced values don't linger in free pages.
    c.execute_batch(&format!("PRAGMA secure_delete = ON; {SCHEMA}")).map_err(|e| e.to_string())?;
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
    let mine = c
        .query_row("SELECT user_id, name, value FROM user_secrets LIMIT 1", [], |r| Ok((user_context(&r.get::<_, String>(0)?, &r.get::<_, String>(1)?), r.get(2)?)))
        .optional()?;
    if mine.is_some() {
        return Ok(mine);
    }
    c.query_row("SELECT id, input FROM approvals WHERE input LIKE 'sb1:%' LIMIT 1", [], |r| Ok((approval_context(&r.get::<_, String>(0)?), r.get(1)?)))
        .optional()
}

/// Drops the sealed values `keep` can't open (all of them without a key) and the key
/// check. Approval inputs keep a marker; everything else about them stays.
fn discard(c: &Connection, keep: Option<&Cipher>) -> rusqlite::Result<usize> {
    let opens = |context: &str, v: &str| keep.is_some_and(|k| k.open(context, v).is_ok());
    let tx = c.unchecked_transaction()?;
    let pairs = |sql: &str| -> rusqlite::Result<Vec<(String, String)>> {
        let mut s = tx.prepare(sql)?;
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
    };
    let secrets = pairs("SELECT name, value FROM secrets")?;
    let approvals = pairs("SELECT id, input FROM approvals WHERE input LIKE 'sb1:%'")?;
    let mut n = 0;
    for (name, v) in secrets.iter().filter(|(name, v)| !opens(&context(name), v)) {
        n += tx.execute("DELETE FROM secrets WHERE name = ? AND value = ?", params![name, v])?;
    }
    let mine: Vec<(String, String, String)> = {
        let mut s = tx.prepare("SELECT user_id, name, value FROM user_secrets")?;
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<_>>()?
    };
    for (user, name, v) in mine.iter().filter(|(u, name, v)| !opens(&user_context(u, name), v)) {
        n += tx.execute("DELETE FROM user_secrets WHERE user_id = ? AND name = ? AND value = ?", params![user, name, v])?;
    }
    for (id, _) in approvals.iter().filter(|(id, v)| !opens(&approval_context(id), v)) {
        n += tx.execute("UPDATE approvals SET input = '{\"sealed\":\"discarded\"}' WHERE id = ?", [id])?;
    }
    tx.execute("DELETE FROM settings WHERE key = ?", [KEY_CHECK])?;
    tx.commit()?;
    Ok(n)
}

/// Rewrites the database file and empties the WAL, so plaintext that sealing or
/// redaction replaced doesn't linger in old pages. Run after a start that changed rows.
pub fn purge_old_pages(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch("VACUUM")?;
    let busy: i64 = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
    if busy != 0 {
        eprintln!("Secrets: the database was busy, so old pages may stay in the WAL until the next checkpoint.");
    }
    Ok(())
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
        // Parsed when it's JSON, so a secret with quotes or backslashes matches unescaped.
        let clean = match serde_json::from_str::<serde_json::Value>(input) {
            Ok(v) => redact::value(v).to_string(),
            Err(_) => redact::text(input).to_string(),
        };
        let sealed = cipher.seal(&approval_context(id), clean.as_bytes());
        tx.execute("UPDATE approvals SET input = ? WHERE id = ?", params![sealed, id])?;
    }
    tx.commit()?;
    Ok(rows.len())
}

/// Whether `cipher` opens what this database has sealed. True when nothing is sealed yet.
fn opens(c: &Connection, cipher: &Cipher) -> rusqlite::Result<bool> {
    if let Some(v) = key_check(c)? {
        return Ok(cipher.open("key-check", &v).is_ok_and(|p| p.as_slice() == KEY_CHECK_PLAIN));
    }
    Ok(any_sealed(c)?.is_none_or(|(context, v)| cipher.open(&context, &v).is_ok()))
}

/// Startup checks: find or make the key (never making one when sealed values exist),
/// prove it opens what's sealed, then seal leftover plaintext. `forget` drops sealed
/// values only when the key is missing or wrong, so leaving it set does no harm.
pub fn bootstrap(
    c: &Connection,
    found: Option<MasterKey>,
    create: impl FnOnce() -> Result<MasterKey, String>,
    forget: bool,
) -> Result<(Cipher, Bootstrap), String> {
    let db = |e: rusqlite::Error| format!("database: {e}");
    let mut b = Bootstrap::default();
    let cipher = match found {
        Some(k) => {
            let cipher = Cipher::new(&k);
            if !opens(c, &cipher).map_err(db)? {
                if !forget {
                    return Err(WRONG_KEY.into());
                }
                b.discarded = discard(c, Some(&cipher)).map_err(db)?;
            }
            cipher
        }
        None => {
            if key_check(c).map_err(db)?.is_some() || any_sealed(c).map_err(db)?.is_some() {
                if !forget {
                    return Err(MISSING_KEY.into());
                }
                b.discarded = discard(c, None).map_err(db)?;
            }
            b.created = true;
            Cipher::new(&create()?)
        }
    };
    if key_check(c).map_err(db)?.is_none() {
        c.execute("INSERT INTO settings (key, value) VALUES (?, ?)", params![KEY_CHECK, cipher.seal("key-check", KEY_CHECK_PLAIN)]).map_err(db)?;
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

/// The associated data names the user too, so a value copied to another user's row
/// doesn't open as theirs.
fn user_context(user_id: &str, name: &str) -> String {
    format!("user-secrets/{user_id}/{name}")
}

/// Each user's own secrets (ADR 0029): API keys and tokens that reach only that user's
/// Bots. Every query names the user.
pub struct UserSecrets {
    c: Mutex<Connection>,
    cipher: Arc<Cipher>,
}

impl UserSecrets {
    pub fn new(c: Connection, cipher: Arc<Cipher>) -> UserSecrets {
        UserSecrets { c: Mutex::new(c), cipher }
    }

    fn c(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.c.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self, user_id: &str, name: &str) -> Result<Option<Secret>, Error> {
        let v: Option<String> = self
            .c()
            .query_row("SELECT value FROM user_secrets WHERE user_id = ? AND name = ?", [user_id, name], |r| r.get(0))
            .optional()
            .map_err(store_err)?;
        v.map(|v| self.cipher.open_text(&user_context(user_id, name), &v)).transpose()
    }

    /// The user's secret names, when each was first saved and when last set. Never values.
    pub fn names(&self, user_id: &str) -> Result<Vec<(String, i64, i64)>, Error> {
        let c = self.c();
        let mut s = c.prepare("SELECT name, created_at, updated_at FROM user_secrets WHERE user_id = ? ORDER BY name").map_err(store_err)?;
        s.query_map([user_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(store_err)?.collect::<rusqlite::Result<_>>().map_err(store_err)
    }

    pub fn put(&self, user_id: &str, name: &str, value: &str) -> Result<(), Error> {
        let sealed = self.cipher.seal(&user_context(user_id, name), value.as_bytes());
        self.c()
            .execute(
                "INSERT INTO user_secrets (user_id, name, value, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(user_id, name) DO UPDATE SET value = ?3, updated_at = ?4",
                params![user_id, name, sealed, crate::db::now()],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// True if the user had it.
    pub fn delete(&self, user_id: &str, name: &str) -> Result<bool, Error> {
        Ok(self.c().execute("DELETE FROM user_secrets WHERE user_id = ? AND name = ?", [user_id, name]).map_err(store_err)? == 1)
    }

    /// Every value, for the redactor at startup.
    /// Every value, with the user it belongs to.
    pub fn all_values(&self) -> Vec<(String, Secret)> {
        let rows: Vec<(String, String, String)> = {
            let c = self.c();
            let Ok(mut s) = c.prepare("SELECT user_id, name, value FROM user_secrets") else { return Vec::new() };
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map(|m| m.filter_map(Result::ok).collect()).unwrap_or_default()
        };
        rows.into_iter().filter_map(|(u, n, v)| self.cipher.open_text(&user_context(&u, &n), &v).ok().map(|v| (u, v))).collect()
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
    fn user_secrets_are_per_user_and_bound_to_their_row() {
        let (path, _db, c) = fresh();
        let (cipher, _) = bootstrap(&c, None, || Ok(MasterKey::generate()), false).unwrap();
        let s = UserSecrets::new(c, Arc::new(cipher));
        let a = format!("sk-ant-{}", crate::random_hex(16));
        s.put("ua", "ANTHROPIC_API_KEY", &a).unwrap();
        s.put("ub", "ANTHROPIC_API_KEY", "b-key").unwrap();
        s.put("ub", "OPENAI_API_KEY", "b-openai").unwrap();
        assert_eq!(s.get("ua", "ANTHROPIC_API_KEY").unwrap().unwrap().expose(), a);
        assert_eq!(s.get("ub", "ANTHROPIC_API_KEY").unwrap().unwrap().expose(), "b-key");
        assert!(s.get("ua", "OPENAI_API_KEY").unwrap().is_none(), "B's key isn't A's");
        assert_eq!(s.names("ua").unwrap().into_iter().map(|(n, ..)| n).collect::<Vec<_>>(), ["ANTHROPIC_API_KEY"]);
        // Replacing a value keeps when it was first saved.
        s.c().execute("UPDATE user_secrets SET created_at = 1, updated_at = 1 WHERE user_id = 'ub' AND name = 'OPENAI_API_KEY'", []).unwrap();
        s.put("ub", "OPENAI_API_KEY", "b-openai-2").unwrap();
        let (_, created, updated) = s.names("ub").unwrap().into_iter().find(|(n, ..)| n == "OPENAI_API_KEY").unwrap();
        assert!(created == 1 && updated > 1, "{created} {updated}");
        assert_eq!(s.get("ub", "OPENAI_API_KEY").unwrap().unwrap().expose(), "b-openai-2");
        assert!(!s.delete("ua", "OPENAI_API_KEY").unwrap(), "A can't delete B's");
        assert!(s.get("ub", "OPENAI_API_KEY").unwrap().is_some());
        // A ciphertext moved to another user's row doesn't open there.
        {
            let c = s.c();
            let av: String = c.query_row("SELECT value FROM user_secrets WHERE user_id = 'ua'", [], |r| r.get(0)).unwrap();
            assert!(!av.contains(&a));
            c.execute("UPDATE user_secrets SET value = ? WHERE user_id = 'ub' AND name = 'ANTHROPIC_API_KEY'", [av]).unwrap();
        }
        assert!(s.get("ub", "ANTHROPIC_API_KEY").is_err());
        assert_eq!(s.all_values().len(), 2, "the moved value is skipped, not read as B's");
        drop(s);
        let raw = std::fs::read(&path).unwrap();
        let wal = std::fs::read(path.with_extension("sqlite-wal")).unwrap_or_default();
        let has = |hay: &[u8]| hay.windows(a.len()).any(|w| w == a.as_bytes());
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
        let quoted = format!("pw\"{}\\", crate::random_hex(8));
        let input = json!({ "file_path": "/w/.env", "content": format!("TOKEN={secret}\n"), "password": quoted }).to_string();
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
        redact::register(&quoted);
        let on_disk = || {
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.extend(std::fs::read(path.with_extension("sqlite-wal")).unwrap_or_default());
            bytes.windows(secret.len()).any(|w| w == secret.as_bytes())
        };
        assert!(on_disk());
        let key = MasterKey::generate();
        let key_bytes = *key.bytes();
        let (cipher, b) = bootstrap(&c, Some(key), no_key, false).unwrap();
        assert_eq!(b.sealed, 2);
        purge_old_pages(&c).unwrap();
        assert!(!on_disk(), "old pages holding the plaintext are gone from the file and the WAL");
        let stored: String = raw.query_row("SELECT input FROM approvals WHERE id = 'old1'", [], |r| r.get(0)).unwrap();
        assert!(is_sealed(&stored));
        let opened = cipher.open_text(&approval_context("old1"), &stored).unwrap();
        let v: serde_json::Value = serde_json::from_str(opened.expose()).unwrap();
        assert_eq!(v["file_path"], "/w/.env", "no data lost");
        assert_eq!(v["content"], "TOKEN=[redacted]\n", "known secrets redacted before sealing");
        assert_eq!(v["password"], redact::MARK, "escaped in JSON, still found");
        assert!(cipher.open(&approval_context("old2"), &stored).is_err(), "bound to its row");

        // Upgrading again (or restarting) changes nothing.
        let again = MasterKey::parse(&B64.encode(key_bytes)).unwrap();
        let (_, b) = bootstrap(&c, Some(again), no_key, false).unwrap();
        assert_eq!(b.sealed, 0);
        let after: String = raw.query_row("SELECT input FROM approvals WHERE id = 'old1'", [], |r| r.get(0)).unwrap();
        assert_eq!(after, stored);
        redact::forget(&secret);
        redact::forget(&quoted);
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
        let key = MasterKey::generate();
        let same_key = MasterKey::parse(&key.base64()).unwrap();
        let (cipher, _) = bootstrap(&c, Some(key), no_key, false).unwrap();
        let cipher = Arc::new(cipher);
        SealedStore::new(connect_again(&c), cipher.clone()).put("X_TOKEN", "v").unwrap();
        let (_, b) = bootstrap(&c, Some(same_key), no_key, true).unwrap();
        assert_eq!(b.discarded, 0, "a key that works keeps everything, even with the flag left on");
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

        // A wrong key with the flag: drop what it can't open, then adopt that key.
        SealedStore::new(connect_again(&c), Arc::new(fresh_cipher)).put("Y_TOKEN", "v").unwrap();
        let other = MasterKey::generate();
        let other_copy = MasterKey::parse(&other.base64()).unwrap();
        let (_, b) = bootstrap(&c, Some(other), no_key, true).unwrap();
        assert_eq!((b.discarded, b.created), (2, false));
        assert!(bootstrap(&c, Some(other_copy), no_key, false).is_ok());
    }

    #[test]
    fn forgetting_keeps_what_the_key_still_opens() {
        let (_, _db, c) = fresh();
        let key = MasterKey::generate();
        let same_key = MasterKey::parse(&key.base64()).unwrap();
        let (cipher, _) = bootstrap(&c, Some(key), no_key, false).unwrap();
        SealedStore::new(connect_again(&c), Arc::new(cipher)).put("KEEP_TOKEN", "kept").unwrap();
        // A value and a key check sealed with another key, e.g. after the key file was swapped.
        let other = Cipher::new(&MasterKey::generate());
        c.execute("INSERT INTO secrets (name, value, created_at, updated_at) VALUES ('LOST_TOKEN', ?, 0, 0)", [other.seal(&context("LOST_TOKEN"), b"lost")]).unwrap();
        c.execute("UPDATE settings SET value = ? WHERE key = ?", params![other.seal("key-check", KEY_CHECK_PLAIN), KEY_CHECK]).unwrap();

        let (cipher, b) = bootstrap(&c, Some(same_key), no_key, true).unwrap();
        assert_eq!(b.discarded, 1, "only the value this key can't open is dropped");
        let store = SealedStore::new(connect_again(&c), Arc::new(cipher));
        assert_eq!(store.get("KEEP_TOKEN").unwrap().unwrap().expose(), "kept");
        assert_eq!(store.names().unwrap(), ["KEEP_TOKEN"]);
    }
}
