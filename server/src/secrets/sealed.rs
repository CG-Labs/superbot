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
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroizing;

pub const PREFIX: &str = "sb1:";
const NONCE: usize = 24;
const TAG: usize = 16;
/// Settings row holding a sealed known value, to tell a wrong key from a right one.
const KEY_CHECK: &str = "secrets_key_check";
const KEY_CHECK_PLAIN: &[u8] = b"superbot master key check";
/// Settings row holding the root for derived keys, sealed under the current key. Written
/// by the first rotation (ADR 0096), so derived keys (the machine CA) outlive the key
/// they were first derived from. Absent until then: the root comes from the key itself.
const DERIVE_ROOT: &str = "secrets_derive_root";
const DERIVE_ROOT_CONTEXT: &str = "derive-root";

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

    /// 32 bytes for `purpose` (e.g. the machine CA's key, ADR 0031), derived with
    /// HMAC-SHA256 from a root that comes from the master key, or, after a rotation, from
    /// the root the first key had (sealed in `settings`, ADR 0096). Rotating the master key
    /// keeps derived keys.
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

/// Where a user's TOTP secret is sealed (ADR 0094).
pub fn mfa_context(user_id: &str) -> String {
    format!("user_mfa.secret/{user_id}")
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
    /// What re-sealing under the new key did, when the previous key opened the database.
    pub rotated: Option<Rotation>,
    /// A previous key is set, but the current key already opens everything.
    pub previous_unused: bool,
}

pub const MISSING_KEY: &str = "the database holds encrypted values but no master key was found. \
     Restore the key (SUPERBOT_MASTER_KEY or SUPERBOT_MASTER_KEY_FILE; see deploy/README.md). \
     If it is lost for good, start once with SUPERBOT_FORGET_SEALED=1 to drop the encrypted values and make a new key.";

const WRONG_KEY: &str = "the master key doesn't open this database's encrypted values (wrong key). \
     Use the key this database was sealed with; see deploy/README.md.";

const WRONG_KEYS: &str = "neither the master key nor SUPERBOT_MASTER_KEY_PREVIOUS opens this database's encrypted values. \
     Set the previous key to the one this database was sealed with; see docs/ops/master-key-rotation.md.";

const NO_NEW_KEY: &str = "SUPERBOT_MASTER_KEY_PREVIOUS is set but there is no new master key. \
     Set the new key in SUPERBOT_MASTER_KEY or SUPERBOT_MASTER_KEY_FILE; see docs/ops/master-key-rotation.md.";

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
    let mfa = c.query_row("SELECT user_id, secret FROM user_mfa LIMIT 1", [], |r| Ok((mfa_context(&r.get::<_, String>(0)?), r.get(1)?))).optional()?;
    if mfa.is_some() {
        return Ok(mfa);
    }
    c.query_row("SELECT id, input FROM approvals WHERE input LIKE 'sb1:%' LIMIT 1", [], |r| Ok((approval_context(&r.get::<_, String>(0)?), r.get(1)?)))
        .optional()
}

/// Drops the sealed values `keep` can't open (all of them without a key) and the key
/// check. Approval inputs keep a marker; everything else about them stays. Push devices
/// go, so their phones can register again. A second factor goes with its recovery codes,
/// whose keyed hashes no longer match either; if the policy requires one, its user sets
/// it up again at their next sign-in (ADR 0094).
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
    for (id, v) in pairs("SELECT id, token FROM push_devices WHERE token LIKE 'sb1:%'")?.iter().filter(|(_, v)| !opens(crate::db::PUSH_TOKEN_CONTEXT, v)) {
        n += tx.execute("DELETE FROM push_devices WHERE id = ? AND token = ?", params![id, v])?;
    }
    for (user, v) in pairs("SELECT user_id, secret FROM user_mfa")?.iter().filter(|(u, v)| !opens(&mfa_context(u), v)) {
        n += tx.execute("DELETE FROM user_mfa WHERE user_id = ? AND secret = ?", params![user, v])?;
        tx.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", [user])?;
    }
    for (id, _) in approvals.iter().filter(|(id, v)| !opens(&approval_context(id), v)) {
        n += tx.execute("UPDATE approvals SET input = '{\"sealed\":\"discarded\"}' WHERE id = ?", [id])?;
    }
    tx.execute("DELETE FROM settings WHERE key = ?", [KEY_CHECK])?;
    if derive_root(&tx)?.is_some_and(|v| !opens(DERIVE_ROOT_CONTEXT, &v)) {
        tx.execute("DELETE FROM settings WHERE key = ?", [DERIVE_ROOT])?;
    }
    tx.commit()?;
    Ok(n)
}

fn derive_root(c: &Connection) -> rusqlite::Result<Option<String>> {
    c.query_row("SELECT value FROM settings WHERE key = ?", [DERIVE_ROOT], |r| r.get(0)).optional()
}

/// `cipher` with the derived-key root this database keeps, if a rotation stored one.
fn with_root(c: &Connection, mut cipher: Cipher) -> Result<Cipher, String> {
    let Some(v) = derive_root(c).map_err(|e| format!("database: {e}"))? else { return Ok(cipher) };
    let root = cipher.open(DERIVE_ROOT_CONTEXT, &v).ok().filter(|r| r.len() == 32);
    let root = root.ok_or("the derived-key root in settings doesn't open with the master key; see deploy/README.md")?;
    cipher.1.copy_from_slice(&root);
    Ok(cipher)
}

/// What a master-key rotation did.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Rotation {
    /// Values opened with the previous key and sealed again under the new one.
    pub resealed: usize,
    /// Values already sealed under the new key, left as they were.
    pub current: usize,
    /// Values neither key opens. Left as they were: they were unreadable before too.
    pub unreadable: usize,
}

/// The key a rotation starts from, and whether derived keys change with it.
pub struct Previous {
    pub key: MasterKey,
    /// New derived keys from the new master key (a new machine CA, so every machine enrolls
    /// again), instead of keeping the ones in use. For a key that may have leaked.
    pub new_derived_keys: bool,
}

impl From<MasterKey> for Previous {
    fn from(key: MasterKey) -> Previous {
        Previous { key, new_derived_keys: false }
    }
}

/// Every sealed value in the database: the statement that replaces it, its rowid, context, and value.
fn sealed_rows(c: &Connection) -> rusqlite::Result<Vec<(&'static str, i64, String, String)>> {
    let mut out = Vec::new();
    let mut s = c.prepare("SELECT rowid, name, value FROM secrets")?;
    for r in s.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
        let (id, name, v) = r?;
        out.push(("UPDATE secrets SET value = ? WHERE rowid = ?", id, context(&name), v));
    }
    let mut s = c.prepare("SELECT rowid, user_id, name, value FROM user_secrets")?;
    for r in s.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)))? {
        let (id, user, name, v) = r?;
        out.push(("UPDATE user_secrets SET value = ? WHERE rowid = ?", id, user_context(&user, &name), v));
    }
    let mut s = c.prepare("SELECT rowid, id, input FROM approvals WHERE input LIKE 'sb1:%'")?;
    for r in s.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
        let (id, approval, v) = r?;
        out.push(("UPDATE approvals SET input = ? WHERE rowid = ?", id, approval_context(&approval), v));
    }
    let mut s = c.prepare("SELECT rowid, token FROM push_devices WHERE token LIKE 'sb1:%'")?;
    for r in s.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
        let (id, v) = r?;
        out.push(("UPDATE push_devices SET token = ? WHERE rowid = ?", id, crate::db::PUSH_TOKEN_CONTEXT.to_string(), v));
    }
    let mut s = c.prepare("SELECT rowid, user_id, secret FROM user_mfa")?;
    for r in s.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
        let (id, user, v) = r?;
        out.push(("UPDATE user_mfa SET secret = ? WHERE rowid = ?", id, mfa_context(&user), v));
    }
    Ok(out)
}

/// Seals everything `old` sealed under `new` instead, in one write transaction with its
/// audit event: a crash or error leaves the database as it was, still opened by `old`.
/// The key check is sealed again. The derived-key root `old` used is kept, sealed under
/// `new`, so the machine CA and other derived keys don't change, unless `new_derived_keys`.
/// Values `new` already opens are left alone, so running it again changes nothing.
/// MFA recovery codes are stored as keyed hashes under a derived key, so new derived keys
/// drop them: each user keeps their authenticator and makes new codes (ADR 0094).
fn rotate(c: &Connection, old: &Cipher, new: &Cipher, new_derived_keys: bool) -> rusqlite::Result<Rotation> {
    let tx = rusqlite::Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;
    let mut done = Rotation::default();
    for (update, rowid, context, v) in sealed_rows(&tx)? {
        if new.open(&context, &v).is_ok() {
            done.current += 1;
            continue;
        }
        let Ok(plain) = old.open(&context, &v) else {
            done.unreadable += 1;
            continue;
        };
        tx.execute(update, params![new.seal(&context, &plain), rowid])?;
        done.resealed += 1;
    }
    let set = "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2";
    tx.execute(set, params![KEY_CHECK, new.seal("key-check", KEY_CHECK_PLAIN)])?;
    let mut recovery_codes_dropped = 0;
    if new_derived_keys {
        tx.execute("DELETE FROM settings WHERE key = ?", [DERIVE_ROOT])?;
        recovery_codes_dropped = tx.execute("DELETE FROM mfa_recovery_codes", [])?;
    } else {
        tx.execute(set, params![DERIVE_ROOT, new.seal(DERIVE_ROOT_CONTEXT, &old.1[..])])?;
    }
    let details = serde_json::json!({
        "resealed": done.resealed,
        "current": done.current,
        "unreadable": done.unreadable,
        "derivedKeysKept": !new_derived_keys,
        "recoveryCodesDropped": recovery_codes_dropped,
    });
    tx.execute(
        "INSERT INTO audit_events (at, actor_kind, actor_id, action, target_type, target_id, outcome, details)
         VALUES (?, 'system', 'secrets', 'secret.master_key_rotated', 'secret', 'master-key', 'success', ?)",
        params![crate::db::now(), details.to_string()],
    )?;
    tx.commit()?;
    Ok(done)
}

/// Rewrites the database file and empties the WAL, so plaintext that sealing or
/// redaction replaced doesn't linger in old pages. Run after a start that changed rows.
pub fn purge_old_pages(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch("VACUUM")?;
    let busy: i64 = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
    if busy != 0 {
        crate::obs::log::log_warn!("Secrets: the database was busy, so old pages may stay in the WAL until the next checkpoint.");
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
    previous: Option<Previous>,
    create: impl FnOnce() -> Result<MasterKey, String>,
    forget: bool,
) -> Result<(Cipher, Bootstrap), String> {
    let db = |e: rusqlite::Error| format!("database: {e}");
    let mut b = Bootstrap::default();
    let cipher = match found {
        Some(k) => {
            let cipher = Cipher::new(&k);
            let old = previous.as_ref().map(|p| Cipher::new(&p.key));
            if opens(c, &cipher).map_err(db)? {
                b.previous_unused = old.is_some();
            } else if let Some(old) = match old {
                Some(old) if opens(c, &old).map_err(db)? => Some(old),
                _ => None,
            } {
                let old = with_root(c, old)?;
                let new_derived_keys = previous.as_ref().is_some_and(|p| p.new_derived_keys);
                b.rotated = Some(rotate(c, &old, &cipher, new_derived_keys).map_err(db)?);
            } else {
                if !forget {
                    return Err(if previous.is_some() { WRONG_KEYS } else { WRONG_KEY }.into());
                }
                b.discarded = discard(c, Some(&cipher)).map_err(db)?;
            }
            cipher
        }
        None if previous.is_some() => return Err(NO_NEW_KEY.into()),
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
    let cipher = with_root(c, cipher)?;
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

    /// True if it replaced a value the user already had. Checked and written in one
    /// transaction, so two first saves can't both say they were first. It takes the write
    /// lock before the read (`IMMEDIATE`): a deferred one that reads first fails with
    /// `SQLITE_BUSY_SNAPSHOT`, with no wait, if another connection writes in between.
    pub fn put(&self, user_id: &str, name: &str, value: &str) -> Result<bool, Error> {
        let sealed = self.cipher.seal(&user_context(user_id, name), value.as_bytes());
        let mut c = self.c();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate).map_err(store_err)?;
        let existed = tx.query_row("SELECT 1 FROM user_secrets WHERE user_id = ? AND name = ?", [user_id, name], |_| Ok(())).optional().map_err(store_err)?.is_some();
        tx.execute(
            "INSERT INTO user_secrets (user_id, name, value, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(user_id, name) DO UPDATE SET value = ?3, updated_at = ?4",
            params![user_id, name, sealed, crate::db::now()],
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)?;
        Ok(existed)
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
        let (cipher, b) = bootstrap(&c, None, None, || Ok(MasterKey::generate()), false).unwrap();
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
        let (cipher, _) = bootstrap(&c, None, None, || Ok(MasterKey::generate()), false).unwrap();
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
        assert!(s.put("ub", "OPENAI_API_KEY", "b-openai-2").unwrap(), "says it replaced one");
        assert!(!s.put("ua", "OPENAI_API_KEY", "a-openai").unwrap(), "B's isn't A's to replace");
        assert!(s.delete("ua", "OPENAI_API_KEY").unwrap());
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
        let (cipher, _) = bootstrap(&c, None, None, || Ok(MasterKey::generate()), false).unwrap();
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
        let (cipher, b) = bootstrap(&c, Some(key), None, no_key, false).unwrap();
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
        let (_, b) = bootstrap(&c, Some(again), None, no_key, false).unwrap();
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
        bootstrap(&c, Some(key), None, no_key, false).unwrap();
        assert_eq!(bootstrap(&c, Some(MasterKey::generate()), None, no_key, false).err().unwrap(), WRONG_KEY);
        assert_eq!(bootstrap(&c, None, None, no_key, false).err().unwrap(), MISSING_KEY);
        assert!(bootstrap(&c, Some(copy), None, no_key, false).is_ok());
    }

    #[test]
    fn a_wrong_key_is_caught_even_without_the_check_row() {
        let (_, _db, c) = fresh();
        let (cipher, _) = bootstrap(&c, Some(MasterKey::generate()), None, no_key, false).unwrap();
        SealedStore::new(connect_again(&c), Arc::new(cipher)).put("X_TOKEN", "v").unwrap();
        c.execute("DELETE FROM settings WHERE key = ?", [KEY_CHECK]).unwrap();
        assert_eq!(bootstrap(&c, Some(MasterKey::generate()), None, no_key, false).err().unwrap(), WRONG_KEY);
    }

    #[test]
    fn a_save_waits_for_another_connections_write() {
        let (_path, _db, c) = fresh();
        let (cipher, _) = bootstrap(&c, None, None, || Ok(MasterKey::generate()), false).unwrap();
        let other = connect_again(&c);
        let s = UserSecrets::new(c, Arc::new(cipher));
        s.put("ua", "A_TOKEN", "first").unwrap();
        // Another connection holds the write lock and commits a change while the save waits.
        other.execute_batch("BEGIN IMMEDIATE; INSERT INTO secrets (name, value, created_at, updated_at) VALUES ('OTHER_TOKEN', 'x', 1, 1);").unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            other.execute_batch("COMMIT").unwrap();
        });
        assert!(s.put("ua", "A_TOKEN", "second").unwrap(), "saved after the other write, not refused as a stale read");
        writer.join().unwrap();
        assert_eq!(s.get("ua", "A_TOKEN").unwrap().unwrap().expose(), "second");
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
        let (cipher, _) = bootstrap(&c, Some(key), None, no_key, false).unwrap();
        let cipher = Arc::new(cipher);
        SealedStore::new(connect_again(&c), cipher.clone()).put("X_TOKEN", "v").unwrap();
        let (_, b) = bootstrap(&c, Some(same_key), None, no_key, true).unwrap();
        assert_eq!(b.discarded, 0, "a key that works keeps everything, even with the flag left on");
        let sealed = cipher.seal(&approval_context("a1"), b"{}");
        c.execute(
            "INSERT INTO approvals (id, bot_id, harness, tool, kind, subject, input, class, reason, status, created_at, expires_at)
             VALUES ('a1', ?, 'claude', 'Bash', 'shell', 'ls', ?, '', 'r', 'denied', 0, 0)",
            params![bot.id, sealed],
        )
        .unwrap();
        let (fresh_cipher, b) = bootstrap(&c, None, None, || Ok(MasterKey::generate()), true).unwrap();
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
        let (_, b) = bootstrap(&c, Some(other), None, no_key, true).unwrap();
        assert_eq!((b.discarded, b.created), (2, false));
        assert!(bootstrap(&c, Some(other_copy), None, no_key, false).is_ok());
    }

    #[test]
    fn forgetting_keeps_what_the_key_still_opens() {
        let (_, db, c) = fresh();
        let key = MasterKey::generate();
        let same_key = MasterKey::parse(&key.base64()).unwrap();
        let (cipher, _) = bootstrap(&c, Some(key), None, no_key, false).unwrap();
        let push = |cipher: &Cipher, n: u8| {
            let u = db.create_user(None, Some(&format!("p{n}@example.com")), "P", crate::rbac::Role::Member).unwrap();
            let s = crate::db::NewSession { user_id: &u.id, token_hash: &crate::random_hex(16), kind: "token", method: "code", idp_subject: None, idp_provider: None, label: None, ip: None, user_agent: None, expires_at: crate::db::now() + 60_000, mfa: None };
            let s = db.create_session(&s).id;
            let token = cipher.seal(crate::db::PUSH_TOKEN_CONTEXT, format!("ExponentPushToken[{n}]").as_bytes());
            c.execute(
                "INSERT INTO push_devices (id, user_id, session_id, provider, token_hash, token, platform, created_at, updated_at) VALUES (?1, ?2, ?3, 'expo', ?1, ?4, 'ios', 0, 0)",
                params![format!("pd{n}"), u.id, s, token],
            )
            .unwrap();
        };
        push(&cipher, 1);
        let mfa = |cipher: &Cipher, n: u8| {
            let u = db.create_user(None, Some(&format!("m{n}@example.com")), "M", crate::rbac::Role::Member).unwrap();
            assert!(db.mfa_enable(&u.id, &cipher.seal(&mfa_context(&u.id), b"12345678901234567890"), 1, &[format!("hash{n}")]));
            u.id
        };
        let kept_mfa = mfa(&cipher, 1);
        SealedStore::new(connect_again(&c), Arc::new(cipher)).put("KEEP_TOKEN", "kept").unwrap();
        // A value and a key check sealed with another key, e.g. after the key file was swapped.
        let other = Cipher::new(&MasterKey::generate());
        c.execute("INSERT INTO secrets (name, value, created_at, updated_at) VALUES ('LOST_TOKEN', ?, 0, 0)", [other.seal(&context("LOST_TOKEN"), b"lost")]).unwrap();
        push(&other, 2);
        let lost_mfa = mfa(&other, 2);
        c.execute("UPDATE settings SET value = ? WHERE key = ?", params![other.seal("key-check", KEY_CHECK_PLAIN), KEY_CHECK]).unwrap();

        let (cipher, b) = bootstrap(&c, Some(same_key), None, no_key, true).unwrap();
        assert_eq!(b.discarded, 3, "only the values this key can't open are dropped");
        let left: Vec<String> = c.prepare("SELECT id FROM push_devices").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
        assert_eq!(left, ["pd1"], "an unreadable push device goes, so its phone can register again");
        assert!(db.mfa(&kept_mfa).is_some() && db.mfa_recovery_left(&kept_mfa) == 1);
        assert!(db.mfa(&lost_mfa).is_none() && db.mfa_recovery_left(&lost_mfa) == 0, "an unreadable second factor goes with its recovery codes");
        let store = SealedStore::new(connect_again(&c), Arc::new(cipher));
        assert_eq!(store.get("KEEP_TOKEN").unwrap().unwrap().expose(), "kept");
        assert_eq!(store.names().unwrap(), ["KEEP_TOKEN"]);
    }

    fn copy(k: &MasterKey) -> MasterKey {
        MasterKey::parse(&k.base64()).unwrap()
    }

    /// One sealed value of each kind: a saved secret, a user's secret, an approval input,
    /// a push token and a second factor with one recovery code. Returns how many.
    fn seal_one_of_each(db: &Db, c: &Connection, cipher: &Arc<Cipher>) -> usize {
        SealedStore::new(connect_again(c), cipher.clone()).put("OPENAI_API_KEY", "sk-saved").unwrap();
        UserSecrets::new(connect_again(c), cipher.clone()).put("ua", "GITHUB_TOKEN", "ghp-mine").unwrap();
        let bot = db.create_bot("A", "#fff", "waddle", "claude", None, true);
        c.execute(
            "INSERT INTO approvals (id, bot_id, harness, tool, kind, subject, input, class, reason, status, created_at, expires_at)
             VALUES ('a1', ?, 'claude', 'Bash', 'shell', 'ls', ?, '', 'r', 'denied', 0, 0)",
            params![bot.id, cipher.seal(&approval_context("a1"), br#"{"command":"ls"}"#)],
        )
        .unwrap();
        let u = db.create_user(None, Some("rot@example.com"), "R", crate::rbac::Role::Member).unwrap();
        let s = crate::db::NewSession { user_id: &u.id, token_hash: &crate::random_hex(16), kind: "token", method: "code", idp_subject: None, idp_provider: None, label: None, ip: None, user_agent: None, expires_at: now() + 60_000, mfa: None };
        let s = db.create_session(&s).id;
        c.execute(
            "INSERT INTO push_devices (id, user_id, session_id, provider, token_hash, token, platform, created_at, updated_at) VALUES ('pd1', ?1, ?2, 'expo', 'pd1', ?3, 'ios', 0, 0)",
            params![u.id, s, cipher.seal(crate::db::PUSH_TOKEN_CONTEXT, b"ExponentPushToken[r]")],
        )
        .unwrap();
        assert!(db.mfa_enable(&u.id, &cipher.seal(&mfa_context(&u.id), b"12345678901234567890"), 1, &["hash".into()]));
        5
    }

    /// Whether every value `seal_one_of_each` wrote opens with `cipher`, as it was written.
    fn all_open_with(c: &Connection, cipher: &Cipher) -> bool {
        let one = |sql: &str| -> String { c.query_row(sql, [], |r| r.get(0)).unwrap() };
        let is = |context: &str, v: String, want: &[u8]| cipher.open(context, &v).is_ok_and(|p| p.as_slice() == want);
        is(&context("OPENAI_API_KEY"), one("SELECT value FROM secrets"), b"sk-saved")
            && is(&user_context("ua", "GITHUB_TOKEN"), one("SELECT value FROM user_secrets"), b"ghp-mine")
            && is(&approval_context("a1"), one("SELECT input FROM approvals WHERE id = 'a1'"), br#"{"command":"ls"}"#)
            && is(crate::db::PUSH_TOKEN_CONTEXT, one("SELECT token FROM push_devices"), b"ExponentPushToken[r]")
            && is(&mfa_context(&one("SELECT user_id FROM user_mfa")), one("SELECT secret FROM user_mfa"), b"12345678901234567890")
    }

    fn recovery_codes(c: &Connection) -> i64 {
        c.query_row("SELECT COUNT(*) FROM mfa_recovery_codes", [], |r| r.get(0)).unwrap()
    }

    fn rotations(c: &Connection) -> Vec<serde_json::Value> {
        let mut s = c.prepare("SELECT details FROM audit_events WHERE action = 'secret.master_key_rotated' ORDER BY id").unwrap();
        s.query_map([], |r| r.get::<_, String>(0)).unwrap().map(|d| serde_json::from_str(&d.unwrap()).unwrap()).collect()
    }

    #[test]
    fn rotation_reseals_everything_under_the_new_key_and_keeps_derived_keys() {
        let (_, db, c) = fresh();
        let a = MasterKey::generate();
        let (cipher_a, _) = bootstrap(&c, Some(copy(&a)), None, no_key, false).unwrap();
        let ca = cipher_a.derive("machine-ca");
        let cipher_a = Arc::new(cipher_a);
        let n = seal_one_of_each(&db, &c, &cipher_a);

        let b = MasterKey::generate();
        let (cipher_b, boot) = bootstrap(&c, Some(copy(&b)), Some(copy(&a).into()), no_key, false).unwrap();
        assert_eq!(boot.rotated, Some(Rotation { resealed: n, current: 0, unreadable: 0 }));
        assert!(!boot.previous_unused);
        assert!(all_open_with(&c, &cipher_b), "every value opens with the new key");
        assert!(!all_open_with(&c, &Cipher::new(&a)), "and no longer with the old one");
        assert_eq!(cipher_b.derive("machine-ca"), ca, "derived keys (the machine CA) survive the rotation");
        let events = rotations(&c);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["resealed"], n);
        assert_eq!(events[0]["derivedKeysKept"], true);
        assert_eq!(recovery_codes(&c), 1, "recovery codes still match: their key is derived");
        let audit: String = c.query_row("SELECT actor_kind || '/' || actor_id || '/' || target_id FROM audit_events WHERE action = 'secret.master_key_rotated'", [], |r| r.get(0)).unwrap();
        assert_eq!(audit, "system/secrets/master-key");

        // The new key alone opens it from now on; the old one alone is refused.
        assert!(bootstrap(&c, Some(copy(&b)), None, no_key, false).is_ok());
        assert_eq!(bootstrap(&c, Some(copy(&a)), None, no_key, false).err().unwrap(), WRONG_KEY);

        // A second rotation keeps the same derived keys.
        let k3 = MasterKey::generate();
        let (cipher_3, boot) = bootstrap(&c, Some(copy(&k3)), Some(copy(&b).into()), no_key, false).unwrap();
        assert_eq!(boot.rotated.unwrap().resealed, n);
        assert!(all_open_with(&c, &cipher_3));
        assert_eq!(cipher_3.derive("machine-ca"), ca);
        assert_eq!(rotations(&c).len(), 2);
    }

    #[test]
    fn a_rotation_can_change_derived_keys_too() {
        let (_, db, c) = fresh();
        let a = MasterKey::generate();
        let (cipher_a, _) = bootstrap(&c, Some(copy(&a)), None, no_key, false).unwrap();
        let n = seal_one_of_each(&db, &c, &Arc::new(cipher_a));
        let b = MasterKey::generate();
        bootstrap(&c, Some(copy(&b)), Some(copy(&a).into()), no_key, false).unwrap();
        // A second rotation, from a key that may have leaked: the CA goes with it.
        let k3 = MasterKey::generate();
        let previous = Previous { key: copy(&b), new_derived_keys: true };
        let (cipher_3, boot) = bootstrap(&c, Some(copy(&k3)), Some(previous), no_key, false).unwrap();
        assert_eq!(boot.rotated.unwrap().resealed, n);
        assert!(all_open_with(&c, &cipher_3));
        assert_eq!(cipher_3.derive("machine-ca"), Cipher::new(&k3).derive("machine-ca"), "derived from the new key alone");
        assert_ne!(cipher_3.derive("machine-ca"), Cipher::new(&a).derive("machine-ca"));
        assert_eq!(rotations(&c)[1]["derivedKeysKept"], false);
        assert_eq!(rotations(&c)[1]["recoveryCodesDropped"], 1);
        assert_eq!(recovery_codes(&c), 0, "recovery codes hashed under the old derived key go");
        let (again, _) = bootstrap(&c, Some(k3), None, no_key, false).unwrap();
        assert_eq!(again.derive("machine-ca"), cipher_3.derive("machine-ca"));
    }

    #[test]
    fn rotating_again_changes_nothing() {
        let (_, db, c) = fresh();
        let a = MasterKey::generate();
        let (cipher_a, _) = bootstrap(&c, Some(copy(&a)), None, no_key, false).unwrap();
        seal_one_of_each(&db, &c, &Arc::new(cipher_a));
        let b = MasterKey::generate();
        bootstrap(&c, Some(copy(&b)), Some(copy(&a).into()), no_key, false).unwrap();
        let before: Vec<String> = c.prepare("SELECT value FROM secrets UNION ALL SELECT value FROM settings").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();

        // The previous key left set across restarts: nothing to do, and botd says so.
        for _ in 0..2 {
            let (cipher_b, boot) = bootstrap(&c, Some(copy(&b)), Some(copy(&a).into()), no_key, false).unwrap();
            assert!(boot.rotated.is_none() && boot.previous_unused);
            assert!(all_open_with(&c, &cipher_b));
        }
        let after: Vec<String> = c.prepare("SELECT value FROM secrets UNION ALL SELECT value FROM settings").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
        assert_eq!(before, after, "no value was sealed again");
        assert_eq!(rotations(&c).len(), 1, "one rotation, one audit event");

        // The same key as both: nothing to rotate.
        let (_, boot) = bootstrap(&c, Some(copy(&b)), Some(copy(&b).into()), no_key, false).unwrap();
        assert!(boot.rotated.is_none() && boot.previous_unused);
    }

    #[test]
    fn a_crash_in_the_middle_of_a_rotation_loses_nothing_and_the_next_start_finishes_it() {
        let (_, db, c) = fresh();
        let a = MasterKey::generate();
        let (cipher_a, _) = bootstrap(&c, Some(copy(&a)), None, no_key, false).unwrap();
        let cipher_a = Arc::new(cipher_a);
        let n = seal_one_of_each(&db, &c, &cipher_a);
        // Fail after `secrets` was sealed again, part-way through the other tables.
        c.execute_batch("CREATE TEMP TRIGGER crash BEFORE UPDATE ON user_secrets BEGIN SELECT RAISE(ABORT, 'crash'); END;").unwrap();
        let b = MasterKey::generate();
        let err = bootstrap(&c, Some(copy(&b)), Some(copy(&a).into()), no_key, false).err().unwrap();
        assert!(err.contains("crash"), "{err}");
        assert!(all_open_with(&c, &cipher_a), "everything is still sealed under the old key");
        assert!(rotations(&c).is_empty(), "no audit event for a rotation that didn't happen");
        // Until the rotation completes, the old key alone still works.
        assert!(bootstrap(&c, Some(copy(&a)), None, no_key, false).is_ok());
        assert_eq!(bootstrap(&c, Some(copy(&b)), None, no_key, false).err().unwrap(), WRONG_KEY);

        c.execute_batch("DROP TRIGGER crash").unwrap();
        let (cipher_b, boot) = bootstrap(&c, Some(copy(&b)), Some(copy(&a).into()), no_key, false).unwrap();
        assert_eq!(boot.rotated.unwrap().resealed, n);
        assert!(all_open_with(&c, &cipher_b));
        assert_eq!(cipher_b.derive("machine-ca"), cipher_a.derive("machine-ca"));
    }

    #[test]
    fn wrong_keys_refuse_to_start_and_change_nothing() {
        let (_, db, c) = fresh();
        let a = MasterKey::generate();
        let (cipher_a, _) = bootstrap(&c, Some(copy(&a)), None, no_key, false).unwrap();
        let cipher_a = Arc::new(cipher_a);
        seal_one_of_each(&db, &c, &cipher_a);
        let err = bootstrap(&c, Some(MasterKey::generate()), Some(MasterKey::generate().into()), no_key, false).err().unwrap();
        assert_eq!(err, WRONG_KEYS);
        assert_eq!(bootstrap(&c, None, Some(copy(&a).into()), no_key, false).err().unwrap(), NO_NEW_KEY, "a key is never made during a rotation");
        assert!(all_open_with(&c, &cipher_a));
        assert!(rotations(&c).is_empty());
        // A wrong previous key with the right current one: nothing to rotate.
        let (_, boot) = bootstrap(&c, Some(copy(&a)), Some(MasterKey::generate().into()), no_key, false).unwrap();
        assert!(boot.rotated.is_none() && boot.previous_unused);
    }

    #[test]
    fn values_neither_key_opens_are_left_as_they_were() {
        let (_, db, c) = fresh();
        let a = MasterKey::generate();
        let (cipher_a, _) = bootstrap(&c, Some(copy(&a)), None, no_key, false).unwrap();
        let n = seal_one_of_each(&db, &c, &Arc::new(cipher_a));
        let lost = Cipher::new(&MasterKey::generate()).seal(&context("LOST_TOKEN"), b"lost");
        c.execute("INSERT INTO secrets (name, value, created_at, updated_at) VALUES ('LOST_TOKEN', ?, 0, 0)", [&lost]).unwrap();
        let b = MasterKey::generate();
        let (_, boot) = bootstrap(&c, Some(copy(&b)), Some(copy(&a).into()), no_key, false).unwrap();
        assert_eq!(boot.rotated, Some(Rotation { resealed: n, current: 0, unreadable: 1 }));
        let kept: String = c.query_row("SELECT value FROM secrets WHERE name = 'LOST_TOKEN'", [], |r| r.get(0)).unwrap();
        assert_eq!(kept, lost);
        assert_eq!(rotations(&c)[0]["unreadable"], 1);
    }

    #[test]
    fn forgetting_after_a_rotation_drops_a_derived_root_the_key_cant_open() {
        let (_, db, c) = fresh();
        let a = MasterKey::generate();
        let (cipher_a, _) = bootstrap(&c, Some(copy(&a)), None, no_key, false).unwrap();
        let n = seal_one_of_each(&db, &c, &Arc::new(cipher_a));
        bootstrap(&c, Some(MasterKey::generate()), Some(copy(&a).into()), no_key, false).unwrap();
        // The rotated key is lost: a new one starts over, with new derived keys.
        let fresh_key = MasterKey::generate();
        let (cipher, boot) = bootstrap(&c, Some(copy(&fresh_key)), None, no_key, true).unwrap();
        assert_eq!(boot.discarded, n);
        assert_eq!(cipher.derive("machine-ca"), Cipher::new(&fresh_key).derive("machine-ca"));
        assert!(bootstrap(&c, Some(fresh_key), None, no_key, false).is_ok());
    }
}
