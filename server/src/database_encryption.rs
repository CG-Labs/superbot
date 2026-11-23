//! The database encrypted at rest (ADR 0116): SQLCipher (AES-256 pages, each with an
//! HMAC) under a key derived from the master key, so `app.sqlite`, a disk image or the
//! database in a backup reads as noise without the master key.
//!
//! SUPERBOT_DATABASE_ENCRYPTION says what to do with a plain database: `auto` (the default)
//! creates new databases encrypted and leaves an existing plain one plain, with a warning
//! at startup, an open setup checklist item and `/metrics`; `required` encrypts a plain
//! database at start, keeping a plain copy beside it until the operator deletes it, and
//! refuses to start if it can't; `off` creates new databases plain by choice, which
//! `/metrics` and the audit log still show. An encrypted database is always opened with
//! its key, whatever the setting: botd never decrypts one. Every change of policy,
//! encryption or plain copies is audited once, as `server.database_encryption_changed`.
//!
//! The key changes with the master key: a rotation (ADR 0096) re-encrypts the file under
//! the new key at start, before the sealed values are sealed again.

use crate::audit::{Actor, Event};
use crate::obs::metrics;
use crate::runner::App;
use crate::secrets::key::MasterKey;
use crate::secrets::Keys;
use crate::AppState;
use rusqlite::{params, Connection, OpenFlags};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use zeroize::Zeroizing;

/// Settings key: the last state audited, as `state_key` writes it.
const STATE: &str = "database_encryption_state";
const ACTOR: &str = "database-encryption";
/// How often botd looks again: the operator may delete a plain copy at any time.
const EVERY: Duration = Duration::from_secs(60);
/// What every plain SQLite file starts with. SQLCipher's first 16 bytes are a random salt.
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
/// HMAC-SHA256 purpose for the database key, under the master key itself: the derived-key
/// root (ADR 0096) lives inside the database, so it can't be what opens it.
const PURPOSE: &[u8] = b"superbot/database/v1";
/// A plain copy kept when a plain database is encrypted: `app.sqlite-plain-<UTC stamp>`.
/// superbot-backup leaves `app.sqlite-*` out of archives.
pub const PLAIN_COPY_PREFIX: &str = "app.sqlite-plain-";
/// Where a re-encrypted copy is written before it replaces the database.
const WORK_SUFFIX: &str = "-reencrypt";

const NO_KEY: &str = "the database is encrypted (ADR 0116) but no master key was found. \
     Restore the key it was encrypted under (SUPERBOT_MASTER_KEY or SUPERBOT_MASTER_KEY_FILE; see docs/ops/database-encryption.md). \
     Without it the database can't be read, and SUPERBOT_FORGET_SEALED doesn't help: restore a backup and its key instead.";

const WRONG_KEY: &str = "the master key doesn't open the encrypted database (wrong key). \
     Use the key it was encrypted under; after a rotation, set the old one as SUPERBOT_MASTER_KEY_PREVIOUS (docs/ops/master-key-rotation.md).";

const WRONG_KEYS: &str = "neither the master key nor SUPERBOT_MASTER_KEY_PREVIOUS opens the encrypted database (wrong key). \
     Set the previous key to the one it was encrypted under; see docs/ops/master-key-rotation.md.";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Policy {
    Auto,
    Required,
    Off,
}

impl Policy {
    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Auto => "auto",
            Policy::Required => "required",
            Policy::Off => "off",
        }
    }

    /// SUPERBOT_DATABASE_ENCRYPTION: auto (or unset), required or off.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Policy, String> {
        match var("SUPERBOT_DATABASE_ENCRYPTION").trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Policy::Auto),
            "required" => Ok(Policy::Required),
            "off" => Ok(Policy::Off),
            other => Err(format!("SUPERBOT_DATABASE_ENCRYPTION must be auto, required or off, not \"{}\"", crate::audit::clip(other, 20))),
        }
    }
}

/// SQLCipher's raw key, `x'<64 hex>'`: used as is, with no passphrase stretching.
#[derive(Clone)]
pub struct DbKey(Zeroizing<String>);

impl std::fmt::Debug for DbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(crate::secrets::redact::MARK)
    }
}

impl DbKey {
    pub fn derive(master: &MasterKey) -> DbKey {
        use aws_lc_rs::hmac;
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, master.bytes()), PURPOSE);
        let hex: Zeroizing<String> = Zeroizing::new(tag.as_ref().iter().map(|b| format!("{b:02x}")).collect());
        DbKey(Zeroizing::new(format!("x'{}'", hex.as_str())))
    }

    /// The key as SQLCipher takes it in `ATTACH ... KEY`.
    pub(crate) fn raw(&self) -> &str {
        self.0.as_str()
    }
}

/// What a database file is, from its first bytes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Format {
    /// No file, or an empty one: SQLite makes a new database.
    Missing,
    Plain,
    Encrypted,
}

pub fn format(path: &Path) -> Result<Format, String> {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Format::Missing),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut head = Vec::with_capacity(16);
    f.take(16).read_to_end(&mut head).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(match head.as_slice() {
        [] => Format::Missing,
        h if h == SQLITE_HEADER => Format::Plain,
        _ => Format::Encrypted,
    })
}

/// The key this process opens its database with, set once at startup when it's encrypted.
static KEY: OnceLock<DbKey> = OnceLock::new();

pub fn install(key: DbKey) {
    let _ = KEY.set(key);
}

/// The key botd's database is open with. None: it is plain.
pub fn installed() -> Option<&'static DbKey> {
    KEY.get()
}

/// Brings a region's chat store (ADR 0215) under `key`, botd's own database key: encrypts
/// a plain one when botd's is encrypted, and re-encrypts one `previous` opens, mid-rotation
/// (ADR 0096), with the same verified copy as botd's own. No plain copy is kept: the store
/// holds only chats, already in its region's backups. True if it changed.
pub fn prepare_store(path: &Path, key: Option<&DbKey>, previous: Option<&DbKey>) -> Result<bool, String> {
    let shown = path.display();
    match (format(path)?, key) {
        (Format::Missing, _) | (Format::Plain, None) => Ok(false),
        (Format::Plain, Some(k)) => reencrypt(path, None, Some(k), None).map(|_| true).map_err(|e| format!("{shown}: {e}")),
        (Format::Encrypted, None) => Err(format!("{shown} is encrypted but botd's database isn't; a chat store is kept like botd's own database (ADR 0215)")),
        (Format::Encrypted, Some(k)) if opens(path, k) => Ok(false),
        (Format::Encrypted, Some(k)) => match previous.filter(|p| opens(path, p)) {
            Some(p) => reencrypt(path, Some(p), Some(k), None).map(|_| true).map_err(|e| format!("{shown}: {e}")),
            None => Err(format!("{shown} doesn't open with botd's database key: {WRONG_KEY}")),
        },
    }
}

/// A connection to botd's database: with its key when it is encrypted.
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    open_with(path, KEY.get())
}

pub fn open_with(path: &Path, key: Option<&DbKey>) -> rusqlite::Result<Connection> {
    keyed(Connection::open(path)?, key)
}

pub(crate) fn open_read_only(path: &Path, key: Option<&DbKey>) -> rusqlite::Result<Connection> {
    keyed(Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?, key)
}

fn keyed(c: Connection, key: Option<&DbKey>) -> rusqlite::Result<Connection> {
    // SQLCipher writes its own lines to stderr when a key doesn't fit; botd says what it means.
    c.execute_batch("PRAGMA cipher_log_level = NONE")?;
    if let Some(k) = key {
        c.key(None::<&str>, k.0.as_bytes(), false)?;
    }
    Ok(c)
}

/// Whether `key` opens the encrypted database at `path`. A wrong key reads as "not a database".
pub fn opens(path: &Path, key: &DbKey) -> bool {
    open_read_only(path, Some(key)).and_then(|c| c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))).is_ok()
}

/// What startup did to the database file.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Start {
    pub encrypted: bool,
    /// A new database, created encrypted.
    pub created: bool,
    /// A plain database encrypted on this start: the plain copy kept beside it.
    pub migrated: Option<String>,
    /// Re-encrypted under the new master key, mid-rotation (ADR 0096).
    pub rekeyed: bool,
}

/// Opens the way for `Db::open`: works out the key, makes the master key for a new
/// database, encrypts a plain one under `required`, and re-encrypts one the previous key
/// opens under the current key. Returns the key to open it with (None: plain). Nothing
/// is changed when it fails, and the original file is replaced only by a verified copy.
pub fn prepare(path: &Path, policy: Policy, keys: &mut Keys) -> Result<(Option<DbKey>, Start), String> {
    match format(path)? {
        Format::Missing if policy == Policy::Off => Ok((None, Start::default())),
        Format::Missing => {
            let key = DbKey::derive(keys.current_or_create()?);
            Ok((Some(key), Start { encrypted: true, created: true, ..Start::default() }))
        }
        Format::Encrypted => {
            let current = keys.current.as_ref().map(|(k, _)| DbKey::derive(k));
            if let Some(k) = current.as_ref().filter(|k| opens(path, k)) {
                return Ok((Some(k.clone()), Start { encrypted: true, ..Start::default() }));
            }
            let previous = keys.previous.as_ref().map(|(k, _)| DbKey::derive(k));
            match (current, previous) {
                (None, _) => Err(NO_KEY.into()),
                (Some(cur), Some(prev)) if opens(path, &prev) => {
                    reencrypt(path, Some(&prev), Some(&cur), None)?;
                    Ok((Some(cur), Start { encrypted: true, rekeyed: true, ..Start::default() }))
                }
                (Some(_), Some(_)) => Err(WRONG_KEYS.into()),
                (Some(_), None) => Err(WRONG_KEY.into()),
            }
        }
        Format::Plain if policy != Policy::Required => Ok((None, Start::default())),
        Format::Plain => {
            // Bring the schema up to date, then check the key against what's sealed, so the
            // file is never encrypted under a key that isn't the database's own.
            drop(crate::db::Db::open(path).map_err(|e| format!("database: {e}"))?);
            {
                let c = open_with(path, None).map_err(|e| format!("database: {e}"))?;
                // A database from before saved secrets doesn't have their tables yet.
                c.execute_batch(crate::secrets::sealed::SCHEMA).map_err(|e| format!("database: {e}"))?;
                let (current, previous) = (keys.current.as_ref().map(|(k, _)| k), keys.previous.as_ref().map(|(k, _)| k));
                crate::secrets::sealed::check_keys(&c, current, previous, crate::secrets::forget_sealed())?;
            }
            let key = DbKey::derive(keys.current_or_create()?);
            let name = format!("{PLAIN_COPY_PREFIX}{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
            reencrypt(path, None, Some(&key), Some(&path.with_file_name(&name)))?;
            Ok((Some(key), Start { encrypted: true, migrated: Some(name), ..Start::default() }))
        }
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

fn remove_files(path: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(with_suffix(path, suffix));
    }
}

/// Every table's row count, to check a copy against the original.
fn counts(c: &Connection) -> rusqlite::Result<Vec<(String, i64)>> {
    let names: Vec<String> = {
        let mut s = c.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
        s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
    };
    names
        .into_iter()
        .map(|n| {
            let count = c.query_row(&format!("SELECT count(*) FROM \"{}\"", n.replace('"', "\"\"")), [], |r| r.get(0))?;
            Ok((n, count))
        })
        .collect()
}

fn user_version(c: &Connection) -> rusqlite::Result<i64> {
    c.query_row("PRAGMA user_version", [], |r| r.get(0))
}

fn sync_dir(path: &Path) {
    if let Some(dir) = path.parent().and_then(|d| std::fs::File::open(d).ok()) {
        let _ = dir.sync_all();
    }
}

/// Copies the database at `path` (opened with `from`) into a new file under `to`, checks
/// the copy (integrity, every table's rows, the schema version), and only then puts it in
/// the database's place with one rename. `keep`: a plain copy of the original is linked
/// there first. Any failure leaves the original as it was.
pub fn reencrypt(path: &Path, from: Option<&DbKey>, to: Option<&DbKey>, keep: Option<&Path>) -> Result<(), String> {
    let work = with_suffix(path, WORK_SUFFIX);
    remove_files(&work);
    let r = reencrypt_via(path, &work, from, to, keep);
    if r.is_err() {
        remove_files(&work);
    }
    r
}

fn reencrypt_via(path: &Path, work: &Path, from: Option<&DbKey>, to: Option<&DbKey>, keep: Option<&Path>) -> Result<(), String> {
    let db = |e: rusqlite::Error| format!("encrypting the database: {e}");
    let work_str = work.to_str().ok_or("DATA_DIR must be valid UTF-8")?;
    // Held until the copy is in place, so no other connection writes to the original
    // after it is copied. Leaving WAL needs every other connection closed, and the
    // exclusive locking mode keeps the write lock taken below until `c` is dropped.
    let c = open_with(path, from).map_err(db)?;
    c.busy_timeout(std::time::Duration::from_secs(1)).map_err(db)?;
    let busy = |e: rusqlite::Error| match e.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            "encrypting the database: another process has it open (is another botd running?); nothing was changed".to_string()
        }
        _ => db(e),
    };
    let mode: String = c.query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0)).map_err(busy)?;
    if mode != "delete" {
        return Err(format!("encrypting the database: it stayed in {mode} mode (is another botd running?); nothing was changed"));
    }
    c.execute_batch("PRAGMA locking_mode = EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT;").map_err(busy)?;
    let before = counts(&c).map_err(db)?;
    let version = user_version(&c).map_err(db)?;
    c.execute("ATTACH DATABASE ?1 AS reencrypt KEY ?2", params![work_str, to.map_or("", |k| k.0.as_str())]).map_err(db)?;
    c.query_row("SELECT sqlcipher_export('reencrypt')", [], |_| Ok(())).map_err(db)?;
    c.execute_batch(&format!("PRAGMA reencrypt.user_version = {version}")).map_err(db)?;
    c.execute("DETACH DATABASE reencrypt", []).map_err(db)?;
    {
        let w = open_with(work, to).map_err(db)?;
        let check: String = w.query_row("PRAGMA integrity_check", [], |r| r.get(0)).map_err(db)?;
        if check != "ok" {
            return Err(format!("encrypting the database: the copy failed its integrity check ({check}); nothing was changed"));
        }
        if counts(&w).map_err(db)? != before || user_version(&w).map_err(db)? != version {
            return Err("encrypting the database: the copy doesn't hold the same rows; nothing was changed".into());
        }
    }
    fn io(what: &Path) -> impl FnOnce(std::io::Error) -> String + '_ {
        move |e| format!("encrypting the database: {}: {e}", what.display())
    }
    std::fs::File::open(work).and_then(|f| f.sync_all()).map_err(io(work))?;
    if let Some(keep) = keep {
        use std::os::unix::fs::PermissionsExt;
        // A hard link costs no space; a copy where links aren't allowed.
        if std::fs::hard_link(path, keep).is_err() {
            std::fs::copy(path, keep).map_err(io(keep))?;
        }
        std::fs::set_permissions(keep, std::fs::Permissions::from_mode(0o600)).map_err(io(keep))?;
        std::fs::File::open(keep).and_then(|f| f.sync_all()).map_err(io(keep))?;
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(with_suffix(path, suffix));
    }
    std::fs::rename(work, path).map_err(io(path))?;
    sync_dir(path);
    drop(c);
    Ok(())
}

/// Held for botd's lifetime: a second botd on the same DATA_DIR would write to a database
/// the first may be replacing, or run the same routines twice.
pub fn lock_data_dir(db_path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let lock = with_suffix(db_path, "-lock");
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(&lock).map_err(|e| format!("{}: {e}", lock.display()))?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => Err(format!("another botd is using this DATA_DIR (it holds {}); stop it first", lock.display())),
        Err(std::fs::TryLockError::Error(e)) => Err(format!("{}: {e}", lock.display())),
    }
}

/// A plain copy of the database left by encrypting it.
#[derive(Clone, Debug, PartialEq)]
pub struct PlainCopy {
    pub name: String,
    pub bytes: u64,
}

pub fn plain_copies(dir: &Path) -> Vec<PlainCopy> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PlainCopy> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            let meta = e.metadata().ok().filter(|m| m.is_file())?;
            name.starts_with(PLAIN_COPY_PREFIX).then_some(PlainCopy { name, bytes: meta.len() })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The database's encryption as found at startup.
#[derive(Clone, Debug)]
pub struct State {
    pub policy: Policy,
    pub start: Start,
    /// DATA_DIR, where plain copies are.
    pub dir: PathBuf,
    /// Set until the first `watch`, which then audits this start's migration or rekey even
    /// when the state it records is the same as before.
    announce: Arc<AtomicBool>,
}

impl State {
    pub fn new(policy: Policy, start: Start, dir: &Path) -> State {
        let announce = Arc::new(AtomicBool::new(start.migrated.is_some() || start.rekeyed));
        State { policy, start, dir: dir.to_path_buf(), announce }
    }

    pub fn encrypted(&self) -> bool {
        self.start.encrypted
    }
}

fn names(copies: &[PlainCopy]) -> String {
    copies.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ")
}

/// The lines botd logs at startup: one summary, then warnings for a plain database (unless
/// plaintext was chosen) and for each plain copy left beside an encrypted one.
pub fn startup_lines(s: &State, copies: &[PlainCopy]) -> (String, Vec<String>) {
    let policy = s.policy.as_str();
    let summary = match (s.encrypted(), s.policy) {
        (true, p) => {
            let mut line = format!("encrypted with SQLCipher under a key derived from the master key, SUPERBOT_DATABASE_ENCRYPTION={policy}");
            if s.start.created {
                line.push_str("; created encrypted");
            }
            if let Some(copy) = &s.start.migrated {
                line.push_str(&format!("; encrypted the plain database on this start, keeping a plain copy in {copy}"));
            }
            if s.start.rekeyed {
                line.push_str("; re-encrypted under the new master key");
            }
            if p == Policy::Off {
                line.push_str("; off doesn't decrypt a database that is already encrypted");
            }
            line
        }
        (false, Policy::Off) => "plain by choice (SUPERBOT_DATABASE_ENCRYPTION=off); anyone who gets app.sqlite can read it".into(),
        (false, _) => format!("plain, SUPERBOT_DATABASE_ENCRYPTION={policy}"),
    };
    let mut warnings = Vec::new();
    if !s.encrypted() && s.policy != Policy::Off {
        warnings.push(
            "The database isn't encrypted: anyone who gets app.sqlite, a disk image or a copy of DATA_DIR can read every chat, Bot's memory and the audit log in it. \
             Set SUPERBOT_DATABASE_ENCRYPTION=required and restart to encrypt it; botd keeps a plain copy until you delete it (docs/ops/database-encryption.md, ADR 0116)."
                .to_string(),
        );
    }
    if !copies.is_empty() {
        warnings.push(format!(
            "A plain copy of the database from before it was encrypted is still in DATA_DIR: {}. Anyone who gets it can read it. Check SuperBot looks right, then delete it (docs/ops/database-encryption.md#the-plain-copy).",
            names(copies)
        ));
    }
    (summary, warnings)
}

fn state_key(s: &State, copies: &[PlainCopy]) -> String {
    format!("{} encrypted={} plain_copies={}", s.policy.as_str(), s.encrypted(), copies.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(","))
}

/// Audits a change of policy, encryption or plain copies once, and this start's migration
/// or rekey. True if it recorded one.
pub fn watch(app: &App) -> bool {
    static WATCHING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = WATCHING.lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = app.database.get() else {
        return false;
    };
    let copies = plain_copies(&s.dir);
    let key = state_key(s, &copies);
    let previous = app.db.setting(STATE);
    let announce = s.announce.load(Ordering::SeqCst);
    if previous.as_deref() == Some(key.as_str()) && !announce {
        return false;
    }
    let d = json!({
        "policy": s.policy.as_str(),
        "encrypted": s.encrypted(),
        "cipher": s.encrypted().then_some("sqlcipher"),
        "plainCopies": copies.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        "plaintextAllowed": s.policy == Policy::Off && !s.encrypted(),
        "created": s.start.created,
        "migrated": s.start.migrated.as_ref().filter(|_| announce),
        "rekeyed": announce && s.start.rekeyed,
        "previous": previous,
    });
    // As backup encryption: the state is saved only once the event is.
    if let Err(e) = app.db.try_record(&Event::new(Actor::system(ACTOR), "server.database_encryption_changed").target("server", "database").details(d)) {
        crate::obs::log::log_warn!("database encryption: could not record the change, will try again: {e}");
        return false;
    }
    s.announce.store(false, Ordering::SeqCst);
    app.db.set_setting(STATE, &key);
    true
}

/// Audits the state at startup, then looks again every minute.
pub fn start(app: AppState) {
    watch(&app);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            watch(&app);
        }
    });
}

/// For `GET /api/database` and `botctl database`.
pub fn view(app: &App) -> Value {
    let Some(s) = app.database.get() else {
        return Value::Null;
    };
    let copies = plain_copies(&s.dir);
    let (done, detail) = checklist(app);
    json!({
        "policy": s.policy.as_str(),
        "encrypted": s.encrypted(),
        "cipher": s.encrypted().then_some("sqlcipher"),
        "key": s.encrypted().then_some("derived from the master key"),
        "plaintextAllowed": s.policy == Policy::Off && !s.encrypted(),
        "plainCopies": copies.iter().map(|c| json!({ "name": c.name, "bytes": c.bytes })).collect::<Vec<_>>(),
        "ok": done,
        "detail": detail,
    })
}

/// `GET /api/database` (admins).
pub async fn get(axum::extract::State(app): axum::extract::State<AppState>) -> axum::Json<Value> {
    axum::Json(view(&app))
}

/// The setup checklist's item: done when the database is encrypted and no plain copy is left.
pub fn checklist(app: &App) -> (bool, String) {
    let Some(s) = app.database.get() else {
        return (false, "botd hasn't checked whether the database is encrypted.".into());
    };
    let copies = plain_copies(&s.dir);
    match (s.encrypted(), copies.is_empty(), s.policy) {
        (true, true, _) => (true, "Encrypted with SQLCipher under a key derived from the master key. Keep the master key off this host as well: restoring a backup needs it.".into()),
        (true, false, _) => (false, format!("Encrypted, but a plain copy from before is still in DATA_DIR: {}. Delete it once SuperBot looks right.", names(&copies))),
        (false, _, Policy::Off) => (false, "Plain by choice (SUPERBOT_DATABASE_ENCRYPTION=off): anyone who gets app.sqlite or a disk image can read it.".into()),
        (false, _, _) => (
            false,
            "Not encrypted. Set SUPERBOT_DATABASE_ENCRYPTION=required and restart: botd encrypts it and keeps a plain copy until you delete it. See docs/ops/database-encryption.md.".into(),
        ),
    }
}

/// The gauges `/metrics` shows.
pub fn render(app: &App, out: &mut String) {
    let Some(s) = app.database.get() else { return };
    metrics::family(out, "superbot_database_encrypted", "gauge", "1 when the database is encrypted at rest with SQLCipher, 0 when it is plain (ADR 0116).");
    metrics::sample(out, "superbot_database_encrypted", &[], s.encrypted() as u8 as f64);
    metrics::family(out, "superbot_database_plaintext_allowed", "gauge", "1 when SUPERBOT_DATABASE_ENCRYPTION=off keeps the database plain by choice.");
    metrics::sample(out, "superbot_database_plaintext_allowed", &[], (s.policy == Policy::Off && !s.encrypted()) as u8 as f64);
    metrics::family(out, "superbot_database_plain_copies", "gauge", "Plain copies of the database left in DATA_DIR by encrypting it.");
    metrics::sample(out, "superbot_database_plain_copies", &[], plain_copies(&s.dir).len() as f64);
}

// `botd database ...`: for superbot-backup and superbot-restore, which can't read an
// encrypted database with sqlite3.

const USAGE: &str = "usage: botd database backup <database> <new file> | query <database> <sql> | status <database>
The master key comes from SUPERBOT_MASTER_KEY, SUPERBOT_MASTER_KEY_FILE or ~/.config/superbot/master.key,
and SUPERBOT_MASTER_KEY_PREVIOUS(_FILE) during a rotation, as for botd.";

/// The key that opens `path`: None for a plain database.
fn cli_key(path: &Path) -> Result<Option<DbKey>, String> {
    match format(path)? {
        Format::Missing => Err(format!("{}: no database there", path.display())),
        Format::Plain => Ok(None),
        Format::Encrypted => {
            // Keys are refused inside their DATA_DIR; this may be any copy of the database, so
            // only the file itself is out of bounds.
            let found: Vec<DbKey> = [crate::secrets::key::locate(path)?, crate::secrets::key::locate_previous(path)?]
                .into_iter()
                .flatten()
                .map(|(k, _)| DbKey::derive(&k))
                .collect();
            if found.is_empty() {
                return Err(format!("{} is encrypted and no master key was found (SUPERBOT_MASTER_KEY or SUPERBOT_MASTER_KEY_FILE)", path.display()));
            }
            found.into_iter().find(|k| opens(path, k)).map(Some).ok_or_else(|| format!("{}: the master key doesn't open it (wrong key)", path.display()))
        }
    }
}

/// A consistent copy of a live database (SQLite's online backup), encrypted under the same
/// key when the source is. `dest` must not exist.
pub fn backup(src: &Path, dest: &Path, key: Option<&DbKey>) -> Result<(), String> {
    if std::fs::symlink_metadata(dest).is_ok() {
        return Err(format!("{} already exists", dest.display()));
    }
    let db = |e: rusqlite::Error| format!("backup: {e}");
    let from = open_read_only(src, key).map_err(db)?;
    let mut to = open_with(dest, key).map_err(db)?;
    let r = copy_all(&from, &mut to).map_err(db);
    drop(to);
    if r.is_err() {
        remove_files(dest);
    }
    r
}

/// Every page in one step, so the copy is one read transaction: one moment's database.
fn copy_all(from: &Connection, to: &mut Connection) -> rusqlite::Result<()> {
    use rusqlite::backup::{Backup, StepResult};
    let b = Backup::new(from, to)?;
    for _ in 0..600 {
        match b.step(-1)? {
            StepResult::Done => return Ok(()),
            StepResult::More => {}
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY), Some("the database stayed busy for a minute".into())))
}

fn query(path: &Path, key: Option<&DbKey>, sql: &str) -> Result<Vec<String>, String> {
    use rusqlite::types::ValueRef;
    let c = open_read_only(path, key).map_err(|e| e.to_string())?;
    let mut s = c.prepare(sql).map_err(|e| e.to_string())?;
    let n = s.column_count();
    let mut rows = s.query([]).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().map_err(|e| e.to_string())? {
        let cols: Vec<String> = (0..n)
            .map(|i| match r.get_ref(i) {
                Ok(ValueRef::Null) | Err(_) => String::new(),
                Ok(ValueRef::Integer(v)) => v.to_string(),
                Ok(ValueRef::Real(v)) => v.to_string(),
                Ok(ValueRef::Text(t)) => String::from_utf8_lossy(t).into_owned(),
                Ok(ValueRef::Blob(b)) => b.iter().map(|x| format!("{x:02x}")).collect(),
            })
            .collect();
        out.push(cols.join("|"));
    }
    Ok(out)
}

fn cli_run(args: &[String]) -> Result<Vec<String>, String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["backup", src, dest] => {
            let src = Path::new(src);
            backup(src, Path::new(dest), cli_key(src)?.as_ref())?;
            Ok(Vec::new())
        }
        ["query", path, sql] => {
            let path = Path::new(path);
            query(path, cli_key(path)?.as_ref(), sql)
        }
        ["status", path] => {
            let path = Path::new(path);
            match format(path)? {
                Format::Missing => Err(format!("{}: no database there", path.display())),
                Format::Plain => Ok(vec!["plain".into()]),
                Format::Encrypted => Ok(vec!["encrypted".into()]),
            }
        }
        _ => Err(USAGE.into()),
    }
}

/// `botd database <args>`: prints the result, and returns the exit code.
pub fn cli(args: &[String]) -> i32 {
    match cli_run(args) {
        Ok(lines) => {
            for l in lines {
                println!("{l}");
            }
            0
        }
        Err(e) => {
            eprintln!("botd database: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::sealed::{self, Cipher};

    fn db_in(tag: &str) -> PathBuf {
        let dir = crate::db::temp_path(tag);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("app.sqlite")
    }

    fn keys(path: &Path, current: Option<&MasterKey>, previous: Option<&MasterKey>) -> Keys {
        let copy = |k: &MasterKey| (MasterKey::parse(&k.base64()).unwrap(), "test".to_string());
        Keys::with(current.map(copy), previous.map(copy), path.parent().unwrap())
    }

    /// A plain database with the full schema, a Bot, and a secret sealed under `sealed_under`.
    fn plain_db(path: &Path, sealed_under: &MasterKey) {
        let db = crate::db::Db::open(path).unwrap();
        db.create_bot("KeepMe", "#fff", "waddle", "claude", None, true);
        drop(db);
        let c = sealed::connect(path).unwrap();
        let cipher = Cipher::new(sealed_under);
        c.execute("INSERT INTO secrets (name, value, created_at, updated_at) VALUES ('API_KEY', ?, 0, 0)", [cipher.seal("secrets/API_KEY", b"value-123")])
            .unwrap();
    }

    fn bots(c: &Connection) -> Vec<String> {
        let mut s = c.prepare("SELECT name FROM bots ORDER BY name").unwrap();
        s.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap()
    }

    #[test]
    fn the_policy_defaults_to_auto_and_odd_values_stop_botd() {
        let env = |v: &'static str| {
            move |k: &str| {
                if k == "SUPERBOT_DATABASE_ENCRYPTION" {
                    v.to_string()
                } else {
                    String::new()
                }
            }
        };
        assert_eq!(Policy::from_env(&env("")).unwrap(), Policy::Auto);
        assert_eq!(Policy::from_env(&env(" Required ")).unwrap(), Policy::Required);
        assert_eq!(Policy::from_env(&env("off")).unwrap(), Policy::Off);
        assert!(Policy::from_env(&env("yes")).unwrap_err().contains("auto, required or off"));
    }

    #[test]
    fn the_key_is_derived_from_the_master_key_and_never_printed() {
        let (a, b) = (MasterKey::generate(), MasterKey::generate());
        let ka = DbKey::derive(&a);
        assert_eq!(ka.0.as_str(), DbKey::derive(&MasterKey::parse(&a.base64()).unwrap()).0.as_str());
        assert_ne!(ka.0.as_str(), DbKey::derive(&b).0.as_str());
        assert!(ka.0.starts_with("x'") && ka.0.len() == 67, "a raw 256-bit SQLCipher key");
        let hex: String = a.bytes().iter().map(|x| format!("{x:02x}")).collect();
        assert!(!ka.0.contains(&hex), "not the master key itself");
        assert_eq!(format!("{ka:?}"), "[redacted]");
    }

    #[test]
    fn new_databases_are_encrypted_unless_off() {
        let path = db_in("dbe-new");
        let master = MasterKey::generate();
        let mut k = keys(&path, Some(&master), None);
        assert_eq!(format(&path).unwrap(), Format::Missing);
        let (key, start) = prepare(&path, Policy::Auto, &mut k).unwrap();
        assert_eq!(start, Start { encrypted: true, created: true, ..Start::default() });
        let key = key.unwrap();
        drop(crate::db::Db::open_keyed(&path, &key));
        assert_eq!(format(&path).unwrap(), Format::Encrypted);
        assert!(opens(&path, &key));
        assert!(open_with(&path, None).unwrap().query_row("SELECT count(*) FROM bots", [], |r| r.get::<_, i64>(0)).is_err(), "unreadable without the key");
        assert!(!opens(&path, &DbKey::derive(&MasterKey::generate())), "or with another");

        let plain = db_in("dbe-new-off");
        let (key, start) = prepare(&plain, Policy::Off, &mut keys(&plain, Some(&master), None)).unwrap();
        assert!(key.is_none() && start == Start::default());
    }

    #[test]
    fn a_plain_database_stays_plain_unless_required_then_is_encrypted_with_a_plain_copy_kept() {
        let path = db_in("dbe-migrate");
        let master = MasterKey::generate();
        plain_db(&path, &master);
        let before = std::fs::read(&path).unwrap();
        for policy in [Policy::Auto, Policy::Off] {
            let (key, start) = prepare(&path, policy, &mut keys(&path, Some(&master), None)).unwrap();
            assert!(key.is_none() && !start.encrypted, "{policy:?} leaves it plain");
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);

        let (key, start) = prepare(&path, Policy::Required, &mut keys(&path, Some(&master), None)).unwrap();
        let key = key.unwrap();
        let copy = start.migrated.clone().expect("a plain copy");
        assert!(start.encrypted && copy.starts_with(PLAIN_COPY_PREFIX), "{start:?}");
        assert_eq!(format(&path).unwrap(), Format::Encrypted);
        let c = open_with(&path, Some(&key)).unwrap();
        assert_eq!(bots(&c), ["KeepMe"], "every row came across");
        let sealed: String = c.query_row("SELECT value FROM secrets WHERE name = 'API_KEY'", [], |r| r.get(0)).unwrap();
        assert_eq!(Cipher::new(&master).open("secrets/API_KEY", &sealed).unwrap().as_slice(), b"value-123");
        assert_eq!(user_version(&c).unwrap(), user_version(&open_with(&path.with_file_name(&copy), None).unwrap()).unwrap());
        drop(c);

        let copy_path = path.with_file_name(&copy);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&copy_path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(format(&copy_path).unwrap(), Format::Plain);
        assert_eq!(bots(&open_with(&copy_path, None).unwrap()), ["KeepMe"], "the plain copy is the database as it was");
        assert_eq!(plain_copies(path.parent().unwrap()).iter().map(|c| c.name.clone()).collect::<Vec<_>>(), [copy]);
        assert!(!with_suffix(&path, WORK_SUFFIX).exists());

        // The next start just opens it.
        let (again, start) = prepare(&path, Policy::Required, &mut keys(&path, Some(&master), None)).unwrap();
        assert_eq!((again.unwrap().0.as_str(), start), (key.0.as_str(), Start { encrypted: true, ..Start::default() }));
    }

    #[test]
    fn a_plain_database_is_never_encrypted_under_a_key_that_doesnt_open_its_secrets() {
        let path = db_in("dbe-wrong");
        let (a, b) = (MasterKey::generate(), MasterKey::generate());
        plain_db(&path, &a);
        let e = prepare(&path, Policy::Required, &mut keys(&path, Some(&b), None)).unwrap_err();
        assert!(e.contains("wrong key"), "{e}");
        let e = prepare(&path, Policy::Required, &mut keys(&path, None, None)).unwrap_err();
        assert!(e.contains("no master key was found"), "{e}");
        assert_eq!(format(&path).unwrap(), Format::Plain, "nothing changed");
        assert!(plain_copies(path.parent().unwrap()).is_empty());

        // Mid-rotation: encrypted under the new key; the sealed values follow at bootstrap.
        let (key, _) = prepare(&path, Policy::Required, &mut keys(&path, Some(&b), Some(&a))).unwrap();
        let c = open_with(&path, key.as_ref()).unwrap();
        let (_, boot) =
            sealed::bootstrap(&c, Some(MasterKey::parse(&b.base64()).unwrap()), Some(MasterKey::parse(&a.base64()).unwrap().into()), || unreachable!(), false)
                .unwrap();
        assert_eq!(boot.rotated.unwrap().resealed, 1);
        let sealed: String = c.query_row("SELECT value FROM secrets WHERE name = 'API_KEY'", [], |r| r.get(0)).unwrap();
        assert_eq!(Cipher::new(&b).open("secrets/API_KEY", &sealed).unwrap().as_slice(), b"value-123");
    }

    #[test]
    fn a_master_key_rotation_re_encrypts_the_database_under_the_new_key() {
        let path = db_in("dbe-rotate");
        let (a, b) = (MasterKey::generate(), MasterKey::generate());
        drop(crate::db::Db::open_keyed(&path, &DbKey::derive(&a)).create_bot("KeepMe", "#fff", "waddle", "claude", None, true));

        for (k, want) in [
            (keys(&path, None, None), "no master key was found"),
            (keys(&path, Some(&b), None), "wrong key"),
            (keys(&path, Some(&b), Some(&b)), "neither the master key nor"),
        ] {
            let mut k = k;
            let e = prepare(&path, Policy::Auto, &mut k).unwrap_err();
            assert!(e.contains(want), "{e}");
        }
        assert!(opens(&path, &DbKey::derive(&a)), "refusing changed nothing");

        let (key, start) = prepare(&path, Policy::Auto, &mut keys(&path, Some(&b), Some(&a))).unwrap();
        assert!(start.rekeyed && start.migrated.is_none(), "{start:?}");
        assert!(opens(&path, &DbKey::derive(&b)) && !opens(&path, &DbKey::derive(&a)), "under the new key only");
        assert_eq!(bots(&open_with(&path, key.as_ref()).unwrap()), ["KeepMe"]);
        assert!(plain_copies(path.parent().unwrap()).is_empty(), "no copy under the old key is kept");
        // Left set by mistake: nothing more to do.
        let (_, start) = prepare(&path, Policy::Auto, &mut keys(&path, Some(&b), Some(&a))).unwrap();
        assert!(!start.rekeyed);
    }

    #[test]
    fn a_failed_encryption_leaves_the_database_as_it_was() {
        let path = db_in("dbe-fail");
        let master = MasterKey::generate();
        plain_db(&path, &master);
        let key = DbKey::derive(&master);
        let e = reencrypt(&path, None, Some(&key), Some(&path.with_file_name("missing-dir/copy"))).unwrap_err();
        assert!(e.contains("missing-dir"), "{e}");
        assert_eq!(format(&path).unwrap(), Format::Plain);
        assert_eq!(bots(&open_with(&path, None).unwrap()), ["KeepMe"], "only its journal mode changed");
        assert!(!with_suffix(&path, WORK_SUFFIX).exists(), "the half-made copy is gone");

        // Another connection's unwritten changes stop it too.
        let other = open_with(&path, None).unwrap();
        other.execute_batch("PRAGMA journal_mode = WAL; BEGIN; INSERT INTO bots (id, name, color, shape, harness, created_at) VALUES ('b9', 'Late', '#fff', 'waddle', 'claude', 0);").unwrap();
        let reader = open_with(&path, None).unwrap();
        reader.execute_batch("BEGIN; SELECT count(*) FROM bots;").unwrap();
        other.execute_batch("COMMIT").unwrap();
        let e = reencrypt(&path, None, Some(&key), None).unwrap_err();
        assert!(e.contains("another process has it open"), "{e}");
        drop(reader);
        drop(other);
        assert_eq!(format(&path).unwrap(), Format::Plain);
        assert_eq!(bots(&open_with(&path, None).unwrap()), ["KeepMe", "Late"]);
    }

    #[test]
    fn a_plain_database_from_before_saved_secrets_is_encrypted_too() {
        let path = db_in("dbe-old");
        let db = crate::db::Db::open(&path).unwrap();
        db.create_bot("KeepMe", "#fff", "waddle", "claude", None, true);
        drop(db);
        let master = MasterKey::generate();
        let (key, start) = prepare(&path, Policy::Required, &mut keys(&path, Some(&master), None)).unwrap();
        assert!(start.migrated.is_some() && opens(&path, key.as_ref().unwrap()));
        assert_eq!(bots(&open_with(&path, key.as_ref()).unwrap()), ["KeepMe"]);
    }

    #[test]
    fn one_botd_per_data_dir() {
        let path = db_in("dbe-lock");
        let held = lock_data_dir(&path).unwrap();
        let e = lock_data_dir(&path).unwrap_err();
        assert!(e.contains("another botd is using this DATA_DIR"), "{e}");
        drop(held);
        lock_data_dir(&path).unwrap();
    }

    #[test]
    fn backups_of_an_encrypted_database_stay_encrypted_under_its_key() {
        let path = db_in("dbe-backup");
        let key = DbKey::derive(&MasterKey::generate());
        let db = crate::db::Db::open_keyed(&path, &key);
        db.create_bot("KeepMe", "#fff", "waddle", "claude", None, true);
        let dest = path.with_file_name("snapshot.sqlite");
        backup(&path, &dest, Some(&key)).unwrap();
        drop(db);
        assert_eq!(format(&dest).unwrap(), Format::Encrypted);
        assert_eq!(bots(&open_with(&dest, Some(&key)).unwrap()), ["KeepMe"]);
        assert!(backup(&path, &dest, Some(&key)).unwrap_err().contains("already exists"));
        assert_eq!(query(&dest, Some(&key), "SELECT name, primary_bot FROM bots").unwrap(), ["KeepMe|1"]);
        assert!(query(&dest, None, "SELECT 1 FROM bots").is_err());

        let plain = db_in("dbe-backup-plain");
        plain_db(&plain, &MasterKey::generate());
        let dest = plain.with_file_name("snapshot.sqlite");
        backup(&plain, &dest, None).unwrap();
        assert_eq!(format(&dest).unwrap(), Format::Plain);
    }

    #[test]
    fn startup_warns_about_a_plain_database_and_plain_copies() {
        let dir = crate::db::temp_path("dbe-lines");
        let plain = State::new(Policy::Auto, Start::default(), &dir);
        let (line, w) = startup_lines(&plain, &[]);
        assert_eq!(line, "plain, SUPERBOT_DATABASE_ENCRYPTION=auto");
        assert!(w.len() == 1 && w[0].contains("SUPERBOT_DATABASE_ENCRYPTION=required"), "{w:?}");
        let (line, w) = startup_lines(&State::new(Policy::Off, Start::default(), &dir), &[]);
        assert!(line.starts_with("plain by choice") && w.is_empty(), "{line} {w:?}");
        let migrated = State::new(Policy::Required, Start { encrypted: true, migrated: Some("app.sqlite-plain-1".into()), ..Start::default() }, &dir);
        let copies = [PlainCopy { name: "app.sqlite-plain-1".into(), bytes: 1 }];
        let (line, w) = startup_lines(&migrated, &copies);
        assert!(line.contains("keeping a plain copy in app.sqlite-plain-1"), "{line}");
        assert!(w.len() == 1 && w[0].contains("still in DATA_DIR: app.sqlite-plain-1"), "{w:?}");
        let (line, w) = startup_lines(&State::new(Policy::Auto, Start { encrypted: true, rekeyed: true, ..Start::default() }, &dir), &[]);
        assert!(line.contains("re-encrypted under the new master key") && w.is_empty(), "{line}");
    }
}
