//! Regional chat stores (ADR 0215, ADR 0228, ADR 0276, ADR 0277): pinned people's chats,
//! routines, approvals, Bots' memory and their own facts in a database in their region, the
//! first part of splitting botd's database by region. REGION_DATA_DIRS names a folder per
//! region, which the operator puts on storage in that region; botd keeps `chats.sqlite`
//! there (keyed like its own database) and its backups in `backups/` beside it, never in
//! DATA_DIR. A Bot's chat, routines, approvals and memory live in the store of its owner's
//! pin (their team's, else their own), a person's facts (`USER.md`) in the store of their
//! own pin, and they move when that changes: at startup, after a pin or unpin, and on every
//! reconcile pass. botd's own copy of a Bot's memory or a person's facts is otherwise its
//! file in DATA_DIR. Accounts, sessions and the audit log stay where botd runs; botd still
//! reads and writes the stores from wherever it runs.
//!
//! The storage itself is `db::chats`. This module reads the settings, opens the stores
//! at startup (sealing their approvals' tool inputs under the master key), audits each
//! move (`residency.chats_moved`), backs each store up daily in its folder, and says where
//! a pin's data is for reports, the app and admins. Once a Bot's rows have left a store,
//! botd rewrites that store's backups without them (ADR 0238), so a pin's data isn't left
//! in another region's backups until they age out.

use super::ControlPlane;
use super::server_data::{Policy, ServerData};
use crate::audit::{Outcome, Who, clip};
use crate::database_encryption::{self, DbKey};
use crate::db::{ChatMove, ChatStore, Db, Doc, Held, MovesOut, now};
use crate::secrets::sealed::{Cipher, StoreApprovals};
use crate::obs::log::{log_info, log_warn};
use crate::runner::App;
use crate::AppState;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub const SETTING: &str = "REGION_DATA_DIRS";
/// Backups of each store kept in its folder when REGION_DATA_BACKUPS doesn't say.
pub const DEFAULT_KEEP: usize = 7;
const MAX_KEEP: usize = 365;
/// A store is backed up once its newest backup is this old.
const BACKUP_EVERY_MS: i64 = 24 * 3_600_000;
/// Admins are warned once a store's newest backup is older than this (a day, plus slack
/// for a pass that waited on a busy store).
const BACKUP_STALE_MS: i64 = 26 * 3_600_000;
const CHECK_EVERY: Duration = Duration::from_secs(3_600);
const PREFIX: &str = "chats-";
const SUFFIX: &str = ".sqlite";
const ACTOR: &str = "residency";
pub const MOVED: &str = "residency.chats_moved";
pub const BACKUP_FAILED: &str = "residency.chat_store_backup_failed";
pub const FORGOTTEN: &str = "residency.chat_store_forgotten";
pub const CLEARED: &str = "residency.chat_store_backups_cleared";
const FORGET: &str = "REGION_DATA_FORGET";
/// Admins are warned once rows that left a store have been in its backups this long (two
/// hourly checks, plus slack).
const CLEAR_STALE_MS: i64 = 3 * 3_600_000;

/// REGION_DATA_DIRS, REGION_DATA_BACKUPS and REGION_DATA_FORGET.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Each region's folder, canonical, in the order given.
    pub dirs: Vec<(String, PathBuf)>,
    /// Backups of each store kept in its folder.
    pub keep: usize,
    /// Regions dropped from REGION_DATA_DIRS whose store is gone for good: botd stops
    /// recording them though nothing shows they held no chats.
    pub forget: Vec<String>,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { dirs: Vec::new(), keep: DEFAULT_KEEP, forget: Vec::new() }
    }
}

impl Settings {
    /// `REGION_DATA_DIRS=<region>=<folder>,...`: each region one of MACHINE_REGIONS (they
    /// hold pins only with the control plane on), not botd's own data region, and each
    /// folder absolute, its own, and outside DATA_DIR, so server backups never take a
    /// store's chats out of its region. Folders are made if missing, readable by botd only.
    /// Refused with RESIDENCY_SERVER_DATA=require, which holds every pin to botd's region.
    pub fn from_env(var: &dyn Fn(&str) -> String, control_plane: bool, regions: &[String], server: &ServerData, data_dir: &Path) -> Result<Settings, String> {
        let raw = var(SETTING);
        let keep = match var("REGION_DATA_BACKUPS").trim() {
            "" => DEFAULT_KEEP,
            v => v.parse::<usize>().ok().filter(|n| (1..=MAX_KEEP).contains(n)).ok_or_else(|| format!("REGION_DATA_BACKUPS must be 1 to {MAX_KEEP}, not \"{}\"", clip(v, 20)))?,
        };
        let forget: Vec<String> = var(FORGET).split(',').map(str::trim).filter(|r| !r.is_empty()).map(str::to_string).collect();
        let entries: Vec<&str> = raw.split(',').map(str::trim).filter(|e| !e.is_empty()).collect();
        if entries.is_empty() {
            return Ok(Settings { dirs: Vec::new(), keep, forget });
        }
        if !control_plane {
            return Err(format!("{SETTING} holds pinned people's chats, and residency pins need the control plane (MACHINE_PROVIDER, ADR 0129)"));
        }
        if server.policy == Policy::Require {
            return Err(format!("{SETTING} is set, but RESIDENCY_SERVER_DATA=require holds every pin to botd's own data region, so no chats would go to another region's store"));
        }
        let data_dir = std::fs::canonicalize(data_dir).map_err(|e| format!("DATA_DIR: {e}"))?;
        let mut dirs: Vec<(String, PathBuf)> = Vec::new();
        for entry in entries {
            let Some((region, dir)) = entry.split_once('=').map(|(r, d)| (r.trim(), d.trim())) else {
                return Err(format!("{SETTING}: \"{}\" isn't <region>=<folder>", clip(entry, 64)));
            };
            if !regions.iter().any(|r| r == region) {
                return Err(format!("{SETTING}: \"{}\" isn't one of MACHINE_REGIONS ({})", clip(region, 32), regions.join(", ")));
            }
            if server.region.as_deref() == Some(region) {
                return Err(format!("{SETTING}: {region} is botd's own data region (SERVER_DATA_REGION), whose chats stay in botd's database"));
            }
            if dirs.iter().any(|(r, _)| r == region) {
                return Err(format!("{SETTING} names {region} twice"));
            }
            if !Path::new(dir).is_absolute() {
                return Err(format!("{SETTING}: {region}'s folder must be an absolute path, not \"{}\"", clip(dir, 64)));
            }
            let path = crate::paths::root(dir).map_err(|e| format!("{SETTING}: {region}: {e}"))?;
            if path.starts_with(&data_dir) || data_dir.starts_with(&path) {
                return Err(format!("{SETTING}: {region}'s folder {} must be outside DATA_DIR ({}), whose archives leave the region with server backups", path.display(), data_dir.display()));
            }
            if let Some((other, _)) = dirs.iter().find(|(_, d)| d.starts_with(&path) || path.starts_with(d)) {
                return Err(format!("{SETTING}: {region}'s folder overlaps {other}'s"));
            }
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("{SETTING}: {}: {e}", path.display()))?;
            dirs.push((region.to_string(), path));
        }
        if let Some((r, _)) = dirs.iter().find(|(r, _)| forget.contains(r)) {
            return Err(format!("{FORGET} names {r}, which {SETTING} still keeps chats for"));
        }
        Ok(Settings { dirs, keep, forget })
    }

    /// For the startup log.
    pub fn describe(&self) -> String {
        if self.dirs.is_empty() {
            return "none; every chat is in botd's own database".into();
        }
        let each: Vec<String> = self.dirs.iter().map(|(r, d)| format!("{r} in {}", d.display())).collect();
        format!("{}; {} backups kept in each", each.join(", "), self.keep)
    }
}

/// What opening the stores did.
#[derive(Debug, Default)]
pub struct Opened {
    /// For the startup log.
    pub lines: Vec<String>,
    /// Stores re-encrypted from the previous database key, mid-rotation.
    pub rekeyed: usize,
    /// What bringing their approvals' tool inputs under the master key did (ADR 0228).
    pub approvals: StoreApprovals,
}

/// The master keys a start opens stores' approvals with: the current one, the previous
/// one mid-rotation (SUPERBOT_MASTER_KEY_PREVIOUS), and whether SUPERBOT_FORGET_SEALED=1
/// drops what neither opens.
pub struct Keys<'a> {
    pub current: &'a Cipher,
    pub previous: Option<&'a Cipher>,
    pub forget: bool,
}

/// Opens the stores at startup, once botd's database is open and the master key checked:
/// holds each folder's lock, brings each store under botd's database key (`previous`: the
/// key before a rotation), checks them against botd's record and attaches them, brings
/// their approvals' tool inputs under the master key (`keys`), redacts known secrets from
/// them, and moves chats, routines and approvals to where they belong. Run with no stores
/// too, so a store that still holds them can't be dropped from the settings.
pub fn open(db: &Db, s: &Settings, data_dir: &Path, previous: Option<&DbKey>, keys: Keys) -> Result<Opened, String> {
    let key = database_encryption::installed();
    let mut rekeyed = 0;
    for (_, dir) in &s.dirs {
        std::mem::forget(database_encryption::lock_data_dir(&dir.join("chats.sqlite"))?);
    }
    // Before anything rewrites a restored store, which its restore's note names by inode.
    let restored = super::chat_store_restore::audit_restores(db, &s.dirs);
    for (_, dir) in &s.dirs {
        super::chat_store_restore::drop_leftovers(dir)?;
    }
    for (_, dir) in &s.dirs {
        let path = dir.join("chats.sqlite");
        let was_encrypted = database_encryption::format(&path)? == database_encryption::Format::Encrypted;
        if database_encryption::prepare_store(&path, key, previous)? {
            rekeyed += usize::from(was_encrypted);
            log_info!("Regional chat stores: {} brought under botd's database key (ADR 0215).", path.display());
        }
    }
    let attached = db.attach_chat_stores(&s.dirs, &s.forget, key.map(DbKey::raw))?;
    for (region, path) in &attached.forgotten {
        db.record(&Who::system(ACTOR).event(FORGOTTEN).details(json!({ "region": region, "path": path, "named": s.forget.contains(region) })));
    }
    let approvals = db.seal_store_approvals(keys.current, keys.previous, keys.forget)?;
    let mut lines = vec![format!("Regional chat stores: {} (ADR 0215).", s.describe())];
    lines.extend(restored);
    lines.extend(attached.created.iter().map(|r| format!("Regional chat stores: made {r}'s store.")));
    lines.extend(attached.forgotten.iter().map(|(r, p)| {
        let why = if s.forget.contains(r) { format!("is named in {FORGET}") } else { "held no chats".into() };
        format!("Regional chat stores: {r} is no longer in {SETTING} and its store ({p}) {why}, so botd stopped recording it. Its folder's backups/ is left for you to delete.")
    }));
    if approvals.sealed + approvals.discarded > 0 {
        lines.push(format!(
            "Regional chat stores: sealed {} saved tool inputs of approvals and discarded {} sealed ones the master key doesn't open (ADR 0228).",
            approvals.sealed, approvals.discarded
        ));
    }
    let scrubbed = db.scrub_chat_stores().map_err(|e| format!("chat stores: {e}"))?;
    if scrubbed > 0 {
        lines.push(format!("Regional chat stores: redacted {scrubbed} saved rows."));
    }
    for m in place(db, data_dir) {
        lines.push(format!("Regional chat stores: moved {} of {} Bots from {} to {}.", moved(&m), m.bots, place_name(&m.from), place_name(&m.to)));
    }
    Ok(Opened { lines, rekeyed, approvals })
}

fn moved(m: &ChatMove) -> String {
    Held { messages: m.messages as i64, routines: m.routines as i64, approvals: m.approvals as i64, memories: m.memories as i64, facts: m.facts as i64 }.describe()
}

fn place_name(region: &Option<String>) -> String {
    region.as_ref().map_or("botd's own database".to_string(), |r| format!("{r}'s chat store"))
}

/// Moves every Bot's chat, routines, approvals and memory, and every person's facts, to
/// where their pin says they belong now, each move audited as `residency.chats_moved` by
/// botd itself. A failure is logged and left for the next pass.
///
/// botd's own copy of a Bot's memory or a person's facts is its file in DATA_DIR (ADR 0276,
/// ADR 0277). One that belongs in a store is first taken into botd's own table and its file
/// deleted, so the move takes it there like any other row; one that came back out of a
/// store is written to its file, then deleted from botd's table.
pub fn place(db: &Db, data_dir: &Path) -> Vec<ChatMove> {
    let _held = memory_lock();
    place_held(db, data_dir)
}

/// Held while botd's copy of a Bot's memory or a person's facts is moved or saved (`place`,
/// `App::keep_memory_text`, `App::keep_facts_text`), so a save can't land between a move
/// reading it and writing it to its file, only to be overwritten with the older text.
pub(crate) fn memory_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `place`, with `memory_lock` already held.
pub(crate) fn place_held(db: &Db, data_dir: &Path) -> Vec<ChatMove> {
    for doc in [Doc::Memory, Doc::Facts] {
        from_files(db, data_dir, doc);
    }
    let moves = match db.place_chats() {
        Ok(m) => m,
        Err(e) => {
            log_warn!("Regional chat stores: chats, routines, approvals, Bots' memory and people's facts couldn't be moved to where they belong; the next pass tries again: {e} (ADR 0215).");
            return Vec::new();
        }
    };
    for doc in [Doc::Memory, Doc::Facts] {
        to_files(db, data_dir, doc);
    }
    if db.chat_stores_unflushed() {
        log_warn!("Regional chat stores: a reader kept botd from emptying a database's WAL after rows left it, so they may still be readable in its file; the next pass tries again (ADR 0228).");
    }
    for m in &moves {
        db.record(&Who::system(ACTOR).event(MOVED).details(json!({
            "from": m.from, "to": m.to, "bots": m.bots, "messages": m.messages, "routines": m.routines, "approvals": m.approvals, "memories": m.memories, "facts": m.facts,
        })));
    }
    moves
}

/// Where botd keeps `doc` of `id` as a file in DATA_DIR.
fn doc_file(data_dir: &Path, doc: Doc, id: &str) -> Option<PathBuf> {
    match doc {
        Doc::Memory => crate::runner::memory_path(data_dir, id),
        Doc::Facts => crate::runner::facts_path(data_dir, id),
    }
}

/// What `doc` is in the log, one and all of them, and its ADR.
fn doc_words(doc: Doc) -> (&'static str, &'static str, &'static str) {
    match doc {
        Doc::Memory => ("a Bot's memory", "Bots' memory", "ADR 0276"),
        Doc::Facts => ("a person's facts", "people's facts", "ADR 0277"),
    }
}

/// Takes the files of Bots' memory or people's facts that belong in a store into botd's own
/// table, for `place_chats` to move there, and deletes each file once it is (ADR 0276, ADR
/// 0277). A link or anything but a plain file is left alone.
fn from_files(db: &Db, data_dir: &Path, doc: Doc) {
    let (one, all, adr) = doc_words(doc);
    let ids = match db.with_doc_in_stores(doc) {
        Ok(ids) => ids,
        Err(e) => return log_warn!("Regional chat stores: couldn't list the {all} that belongs in a store; the next pass tries again: {e} ({adr})."),
    };
    for id in ids {
        let Some(path) = doc_file(data_dir, doc, &id) else { continue };
        if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
            continue;
        }
        let taken = std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|text| db.doc_from_file(doc, &id, &text).map_err(|e| e.to_string()));
        let removed = taken.and_then(|_| std::fs::remove_file(&path).map_err(|e| e.to_string()));
        match removed {
            Ok(()) => sync_parent(&path),
            Err(e) => log_warn!("Regional chat stores: {one} file ({}) couldn't be moved to its region's store; the next pass tries again: {e} ({adr}).", path.display()),
        }
    }
}

/// Writes the Bots' memory or people's facts that came back out of a store
/// (`Db::docs_for_files`) to their files in DATA_DIR, then deletes them from botd's own
/// table (ADR 0276, ADR 0277).
fn to_files(db: &Db, data_dir: &Path, doc: Doc) {
    let (one, all, adr) = doc_words(doc);
    let rows = match db.docs_for_files(doc) {
        Ok(r) => r,
        Err(e) => return log_warn!("Regional chat stores: couldn't read the {all} on its way back to its files; the next pass tries again: {e} ({adr})."),
    };
    for (id, text) in rows {
        let Some(path) = doc_file(data_dir, doc, &id) else { continue };
        let done = crate::runner::write_kept_file(&path, &text).map_err(|e| e.to_string()).and_then(|()| db.delete_doc(doc, &id).map(|_| ()).map_err(|e| e.to_string()));
        if let Err(e) = done {
            log_warn!("Regional chat stores: {one} couldn't be written back to its file ({}); the next pass tries again: {e} ({adr}).", path.display());
        }
    }
}

fn sync_parent(path: &Path) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
}

// Backups

pub(super) fn backups_dir(store: &ChatStore) -> PathBuf {
    store.path.parent().unwrap_or(Path::new("/")).join("backups")
}

/// When a backup named `chats-<YYYYMMDD-HHMMSS>.sqlite` was made (UTC, ms).
pub(super) fn backup_time(name: &str) -> Option<i64> {
    let stamp = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%d-%H%M%S").ok().map(|t| t.and_utc().timestamp_millis())
}

/// A store's finished backups, newest first.
fn backups(store: &ChatStore) -> Vec<(i64, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(backups_dir(store)) else { return Vec::new() };
    let mut out: Vec<(i64, PathBuf)> = entries.flatten().filter_map(|e| Some((backup_time(e.file_name().to_str()?)?, e.path()))).collect();
    out.sort_by(|a, b| b.cmp(a));
    out
}

/// Copies `store` into its folder's `backups/` as `chats-<UTC stamp>.sqlite`, under the
/// same key, with botd's online backup (one read transaction, so writes meanwhile can't tear it),
/// then keeps the newest `keep`. The path written.
pub fn back_up(store: &ChatStore, key: Option<&DbKey>, keep: usize, at: i64) -> Result<PathBuf, String> {
    let dir = backups_dir(store);
    fn io(p: &Path) -> impl Fn(std::io::Error) -> String + '_ {
        move |e| format!("{}: {e}", p.display())
    }
    std::fs::create_dir_all(&dir).map_err(io(&dir))?;
    let stamp = chrono::DateTime::from_timestamp_millis(at).unwrap_or_default().format("%Y%m%d-%H%M%S");
    let name = format!("{PREFIX}{stamp}{SUFFIX}");
    let (partial, done) = (dir.join(format!(".partial-{name}")), dir.join(&name));
    let db = |e: rusqlite::Error| format!("backing up {}: {e}", store.path.display());
    let r = (|| {
        let _ = std::fs::remove_file(&partial);
        database_encryption::backup(&store.path, &partial, key).map_err(|e| format!("backing up {}: {e}", store.path.display()))?;
        let dst = database_encryption::open_with(&partial, key).map_err(db)?;
        let check: String = dst.query_row("PRAGMA integrity_check", [], |r| r.get(0)).map_err(db)?;
        if check != "ok" {
            return Err(format!("backing up {}: the copy failed its integrity check ({check})", store.path.display()));
        }
        // A single self-contained file, with no -wal beside it to lose in the rename.
        dst.query_row("PRAGMA journal_mode=DELETE", [], |_| Ok(())).map_err(db)?;
        drop(dst);
        std::fs::File::open(&partial).and_then(|f| f.sync_all()).map_err(io(&partial))?;
        std::fs::rename(&partial, &done).map_err(io(&done))
    })();
    if let Err(e) = r {
        let _ = std::fs::remove_file(&partial);
        return Err(e);
    }
    for (_, old) in backups(store).into_iter().skip(keep) {
        let _ = std::fs::remove_file(old);
    }
    Ok(done)
}

/// Backs up each store whose newest backup is a day old or more. A failure is audited
/// (`residency.chat_store_backup_failed`) and tried again on the next check.
pub fn backup_pass(db: &Db, keep: usize, at: i64) -> Vec<(String, Result<PathBuf, String>)> {
    let key = database_encryption::installed();
    let mut out = Vec::new();
    for store in db.chat_stores() {
        if backups(&store).first().is_some_and(|(t, _)| at - t < BACKUP_EVERY_MS) {
            continue;
        }
        let r = back_up(&store, key, keep, at);
        if let Err(e) = &r {
            log_warn!("Regional chat stores: {}'s store couldn't be backed up: {e} (ADR 0215).", store.region);
            db.record(&Who::system(ACTOR).event(BACKUP_FAILED).outcome(Outcome::Failure).details(json!({ "region": store.region, "error": clip(e, 500) })));
        }
        out.push((store.region.clone(), r));
    }
    out
}

/// What clearing one store's backups of rows that left it did (ADR 0238).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Cleared {
    /// Bots whose rows left the store and were looked for.
    pub bots: usize,
    /// People whose facts left the store and were looked for (ADR 0277).
    pub users: usize,
    /// Backups that held some of them and were rewritten.
    pub backups: usize,
    /// What was taken out of them, together.
    pub held: Held,
}

/// Rewrites the backup at `path` without the rows of `whose`, under the same key: copied
/// beside it, cleared, checked and renamed over it, so a crash leaves the old file or the
/// new one, never half of either. Left as it is when it holds none of them. What it took out.
fn clear_backup(path: &Path, whose: &crate::db::Whose, key: Option<&DbKey>) -> Result<Held, String> {
    let db = |e: rusqlite::Error| format!("clearing {}: {e}", path.display());
    fn io(p: &Path) -> impl Fn(std::io::Error) -> String + '_ {
        move |e| format!("{}: {e}", p.display())
    }
    let held = crate::db::held_in_copy(&database_encryption::open_read_only(path, key).map_err(db)?, whose).map_err(db)?;
    if held.total() == 0 {
        return Ok(held);
    }
    let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| format!("{}: not a backup's name", path.display()))?;
    let partial = path.with_file_name(format!(".partial-{name}"));
    let r = (|| {
        let _ = std::fs::remove_file(&partial);
        std::fs::copy(path, &partial).map_err(io(&partial))?;
        let c = database_encryption::open_with(&partial, key).map_err(db)?;
        // VACUUM's working copy would otherwise go to the host's temp folder, outside the region.
        c.execute_batch("PRAGMA temp_store = MEMORY").map_err(db)?;
        c.query_row("PRAGMA journal_mode = MEMORY", [], |_| Ok(())).map_err(db)?;
        let dropped = crate::db::drop_from_copy(&c, whose).map_err(db)?;
        let check: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).map_err(db)?;
        if check != "ok" {
            return Err(format!("clearing {}: the rewritten copy failed its integrity check ({check})", path.display()));
        }
        drop(c);
        std::fs::File::open(&partial).and_then(|f| f.sync_all()).map_err(io(&partial))?;
        std::fs::rename(&partial, path).map_err(io(path))?;
        if let Some(dir) = path.parent() {
            let _ = std::fs::File::open(dir).and_then(|f| f.sync_all());
        }
        Ok(dropped)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    r
}

/// A store's finished backups, newest first, for clearing: unlike `backups`, a folder or
/// entry botd can't read is an error, so nothing is taken as cleared unchecked. Copies a
/// crash left half made (`.partial-*`, of a backup or a rewrite) may hold moved rows too, and
/// are deleted first; nothing else writes there while the hourly check runs.
fn backups_to_clear(store: &ChatStore) -> Result<Vec<(i64, PathBuf)>, String> {
    list_strictly(store, true)
}

/// A store's finished backups, newest first, to copy off the host (ADR 0246): a folder or
/// entry botd can't read is an error, so the bucket isn't emptied to match a folder it
/// couldn't list. Half-made copies are left out.
pub(super) fn backups_strictly(store: &ChatStore) -> Result<Vec<(i64, PathBuf)>, String> {
    list_strictly(store, false)
}

fn list_strictly(store: &ChatStore, drop_partial: bool) -> Result<Vec<(i64, PathBuf)>, String> {
    let dir = backups_dir(store);
    let unreadable = |e: std::io::Error| format!("{}: {e}", dir.display());
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(unreadable(e)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(unreadable)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".partial-") {
            if drop_partial {
                std::fs::remove_file(entry.path()).map_err(|e| format!("{}: {e}", entry.path().display()))?;
            }
        } else if let Some(t) = backup_time(&name) {
            out.push((t, entry.path()));
        }
    }
    out.sort_by(|a, b| b.cmp(a));
    Ok(out)
}

/// One store's backups cleared of rows that left it, its moves not yet recorded as cleared.
pub struct Clearing {
    store: ChatStore,
    moves: MovesOut,
    done: Cleared,
    failed: Vec<String>,
}

/// Clears each store's backups of the rows of Bots and people that left it (`Db::moves_out_to_clear`),
/// then records those moves as cleared, so reports stop listing the backups as earlier
/// copies. Each store that had backups rewritten is audited as
/// `residency.chat_store_backups_cleared`; a failure is audited with it as a failure, the
/// moves stay uncleared, and the next check tries again.
#[cfg(test)]
pub fn clear_pass(db: &Db, at: i64) -> Vec<(String, Result<Cleared, String>)> {
    finish_clearing::<()>(db, clear_backups(db), &HashMap::new(), at)
}

/// The first half of `clear_pass`: rewrites each store's backups without the rows of Bots
/// that left it. By region; an error is a store whose moves couldn't be read.
pub fn clear_backups(db: &Db) -> Vec<(String, Result<Clearing, String>)> {
    let key = database_encryption::installed();
    let mut out = Vec::new();
    for store in db.chat_stores() {
        let moves = match db.moves_out_to_clear(&store) {
            Ok(m) if m.is_empty() => continue,
            Ok(m) => m,
            Err(e) => {
                out.push((store.region.clone(), Err(format!("{}'s chat store: {e}", store.region))));
                continue;
            }
        };
        let whose = moves.whose();
        let mut done = Cleared { bots: whose.bots.len(), users: whose.users.len(), ..Cleared::default() };
        let (listed, mut failed) = match backups_to_clear(&store) {
            Ok(b) => (b, Vec::new()),
            Err(e) => (Vec::new(), vec![e]),
        };
        for (_, path) in listed {
            match clear_backup(&path, &whose, key) {
                Ok(h) if h.total() > 0 => {
                    done.backups += 1;
                    done.held.add(h);
                }
                Ok(_) => {}
                Err(e) => failed.push(e),
            }
        }
        out.push((store.region.clone(), Ok(Clearing { store, moves, done, failed })));
    }
    out
}

/// The second half of `clear_pass`: records each store's moves as cleared once its backups
/// are, and, for a store whose backups are copied off the host (ADR 0246), once `copies`
/// (by region, from a pass after the rewrite) says its bucket matches them, and audits it.
pub fn finish_clearing<T>(db: &Db, cleared: Vec<(String, Result<Clearing, String>)>, copies: &HashMap<String, Result<T, String>>, at: i64) -> Vec<(String, Result<Cleared, String>)> {
    let mut out = Vec::new();
    for (region, c) in cleared {
        let Clearing { store, moves, done, failed } = match c {
            Ok(c) => c,
            Err(e) => {
                out.push((region, Err(e)));
                continue;
            }
        };
        let details = |done: &Cleared| {
            json!({
                "region": store.region, "bots": done.bots, "users": done.users, "backups": done.backups, "messages": done.held.messages, "routines": done.held.routines,
                "approvals": done.held.approvals, "memories": done.held.memories, "facts": done.held.facts,
            })
        };
        let r = match (failed.is_empty(), copies.get(&store.region)) {
            (false, _) => Err(failed.join("; ")),
            (true, Some(Err(e))) => Err(format!("the backups' copies off the host: {e}")),
            (true, _) => db.moves_out_cleared(&store.region, &moves, at).map(|_| ()).map_err(|e| e.to_string()),
        };
        match &r {
            Ok(()) if done.backups > 0 => {
                log_info!(
                    "Regional chat stores: took {} of {} Bots and {} people that left {}'s store out of {} of its backups (ADR 0238, ADR 0277).",
                    done.held.describe(),
                    done.bots,
                    done.users,
                    store.region,
                    done.backups
                );
                db.record(&Who::system(ACTOR).event(CLEARED).details(details(&done)));
            }
            Ok(()) => {}
            Err(e) => {
                log_warn!("Regional chat stores: {}'s backups couldn't all be cleared of rows that left the store; the next check tries again: {e} (ADR 0238).", store.region);
                let mut d = details(&done);
                d["error"] = json!(clip(e, 500));
                db.record(&Who::system(ACTOR).event(CLEARED).outcome(Outcome::Failure).details(d));
            }
        }
        out.push((store.region.clone(), r.map(|()| done)));
    }
    out
}

/// One hourly check: backs up stores due a backup, clears backups of rows that left their
/// store, copies them off the host where a region has a bucket (ADR 0246), and only then
/// records the moves as cleared.
pub async fn hourly(app: &AppState, cp: &ControlPlane) {
    let (a, keep) = (app.clone(), cp.chat_stores.keep);
    let cleared = tokio::task::spawn_blocking(move || {
        backup_pass(&a.db, keep, now());
        clear_backups(&a.db)
    })
    .await
    .unwrap_or_default();
    let copies = match cp.chat_copies.as_deref() {
        Some(c) => c.pass(&app.db, now()).await,
        None => HashMap::new(),
    };
    let a = app.clone();
    let _ = tokio::task::spawn_blocking(move || finish_clearing(&a.db, cleared, &copies, now())).await;
}

/// Runs `hourly` from startup on.
pub fn start(app: AppState, cp: Arc<ControlPlane>) {
    if cp.chat_stores.dirs.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CHECK_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            hourly(&app, &cp).await;
        }
    });
}

// Views

fn store_view(cp: &ControlPlane, store: &ChatStore, held: &Held) -> Value {
    let b = backups(store);
    json!({
        "region": store.region, "messages": held.messages, "routines": held.routines, "approvals": held.approvals, "memories": held.memories, "facts": held.facts,
        "backups": b.len(), "lastBackupAt": b.first().map(|(t, _)| *t),
        "offHost": cp.chat_copies.as_deref().and_then(|c| c.view(store)),
    })
}

/// For `GET /api/regions`: each store, what it holds and its backups, and how many are kept.
pub fn summary(app: &App, cp: &ControlPlane) -> Value {
    let stores: Vec<Value> = app.db.chat_store_counts().iter().map(|(s, n)| store_view(cp, s, n)).collect();
    json!({ "stores": stores, "keep": cp.chat_stores.keep })
}

/// The store `region` has, as `summary` shows it. None: it has none.
pub fn region_view(app: &App, cp: &ControlPlane, region: &str) -> Option<Value> {
    app.db.chat_store_counts().iter().find(|(s, _)| s.region == region).map(|(s, n)| store_view(cp, s, n))
}

/// Warnings for admins: stores whose newest backup is over a day old while they hold
/// anything, stores whose backups have held rows that left them for over two checks, and
/// stores whose backups' last copy off the host failed (ADR 0246).
pub fn warnings(app: &App, cp: &ControlPlane, at: i64) -> Vec<String> {
    let copies = cp.chat_copies.as_deref().map(|c| c.warnings(&app.db.chat_stores())).unwrap_or_default();
    let counts = app.db.chat_store_counts();
    let stale = counts
        .iter()
        .filter(|(s, n)| n.total() > 0 && backups(s).first().is_none_or(|(t, _)| at - t > BACKUP_STALE_MS))
        .map(|(s, _)| format!("{}'s chat store has no backup from the last day in its folder's backups/; check botd's log for {BACKUP_FAILED} (ADR 0215).", s.region));
    let uncleared = counts.iter().filter_map(|(s, _)| {
        let moves = app.db.moves_out_to_clear(s).ok()?;
        let late = |l: &[(String, i64)]| l.iter().filter(|(_, moved_at)| at - moved_at > CLEAR_STALE_MS).count();
        let (bots, users) = (late(&moves.bots), late(&moves.users));
        (bots + users > 0 && !backups(s).is_empty()).then(|| {
            let mut whose = Vec::new();
            if bots > 0 {
                whose.push(if bots == 1 { "the rows of 1 Bot".to_string() } else { format!("the rows of {bots} Bots") });
            }
            if users > 0 {
                whose.push(if users == 1 { "the facts of 1 person".to_string() } else { format!("the facts of {users} people") });
            }
            format!("{}'s chat store's backups may still hold {} that left it; check botd's log for {CLEARED} failures (ADR 0238).", s.region, whose.join(" and "))
        })
    });
    stale.chain(uncleared).chain(copies).collect()
}

/// What of the Bots `owners` own, and of their own facts, is in a pin to `region`'s store, in
/// botd's own database (memory and facts files in DATA_DIR included, ADR 0276, ADR 0277),
/// and in other regions' stores.
fn split(app: &App, region: &str, owners: &[String]) -> (Held, Held, Held) {
    let (mut store, mut database, mut elsewhere) = (Held::default(), Held::default(), Held::default());
    for c in app.db.chat_counts(owners) {
        match c.region.as_deref() {
            Some(r) if r == region => store.add(c.held),
            Some(_) => elsewhere.add(c.held),
            None => database.add(c.held),
        }
    }
    let files = owners.iter().flat_map(|o| app.db.owned_bot_ids(o)).filter(|id| app.data_memory_file(id).is_some_and(|p| std::fs::symlink_metadata(p).is_ok())).count();
    database.memories += files as i64;
    let facts = owners.iter().filter(|o| crate::runner::facts_path(&app.cfg.data_dir, o).is_some_and(|p| std::fs::symlink_metadata(p).is_ok())).count();
    database.facts += facts as i64;
    (store, database, elsewhere)
}

/// Where the chats, routines and approvals of Bots `owners` own are against a pin to
/// `region`: in its store, in botd's own database (in the region only when botd's own data
/// is, `server_in`), or in another region's store; and the backups of other stores made
/// before they left them (`earlierCopies`), which hold them until botd clears them out
/// (ADR 0238); and the copies of the region's store's backups off the host (`offHost`,
/// ADR 0246), null when they aren't copied.
pub fn against(app: &App, cp: &ControlPlane, region: &str, owners: &[String], server_in: bool) -> Value {
    let (store, database, elsewhere) = split(app, region, owners);
    let each = |n: fn(&Held) -> i64| json!({ "inStore": n(&store), "inServerDatabase": n(&database), "elsewhere": n(&elsewhere) });
    let stores = app.db.chat_stores();
    let earlier: Vec<Value> = app
        .db
        .chat_moves_out(owners, region)
        .into_iter()
        .filter_map(|(r, moved_at)| {
            let s = stores.iter().find(|s| s.region == r);
            let n = s.map_or(0, |s| backups(s).iter().filter(|(t, _)| *t <= moved_at).count());
            let off = s.is_some_and(|s| cp.chat_copies.as_deref().is_some_and(|c| c.may_hold(s, moved_at)));
            (n > 0 || off).then(|| json!({ "region": r, "backups": n, "offHost": off, "movedAt": moved_at }))
        })
        .collect();
    let has = stores.iter().find(|s| s.region == region);
    let last = has.and_then(|s| backups(s).first().map(|(t, _)| *t));
    json!({
        "store": has.is_some(),
        "messages": each(|h| h.messages),
        "routines": each(|h| h.routines),
        "approvals": each(|h| h.approvals),
        "memories": each(|h| h.memories),
        "facts": each(|h| h.facts),
        "inRegion": elsewhere.total() == 0 && (database.total() == 0 || server_in) && earlier.is_empty(),
        "earlierCopies": earlier,
        "lastBackupAt": last,
        "offHost": has.and_then(|s| cp.chat_copies.as_deref().and_then(|c| c.report_view(s))),
    })
}

/// Why `user_id`'s chats, routines and approvals aren't where a pin to `region` keeps
/// them: some are in another region's store, or, when `region` has a store, not in it (a
/// move that failed). Like `residency::outside`, these make the pin unkept, but they aren't
/// checked before a pin, whose own move puts them there.
pub fn outside(app: &App, region: &str, user_id: &str) -> Vec<String> {
    let has = app.db.chat_stores().iter().any(|s| s.region == region);
    let (_, database, elsewhere) = split(app, region, &[user_id.to_string()]);
    let mut out = Vec::new();
    let bots = database.of_bots();
    if has && bots.total() > 0 {
        let files = if bots.memories > 0 { " or its files" } else { "" };
        out.push(format!("their Bots have {} in botd's own database{files}, not {region}'s chat store (ADR 0215, ADR 0228, ADR 0276)", bots.describe()));
    }
    if has && database.facts > 0 {
        out.push(format!("their facts are in botd's own database or its files, not {region}'s chat store (ADR 0277)"));
    }
    if elsewhere.of_bots().total() > 0 {
        out.push(format!("their Bots have {} in another region's chat store (ADR 0215, ADR 0228, ADR 0276)", elsewhere.of_bots().describe()));
    }
    if elsewhere.facts > 0 {
        out.push("their facts are in another region's chat store (ADR 0277)".to_string());
    }
    out
}

/// Report warnings about `chats` (`against`): no recent backup of the region's store, and
/// other stores' backups that still hold their chats.
pub fn report_warnings(chats: &Value, region: &str, at: i64) -> Vec<String> {
    let mut out = Vec::new();
    let in_store: i64 = ["messages", "routines", "approvals", "memories", "facts"].iter().filter_map(|k| chats[k]["inStore"].as_i64()).sum();
    if in_store > 0 && chats["lastBackupAt"].as_i64().is_none_or(|t| at - t > BACKUP_STALE_MS) {
        out.push(format!("{region}'s chat store has no backup from the last day (ADR 0215)"));
    }
    for e in chats["earlierCopies"].as_array().into_iter().flatten() {
        let r = e["region"].as_str().unwrap_or_default();
        out.push(match (e["backups"].as_i64().unwrap_or(0), e["offHost"] == true) {
            (0, _) => format!("copies off the host of {r}'s chat store's backups from before their chats, routines or approvals moved out of it may still hold them, until botd clears them out on its next hourly check (ADR 0238, ADR 0246)"),
            (n, off) => format!(
                "{n} backups of {r}'s chat store{} were made before their chats, routines or approvals moved out of it and still hold them, until botd clears them out of those backups on its next hourly check (ADR 0215, ADR 0238)",
                if off { ", and their copies off the host," } else { "" },
            ),
        });
    }
    if chats["offHost"]["failing"] == true {
        out.push(format!("{region}'s chat store's backups couldn't all be copied off the host on botd's last check; it tries again each hour (ADR 0246)"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn with(pairs: &[(&str, &str)], cp: bool, server: ServerData, data_dir: &Path) -> Result<Settings, String> {
        let env: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Settings::from_env(&|k| env.get(k).cloned().unwrap_or_default(), cp, &["gb-lon".to_string(), "de-fra-2".to_string()], &server, data_dir)
    }

    #[test]
    fn region_data_dirs_name_offered_regions_with_folders_of_their_own_outside_data_dir() {
        let t = crate::db::Scratch::new();
        let data = t.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let (lon, fra) = (t.path().join("lon"), t.path().join("fra"));
        let set = |v: String| with(&[(SETTING, v.as_str())], true, ServerData::default(), &data);
        assert_eq!(set(String::new()).unwrap(), Settings::default());
        let s = set(format!(" gb-lon={} , de-fra-2={} ", lon.display(), fra.display())).unwrap();
        assert_eq!(s.dirs.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(), vec!["gb-lon", "de-fra-2"]);
        assert!(lon.is_dir() && fra.is_dir());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&lon).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(s.describe().contains("gb-lon in") && s.describe().contains("7 backups kept in each"), "{}", s.describe());

        for (v, want) in [
            (format!("us-east={}", lon.display()), "isn't one of MACHINE_REGIONS (gb-lon, de-fra-2)"),
            ("gb-lon".to_string(), "isn't <region>=<folder>"),
            ("gb-lon=relative/dir".to_string(), "must be an absolute path"),
            (format!("gb-lon={}", data.join("chats").display()), "must be outside DATA_DIR"),
            (format!("gb-lon={}", t.path().display()), "must be outside DATA_DIR"),
            (format!("gb-lon={},gb-lon={}", lon.display(), fra.display()), "names gb-lon twice"),
            (format!("gb-lon={},de-fra-2={}", lon.display(), lon.join("x").display()), "overlaps gb-lon's"),
        ] {
            let e = set(v.clone()).unwrap_err();
            assert!(e.contains(want), "{v}: {e}");
        }
        let one = [(SETTING, format!("gb-lon={}", lon.display()))];
        let one: Vec<(&str, &str)> = one.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert!(with(&one, false, ServerData::default(), &data).unwrap_err().contains("need the control plane"));
        let london = ServerData { region: Some("gb-lon".into()), ..ServerData::default() };
        assert!(with(&one, true, london, &data).unwrap_err().contains("is botd's own data region"));
        let require = ServerData { region: Some("de-fra-2".into()), policy: Policy::Require, ..ServerData::default() };
        assert!(with(&one, true, require, &data).unwrap_err().contains("RESIDENCY_SERVER_DATA=require"));
        let keep = |v: &str| with(&[("REGION_DATA_BACKUPS", v)], true, ServerData::default(), &data);
        assert_eq!(keep("30").unwrap().keep, 30);
        let forget = with(&[(FORGET, " us-east , gb-lon ")], true, ServerData::default(), &data).unwrap();
        assert_eq!(forget.forget, vec!["us-east", "gb-lon"], "read without REGION_DATA_DIRS too, to retire the last store");
        let both = [(SETTING, format!("gb-lon={}", lon.display())), (FORGET, "gb-lon".to_string())];
        let both: Vec<(&str, &str)> = both.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert!(with(&both, true, ServerData::default(), &data).unwrap_err().contains("REGION_DATA_FORGET names gb-lon, which REGION_DATA_DIRS still keeps chats for"));
        assert!(keep("0").unwrap_err().contains("must be 1 to 365") && keep("x").is_err());
    }

    #[test]
    fn backups_are_named_by_time_and_only_the_newest_are_kept() {
        assert_eq!(backup_time("chats-20261123-221500.sqlite"), Some(chrono::DateTime::parse_from_rfc3339("2026-11-23T22:15:00Z").unwrap().timestamp_millis()));
        for name in ["chats-2026.sqlite", ".partial-chats-20261123-221500.sqlite", "chats-20261123-221500.sqlite-wal", "app.sqlite"] {
            assert_eq!(backup_time(name), None, "{name}");
        }
        let t = crate::db::Scratch::new();
        let db = Db::open(&t.path().join("app.sqlite")).unwrap();
        let dir = t.path().join("lon");
        std::fs::create_dir_all(&dir).unwrap();
        db.attach_chat_stores(&[("gb-lon".into(), dir.clone())], &[], None).unwrap();
        let day = BACKUP_EVERY_MS;
        let start = chrono::DateTime::parse_from_rfc3339("2026-11-01T03:00:00Z").unwrap().timestamp_millis();
        for i in 0..4 {
            let r = backup_pass(&db, 2, start + i * day);
            assert!(r.len() == 1 && r[0].1.is_ok(), "{r:?}");
        }
        assert!(backup_pass(&db, 2, start + 3 * day + 3_600_000).is_empty(), "not again within the day");
        let store = &db.chat_stores()[0];
        let names: Vec<String> = backups(store).iter().map(|(_, p)| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec!["chats-20261104-030000.sqlite", "chats-20261103-030000.sqlite"]);
        let copy = rusqlite::Connection::open(dir.join("backups").join(&names[0])).unwrap();
        let region: String = copy.query_row("SELECT region FROM chat_store", [], |r| r.get(0)).unwrap();
        assert_eq!(region, "gb-lon", "a backup is the store itself, ready to put back");
        let mode: String = copy.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
        assert_eq!(mode, "delete", "one self-contained file");
        let files: Vec<String> = std::fs::read_dir(dir.join("backups")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(files.len(), 2, "no -wal, -shm or partial copies left: {files:?}");
    }

    struct Two {
        t: crate::db::Scratch,
        db: Db,
        lon: PathBuf,
    }

    /// botd with London's and Frankfurt's stores.
    fn two() -> Two {
        let t = crate::db::Scratch::new();
        let db = Db::open(&t.path().join("app.sqlite")).unwrap();
        let (lon, fra) = (t.path().join("lon"), t.path().join("fra"));
        std::fs::create_dir_all(&lon).unwrap();
        std::fs::create_dir_all(&fra).unwrap();
        db.attach_chat_stores(&[("gb-lon".into(), lon.clone()), ("de-fra-2".into(), fra)], &[], None).unwrap();
        Two { t, db, lon }
    }

    fn pinned_bot(db: &Db, name: &str, region: &str) -> (String, String) {
        let u = db.create_user(None, Some(&format!("{name}@example.com")), name, crate::rbac::Role::Member).unwrap().id;
        db.pin_residency(crate::db::PinOn::User, &u, region, "DPA-1", None).unwrap();
        let bot = db.create_bot_owned("B", "#fff", "waddle", "claude", None, false, &u, crate::acl::Visibility::Private).id;
        (u, bot)
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    fn holds(path: &Path, w: &str) -> bool {
        std::fs::read(path).is_ok_and(|b| b.windows(w.len()).any(|x| x == w.as_bytes()))
    }

    #[test]
    fn backups_are_cleared_of_rows_that_left_the_store_and_keep_everyone_elses() {
        let Two { t: _t, db, lon } = two();
        let (ada, bot) = pinned_bot(&db, "ada", "gb-lon");
        let (_, cys) = pinned_bot(&db, "cy", "gb-lon");
        let words = ["chat-0b5e1f-contract", "routine-6d2a90-instruction", "approval-f31c7e-subject"];
        db.add_message(&bot, "user", words[0], None, false, None);
        db.add_routine(&bot, "daily", "0 9 * * *", words[1]);
        db.add_approval(&bot, "claude", "Bash", "command", words[2], &json!({ "command": words[2] }), "write", "asks", now() + 60_000);
        db.add_message(&cys, "user", "cy-stays-in-london", None, false, None);
        let start = chrono::DateTime::parse_from_rfc3339("2026-11-01T03:00:00Z").unwrap().timestamp_millis();
        backup_pass(&db, 7, start);
        backup_pass(&db, 7, start + BACKUP_EVERY_MS);
        let dir = lon.join("backups");
        let before = files_in(&dir);
        assert_eq!(before.len(), 2);
        assert!(before.iter().all(|f| words.iter().all(|w| holds(&dir.join(f), w))));
        assert!(clear_pass(&db, now()).is_empty(), "nothing has left London yet");

        // Pinned to Frankfurt, her rows move; London's backups are rewritten without them.
        db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
        db.pin_residency(crate::db::PinOn::User, &ada, "de-fra-2", "DPA-2", None).unwrap();
        db.place_chats().unwrap();
        assert_eq!(db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").len(), 1, "listed as an earlier copy until cleared");
        let r = clear_pass(&db, now());
        let want = Cleared { bots: 1, users: 0, backups: 2, held: Held { messages: 2, routines: 2, approvals: 2, memories: 0, facts: 0 } };
        assert_eq!(r, vec![("gb-lon".to_string(), Ok(want))]);
        assert_eq!(files_in(&dir), before, "the same restore points, no partial copies left");
        for f in &before {
            let path = dir.join(f);
            for w in words {
                assert!(!holds(&path, w), "{w} left in {f}");
            }
            let c = rusqlite::Connection::open(&path).unwrap();
            let check: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
            let texts: Vec<String> = c.prepare("SELECT text FROM messages").unwrap().query_map([], |r| r.get(0)).unwrap().flatten().collect();
            assert_eq!((check.as_str(), texts), ("ok", vec!["cy-stays-in-london".to_string()]), "{f}");
            let mode: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
            assert_eq!(mode, "delete", "still one self-contained file");
        }
        assert!(db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").is_empty(), "no earlier copies once cleared");
        assert!(clear_pass(&db, now()).is_empty(), "done once");

        // Moving out again makes the newer move uncleared, even with nothing left to take out.
        db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
        db.pin_residency(crate::db::PinOn::User, &ada, "gb-lon", "DPA-3", None).unwrap();
        db.place_chats().unwrap();
        db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
        db.place_chats().unwrap();
        let r = clear_pass(&db, now());
        assert!(r.contains(&("gb-lon".to_string(), Ok(Cleared { bots: 1, ..Cleared::default() }))), "{r:?}");
        assert!(r.contains(&("de-fra-2".to_string(), Ok(Cleared { bots: 1, ..Cleared::default() }))), "Frankfurt has no backups to clear: {r:?}");
        assert!(clear_pass(&db, now()).is_empty());
    }

    #[test]
    fn a_bots_memory_file_moves_into_its_store_and_back_and_backups_are_cleared_of_it() {
        let Two { t, db, lon } = two();
        let data = t.path();
        let (ada, bot) = pinned_bot(&db, "ada", "gb-lon");
        let (_, linked) = pinned_bot(&db, "cy", "gb-lon");
        let word = "memory-2c7f41-the-plan";
        let file = crate::runner::memory_path(data, &bot).unwrap();
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, word).unwrap();
        let link = crate::runner::memory_path(data, &linked).unwrap();
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&file, &link).unwrap();

        let moves = place(&db, data);
        assert_eq!(moves.iter().map(|m| (m.to.as_deref(), m.memories)).collect::<Vec<_>>(), vec![(Some("gb-lon"), 1)]);
        assert!(!file.exists() && db.memory(&bot).as_deref() == Some(word), "taken into the store, its file deleted");
        assert!(std::fs::symlink_metadata(&link).is_ok() && db.memory(&linked).is_none(), "a link is left alone");
        let f = crate::audit::Filter { actions: vec![MOVED.into()], ..Default::default() };
        let events: Vec<Value> = db.audit_events(&f, 10, true).iter().map(|e| serde_json::to_value(e).unwrap()).collect();
        assert_eq!(events.iter().map(|e| e["details"]["memories"].as_i64()).collect::<Vec<_>>(), vec![Some(1)], "{events:?}");
        assert!(place(&db, data).is_empty(), "once");

        let start = chrono::DateTime::parse_from_rfc3339("2026-11-01T03:00:00Z").unwrap().timestamp_millis();
        backup_pass(&db, 7, start);
        let dir = lon.join("backups");
        assert!(files_in(&dir).iter().all(|f| holds(&dir.join(f), word)));

        // Unpinned, it is written back to its file and leaves the store and its backups.
        db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
        let moves = place(&db, data);
        assert_eq!(moves.iter().map(|m| (m.from.as_deref(), m.memories)).collect::<Vec<_>>(), vec![(Some("gb-lon"), 1)]);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), word);
        assert!(db.memory(&bot).is_none() && db.docs_for_files(Doc::Memory).unwrap().is_empty());
        assert!(!holds(&lon.join("chats.sqlite"), word) && !holds(&t.path().join("app.sqlite"), word));
        let r = clear_pass(&db, now());
        assert_eq!(r, vec![("gb-lon".to_string(), Ok(Cleared { bots: 1, users: 0, backups: 1, held: Held { memories: 1, ..Held::default() } }))]);
        assert!(files_in(&dir).iter().all(|f| !holds(&dir.join(f), word)));
    }

    #[test]
    fn a_persons_facts_file_moves_into_their_store_and_back_and_backups_are_cleared_of_it() {
        let Two { t, db, lon } = two();
        let data = t.path();
        let (ada, _) = pinned_bot(&db, "ada", "gb-lon");
        let (cy, _) = pinned_bot(&db, "cy", "gb-lon");
        let word = "facts-7d01e3-ada-is-in-london";
        let file = crate::runner::facts_path(data, &ada).unwrap();
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, word).unwrap();
        let link = crate::runner::facts_path(data, &cy).unwrap();
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&file, &link).unwrap();

        let moves = place(&db, data);
        assert_eq!(moves.iter().map(|m| (m.to.as_deref(), m.bots, m.facts)).collect::<Vec<_>>(), vec![(Some("gb-lon"), 0, 1)]);
        assert!(!file.exists() && db.facts(&ada).as_deref() == Some(word), "taken into the store, the file deleted");
        assert!(std::fs::symlink_metadata(&link).is_ok() && db.facts(&cy).is_none(), "a link is left alone");
        let f = crate::audit::Filter { actions: vec![MOVED.into()], ..Default::default() };
        let events: Vec<Value> = db.audit_events(&f, 10, true).iter().map(|e| serde_json::to_value(e).unwrap()).collect();
        assert_eq!(events.iter().map(|e| e["details"]["facts"].as_i64()).collect::<Vec<_>>(), vec![Some(1)], "{events:?}");
        assert!(place(&db, data).is_empty(), "once");

        let start = chrono::DateTime::parse_from_rfc3339("2026-11-01T03:00:00Z").unwrap().timestamp_millis();
        backup_pass(&db, 7, start);
        let dir = lon.join("backups");
        assert!(files_in(&dir).iter().all(|f| holds(&dir.join(f), word)));

        // Unpinned, they are written back to the file and leave the store and its backups.
        db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
        let moves = place(&db, data);
        assert_eq!(moves.iter().map(|m| (m.from.as_deref(), m.facts)).collect::<Vec<_>>(), vec![(Some("gb-lon"), 1)]);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), word);
        assert!(db.facts(&ada).is_none() && db.docs_for_files(Doc::Facts).unwrap().is_empty());
        assert!(!holds(&lon.join("chats.sqlite"), word) && !holds(&t.path().join("app.sqlite"), word));
        let r = clear_pass(&db, now());
        assert_eq!(r, vec![("gb-lon".to_string(), Ok(Cleared { bots: 0, users: 1, backups: 1, held: Held { facts: 1, ..Held::default() } }))]);
        assert!(files_in(&dir).iter().all(|f| !holds(&dir.join(f), word)));
        let f = crate::audit::Filter { actions: vec![CLEARED.into()], ..Default::default() };
        let cleared: Vec<Value> = db.audit_events(&f, 10, true).iter().map(|e| serde_json::to_value(e).unwrap()).collect();
        assert_eq!((cleared[0]["details"]["users"].as_i64(), cleared[0]["details"]["facts"].as_i64()), (Some(1), Some(1)), "{cleared:?}");
    }

    #[test]
    fn a_move_still_pending_or_back_into_the_store_isnt_cleared_from_its_backups() {
        let Two { t: _t, db, lon: _ } = two();
        let (ada, bot) = pinned_bot(&db, "ada", "gb-lon");
        db.add_message(&bot, "user", "x", None, false, None);
        db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
        db.place_chats().unwrap();
        // Back in London: its backups hold her rows in her own region.
        db.pin_residency(crate::db::PinOn::User, &ada, "gb-lon", "DPA-1", None).unwrap();
        db.place_chats().unwrap();
        let store = db.chat_stores()[0].clone();
        assert!(db.moves_out_to_clear(&store).unwrap().is_empty());
        backup_pass(&db, 7, now());
        // Unpinned, but not moved yet: the backup may be the only other copy of what London still holds.
        db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
        assert!(db.moves_out_to_clear(&store).unwrap().is_empty());
        assert!(clear_pass(&db, now()).is_empty());
        let backup = &backups(&store)[0].1;
        assert_eq!(crate::db::held_in_copy(&rusqlite::Connection::open(backup).unwrap(), &crate::db::Whose { bots: vec![bot.clone()], users: Vec::new() }).unwrap().messages, 1);
        // Moved, then the Bot deleted: still taken out of London's backups.
        db.place_chats().unwrap();
        db.delete_bot(&bot);
        assert_eq!(db.moves_out_to_clear(&store).unwrap().len(), 1);
        assert_eq!(clear_pass(&db, now())[0].1.as_ref().unwrap().held.messages, 1);
        assert_eq!(rusqlite::Connection::open(backup).unwrap().query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }

    #[test]
    fn a_backup_that_cant_be_cleared_keeps_the_move_uncleared_until_it_can() {
        let Two { t: _t, db, lon } = two();
        let (ada, bot) = pinned_bot(&db, "ada", "gb-lon");
        db.add_message(&bot, "user", "x", None, false, None);
        backup_pass(&db, 7, now());
        let bad = lon.join("backups").join("chats-20200101-000000.sqlite");
        std::fs::write(&bad, b"not a database").unwrap();
        db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
        db.place_chats().unwrap();
        let r = clear_pass(&db, now());
        let e = r[0].1.as_ref().unwrap_err();
        assert!(e.contains("chats-20200101-000000.sqlite"), "{e}");
        assert_eq!(db.moves_out_to_clear(&db.chat_stores()[0]).unwrap().len(), 1, "tried again on the next check");
        assert_eq!(db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").len(), 1, "still an earlier copy");
        let good = &backups(&db.chat_stores()[0]).into_iter().find(|(_, p)| *p != bad).unwrap().1;
        assert_eq!(rusqlite::Connection::open(good).unwrap().query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0)).unwrap(), 0, "the others are cleared meanwhile");
        assert_eq!(files_in(&lon.join("backups")).len(), 2, "no partial copies left");
        std::fs::remove_file(&bad).unwrap();
        assert!(clear_pass(&db, now())[0].1.is_ok());
        assert!(db.chat_moves_out(std::slice::from_ref(&ada), "de-fra-2").is_empty());
    }

    #[test]
    fn a_backup_folder_botd_cant_read_isnt_taken_as_cleared_and_half_made_copies_go() {
        let Two { t: _t, db, lon } = two();
        let (ada, bot) = pinned_bot(&db, "ada", "gb-lon");
        let word = "chat-a8e04d-left-behind";
        db.add_message(&bot, "user", word, None, false, None);
        backup_pass(&db, 7, now());
        let dir = lon.join("backups");
        db.unpin_residency(crate::db::PinOn::User, &ada).unwrap();
        db.place_chats().unwrap();
        // The folder can't be listed: nothing shows what its backups hold.
        let aside = lon.join("backups-aside");
        std::fs::rename(&dir, &aside).unwrap();
        std::fs::write(&dir, b"not a folder").unwrap();
        let r = clear_pass(&db, now());
        assert!(r[0].1.as_ref().unwrap_err().contains("backups"), "{r:?}");
        assert_eq!(db.moves_out_to_clear(&db.chat_stores()[0]).unwrap().len(), 1, "not cleared unchecked");
        std::fs::remove_file(&dir).unwrap();
        std::fs::rename(&aside, &dir).unwrap();
        // A copy a crash left half made, of a backup or a rewrite, holds her rows too.
        let backup = files_in(&dir).pop().unwrap();
        let partial = dir.join(format!(".partial-{backup}"));
        std::fs::copy(dir.join(&backup), &partial).unwrap();
        assert!(holds(&partial, word));
        let r = clear_pass(&db, now());
        assert_eq!(r[0].1.as_ref().map(|c| c.backups), Ok(1), "{r:?}");
        assert_eq!(files_in(&dir), vec![backup.clone()], "the half-made copy is gone");
        assert!(!holds(&dir.join(&backup), word));
        assert!(db.moves_out_to_clear(&db.chat_stores()[0]).unwrap().is_empty());
    }

    #[test]
    fn reports_warn_of_earlier_copies_off_the_host_once_the_backups_themselves_are_pruned() {
        let chats = json!({ "earlierCopies": [
            { "region": "gb-lon", "backups": 2, "offHost": true, "movedAt": 1 },
            { "region": "nl-ams", "backups": 0, "offHost": true, "movedAt": 1 },
        ] });
        let w = report_warnings(&chats, "de-fra-2", 0);
        assert!(w[0].starts_with("2 backups of gb-lon's chat store, and their copies off the host, were made before"), "{w:?}");
        assert!(w[1].starts_with("copies off the host of nl-ams's chat store's backups from before their chats") && w[1].contains("ADR 0246"), "{w:?}");
    }
}
