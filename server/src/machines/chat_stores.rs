//! Regional chat stores (ADR 0215): pinned people's chats in a database in their region,
//! the first part of splitting botd's database by region. REGION_DATA_DIRS names a
//! folder per region, which the operator puts on storage in that region; botd keeps
//! `chats.sqlite` there (keyed like its own database) and its backups in `backups/`
//! beside it, never in DATA_DIR. A Bot's chat lives in the store of its owner's pin (their
//! team's, else their own), and moves when that changes: at startup, after a pin or unpin,
//! and on every reconcile pass. Accounts, routines, approvals and the audit log stay in
//! botd's own database; botd still reads and writes the stores from wherever it runs.
//!
//! The storage itself is `db::chats`. This module reads the settings, opens the stores
//! at startup, audits each move (`residency.chats_moved`), backs each store up daily in
//! its folder, and says where a pin's chats are for reports, the app and admins.

use super::ControlPlane;
use super::server_data::{Policy, ServerData};
use crate::audit::{Outcome, Who, clip};
use crate::database_encryption::{self, DbKey};
use crate::db::{ChatMove, ChatStore, Db, now};
use crate::obs::log::{log_info, log_warn};
use crate::runner::App;
use crate::AppState;
use serde_json::{Value, json};
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

/// REGION_DATA_DIRS and REGION_DATA_BACKUPS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Each region's folder, canonical, in the order given.
    pub dirs: Vec<(String, PathBuf)>,
    /// Backups of each store kept in its folder.
    pub keep: usize,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { dirs: Vec::new(), keep: DEFAULT_KEEP }
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
        let entries: Vec<&str> = raw.split(',').map(str::trim).filter(|e| !e.is_empty()).collect();
        if entries.is_empty() {
            return Ok(Settings { dirs: Vec::new(), keep });
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
        Ok(Settings { dirs, keep })
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

/// Opens the stores at startup, once botd's database is open: holds each folder's lock,
/// brings each store under botd's database key (`previous`: the key before a rotation),
/// checks them against botd's record and attaches them, redacts known secrets from them,
/// and moves chats to where they belong. Run with no stores too, so a store that still
/// holds chats can't be dropped from the settings. Lines for the startup log.
pub fn open(db: &Db, s: &Settings, previous: Option<&DbKey>) -> Result<Vec<String>, String> {
    let key = database_encryption::installed();
    for (_, dir) in &s.dirs {
        let path = dir.join("chats.sqlite");
        std::mem::forget(database_encryption::lock_data_dir(&path)?);
        if database_encryption::prepare_store(&path, key, previous)? {
            log_info!("Regional chat stores: {} brought under botd's database key (ADR 0215).", path.display());
        }
    }
    let attached = db.attach_chat_stores(&s.dirs, key.map(DbKey::raw))?;
    let mut lines = vec![format!("Regional chat stores: {} (ADR 0215).", s.describe())];
    lines.extend(attached.created.iter().map(|r| format!("Regional chat stores: made {r}'s store.")));
    lines.extend(attached.forgotten.iter().map(|(r, p)| format!("Regional chat stores: {r} is no longer in {SETTING} and its store ({p}) held no chats, so botd stopped recording it.")));
    let scrubbed = db.scrub_chat_stores().map_err(|e| format!("chat stores: {e}"))?;
    if scrubbed > 0 {
        lines.push(format!("Regional chat stores: redacted {scrubbed} saved rows."));
    }
    for m in place(db) {
        lines.push(format!("Regional chat stores: moved {} messages of {} Bots from {} to {}.", m.messages, m.bots, place_name(&m.from), place_name(&m.to)));
    }
    Ok(lines)
}

fn place_name(region: &Option<String>) -> String {
    region.as_ref().map_or("botd's own database".to_string(), |r| format!("{r}'s chat store"))
}

/// Moves every Bot's chat to where its owner's pin says it belongs now, each move audited
/// as `residency.chats_moved` by botd itself. A failure is logged and left for the next pass.
pub fn place(db: &Db) -> Vec<ChatMove> {
    let moves = match db.place_chats() {
        Ok(m) => m,
        Err(e) => {
            log_warn!("Regional chat stores: chats couldn't be moved to where they belong; the next pass tries again: {e} (ADR 0215).");
            return Vec::new();
        }
    };
    for m in &moves {
        db.record(&Who::system(ACTOR).event(MOVED).details(json!({ "from": m.from, "to": m.to, "bots": m.bots, "messages": m.messages })));
    }
    moves
}

// Backups

fn backups_dir(store: &ChatStore) -> PathBuf {
    store.path.parent().unwrap_or(Path::new("/")).join("backups")
}

/// When a backup named `chats-<YYYYMMDD-HHMMSS>.sqlite` was made (UTC, ms).
fn backup_time(name: &str) -> Option<i64> {
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
/// same key, with SQLite's online backup (one step, so writes meanwhile can't tear it),
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
        let src = database_encryption::open_with(&store.path, key).map_err(db)?;
        let mut dst = database_encryption::open_with(&partial, key).map_err(db)?;
        let step = rusqlite::backup::Backup::new(&src, &mut dst).map_err(db)?.step(-1).map_err(db)?;
        if step != rusqlite::backup::StepResult::Done {
            return Err(format!("backing up {}: the store was busy ({step:?}); tried again on the next check", store.path.display()));
        }
        let check: String = dst.query_row("PRAGMA integrity_check", [], |r| r.get(0)).map_err(db)?;
        if check != "ok" {
            return Err(format!("backing up {}: the copy failed its integrity check ({check})", store.path.display()));
        }
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

/// Checks hourly for stores due a backup.
pub fn start(app: AppState, cp: Arc<ControlPlane>) {
    if cp.chat_stores.dirs.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CHECK_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let (a, keep) = (app.clone(), cp.chat_stores.keep);
            let _ = tokio::task::spawn_blocking(move || backup_pass(&a.db, keep, now())).await;
        }
    });
}

// Views

fn store_view(store: &ChatStore, messages: i64) -> Value {
    let b = backups(store);
    json!({ "region": store.region, "messages": messages, "backups": b.len(), "lastBackupAt": b.first().map(|(t, _)| *t) })
}

/// For `GET /api/regions`: each store, its messages and backups, and how many are kept.
pub fn summary(app: &App, cp: &ControlPlane) -> Value {
    let stores: Vec<Value> = app.db.chat_store_counts().iter().map(|(s, n)| store_view(s, *n)).collect();
    json!({ "stores": stores, "keep": cp.chat_stores.keep })
}

/// The store `region` has, as `summary` shows it. None: it has none.
pub fn region_view(app: &App, region: &str) -> Option<Value> {
    app.db.chat_store_counts().iter().find(|(s, _)| s.region == region).map(|(s, n)| store_view(s, *n))
}

/// Warnings for admins: stores whose newest backup is over a day old while they hold chats.
pub fn warnings(app: &App, at: i64) -> Vec<String> {
    app.db
        .chat_store_counts()
        .iter()
        .filter(|(s, n)| *n > 0 && backups(s).first().is_none_or(|(t, _)| at - t > BACKUP_STALE_MS))
        .map(|(s, _)| format!("{}'s chat store has no backup from the last day in its folder's backups/; check botd's log for {BACKUP_FAILED} (ADR 0215).", s.region))
        .collect()
}

/// Where the chats of Bots `owners` own are against a pin to `region`: in its store, in
/// botd's own database (in the region only when botd's own data is, `server_in`), or in
/// another region's store.
pub fn against(app: &App, region: &str, owners: &[String], server_in: bool) -> Value {
    let (mut store, mut database, mut elsewhere) = (0, 0, 0);
    for c in app.db.chat_counts(owners) {
        match c.region.as_deref() {
            Some(r) if r == region => store += c.messages,
            Some(_) => elsewhere += c.messages,
            None => database += c.messages,
        }
    }
    let has = app.db.chat_stores().into_iter().find(|s| s.region == region);
    let last = has.as_ref().and_then(|s| backups(s).first().map(|(t, _)| *t));
    json!({
        "store": has.is_some(),
        "messages": { "inStore": store, "inServerDatabase": database, "elsewhere": elsewhere },
        "inRegion": elsewhere == 0 && (database == 0 || server_in),
        "lastBackupAt": last,
    })
}

/// Report warnings about `chats` (`against`): messages still to move, or in another
/// region's store.
pub fn report_warnings(chats: &Value, region: &str, server_in: bool, at: i64) -> Vec<String> {
    let m = &chats["messages"];
    let mut out = Vec::new();
    if m["inStore"].as_i64().is_some_and(|n| n > 0) && chats["lastBackupAt"].as_i64().is_none_or(|t| at - t > BACKUP_STALE_MS) {
        out.push(format!("{region}'s chat store has no backup from the last day (ADR 0215)"));
    }
    if chats["store"] == true && !server_in && let Some(n) = m["inServerDatabase"].as_i64().filter(|n| *n > 0) {
        out.push(format!("{n} of their chat messages are still in botd's own database; they move to {region}'s chat store on the next pass (ADR 0215)"));
    }
    if let Some(n) = m["elsewhere"].as_i64().filter(|n| *n > 0) {
        out.push(format!("{n} of their chat messages are in another region's chat store; they move on the next pass (ADR 0215)"));
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
        db.attach_chat_stores(&[("gb-lon".into(), dir.clone())], None).unwrap();
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
    }
}
