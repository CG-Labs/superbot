//! Moving a regional chat store to another folder while botd runs (ADR 0309): onto a new
//! volume in the same region, say, without stopping botd. An admin names the region and an
//! empty folder (`POST /api/regions/{region}/chat-store/move`, `botctl regions move-store`).
//! botd holds the folder's lock, copies the store there with nothing writing to it, checks
//! the copy and attaches it in the old file's place (`Db::move_chat_store`), then moves the
//! store's backups and deletes the old file, leaving a note in the old folder. A store keeps
//! its region: what moves pinned data between regions is a pin.
//!
//! REGION_DATA_DIRS still names the old folder until the operator changes it. botd warns
//! admins meanwhile, and won't start until it names the new one, rather than make an empty
//! store in the old folder.

use super::{ControlPlane, conflict};
use super::chat_stores::{self, SETTING};
use crate::audit::{Outcome, Who, clip};
use crate::database_encryption;
use crate::db::{ChatStore, Db, StoreMoved, now, remove_store_files};
use crate::secrets::sealed::UserSecrets;
use crate::{AppState, Auth, Res, bad, not_found};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path as UrlPath, State as AppS};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const STORE_MOVED: &str = "residency.chat_store_moved";
/// Left in the old folder, for whoever looks there next.
pub const NOTE: &str = "MOVED.txt";
const PARTIAL: &str = ".partial-";

/// Held by each hourly check of the stores and by a move, so a move never runs while a
/// backup, clearing or copy off the host reads or writes a store's folder.
pub(super) static FOLDERS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What a move did.
#[derive(Debug)]
pub struct Moved {
    pub store: StoreMoved,
    /// Backups moved with it.
    pub backups: usize,
    /// Files left in the old folder that couldn't be moved or deleted, with why.
    pub left: Vec<String>,
}

fn euid() -> u32 {
    // SAFETY: geteuid can't fail.
    unsafe { libc::geteuid() }
}

/// The folder `region`'s store can move to, and whether botd made it: `folder`, canonical,
/// made if missing (and removed again when refused), and then the store's own as
/// REGION_DATA_DIRS folders are: outside DATA_DIR, overlapping no store's folder, this
/// one's included, empty, botd's, and readable by botd only.
fn new_folder(stores: &[ChatStore], region: &str, folder: &str, data_dir: &Path) -> Result<(PathBuf, bool), String> {
    let folder = folder.trim();
    if !Path::new(folder).is_absolute() {
        return Err(format!("the folder must be an absolute path, not \"{}\"", clip(folder, 64)));
    }
    let existed = std::fs::symlink_metadata(folder).is_ok();
    let path = crate::paths::root(folder).map_err(|e| format!("{}: {e}", clip(folder, 200)))?;
    let checked = check_folder(stores, region, &path, data_dir);
    if checked.is_err() && !existed {
        let _ = std::fs::remove_dir(&path);
    }
    checked.map(|()| (path, !existed))
}

fn check_folder(stores: &[ChatStore], region: &str, path: &Path, data_dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let data_dir = std::fs::canonicalize(data_dir).map_err(|e| format!("DATA_DIR: {e}"))?;
    if path.starts_with(&data_dir) || data_dir.starts_with(path) {
        return Err(format!("{} must be outside DATA_DIR ({}), whose archives leave the region with server backups (ADR 0215)", path.display(), data_dir.display()));
    }
    for s in stores {
        let Some(d) = s.path.parent() else { continue };
        if d.starts_with(path) || path.starts_with(d) {
            return Err(if s.region == region {
                format!("{} is or overlaps {region}'s store's own folder ({})", path.display(), d.display())
            } else {
                format!("{} overlaps {}'s chat store's folder ({})", path.display(), s.region, d.display())
            });
        }
    }
    let mut entries = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if entries.any(|e| e.map_or(true, |e| e.file_name() != NOTE)) {
        return Err(format!("{} isn't empty; botd moves a store only into an empty folder (or one holding only a {NOTE} a move left)", path.display()));
    }
    let (owner, uid) = (std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?.uid(), euid());
    if owner != uid {
        return Err(format!("{} belongs to uid {owner}, not the user botd runs as (uid {uid})", path.display()));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", path.display()))
}

fn lock_file(store: &Path) -> PathBuf {
    store.with_file_name("chats.sqlite-lock")
}

/// Moves `region`'s store into `folder` while botd runs (ADR 0309), with the users' secrets'
/// connection (`secrets`) held and attached to it too, and its backups after it. The old
/// file is deleted once the new one is attached, with a note left in its folder.
pub fn move_store(db: &Db, secrets: Option<&UserSecrets>, region: &str, folder: &str, data_dir: &Path, at: i64) -> Result<Moved, String> {
    let stores = db.chat_stores();
    let store = stores.iter().find(|s| s.region == region).cloned().ok_or_else(|| format!("{region} has no chat store ({SETTING}, ADR 0215)"))?;
    let (to_dir, made) = new_folder(&stores, region, folder, data_dir)?;
    let to = to_dir.join("chats.sqlite");
    chat_stores::hold_store_lock(&to)?;
    let moved = match db.move_chat_store(region, &to, database_encryption::installed(), secrets) {
        Ok(m) => m,
        Err(e) => {
            chat_stores::release_store_lock(&to);
            let _ = std::fs::remove_file(lock_file(&to));
            if made {
                let _ = std::fs::remove_dir(&to_dir);
            }
            return Err(e);
        }
    };
    let _ = std::fs::remove_file(to_dir.join(NOTE));
    let from_dir = store.path.parent().unwrap_or(Path::new("/")).to_path_buf();
    let (backups, mut left) = move_backups(&from_dir.join("backups"), &to_dir.join("backups"));
    remove_store_files(&store.path);
    for f in ["", "-wal", "-shm"] {
        let p = store.path.with_file_name(format!("chats.sqlite{f}"));
        if std::fs::symlink_metadata(&p).is_ok() {
            left.push(format!("{}: couldn't be deleted", p.display()));
        }
    }
    chat_stores::release_store_lock(&store.path);
    let _ = std::fs::remove_file(lock_file(&store.path));
    let date = chrono::DateTime::from_timestamp_millis(at).unwrap_or_default().format("%Y-%m-%d %H:%M UTC");
    let mut note = format!(
        "botd moved {region}'s chat store (store {}) to {} on {date}, while it ran (ADR 0309).\n\
         Set {SETTING} to {region}={} before botd next starts: it won't start while {SETTING} names this folder.\n",
        store.id,
        to_dir.display(),
        to_dir.display()
    );
    if !left.is_empty() {
        note.push_str("These couldn't be moved or deleted and are left here:\n");
        note.extend(left.iter().map(|l| format!("- {l}\n")));
    } else {
        note.push_str("This folder holds nothing botd needs.\n");
    }
    let _ = std::fs::write(from_dir.join(NOTE), note);
    Ok(Moved { store: moved, backups, left })
}

/// Moves each backup in `from` to `to`: copied beside it, synced, renamed into place with
/// `to` synced, then deleted from `from`. Half-made ones are deleted. How many moved, and what was left.
fn move_backups(from: &Path, to: &Path) -> (usize, Vec<String>) {
    let mut left = Vec::new();
    let entries = match std::fs::read_dir(from) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, left),
        Err(e) => return (0, vec![format!("{}: {e}", from.display())]),
    };
    let sync_dir = |d: &Path| std::fs::File::open(d).and_then(|d| d.sync_all());
    if let Err(e) = std::fs::create_dir_all(to).and_then(|()| to.parent().map_or(Ok(()), sync_dir)) {
        return (0, vec![format!("{}: {e}; the backups are left in {}", to.display(), from.display())]);
    }
    let mut n = 0;
    for entry in entries.flatten() {
        let (p, name) = (entry.path(), entry.file_name().to_string_lossy().into_owned());
        if !std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file()) {
            left.push(format!("{}: not a plain file", p.display()));
            continue;
        }
        if name.starts_with(PARTIAL) {
            let _ = std::fs::remove_file(&p);
            continue;
        }
        let partial = to.join(format!("{PARTIAL}{name}"));
        let copied = std::fs::copy(&p, &partial)
            .and_then(|_| std::fs::File::open(&partial)?.sync_all())
            .and_then(|()| std::fs::rename(&partial, to.join(&name)))
            .and_then(|()| sync_dir(to))
            .and_then(|()| std::fs::remove_file(&p));
        match copied {
            Ok(()) => n += 1,
            Err(e) => {
                let _ = std::fs::remove_file(&partial);
                left.push(format!("{}: {e}", p.display()));
            }
        }
    }
    let _ = std::fs::remove_dir(from);
    (n, left)
}

/// REGION_DATA_DIRS as it should be now: every store's folder, where it is.
fn settings_now(db: &Db) -> String {
    db.chat_stores().iter().map(|s| format!("{}={}", s.region, s.path.parent().unwrap_or(Path::new("/")).display())).collect::<Vec<_>>().join(",")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveBody {
    folder: String,
}

/// `POST /api/regions/{region}/chat-store/move` `{folder}`: moves the region's chat store to
/// an empty folder while botd runs, audited as `residency.chat_store_moved` (ADR 0309).
pub async fn move_http(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    UrlPath(region): UrlPath<String>,
    body: Result<Json<MoveBody>, JsonRejection>,
) -> Res {
    let cp: &ControlPlane = &a.machines;
    cp.need()?;
    let Ok(Json(b)) = body else {
        return Err(bad("Send {\"folder\": \"<an empty folder on storage in the region>\"}."));
    };
    if !app.db.chat_stores().iter().any(|s| s.region == region) {
        return Err(not_found("Chat store for this region"));
    }
    let _ops = cp.lock_ops().await;
    let _folders = FOLDERS.lock().await;
    let (a2, r, folder, data_dir) = (app.clone(), region.clone(), b.folder.clone(), app.cfg.data_dir.clone());
    let done = tokio::task::spawn_blocking(move || move_store(&a2.db, crate::secrets::global().users_for_stores(), &r, &folder, &data_dir, now()))
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
    let m = match done {
        Ok(m) => m,
        Err(e) => {
            let d = json!({ "region": region, "folder": clip(&b.folder, 200), "error": clip(&e, 500) });
            app.db.record(&by.event(STORE_MOVED).target("chat_store", &region).outcome(Outcome::Failure).details(d));
            return Err(conflict(format!("{region}'s chat store wasn't moved: {e} (ADR 0309).")));
        }
    };
    let dir = |p: &Path| p.parent().unwrap_or(Path::new("/")).display().to_string();
    let settings = settings_now(&app.db);
    let v = json!({
        "region": region, "storeId": m.store.store_id, "from": dir(&m.store.from), "to": dir(&m.store.to), "bytes": m.store.bytes,
        "backups": m.backups, "left": m.left, "regionDataDirs": settings,
    });
    app.db.record(&by.event(STORE_MOVED).target("chat_store", &region).details(v.clone()));
    crate::obs::log::log_info!("Regional chat stores: {region}'s store moved from {} to {} (ADR 0309). Set {SETTING}={settings} before botd next starts.", dir(&m.store.from), dir(&m.store.to));
    Ok(Json(with_next(v)))
}

fn with_next(mut v: Value) -> Value {
    v["next"] = json!(format!("Set {SETTING}={} before botd next starts: it won't start while {SETTING} names the old folder.", v["regionDataDirs"].as_str().unwrap_or_default()));
    v
}

/// Warnings for admins: stores moved while botd ran whose folder REGION_DATA_DIRS doesn't
/// name yet (ADR 0309).
pub fn warnings(db: &Db, cp: &ControlPlane) -> Vec<String> {
    db.chat_stores()
        .iter()
        .filter_map(|s| {
            let now = s.path.parent()?;
            let (_, named) = cp.chat_stores.dirs.iter().find(|(r, _)| *r == s.region)?;
            (named != now).then(|| {
                format!(
                    "{}'s chat store was moved to {} while botd ran, but {SETTING} still names {}: set it to {}={} before botd next starts, or botd won't start (ADR 0309).",
                    s.region,
                    now.display(),
                    named.display(),
                    s.region,
                    now.display()
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Scratch;

    #[test]
    fn backups_move_whole_and_half_made_ones_are_dropped() {
        let t = Scratch::new();
        let (from, to) = (t.path().join("old").join("backups"), t.path().join("new").join("backups"));
        std::fs::create_dir_all(&from).unwrap();
        std::fs::write(from.join("chats-20261126-010000.sqlite"), "one").unwrap();
        std::fs::write(from.join("chats-20261125-010000.sqlite"), "two").unwrap();
        std::fs::write(from.join(".partial-chats-20261126-020000.sqlite"), "half").unwrap();
        assert_eq!(move_backups(&from, &to), (2, Vec::new()));
        assert!(!from.exists());
        let mut names: Vec<String> = std::fs::read_dir(&to).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, ["chats-20261125-010000.sqlite", "chats-20261126-010000.sqlite"]);
        assert_eq!(std::fs::read_to_string(to.join("chats-20261126-010000.sqlite")).unwrap(), "one");
        assert_eq!(move_backups(&t.path().join("none"), &to), (0, Vec::new()));
    }

    #[test]
    fn a_refused_move_keeps_a_folder_botd_didnt_make_and_removes_one_it_did() {
        let t = Scratch::new();
        let (lon, data) = (t.path().join("lon"), t.path().join("data"));
        for d in [&lon, &data] {
            std::fs::create_dir_all(d).unwrap();
        }
        let db = Db::open(&data.join("app.sqlite")).unwrap();
        db.attach_chat_stores(&[("gb-lon".into(), lon.clone())], &[], None).unwrap();
        let mine = data.join("mine");
        std::fs::create_dir_all(&mine).unwrap();
        assert!(move_store(&db, None, "gb-lon", mine.to_str().unwrap(), &data, 0).unwrap_err().contains("outside DATA_DIR"));
        assert!(mine.is_dir(), "the operator's folder stays");
        let made = data.join("made");
        assert!(move_store(&db, None, "gb-lon", made.to_str().unwrap(), &data, 0).unwrap_err().contains("outside DATA_DIR"));
        assert!(!made.exists(), "botd's own goes");
        assert!(move_store(&db, None, "de-fra-2", t.path().join("x").to_str().unwrap(), &data, 0).unwrap_err().contains("has no chat store"));

        let away = t.path().join("away");
        let m = move_store(&db, None, "gb-lon", away.to_str().unwrap(), &data, 0).unwrap();
        assert_eq!((m.store.to, m.backups, m.left.len()), (away.join("chats.sqlite"), 0, 0));
        assert!(!lon.join("chats.sqlite").exists() && !lon.join("chats.sqlite-lock").exists() && lon.join(NOTE).exists());
    }
}
