//! Storage limits per tier (ADR 0082). A tier's `maxStorageMb` caps what one user's files
//! take on this server: their working folder (`WORKSPACE_DIR/users/<id>`, or their whole
//! account folder with `ISOLATION=users`), their facts folder (`DATA_DIR/users/<id>`) and
//! their Bots' folders (`DATA_DIR/bots/<id>`). From `WARN_PERCENT` the Bot warns once a
//! day; at the cap new messages and runs are refused. A tier without one measures only
//! when someone looks, and never refuses anything.

use crate::paths;
use crate::runner::App;
use crate::tiers::Limits;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 1 MB, as `maxStorageMb` counts it.
pub const MB: u64 = 1_000_000;
/// The largest `maxStorageMb`: 1 PB.
pub const MAX_MB: u64 = 1_000_000_000;
/// From this share of the cap, people are warned.
pub const WARN_PERCENT: u64 = 90;
/// Files and folders one measurement visits at most; past it, the total is a lower bound.
const MAX_ENTRIES: u64 = 500_000;
/// How old a measurement may be when a message or run is checked against the cap.
pub const CHECK_AGE: Duration = Duration::from_secs(10);
/// How old a measurement may be when it's only shown.
pub const VIEW_AGE: Duration = Duration::from_secs(60);

/// One user's storage, measured.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Measured {
    /// Their working folder (or account folder), in bytes.
    pub files: u64,
    /// What botd keeps for them and their Bots, in bytes.
    pub data: u64,
    /// Some of it couldn't be read, or there was too much to walk: the total is a lower bound.
    pub partial: bool,
    /// Unix ms.
    pub at: i64,
}

impl Measured {
    pub fn used(&self) -> u64 {
        self.files.saturating_add(self.data)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ok,
    Warning,
    Over,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Ok => "ok",
            State::Warning => "warning",
            State::Over => "over",
        }
    }
}

/// The tier's cap in bytes. None: no cap.
pub fn limit(limits: &Limits) -> Option<u64> {
    limits.max_storage_mb.map(|m| m.saturating_mul(MB))
}

/// Where `used` stands against `limit`: over at or past it, a warning from `WARN_PERCENT`.
pub fn state(used: u64, limit: Option<u64>) -> State {
    match limit {
        None => State::Ok,
        Some(l) if used >= l => State::Over,
        Some(l) if u128::from(used) * 100 >= u128::from(l) * u128::from(WARN_PERCENT) => State::Warning,
        Some(_) => State::Ok,
    }
}

/// Whole percent of `limit` used, rounded down. None: no cap.
pub fn percent(used: u64, limit: Option<u64>) -> Option<u64> {
    limit.map(|l| u64::try_from(u128::from(used) * 100 / u128::from(l.max(1))).unwrap_or(u64::MAX))
}

/// `1234567` -> `1.2 MB`; decimal units, as `maxStorageMb` counts.
pub fn human(bytes: u64) -> String {
    const UNITS: [(u64, &str); 4] = [(1_000_000_000_000, "TB"), (1_000_000_000, "GB"), (MB, "MB"), (1000, "KB")];
    for (size, unit) in UNITS {
        if bytes >= size {
            let tenths = u128::from(bytes) * 10 / u128::from(size);
            return if tenths % 10 == 0 || tenths >= 1000 { format!("{} {unit}", tenths / 10) } else { format!("{}.{} {unit}", tenths / 10, tenths % 10) };
        }
    }
    format!("{bytes} bytes")
}

/// The folders counted for a user. Never created here.
#[derive(Clone, Debug, Default)]
pub struct Folders {
    pub files: Vec<PathBuf>,
    pub data: Vec<PathBuf>,
}

/// A user's folders on this server. Every path comes from the user's id or their Bots'
/// ids, checked as single folder names, so nobody else's folder is ever counted.
pub fn folders(app: &App, user_id: &str) -> Folders {
    let mut f = Folders::default();
    let users = |root: &std::path::Path| paths::canonical(root).and_then(|r| paths::child(&r, crate::isolation::USERS)).and_then(|u| paths::child(&u, user_id));
    match app.isolation() {
        Some(iso) => f.files.extend(iso.user_root(user_id)),
        None => f.files.extend(users(&app.cfg.workspace)),
    }
    f.data.extend(users(&app.cfg.data_dir));
    for id in app.db.owned_bot_ids(user_id) {
        f.data.extend(app.bot_dir(&id));
    }
    f
}

/// Adds up file sizes, never following a link (a link counts as itself), and counts each
/// file once across every walk, even when roots overlap or files are hard links. Folders
/// that can't be read, and anything past `max` entries, are left out: the total is partial.
struct Walker {
    inodes: std::collections::HashSet<(u64, u64)>,
    seen: u64,
    max: u64,
    partial: bool,
}

impl Walker {
    fn new(max: u64) -> Walker {
        Walker { inodes: Default::default(), seen: 0, max, partial: false }
    }

    fn size(&mut self, m: &std::fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt;
        if self.inodes.insert((m.dev(), m.ino())) { m.len() } else { 0 }
    }

    fn add(&mut self, roots: &[PathBuf]) -> u64 {
        let mut total = 0u64;
        let mut stack: Vec<PathBuf> = Vec::new();
        for r in roots {
            match std::fs::symlink_metadata(r) {
                Ok(m) if m.is_dir() => stack.push(r.clone()),
                Ok(m) => total = total.saturating_add(self.size(&m)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => self.partial = true,
            }
        }
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                self.partial = true;
                continue;
            };
            for entry in entries {
                self.seen += 1;
                if self.seen > self.max {
                    self.partial = true;
                    return total;
                }
                // DirEntry::metadata doesn't follow links.
                let Ok(m) = entry.and_then(|e| e.metadata().map(|m| (e.path(), m))) else {
                    self.partial = true;
                    continue;
                };
                if m.1.is_dir() {
                    stack.push(m.0);
                } else {
                    total = total.saturating_add(self.size(&m.1));
                }
            }
        }
        total
    }
}

/// The bytes under `roots`, and whether that's a lower bound.
#[cfg(test)]
pub fn walk(roots: &[PathBuf], max: u64) -> (u64, bool) {
    let mut w = Walker::new(max);
    let n = w.add(roots);
    (n, w.partial)
}

/// Measures now. Blocking: it walks the folders.
pub fn measure(f: &Folders) -> Measured {
    let mut w = Walker::new(MAX_ENTRIES);
    let files = w.add(&f.files);
    let data = w.add(&f.data);
    Measured { files, data, partial: w.partial, at: crate::db::now() }
}

/// Recent measurements by user, and the day each user was last warned.
#[derive(Default)]
pub struct Cache {
    measured: Mutex<HashMap<String, (Instant, Measured)>>,
    warned: Mutex<HashMap<String, String>>,
}

impl Cache {
    fn get(&self, user_id: &str, max_age: Duration) -> Option<Measured> {
        let m = self.measured.lock().unwrap_or_else(|e| e.into_inner());
        m.get(user_id).filter(|(at, _)| at.elapsed() <= max_age).map(|(_, v)| v.clone())
    }

    fn put(&self, user_id: &str, v: Measured) {
        self.measured.lock().unwrap_or_else(|e| e.into_inner()).insert(user_id.to_string(), (Instant::now(), v));
    }

    /// The last measurement, however old.
    pub fn last(&self, user_id: &str) -> Option<Measured> {
        self.measured.lock().unwrap_or_else(|e| e.into_inner()).get(user_id).map(|(_, v)| v.clone())
    }

    /// Drops a user's measurement, so the next check measures again (after a run).
    pub fn forget(&self, user_id: &str) {
        self.measured.lock().unwrap_or_else(|e| e.into_inner()).remove(user_id);
    }

    /// True the first time it's asked for this user on `day`.
    pub fn first_warning(&self, user_id: &str, day: &str) -> bool {
        let mut w = self.warned.lock().unwrap_or_else(|e| e.into_inner());
        if w.get(user_id).is_some_and(|d| d == day) {
            return false;
        }
        w.insert(user_id.to_string(), day.to_string());
        true
    }
}

/// A user's storage, measured within `max_age`. The walk runs off the async threads.
pub async fn current(app: &std::sync::Arc<App>, user_id: &str, max_age: Duration) -> Measured {
    if let Some(m) = app.storage.get(user_id, max_age) {
        return m;
    }
    let f = folders(app, user_id);
    let m = tokio::task::spawn_blocking(move || measure(&f)).await.unwrap_or_else(|_| Measured { partial: true, at: crate::db::now(), ..Default::default() });
    app.storage.put(user_id, m.clone());
    m
}

/// Measures each user unless measured within `VIEW_AGE`, so views show recent numbers.
pub async fn warm(app: &std::sync::Arc<App>, user_ids: &[String]) {
    for id in user_ids {
        current(app, id, VIEW_AGE).await;
    }
}

/// Where a user stands against their tier's cap, when it has one: `(used, limit, state)`.
pub async fn check(app: &std::sync::Arc<App>, user_id: &str) -> Option<(Measured, u64, State)> {
    let limit = limit(&app.tier_of(user_id).limits)?;
    let m = current(app, user_id, CHECK_AGE).await;
    let s = state(m.used(), Some(limit));
    Some((m, limit, s))
}

/// What people are told when their storage is full. No paths, no model names.
pub fn full_text(label: &str, used: u64, limit: u64) -> String {
    format!(
        "Storage is full: {} used of the {label} plan's {}, so I didn't run. Delete files from the workspace, or move to a bigger plan, then ask again.",
        human(used),
        human(limit)
    )
}

/// What a person sending a message is told when the Bot's owner's storage is full.
pub fn refusal_text(label: &str, used: u64, limit: u64) -> String {
    format!(
        "Storage is full: {} used of the {label} plan's {}. Delete files from the workspace, or move to a bigger plan, before sending more.",
        human(used),
        human(limit)
    )
}

/// What the Bot says, once a day, when its owner's storage is nearly full.
pub fn warning_text(label: &str, used: u64, limit: u64) -> String {
    let p = percent(used, Some(limit)).unwrap_or(0);
    format!(
        "Storage is {p}% full: {} used of the {label} plan's {}. At 100%, I'll stop taking new tasks until files are deleted or the plan grows.",
        human(used),
        human(limit)
    )
}

/// A user's storage for the usage and plan views, from the last measurement. `onMachine`:
/// their Bots run on their own machine, whose disk this doesn't see (its plan caps it).
pub fn view(app: &App, user_id: &str) -> Value {
    let limits = &app.tier_of(user_id).limits;
    let cap = limit(limits);
    let m = app.storage.last(user_id);
    let used = m.as_ref().map_or(0, Measured::used);
    json!({
        "used": m.as_ref().map(Measured::used),
        "files": m.as_ref().map(|m| m.files),
        "data": m.as_ref().map(|m| m.data),
        "limit": cap,
        "limitMb": limits.max_storage_mb,
        "percent": m.as_ref().and(percent(used, cap)),
        "state": m.as_ref().map(|_| state(used, cap).as_str()),
        "warnAt": WARN_PERCENT,
        "partial": m.as_ref().is_some_and(|m| m.partial),
        "measuredAt": m.as_ref().map(|m| m.at),
        "onMachine": app.db.placed_at(user_id).is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_and_percentages() {
        assert_eq!(state(10, None), State::Ok);
        assert_eq!(state(899_999, Some(MB)), State::Ok);
        assert_eq!(state(900_000, Some(MB)), State::Warning);
        assert_eq!(state(999_999, Some(MB)), State::Warning);
        assert_eq!(state(MB, Some(MB)), State::Over);
        assert_eq!(state(u64::MAX, Some(u64::MAX - 1)), State::Over);
        assert_eq!(percent(950_000, Some(MB)), Some(95));
        assert_eq!(percent(5, None), None);
        assert_eq!(limit(&Limits { max_storage_mb: Some(5_000), ..Default::default() }), Some(5_000_000_000));
        assert_eq!(limit(&Limits::default()), None);
    }

    #[test]
    fn sizes_read_like_people_write_them() {
        assert_eq!(human(0), "0 bytes");
        assert_eq!(human(999), "999 bytes");
        assert_eq!(human(1_500), "1.5 KB");
        assert_eq!(human(MB), "1 MB");
        assert_eq!(human(1_234_567), "1.2 MB");
        assert_eq!(human(5_000_000_000), "5 GB");
        assert_eq!(human(250_000_000_000), "250 GB");
    }

    #[test]
    fn walking_counts_files_once_and_never_follows_links() {
        let root = crate::db::temp_path("storage-walk");
        let mine = root.join("mine");
        let theirs = root.join("theirs");
        std::fs::create_dir_all(mine.join("deep/er")).unwrap();
        std::fs::create_dir_all(&theirs).unwrap();
        std::fs::write(mine.join("a.txt"), vec![0u8; 1000]).unwrap();
        std::fs::write(mine.join("deep/er/b.bin"), vec![0u8; 2500]).unwrap();
        std::fs::write(theirs.join("big"), vec![0u8; 1_000_000]).unwrap();
        // A link to someone else's folder or file counts as the link, not what it points at.
        std::os::unix::fs::symlink(&theirs, mine.join("to-theirs")).unwrap();
        std::os::unix::fs::symlink(theirs.join("big"), mine.join("big-link")).unwrap();
        // A hard link is the same file: counted once.
        std::fs::hard_link(mine.join("a.txt"), mine.join("deep/a-again.txt")).unwrap();
        let (n, partial) = walk(std::slice::from_ref(&mine), MAX_ENTRIES);
        assert!(!partial);
        let links = std::fs::symlink_metadata(mine.join("to-theirs")).unwrap().len() + std::fs::symlink_metadata(mine.join("big-link")).unwrap().len();
        assert_eq!(n, 3500 + links);
        // A root that isn't there is nothing; overlapping roots count once.
        assert_eq!(walk(&[root.join("nope")], MAX_ENTRIES), (0, false));
        assert_eq!(walk(&[mine.clone(), mine.join("deep")], MAX_ENTRIES).0, n);
        // Too much to walk: a lower bound, said to be one.
        let (some, partial) = walk(std::slice::from_ref(&mine), 2);
        assert!(partial && some <= n);
    }

    #[test]
    fn a_folder_it_cant_read_makes_it_partial() {
        use std::os::unix::fs::PermissionsExt;
        if nix_root() {
            return; // root reads everything
        }
        let root = crate::db::temp_path("storage-locked");
        std::fs::create_dir_all(root.join("locked")).unwrap();
        std::fs::write(root.join("open.txt"), vec![0u8; 10]).unwrap();
        std::fs::write(root.join("locked/x"), vec![0u8; 10]).unwrap();
        std::fs::set_permissions(root.join("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let (n, partial) = walk(std::slice::from_ref(&root), MAX_ENTRIES);
        std::fs::set_permissions(root.join("locked"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!((n, partial), (10, true));
    }

    fn nix_root() -> bool {
        std::fs::read_to_string("/proc/self/status").is_ok_and(|s| s.lines().any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(1) == Some("0")))
    }

    #[test]
    fn people_are_told_in_plain_words() {
        let full = full_text("Starter", 5_200_000_000, 5_000_000_000);
        assert_eq!(full, "Storage is full: 5.2 GB used of the Starter plan's 5 GB, so I didn't run. Delete files from the workspace, or move to a bigger plan, then ask again.");
        let warn = warning_text("Starter", 4_600_000_000, 5_000_000_000);
        assert!(warn.starts_with("Storage is 92% full: 4.6 GB used of the Starter plan's 5 GB."), "{warn}");
        let cache = Cache::default();
        assert!(cache.first_warning("u1", "2026-11-21"));
        assert!(!cache.first_warning("u1", "2026-11-21"));
        assert!(cache.first_warning("u2", "2026-11-21"));
        assert!(cache.first_warning("u1", "2026-11-22"));
    }
}
