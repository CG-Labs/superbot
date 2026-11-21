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
///
/// Bots can change these folders while they're walked, so each folder is opened from its
/// already-open parent, one name at a time, refusing links: one swapped for a link after
/// it was listed can't lead the walk (with botd's wider access) outside.
struct Walker {
    inodes: std::collections::HashSet<(u64, u64)>,
    seen: u64,
    max: u64,
    partial: bool,
}

/// An open folder, and the names in it with what `lstat` says about each.
struct Dir(std::os::fd::OwnedFd);

impl Dir {
    const FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    fn open(path: &std::path::Path) -> std::io::Result<Dir> {
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)?;
        Ok(Dir(f.into()))
    }

    /// The folder `name` in this one; an error if it's anything else now, a link included.
    fn child(&self, name: &std::ffi::CStr) -> std::io::Result<Dir> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // SAFETY: `self.0` is an open folder and `name` a NUL-terminated name.
        let fd = unsafe { libc::openat(self.0.as_raw_fd(), name.as_ptr(), Self::FLAGS) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a new descriptor that nothing else owns.
        Ok(Dir(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Each name here (not `.` or `..`) with its `lstat`, or None where that failed.
    fn entries(&self) -> std::io::Result<Vec<(std::ffi::CString, Option<libc::stat>)>> {
        use std::os::fd::{AsRawFd, IntoRawFd};
        let dup = self.0.try_clone()?.into_raw_fd();
        // SAFETY: `dup` is an open folder that the stream now owns and closes.
        let stream = unsafe { libc::fdopendir(dup) };
        if stream.is_null() {
            let e = std::io::Error::last_os_error();
            // SAFETY: fdopendir failed, so `dup` is still ours to close.
            unsafe { libc::close(dup) };
            return Err(e);
        }
        let mut out = Vec::new();
        loop {
            // SAFETY: `stream` is open; the entry is read before the next call.
            let e = unsafe { libc::readdir(stream) };
            if e.is_null() {
                break;
            }
            // SAFETY: `d_name` is NUL-terminated within the entry.
            let name = unsafe { std::ffi::CStr::from_ptr((*e).d_name.as_ptr()) };
            if name == c"." || name == c".." {
                continue;
            }
            // SAFETY: an all-zero stat is valid; fstatat fills it in.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: as above; AT_SYMLINK_NOFOLLOW describes a link, not its target.
            let ok = unsafe { libc::fstatat(self.0.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0;
            out.push((name.to_owned(), ok.then_some(st)));
        }
        // SAFETY: `stream` is open and closed once.
        unsafe { libc::closedir(stream) };
        Ok(out)
    }
}

impl Walker {
    fn new(max: u64) -> Walker {
        Walker { inodes: Default::default(), seen: 0, max, partial: false }
    }

    fn size(&mut self, dev: u64, ino: u64, len: u64) -> u64 {
        if self.inodes.insert((dev, ino)) { len } else { 0 }
    }

    fn add(&mut self, roots: &[PathBuf]) -> u64 {
        use std::os::unix::fs::MetadataExt;
        use std::rc::Rc;
        let mut total = 0u64;
        // Folders still to list. Each queued name is opened from its parent, which stays
        // open until its last child is: as many open folders as the walk is deep.
        let mut stack: Vec<Rc<Dir>> = Vec::new();
        let mut queued: Vec<(Rc<Dir>, std::ffi::CString)> = Vec::new();
        for r in roots {
            match std::fs::symlink_metadata(r) {
                Ok(m) if m.is_dir() => match Dir::open(r) {
                    Ok(d) => stack.push(Rc::new(d)),
                    Err(_) => self.partial = true,
                },
                Ok(m) => total = total.saturating_add(self.size(m.dev(), m.ino(), m.len())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => self.partial = true,
            }
        }
        loop {
            let dir = match stack.pop() {
                Some(d) => d,
                None => match queued.pop() {
                    Some((parent, name)) => match parent.child(&name) {
                        Ok(d) => Rc::new(d),
                        // Gone, or now a file or a link: not a folder to walk any more.
                        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)) => continue,
                        Err(_) => {
                            self.partial = true;
                            continue;
                        }
                    },
                    None => break,
                },
            };
            let Ok(entries) = dir.entries() else {
                self.partial = true;
                continue;
            };
            for (name, st) in entries {
                self.seen += 1;
                if self.seen > self.max {
                    self.partial = true;
                    return total;
                }
                let Some(st) = st else {
                    self.partial = true;
                    continue;
                };
                if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                    queued.push((dir.clone(), name));
                } else {
                    #[allow(clippy::unnecessary_cast)]
                    let (dev, ino, len) = (st.st_dev as u64, st.st_ino as u64, st.st_size.max(0) as u64);
                    total = total.saturating_add(self.size(dev, ino, len));
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
    /// Bumped by `forget`: a walk that started before it doesn't put its result back.
    generation: Mutex<HashMap<String, u64>>,
    /// One walk per user at a time; callers who wait get its result.
    walking: Mutex<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    warned: Mutex<HashMap<String, String>>,
}

impl Cache {
    fn get(&self, user_id: &str, max_age: Duration) -> Option<Measured> {
        let m = self.measured.lock().unwrap_or_else(|e| e.into_inner());
        m.get(user_id).filter(|(at, _)| at.elapsed() <= max_age).map(|(_, v)| v.clone())
    }

    fn generation(&self, user_id: &str) -> u64 {
        self.generation.lock().unwrap_or_else(|e| e.into_inner()).get(user_id).copied().unwrap_or(0)
    }

    /// Keeps `v` unless the user was forgotten since generation `g`, when its walk began.
    fn put(&self, user_id: &str, g: u64, v: Measured) {
        let gens = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        if gens.get(user_id).copied().unwrap_or(0) == g {
            self.measured.lock().unwrap_or_else(|e| e.into_inner()).insert(user_id.to_string(), (Instant::now(), v));
        }
    }

    fn walk_lock(&self, user_id: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        self.walking.lock().unwrap_or_else(|e| e.into_inner()).entry(user_id.to_string()).or_default().clone()
    }

    /// The last measurement, however old.
    pub fn last(&self, user_id: &str) -> Option<Measured> {
        self.measured.lock().unwrap_or_else(|e| e.into_inner()).get(user_id).map(|(_, v)| v.clone())
    }

    /// Drops a user's measurement, so the next check measures again (after a run).
    pub fn forget(&self, user_id: &str) {
        let mut gens = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        *gens.entry(user_id.to_string()).or_default() += 1;
        self.measured.lock().unwrap_or_else(|e| e.into_inner()).remove(user_id);
    }

    /// True the first time it's asked for this user on the UTC day of `now` (ms). The
    /// audit log remembers across restarts: a warning recorded today counts.
    pub fn first_warning(&self, db: &crate::db::Db, user_id: &str, now: i64) -> bool {
        let day = crate::tiers::day(now);
        let mut w = self.warned.lock().unwrap_or_else(|e| e.into_inner());
        if w.get(user_id).is_some_and(|d| *d == day) {
            return false;
        }
        w.insert(user_id.to_string(), day);
        !db.audited_since(WARNING_ACTION, "user", user_id, now - now.rem_euclid(86_400_000))
    }
}

/// What a warning is audited as.
pub const WARNING_ACTION: &str = "usage.storage_warning";

/// A user's storage, measured within `max_age`. The walk runs off the async threads.
pub async fn current(app: &std::sync::Arc<App>, user_id: &str, max_age: Duration) -> Measured {
    if let Some(m) = app.storage.get(user_id, max_age) {
        return m;
    }
    let lock = app.storage.walk_lock(user_id);
    let _walking = lock.lock().await;
    // Whoever held it may just have measured.
    if let Some(m) = app.storage.get(user_id, max_age) {
        return m;
    }
    let g = app.storage.generation(user_id);
    let f = folders(app, user_id);
    let m = tokio::task::spawn_blocking(move || measure(&f)).await.unwrap_or_else(|_| Measured { partial: true, at: crate::db::now(), ..Default::default() });
    app.storage.put(user_id, g, m.clone());
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
    }

    #[test]
    fn a_walk_from_before_a_forget_isnt_kept() {
        let cache = Cache::default();
        let g = cache.generation("u1");
        cache.forget("u1");
        cache.put("u1", g, Measured { files: 5, ..Default::default() });
        assert!(cache.last("u1").is_none());
        cache.put("u1", cache.generation("u1"), Measured { files: 7, ..Default::default() });
        assert_eq!(cache.last("u1").map(|m| m.files), Some(7));
    }

    #[test]
    fn a_folder_swapped_for_a_link_isnt_opened() {
        let root = crate::db::temp_path("storage-swap");
        std::fs::create_dir_all(root.join("mine/sub")).unwrap();
        std::fs::create_dir_all(root.join("theirs")).unwrap();
        let dir = Dir::open(&root.join("mine")).unwrap();
        assert!(dir.child(c"sub").is_ok());
        // Listed as a folder, then swapped for a link before it's opened.
        std::fs::remove_dir(root.join("mine/sub")).unwrap();
        std::os::unix::fs::symlink(root.join("theirs"), root.join("mine/sub")).unwrap();
        assert!(matches!(dir.child(c"sub").err().and_then(|e| e.raw_os_error()), Some(libc::ENOTDIR | libc::ELOOP)));
        // A root that's a link isn't walked either.
        assert!(Dir::open(&root.join("mine/sub")).is_err());
    }
}
