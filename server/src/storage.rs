//! Storage limits per tier (ADR 0082). A tier's `maxStorageMb` caps what one user's files
//! take on this server: their working folder (`WORKSPACE_DIR/users/<id>`, or their whole
//! account folder with `ISOLATION=users`), their facts folder (`DATA_DIR/users/<id>`) and
//! their Bots' folders (`DATA_DIR/bots/<id>`). From `WARN_PERCENT` the Bot warns once a
//! day; at the cap new messages and runs are refused. A tier without one measures only
//! when someone looks, and never refuses anything.
//!
//! When the user's Bots work on their own machine (ADR 0105), what that machine's agent
//! last said its homes hold counts instead of their working folder here, which their
//! Bots no longer write to: a report that's old still counts, and none yet counts as
//! nothing, with the total a lower bound.

use crate::db::Machine;
use crate::machines::route::Routing;
use crate::paths;
use crate::runner::App;
use crate::tiers::Limits;
use crate::walk::{MAX_ENTRIES, Walker};
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
/// How old a measurement may be when a message or run is checked against the cap.
pub const CHECK_AGE: Duration = Duration::from_secs(10);
/// How old a measurement may be when it's only shown.
pub const VIEW_AGE: Duration = Duration::from_secs(60);

/// One user's storage, measured.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Measured {
    /// Their working folder (or account folder), in bytes. 0 while their Bots work on
    /// their machine: it isn't walked then.
    pub files: u64,
    /// What botd keeps for them and their Bots, in bytes.
    pub data: u64,
    /// Some of it couldn't be read, or there was too much to walk.
    pub partial: bool,
    /// Unix ms.
    pub at: i64,
    /// Walked without the working folder, as for a user whose Bots work on their machine.
    pub placed: bool,
    /// Their machine's report, while their Bots work there (ADR 0105).
    pub machine: Option<OnMachine>,
}

impl Measured {
    pub fn used(&self) -> u64 {
        self.files.saturating_add(self.data).saturating_add(self.machine.map_or(0, |m| m.bytes))
    }

    /// Whether the true total may be higher: a folder couldn't be read, there was too much
    /// to walk, or the machine hasn't said, or said it couldn't read everything.
    pub fn lower_bound(&self) -> bool {
        self.partial || self.machine.is_some_and(|m| m.partial || m.report == Report::Missing)
    }
}

/// How recent a machine's report of its homes is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    /// Heard within `resize::DISK_FRESH_MS` (for a suspended machine, of being suspended).
    Fresh,
    /// Older: its agent hasn't answered since. Bots write there only in runs, and each
    /// run starts by reaching the agent, so the last report still counts.
    Stale,
    /// Never heard (an agent from before ADR 0105, or one that hasn't measured yet).
    Missing,
}

impl Report {
    pub fn as_str(self) -> &'static str {
        match self {
            Report::Fresh => "fresh",
            Report::Stale => "stale",
            Report::Missing => "missing",
        }
    }
}

/// What a user's machine said its homes hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OnMachine {
    /// Bytes; 0 when `Missing`.
    pub bytes: u64,
    /// Whether the agent's own walk was a lower bound.
    pub partial: bool,
    /// When botd heard it, Unix ms.
    pub at: Option<i64>,
    pub report: Report,
}

/// `m`'s report of its homes at `now`.
pub fn on_machine(m: &Machine, now: i64) -> OnMachine {
    match (m.disk_files, m.disk_files_at) {
        (Some(b), Some(at)) => OnMachine {
            bytes: u64::try_from(b).unwrap_or(0),
            partial: m.disk_files_partial,
            at: Some(at),
            report: if crate::machines::resize::fresh(m, Some(at), now) { Report::Fresh } else { Report::Stale },
        },
        _ => OnMachine { bytes: 0, partial: false, at: None, report: Report::Missing },
    }
}

/// The user's machine, when their Bots work on it: machine routing is on and the machine
/// is assigned to them (ADR 0036), whatever state it's in now. Then their working folder
/// on this server is a copy nothing writes to, and the machine's homes count instead.
pub fn placed_machine(app: &App, user_id: &str) -> Option<Machine> {
    app.control_plane.get().filter(|cp| cp.enabled() && cp.routing != Routing::Off)?;
    app.db.user_machine(user_id).filter(|m| m.user_id == user_id && m.assigned_at.is_some())
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
/// ids, checked as single folder names, so nobody else's folder is ever counted. `placed`:
/// their Bots work on their machine, so their working folder here isn't counted.
pub fn folders(app: &App, user_id: &str, placed: bool) -> Folders {
    let mut f = Folders::default();
    let users = |root: &std::path::Path| paths::canonical(root).and_then(|r| paths::child(&r, crate::isolation::USERS)).and_then(|u| paths::child(&u, user_id));
    match app.isolation() {
        _ if placed => {}
        Some(iso) => f.files.extend(iso.user_root(user_id)),
        None => f.files.extend(users(&app.cfg.workspace)),
    }
    f.data.extend(users(&app.cfg.data_dir));
    for id in app.db.owned_bot_ids(user_id) {
        f.data.extend(app.bot_dir(&id));
    }
    f
}

/// Measures now. Blocking: it walks the folders.
pub fn measure(f: &Folders) -> Measured {
    let mut w = Walker::new(MAX_ENTRIES);
    let files = w.add(&f.files);
    let data = w.add(&f.data);
    Measured { files, data, partial: w.partial(), at: crate::db::now(), ..Default::default() }
}

pub struct Forget<'a>(&'a Cache, &'a str);

impl Drop for Forget<'_> {
    fn drop(&mut self) {
        self.0.forget(self.1);
    }
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
    /// A walk within `max_age` of the same folders: one from before the user's Bots moved
    /// onto or off their machine walked the wrong ones.
    fn get(&self, user_id: &str, max_age: Duration, placed: bool) -> Option<Measured> {
        let m = self.measured.lock().unwrap_or_else(|e| e.into_inner());
        m.get(user_id).filter(|(at, v)| at.elapsed() <= max_age && v.placed == placed).map(|(_, v)| v.clone())
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

    /// Forgets the user when dropped. Declared after a run's slot, it drops first: a Bot
    /// let in by that slot can't pass on a measurement from before the run.
    pub fn forget_on_drop<'a>(&'a self, user_id: &'a str) -> Forget<'a> {
        Forget(self, user_id)
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

/// A user's storage, measured within `max_age`, with their machine's latest report while
/// their Bots work there. The walk runs off the async threads.
pub async fn current(app: &std::sync::Arc<App>, user_id: &str, max_age: Duration) -> Measured {
    let machine = placed_machine(app, user_id);
    let mut m = walked(app, user_id, max_age, machine.is_some()).await;
    m.machine = machine.map(|mm| on_machine(&mm, crate::db::now()));
    m
}

async fn walked(app: &std::sync::Arc<App>, user_id: &str, max_age: Duration, placed: bool) -> Measured {
    if let Some(m) = app.storage.get(user_id, max_age, placed) {
        return m;
    }
    let lock = app.storage.walk_lock(user_id);
    let _walking = lock.lock().await;
    // Whoever held it may just have measured.
    if let Some(m) = app.storage.get(user_id, max_age, placed) {
        return m;
    }
    let g = app.storage.generation(user_id);
    let f = folders(app, user_id, placed);
    let mut m = tokio::task::spawn_blocking(move || measure(&f)).await.unwrap_or_else(|_| Measured { partial: true, at: crate::db::now(), ..Default::default() });
    m.placed = placed;
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

/// What people are told when their storage is full, said by the Bot. No paths, no
/// model names. Where to delete files is where the owner's Bots work.
pub fn full_text(label: &str, m: &Measured, limit: u64) -> String {
    let place = if m.machine.is_some() { "on the computer I work on" } else { "from the workspace" };
    format!(
        "Storage is full: {} used of the {label} plan's {}, so I didn't run. Delete files {place}, or move to a bigger plan, then ask again.",
        human(m.used()),
        human(limit)
    )
}

/// What a person sending a message is told when the Bot's owner's storage is full.
pub fn refusal_text(label: &str, m: &Measured, limit: u64) -> String {
    let place = if m.machine.is_some() { "on the computer this Bot works on" } else { "from the workspace" };
    format!(
        "Storage is full: {} used of the {label} plan's {}. Delete files {place}, or move to a bigger plan, before sending more.",
        human(m.used()),
        human(limit)
    )
}

/// What the Bot says, once a day, when its owner's storage is nearly full.
pub fn warning_text(label: &str, m: &Measured, limit: u64) -> String {
    let used = m.used();
    let p = percent(used, Some(limit)).unwrap_or(0);
    format!(
        "Storage is {p}% full: {} used of the {label} plan's {}. At 100%, I'll stop taking new tasks until files are deleted or the plan grows.",
        human(used),
        human(limit)
    )
}

/// `d`, an object, with what a storage refusal or warning records of the measurement:
/// the total, whether it's a lower bound, and the machine's part and how recent its
/// report was. Byte counts only.
pub fn details(m: &Measured, mut d: Value) -> Value {
    d["used"] = json!(m.used());
    d["partial"] = json!(m.lower_bound());
    if let Some(on) = &m.machine {
        d["machine"] = json!({ "used": on.bytes, "report": on.report.as_str(), "partial": on.partial, "measuredAt": on.at });
    }
    d
}

/// A user's storage for the usage and plan views, from the last measurement and their
/// machine's latest report. `onMachine`: their Bots work on their own machine, so its
/// homes count (`machine`) and their working folder here doesn't (`files` is null).
pub fn view(app: &App, user_id: &str) -> Value {
    let limits = &app.tier_of(user_id).limits;
    let cap = limit(limits);
    let machine = placed_machine(app, user_id).map(|mm| on_machine(&mm, crate::db::now()));
    let m = app.storage.last(user_id).map(|m| Measured { machine, ..m });
    let used = m.as_ref().map_or(0, Measured::used);
    json!({
        "used": m.as_ref().map(Measured::used),
        "files": m.as_ref().filter(|_| machine.is_none()).map(|m| m.files),
        "data": m.as_ref().map(|m| m.data),
        "machine": machine.map(|on| json!({
            "used": (on.report != Report::Missing).then_some(on.bytes),
            "report": on.report.as_str(),
            "partial": on.partial,
            "measuredAt": on.at,
        })),
        "limit": cap,
        "limitMb": limits.max_storage_mb,
        "percent": m.as_ref().and(percent(used, cap)),
        "state": m.as_ref().map(|_| state(used, cap).as_str()),
        "warnAt": WARN_PERCENT,
        "partial": m.as_ref().is_some_and(Measured::lower_bound),
        "measuredAt": m.as_ref().map(|m| m.at),
        "onMachine": machine.is_some(),
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
    fn people_are_told_in_plain_words() {
        let here = Measured { files: 5_000_000_000, data: 200_000_000, ..Default::default() };
        let full = full_text("Starter", &here, 5_000_000_000);
        assert_eq!(full, "Storage is full: 5.2 GB used of the Starter plan's 5 GB, so I didn't run. Delete files from the workspace, or move to a bigger plan, then ask again.");
        let warn = warning_text("Starter", &Measured { files: 4_600_000_000, ..Default::default() }, 5_000_000_000);
        assert!(warn.starts_with("Storage is 92% full: 4.6 GB used of the Starter plan's 5 GB."), "{warn}");
        // On a machine, they're told to delete files where the Bots work: on it.
        let there = Measured { data: 200_000_000, machine: Some(OnMachine { bytes: 5_000_000_000, partial: false, at: Some(1), report: Report::Fresh }), ..Default::default() };
        assert_eq!(full_text("Starter", &there, 5_000_000_000), "Storage is full: 5.2 GB used of the Starter plan's 5 GB, so I didn't run. Delete files on the computer I work on, or move to a bigger plan, then ask again.");
        assert!(refusal_text("Starter", &there, 5_000_000_000).contains("Delete files on the computer this Bot works on, or move to a bigger plan"));
    }

    #[test]
    fn a_machines_report_counts_however_old_and_none_is_a_lower_bound() {
        let db = crate::db::Db::open(&crate::db::temp_path("storage-report").join("app.sqlite")).unwrap();
        let u = db.create_user(None, Some("ada@example.com"), "Ada", crate::rbac::Role::Member).unwrap();
        let new = crate::db::NewMachine { user_id: &u.id, provider: "fake", label_prefix: "superbot", tier: "small", plan: "p", region: "r", created_by: None };
        let mut m = db.add_machine(&new).unwrap();
        m.state = crate::machines::State::Running;
        let now = 100 * 60_000;
        assert_eq!(on_machine(&m, now), OnMachine { bytes: 0, partial: false, at: None, report: Report::Missing });
        m.disk_files = Some(3_000_000);
        m.disk_files_at = Some(now - 60_000);
        assert_eq!(on_machine(&m, now).report, Report::Fresh);
        m.disk_files_at = Some(now - 16 * 60_000);
        assert_eq!(on_machine(&m, now), OnMachine { bytes: 3_000_000, partial: false, at: Some(now - 16 * 60_000), report: Report::Stale });
        // Suspended: what it said just before still holds, since its disk can't change.
        m.state = crate::machines::State::Suspended;
        m.suspended_at = Some(now - 16 * 60_000 + 1);
        assert_eq!(on_machine(&m, now).report, Report::Fresh);

        // Every byte counts, old or not; none said yet is nothing, as a lower bound.
        let with = |on: OnMachine| Measured { files: 0, data: 1_000, machine: Some(on), ..Default::default() };
        let stale = with(OnMachine { bytes: 3_000_000, partial: false, at: Some(1), report: Report::Stale });
        assert_eq!((stale.used(), stale.lower_bound()), (3_001_000, false));
        let missing = with(OnMachine { bytes: 0, partial: false, at: None, report: Report::Missing });
        assert_eq!((missing.used(), missing.lower_bound()), (1_000, true));
        let partial = with(OnMachine { bytes: 5, partial: true, at: Some(1), report: Report::Fresh });
        assert!(partial.lower_bound());
        let d = details(&stale, json!({}));
        assert_eq!((d["used"].as_u64(), d["partial"].as_bool(), d["machine"]["report"].as_str(), d["machine"]["used"].as_u64()), (Some(3_001_000), Some(false), Some("stale"), Some(3_000_000)), "{d}");
        assert!(details(&Measured::default(), json!({ "limit": 1 })).get("machine").is_none());
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

}
