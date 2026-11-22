//! Retention for harness session files and teammates' archived work (ADR 0112), run by the
//! retention pass (`retention::start`) beside chat retention.
//!
//! `HARNESS_SESSION_RETENTION_DAYS` deletes harness sessions nothing has changed for that
//! long: Claude Code's and Codex's in the HOME their runs use, Pi's in each Bot's folder
//! (each adapter's `sessions`), and Hermes Agent's from its database (`prune_sessions`). It
//! sweeps botd's own HOME and Bot folders, each per-user account's (as the account, through
//! `superbot-run --sweep`), and each user's machine (`/v1/retention`, as its agent). A HOME
//! where a held Bot runs isn't swept at all, nor a held Bot's own folder, and a Bot's
//! harness is told to keep its own sessions there. Each Bot it sweeps for is kept from
//! starting a run until the sweep is done; a running Bot's session stays.
//!
//! `TEAMMATE_FILES_RETENTION_DAYS` deletes a leaving teammate's work archived to their
//! owner's `from-teammates/` folder (ADR 0052, 0066) that long after it was moved there,
//! unless one of the owner's Bots is held.

use crate::accounts::Space;
use crate::adapters;
use crate::audit::{Actor, Event, Outcome};
use crate::db::{Bot, Machine};
use crate::machines::wire::{self, JobEvent, RetentionRequest, SessionDir};
use crate::obs::log::log_warn;
use crate::runner::App;
use crate::sweep::{Folder, Root, Sweep, Swept};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const SESSIONS_KEY: &str = "harness_session_retention_days";
pub const FILES_KEY: &str = "teammate_files_retention_days";
pub const SESSIONS_LAST: &str = "harness_sessions_last_pass";
pub const FILES_LAST: &str = "teammate_files_last_pass";
const DAY_MS: i64 = 86_400_000;
/// Longest a Hermes prune may take.
const PRUNE_SECS: u64 = 300;

/// Every harness's session folders, under a HOME and under a Bot's folder.
fn session_dirs() -> (Vec<SessionDir>, Vec<SessionDir>) {
    let (mut home, mut state) = (Vec::new(), Vec::new());
    for name in adapters::NAMES {
        let Some(a) = adapters::get(name) else { continue };
        let s = a.sessions();
        for (list, dirs) in [(&mut home, s.home), (&mut state, s.state)] {
            for (path, depth) in dirs {
                if !list.iter().any(|d: &SessionDir| d.path == *path) {
                    list.push(SessionDir { path: path.to_string(), depth: *depth });
                }
            }
        }
    }
    (home, state)
}

/// How long the harness of a run of `bot` should keep its own old sessions (`RunInput::
/// keep_sessions_days`): forever while a Bot sharing its HOME is held, else the retention.
/// Its HOME is shared by the owner's Bots on a machine or in a per-user account, and by
/// every Bot on this server otherwise.
pub fn keep_sessions_days(app: &App, bot: &Bot, on_machine: bool, isolated: bool) -> Option<u32> {
    let held = app.db.retention_holds().iter().any(|h| (!on_machine && !isolated) || app.db.bot_owner(&h.bot_id).as_deref() == Some(bot.owner_id.as_str()));
    if held { Some(crate::retention::MAX_DAYS) } else { app.db.retention_days(SESSIONS_KEY) }
}

/// What a pass found about the Bots it sweeps for.
struct Bots {
    all: Vec<Bot>,
    held: HashSet<String>,
    /// Running: their files stay where they are, their saved session whatever its age.
    busy: HashSet<String>,
}

impl Bots {
    fn of<'a>(&'a self, owner: Option<&'a str>) -> impl Iterator<Item = &'a Bot> + 'a {
        self.all.iter().filter(move |b| owner.is_none_or(|o| b.owner_id == o))
    }

    fn idle(&self, b: &Bot) -> bool {
        !self.held.contains(&b.id) && !self.busy.contains(&b.id)
    }

    /// Of `owner`'s Bots (everyone's if None): whether one is held, the saved sessions of
    /// those running, which stay, and those of the rest, to say whether they went.
    fn sessions(&self, owner: Option<&str>) -> (bool, Vec<String>, Vec<String>) {
        let (mut keep, mut report) = (Vec::new(), Vec::new());
        for b in self.of(owner) {
            let list = if self.idle(b) { &mut report } else { &mut keep };
            list.extend(b.session_id.clone());
        }
        (self.of(owner).any(|b| self.held.contains(&b.id)), keep, report)
    }

    /// The sweep of a HOME and the folders of `owner`'s Bots (everyone's if None) in it,
    /// `state(bot)` for each idle one. `own`: their saved sessions live here. Also whether
    /// the HOME was left alone for a hold.
    fn sweep(&self, before: i64, owner: Option<&str>, home: Option<&Path>, state: impl Fn(&Bot) -> Option<PathBuf>, own: bool) -> (Sweep, bool) {
        let (home_dirs, state_dirs) = session_dirs();
        let (held, keep, report) = self.sessions(owner);
        let mut s = Sweep { before, ..Default::default() };
        if own {
            (s.keep, s.report) = (keep, report);
        }
        if let Some(h) = home.filter(|_| !held) {
            s.roots.extend(home_dirs.iter().map(|d| Root { base: h.display().to_string(), path: d.path.clone(), depth: d.depth }));
        }
        for dir in self.of(owner).filter(|b| self.idle(b)).filter_map(state) {
            s.roots.extend(state_dirs.iter().map(|d| Root { base: dir.display().to_string(), path: d.path.clone(), depth: d.depth }));
        }
        (s, held && home.is_some())
    }
}

/// What one pass did, in total.
#[derive(Default)]
struct Tally {
    swept: Swept,
    places: u32,
    /// HOMEs left alone because a Bot running there is held.
    held_homes: u32,
    hermes: u32,
    errors: Vec<String>,
}

impl Tally {
    fn error(&mut self, e: String) {
        if self.errors.len() < 10 {
            self.errors.push(e);
        }
    }
}

/// One pass of harness session retention. Returns what it saved as the last pass.
pub async fn prune_sessions(app: &Arc<App>, days: u32, at: i64) -> Value {
    let before = at - i64::from(days) * DAY_MS;
    let all = app.db.bots();
    let held: HashSet<String> = app.db.retention_holds().into_iter().map(|h| h.bot_id).collect();
    let mut guards = Vec::new();
    let mut busy = HashSet::new();
    for b in &all {
        match app.sweeping_session_files(&b.id) {
            Some(g) => guards.push(g),
            None => {
                busy.insert(b.id.clone());
            }
        }
    }
    let bots = Bots { all, held, busy };
    let mut t = Tally::default();

    // botd's own HOME and Bot folders, which every Bot here used without per-user accounts.
    let (s, skipped) = bots.sweep(before, None, app.cfg.home.as_deref(), |b| app.bot_dir(&b.id), app.isolation().is_none());
    t.held_homes += u32::from(skipped);
    match tokio::task::spawn_blocking(move || crate::sweep::run(&s)).await {
        Ok(out) => add(&mut t, "this server", Ok(out)),
        Err(e) => t.error(format!("this server: {e}")),
    }

    // Each per-user account's, as the account (ADR 0037, 0064).
    if let Some(iso) = app.isolation() {
        let mut spaces: Vec<(String, Option<String>)> = Vec::new();
        for b in &bots.all {
            if !spaces.iter().any(|(o, t)| *o == b.owner_id && t.is_none()) {
                spaces.push((b.owner_id.clone(), None));
            }
        }
        spaces.extend(iso.teammate_pairs().into_iter().map(|(o, t)| (o, Some(t))));
        for (owner, teammate) in spaces {
            let space = Space::of(&owner, teammate.as_deref());
            let (Some(run_as), Some(home)) = (iso.run_as_in(space), iso.home_in(space)) else { continue };
            if !iso.ready_in(space) {
                continue;
            }
            let (s, skipped) = bots.sweep(before, Some(&owner), Some(&home), |b| iso.bot_state_in(space, &b.id), teammate.is_none());
            t.held_homes += u32::from(skipped);
            let what = format!("{}'s account", run_as.account);
            match tokio::task::spawn_blocking(move || run_as.sweep(&home, &s)).await {
                Ok(r) => add(&mut t, &what, r),
                Err(e) => t.error(format!("{what}: {e}")),
            }
        }
    }

    // Each user's machine, by its agent (ADR 0036).
    for m in sweepable_machines(app) {
        let (held, keep, report) = bots.sessions(Some(&m.user_id));
        t.held_homes += u32::from(held);
        let (home, state) = session_dirs();
        let req = RetentionRequest {
            owner_id: m.user_id.clone(),
            before,
            home: if held { Vec::new() } else { home },
            bots: bots.of(Some(&m.user_id)).filter(|b| bots.idle(b)).map(|b| b.id.clone()).collect(),
            state,
            keep,
            report,
            archives: Vec::new(),
        };
        let what = format!("machine {}", m.id);
        add(&mut t, &what, ask_machine(app, &m, &req).await);
    }

    // Hermes Agent keeps its sessions in a database, which only it may change.
    for b in bots.all.iter().filter(|b| bots.idle(b)) {
        if let Some(a) = adapters::get(&b.harness).filter(|a| a.prune_sessions(Path::new("/"), days, None).is_some()) {
            match prune_db(app, a.as_ref(), b, days).await {
                Ok(true) => t.hermes += 1,
                Ok(false) => {}
                Err(e) => t.error(format!("{} for Bot {}: {e}", b.harness, b.id)),
            }
        }
    }

    // A Bot whose saved session went starts a new one next time.
    let mut forgotten = 0u32;
    for b in bots.all.iter().filter(|b| bots.idle(b)) {
        if let Some(s) = b.session_id.as_ref().filter(|s| t.swept.gone.contains(s)) {
            forgotten += u32::from(app.db.forget_session_if(&b.id, s));
        }
    }
    drop(guards);

    let failed = !t.errors.is_empty() || !t.swept.errors.is_empty();
    let mut errors = t.errors.clone();
    errors.extend(t.swept.errors.iter().cloned());
    errors.truncate(10);
    let pass = json!({
        "at": at,
        "olderThan": before,
        "retentionDays": days,
        "sessions": t.swept.sessions,
        "files": t.swept.files,
        "bytes": t.swept.bytes,
        "hermesBots": t.hermes,
        "places": t.places,
        "sessionsForgotten": forgotten,
        "heldBots": bots.held.len(),
        "heldHomes": t.held_homes,
        "busyBots": bots.busy.len(),
        "partial": t.swept.partial,
        "errors": errors,
    });
    finish(app, SESSIONS_LAST, "harness_sessions.pruned", &pass, failed, t.swept.files > 0 || t.hermes > 0);
    pass
}

fn add(t: &mut Tally, what: &str, r: Result<Swept, String>) {
    match r {
        Ok(out) => {
            t.places += 1;
            t.swept.add(out);
        }
        Err(e) => t.error(format!("{what}: {e}")),
    }
}

/// Saves the pass and records it when it deleted something or failed.
fn finish(app: &App, key: &str, action: &str, pass: &Value, failed: bool, deleted: bool) {
    if let Err(e) = app.db.try_set_setting(key, &pass.to_string()) {
        log_warn!("{action}: couldn't save the last pass: {e}");
    }
    let event = Event::new(Actor::system("retention"), action).details(pass.clone());
    if failed {
        log_warn!("{action}: {}", pass["errors"]);
        app.db.record(&event.outcome(Outcome::Failure));
    } else if deleted {
        app.db.record(&event);
    }
}

/// Machines whose agent can sweep now: running, enrolled, and new enough.
fn sweepable_machines(app: &App) -> Vec<Machine> {
    if app.control_plane.get().and_then(|cp| cp.enrollment.as_ref()).is_none() {
        return Vec::new();
    }
    let can = |m: &Machine| m.agent_upkeep.as_ref().and_then(|v| v["can"].as_array()).is_some_and(|c| c.iter().any(|c| c == wire::CAN_RETENTION));
    app.db.machines(None).into_iter().filter(|m| crate::machines::offboard::reachable(m).is_ok() && can(m)).collect()
}

async fn ask_machine(app: &App, m: &Machine, req: &RetentionRequest) -> Result<Swept, String> {
    let e = app.control_plane.get().and_then(|cp| cp.enrollment.clone()).ok_or("machine enrollment is off")?;
    let v = crate::machines::offboard::ask(app, &e, m, "/v1/retention", req).await?;
    serde_json::from_value(v).map_err(|e| format!("its agent's answer didn't parse: {e}"))
}

/// Has the Bot's harness delete its own sessions unused for `days`, where the Bot runs.
/// Whether it did.
async fn prune_db(app: &App, a: &dyn adapters::Adapter, b: &Bot, days: u32) -> Result<bool, String> {
    use crate::machines::route::Target;
    let path = std::env::var("PATH").ok();
    let target = match app.control_plane.get() {
        Some(cp) => cp.route(&app.db, &b.owner_id).map_err(|_| "its owner's machine isn't ready".to_string())?,
        None => Target::Local,
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let (_stop, abort) = tokio::sync::watch::channel(None);
    let run = async move {
        let r: Result<bool, String> = match &target {
            Target::Local => {
                let iso = app.isolation();
                let space = Space::User(&b.owner_id);
                let state = match iso {
                    Some(i) => i.bot_state_in(space, &b.id),
                    None => app.bot_dir(&b.id).filter(|d| d.join("hermes").is_dir()),
                };
                let Some(state) = state else { return Ok(false) };
                if !adapters::installed().contains(&a.bin()) {
                    return Ok(false);
                }
                let Some(mut job) = a.prune_sessions(&state, days, path.as_deref()) else { return Ok(false) };
                if let Some(r) = iso.and_then(|i| i.ready_in(space).then(|| i.run_as_in(space)).flatten()) {
                    job = r.prepare(job)?;
                } else if iso.is_some() {
                    return Ok(false);
                }
                let stop = async { tokio::time::sleep(std::time::Duration::from_secs(PRUNE_SECS)).await };
                crate::machines::job::run(&adapters::local_host(), &job, stop, &tx).await;
                Ok(true)
            }
            Target::Machine(to) => {
                let cp = app.control_plane.get().ok_or("no control plane")?;
                let hb = cp.link.check(app, to, &[a.bin()]).await?;
                let Some(layout) = hb.layout.filter(|_| !hb.missing.iter().any(|m| m == a.bin())) else { return Ok(false) };
                let state = Path::new(&layout.bots).join(&b.id);
                let Some(mut job) = a.prune_sessions(&state, days, None) else { return Ok(false) };
                job.job_id = format!("j{}", crate::random_hex(8));
                job.bot_id = b.id.clone();
                job.owner_id = b.owner_id.clone();
                let stopper = tokio::spawn({
                    let stop = _stop.clone();
                    async move {
                        tokio::time::sleep(std::time::Duration::from_secs(PRUNE_SECS)).await;
                        let _ = stop.send(Some("timeout"));
                    }
                });
                cp.link.run(to, job, abort.clone(), tx.clone()).await;
                stopper.abort();
                Ok(true)
            }
        };
        r
    };
    let collect = async {
        let mut result: Result<(), String> = Err("it didn't finish".into());
        while let Some(ev) = rx.recv().await {
            match ev {
                JobEvent::Exit { success: true, .. } => result = Ok(()),
                JobEvent::Exit { status, stderr, .. } => result = Err(format!("{} exited with {status}: {}", a.bin(), stderr.trim())),
                JobEvent::Error { message } => result = Err(message),
                JobEvent::Cleanup { why } => result = Err(why),
                _ => {}
            }
        }
        result
    };
    let (ran, result) = tokio::join!(run, collect);
    match ran? {
        true => result.map(|()| true),
        false => Ok(false),
    }
}

/// One pass of teammates' archived work retention. Returns what it saved as the last pass.
pub async fn prune_teammate_files(app: &Arc<App>, days: u32, at: i64) -> Value {
    let before = at - i64::from(days) * DAY_MS;
    let held: HashSet<String> = app.db.retention_holds().into_iter().filter_map(|h| app.db.bot_owner(&h.bot_id)).collect();
    let (mut deleted, mut missing, mut held_n, mut waiting, mut unknown, mut files, mut bytes) = (0u32, 0u32, 0u32, 0u32, 0u32, 0u64, 0u64);
    let mut errors: Vec<String> = Vec::new();
    for (table, id, owner, machine, archived_to) in app.db.archives_before(before) {
        if held.contains(&owner) {
            held_n += 1;
            continue;
        }
        // A removal that couldn't name its archive said only the folder it went into.
        let Some(name) = archive_name(&archived_to) else {
            unknown += 1;
            continue;
        };
        let r = match &machine {
            Some(machine_id) => match app.db.machine(machine_id) {
                Some(m) if m.user_id == owner && crate::machines::offboard::live(&m) => {
                    if crate::machines::offboard::reachable(&m).is_err() || !sweepable_machines(app).iter().any(|s| s.id == m.id) {
                        waiting += 1;
                        continue;
                    }
                    let req = RetentionRequest { owner_id: owner.clone(), before, archives: vec![name], ..Default::default() };
                    ask_machine(app, &m, &req).await
                }
                // The machine went, and its files with it.
                _ => Ok(Swept { missing: 1, ..Default::default() }),
            },
            None => match app.isolation() {
                Some(iso) => {
                    let space = Space::User(&owner);
                    match (iso.run_as_in(space), iso.home_in(space), iso.workspace_in(space)) {
                        (Some(run_as), Some(home), Some(ws)) if iso.ready_in(space) => {
                            let s = Sweep { folders: vec![Folder { base: ws.display().to_string(), path: format!("{}/{name}", wire::TEAMMATE_ARCHIVE_DIR) }], ..Default::default() };
                            tokio::task::spawn_blocking(move || run_as.sweep(&home, &s)).await.unwrap_or_else(|e| Err(e.to_string()))
                        }
                        // No account any more: nothing of theirs is left on this server.
                        _ if !iso.ready_in(space) => Ok(Swept { missing: 1, ..Default::default() }),
                        _ => Err("the owner's folders aren't known".into()),
                    }
                }
                None => Ok(Swept { missing: 1, ..Default::default() }),
            },
        };
        match r {
            Ok(out) if out.errors.is_empty() && out.folders + out.missing > 0 => {
                deleted += out.folders as u32;
                missing += out.missing as u32;
                files += out.files;
                bytes += out.bytes;
                app.db.archive_pruned(table, &id);
            }
            Ok(out) => errors.push(format!("{id}: {}", out.errors.join("; "))),
            Err(e) => errors.push(format!("{id}: {e}")),
        }
    }
    errors.truncate(10);
    let pass = json!({
        "at": at,
        "olderThan": before,
        "retentionDays": days,
        "deleted": deleted,
        "missing": missing,
        "files": files,
        "bytes": bytes,
        "held": held_n,
        "waiting": waiting,
        "unknown": unknown,
        "errors": errors,
    });
    finish(app, FILES_LAST, "teammate_files.pruned", &pass, !errors.is_empty(), deleted + missing > 0);
    pass
}

/// The archive's folder name, from where the removal said it put it.
fn archive_name(archived_to: &str) -> Option<String> {
    let p = Path::new(archived_to.trim_end_matches('/'));
    let name = p.file_name()?.to_str()?;
    let in_archive = p.parent().and_then(Path::file_name).is_some_and(|d| d == wire::TEAMMATE_ARCHIVE_DIR);
    (in_archive && !name.starts_with('.') && !name.contains(['/', '\\'])).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_names() {
        assert_eq!(archive_name("/home/superbot/work/from-teammates/bea-2026-01-02").as_deref(), Some("bea-2026-01-02"));
        assert_eq!(archive_name("/srv/users/u1/workspace/from-teammates/bea-2026-01-02-2/").as_deref(), Some("bea-2026-01-02-2"));
        for bad in ["/home/superbot/work/bea", "from-teammates", "/x/from-teammates/..", "/x/from-teammates/.hidden"] {
            assert_eq!(archive_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn every_harness_says_where_its_sessions_are() {
        let (home, state) = session_dirs();
        let paths: Vec<&str> = home.iter().chain(&state).map(|d| d.path.as_str()).collect();
        for p in [".claude/projects", ".codex/sessions", ".codex/archived_sessions", "pi-sessions"] {
            assert!(paths.contains(&p), "{p}: {paths:?}");
        }
        assert!(home.iter().chain(&state).all(|d| wire::home_path(&d.path) && (1..=8).contains(&d.depth)));
    }
}
