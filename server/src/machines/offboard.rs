//! Removing teammates' users from machines when they leave (ADR 0052), botd's side.
//! A teammate keeps their own user on a machine (ADR 0048) only while they're active
//! and can still run one of its owner's Bots. When that stops (disabled, deprovisioned
//! by SCIM, or the Bots taken from them: a grant revoked, a Bot made private, given
//! away or deleted), botd queues a removal for that machine and asks its agent at once
//! to stop the teammate's jobs, screens and processes, take their work folder aside,
//! and delete their home and user (`POST /v1/teammates/{user}/remove`). An agent that
//! doesn't answer is asked again after every round of heartbeats until it does; one
//! that answers is done, and asking again changes nothing. Heartbeats also say which
//! teammates have a user there, so ones made before this, or missed, are found too.
//! Their work goes to the owner's workspace (`MACHINE_TEAMMATE_FILES=archive`, the
//! default), or is held aside and deleted after `MACHINE_TEAMMATE_FILES_DAYS`
//! (`delete`). The machine's own user and other teammates are never touched. Every
//! step is audited.

use super::enroll::{self, Enrollment};
use super::wire::{self, TeammatePurge, TeammatePurged, TeammateRemoval, TeammateRemoved};
use super::{State, event, system};
use crate::acl::{Access, Viewer};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, NewTeammateCleanup, TeammateCleanup, now};
use crate::runner::App;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Res, bad};
use axum::Json;
use axum::extract::{Extension, Path, Query, State as AppS};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

pub const DISABLED: &str = "disabled";
pub const DEPROVISIONED: &str = "deprovisioned";
pub const DELETED: &str = "deleted";
pub const ACCESS_LOST: &str = "access_lost";
/// An admin asked, whether or not the teammate still has access.
pub const ADMIN: &str = "admin";

const PENDING: &str = "pending";
const HELD: &str = "held";
const DONE: &str = "done";
const CANCELLED: &str = "cancelled";
const DAY_MS: i64 = 86_400_000;
/// A removal waits this long at most for the agent: it stops processes and deletes a
/// home, which can be large.
const REMOVE_SECS: u64 = 300;

/// What becomes of a leaving teammate's work folder on the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Files {
    /// Moved to the owner's workspace, `work/from-teammates/<name>-<date>`.
    Archive,
    /// Held aside, root's alone, then deleted after `grace_days` (at once with 0).
    Delete,
}

impl Files {
    pub fn as_str(self) -> &'static str {
        match self {
            Files::Archive => wire::TEAMMATE_FILES_ARCHIVE,
            Files::Delete => wire::TEAMMATE_FILES_DELETE,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub files: Files,
    pub grace_days: u32,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { files: Files::Archive, grace_days: 7 }
    }
}

impl Settings {
    /// MACHINE_TEAMMATE_FILES (`archive`, the default, or `delete`) and
    /// MACHINE_TEAMMATE_FILES_DAYS (0 to 365, default 7; only with `delete`).
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Settings, String> {
        let files = match var("MACHINE_TEAMMATE_FILES").trim() {
            "" | "archive" => Files::Archive,
            "delete" => Files::Delete,
            v => return Err(format!("MACHINE_TEAMMATE_FILES must be archive or delete, not \"{v}\"")),
        };
        let grace_days = match var("MACHINE_TEAMMATE_FILES_DAYS").trim() {
            "" => 7,
            d => d
                .parse::<u32>()
                .ok()
                .filter(|d| *d <= 365)
                .ok_or(format!("MACHINE_TEAMMATE_FILES_DAYS must be 0 to 365, not \"{d}\""))?,
        };
        if files == Files::Archive && !var("MACHINE_TEAMMATE_FILES_DAYS").trim().is_empty() {
            return Err("MACHINE_TEAMMATE_FILES_DAYS needs MACHINE_TEAMMATE_FILES=delete: archived work is kept".into());
        }
        Ok(Settings { files, grace_days })
    }

    pub fn describe(&self) -> String {
        match (self.files, self.grace_days) {
            (Files::Archive, _) => "leaving teammates' work archived to the owner".into(),
            (Files::Delete, 0) => "leaving teammates' work deleted".into(),
            (Files::Delete, d) => format!("leaving teammates' work deleted after {d} days"),
        }
    }
}

/// Removals tried at once, across machines: each can wait minutes on its agent.
const AT_ONCE: usize = 4;

/// Removals being tried now, by id, so an event and the reconciler never send one twice
/// at once; and whether a background pass is running, or wanted again after it.
#[derive(Default)]
pub struct Working {
    taken: Mutex<HashSet<String>>,
    running: AtomicBool,
    again: AtomicBool,
}

struct Taken<'a>(&'a Working, String);

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        self.0.lock().remove(&self.1);
    }
}

impl Working {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.taken.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn take(&self, id: &str) -> Option<Taken<'_>> {
        self.lock().insert(id.to_string()).then(|| Taken(self, id.to_string()))
    }
}

fn enrollment(app: &App) -> Option<&std::sync::Arc<Enrollment>> {
    app.control_plane.get()?.enrollment.as_ref()
}

/// Whether `user_id` keeps their user on `owner_id`'s machine: they're active, aren't
/// its owner, and can still run one of the owner's Bots.
pub fn wanted(app: &App, owner_id: &str, user_id: &str) -> bool {
    if user_id == owner_id {
        return false;
    }
    let v = Viewer::person(&app.db, user_id);
    v != Viewer::Nobody && app.db.bots().iter().any(|b| b.owner_id == owner_id && v.access(&app.db, b) >= Access::Operate)
}

/// Why `user_id` no longer has a user on a machine, as best botd can tell.
fn reason_for(app: &App, user_id: &str) -> &'static str {
    match app.db.user(user_id) {
        None => DELETED,
        Some(u) if !u.active() => DISABLED,
        Some(_) => ACCESS_LOST,
    }
}

/// The teammates with a user on `m`: as its agent last said, and as botd made since.
fn known(m: &Machine) -> Vec<String> {
    m.agent_upkeep
        .as_ref()
        .and_then(|v| v["teammates"].as_array())
        .map(|a| a.iter().filter_map(|u| u.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// Changes the teammates `m`'s agent is known to have, until a heartbeat says.
fn edit_known(app: &App, machine_id: &str, f: impl Fn(&mut Vec<String>)) {
    for _ in 0..3 {
        let Some(m) = app.db.machine(machine_id) else { return };
        let mut list = known(&m);
        let before = list.clone();
        f(&mut list);
        if list == before {
            return;
        }
        let mut v = m.agent_upkeep.clone().unwrap_or_else(|| json!({}));
        v["teammates"] = json!(list);
        if app.db.machine_upkeep_swap(machine_id, m.agent_upkeep.as_ref(), &v) {
            return;
        }
    }
}

/// A teammate's user was just made on the machine: a leave before the next heartbeat
/// finds it.
pub fn seen(app: &App, machine_id: &str, user_id: &str) {
    edit_known(app, machine_id, |l| {
        if !l.iter().any(|u| u == user_id) {
            l.push(user_id.to_string());
        }
    });
}

fn live(m: &Machine) -> bool {
    !matches!(m.state, State::Destroying | State::Destroyed)
}

/// Queues `user_id`'s removal from `m`, unless one is pending; audited when new.
fn queue(app: &App, e: &Enrollment, by: &Who, m: &Machine, user_id: &str, reason: &str) -> Option<(TeammateCleanup, bool)> {
    let s = &e.offboard;
    let (row, made) = app.db.teammate_cleanup_queue(&NewTeammateCleanup {
        machine_id: &m.id,
        owner_id: &m.user_id,
        user_id,
        os_user: &wire::teammate_user(user_id),
        reason,
        files: s.files.as_str(),
        grace_days: if s.files == Files::Delete { s.grace_days as i64 } else { 0 },
        created_by: by.actor.id.as_deref(),
    })?;
    if made {
        app.db.record(&cleanup_event(by, "machine.teammate_removal_queued", m, &row, json!({})));
    }
    Some((row, made))
}

fn cleanup_event(by: &Who, action: &str, m: &Machine, row: &TeammateCleanup, extra: Value) -> crate::audit::Event {
    let mut d = json!({ "forUser": row.user_id, "user": row.os_user, "reason": row.reason, "files": row.files, "cleanupId": row.id });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
        d.extend(x);
    }
    event(by, action, m, d)
}

/// Queues removals on `m` for each teammate there who shouldn't keep a user, with
/// `reason` if `only` is them, else as botd can tell. How many it queued.
fn sweep(app: &App, e: &Enrollment, by: &Who, m: &Machine, only: Option<(&str, &str)>) -> usize {
    if !live(m) {
        return 0;
    }
    known(m)
        .iter()
        .filter(|u| only.is_none_or(|(o, _)| o == u.as_str()))
        .filter(|u| **u != m.user_id && !wanted(app, &m.user_id, u))
        .filter_map(|u| queue(app, e, by, m, u, only.map_or_else(|| reason_for(app, u), |(_, r)| r)))
        .filter(|(_, made)| *made)
        .count()
}

/// Tries what's pending now, in the background, so heartbeats never wait on a slow
/// agent. One pass runs at a time; a kick during it runs another after.
fn kick(app: &AppState) {
    let Some(e) = enrollment(app).cloned() else { return };
    e.offboarding.again.store(true, Ordering::SeqCst);
    if e.offboarding.running.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    tokio::spawn(async move {
        let w = &e.offboarding;
        loop {
            while w.again.swap(false, Ordering::SeqCst) {
                run(&app).await;
            }
            w.running.store(false, Ordering::SeqCst);
            if !w.again.load(Ordering::SeqCst) || w.running.swap(true, Ordering::SeqCst) {
                break;
            }
        }
    });
}

/// Waits until no background pass is running or wanted.
#[cfg(test)]
pub async fn settled(app: &App) {
    let Some(e) = enrollment(app) else { return };
    for _ in 0..3000 {
        if !e.offboarding.running.load(Ordering::SeqCst) && !e.offboarding.again.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("teammate removals never settled");
}

/// `user_id` was disabled, deprovisioned or lost their role: queue their removal from
/// every machine they have a user on, and try at once.
pub fn left(app: &AppState, by: &Who, user_id: &str, reason: &str) {
    let Some(e) = enrollment(app) else { return };
    let mut queued = 0;
    for m in app.db.machines(None) {
        queued += sweep(app, e, by, &m, Some((user_id, reason)));
    }
    if queued > 0 {
        kick(app);
    }
}

/// `owner_id`'s Bots may have been taken from someone (a grant revoked, a Bot made
/// private, given away or deleted): queue removals on their machine, and try at once.
pub fn check_owner(app: &AppState, by: &Who, owner_id: &str) {
    let Some(e) = enrollment(app) else { return };
    let Some(m) = app.db.user_machine(owner_id) else { return };
    if sweep(app, e, by, &m, None) > 0 {
        kick(app);
    }
}

/// After every round of heartbeats: queues removals for teammates heartbeats show who
/// shouldn't be there, then tries every pending one and purges held work that's due,
/// in the background.
pub fn follow_up(app: &AppState) {
    let Some(e) = enrollment(app) else { return };
    for m in app.db.machines(None) {
        sweep(app, e, &system(&m), &m, None);
    }
    let at = now();
    let held = app.db.teammate_cleanups(Some(HELD), None);
    if !app.db.teammate_cleanups(Some(PENDING), None).is_empty() || held.iter().any(|r| r.purge_at.is_some_and(|p| p <= at)) {
        kick(app);
    }
}

/// Tries every pending removal, and purges held work that's due, `AT_ONCE` at a time.
/// Counts what happened.
async fn run(app: &App) -> Value {
    use futures_util::StreamExt;
    let Some(e) = enrollment(app) else { return Value::Null };
    let tried: Vec<&str> = futures_util::stream::iter(app.db.teammate_cleanups(Some(PENDING), None))
        .map(|row| async move {
            let m = app.db.machine(&row.machine_id)?;
            Some(match try_removal(app, e, &system(&m), &row, false).await {
                Tried::Removed(_) => "removed",
                Tried::Failed(_) => "failed",
                Tried::Waiting(_) => "waiting",
                Tried::Cancelled => "cancelled",
                Tried::Busy => return None,
            })
        })
        .buffer_unordered(AT_ONCE)
        .filter_map(|k| async move { k })
        .collect()
        .await;
    let at = now();
    let due = app.db.teammate_cleanups(Some(HELD), None).into_iter().filter(|r| r.purge_at.is_some_and(|p| p <= at));
    let purged = futures_util::stream::iter(due)
        .map(|row| async move { purge(app, e, &row).await })
        .buffer_unordered(AT_ONCE)
        .filter(|done| std::future::ready(*done))
        .count()
        .await;
    let mut out = json!({ "removed": 0, "failed": 0, "waiting": 0, "cancelled": 0, "purged": purged });
    for k in tried {
        out[k] = json!(out[k].as_i64().unwrap_or(0) + 1);
    }
    out
}

enum Tried {
    Removed(Box<TeammateRemoved>),
    /// The agent was asked and didn't do it, or didn't answer.
    Failed(String),
    /// The machine isn't there to ask, or its agent can't do it yet.
    Waiting(String),
    Cancelled,
    /// Another call is trying it now.
    Busy,
}

/// The folder name archived work gets: the teammate's email name (or id) and the date.
fn archive_name(app: &App, user_id: &str) -> String {
    let who = app
        .db
        .user(user_id)
        .and_then(|u| u.email.as_deref().and_then(|e| e.split('@').next()).map(str::to_string))
        .unwrap_or_else(|| user_id.to_string());
    let mut name: String = who
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '-' })
        .take(40)
        .collect();
    name = name.trim_matches(|c| c == '.' || c == '-').to_string();
    if name.is_empty() {
        name = "teammate".into();
    }
    format!("{name}-{}", chrono::Utc::now().format("%Y-%m-%d"))
}

/// Records a failed or waiting attempt, auditing it only when the reason is new, so a
/// machine offline for a week leaves one failure in the log, not one a minute.
fn note(app: &App, by: &Who, m: &Machine, row: &TeammateCleanup, state: &str, why: &str, attempt: bool) {
    let changed = row.last_error.as_deref() != Some(why);
    if app.db.teammate_cleanup_failed(&row.id, state, why, attempt) && changed {
        let action = if state == HELD { "machine.teammate_files_purge_failed" } else { "machine.teammate_removal_failed" };
        let d = json!({ "error": why, "attempts": row.attempts + attempt as i64 });
        app.db.record(&cleanup_event(by, action, m, row, d).outcome(Outcome::Failure));
    }
}

fn cancel(app: &App, by: &Who, m: &Machine, row: &TeammateCleanup, why: &str) -> Tried {
    if app.db.teammate_cleanup_end(&row.id, PENDING, CANCELLED, Some(why)) {
        app.db.record(&cleanup_event(by, "machine.teammate_removal_cancelled", m, row, json!({ "why": why })));
    }
    Tried::Cancelled
}

/// Whether `m` is up and its agent enrolled, and what to say if not.
fn reachable(m: &Machine) -> Result<(), String> {
    if m.state != State::Running {
        return Err(format!("waiting for the machine: it is {}", m.state.as_str()));
    }
    if m.enrollment != "enrolled" {
        return Err("waiting for the machine: its agent isn't enrolled".into());
    }
    Ok(())
}

fn can_remove(m: &Machine) -> bool {
    m.agent_upkeep
        .as_ref()
        .and_then(|v| v["can"].as_array())
        .is_some_and(|c| c.iter().any(|c| c == wire::CAN_TEAMMATE_REMOVAL))
}

/// Asks the agent to remove one teammate, unless they're wanted there again and it
/// isn't `forced` by an admin.
async fn try_removal(app: &App, e: &Enrollment, by: &Who, row: &TeammateCleanup, forced: bool) -> Tried {
    let Some(_taken) = e.offboarding.take(&row.id) else { return Tried::Busy };
    let Some(row) = app.db.teammate_cleanup(&row.id).filter(|r| r.state == PENDING) else { return Tried::Busy };
    let Some(m) = app.db.machine(&row.machine_id) else { return Tried::Busy };
    if !live(&m) || m.user_id != row.owner_id {
        return cancel(app, by, &m, &row, "machine_gone");
    }
    // Once the agent has been asked, it may have done some of it (the user deleted, the
    // work not yet moved): finish rather than leave it half done. A later run makes the
    // teammate a new user.
    // The update checks again, so an admin's ask that lands meanwhile still stands.
    if !forced && row.reason != ADMIN && row.attempts == 0 && wanted(app, &row.owner_id, &row.user_id) {
        let why = "access_back";
        if app.db.teammate_cleanup_cancel_unasked(&row.id, why) {
            app.db.record(&cleanup_event(by, "machine.teammate_removal_cancelled", &m, &row, json!({ "why": why })));
            return Tried::Cancelled;
        }
        return Tried::Busy;
    }
    if let Err(why) = reachable(&m) {
        note(app, by, &m, &row, PENDING, &why, false);
        return Tried::Waiting(why);
    }
    if !can_remove(&m) {
        let why = "its agent can't remove teammates' users (it is older than ADR 0052); upgrade it".to_string();
        note(app, by, &m, &row, PENDING, &why, false);
        return Tried::Waiting(why);
    }
    super::screens::close_for(app, by, &m.id, &row.user_id, "teammate_left").await;
    let delete = row.files == wire::TEAMMATE_FILES_DELETE;
    let body = TeammateRemoval {
        owner_id: m.user_id.clone(),
        cleanup_id: row.id.clone(),
        files: row.files.clone(),
        archive_name: (!delete).then(|| archive_name(app, &row.user_id)),
        hold: delete && row.grace_days > 0,
    };
    match ask(app, e, &m, &format!("/v1/teammates/{}/remove", row.user_id), &body).await {
        Ok(v) => match serde_json::from_value::<TeammateRemoved>(v) {
            Ok(r) => {
                let purge_at = (r.files == "held").then(|| now() + row.grace_days * DAY_MS);
                if app.db.teammate_cleanup_removed(&row.id, r.archived_to.as_deref(), purge_at) {
                    edit_known(app, &m.id, |l| l.retain(|u| u != &row.user_id));
                    let d = json!({
                        "alreadyGone": r.already_gone, "userRemoved": r.user_removed, "jobsStopped": r.jobs_stopped,
                        "screensStopped": r.screens_stopped, "processesStopped": r.processes_stopped, "tempRemoved": r.temp_removed,
                        "work": r.files, "archivedTo": r.archived_to, "purgeAt": purge_at, "attempts": row.attempts + 1,
                    });
                    app.db.record(&cleanup_event(by, "machine.teammate_removed", &m, &row, d));
                }
                Tried::Removed(Box::new(r))
            }
            Err(err) => {
                let why = format!("its agent's answer didn't parse: {err}");
                note(app, by, &m, &row, PENDING, &why, true);
                Tried::Failed(why)
            }
        },
        Err(why) => {
            note(app, by, &m, &row, PENDING, &why, true);
            Tried::Failed(why)
        }
    }
}

/// Deletes the work a removal held, once its days are up. Whether it's done.
async fn purge(app: &App, e: &Enrollment, row: &TeammateCleanup) -> bool {
    let Some(_taken) = e.offboarding.take(&row.id) else { return false };
    let Some(m) = app.db.machine(&row.machine_id) else { return false };
    let by = system(&m);
    if !live(&m) {
        if app.db.teammate_cleanup_end(&row.id, HELD, DONE, Some("machine_gone")) {
            app.db.record(&cleanup_event(&by, "machine.teammate_files_purged", &m, row, json!({ "purged": false, "why": "machine_gone" })));
        }
        return true;
    }
    if let Err(why) = reachable(&m) {
        note(app, &by, &m, row, HELD, &why, false);
        return false;
    }
    let body = TeammatePurge { owner_id: m.user_id.clone(), cleanup_id: row.id.clone() };
    match ask(app, e, &m, &format!("/v1/teammates/{}/purge", row.user_id), &body).await {
        Ok(v) => {
            let purged = serde_json::from_value::<TeammatePurged>(v).is_ok_and(|p| p.purged);
            if app.db.teammate_cleanup_end(&row.id, HELD, DONE, None) {
                app.db.record(&cleanup_event(&by, "machine.teammate_files_purged", &m, row, json!({ "purged": purged })));
            }
            true
        }
        Err(why) => {
            note(app, &by, &m, row, HELD, &why, true);
            false
        }
    }
}

/// POSTs `body` to the machine's agent, pinned to its certificates. Its JSON answer, or
/// why it didn't do it.
async fn ask<T: serde::Serialize>(app: &App, e: &Enrollment, m: &Machine, path: &str, body: &T) -> Result<Value, String> {
    let pins = app.db.machine_pins(&m.id);
    if pins.is_empty() {
        return Err("it has no usable certificate".into());
    }
    let address = m.ipv4.as_deref().ok_or("it has no address yet")?;
    let client = e.upload_client(pins, REMOVE_SECS)?;
    let mut r = client
        .post(e.agent_url(address, path))
        .json(body)
        .send()
        .await
        .map_err(|err| format!("its agent didn't answer: {}", enroll::without_url(err)))?;
    let code = r.status();
    let reply: Value = enroll::read_capped(&mut r, 64 << 10).await.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
    if code.is_success() {
        return Ok(reply);
    }
    Err(match reply["error"].as_str() {
        Some(said) => format!("its agent answered {}: {said}", code.as_u16()),
        None => format!("its agent answered {}", code.as_u16()),
    })
}

// Admin API: `/api/machines/teammate-removals` and `/api/users/{key}/machine/teammates`
// (admin only, rbac::classify).

fn view(app: &App, r: &TeammateCleanup) -> Value {
    let person = |id: &str| app.db.user(id).map(|u| json!({ "id": u.id, "name": u.name, "email": u.email })).unwrap_or(json!({ "id": id }));
    let mut v = serde_json::to_value(r).unwrap_or_default();
    v["teammate"] = person(&r.user_id);
    v["owner"] = person(&r.owner_id);
    v
}

fn need_enrollment(app: &App) -> Res<&std::sync::Arc<Enrollment>> {
    let cp = app.control_plane.get().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, super::NOT_CONFIGURED.into()))?;
    enroll::need(cp)
}

#[derive(serde::Deserialize)]
pub struct ListQuery {
    state: Option<String>,
}

/// `GET /api/machines/teammate-removals[?state=pending|held|done|cancelled|open]`: every
/// removal, newest first; `open` is pending and held. Also how many are open on each
/// machine.
pub async fn list_all(AppS(app): AppS<AppState>, Query(q): Query<ListQuery>) -> Res {
    let e = need_enrollment(&app)?;
    let all = app.db.teammate_cleanups(None, None);
    let rows: Vec<&TeammateCleanup> = match q.state.as_deref() {
        None | Some("") | Some("all") => all.iter().collect(),
        Some("open") => all.iter().filter(|r| r.state == PENDING || r.state == HELD).collect(),
        Some(s @ (PENDING | HELD | DONE | CANCELLED)) => all.iter().filter(|r| r.state == s).collect(),
        Some(s) => return Err(bad(format!("state must be pending, held, done, cancelled, open or all, not \"{s}\""))),
    };
    let mut by_machine: std::collections::BTreeMap<&str, Value> = std::collections::BTreeMap::new();
    for r in all.iter().filter(|r| r.state == PENDING || r.state == HELD) {
        let c = by_machine.entry(&r.machine_id).or_insert_with(|| json!({ "machineId": r.machine_id, "ownerId": r.owner_id, "pending": 0, "held": 0 }));
        c[r.state.as_str()] = json!(c[r.state.as_str()].as_i64().unwrap_or(0) + 1);
    }
    Ok(Json(json!({
        "files": e.offboard.files.as_str(),
        "graceDays": e.offboard.grace_days,
        "removals": rows.into_iter().map(|r| view(&app, r)).collect::<Vec<_>>(),
        "openByMachine": by_machine.into_values().collect::<Vec<_>>(),
    })))
}

/// `GET /api/users/{key}/machine/teammates`: the teammates with a user on the user's
/// machine, whether each still should, and the machine's removals.
pub async fn on_machine(AppS(app): AppS<AppState>, Path(key): Path<String>) -> Res {
    need_enrollment(&app)?;
    let u = need_user_key(&app, &key)?;
    let m = app.db.user_machine(&u.id).ok_or_else(|| crate::not_found("Machine"))?;
    let removals = app.db.teammate_cleanups(None, Some(&m.id));
    let teammates: Vec<Value> = known(&m)
        .iter()
        .map(|t| {
            let open = removals.iter().find(|r| &r.user_id == t && r.state == PENDING);
            let p = app.db.user(t);
            json!({
                "id": t, "name": p.as_ref().map(|p| &p.name), "email": p.as_ref().map(|p| &p.email),
                "user": wire::teammate_user(t), "wanted": wanted(&app, &m.user_id, t), "removal": open.map(|r| view(&app, r)),
            })
        })
        .collect();
    Ok(Json(json!({
        "machineId": m.id,
        "canRemove": can_remove(&m),
        "teammates": teammates,
        "removals": removals.iter().map(|r| view(&app, r)).collect::<Vec<_>>(),
    })))
}

/// `POST /api/users/{key}/machine/teammates/{teammate}/remove`: removes the teammate's
/// user from the machine now, even if they still have access (their next run there
/// makes a new one). 200 when done, 202 with why when it's still pending.
pub async fn remove_now(AppS(app): AppS<AppState>, Extension(by): Extension<Who>, Path((key, teammate)): Path<(String, String)>) -> Res<(StatusCode, Json<Value>)> {
    let e = need_enrollment(&app)?;
    let u = need_user_key(&app, &key)?;
    let m = app.db.user_machine(&u.id).ok_or_else(|| crate::not_found("Machine"))?;
    let t = app.db.find_user(&teammate).map_or(teammate.clone(), |t| t.id);
    if t == m.user_id {
        return Err(bad("That is the machine's own user, not a teammate."));
    }
    if t.is_empty() || t.len() > 64 || !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(bad("Name a teammate by id or email."));
    }
    let (row, _) = queue(&app, e, &by, &m, &t, ADMIN).ok_or_else(|| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Couldn't queue the removal.".into()))?;
    // A removal already waiting for another reason is the admin's from now on, so a
    // later pass never cancels it because the teammate is wanted again.
    if row.reason != ADMIN && app.db.teammate_cleanup_force(&row.id) {
        app.db.record(&cleanup_event(&by, "machine.teammate_removal_forced", &m, &row, json!({ "was": row.reason })));
    }
    let tried = try_removal(&app, e, &by, &row, true).await;
    let after = app.db.teammate_cleanup(&row.id).map(|r| view(&app, &r)).unwrap_or(Value::Null);
    Ok(match tried {
        Tried::Removed(r) => (StatusCode::OK, Json(json!({ "removal": after, "agent": *r }))),
        Tried::Failed(why) | Tried::Waiting(why) => (StatusCode::ACCEPTED, Json(json!({ "removal": after, "error": why }))),
        Tried::Cancelled | Tried::Busy => (StatusCode::ACCEPTED, Json(json!({ "removal": after }))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> String {
        move |k| pairs.iter().find(|(n, _)| *n == k).map_or(String::new(), |(_, v)| v.to_string())
    }

    #[test]
    fn work_is_archived_unless_asked_and_deleted_after_its_days() {
        assert_eq!(Settings::from_env(&with(&[])).unwrap(), Settings::default());
        assert_eq!(Settings::default().files, Files::Archive);
        let d = Settings::from_env(&with(&[("MACHINE_TEAMMATE_FILES", "delete")])).unwrap();
        assert_eq!((d.files, d.grace_days), (Files::Delete, 7));
        let now = Settings::from_env(&with(&[("MACHINE_TEAMMATE_FILES", "delete"), ("MACHINE_TEAMMATE_FILES_DAYS", "0")])).unwrap();
        assert_eq!(now.grace_days, 0);
        assert!(now.describe().ends_with("deleted"), "{}", now.describe());
        assert!(Settings::from_env(&with(&[("MACHINE_TEAMMATE_FILES", "keep")])).is_err());
        assert!(Settings::from_env(&with(&[("MACHINE_TEAMMATE_FILES", "delete"), ("MACHINE_TEAMMATE_FILES_DAYS", "400")])).is_err());
        assert!(Settings::from_env(&with(&[("MACHINE_TEAMMATE_FILES_DAYS", "3")])).is_err(), "days mean nothing for archived work");
    }

    #[test]
    fn one_removal_is_tried_at_a_time() {
        let w = Working::default();
        let a = w.take("c1").unwrap();
        assert!(w.take("c1").is_none());
        assert!(w.take("c2").is_some());
        drop(a);
        assert!(w.take("c1").is_some());
    }
}
