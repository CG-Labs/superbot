//! Removing leaving teammates' accounts on one server (ADR 0066), the one-server side of
//! ADR 0052. With `ISOLATION_TEAMMATES` a teammate's run of a shared Bot uses an account
//! of its own for that owner (ADR 0064). It stays only while the teammate is active and
//! can still run one of the owner's Bots. When that stops (disabled, deprovisioned by
//! SCIM, deleted, or the Bots taken from them: a grant revoked, a Bot made private, given
//! away or deleted), botd queues a removal and runs the root helper at once
//! (`superbot-userctl remove`): it kills the account's processes, hands its workspace to
//! the owner's account (`ISOLATION_TEAMMATE_FILES=archive`, the default) or holds it
//! aside and deletes it after `ISOLATION_TEAMMATE_FILES_DAYS` (`delete`), and deletes
//! its folder, harness logins and temp files, then the account. A removal that fails is
//! tried again every few minutes until it's done; trying again changes nothing once it
//! is. Accounts made before this, or missed, are found in the password database, or in
//! botd's record of the pairs it set up (a recreated container keeps the folders). A
//! user's own account, the owner's and every other account are never touched. Every step
//! is audited.

use crate::accounts::{Isolation, Removed, Space, Work};
use crate::audit::{Actor, Event, Outcome, Source, Who};
use crate::db::{AccountRemoval, NewAccountRemoval, now};
use crate::machines::offboard::{self, ADMIN, Files};
use crate::runner::App;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Res, bad};
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

const PENDING: &str = "pending";
const HELD: &str = "held";
const DONE: &str = "done";
const CANCELLED: &str = "cancelled";
const DAY_MS: i64 = 86_400_000;
/// How often botd looks for accounts that should go, and tries failed removals again.
const SWEEP_SECS: u64 = 300;
/// Work that was to be archived, held this long instead when it can't be: its owner is
/// gone, or their account can't be made.
const ORPHAN_DAYS: i64 = 30;
/// How long a removal waits for the account's runs to end and save their memory.
const RUN_END_SECS: u64 = 60;

type Pair = (String, String);

/// Teammate accounts in use now (a run, or a login starting) and being removed, so the
/// two never overlap: a removal stops the account's runs and waits for them to end, and
/// nothing starts in an account being removed or waiting to be.
#[derive(Default)]
pub struct Gate(Mutex<GateState>);

#[derive(Default)]
struct GateState {
    removing: HashSet<Pair>,
    using: HashMap<Pair, u32>,
}

impl Gate {
    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn in_use(&self, pair: &Pair) -> bool {
        self.lock().using.get(pair).is_some_and(|n| *n > 0)
    }
}

/// A run or login in a teammate's account; the account can't go until it's dropped.
pub struct InUse<'a>(&'a Gate, Pair);

impl Drop for InUse<'_> {
    fn drop(&mut self) {
        let mut s = self.0.lock();
        if let Some(n) = s.using.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                s.using.remove(&self.1);
            }
        }
    }
}

/// A removal of a teammate's account under way; nothing starts in it until it's dropped.
struct Closed<'a>(&'a Gate, Pair);

impl Drop for Closed<'_> {
    fn drop(&mut self) {
        self.0.lock().removing.remove(&self.1);
    }
}

/// Lets a run or a login start in `teammate`'s account for `owner`'s Bots. None while
/// that account is being removed or a removal of it is pending, which this hurries
/// along: the caller refuses, and checks access again once it's let in.
pub fn enter<'a>(app: &'a AppState, owner: &str, teammate: &str) -> Option<InUse<'a>> {
    let pair = (owner.to_string(), teammate.to_string());
    let mut s = app.teammate_gate.lock();
    let pending = || app.db.account_removals(Some(PENDING), Some(teammate)).iter().any(|r| r.owner_id == owner && r.user_id == teammate);
    if s.removing.contains(&pair) || pending() {
        drop(s);
        kick(app);
        return None;
    }
    *s.using.entry(pair.clone()).or_default() += 1;
    Some(InUse(&app.teammate_gate, pair))
}

fn isolation(app: &App) -> Option<Arc<Isolation>> {
    app.isolation.get().cloned()
}

/// botd itself, acting for the account's owner.
fn system(owner_id: &str) -> Who {
    Who { actor: Actor::system("isolation").on_behalf_of(owner_id), source: Source::default() }
}

fn removal_event(by: &Who, action: &str, row: &AccountRemoval, extra: Value) -> Event {
    let mut d = json!({ "forUser": row.user_id, "account": row.account, "reason": row.reason, "files": row.files, "cleanupId": row.id });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
        d.extend(x);
    }
    by.event(action).target("user", &row.owner_id).details(d)
}

/// Queues the removal of `teammate`'s account for `owner`'s Bots, unless one is pending;
/// audited when new.
fn queue(app: &App, iso: &Isolation, by: &Who, owner: &str, teammate: &str, reason: &str) -> Option<(AccountRemoval, bool)> {
    let account = Space::Teammate { owner, teammate }.account()?;
    let s = &iso.offboard;
    let (row, made) = app.db.account_removal_queue(&NewAccountRemoval {
        owner_id: owner,
        user_id: teammate,
        account: &account,
        reason,
        files: s.files.as_str(),
        grace_days: if s.files == Files::Delete { s.grace_days as i64 } else { 0 },
        created_by: by.actor.id.as_deref(),
    })?;
    if made {
        app.db.record(&removal_event(by, "isolation.teammate_removal_queued", &row, json!({})));
    }
    Some((row, made))
}

/// Whether `teammate` keeps their account for `owner`'s Bots here: as on machines
/// (`offboard::wanted`), and only while the owner is active, since none of a disabled
/// owner's Bots run.
pub fn wanted(app: &App, owner: &str, teammate: &str) -> bool {
    app.db.user(owner).is_some_and(|u| u.active()) && offboard::wanted(app, owner, teammate)
}

/// Every teammate account here, as `(owner, teammate)`: in the password database, or
/// made by botd and not removed since (a recreated container keeps the folders, not the
/// accounts), and every pair a removal is still pending for.
fn pairs(app: &App, iso: &Isolation) -> Vec<(String, String)> {
    let mut p = iso.teammate_pairs();
    p.extend(app.db.teammate_spaces());
    p.extend(app.db.account_removals(Some(PENDING), None).into_iter().map(|r| (r.owner_id, r.user_id)));
    p.sort();
    p.dedup();
    p
}

/// Queues removals for the pairs `only` picks whose teammate shouldn't keep the account:
/// as `by` (else botd for the owner), with `reason` (else as botd can tell). How many it
/// queued.
fn sweep(app: &App, iso: &Isolation, by: Option<&Who>, only: impl Fn(&str, &str) -> bool, reason: Option<&str>) -> usize {
    pairs(app, iso)
        .iter()
        .filter(|(o, t)| only(o, t) && !wanted(app, o, t))
        .filter_map(|(o, t)| queue(app, iso, by.unwrap_or(&system(o)), o, t, reason.unwrap_or_else(|| offboard::reason_for(app, t))))
        .filter(|(_, made)| *made)
        .count()
}

/// `user_id` was disabled, deprovisioned or lost their role: queue the removal of their
/// accounts for owners' Bots here, and of teammates' accounts for their own Bots that no
/// one may use now, and try at once.
pub fn left(app: &AppState, by: &Who, user_id: &str, reason: &str) {
    let Some(iso) = isolation(app) else { return };
    let mut queued = sweep(app, &iso, Some(by), |_, t| t == user_id, Some(reason));
    queued += sweep(app, &iso, Some(by), |o, _| o == user_id, None);
    if queued > 0 {
        kick(app);
    }
}

/// `owner_id`'s Bots may have been taken from someone (a grant revoked, a Bot made
/// private, given away or deleted): queue removals of teammates' accounts for them, and
/// try at once.
pub fn check_owner(app: &AppState, by: &Who, owner_id: &str) {
    let Some(iso) = isolation(app) else { return };
    if sweep(app, &iso, Some(by), |o, _| o == owner_id, None) > 0 {
        kick(app);
    }
}

/// Queues removals for every account that shouldn't be here, then tries every pending
/// one and purges held work that's due, in the background.
pub fn follow_up(app: &AppState) {
    let Some(iso) = isolation(app) else { return };
    sweep(app, &iso, None, |_, _| true, None);
    let at = now();
    let due = app.db.account_removals(Some(HELD), None).iter().any(|r| r.purge_at.is_some_and(|p| p <= at));
    if due || !app.db.account_removals(Some(PENDING), None).is_empty() {
        kick(app);
    }
}

/// With per-user accounts: `follow_up` now, for leaves while botd was down, and every
/// few minutes after.
pub fn start(app: &AppState) {
    if isolation(app).is_none() {
        return;
    }
    let app = app.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(std::time::Duration::from_secs(SWEEP_SECS));
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            follow_up(&app);
        }
    });
}

/// Tries what's pending now, in the background. One pass runs at a time; a kick during
/// it runs another after.
fn kick(app: &AppState) {
    let w = &app.account_removals;
    w.again.store(true, Ordering::SeqCst);
    if w.running.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    tokio::spawn(async move {
        let w = &app.account_removals;
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
    let w = &app.account_removals;
    for _ in 0..3000 {
        if !w.running.load(Ordering::SeqCst) && !w.again.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("account removals never settled");
}

/// Tries every pending removal, then purges held work that's due, one at a time (the
/// helper takes one call at a time anyway).
async fn run(app: &App) {
    let Some(iso) = isolation(app) else { return };
    for row in app.db.account_removals(Some(PENDING), None) {
        try_removal(app, &iso, &system(&row.owner_id), &row, false).await;
    }
    let at = now();
    for row in app.db.account_removals(Some(HELD), None).into_iter().filter(|r| r.purge_at.is_some_and(|p| p <= at)) {
        purge(app, &iso, &row).await;
    }
}

enum Tried {
    Removed(Removed),
    Failed(String),
    Cancelled,
    /// Another call is trying it now.
    Busy,
}

/// Records a failed try, auditing it only when the reason is new, so a removal that
/// fails every few minutes for a day leaves one failure in the log.
fn note(app: &App, by: &Who, row: &AccountRemoval, state: &str, why: &str) {
    let changed = row.last_error.as_deref() != Some(why);
    if app.db.account_removal_failed(&row.id, state, why) && changed {
        let action = if state == HELD { "isolation.teammate_files_purge_failed" } else { "isolation.teammate_removal_failed" };
        let attempts = app.db.account_removal(&row.id).map_or(row.attempts, |r| r.attempts);
        let d = json!({ "error": why, "attempts": attempts });
        app.db.record(&removal_event(by, action, row, d).outcome(Outcome::Failure));
    }
}

/// Removes one teammate's account, unless they're wanted again and it isn't `forced` by
/// an admin.
async fn try_removal(app: &App, iso: &Arc<Isolation>, by: &Who, row: &AccountRemoval, forced: bool) -> Tried {
    let Some(_taken) = app.account_removals.take(&row.id) else { return Tried::Busy };
    let Some(row) = app.db.account_removal(&row.id).filter(|r| r.state == PENDING) else { return Tried::Busy };
    // Once the helper has started, it may have done some of it (processes killed, work
    // moved): finish rather than leave it half done. A later run makes the teammate a new
    // account. The update checks again, so an admin's ask that lands meanwhile still stands.
    if !forced && row.reason != ADMIN && row.attempts == 0 && wanted(app, &row.owner_id, &row.user_id) {
        let why = "access_back";
        if app.db.account_removal_cancel_unasked(&row.id, why) {
            app.db.record(&removal_event(by, "isolation.teammate_removal_cancelled", &row, json!({ "why": why })));
            return Tried::Cancelled;
        }
        return Tried::Busy;
    }
    let pair = (row.owner_id.clone(), row.user_id.clone());
    app.teammate_gate.lock().removing.insert(pair.clone());
    let _closed = Closed(&app.teammate_gate, pair.clone());
    let mut runs = app.stop_teammate_runs(&row.owner_id, &row.user_id);
    // A run saves its memory copy back as it ends: the folder goes only after. One let in
    // just before the gate closed may still be setting up, so it's stopped once it starts.
    let mut waited = 0;
    while app.teammate_gate.in_use(&pair) && waited < RUN_END_SECS * 20 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += 1;
        if waited % 10 == 0 {
            runs = runs.max(app.stop_teammate_runs(&row.owner_id, &row.user_id));
        }
    }
    if app.teammate_gate.in_use(&pair) {
        let why = "a run in the account is still ending";
        note(app, by, &row, PENDING, why);
        return Tried::Failed(why.into());
    }
    let logins = app.teammate_logins.stop_for(&row.owner_id, &row.user_id);
    // The work goes to the owner's own account, made now if they never ran a Bot here.
    // With no one to hand it to, it's kept aside a while for an admin instead: the
    // account still goes now.
    let mut unarchived = None;
    let (work, mut days) = match (row.files == Files::Delete.as_str(), row.grace_days) {
        (true, 0) => (Work::Delete, 0),
        (true, d) => (Work::Hold, d),
        (false, _) => match app.db.user(&row.owner_id) {
            None => {
                unarchived = Some("owner_gone".to_string());
                (Work::Hold, ORPHAN_DAYS)
            }
            Some(_) => match app.ensure_space(Space::User(&row.owner_id), by).await {
                Ok(_) => (Work::Archive(offboard::archive_name(app, &row.user_id)), 0),
                Err(why) => {
                    unarchived = Some(format!("couldn't set up the owner's account: {why}"));
                    (Work::Hold, ORPHAN_DAYS)
                }
            },
        },
    };
    // From here the helper may change files, so the removal is never cancelled after.
    if !app.db.account_removal_tried(&row.id, PENDING) {
        return Tried::Busy;
    }
    let done = tokio::task::spawn_blocking({
        let (iso, row, work) = (iso.clone(), row.clone(), work.clone());
        move || iso.remove_teammate(&row.owner_id, &row.user_id, &row.id, &work)
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    match done {
        Ok(r) => {
            app.db.teammate_space_gone(&row.owner_id, &row.user_id);
            if r.work == "held" && work != Work::Hold {
                days = held_days(&row);
                unarchived.get_or_insert_with(|| "held by an earlier try".into());
            }
            let purge_at = (r.work == "held").then(|| now() + days * DAY_MS);
            let archived_to = r.path.as_deref().filter(|_| r.work == "archived");
            if app.db.account_removal_removed(&row.id, archived_to, purge_at) {
                let d = json!({
                    "accountRemoved": r.account_removed, "processesStopped": r.processes, "tempRemoved": r.temp,
                    "runsStopped": runs, "loginsStopped": logins, "work": r.work, "archivedTo": archived_to, "purgeAt": purge_at,
                    "attempts": row.attempts + 1, "notArchived": unarchived.filter(|_| r.work == "held"),
                });
                app.db.record(&removal_event(by, "isolation.teammate_removed", &row, d));
            }
            Tried::Removed(r)
        }
        Err(why) => {
            note(app, by, &row, PENDING, &why);
            Tried::Failed(why)
        }
    }
}

/// How long work an earlier try held is kept when this try meant to archive or delete
/// it: never less than if it were held now, so a retry never makes it due at once.
fn held_days(row: &AccountRemoval) -> i64 {
    if row.files == Files::Delete.as_str() { row.grace_days.max(1) } else { ORPHAN_DAYS }
}

/// Deletes the work a removal held, once its days are up. Whether it's done.
async fn purge(app: &App, iso: &Arc<Isolation>, row: &AccountRemoval) -> bool {
    let Some(_taken) = app.account_removals.take(&row.id) else { return false };
    let by = system(&row.owner_id);
    if !app.db.account_removal_tried(&row.id, HELD) {
        return false;
    }
    let done = tokio::task::spawn_blocking({
        let (iso, id) = (iso.clone(), row.id.clone());
        move || iso.purge(&id)
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    match done {
        Ok(purged) => {
            if app.db.account_removal_end(&row.id, HELD, DONE, None) {
                app.db.record(&removal_event(&by, "isolation.teammate_files_purged", row, json!({ "purged": purged })));
            }
            true
        }
        Err(why) => {
            note(app, &by, row, HELD, &why);
            false
        }
    }
}

// Admin API: `/api/isolation/teammate-removals` and `/api/users/{key}/teammate-accounts`
// (admin only, rbac::classify).

fn person(app: &App, id: &str) -> Value {
    app.db.user(id).map(|u| json!({ "id": u.id, "name": u.name, "email": u.email })).unwrap_or(json!({ "id": id }))
}

fn view(app: &App, r: &AccountRemoval) -> Value {
    let mut v = serde_json::to_value(r).unwrap_or_default();
    v["teammate"] = person(app, &r.user_id);
    v["owner"] = person(app, &r.owner_id);
    v
}

fn need_teammates(app: &App) -> Res<Arc<Isolation>> {
    isolation(app)
        .filter(|i| i.teammates || !i.teammate_pairs().is_empty() || !app.db.teammate_spaces().is_empty())
        .ok_or_else(|| ApiError(StatusCode::CONFLICT, "Teammates have no accounts of their own here: per-user accounts and ISOLATION_TEAMMATES are off.".into()))
}

#[derive(serde::Deserialize)]
pub struct ListQuery {
    state: Option<String>,
}

/// `GET /api/isolation/teammate-removals[?state=pending|held|done|cancelled|open]`:
/// every removal, newest first; `open` is pending and held.
pub async fn list_all(State(app): State<AppState>, Query(q): Query<ListQuery>) -> Res {
    let iso = need_teammates(&app)?;
    let all = app.db.account_removals(None, None);
    let rows: Vec<&AccountRemoval> = match q.state.as_deref() {
        None | Some("") | Some("all") => all.iter().collect(),
        Some("open") => all.iter().filter(|r| r.state == PENDING || r.state == HELD).collect(),
        Some(s @ (PENDING | HELD | DONE | CANCELLED)) => all.iter().filter(|r| r.state == s).collect(),
        Some(s) => return Err(bad(format!("state must be pending, held, done, cancelled, open or all, not \"{s}\""))),
    };
    Ok(Json(json!({
        "files": iso.offboard.files.as_str(),
        "graceDays": iso.offboard.grace_days,
        "removals": rows.into_iter().map(|r| view(&app, r)).collect::<Vec<_>>(),
    })))
}

/// `GET /api/users/{key}/teammate-accounts`: the teammate accounts here for the user's
/// Bots, and theirs for others' Bots, whether each should stay, and their removals.
pub async fn of_user(State(app): State<AppState>, Path(key): Path<String>) -> Res {
    let iso = need_teammates(&app)?;
    let u = need_user_key(&app, &key)?;
    let removals = app.db.account_removals(None, Some(&u.id));
    let accounts: Vec<Value> = pairs(&app, &iso)
        .into_iter()
        .filter(|(o, t)| *o == u.id || *t == u.id)
        .map(|(o, t)| {
            let open = removals.iter().find(|r| r.owner_id == o && r.user_id == t && r.state == PENDING);
            json!({
                "owner": person(&app, &o), "teammate": person(&app, &t), "account": Space::Teammate { owner: &o, teammate: &t }.account(),
                "wanted": wanted(&app, &o, &t), "removal": open.map(|r| view(&app, r)),
            })
        })
        .collect();
    Ok(Json(json!({
        "userId": u.id,
        "files": iso.offboard.files.as_str(),
        "graceDays": iso.offboard.grace_days,
        "accounts": accounts,
        "removals": removals.iter().map(|r| view(&app, r)).collect::<Vec<_>>(),
    })))
}

/// `POST /api/users/{key}/teammate-accounts/{teammate}/remove`: removes the teammate's
/// account for the user's Bots now, even if they still have access (their next run makes
/// a new one). 200 when done, 202 with why when it's still pending.
pub async fn remove_now(State(app): State<AppState>, Extension(by): Extension<Who>, Path((key, teammate)): Path<(String, String)>) -> Res<(StatusCode, Json<Value>)> {
    let iso = need_teammates(&app)?;
    let owner = need_user_key(&app, &key)?;
    let t = app.db.find_user(&teammate).map_or(teammate.clone(), |t| t.id);
    if t == owner.id {
        return Err(bad("That is the user's own account, which is never removed here. Name a teammate."));
    }
    if crate::accounts::teammate_account(&owner.id, &t).is_none() {
        return Err(bad("Name a teammate by id or email."));
    }
    let (row, _) = queue(&app, &iso, &by, &owner.id, &t, ADMIN).ok_or_else(|| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Couldn't queue the removal.".into()))?;
    // A removal already waiting for another reason is the admin's from now on, so a later
    // pass never cancels it because the teammate is wanted again.
    if row.reason != ADMIN && app.db.account_removal_force(&row.id) {
        app.db.record(&removal_event(&by, "isolation.teammate_removal_forced", &row, json!({ "was": row.reason })));
    }
    let tried = try_removal(&app, &iso, &by, &row, true).await;
    let after = app.db.account_removal(&row.id).map(|r| view(&app, &r)).unwrap_or(Value::Null);
    Ok(match tried {
        Tried::Removed(r) => (StatusCode::OK, Json(json!({ "removal": after, "removed": r }))),
        Tried::Failed(why) => (StatusCode::ACCEPTED, Json(json!({ "removal": after, "error": why }))),
        Tried::Cancelled | Tried::Busy => (StatusCode::ACCEPTED, Json(json!({ "removal": after }))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_an_earlier_try_held_is_never_due_at_once() {
        let row = |files: &str, grace_days| AccountRemoval {
            id: "c1".into(),
            owner_id: "u1".into(),
            user_id: "u2".into(),
            account: "sb-t-1".into(),
            reason: "disabled".into(),
            files: files.into(),
            grace_days,
            state: PENDING.into(),
            attempts: 2,
            last_error: None,
            tried_at: None,
            created_at: 0,
            created_by: None,
            removed_at: None,
            archived_to: None,
            purge_at: None,
            done_at: None,
        };
        assert_eq!(held_days(&row("archive", 0)), ORPHAN_DAYS);
        assert_eq!(held_days(&row("delete", 7)), 7);
        assert_eq!(held_days(&row("delete", 0)), 1);
    }
}
