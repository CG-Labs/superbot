//! Resizing a user's machine when their tier changes (ADR 0085).
//!
//! A tier change (a Stripe subscription event, or an admin) asks for the machine to
//! become the size the new tier gives (`size_for`). Asking is idempotent: the target
//! comes from the user's tier now, so a redelivered event, or a second change back,
//! finds the same answer. The reconciler does the work, under the control plane's
//! lock, from the state each step expects:
//!
//! - `pending`: to be tried on the next pass (after a backoff, once a try failed).
//! - `waiting`: not safe yet, with the reason in plain words, looked at again on every
//!   pass: the user's storage is over the new tier's cap, the machine's disk holds more
//!   than the new size's disk would with room to spare (or botd can't tell), its host
//!   hasn't room to grow it, or Bots are running on a machine the resize would restart
//!   or squeeze.
//! - `done`, `failed`, `cancelled`: settled. A newer tier change asks again.
//!
//! The size sent to the provider is kept until its outcome is seen (`settle`), whatever
//! becomes of the request: its host keeps room for it, and a tier change back to the
//! size botd has on record asks for that size again rather than cancelling.
//!
//! Nothing is lost on a downgrade: a machine is only made smaller once what's on it
//! fits. An admin can still resize by hand (`POST /api/users/{key}/machine/resize`).

use super::provider::{MachineProvider, ProviderError, Resources};
use super::{ControlPlane, State, event, hosts, placement, rebuild, size_for, system, transient};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, now};
use crate::notify::{self, Alert};
use crate::runner::App;
use crate::storage;
use crate::users::need_user_key;
use crate::{AppState, Res, not_found};
use axum::Json;
use axum::extract::{Extension, Path, State as AppS};
use serde_json::{Value, json};
use std::sync::Arc;

/// Tries that failed for a reason that may pass (the provider's outages, the network)
/// before it gives up.
pub const MAX_ATTEMPTS: i64 = 5;
/// Bots running on a machine a resize would restart or squeeze hold it up this long at
/// most; then it goes ahead, since a busy plan must still end.
pub const BUSY_MAX_MS: i64 = 6 * 60 * 60_000;
/// A running machine's disk report older than this isn't trusted to make it smaller.
pub const DISK_FRESH_MS: i64 = 15 * 60_000;
/// What a smaller disk must leave free: what's on it may take at most 90%.
pub const DISK_FILL_PERCENT: u64 = 90;

const OPEN: [&str; 2] = ["pending", "waiting"];

fn open(m: &Machine) -> bool {
    m.resize_state.as_deref().is_some_and(|s| OPEN.contains(&s))
}

/// Whether a resize sent to the provider, with its outcome unknown, may have left the
/// machine at another size than botd's record.
fn unsettled(m: &Machine) -> bool {
    m.resize_sent_plan.as_deref().is_some_and(|s| s != m.plan)
}

fn details(m: &Machine, extra: Value) -> Value {
    let mut d = json!({
        "fromTier": m.resize_from_tier, "toTier": m.resize_tier, "fromPlan": m.resize_from_plan, "toPlan": m.resize_plan,
        "cause": m.resize_cause, "eventId": m.resize_event, "attempts": m.resize_attempts,
    });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
        d.extend(x);
    }
    d
}

fn cancel(app: &App, by: &Who, m: &Machine, reason: &str, text: &str) {
    let Some(plan) = &m.resize_plan else { return };
    if app.db.machine_resize_move(&m.id, plan, &OPEN, "cancelled", Some(reason), Some(text), false, None) {
        app.db.record(&event(by, "machine.resize_cancelled", m, details(m, json!({ "reason": reason }))));
    }
}

/// Makes the machine follow its user's tier: asks for the size the tier gives, cancels
/// a resize the tier no longer wants, or leaves an open one as it is. `fresh`: the tier
/// has just changed, so a size asked for before (and failed, say) is asked for again; a
/// redelivered event isn't fresh. Returns `queued` when it asked.
pub fn follow(app: &App, by: &Who, user_id: &str, cause: &str, event_id: Option<&str>, fresh: bool) -> Option<&'static str> {
    let cp = app.control_plane.get()?;
    let m = app.db.user_machine(user_id)?;
    if !cp.owns(&m) || matches!(m.state, State::Destroying | State::Destroyed) {
        return None;
    }
    let Some((tier, plan)) = size_for(app, cp, user_id) else {
        if open(&m) {
            cancel(app, by, &m, "plan_sets_no_size", "The plan no longer sets a machine size, so the machine stays as it is.");
        }
        return None;
    };
    // A resize sent whose outcome is unknown may have left the machine at another size
    // than botd's record: it's asked for again, not taken as done.
    let unsettled = unsettled(&m);
    if (&tier, &plan) == (&m.tier, &m.plan) && !unsettled {
        if open(&m) {
            cancel(app, by, &m, "already_that_size", "The machine is that size already.");
        }
        return None;
    }
    let same = m.resize_tier.as_deref() == Some(tier.as_str()) && m.resize_plan.as_deref() == Some(plan.as_str());
    if same && (open(&m) || (!fresh && !unsettled)) {
        return None;
    }
    if !app.db.machine_resize_queue(&m.id, &tier, &plan, (&m.tier, &m.plan), cause, event_id) {
        return None;
    }
    let replaces = (open(&m) && !same).then(|| json!({ "tier": m.resize_tier, "plan": m.resize_plan }));
    let now_m = app.db.machine(&m.id).unwrap_or(m);
    app.db.record(&event(by, "machine.resize_queued", &now_m, details(&now_m, json!({ "replaces": replaces }))));
    Some("queued")
}

/// What decides whether a resize may go ahead now.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    /// The provider restarts a machine to resize it (a VM).
    pub restarts: bool,
    /// What the old and new plans give, where the provider can say.
    pub from: Option<Resources>,
    pub to: Option<Resources>,
    /// The old and new plans' disks, in bytes.
    pub from_disk: Option<u64>,
    pub to_disk: Option<u64>,
    /// What's on the machine's disk, if its agent said lately.
    pub disk_used: Option<u64>,
    /// The user's storage against the new tier's cap: `(used, cap)`.
    pub storage: Option<(u64, u64)>,
    /// The new tier's name for people.
    pub label: String,
    /// Bots running on the machine now, and how long the resize has waited.
    pub runs: u32,
    pub waited_ms: i64,
    /// Whether its host has room to grow it there; None where hosts don't matter.
    pub room: Option<Result<(), String>>,
}

impl Facts {
    /// Whether any of CPUs, memory or disk would be smaller.
    fn shrinks(&self) -> bool {
        match (self.from, self.to) {
            (Some(a), Some(b)) => b.cpus < a.cpus || b.memory_gib < a.memory_gib || b.disk_gib < a.disk_gib,
            _ => self.disk_shrinks(),
        }
    }

    /// Whether the disk would be smaller, or botd can't tell that it won't be.
    fn disk_shrinks(&self) -> bool {
        !matches!((self.from_disk, self.to_disk), (Some(a), Some(b)) if b >= a)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Decision {
    Go,
    /// Not yet: a reason code and what people are told.
    Wait(&'static str, String),
}

/// Whether the resize may go ahead now, or why not, most actionable reason first.
pub fn decide(f: &Facts) -> Decision {
    let label = &f.label;
    if let Some((used, cap)) = f.storage
        && used >= cap
    {
        return Decision::Wait(
            "storage_over",
            format!(
                "Storage is {} used of the {label} plan's {}. The machine moves to the {label} size once that's deleted down below the plan's limit, so nothing on it is lost.",
                storage::human(used),
                storage::human(cap)
            ),
        );
    }
    if f.disk_shrinks() {
        let Some(disk) = f.to_disk else {
            return Decision::Wait("plan_disk_unknown", format!("botd can't tell how big the {label} size's disk is, so the machine isn't made smaller yet."));
        };
        let Some(used) = f.disk_used else {
            return Decision::Wait("disk_unknown", "The machine hasn't said lately how full its disk is, so it isn't made smaller yet. It moves once its agent reports it.".into());
        };
        let fits = disk.saturating_mul(DISK_FILL_PERCENT) / 100;
        if used > fits {
            return Decision::Wait(
                "disk_too_full",
                format!(
                    "The machine's disk has {} on it, and the {label} size's disk is {}. Delete files on the machine to get below {}, and it moves then, so nothing on it is lost.",
                    storage::human(used),
                    storage::human(disk),
                    storage::human(fits)
                ),
            );
        }
    }
    if let Some(Err(why)) = &f.room {
        return Decision::Wait("no_room", format!("Its host hasn't room for the {label} size yet: {why}. It moves once there is."));
    }
    if f.runs > 0 && (f.restarts || f.shrinks()) && f.waited_ms < BUSY_MAX_MS {
        let what = if f.restarts { "resizing restarts it" } else { "a smaller size could stop them" };
        return Decision::Wait("busy", format!("Waiting for the Bots' work on the machine to finish: {what}."));
    }
    Decision::Go
}

/// What people are told of a waiting resize: the host's details are for admins.
fn user_text(m: &Machine) -> Option<String> {
    match m.resize_reason.as_deref() {
        Some("no_room") => Some(format!(
            "The server it's on hasn't room for the {} size yet. It moves once there is.",
            m.resize_tier.as_deref().unwrap_or("new")
        )),
        Some("provider") if m.resize_state.as_deref() == Some("failed") => {
            Some("The machine couldn't be resized. An admin has been told.".into())
        }
        Some("provider") => Some("The machine's provider didn't answer; it's tried again shortly.".into()),
        _ => m.resize_error.clone(),
    }
}

/// The machine's latest resize, as admins see it. Null: never asked.
pub fn view(m: &Machine) -> Value {
    if m.resize_state.is_none() {
        return Value::Null;
    }
    json!({
        "state": m.resize_state, "fromTier": m.resize_from_tier, "toTier": m.resize_tier, "fromPlan": m.resize_from_plan,
        "toPlan": m.resize_plan, "cause": m.resize_cause, "eventId": m.resize_event, "reason": m.resize_reason,
        "message": m.resize_error, "attempts": m.resize_attempts, "requestedAt": m.resize_requested_at,
        "updatedAt": m.resize_at, "nextAt": m.resize_next_at,
    })
}

/// The machine's latest resize, as its user sees it: tiers, not plans or hosts.
pub fn own_view(m: &Machine) -> Value {
    if m.resize_state.is_none() {
        return Value::Null;
    }
    json!({
        "state": m.resize_state, "fromTier": m.resize_from_tier, "toTier": m.resize_tier, "reason": m.resize_reason,
        "message": user_text(m), "requestedAt": m.resize_requested_at, "updatedAt": m.resize_at,
    })
}

/// A user's machine on their plan view: its tier, state and latest resize. Null: none.
pub fn plan_view(app: &App, user_id: &str) -> Value {
    match app.control_plane.get().filter(|cp| cp.enabled()).and(app.db.user_machine(user_id)) {
        Some(m) => json!({ "tier": m.tier, "state": m.state, "resize": own_view(&m) }),
        None => Value::Null,
    }
}

fn alert(app: &AppState, m: &Machine, title: &str, why: &str) {
    let a = Alert {
        event: "machine.resize_waiting".into(),
        title: title.into(),
        lines: vec![
            why.to_string(),
            format!("{} should be {} for their plan. `botctl machine resize {} status` shows where it stands.", m.user_id, m.resize_tier.as_deref().unwrap_or("?"), m.user_id),
        ],
        target_type: "machine".into(),
        target_id: m.id.clone(),
        link: None,
    };
    notify::alert(app, a, "machines");
}

fn wait(app: &AppState, m: &Machine, plan: &str, reason: &str, text: &str) {
    let again = m.resize_reason.as_deref() == Some(reason) && m.resize_state.as_deref() == Some("waiting");
    if !app.db.machine_resize_move(&m.id, plan, &OPEN, "waiting", Some(reason), Some(text), false, None) || again {
        return;
    }
    // Said once per reason, not every pass.
    app.db.record(&event(&system(m), "machine.resize_waiting", m, details(m, json!({ "reason": reason, "error": text }))));
    if reason == "no_room" {
        alert(app, m, "A machine can't grow on its host", text);
    }
}

fn fail(app: &AppState, m: &Machine, plan: &str, e: &ProviderError, count: bool) {
    let text = format!("The provider couldn't resize the machine: {e}");
    if app.db.machine_resize_move(&m.id, plan, &OPEN, "failed", Some("provider"), Some(&text), count, None) {
        let m = app.db.machine(&m.id).unwrap_or_else(|| m.clone());
        app.db.record(&event(&system(&m), "machine.resize_failed", &m, details(&m, json!({ "error": e.to_string() }))).outcome(Outcome::Failure));
        alert(app, &m, "A machine couldn't be resized to its plan", &text);
    }
}

/// A try that failed: again after the backoff if the cause may pass, else failed.
fn retry(app: &AppState, m: &Machine, plan: &str, e: ProviderError) {
    let tries = m.resize_attempts + 1;
    if !transient(&e) || tries >= MAX_ATTEMPTS {
        return fail(app, m, plan, &e, true);
    }
    let text = format!("The provider didn't answer; trying again: {e}");
    app.db.machine_resize_move(&m.id, plan, &OPEN, "pending", Some("provider"), Some(&text), true, Some(now() + rebuild::backoff_ms(tries)));
}

/// What botd knows of the machine and the plans, for `decide`.
/// Err: the provider failed to say what a plan's disk is (None: it can't say).
async fn facts(app: &AppState, cp: &ControlPlane, p: &dyn MachineProvider, m: &Machine, plan: &str) -> Result<Facts, ProviderError> {
    let (from, to) = (p.plan_resources(&m.plan), p.plan_resources(plan));
    let (from_disk, to_disk) = (p.plan_disk(&m.plan).await?, p.plan_disk(plan).await?);
    // A suspended machine's disk can't change, so what it said before still holds.
    let fresh = m.state == State::Suspended || m.disk_seen_at.is_some_and(|t| now() - t < DISK_FRESH_MS);
    let tier = app.tier_of(&m.user_id);
    let storage = match storage::limit(&tier.limits) {
        Some(cap) => Some((storage::current(app, &m.user_id, storage::CHECK_AGE).await.used(), cap)),
        None => None,
    };
    let room = hosts::of(cp, m).map(|h| placement::grow(app, cp, &h, m, plan));
    Ok(Facts {
        restarts: p.substrate() == "vm",
        from,
        to,
        from_disk,
        to_disk,
        disk_used: m.disk_used.filter(|_| fresh).and_then(|u| u64::try_from(u).ok()),
        storage,
        label: tier.label.clone(),
        runs: if m.state == State::Running { app.runs_on_machine(&m.user_id) } else { 0 },
        waited_ms: now() - m.resize_requested_at.unwrap_or_else(now),
        room,
    })
}

/// A resize sent whose outcome botd hasn't seen, settled from what the provider says
/// now: the size it took is recorded, one it didn't take is forgotten. Left as it is
/// while the provider is still resizing. Callers hold `ops`.
async fn settle(app: &AppState, p: &dyn MachineProvider, m: &Machine) -> Result<(), ProviderError> {
    let (Some(tier), Some(sent)) = (m.resize_sent_tier.clone(), m.resize_sent_plan.clone()) else { return Ok(()) };
    let pid = match &m.provider_id {
        Some(pid) if !matches!(m.state, State::Destroying | State::Destroyed) => pid.clone(),
        _ => {
            app.db.machine_resize_unsent(&m.id, Some(&sent));
            return Ok(());
        }
    };
    let pm = match p.get(&pid).await {
        Ok(pm) => pm,
        Err(ProviderError::NotFound) => {
            app.db.machine_resize_unsent(&m.id, Some(&sent));
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    if pm.status == "resizing" {
        return Ok(());
    }
    if pm.plan == sent && sent != m.plan {
        let mut after = m.clone();
        (after.tier, after.plan, after.last_error) = (tier.clone(), sent.clone(), None);
        if !app.db.save_machine(&after, m.state) {
            return Ok(()); // changed meanwhile: the next pass looks again
        }
        let extra = json!({
            "fromTier": m.tier, "toTier": tier, "fromPlan": m.plan, "toPlan": sent, "providerCall": false,
            "auto": true, "settled": true, "providerId": pid,
        });
        app.db.record(&event(&system(&after), "machine.resized", &after, extra));
    }
    app.db.machine_resize_unsent(&m.id, Some(&sent));
    Ok(())
}

/// One step for one machine's resize. Callers hold `ops`.
async fn step(app: &AppState, cp: &ControlPlane, p: &dyn MachineProvider, id: &str) {
    let Some(m) = app.db.machine(id) else { return };
    if let Err(e) = settle(app, p, &m).await {
        if let Some(plan) = m.resize_plan.as_deref().filter(|_| open(&m)) {
            retry(app, &m, plan, e);
        }
        return;
    }
    let Some(m) = app.db.machine(id) else { return };
    // The tier may have moved on since it was asked for (or TIERS_FILE did).
    follow(app, &system(&m), &m.user_id, m.resize_cause.as_deref().unwrap_or("admin"), m.resize_event.as_deref(), false);
    let Some(m) = app.db.machine(id).filter(open) else { return };
    let (Some(tier), Some(plan)) = (m.resize_tier.clone(), m.resize_plan.clone()) else { return };
    let not_yet = match m.state {
        State::Running | State::Suspended => None,
        State::Pending | State::Provisioning => Some(("machine_not_ready", "The machine isn't running yet; it's resized once it is.")),
        State::Error => Some(("machine_not_ready", "The machine needs an admin's attention first; it's resized once it's running again.")),
        State::Destroying | State::Destroyed => return cancel(app, &system(&m), &m, "machine_gone", "The machine is gone."),
    };
    let not_yet = not_yet
        .or_else(|| rebuild::underway(&m).then_some(("rebuilding", "The machine is being rebuilt; it's resized after.")))
        .or_else(|| app.db.machine_restoring(&m.id).is_some().then_some(("restoring", "The machine is being restored; it's resized after.")));
    if let Some((reason, text)) = not_yet {
        return wait(app, &m, &plan, reason, text);
    }
    let Some(pid) = m.provider_id.clone() else {
        return wait(app, &m, &plan, "machine_not_ready", "The machine isn't running yet; it's resized once it is.");
    };
    let facts = match facts(app, cp, p, &m, &plan).await {
        Ok(f) => f,
        Err(e) => return retry(app, &m, &plan, e),
    };
    if let Decision::Wait(reason, text) = decide(&facts) {
        return wait(app, &m, &plan, reason, &text);
    }
    // As `act`: ask the provider first, so a resize whose answer was lost isn't sent twice.
    let pm = match p.get(&pid).await {
        Ok(pm) => pm,
        Err(e) => return retry(app, &m, &plan, e),
    };
    if pm.status == "resizing" && pm.plan != plan {
        return wait(app, &m, &plan, "provider_busy", "The provider is still busy resizing the machine.");
    }
    let call = pm.plan != plan;
    if call {
        // Kept until the outcome is seen, whatever becomes of the request meanwhile.
        app.db.machine_resize_sent(&m.id, &tier, &plan);
        if let Err(e) = p.resize(&pid, &plan).await {
            return retry(app, &m, &plan, e);
        }
    }
    let mut after = m.clone();
    let (from_tier, from_plan) = (m.tier.clone(), m.plan.clone());
    (after.tier, after.plan, after.last_error) = (tier.clone(), plan.clone(), None);
    if !app.db.save_machine(&after, m.state) {
        return; // changed meanwhile: the next pass looks again
    }
    app.db.machine_resize_unsent(&m.id, None);
    app.db.machine_resize_move(&m.id, &plan, &OPEN, "done", None, None, false, None);
    let extra = json!({
        "fromTier": from_tier, "toTier": tier, "fromPlan": from_plan, "toPlan": plan, "providerCall": call,
        "auto": true, "cause": m.resize_cause, "eventId": m.resize_event, "providerId": pid,
    });
    app.db.record(&event(&system(&after), "machine.resized", &after, extra));
    // The tier may have changed while the provider worked: a request it cancelled
    // against the old size is asked for again against this one.
    follow(app, &system(&after), &after.user_id, m.resize_cause.as_deref().unwrap_or("admin"), None, false);
}

/// Every machine with a resize due, each under the lock on its own.
pub async fn reconcile(app: &AppState, cp: &ControlPlane) {
    let Some(p) = cp.provider.as_deref() else { return };
    let at = now();
    for m in app.db.machines_resizing() {
        if !cp.owns(&m) || m.resize_next_at.is_some_and(|t| t > at) {
            continue;
        }
        let _g = cp.ops.lock().await;
        step(app, cp, p, &m.id).await;
    }
}

/// `GET /api/users/{key}/machine/resize`: the user's machine's latest resize.
pub async fn status(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<crate::Auth>>, Path(key): Path<String>) -> Res {
    a.machines.need()?;
    let u = need_user_key(&app, &key)?;
    let m = app.db.user_machine(&u.id).ok_or_else(|| not_found("Machine"))?;
    Ok(Json(json!({ "machineId": m.id, "tier": m.tier, "plan": m.plan, "state": m.state, "resize": view(&m) })))
}

/// `GET /api/machines/resizes`: every resize not yet done.
pub async fn list(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<crate::Auth>>) -> Res {
    a.machines.need()?;
    let all: Vec<Value> = app
        .db
        .machines_resizing()
        .iter()
        .map(|m| json!({ "machineId": m.id, "userId": m.user_id, "userEmail": app.db.user(&m.user_id).and_then(|u| u.email), "resize": view(m) }))
        .collect();
    Ok(Json(json!(all)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1_000_000_000;

    fn r(cpus: u64, memory_gib: u64, disk_gib: u64) -> Option<Resources> {
        Some(Resources { cpus, memory_gib, disk_gib })
    }

    fn down() -> Facts {
        Facts { restarts: true, from_disk: Some(80 * GB), to_disk: Some(50 * GB), disk_used: Some(10 * GB), label: "Starter".into(), ..Default::default() }
    }

    fn reason(f: &Facts) -> &'static str {
        match decide(f) {
            Decision::Go => "go",
            Decision::Wait(r, _) => r,
        }
    }

    #[test]
    fn a_downgrade_waits_until_what_is_on_the_machine_fits() {
        assert_eq!(reason(&down()), "go");
        assert_eq!(reason(&Facts { disk_used: None, ..down() }), "disk_unknown");
        assert_eq!(reason(&Facts { to_disk: None, ..down() }), "plan_disk_unknown");
        assert_eq!(reason(&Facts { disk_used: Some(45 * GB), ..down() }), "go", "exactly 90%");
        let Decision::Wait(r, text) = decide(&Facts { disk_used: Some(46 * GB), ..down() }) else { panic!() };
        assert_eq!(r, "disk_too_full");
        assert!(text.contains("46 GB on it") && text.contains("Starter size's disk is 50 GB") && text.contains("below 45 GB"), "{text}");
        // Storage over the new plan's cap comes first: it's what the user can act on.
        let Decision::Wait(r, text) = decide(&Facts { storage: Some((6 * GB, 5 * GB)), disk_used: None, ..down() }) else { panic!() };
        assert_eq!(r, "storage_over");
        assert!(text.contains("6 GB used of the Starter plan's 5 GB"), "{text}");
        assert_eq!(reason(&Facts { storage: Some((4 * GB, 5 * GB)), ..down() }), "go");
    }

    #[test]
    fn an_upgrade_needs_no_disk_report_but_room_on_its_host() {
        let up = Facts { from_disk: Some(50 * GB), to_disk: Some(80 * GB), label: "Pro".into(), ..Default::default() };
        assert_eq!(reason(&up), "go");
        let full = Facts { room: Some(Err("a has 0 of 2 CPUs free, 1 more needed".into())), ..up.clone() };
        let Decision::Wait(r, text) = decide(&full) else { panic!() };
        assert_eq!(r, "no_room");
        assert!(text.contains("a has 0 of 2 CPUs free"), "{text}");
        assert_eq!(reason(&Facts { room: Some(Ok(())), ..up.clone() }), "go");
        // A provider that can't size either plan is treated as shrinking the disk.
        assert_eq!(reason(&Facts { from_disk: None, ..up }), "disk_unknown");
    }

    #[test]
    fn busy_machines_wait_when_the_resize_would_restart_or_squeeze_them() {
        assert_eq!(reason(&Facts { runs: 2, ..down() }), "busy", "a VM restarts");
        assert_eq!(reason(&Facts { runs: 2, waited_ms: BUSY_MAX_MS, ..down() }), "go", "not for ever");
        let grow = Facts { from: r(1, 2, 20), to: r(2, 4, 40), from_disk: Some(20 << 30), to_disk: Some(40 << 30), runs: 3, ..Default::default() };
        assert_eq!(reason(&grow), "go", "a container grows live");
        let squeeze = Facts { from: r(2, 4, 40), to: r(2, 2, 40), from_disk: Some(40 << 30), to_disk: Some(40 << 30), runs: 1, ..Default::default() };
        assert_eq!(reason(&squeeze), "busy", "less memory could stop them");
    }
}
