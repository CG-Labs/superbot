//! Rebuilding machines enrolled before ADR 0039 with today's agent (ADR 0056).
//!
//! Such an agent can't replace itself: its unit runs it read-only, it doesn't say
//! `upgrade` in its heartbeat, and it has none of the later pieces (harness CLIs, the
//! Bots' own user, screens, botctl in its layout). botd never runs code through it.
//! Instead the provider wipes the machine and reinstalls it in place (same id, IP and
//! firewall) with today's first-boot user data and a fresh enrollment token; the
//! machine enrolls again and the usual follow-ups bring it up to date.
//!
//! MACHINE_LEGACY_REBUILDS: `manual` (the default) rebuilds only when an admin asks;
//! `auto` also queues every idle old machine that never ran Bots; `off` never.
//!
//! A rebuild wipes the disks, so one that may hold the user's files (assigned now or
//! ever, or a Bot ran there) needs an admin's `discardWork`. Steps run under the
//! control plane's lock, each from the state it expects, so retries are idempotent:
//!
//! - `queued`: waits for a heartbeat from the old agent showing it idle, then sends.
//! - `rebuilding`: sent (or maybe sent: the provider's answer was lost). Done once the
//!   machine enrolls again with an agent that can upgrade itself.
//! - `retrying`: it didn't come back in time; sent again after a backoff.
//! - `done`, `failed`, `cancelled`: settled. Admins can ask again.

use super::enroll::{self, Enrollment};
use super::provider::{MachineProvider, ProviderError, RebuildSpec};
use super::wire::{self, Heartbeat};
use super::{ControlPlane, State, event, system, transient};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, now};
use crate::runner::App;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Res};
use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Path, Query, State as AppS};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

/// Rebuilds sent, and checks that failed, before it gives up.
pub const MAX_ATTEMPTS: i64 = 5;
/// An old agent that is busy is asked again after this long, without counting a try.
const BUSY_WAIT_MS: i64 = 60_000;
/// How much longer than the enrollment timeout a rebuilt machine has to come back.
const BOOT_SLACK_MS: i64 = 5 * 60_000;
/// A machine that enrolled again but never answers a heartbeat in this long failed.
const ANSWER_MS: i64 = 30 * 60_000;

/// What a later botd asks of a machine's agent. `upgrade` is what an old one lacks
/// first; with it, the agent gets the rest by itself.
const CAPABILITIES: [&str; 8] = [
    wire::CAN_UPGRADE,
    wire::CAN_HARNESSES,
    wire::CAN_LOGINS,
    wire::CAN_SYNC,
    wire::CAN_BOT_USER,
    wire::CAN_SCREENS,
    wire::CAN_TEAMMATES,
    wire::CAN_TEAMMATE_REMOVAL,
];

/// MACHINE_LEGACY_REBUILDS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Rebuilds {
    Off,
    #[default]
    Manual,
    Auto,
}

impl Rebuilds {
    pub fn parse(raw: &str) -> Result<Rebuilds, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "manual" => Ok(Rebuilds::Manual),
            "auto" => Ok(Rebuilds::Auto),
            "off" => Ok(Rebuilds::Off),
            v => Err(format!("MACHINE_LEGACY_REBUILDS must be off, manual or auto, not \"{v}\"")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Rebuilds::Off => "off",
            Rebuilds::Manual => "manual",
            Rebuilds::Auto => "auto",
        }
    }
}

/// Whether the heartbeat is from an agent from before ADR 0039.
pub fn legacy(hb: &Heartbeat) -> bool {
    !hb.can.iter().any(|c| c == wire::CAN_UPGRADE)
}

/// What botd last heard its agent can do. None: never heard, or forgotten by a rebuild.
fn can_seen(m: &Machine) -> Option<Vec<String>> {
    let u = m.agent_upkeep.as_ref()?;
    Some(u["can"].as_array().map_or(Vec::new(), |a| a.iter().filter_map(|c| c.as_str().map(String::from)).collect()))
}

/// What a later botd asks of its agent that it can't do.
pub fn lacks(can: &[String]) -> Vec<&'static str> {
    CAPABILITIES.into_iter().filter(|c| !can.iter().any(|x| x == c)).collect()
}

/// A rebuild is asked for or on its way: Bots don't run there meanwhile.
pub fn underway(m: &Machine) -> bool {
    matches!(m.rebuild_state.as_deref(), Some("queued" | "retrying" | "rebuilding"))
}

/// How long to wait after `attempts` tries: 1, 2, 4, 8, 16, then 30 minutes.
pub fn backoff_ms(attempts: i64) -> i64 {
    (60_000i64 << (attempts - 1).clamp(0, 5)).min(30 * 60_000)
}

/// It enrolled again since the last rebuild was sent.
fn back(m: &Machine) -> bool {
    m.enrollment == "enrolled" && matches!((m.enrolled_at, m.rebuild_sent_at), (Some(e), Some(s)) if e >= s)
}

fn who(m: &Machine) -> &str {
    m.rebuild_by.as_deref().unwrap_or("auto")
}

fn details(m: &Machine, extra: Value) -> Value {
    let mut d = json!({
        "rebuildId": m.rebuild_id, "by": who(m), "discardWork": m.rebuild_discard,
        "attempts": m.rebuild_attempts, "fromVersion": m.rebuild_from,
    });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
        d.extend(x);
    }
    d
}

/// Why botd can't rebuild machines at all, if it can't.
fn unable(cp: &ControlPlane, e: &Enrollment) -> Option<&'static str> {
    if e.upkeep.rebuilds == Rebuilds::Off {
        return Some("Rebuilds are off on this server (MACHINE_LEGACY_REBUILDS=off).");
    }
    if cp.provider.is_none() {
        return Some(super::NOT_CONFIGURED);
    }
    if e.agent_sha256().is_none() {
        return Some("superbot-machine isn't next to botd, so a rebuilt machine would have no agent to install.");
    }
    None
}

/// Ends the rebuild as failed from one of `from`, with any unused token revoked.
fn fail(app: &App, m: &Machine, from: &[&str], reason: &str, error: &str) {
    let Some(id) = &m.rebuild_id else { return };
    if app.db.machine_rebuild_move(&m.id, id, from, "failed", false, None, Some(error)) {
        app.db.revoke_machine_tokens(&m.id);
        let m = app.db.machine(&m.id).unwrap_or_else(|| m.clone());
        app.db.record(
            &event(&system(&m), "machine.rebuild_failed", &m, details(&m, json!({ "reason": reason, "error": error })))
                .outcome(Outcome::Failure),
        );
    }
}

/// A try from `from` failed (`count`: one more try; a rebuild sent counted already):
/// try again from `to` after the backoff, or give up.
fn retry_later(app: &App, m: &Machine, from: &str, to: &str, count: bool, reason: &str, error: &str) {
    let Some(id) = &m.rebuild_id else { return };
    let tries = m.rebuild_attempts + count as i64;
    if tries >= MAX_ATTEMPTS {
        if app.db.machine_rebuild_move(&m.id, id, &[from], from, count, None, Some(error)) {
            fail(app, &app.db.machine(&m.id).unwrap_or_else(|| m.clone()), &[from], reason, error);
        }
        return;
    }
    app.db.machine_rebuild_move(&m.id, id, &[from], to, count, Some(now() + backoff_ms(tries)), Some(error));
}

fn cancel(app: &App, by: &Who, m: &Machine, reason: &str) -> bool {
    let Some(id) = &m.rebuild_id else { return false };
    if !app.db.machine_rebuild_move(&m.id, id, &["queued"], "cancelled", false, None, Some(reason)) {
        return false;
    }
    app.db.record(&event(by, "machine.rebuild_cancelled", m, details(m, json!({ "reason": reason }))));
    true
}

/// Forgets what the old agent said and what was on its disks. Done before the provider
/// is asked, so a botd that stops mid-call can't skip it; if the provider refuses, the
/// old agent says it all again and its Bots start new sessions.
fn forget_old(app: &App, m: &Machine) {
    app.db.machine_rebuilt_reset(&m.id);
    app.db.forget_sessions_of(&m.user_id);
    super::folder::forget(app, &m.id);
}

/// Teammate cleanups asked of the old machine before `before`: its disks are gone.
fn end_cleanups(app: &App, m: &Machine, before: i64) {
    for state in ["pending", "held"] {
        for c in app.db.teammate_cleanups(Some(state), Some(&m.id)).into_iter().filter(|c| c.created_at <= before) {
            app.db.teammate_cleanup_end(&c.id, state, "done", Some("machine rebuilt"));
        }
    }
}

/// The provider took it (or may have): the old agent's certificates and cleanups go.
fn wiped(app: &App, by: &Who, m: &Machine) {
    end_cleanups(app, m, m.rebuild_sent_at.unwrap_or_else(now));
    enroll::revoke_certs(app, by, m, "rebuilt");
}

/// When a rebuild sent at `sent` should have enrolled again by.
fn deadline(e: &Enrollment, sent: i64) -> i64 {
    sent + e.enroll_timeout_ms + BOOT_SLACK_MS
}

/// Sends the rebuild from `from` (`queued` or `retrying`). Caller holds `ops`.
async fn send(app: &App, cp: &ControlPlane, p: &dyn MachineProvider, e: &Enrollment, m: &Machine, from: &str) {
    let Some(id) = m.rebuild_id.clone() else { return };
    // Tried again once the restore is over (ADR 0071).
    if app.db.machine_restoring(&m.id).is_some() {
        return;
    }
    if m.rebuild_attempts >= MAX_ATTEMPTS {
        return fail(app, m, &[from], "attempts", "It was tried as many times as it may be.");
    }
    let Some(pid) = m.provider_id.clone() else {
        return fail(app, m, &[from], "no_provider_id", "It has no provider id.");
    };
    let by = system(m);
    let admin = m.rebuild_by.as_deref().filter(|b| *b != "auto");
    app.db.revoke_machine_tokens(&m.id);
    let (token, expires) = match e.mint_token(app, &m.id, admin) {
        Ok(t) => t,
        Err(why) => return retry_later(app, m, from, from, true, "token", &why),
    };
    app.db.record(&event(&by, "machine.enroll_token_issued", m, json!({ "expiresAt": expires, "via": "rebuild", "rebuildId": id })));
    let spec = RebuildSpec { image: cp.image.clone(), authorized_keys: cp.authorized_keys.clone(), user_data: e.user_data_on(m, &token, super::team_network::subnet_for(app, cp, m)) };
    // Recorded as sent before it is, so a botd that stops mid-call waits for the
    // machine to come back rather than wiping it twice.
    if !app.db.machine_rebuild_sending(&m.id, &id, &[from]) {
        app.db.revoke_machine_tokens(&m.id);
        return;
    }
    let m = app.db.machine(&m.id).unwrap_or_else(|| m.clone());
    forget_old(app, &m);
    let extra = json!({ "providerId": pid, "image": spec.image, "toVersion": super::upkeep::VERSION, "toBuild": e.agent_sha256() });
    match p.rebuild(&pid, &spec).await {
        Ok(()) => {
            wiped(app, &by, &m);
            app.db.record(&event(&by, "machine.rebuild_sent", &m, details(&m, extra)));
        }
        Err(ProviderError::RateLimited) => {
            app.db.revoke_machine_tokens(&m.id);
            let why = ProviderError::RateLimited.to_string();
            app.db.machine_rebuild_move(&m.id, &id, &["rebuilding"], from, false, Some(now() + backoff_ms(m.rebuild_attempts)), Some(&why));
            app.db.record(
                &event(&by, "machine.rebuild_failed", &m, details(&m, json!({ "reason": "rate_limited", "error": why, "retrying": true })))
                    .outcome(Outcome::Failure),
            );
        }
        Err(err) if transient(&err) => {
            // It may have happened: wait for the machine to come back with the new
            // token, and send it again only if it doesn't. Its old agent keeps its
            // certificates and cleanups until then.
            let why = format!("The provider's answer was lost ({err}); waiting to see whether it was rebuilt.");
            app.db.machine_rebuild_move(&m.id, &id, &["rebuilding"], "rebuilding", false, None, Some(&why));
            let mut d = details(&m, extra);
            d["answered"] = json!(false);
            d["error"] = json!(err.to_string());
            app.db.record(&event(&by, "machine.rebuild_sent", &m, d));
        }
        Err(err) => fail(app, &m, &["rebuilding"], "refused", &err.to_string()),
    }
}

/// One step of `machine_id`'s rebuild, if one is underway. Caller holds `ops`.
pub(super) async fn step(app: &App, cp: &ControlPlane, e: &Enrollment, machine_id: &str) {
    let Some(p) = cp.provider.as_deref() else { return };
    let Some(m) = app.db.machine(machine_id).filter(|m| cp.owns(m)) else { return };
    let Some(st) = m.rebuild_state.clone().filter(|_| underway(&m)) else { return };
    let at = now();
    match m.state {
        State::Running => {}
        State::Destroying | State::Destroyed | State::Error => {
            return fail(app, &m, &[st.as_str()], "machine_gone", &format!("The machine is {}.", m.state.as_str()));
        }
        // Suspended or still being made: it waits.
        _ => return,
    }
    match st.as_str() {
        "queued" => {
            if m.rebuild_next_at.is_some_and(|n| n > at) {
                return;
            }
            if m.upgrade_hold_at.is_some() {
                cancel(app, &system(&m), &m, "held");
                return;
            }
            if let Some(why) = unable(cp, e) {
                return fail(app, &m, &["queued"], "unable", why);
            }
            if !m.rebuild_discard && app.db.machine_may_hold_work(&m.id) {
                return fail(app, &m, &["queued"], "may_hold_work", "It may hold the user's files now, and the rebuild wasn't asked to discard them.");
            }
            if m.enrollment != "enrolled" {
                return retry_later(app, &m, "queued", "queued", true, "not_enrolled", "Its agent isn't enrolled, so botd can't check that it's idle.");
            }
            let hb = match enroll::heartbeat(app, e, &m).await {
                Ok(hb) => hb,
                Err(why) => return retry_later(app, &m, "queued", "queued", true, "offline", &format!("Its agent didn't answer: {why}")),
            };
            if !legacy(&hb) {
                cancel(app, &system(&m), &m, "not_needed");
                return;
            }
            if hb.jobs > 0 {
                let id = m.rebuild_id.as_deref().unwrap_or_default();
                let why = format!("Waiting: it's running {} jobs.", hb.jobs);
                app.db.machine_rebuild_move(&m.id, id, &["queued"], "queued", false, Some(at + BUSY_WAIT_MS), Some(&why));
                return;
            }
            send(app, cp, p, e, &m, "queued").await;
        }
        "retrying" => {
            if back(&m) {
                // It enrolled just as the last deadline passed; one that never answers fails.
                if at > deadline(e, m.rebuild_sent_at.unwrap_or(at)) + ANSWER_MS {
                    fail(app, &m, &["retrying"], "no_heartbeat", "It enrolled again but its agent never answered.");
                }
                return;
            }
            if m.rebuild_next_at.is_some_and(|n| n > at) {
                return;
            }
            if let Some(why) = unable(cp, e) {
                return fail(app, &m, &["retrying"], "unable", why);
            }
            // After a lost answer the old agent may still be there: don't wipe it mid-job.
            if m.enrollment == "enrolled"
                && let Ok(hb) = enroll::heartbeat(app, e, &m).await
                && hb.jobs > 0
            {
                let id = m.rebuild_id.as_deref().unwrap_or_default();
                let why = format!("Waiting: it's running {} jobs.", hb.jobs);
                app.db.machine_rebuild_move(&m.id, id, &["retrying"], "retrying", false, Some(at + BUSY_WAIT_MS), Some(&why));
                return;
            }
            send(app, cp, p, e, &m, "retrying").await;
        }
        "rebuilding" => {
            let sent = m.rebuild_sent_at.unwrap_or(at);
            let deadline = deadline(e, sent);
            if back(&m) {
                // The heartbeat loop finishes it; one that never answers fails.
                if at > deadline + ANSWER_MS {
                    fail(app, &m, &["rebuilding"], "no_heartbeat", "It enrolled again but its agent never answered.");
                }
                return;
            }
            // A provider whose rebuild outlasted its answer leaves it stopped; start it
            // here, under the lock, only while it's still meant to be running.
            if let Some(pid) = &m.provider_id
                && let Ok(pm) = p.get(pid).await
                && matches!(pm.status.as_str(), "stopped" | "offline")
                && let Err(err) = p.boot(pid).await
                && !transient(&err)
            {
                crate::obs::log::log_warn!("Machine rebuild: starting {} after its rebuild: {err}", m.id);
            }
            if at > deadline {
                let why = format!("It didn't enroll again within {} minutes of the rebuild.", (deadline - sent) / 60_000);
                app.db.revoke_machine_tokens(&m.id);
                if app.db.machine(&m.id).is_some_and(|m| back(&m)) {
                    return;
                }
                retry_later(app, &m, "rebuilding", "retrying", false, "never_enrolled", &why);
            }
        }
        _ => {}
    }
}

/// Every machine with a rebuild underway, one step each, each under the lock.
pub(super) async fn reconcile(app: &App, cp: &ControlPlane) {
    let Some(e) = cp.enrollment.as_deref() else { return };
    let ids: Vec<String> = app.db.machines(None).into_iter().filter(underway).map(|m| m.id).collect();
    for id in ids {
        let _g = cp.ops.lock().await;
        step(app, cp, e, &id).await;
    }
}

/// Queues a rebuild of `m`. `by`: the admin, or None for MACHINE_LEGACY_REBUILDS=auto.
/// `hb` None: a failed rebuild sent before, whose agent is gone, is sent again
/// (`retrying`) without waiting for it to answer.
fn queue(app: &App, m: &Machine, hb: Option<&Heartbeat>, by: Option<&Who>, discard: bool) -> Option<Machine> {
    let auto = system(m);
    let (by, who) = match by {
        Some(w) => (w, w.actor.id.clone().unwrap_or_default()),
        None => (&auto, "auto".to_string()),
    };
    let id = crate::random_hex(8);
    let from = hb.map(|h| h.version.clone()).or_else(|| m.rebuild_from.clone());
    if !app.db.machine_rebuild_queue(&m.id, &id, &who, discard, from.as_deref()) {
        return None;
    }
    if hb.is_none() && !app.db.machine_rebuild_move(&m.id, &id, &["queued"], "retrying", false, Some(now()), None) {
        return None;
    }
    let m = app.db.machine(&m.id)?;
    let lacks = hb.map_or(CAPABILITIES.to_vec(), |h| lacks(&h.can));
    app.db.record(&event(by, "machine.rebuild_requested", &m, details(&m, json!({ "lacks": lacks, "again": hb.is_none() }))));
    Some(m)
}

/// After a periodic heartbeat: finishes a rebuild whose machine is back, or queues one
/// (MACHINE_LEGACY_REBUILDS=auto) for an idle old machine that never ran Bots.
pub async fn follow_up(app: &AppState, cp: &ControlPlane, e: &Enrollment, machine_id: &str, hb: &Heartbeat) {
    let Some(m) = app.db.machine(machine_id) else { return };
    match m.rebuild_state.as_deref() {
        Some("rebuilding" | "retrying") if back(&m) => {
            let _g = cp.ops.lock().await;
            let Some(m) = app.db.machine(machine_id).filter(back) else { return };
            let from = m.rebuild_state.clone().unwrap_or_default();
            if legacy(hb) {
                return fail(app, &m, &[from.as_str()], "still_legacy", "It came back with an agent that still can't upgrade itself.");
            }
            let id = m.rebuild_id.clone().unwrap_or_default();
            if !app.db.machine_rebuild_move(&m.id, &id, &[from.as_str()], "done", false, None, None) {
                return;
            }
            let m = app.db.machine(machine_id).unwrap_or(m);
            end_cleanups(app, &m, m.rebuild_sent_at.unwrap_or_else(now));
            let by = system(&m);
            app.db.record(&event(&by, "machine.rebuilt", &m, details(&m, json!({ "toVersion": hb.version, "toBuild": hb.build }))));
            if m.assigned_at.is_some() {
                super::folder::assigned(app, cp, &m, &by);
            }
        }
        None if e.upkeep.rebuilds == Rebuilds::Auto
            && cp.owns(&m)
            && legacy(hb)
            && hb.jobs == 0
            && m.upgrade_hold_at.is_none()
            && unable(cp, e).is_none()
            && !app.db.machine_may_hold_work(&m.id) =>
        {
            queue(app, &m, Some(hb), None, false);
        }
        _ => {}
    }
}

// Admin API, under `/api/users/{key}/machine/rebuild` and `/api/machines/legacy`
// (admin only, rbac::classify).

fn view(app: &App, e: &Enrollment, m: &Machine) -> Value {
    let can = can_seen(m);
    json!({
        "machineId": m.id,
        "userId": m.user_id,
        "userEmail": app.db.user(&m.user_id).and_then(|u| u.email),
        "state": m.state,
        "enrollment": m.enrollment,
        "agentVersion": m.agent_version,
        "agentSeenAt": m.agent_seen_at,
        "legacy": can.as_ref().map(|c| !c.iter().any(|x| x == wire::CAN_UPGRADE)),
        "lacks": can.as_ref().map(|c| lacks(c)),
        "assigned": m.assigned_at.is_some(),
        "mayHoldWork": app.db.machine_may_hold_work(&m.id),
        "held": m.upgrade_hold_at.is_some(),
        "rebuilds": e.upkeep.rebuilds.as_str(),
        "rebuild": m.rebuild_id.as_ref().map(|id| json!({
            "id": id, "state": m.rebuild_state, "by": m.rebuild_by, "discardWork": m.rebuild_discard,
            "attempts": m.rebuild_attempts, "maxAttempts": MAX_ATTEMPTS, "requestedAt": m.rebuild_requested_at,
            "at": m.rebuild_at, "sentAt": m.rebuild_sent_at, "nextAt": m.rebuild_next_at, "error": m.rebuild_error,
            "fromVersion": m.rebuild_from,
        })),
    })
}

fn control_plane(app: &App) -> Res<&ControlPlane> {
    app.control_plane.get().map(|cp| &**cp).ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, super::NOT_CONFIGURED.into()))
}

fn need_machine(app: &AppState, key: &str) -> Res<Machine> {
    let u = need_user_key(app, key)?;
    app.db.user_machine(&u.id).ok_or_else(|| crate::not_found("Machine"))
}

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

/// `?discardWork=true`, or nothing.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RebuildQuery {
    #[serde(default)]
    discard_work: bool,
}

/// `GET /api/users/{key}/machine/rebuild`: whether its agent is from before ADR 0039,
/// what it lacks, and its latest rebuild.
pub async fn get(AppS(app): AppS<AppState>, Path(key): Path<String>) -> Res {
    let e = enroll::need(control_plane(&app)?)?;
    let m = need_machine(&app, &key)?;
    Ok(Json(view(&app, e, &m)))
}

/// `POST /api/users/{key}/machine/rebuild[?discardWork=true]`: rebuilds it with today's
/// agent. Its agent must answer and be from before ADR 0039, unless a rebuild sent
/// before failed (it may have none left). 202; it is tried at once,
/// then by the reconciler, and the audit log and `GET` say how it went.
pub async fn request(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
    q: Result<Query<RebuildQuery>, QueryRejection>,
    body: Bytes,
) -> Res<(StatusCode, Json<Value>)> {
    let cp = control_plane(&app)?;
    let e = enroll::need(cp)?;
    let Query(q) = q.map_err(|e| crate::bad(e.body_text()))?;
    if !body.iter().all(u8::is_ascii_whitespace) {
        return Err(crate::bad("It takes no body; pass ?discardWork=true to discard the machine's files."));
    }
    let discard = q.discard_work;
    if let Some(why) = unable(cp, e) {
        return Err(conflict(why));
    }
    let m = need_machine(&app, &key)?;
    let _g = cp.ops.lock().await;
    let m = app.db.machine(&m.id).ok_or_else(|| crate::not_found("Machine"))?;
    cp.need_own(&m)?;
    if underway(&m) {
        return Err(conflict(format!("A rebuild is {} already.", m.rebuild_state.as_deref().unwrap_or_default())));
    }
    if app.db.machine_restoring(&m.id).is_some() {
        return Err(conflict("A restore from a backup is underway."));
    }
    if m.state != State::Running {
        return Err(conflict(format!("The machine is {}; it must be running.", m.state.as_str())));
    }
    if m.upgrade_hold_at.is_some() {
        return Err(conflict("Its agent is held at its build. Release it first (botctl machine upgrade <user> release)."));
    }
    // A rebuild that was sent and failed may have left no agent to answer.
    let again = m.rebuild_state.as_deref() == Some("failed") && m.rebuild_sent_at.is_some();
    let hb = match super::upkeep::fresh(&app, e, &m).await {
        Ok(hb) => Some(hb),
        Err(_) if again => None,
        Err(err) => return Err(err),
    };
    if hb.as_ref().is_some_and(|h| !legacy(h)) {
        return Err(conflict("Its agent can upgrade itself, so it needn't be rebuilt. Use botctl machine upgrade <user>."));
    }
    if !discard && app.db.machine_may_hold_work(&m.id) {
        return Err(conflict(
            "A rebuild wipes its disks, and it is or was assigned, so the user's files may exist only there. \
             Copy off what's needed, then ask again with ?discardWork=true (botctl machine rebuild <user> --discard-work).",
        ));
    }
    let m = queue(&app, &m, hb.as_ref(), Some(&by), discard).ok_or_else(|| conflict("It changed meanwhile; try again."))?;
    step(&app, cp, e, &m.id).await;
    let m = app.db.machine(&m.id).unwrap_or(m);
    Ok((StatusCode::ACCEPTED, Json(view(&app, e, &m))))
}

/// `DELETE /api/users/{key}/machine/rebuild`: cancels a rebuild not yet sent. One sent
/// can't be called back; it ends by itself.
pub async fn cancel_now(AppS(app): AppS<AppState>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res {
    let cp = control_plane(&app)?;
    let e = enroll::need(cp)?;
    let m = need_machine(&app, &key)?;
    let _g = cp.ops.lock().await;
    let m = app.db.machine(&m.id).ok_or_else(|| crate::not_found("Machine"))?;
    if !cancel(&app, &by, &m, "admin") {
        return Err(conflict(match m.rebuild_state.as_deref() {
            Some("retrying" | "rebuilding") => "It was sent to the provider already and can't be called back. It ends by itself.".to_string(),
            s => format!("No rebuild is queued (it is {}).", s.unwrap_or("never asked")),
        }));
    }
    Ok(Json(view(&app, e, &app.db.machine(&m.id).unwrap_or(m))))
}

/// `GET /api/machines/legacy`: machines whose agent is from before ADR 0039, as last
/// heard, and every one with a rebuild underway or failed.
pub async fn legacy_list(AppS(app): AppS<AppState>) -> Res {
    let e = enroll::need(control_plane(&app)?)?;
    let machines: Vec<Value> = app
        .db
        .machines(None)
        .into_iter()
        .filter(|m| m.state != State::Destroyed)
        .filter(|m| {
            underway(m)
                || m.rebuild_state.as_deref() == Some("failed")
                || can_seen(m).is_some_and(|c| !c.iter().any(|x| x == wire::CAN_UPGRADE))
        })
        .map(|m| view(&app, e, &m))
        .collect();
    Ok(Json(json!({ "rebuilds": e.upkeep.rebuilds.as_str(), "machines": machines })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings() {
        assert_eq!(Rebuilds::parse("").unwrap(), Rebuilds::Manual, "manual by default");
        assert_eq!(Rebuilds::parse(" AUTO ").unwrap(), Rebuilds::Auto);
        assert_eq!(Rebuilds::parse("off").unwrap(), Rebuilds::Off);
        assert!(Rebuilds::parse("always").is_err());
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        let mins: Vec<i64> = (1..=8).map(|a| backoff_ms(a) / 60_000).collect();
        assert_eq!(mins, [1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(backoff_ms(0), 60_000);
    }

    #[test]
    fn an_old_agent_lacks_everything_from_adr_0039_on() {
        let old = Heartbeat { version: "0.1.0".into(), ..Default::default() };
        assert!(legacy(&old));
        assert_eq!(lacks(&old.can).len(), CAPABILITIES.len());
        let new: Vec<String> = CAPABILITIES.iter().map(|c| c.to_string()).collect();
        assert!(lacks(&new).is_empty());
        assert!(!legacy(&Heartbeat { can: vec![wire::CAN_UPGRADE.into()], ..old }));
    }
}
