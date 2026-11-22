//! What disabling someone stops at once, whether the IdP deactivates or deletes them over
//! SCIM or an admin turns them off: every run and queued message on their Bots, the runs
//! on others' Bots that are for them, and their own machine, powered off
//! (`MACHINE_ON_DISABLE=suspend`, the default) and held off until they're enabled again.
//! Sessions, routines, screens and teammates' machines are already handled where the
//! user is disabled (ADR 0012, 0047, 0052). Design: docs/adr/0124-deprovisioning-stops-bots-and-machines.md.

use crate::AppState;
use crate::audit::{Actor, Outcome, Source, Who};
use crate::machines::{ControlPlane, State, Step};
use serde_json::{Value, json};

/// How the user was turned off, in `user.deprovisioned`.
pub const ADMIN: &str = "admin";
pub const SCIM: &str = "scim";
pub const SCIM_DELETE: &str = "scim_delete";

fn control_plane(app: &AppState) -> Option<&ControlPlane> {
    app.control_plane.get().map(|cp| cp.as_ref()).filter(|cp| cp.enabled())
}

fn system(user_id: &str) -> Who {
    Who { actor: Actor::system("deprovision").on_behalf_of(user_id), source: Source::default() }
}

fn disabled(app: &AppState, user_id: &str) -> bool {
    !app.db.user(user_id).is_some_and(|u| u.active())
}

/// `user_id` was just disabled (`via`): stops their Bots' work and the work on others'
/// Bots for them, and powers their machine off. Recorded as `user.deprovisioned` with
/// what it stopped. Safe to call again: what is already stopped or off is left alone.
pub async fn user_disabled(app: &AppState, by: &Who, user_id: &str, via: &str) -> Value {
    let mut stopped = Vec::new();
    for b in app.db.bots().into_iter().filter(|b| b.owner_id == user_id) {
        if app.busy(&b.id) {
            app.stop(&b.id);
            stopped.push(b.id);
        }
    }
    let for_them: Vec<String> = app.stop_for_user(user_id).into_iter().filter(|id| !stopped.contains(id)).collect();
    let machine = suspend(app, by, user_id, via).await;
    let details = json!({ "via": via, "botsStopped": stopped, "runsForThemStopped": for_them, "machine": machine });
    app.db.record(&by.event("user.deprovisioned").target("user", user_id).details(details.clone()));
    details
}

/// Powers off `user_id`'s machine for being disabled and holds it off. One not yet
/// running is held, and the reconciler powers it off once it is.
async fn suspend(app: &AppState, by: &Who, user_id: &str, via: &str) -> Value {
    let Some(cp) = control_plane(app) else { return json!({ "state": "none" }) };
    let Some(m) = app.db.user_machine(user_id) else { return json!({ "state": "none" }) };
    if !cp.suspend_on_disable {
        return json!({ "id": m.id, "state": "kept" });
    }
    let state = match m.state {
        State::Suspended if !app.db.disable_hold(&m.id) => "already_suspended",
        State::Suspended => "suspended",
        State::Destroying | State::Destroyed | State::Error => "gone",
        State::Running => {
            app.db.hold_for_disable(&m.id, user_id, via);
            power_off(app, cp, by, user_id, &m.id).await
        }
        State::Pending | State::Provisioning => {
            app.db.hold_for_disable(&m.id, user_id, via);
            "held"
        }
    };
    json!({ "id": m.id, "state": state })
}

/// Suspends `machine_id` if it is still `user_id`'s, running, and they're still disabled.
async fn power_off(app: &AppState, cp: &ControlPlane, by: &Who, user_id: &str, machine_id: &str) -> &'static str {
    let still = |m: &crate::db::Machine| m.id == machine_id && disabled(app, user_id);
    let _ = crate::machines::act_if(app, cp, by, user_id, Step::Suspend, None, &still).await;
    match app.db.machine(machine_id).map(|m| m.state) {
        Some(State::Suspended) => "suspended",
        _ => "failed",
    }
}

/// `user_id` was just enabled: the machine their disable powered off comes back on,
/// unless a team released it meanwhile (ADR 0087 handles that one). Never a machine an
/// admin suspended by hand. What happened, if there was a hold.
pub async fn user_enabled(app: &AppState, by: &Who, user_id: &str) -> Option<&'static str> {
    let cp = control_plane(app)?;
    let m = app.db.user_machine(user_id)?;
    if !app.db.drop_disable_hold(&m.id) {
        return None;
    }
    Some(resume(app, cp, by, user_id, &m).await)
}

async fn resume(app: &AppState, cp: &ControlPlane, by: &Who, user_id: &str, m: &crate::db::Machine) -> &'static str {
    if app.db.team_machine(&m.id).is_some_and(|t| t.released_at.is_some()) {
        return "team_released";
    }
    if m.state != State::Suspended {
        return "not_suspended";
    }
    let still = |x: &crate::db::Machine| x.id == m.id && x.state == State::Suspended && !disabled(app, user_id);
    let _ = crate::machines::act_if(app, cp, by, user_id, Step::Resume, None, &still).await;
    let resumed = app.db.machine(&m.id).is_some_and(|x| x.state == State::Running);
    let e = by.event("user.machine_resumed").target("user", user_id).details(json!({ "machine": m.id, "resumed": resumed }));
    app.db.record(&e.outcome(if resumed { Outcome::Success } else { Outcome::Failure }));
    if resumed { "resumed" } else { "failed" }
}

/// On every reconcile: a held machine whose user is still disabled is powered off once
/// it runs (one still being built, or one whose power-off failed); one whose user was
/// enabled another way comes back on; one that's gone loses its hold.
pub async fn sweep(app: &AppState, cp: &ControlPlane) -> Value {
    let (mut suspended, mut resumed) = (0, 0);
    for (machine_id, user_id, _) in app.db.disable_holds() {
        let Some(m) = app.db.machine(&machine_id).filter(|m| m.user_id == user_id && !matches!(m.state, State::Destroying | State::Destroyed | State::Error)) else {
            app.db.drop_disable_hold(&machine_id);
            continue;
        };
        let by = system(&user_id);
        if !disabled(app, &user_id) {
            app.db.drop_disable_hold(&machine_id);
            resumed += (resume(app, cp, &by, &user_id, &m).await == "resumed") as u32;
        } else if m.state == State::Running && cp.suspend_on_disable {
            suspended += (power_off(app, cp, &by, &user_id, &machine_id).await == "suspended") as u32;
        }
    }
    let mut out = json!({});
    if suspended > 0 {
        out["suspended"] = suspended.into();
    }
    if resumed > 0 {
        out["resumed"] = resumed.into();
    }
    out
}
