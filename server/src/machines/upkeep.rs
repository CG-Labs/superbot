//! Harness CLIs and agent upgrades on users' machines (ADR 0039). Needs enrollment
//! (MACHINE_CONTROL_URL); with neither setting below, nothing here does anything.
//!
//! - MACHINE_HARNESSES: the harness CLIs every machine gets, e.g. `claude,codex,pi`.
//!   Each is pinned (`adapters::install`); `name@version` picks another exact version,
//!   and `name@version=<checksum>` pins its checksum too. After each heartbeat, an
//!   agent that lacks this plan is sent it, and installs it by itself.
//! - MACHINE_AGENT_UPGRADES: `manual` (the default) upgrades an agent only when an
//!   admin asks; `auto` also upgrades every idle agent whose build isn't botd's, once
//!   per build. Either way an admin can hold one machine at its build.
//!
//! An upgrade is the agent replacing itself with the `superbot-machine` that ships
//! next to botd (`/v1/agent`), checked against the SHA-256 botd sends. botd never
//! sends an older version than the agent's. It is done once botd's heartbeat reaches
//! the new agent; the agent puts the old one back if none does in time.

use super::enroll::{self, Enrollment};
use super::wire::{self, HarnessPlan, HarnessStatus, Heartbeat, UpgradeRequest};
use super::{ControlPlane, event, system};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, now};
use crate::runner::App;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Res};
use axum::Json;
use axum::extract::{Extension, Path, State as AppS};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// botd's version, and so that of the agent it ships.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// An agent still without the plan is sent it again after this long.
const RESEND_MS: i64 = 10 * 60_000;
/// A harness that failed to install is tried again after this long.
const RETRY_FAILED_MS: i64 = 30 * 60_000;
/// An upgrade botd hasn't heard the end of this long after its trial is over failed.
const UPGRADE_GRACE_MS: i64 = 10 * 60_000;

/// MACHINE_AGENT_UPGRADES.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Upgrades {
    #[default]
    Manual,
    Auto,
}

impl Upgrades {
    pub fn as_str(self) -> &'static str {
        match self {
            Upgrades::Manual => "manual",
            Upgrades::Auto => "auto",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Upkeep {
    /// What MACHINE_HARNESSES asks for. None: no harness is installed by botd.
    pub plan: Option<HarnessPlan>,
    pub upgrades: Upgrades,
}

/// `claude,codex@0.172.0,hermes@<commit>=<sha256>`: commas or spaces between.
pub fn parse_harnesses(raw: &str) -> Result<Option<HarnessPlan>, String> {
    let mut list = Vec::new();
    for item in raw.split([',', ' ', '\t', '\n']).map(str::trim).filter(|s| !s.is_empty()) {
        let (spec, checksum) = item.split_once('=').map_or((item, None), |(s, c)| (s, Some(c)));
        let (name, version) = spec.split_once('@').map_or((spec, None), |(n, v)| (n, Some(v)));
        let h = crate::adapters::install::install(&name.to_ascii_lowercase(), version, checksum)
            .map_err(|e| format!("MACHINE_HARNESSES: {e}"))?;
        if list.iter().any(|o: &wire::HarnessInstall| o.name == h.name) {
            return Err(format!("MACHINE_HARNESSES names {} twice", h.name));
        }
        list.push(h);
    }
    if list.is_empty() {
        return Ok(None);
    }
    let plan = crate::adapters::install::plan(list);
    super::tools::check(&plan).map_err(|e| format!("MACHINE_HARNESSES: {e}"))?;
    Ok(Some(plan))
}

impl Upkeep {
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Upkeep, String> {
        let upgrades = match var("MACHINE_AGENT_UPGRADES").trim().to_ascii_lowercase().as_str() {
            "" | "manual" => Upgrades::Manual,
            "auto" => Upgrades::Auto,
            v => return Err(format!("MACHINE_AGENT_UPGRADES must be manual or auto, not \"{v}\"")),
        };
        Ok(Upkeep { plan: parse_harnesses(&var("MACHINE_HARNESSES"))?, upgrades })
    }

    pub fn describe(&self) -> String {
        let harnesses = self.plan.as_ref().map_or("none".into(), |p| names(p).join(", "));
        format!("harnesses on machines: {harnesses}; agent upgrades: {}", self.upgrades.as_str())
    }
}

fn names(p: &HarnessPlan) -> Vec<String> {
    p.harnesses.iter().map(|h| format!("{}@{}", h.name, short(&h.version))).collect()
}

fn short(s: &str) -> &str {
    if s.len() > 16 { &s[..12] } else { s }
}

/// a.b.c, for "is it newer". None if it isn't one.
fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let v = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(v)
}

/// Whether the agent's version is newer than botd's: then botd won't replace it.
fn newer(agent: &str) -> bool {
    match (semver(agent), semver(VERSION)) {
        (Some(a), Some(b)) => a > b,
        _ => agent != VERSION,
    }
}

fn upkeep_json(hb: &Heartbeat) -> Value {
    json!({ "can": hb.can, "build": hb.build, "plan": hb.plan, "harnesses": hb.harnesses, "upgrade": hb.upgrade })
}

/// Records what a heartbeat says of harnesses and upgrades, and what changed, in the
/// audit log. Every answered heartbeat comes here, so a change is recorded once.
pub fn observe(app: &App, machine_id: &str, hb: &Heartbeat) {
    let Some(m) = app.db.machine(machine_id) else { return };
    let new = upkeep_json(hb);
    if m.agent_upkeep.as_ref() != Some(&new) {
        let old: BTreeMap<String, HarnessStatus> = m
            .agent_upkeep
            .as_ref()
            .and_then(|v| serde_json::from_value(v["harnesses"].clone()).ok())
            .unwrap_or_default();
        if !app.db.machine_upkeep_swap(&m.id, m.agent_upkeep.as_ref(), &new) {
            return;
        }
        let by = system(&m);
        for (name, st) in &hb.harnesses {
            let was = old.get(name);
            if st.state == wire::HARNESS_INSTALLED && was.is_none_or(|w| w.state != st.state || w.version != st.version) {
                app.db.record(&event(&by, "machine.harness_installed", &m, json!({ "harness": name, "version": st.version })));
            }
            if st.state == wire::HARNESS_FAILED && was.is_none_or(|w| w.state != st.state || w.at != st.at) {
                app.db.record(
                    &event(&by, "machine.harness_install_failed", &m, json!({ "harness": name, "version": st.wanted, "error": st.error }))
                        .outcome(Outcome::Failure),
                );
            }
        }
    }
    let (Some(id), Some(report)) = (&m.upgrade_id, hb.upgrade.as_ref()) else { return };
    if report.id != *id {
        return;
    }
    let details = json!({
        "upgradeId": id, "by": m.upgrade_by, "fromVersion": report.from_version, "fromBuild": report.from_build,
        "toVersion": report.to_version, "toBuild": report.to_build,
    });
    match report.state.as_str() {
        wire::UPGRADE_DONE if app.db.machine_upgrade_end(&m.id, id, None) => {
            app.db.record(&event(&system(&m), "machine.agent_upgraded", &m, details));
        }
        wire::UPGRADE_ROLLED_BACK | wire::UPGRADE_FAILED if app.db.machine_upgrade_end(&m.id, id, m.upgrade_build.as_deref()) => {
            let mut d = details;
            d["reason"] = json!(report.state);
            d["error"] = json!(report.reason);
            app.db.record(&event(&system(&m), "machine.agent_upgrade_failed", &m, d).outcome(Outcome::Failure));
        }
        _ => {}
    }
}

/// How long a new agent is on trial: a few heartbeats.
fn trial_secs(cp: &ControlPlane) -> u64 {
    (cp.reconcile_every.as_secs() * 3).clamp(300, 86_400)
}

/// Why `m`'s agent can't be upgraded to botd's build now, if it can't.
fn blocker(e: &Enrollment, m: &Machine, hb: &Heartbeat) -> Option<String> {
    let Some(served) = e.agent_sha256() else {
        return Some("superbot-machine isn't next to botd, so there's no build to upgrade to.".into());
    };
    if hb.build.as_deref() == Some(served) {
        return Some("Its agent is botd's build already.".into());
    }
    if !hb.can.iter().any(|c| c == wire::CAN_UPGRADE) {
        return Some("Its agent can't replace itself: it was installed before agent upgrades (ADR 0039). Reinstall it.".into());
    }
    if newer(&hb.version) {
        return Some(format!("Its agent ({}) is newer than botd ({VERSION}), and botd doesn't downgrade agents.", hb.version));
    }
    if m.upgrade_hold_at.is_some() {
        return Some("Its agent is held at its build. Release it first.".into());
    }
    if hb.jobs > 0 {
        return Some(format!("It's running {} jobs. Upgrade it when they're done.", hb.jobs));
    }
    None
}

/// Asks `m`'s agent to upgrade itself to botd's build. `by`: who asked, or None when
/// no one did (MACHINE_AGENT_UPGRADES=auto).
async fn upgrade(app: &App, cp: &ControlPlane, e: &Enrollment, m: &Machine, hb: &Heartbeat, by: Option<&Who>) -> Result<Value, ApiError> {
    let conflict = |msg: String| ApiError(StatusCode::CONFLICT, msg);
    if let Some(why) = blocker(e, m, hb) {
        return Err(conflict(why));
    }
    let served = e.agent_sha256().unwrap_or_default().to_string();
    let trial = trial_secs(cp);
    let stale = now() - (trial as i64 * 1000 + UPGRADE_GRACE_MS);
    let id = crate::short_id().replace('-', "");
    let auto = system(m);
    let (by, who) = match by {
        Some(w) => (w, w.actor.id.clone().unwrap_or_default()),
        None => (&auto, "auto".to_string()),
    };
    if !app.db.machine_upgrade_claim(&m.id, &id, &served, &who, stale) {
        let held = app.db.machine(&m.id).is_some_and(|m| m.upgrade_hold_at.is_some());
        return Err(conflict(if held {
            "Its agent is held at its build. Release it first.".into()
        } else {
            "An upgrade is on its way to it already.".into()
        }));
    }
    let req = UpgradeRequest {
        id: id.clone(),
        version: VERSION.into(),
        sha256: served.clone(),
        botctl_sha256: e.botctl_sha256().map(String::from),
        trial_secs: trial,
    };
    let details = json!({
        "upgradeId": id, "by": who, "fromVersion": hb.version, "fromBuild": hb.build, "toVersion": VERSION, "toBuild": served,
    });
    match e.call_agent(app, m, reqwest::Method::POST, "/v1/upgrade", &req).await {
        Ok((202, _)) => {
            app.db.record(&event(by, "machine.agent_upgrade_requested", m, details.clone()));
            Ok(details)
        }
        res => {
            let (code, why) = match res {
                Ok((code, body)) => (code, body["error"].as_str().unwrap_or("no reason given").to_string()),
                Err(e) => (0, e),
            };
            // A bad request won't get better; anything else may next time.
            let failed = (code == 400).then_some(served.as_str());
            app.db.machine_upgrade_end(&m.id, &id, failed);
            let mut d = details;
            d["reason"] = json!("refused");
            d["error"] = json!(why);
            app.db.record(&event(by, "machine.agent_upgrade_failed", m, d).outcome(Outcome::Failure));
            Err(ApiError(StatusCode::BAD_GATEWAY, format!("Its agent didn't take the upgrade: {why}")))
        }
    }
}

/// Sends `m`'s agent the harness plan.
async fn send_plan(app: &App, e: &Enrollment, m: &Machine, plan: &HarnessPlan, by: &Who) -> Result<Value, ApiError> {
    let details = json!({ "planId": plan.id(), "harnesses": names(plan) });
    match e.call_agent(app, m, reqwest::Method::PUT, "/v1/harnesses", plan).await {
        Ok((202, _)) => {
            app.db.machine_harnesses_sent(&m.id, &plan.id());
            app.db.record(&event(by, "machine.harnesses_requested", m, details.clone()));
            Ok(details)
        }
        res => {
            let why = match res {
                Ok((code, body)) => body["error"].as_str().map_or(format!("it answered {code}"), String::from),
                Err(e) => e,
            };
            app.db.machine_harnesses_sent(&m.id, &plan.id());
            let mut d = details;
            d["error"] = json!(why);
            app.db.record(&event(by, "machine.harnesses_requested", m, d).outcome(Outcome::Failure));
            Err(ApiError(StatusCode::BAD_GATEWAY, format!("Its agent didn't take the harness plan: {why}")))
        }
    }
}

/// Whether the agent should be sent the plan now.
fn plan_due(plan: &HarnessPlan, m: &Machine, hb: &Heartbeat, at: i64) -> bool {
    if !hb.can.iter().any(|c| c == wire::CAN_HARNESSES) {
        return false;
    }
    let id = plan.id();
    let sent = m.harnesses_sent_plan.as_deref() == Some(id.as_str()) && m.harnesses_sent_at.is_some_and(|s| at - s < RESEND_MS);
    if sent {
        return false;
    }
    hb.plan.as_deref() != Some(id.as_str())
        || plan.harnesses.iter().any(|h| {
            hb.harnesses.get(&h.name).is_some_and(|s| s.state == wire::HARNESS_FAILED && at - s.at > RETRY_FAILED_MS)
        })
}

/// Ends `m`'s upgrade as failed if its agent hasn't said how it went in time, answering
/// or not. Its build isn't tried again by itself.
pub fn expire_upgrade(app: &App, cp: &ControlPlane, m: &Machine) {
    let (Some(id), Some(at)) = (&m.upgrade_id, m.upgrade_sent_at) else { return };
    if now() - at > trial_secs(cp) as i64 * 1000 + UPGRADE_GRACE_MS
        && app.db.machine_upgrade_end(&m.id, id, m.upgrade_build.as_deref())
    {
        let d = json!({ "upgradeId": id, "by": m.upgrade_by, "toBuild": m.upgrade_build, "reason": "timeout", "error": "it never said how the upgrade went" });
        app.db.record(&event(&system(m), "machine.agent_upgrade_failed", m, d).outcome(Outcome::Failure));
    }
}

/// After a periodic heartbeat: ends an upgrade that never finished, then sends an
/// upgrade (MACHINE_AGENT_UPGRADES=auto) or the harness plan, if either is due.
pub async fn follow_up(app: &App, cp: &ControlPlane, e: &Enrollment, machine_id: &str, hb: &Heartbeat) {
    let Some(m) = app.db.machine(machine_id) else { return };
    if m.upgrade_id.is_some() {
        expire_upgrade(app, cp, &m);
        return;
    }
    let auto = e.upkeep.upgrades == Upgrades::Auto
        && blocker(e, &m, hb).is_none()
        && m.upgrade_failed_build.as_deref() != e.agent_sha256();
    if auto {
        let _ = upgrade(app, cp, e, &m, hb, None).await;
        return;
    }
    if let Some(plan) = &e.upkeep.plan
        && plan_due(plan, &m, hb, now())
    {
        let _ = send_plan(app, e, &m, plan, &system(&m)).await;
    }
}

// Admin API, under `/api/users/{key}/machine/agent` (admin only, rbac::classify).

fn view(e: &Enrollment, m: &Machine) -> Value {
    let agent = m.agent_upkeep.clone().unwrap_or(json!({}));
    json!({
        "machineId": m.id,
        "agentVersion": m.agent_version,
        "agentSeenAt": m.agent_seen_at,
        "agentError": m.agent_error,
        "agent": agent,
        "botd": {
            "version": VERSION,
            "build": e.agent_sha256(),
            "upgrades": e.upkeep.upgrades.as_str(),
            "harnesses": e.upkeep.plan.as_ref().map(names),
            "planId": e.upkeep.plan.as_ref().map(HarnessPlan::id),
        },
        "upToDate": e.agent_sha256().is_some() && agent["build"].as_str() == e.agent_sha256(),
        "upgrade": m.upgrade_id.as_ref().map(|id| json!({ "id": id, "build": m.upgrade_build, "sentAt": m.upgrade_sent_at, "by": m.upgrade_by })),
        "hold": m.upgrade_hold_at.map(|at| json!({ "at": at, "by": m.upgrade_hold_by })),
        "failedBuild": m.upgrade_failed_build,
    })
}

/// The control plane from botd's own state, never from the request.
fn control_plane(app: &App) -> Res<&ControlPlane> {
    app.control_plane.get().map(|cp| &**cp).ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, super::NOT_CONFIGURED.into()))
}

fn need_machine(app: &AppState, key: &str) -> Res<Machine> {
    let u = need_user_key(app, key)?;
    app.db.user_machine(&u.id).ok_or_else(|| crate::not_found("Machine"))
}

/// A heartbeat now, so what follows acts on how the agent is.
async fn fresh(app: &App, e: &Enrollment, m: &Machine) -> Res<Heartbeat> {
    if m.enrollment != "enrolled" {
        return Err(ApiError(StatusCode::CONFLICT, "Its agent isn't enrolled.".into()));
    }
    enroll::heartbeat(app, e, m)
        .await
        .map_err(|why| ApiError(StatusCode::BAD_GATEWAY, format!("Its agent didn't answer: {why}")))
}

/// `GET /api/users/{key}/machine/agent`: its agent's build, harnesses and upgrades,
/// as last heard, against botd's.
pub async fn get(AppS(app): AppS<AppState>, Path(key): Path<String>) -> Res {
    let e = enroll::need(control_plane(&app)?)?;
    let m = need_machine(&app, &key)?;
    Ok(Json(view(e, &m)))
}

/// `POST /api/users/{key}/machine/agent/upgrade`: upgrades its agent to botd's build
/// now, even one that failed before. 202; the audit log and `GET` say how it went.
pub async fn upgrade_now(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res<(StatusCode, Json<Value>)> {
    let cp = control_plane(&app)?;
    let e = enroll::need(cp)?;
    let m = need_machine(&app, &key)?;
    let hb = fresh(&app, e, &m).await?;
    upgrade(&app, cp, e, &m, &hb, Some(&by)).await?;
    let m = app.db.machine(&m.id).unwrap_or(m);
    Ok((StatusCode::ACCEPTED, Json(view(e, &m))))
}

/// `PUT /api/users/{key}/machine/agent/hold`: nothing upgrades its agent until released.
pub async fn hold(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res {
    let e = enroll::need(control_plane(&app)?)?;
    let m = need_machine(&app, &key)?;
    if app.db.machine_upgrade_hold(&m.id, Some(by.actor.id.as_deref())) {
        app.db.record(&event(&by, "machine.agent_upgrade_held", &m, json!({ "build": m.agent_upkeep.as_ref().map(|u| u["build"].clone()) })));
    }
    Ok(Json(view(e, &app.db.machine(&m.id).unwrap_or(m))))
}

/// `DELETE /api/users/{key}/machine/agent/hold`: its agent may be upgraded again, and
/// a build that failed before may be tried again.
pub async fn release(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res {
    let e = enroll::need(control_plane(&app)?)?;
    let m = need_machine(&app, &key)?;
    if app.db.machine_upgrade_hold(&m.id, None) {
        app.db.machine_upgrade_forget_failure(&m.id);
        app.db.record(&event(&by, "machine.agent_upgrade_released", &m, json!({})));
    }
    Ok(Json(view(e, &app.db.machine(&m.id).unwrap_or(m))))
}

/// `POST /api/users/{key}/machine/harnesses`: sends its agent the harness plan now;
/// harnesses that failed are tried again.
pub async fn harnesses_now(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res<(StatusCode, Json<Value>)> {
    let e = enroll::need(control_plane(&app)?)?;
    let plan = e
        .upkeep
        .plan
        .as_ref()
        .ok_or_else(|| ApiError(StatusCode::CONFLICT, "MACHINE_HARNESSES is empty, so there's nothing to install.".into()))?;
    let m = need_machine(&app, &key)?;
    let hb = fresh(&app, e, &m).await?;
    if !hb.can.iter().any(|c| c == wire::CAN_HARNESSES) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "Its agent can't install harnesses: it was installed before ADR 0039. Upgrade or reinstall it.".into(),
        ));
    }
    send_plan(&app, e, &m, plan, &by).await?;
    let m = app.db.machine(&m.id).unwrap_or(m);
    Ok((StatusCode::ACCEPTED, Json(view(e, &m))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings() {
        let none = |_: &str| String::new();
        let u = Upkeep::from_env(&none).unwrap();
        assert!(u.plan.is_none() && u.upgrades == Upgrades::Manual, "off by default");
        let env = |k: &str| match k {
            "MACHINE_HARNESSES" => "claude, Codex@0.172.0 pi".into(),
            "MACHINE_AGENT_UPGRADES" => "AUTO".into(),
            _ => String::new(),
        };
        let u = Upkeep::from_env(&env).unwrap();
        assert_eq!(u.upgrades, Upgrades::Auto);
        let p = u.plan.unwrap();
        assert_eq!(names(&p), ["claude@2.1.329", "codex@0.172.0", "pi@1.5.2"]);
        assert!(p.node.is_some());
        for (k, v) in [
            ("MACHINE_HARNESSES", "claude,claude"),
            ("MACHINE_HARNESSES", "claude@latest"),
            ("MACHINE_HARNESSES", "cursor"),
            ("MACHINE_HARNESSES", "pi@1.5.2=sha512-short"),
            ("MACHINE_AGENT_UPGRADES", "always"),
        ] {
            let bad = |key: &str| if key == k { v.to_string() } else { String::new() };
            assert!(Upkeep::from_env(&bad).is_err(), "{k}={v}");
        }
    }

    #[test]
    fn botd_never_downgrades() {
        assert_eq!(semver("0.10.2"), Some((0, 10, 2)));
        assert_eq!(semver("1.2"), None);
        assert!(!newer(VERSION));
        assert!(newer("99.0.0"));
        assert!(!newer("0.0.1"));
        assert!(newer("not-a-version"), "an agent botd can't place is left alone");
    }
}
