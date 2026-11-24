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
use super::hermes_serve::{self, Bundles};
use super::mirror::{self, Mirrors};
use super::wire::{self, BundleKind, HarnessPlan, HarnessStatus, Heartbeat, UpgradeRequest};
use super::{ControlPlane, event, system};
use crate::adapters::install;
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
    /// MACHINE_LEGACY_REBUILDS (ADR 0056).
    pub rebuilds: super::rebuild::Rebuilds,
    /// MACHINE_HARNESSES was left unset, so the managed tiers' defaults may fill it in.
    pub unset: bool,
    /// The plan is the managed tiers' default harnesses, not MACHINE_HARNESSES (ADR 0079).
    pub defaulted: bool,
    /// Where machines fetch the plan's Node.js and npm harnesses instead (ADR 0186).
    pub mirrors: Option<Mirrors>,
    /// Where machines fetch Hermes Agent instead of from its installer (ADR 0210).
    pub hermes: Option<Bundles>,
    /// Where machines fetch Claude Code, Codex and Pi instead of from npm (ADR 0242).
    pub harness_bundle: Option<Bundles>,
}

/// `claude,codex@0.172.0,hermes@<commit>=<sha256>`: commas or spaces between. `none`:
/// nothing.
pub fn parse_harnesses(raw: &str) -> Result<Option<HarnessPlan>, String> {
    if raw.trim().eq_ignore_ascii_case("none") {
        return Ok(None);
    }
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
    /// Settings from `var`; the npm registry's login from `store`, botd's secrets.
    pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn crate::secrets::SecretStore) -> Result<Upkeep, String> {
        let upgrades = match var("MACHINE_AGENT_UPGRADES").trim().to_ascii_lowercase().as_str() {
            "" | "manual" => Upgrades::Manual,
            "auto" => Upgrades::Auto,
            v => return Err(format!("MACHINE_AGENT_UPGRADES must be manual or auto, not \"{v}\"")),
        };
        let rebuilds = super::rebuild::Rebuilds::parse(&var("MACHINE_LEGACY_REBUILDS"))?;
        let raw = var("MACHINE_HARNESSES");
        let mirrors = Mirrors::from_env(var, store)?;
        let hermes = Bundles::from_env(var, BundleKind::Hermes)?;
        let harness_bundle = Bundles::from_env(var, BundleKind::Harnesses)?;
        let mut u = Upkeep { plan: None, upgrades, rebuilds, unset: raw.trim().is_empty(), defaulted: false, mirrors, hermes, harness_bundle };
        u.plan = parse_harnesses(&raw)?.map(|p| u.served(p)).transpose()?;
        Ok(u)
    }

    /// With MACHINE_HARNESSES unset, every machine gets the managed tiers' default
    /// harnesses at their pins, so a new Bot on a managed plan can run on its owner's
    /// machine (ADR 0079). `MACHINE_HARNESSES=none` keeps machines bare.
    pub fn default_to(&mut self, harnesses: &[&str]) -> Result<(), String> {
        if !self.unset || self.plan.is_some() || harnesses.is_empty() {
            return Ok(());
        }
        self.plan = parse_harnesses(&harnesses.join(","))
            .map_err(|e| format!("the managed tiers' default harnesses: {e}"))?
            .map(|p| self.served(p))
            .transpose()?;
        self.defaulted = self.plan.is_some();
        Ok(())
    }

    /// Harnesses in `wanted` that machines won't get from botd.
    pub fn lacks<'a>(&self, wanted: &[&'a str]) -> Vec<&'a str> {
        wanted.iter().copied().filter(|h| self.plan.as_ref().is_none_or(|p| !p.harnesses.iter().any(|i| i.name == *h))).collect()
    }

    pub fn describe(&self) -> String {
        let harnesses = self.plan.as_ref().map_or("none".into(), |p| names(p).join(", "));
        let harnesses = if self.defaulted { format!("{harnesses} (the managed tiers' default; MACHINE_HARNESSES=none for none)") } else { harnesses };
        let mirrors = self.mirrors.as_ref().map_or(String::new(), |m| format!("; {}", m.describe(self.plan.as_ref())));
        let hermes = self.hermes.as_ref().map_or(String::new(), |h| format!("; {}", h.describe(self.plan.as_ref())));
        let clis = self.harness_bundle.as_ref().map_or(String::new(), |h| format!("; {}", h.describe(self.plan.as_ref())));
        format!(
            "harnesses on machines: {harnesses}{clis}{mirrors}{hermes}; agent upgrades: {}; rebuilds of old machines: {}",
            self.upgrades.as_str(),
            self.rebuilds.as_str()
        )
    }

    /// `plan` from where machines fetch it: botd's harness bundles, the mirrors for
    /// what those don't hold, and botd's Hermes bundles.
    fn served(&self, mut plan: HarnessPlan) -> Result<HarnessPlan, String> {
        if let Some(b) = &self.harness_bundle {
            plan = b.apply(plan)?;
        }
        if let Some(m) = &self.mirrors {
            plan = m.apply(plan);
        }
        if let Some(h) = &self.hermes {
            plan = h.apply(plan)?;
        }
        let keys: Vec<&str> = [&self.harness_bundle, &self.hermes].into_iter().flatten().map(|b| hermes_serve::key(b.kind)).collect();
        if !keys.is_empty() {
            super::tools::check(&plan).map_err(|e| format!("{}: {e}", keys.join(", ")))?;
        }
        Ok(plan)
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
    let (egress, limits) = super::egress_policy::upkeep_json(hb);
    // Logging in means no login is saved yet.
    let logins: BTreeMap<&String, &str> = hb
        .logins
        .iter()
        .map(|(h, l)| (h, if l.state == wire::LOGGED_IN { wire::LOGGED_IN } else { wire::LOGGED_OUT }))
        .collect();
    json!({
        "can": hb.can, "build": hb.build, "plan": hb.plan, "harnesses": hb.harnesses, "upgrade": hb.upgrade, "logins": logins,
        "botUser": super::botuser::upkeep_json(hb),
        "screens": super::screens::upkeep_json(hb),
        "teammates": hb.teammates,
        "hardening": hb.hardening,
        "egressPolicy": egress, "runLimits": limits,
        "teamNetwork": hb.team_network,
    })
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
        let old_logins: BTreeMap<String, String> = m
            .agent_upkeep
            .as_ref()
            .and_then(|v| serde_json::from_value(v["logins"].clone()).ok())
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
        // A login made or lost there, however it happened (ADR 0041).
        let logins: BTreeMap<String, String> = serde_json::from_value(new["logins"].clone()).unwrap_or_default();
        for (name, now) in &logins {
            let was = old_logins.get(name);
            if was.map_or(now == wire::LOGGED_IN, |w| w != now) {
                app.db.record(&event(&by, "machine.harness_login_changed", &m, json!({ "harness": name, "from": was, "to": now })));
            }
        }
        super::botuser::observed(app, &m, &by, m.agent_upkeep.as_ref().map(|v| &v["botUser"]), &new["botUser"]);
        super::hardening::observed(app, &m, &by, m.agent_upkeep.as_ref().map(|v| &v["hardening"]), &new["hardening"]);
        super::egress_policy::observed(app, &m, &by, m.agent_upkeep.as_ref(), &new);
        super::team_network::observed(app, &m, &by, m.agent_upkeep.as_ref(), &new);
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

/// An upgrade sent before this, and not heard of since, no longer counts as on its way.
fn stale_before(cp: &ControlPlane) -> i64 {
    now() - (trial_secs(cp) as i64 * 1000 + UPGRADE_GRACE_MS)
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
        return Some("Its agent can't replace itself: it was installed before agent upgrades (ADR 0039). Rebuild it with today's agent: botctl machine rebuild <user> (ADR 0056).".into());
    }
    if newer(&hb.version) {
        return Some(format!("Its agent ({}) is newer than botd ({VERSION}), and botd doesn't downgrade agents.", hb.version));
    }
    if m.upgrade_hold_at.is_some() {
        return Some("Its agent is held at its build. Release it first.".into());
    }
    if hb.jobs > 0 {
        return Some(format!("It's running {} jobs or logins. Upgrade it when they're done.", hb.jobs));
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
    let stale = stale_before(cp);
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

/// Whether an agent that says `can` installs `plan`. One from before ADR 0186 would
/// refuse a plan with mirrors in it, or fetch it from the internet; one from before
/// ADR 0210 would refuse a Hermes bundle; one from before ADR 0219 would refuse a plan
/// whose registry needs a login; one from before ADR 0242 would refuse a harness bundle.
fn takes(plan: &HarnessPlan, can: &[String]) -> bool {
    let has = |c: &str| can.iter().any(|x| x == c);
    has(wire::CAN_HARNESSES)
        && (!mirror::needs_agent_support(plan) || has(wire::CAN_HARNESS_MIRRORS))
        && (!hermes_serve::bundled(plan) || has(wire::CAN_HARNESS_BUNDLES))
        && (!hermes_serve::bundled_kind(plan, BundleKind::Harnesses) || has(wire::CAN_HARNESS_CLI_BUNDLES))
        && (!plan.npm_login || has(wire::CAN_HARNESS_MIRROR_LOGIN))
}

/// Whether the agent should be sent the plan now.
fn plan_due(plan: &HarnessPlan, m: &Machine, hb: &Heartbeat, at: i64) -> bool {
    if !takes(plan, &hb.can) {
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
    if at < stale_before(cp)
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
    if let Some(plan) = e.upkeep.plan.as_ref().map(|p| install::plan_for(p, &hb.can))
        && plan_due(&plan, &m, hb, now())
    {
        let _ = send_plan(app, e, &m, &plan, &system(&m)).await;
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
pub(super) async fn fresh(app: &App, e: &Enrollment, m: &Machine) -> Res<Heartbeat> {
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
/// 409 while an upgrade is on its way, since that one can't be called back.
pub async fn hold(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res {
    let cp = control_plane(&app)?;
    let e = enroll::need(cp)?;
    let m = need_machine(&app, &key)?;
    if app.db.machine_upgrade_hold(&m.id, by.actor.id.as_deref(), stale_before(cp)) {
        app.db.record(&event(&by, "machine.agent_upgrade_held", &m, json!({ "build": m.agent_upkeep.as_ref().map(|u| u["build"].clone()) })));
    }
    let m = app.db.machine(&m.id).unwrap_or(m);
    if m.upgrade_hold_at.is_none() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "An upgrade is on its way to it. Hold it once that upgrade is done or has failed.".into(),
        ));
    }
    Ok(Json(view(e, &m)))
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
    if app.db.machine_upgrade_release(&m.id) {
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
            "Its agent can't install harnesses: it was installed before ADR 0039. Rebuild it with today's agent: botctl machine rebuild <user> (ADR 0056).".into(),
        ));
    }
    if hermes_serve::bundled(plan) && !hb.can.iter().any(|c| c == wire::CAN_HARNESS_BUNDLES) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "Its agent can't install Hermes Agent from MACHINE_HERMES_BUNDLE: it is older than ADR 0210. Upgrade it first: botctl machine upgrade <user>.".into(),
        ));
    }
    if hermes_serve::bundled_kind(plan, BundleKind::Harnesses) && !hb.can.iter().any(|c| c == wire::CAN_HARNESS_CLI_BUNDLES) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "Its agent can't install harness CLIs from MACHINE_HARNESS_BUNDLE: it is older than ADR 0242. Upgrade it first: botctl machine upgrade <user>.".into(),
        ));
    }
    if plan.npm_login && !hb.can.iter().any(|c| c == wire::CAN_HARNESS_MIRROR_LOGIN) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "Its agent can't sign in to MACHINE_NPM_REGISTRY: it is older than ADR 0219. Upgrade it first: botctl machine upgrade <user>.".into(),
        ));
    }
    if !takes(plan, &hb.can) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "Its agent can't fetch harnesses from MACHINE_NPM_REGISTRY or trust MACHINE_MIRROR_CA_FILE: it is older than ADR 0186. Upgrade it first: botctl machine upgrade <user>.".into(),
        ));
    }
    send_plan(&app, e, &m, &install::plan_for(plan, &hb.can), &by).await?;
    let m = app.db.machine(&m.id).unwrap_or(m);
    Ok((StatusCode::ACCEPTED, Json(view(e, &m))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_secrets() -> crate::secrets::env::EnvStore {
        crate::secrets::env::EnvStore::fixed(&[])
    }

    #[test]
    fn settings() {
        let none = |_: &str| String::new();
        let u = Upkeep::from_env(&none, &no_secrets()).unwrap();
        assert!(u.plan.is_none() && u.upgrades == Upgrades::Manual, "off by default");
        assert_eq!(u.rebuilds, super::super::rebuild::Rebuilds::Manual);
        let env = |k: &str| match k {
            "MACHINE_HARNESSES" => "claude, Codex@0.172.0 pi".into(),
            "MACHINE_AGENT_UPGRADES" => "AUTO".into(),
            _ => String::new(),
        };
        let u = Upkeep::from_env(&env, &no_secrets()).unwrap();
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
            ("MACHINE_LEGACY_REBUILDS", "yes"),
        ] {
            let bad = |key: &str| if key == k { v.to_string() } else { String::new() };
            assert!(Upkeep::from_env(&bad, &no_secrets()).is_err(), "{k}={v}");
        }
    }

    #[test]
    fn mirrors_go_into_the_plan_and_only_to_agents_that_take_them() {
        let env = |k: &str| match k {
            "MACHINE_HARNESSES" => "claude".into(),
            "MACHINE_NODE_MIRROR" => "https://mirror.corp.example/nodejs".into(),
            "MACHINE_NPM_REGISTRY" => "https://mirror.corp.example/npm".into(),
            _ => String::new(),
        };
        let u = Upkeep::from_env(&env, &no_secrets()).unwrap();
        let p = u.plan.clone().unwrap();
        assert_eq!(p.npm_registry.as_deref(), Some("https://mirror.corp.example/npm/"));
        assert!(p.node.as_ref().unwrap().downloads.values().all(|d| d.url.starts_with("https://mirror.corp.example/nodejs/v")));
        assert!(u.describe().contains("npm from https://mirror.corp.example/npm/"), "{}", u.describe());
        let can = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(takes(&p, &can(&[wire::CAN_HARNESSES, wire::CAN_HARNESS_MIRRORS])));
        assert!(!takes(&p, &can(&[wire::CAN_HARNESSES])), "an agent from before ADR 0186 isn't sent it");
        let plain = Upkeep::from_env(&|k: &str| if k == "MACHINE_HARNESSES" { "claude".into() } else { String::new() }, &no_secrets()).unwrap().plan.unwrap();
        assert!(takes(&plain, &can(&[wire::CAN_HARNESSES])), "without mirrors, older agents get the plan as before");

        // The managed tiers' default goes through the mirrors too, and Hermes is named
        // as still needing the internet.
        let mut u = Upkeep::from_env(&|k: &str| if k == "MACHINE_HARNESSES" { String::new() } else { env(k) }, &no_secrets()).unwrap();
        u.default_to(&["hermes", "pi"]).unwrap();
        assert!(u.plan.as_ref().unwrap().npm_registry.is_some());
        assert!(u.describe().contains("hermes still download"), "{}", u.describe());
    }

    #[test]
    fn a_registry_login_goes_only_to_agents_that_fetch_it() {
        let env = |k: &str| match k {
            "MACHINE_HARNESSES" => "claude".into(),
            "MACHINE_NPM_REGISTRY" => "https://mirror.corp.example/npm".into(),
            _ => String::new(),
        };
        let secrets = crate::secrets::env::EnvStore::fixed(&[("MACHINE_NPM_TOKEN", "upkeep-test-token-2b9f")]);
        let u = Upkeep::from_env(&env, &secrets).unwrap();
        let p = u.plan.clone().unwrap();
        assert!(p.npm_login);
        assert!(u.describe().contains("signing in with MACHINE_NPM_TOKEN") && !u.describe().contains("upkeep-test-token-2b9f"), "{}", u.describe());
        let can = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(takes(&p, &can(&[wire::CAN_HARNESSES, wire::CAN_HARNESS_MIRRORS, wire::CAN_HARNESS_MIRROR_LOGIN])));
        assert!(!takes(&p, &can(&[wire::CAN_HARNESSES, wire::CAN_HARNESS_MIRRORS])), "an agent from before ADR 0219 isn't sent it");
        let anonymous = Upkeep::from_env(&env, &no_secrets()).unwrap().plan.unwrap();
        assert!(!anonymous.npm_login && takes(&anonymous, &can(&[wire::CAN_HARNESSES, wire::CAN_HARNESS_MIRRORS])), "without a login, nothing changes");
        let err = Upkeep::from_env(&|k: &str| if k == "MACHINE_NPM_REGISTRY" { String::new() } else { env(k) }, &secrets).unwrap_err();
        assert!(err.contains("need MACHINE_NPM_REGISTRY"), "{err}");
    }

    #[test]
    fn hermes_bundles_go_into_the_plan_and_only_to_agents_that_take_them() {
        use crate::machines::hermes_bundle::standin;
        use sha2::{Digest, Sha256};
        use wire::InstallSource;
        let dir = crate::db::temp_path("upkeep-hermes");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("superbot-hermes-v0.23.3-x86_64.tar.gz");
        let body = standin::good("x86_64", "#!/bin/sh\n");
        std::fs::write(&file, &body).unwrap();
        let sha: String = Sha256::digest(&body).iter().map(|b| format!("{b:02x}")).collect();
        let setting = format!("{}={sha}", file.display());
        let env = move |harnesses: &'static str| {
            let setting = setting.clone();
            move |k: &str| match k {
                "MACHINE_HARNESSES" => harnesses.into(),
                "MACHINE_HERMES_BUNDLE" => setting.clone(),
                "MACHINE_CONTROL_URL" => "https://10.0.0.5:8443".into(),
                _ => String::new(),
            }
        };
        let u = Upkeep::from_env(&env("claude,hermes"), &no_secrets()).unwrap();
        let p = u.plan.clone().unwrap();
        assert!(matches!(p.harnesses[0].source, InstallSource::Npm { .. }));
        assert!(matches!(p.harnesses[1].source, InstallSource::Bundle { .. }), "{p:?}");
        assert!(u.describe().contains("Hermes Agent on machines from botd's Hermes bundles: x86_64"), "{}", u.describe());
        assert!(!u.describe().contains("still download"), "{}", u.describe());
        let can = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(takes(&p, &can(&[wire::CAN_HARNESSES, wire::CAN_HARNESS_BUNDLES])));
        assert!(!takes(&p, &can(&[wire::CAN_HARNESSES, wire::CAN_HARNESS_MIRRORS])), "an agent from before ADR 0210 isn't sent it");
        let without = Upkeep::from_env(&env("claude"), &no_secrets()).unwrap().plan.unwrap();
        assert!(takes(&without, &can(&[wire::CAN_HARNESSES])), "without Hermes in the plan, the bundles change nothing");
        assert_eq!(without, parse_harnesses("claude").unwrap().unwrap(), "nor the plan's id");

        // The managed tiers' default goes through them too.
        let mut u = Upkeep::from_env(&env(""), &no_secrets()).unwrap();
        u.default_to(&["hermes"]).unwrap();
        assert!(matches!(u.plan.unwrap().harnesses[0].source, InstallSource::Bundle { .. }));
        let pinned = Upkeep::from_env(&env("hermes@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"), &no_secrets()).unwrap_err();
        assert!(pinned.contains("but machines' plan pins bbbbbbbbbbbb"), "{pinned}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn harness_bundles_go_into_the_plan_before_the_mirrors_and_only_to_agents_that_take_them() {
        use crate::machines::hermes_bundle::standin;
        use sha2::{Digest, Sha256};
        use wire::InstallSource;
        let dir = crate::db::temp_path("upkeep-harnesses");
        std::fs::create_dir_all(&dir).unwrap();
        let n = install::node();
        let mut pins = format!("harnesses=claude codex pi\nnode={} {}\n", n.version, n.downloads["x86_64"].sha256);
        for b in ["claude", "codex", "pi"] {
            let h = install::install(b, None, None).unwrap();
            let InstallSource::Npm { package, integrity: Some(i) } = h.source else { unreachable!() };
            pins.push_str(&format!("harness_{b}={} {package} {i}\n", h.version));
        }
        let file = dir.join("superbot-harnesses-0.1.0-x86_64.tar.gz");
        let body = standin::good_harnesses("x86_64", &[("claude", "2.1.329")], &pins);
        std::fs::write(&file, &body).unwrap();
        let sha: String = Sha256::digest(&body).iter().map(|b| format!("{b:02x}")).collect();
        let setting = format!("{}={sha}", file.display());
        let env = move |harnesses: &'static str, mirrored: bool| {
            let setting = setting.clone();
            move |k: &str| match k {
                "MACHINE_HARNESSES" => harnesses.into(),
                "MACHINE_HARNESS_BUNDLE" => setting.clone(),
                "MACHINE_CONTROL_URL" => "https://10.0.0.5:8443".into(),
                "MACHINE_NODE_MIRROR" if mirrored => "https://mirror.corp.example/nodejs".into(),
                "MACHINE_NPM_REGISTRY" if mirrored => "https://mirror.corp.example/npm".into(),
                _ => String::new(),
            }
        };
        let u = Upkeep::from_env(&env("claude,codex,hermes", true), &no_secrets()).unwrap();
        let p = u.plan.clone().unwrap();
        assert!(p.harnesses[..2].iter().all(|h| matches!(h.source, InstallSource::Bundle { holds: BundleKind::Harnesses, .. })), "{p:?}");
        assert!(matches!(p.harnesses[2].source, InstallSource::Script { .. }), "Hermes isn't in it");
        assert!(p.node.is_none() && p.npm_registry.is_none() && p.ca.is_none(), "nothing left for the mirrors: {p:?}");
        assert!(u.describe().contains("Claude Code, Codex and Pi on machines from botd's harness bundles: x86_64"), "{}", u.describe());
        let can = |c: &[&str]| c.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let today = can(&[wire::CAN_HARNESSES, wire::CAN_HARNESS_MIRRORS, wire::CAN_HARNESS_BUNDLES, wire::CAN_HARNESS_CLI_BUNDLES]);
        assert!(takes(&p, &today));
        assert!(!takes(&p, &today[..3]), "an agent from before ADR 0242 isn't sent it");
        let without = Upkeep::from_env(&env("hermes", false), &no_secrets()).unwrap().plan.unwrap();
        assert_eq!(without, parse_harnesses("hermes").unwrap().unwrap(), "without an npm harness, the bundles change nothing");
        assert!(takes(&without, &can(&[wire::CAN_HARNESSES])));

        // The managed tiers' default goes through them too, and a pin the bundle
        // doesn't hold keeps botd from starting.
        let mut u = Upkeep::from_env(&env("", false), &no_secrets()).unwrap();
        u.default_to(&["pi"]).unwrap();
        assert!(matches!(u.plan.unwrap().harnesses[0].source, InstallSource::Bundle { holds: BundleKind::Harnesses, .. }));
        let err = Upkeep::from_env(&env("codex@0.172.0", false), &no_secrets()).unwrap_err();
        assert!(err.contains("MACHINE_HARNESS_BUNDLE: ") && err.contains("but machines' plan pins 0.172.0"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn machines_get_the_managed_default_unless_told_otherwise() {
        let with = |v: &'static str| move |k: &str| if k == "MACHINE_HARNESSES" { v.to_string() } else { String::new() };
        // Unset: the managed tiers' default, at its pin.
        let mut u = Upkeep::from_env(&with(""), &no_secrets()).unwrap();
        assert!(u.unset && !u.defaulted);
        assert_eq!(u.lacks(&["hermes"]), ["hermes"]);
        u.default_to(&["hermes"]).unwrap();
        assert_eq!(u.plan.as_ref().map(names).unwrap().len(), 1);
        assert!(names(u.plan.as_ref().unwrap())[0].starts_with("hermes@"));
        assert!(u.defaulted && u.describe().contains("the managed tiers' default"), "{}", u.describe());
        assert!(u.lacks(&["hermes"]).is_empty());
        // No managed tiers (self-host): still nothing.
        let mut open = Upkeep::from_env(&with(""), &no_secrets()).unwrap();
        open.default_to(&[]).unwrap();
        assert!(open.plan.is_none() && !open.defaulted);
        // `none`, or a list of its own, is what machines get.
        let mut none = Upkeep::from_env(&with("none"), &no_secrets()).unwrap();
        none.default_to(&["hermes"]).unwrap();
        assert!(none.plan.is_none() && !none.unset && none.describe().contains("harnesses on machines: none"));
        let mut own = Upkeep::from_env(&with("claude"), &no_secrets()).unwrap();
        own.default_to(&["hermes"]).unwrap();
        assert_eq!(names(own.plan.as_ref().unwrap()), ["claude@2.1.329"]);
        assert_eq!(own.lacks(&["hermes", "claude"]), ["hermes"]);
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
