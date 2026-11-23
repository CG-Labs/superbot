//! Contractual data residency (ADR 0129), on top of data regions (ADR 0117). A server
//! admin pins a user or a team to a region under an agreement (`reference`). While it
//! holds, their machines, off-host backups and restores stay in that region or don't
//! happen:
//!
//! - their region can't be changed or cleared, and a pinned team takes no member whose
//!   data is elsewhere;
//! - a backup goes only to a store in the region, whatever MACHINE_BACKUP_RESIDENCY says;
//! - a restore, a move to another host, or a lost host's recovery is refused unless the
//!   backup's store and the target host are both in the region.
//!
//! A pin is refused while the region can't keep it (not offered, Incus hosts untagged,
//! no backup store there) or while any of their data is still elsewhere. Unpinning needs
//! a reason. Every pin, unpin and refusal is audited. A pinned person's Bot runs take only
//! model routes the tiers file marks as in the region, or are refused (ADR 0139, in the
//! runner). botd's own database and server backups are where the operator runs botd;
//! with RESIDENCY_SERVER_DATA=require, pins are held to that region too (ADR 0184).
//!
//! Someone leaving a pinned team keeps its pin as their own (ADR 0171), and with
//! RESIDENCY_STARTUP=refuse botd won't start while it can't keep a pin.

use super::backup::{self, Offsite};
use super::{ControlPlane, conflict, event, region};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, MachineBackup, PinOn, ResidencyPin, Team, User};
use crate::runner::App;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Auth, Res, bad, not_found};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, State as AppS};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

/// The reason in every refusal a pin causes.
pub const PINNED: &str = "residency_pinned";

/// The pin that holds `user_id`'s data: their team's, else their own. Both agree when
/// both exist; pinning refuses anything else.
pub fn of_user(app: &App, user_id: &str) -> Option<ResidencyPin> {
    app.db.team_id_of(user_id).and_then(|t| app.db.residency_pin(PinOn::Team, &t)).or_else(|| app.db.residency_pin(PinOn::User, user_id))
}

/// The pins a Bot run is held to (ADR 0139): those of everyone whose data it carries
/// (its owner, its asker, and whom an asking Bot carried), once per region. Its model
/// calls must stay in every one.
pub fn of_run(app: &App, people: &[String]) -> Vec<ResidencyPin> {
    let mut out: Vec<ResidencyPin> = Vec::new();
    for p in people.iter().filter_map(|u| of_user(app, u)) {
        if !out.iter().any(|o| o.region == p.region) {
            out.push(p);
        }
    }
    out
}

/// The pins on `people` now in regions a run's route wasn't held to (`held_to`): made
/// while it waited for a slot, so it doesn't start (ADR 0139).
pub fn pinned_beyond(app: &App, people: &[String], held_to: &[String]) -> Vec<ResidencyPin> {
    of_run(app, people).into_iter().filter(|p| !held_to.contains(&p.region)).collect()
}

/// Why `region` can't keep pinned data on this server as it is set up now. Empty: it can.
pub fn unready(cp: &ControlPlane, region: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !cp.regions.iter().any(|r| r == region) {
        out.push(format!("{region} isn't one of MACHINE_REGIONS ({})", cp.regions.join(", ")));
    }
    if let Some(h) = cp.hosts() {
        if !h.tagged() {
            out.push(format!("Incus hosts aren't tagged with data regions, so nothing shows a host is in {region} (INCUS_REGION, INCUS_REGION_<NAME>)"));
        } else if !h.configured().iter().any(|c| c.region.as_deref() == Some(region)) {
            out.push(format!("no Incus host is in {region}"));
        }
    }
    if let Some(off) = cp.offsite.as_deref()
        && !off.in_region(region)
    {
        out.push(format!(
            "machine backups have no store in {region} ({}_BUCKET and the rest, or MACHINE_BACKUP_S3_DATA_REGION={region} if the default store is there)",
            backup::store_name(region)
        ));
    }
    out
}

/// Whether a backup recorded in `store_region`'s store (None: the default store) is in `region`.
pub(super) fn stored_in(off: Option<&Offsite>, store_region: Option<&str>, region: &str) -> bool {
    match store_region {
        Some(r) => r == region,
        None => off.is_some_and(|o| o.s.default_region.as_deref() == Some(region)),
    }
}

/// The Incus host `m` is on now and that host's data region, when botd's hosts hold it.
pub(super) fn host_of(cp: &ControlPlane, m: &Machine) -> Option<(String, Option<String>)> {
    let h = cp.hosts().filter(|_| cp.owns(m))?;
    let host = m.provider_id.as_deref().map(|p| h.host_of(p)).or_else(|| m.placed_on.clone())?;
    let region = h.configured().into_iter().find(|c| c.name == host).and_then(|c| c.region);
    Some((host, region))
}

/// What of `user_id`'s data is outside `region` now: their machine (by its record, and by
/// its host's tag now, since a machine made before hosts were tagged may be on any host),
/// and backups in a store elsewhere that aren't deleted. A failed one counts: its upload
/// may have finished before it failed. Empty: all of it is in.
pub(super) fn outside(app: &App, cp: &ControlPlane, user_id: &str, region: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(m) = app.db.user_machine(user_id) {
        if m.region != region {
            out.push(format!("their machine is in {}", m.region));
        } else if let Some((host, r)) = host_of(cp, &m) {
            match r {
                Some(r) if r == region => {}
                Some(r) => out.push(format!("their machine is on host {host}, in {r}")),
                None => out.push(format!("their machine is on host {host}, which has no data region")),
            }
        }
    }
    let off = cp.offsite.as_deref();
    let n = app
        .db
        .user_machine_backups_kept(user_id)
        .iter()
        .filter(|b| !stored_in(off, b.store_region.as_deref(), region))
        .count();
    if n > 0 {
        out.push(format!("{n} of their machine backups are in a store outside {region}"));
    }
    out
}

pub(super) fn pinned_to(p: &ResidencyPin) -> String {
    format!("pinned to {} ({})", p.region, p.reference)
}

/// The store a backup of `m` goes to (`Offsite::store_for`). For a pinned user, only a
/// store in their pinned region: never the default store elsewhere, even with
/// MACHINE_BACKUP_RESIDENCY=warn. The pin is returned with a refusal it caused.
pub fn backup_store(app: &App, off: &Offsite, m: &Machine) -> Result<Option<String>, (Option<Box<ResidencyPin>>, String)> {
    let Some(p) = of_user(app, &m.user_id) else {
        return off.store_for(&m.region).map(|s| s.map(String::from)).map_err(|e| (None, e));
    };
    if m.region != p.region {
        let why = format!("Its data is {}, and the machine is in {} (ADR 0129).", pinned_to(&p), m.region);
        return Err((Some(Box::new(p)), why));
    }
    match off.store_for(&p.region) {
        Ok(s) if off.in_region(&p.region) => Ok(s.map(String::from)),
        _ => {
            let why = format!(
                "Its data is {}, and no backup store is set there ({}_BUCKET, or MACHINE_BACKUP_S3_DATA_REGION={}) (ADR 0129).",
                pinned_to(&p),
                backup::store_name(&p.region),
                p.region
            );
            Err((Some(Box::new(p)), why))
        }
    }
}

/// Whether restoring `m` from `b` onto host `to` (None: not known yet, or no hosts)
/// keeps a pinned user's data in their region. Err: the pin and why not.
pub fn check_restore(app: &App, cp: &ControlPlane, m: &Machine, b: &MachineBackup, to: Option<&str>) -> Result<(), (Box<ResidencyPin>, String)> {
    let Some(p) = of_user(app, &m.user_id) else { return Ok(()) };
    if m.region != p.region {
        let why = format!("Its data is {}, and the machine is in {} (ADR 0129).", pinned_to(&p), m.region);
        return Err((Box::new(p), why));
    }
    if !stored_in(cp.offsite.as_deref(), b.store_region.as_deref(), &p.region) {
        let store = b.store_region.as_deref().map_or("the default store".to_string(), |r| format!("{r}'s store"));
        let why = format!("Backup {} is in {store}, which isn't said to be in {}, and its data is {} (ADR 0129).", b.id, p.region, pinned_to(&p));
        return Err((Box::new(p), why));
    }
    if let (Some(h), Some(to)) = (cp.hosts(), to) {
        let why = match h.configured().into_iter().find(|c| c.name == to).map(|c| c.region) {
            Some(Some(r)) if r == p.region => return Ok(()),
            Some(Some(r)) => format!("Host {to} is in {r}, and this machine's data is {} (ADR 0129).", pinned_to(&p)),
            _ => format!("Host {to} has no data region, so nothing shows it is in {}, and this machine's data is {} (ADR 0129).", p.region, pinned_to(&p)),
        };
        return Err((Box::new(p), why));
    }
    Ok(())
}

/// Whether a new machine for `user_id` may be placed in `region`: for a pinned user, only
/// their pinned region and, with Incus hosts, only once hosts are tagged, since placement
/// keeps to a region only then. Checked on every attempt, retries included.
pub fn check_create(app: &App, cp: &ControlPlane, user_id: &str, region: &str) -> Result<(), (Box<ResidencyPin>, String)> {
    let Some(p) = of_user(app, user_id) else { return Ok(()) };
    let why = if region != p.region {
        format!("Its data is {}, and the machine would be in {region} (ADR 0129).", pinned_to(&p))
    } else if cp.hosts().is_some_and(|h| !h.tagged()) {
        format!(
            "Its data is {}, and Incus hosts aren't tagged with data regions, so nothing shows a host is in {} (INCUS_REGION, INCUS_REGION_<NAME>) (ADR 0129).",
            pinned_to(&p),
            p.region
        )
    } else {
        return Ok(());
    };
    Err((Box::new(p), why))
}

fn refusal(action: &str, p: &ResidencyPin, why: &str) -> Value {
    json!({ "reason": PINNED, "action": action, "pinnedRegion": p.region, "pinnedOn": p.subject_type, "reference": p.reference, "error": why })
}

/// A machine action a pin refused (`action`: `create`, `backup`, `restore`, `move` or
/// `recover`): audited as `machine.residency_refused`.
pub fn refused(app: &App, by: &Who, m: &Machine, action: &str, p: &ResidencyPin, why: &str) {
    app.db.record(&event(by, "machine.residency_refused", m, refusal(action, p, why)).outcome(Outcome::Denied));
}

/// A new machine a pin refused before there was one to name: audited on the user.
pub fn refused_request(app: &App, by: &Who, user_id: &str, p: &ResidencyPin, why: &str) {
    let mut d = refusal("create", p, why);
    d["userId"] = json!(user_id);
    app.db.record(&by.event("machine.residency_refused").target("user", user_id).outcome(Outcome::Denied).details(d));
}

/// Whether `u`'s own region may become `to`, which makes their region `after`: never
/// away from a pin. A pin on them holds their own region to it, even while their team's
/// pin agrees (that one may end first); one on their team allows only none (the team's)
/// or the same.
pub fn check_user_region(app: &App, u: &User, to: Option<&str>, after: &str) -> Result<(), (Box<ResidencyPin>, String)> {
    let mine = app.db.residency_pin(PinOn::User, &u.id);
    let p = match mine.filter(|p| to != Some(p.region.as_str())) {
        Some(p) => p,
        None => match app.db.team_id_of(&u.id).and_then(|t| app.db.residency_pin(PinOn::Team, &t)).filter(|p| after != p.region) {
            Some(p) => p,
            None => return Ok(()),
        },
    };
    let own = p.subject_type == PinOn::User;
    let whose = if own { "Their data" } else { "Their team's data" };
    let why = format!(
        "{whose} is {} by {}. Unpin it first, with a reason (botctl {} residency ... unpin) (ADR 0129).",
        pinned_to(&p),
        p.pinned_by.as_deref().unwrap_or("an admin"),
        if own { "user" } else { "team" }
    );
    Err((Box::new(p), why))
}

/// Whether `t`'s region may become `to`: never away from its pin.
pub fn check_team_region(app: &App, t: &Team, to: Option<&str>) -> Result<(), (Box<ResidencyPin>, String)> {
    match app.db.residency_pin(PinOn::Team, &t.id) {
        Some(p) if to != Some(p.region.as_str()) => {
            let why = format!("Team {}'s data is {}. Unpin it first, with a reason (botctl team residency ... unpin) (ADR 0129).", t.name, pinned_to(&p));
            Err((Box::new(p), why))
        }
        _ => Ok(()),
    }
}

/// Whether `u` may join `t` without bringing data from outside its pinned region.
pub fn check_join(app: &App, cp: &ControlPlane, t: &Team, u: &User) -> Result<(), String> {
    let Some(p) = app.db.residency_pin(PinOn::Team, &t.id) else { return Ok(()) };
    let mut why = Vec::new();
    if let Some(r) = u.region.as_deref().filter(|r| *r != p.region) {
        why.push(format!("their own data region is {r}"));
    }
    if let Some(own) = app.db.residency_pin(PinOn::User, &u.id).filter(|o| o.region != p.region) {
        why.push(format!("they are {}", pinned_to(&own)));
    }
    why.extend(outside(app, cp, &u.id, &p.region));
    match why.is_empty() {
        true => Ok(()),
        false => Err(format!("Team {}'s data is {}, and {}: {} (ADR 0129).", t.name, pinned_to(&p), u.name, why.join("; "))),
    }
}

/// Whom `p` is on, as "User <name>" or "Team <name>", and the people whose data it
/// holds now: the user, or the team's members. None: they are gone.
pub(super) fn held_by(app: &App, p: &ResidencyPin) -> Option<(String, Vec<String>)> {
    match p.subject_type {
        PinOn::User => app.db.user(&p.subject_id).map(|u| (format!("User {}", u.name), vec![u.id])),
        PinOn::Team => app.db.team(&p.subject_id).map(|t| (format!("Team {}", t.name), app.db.team_members(&t.id).into_iter().map(|m| m.user_id).collect())),
    }
}

/// Why `people`'s plans have no model route in `region` (ADR 0139), each once.
pub(super) fn route_gaps(app: &App, people: &[String], region: &str) -> Vec<String> {
    let mut gaps: Vec<String> = Vec::new();
    for id in people {
        if let Some(g) = app.tiers().residency_gap(app.tier_of(id), region).filter(|g| !gaps.contains(g)) {
            gaps.push(g);
        }
    }
    gaps
}

/// Why this server can't keep `p` now (ADR 0129): its region isn't ready, some of the
/// data it holds is outside it, or, with RESIDENCY_SERVER_DATA=require, botd's own data
/// is (ADR 0184), as one line. None: it can, or whom it is on is gone.
fn unkept_line(app: &App, cp: &ControlPlane, p: &ResidencyPin, name: &str, people: &[String]) -> Option<String> {
    let mut why = unready(cp, &p.region);
    why.extend(cp.server_data.refuses(&p.region));
    for id in people {
        why.extend(outside(app, cp, id, &p.region));
    }
    (!why.is_empty()).then(|| format!("{name} is {}, but {}. Backups, restores and new machines that can't stay there are refused (ADR 0129).", pinned_to(p), why.join("; ")))
}

/// The pins this server can't keep now, each with why: the regions, hosts and backup
/// stores it is set up with don't hold their region, or their data is outside it. Model
/// routes aren't counted: those runs are refused one by one (ADR 0139).
pub fn unkept(app: &App, cp: &ControlPlane) -> Vec<(ResidencyPin, String)> {
    app.db
        .residency_pins()
        .into_iter()
        .filter_map(|p| {
            let (name, people) = held_by(app, &p)?;
            let why = unkept_line(app, cp, &p, &name, &people)?;
            Some((p, why))
        })
        .collect()
}

/// What botd does at startup when a pin can't be kept (`RESIDENCY_STARTUP`, ADR 0171):
/// warn and start (the default), or refuse to start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Startup {
    #[default]
    Warn,
    Refuse,
}

impl Startup {
    pub fn parse(v: &str) -> Result<Startup, String> {
        match v.trim().to_ascii_lowercase().as_str() {
            "" | "warn" => Ok(Startup::Warn),
            "refuse" => Ok(Startup::Refuse),
            v => Err(format!("RESIDENCY_STARTUP must be warn or refuse, not \"{}\"", crate::audit::clip(v, 20))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Startup::Warn => "warn",
            Startup::Refuse => "refuse",
        }
    }
}

static STARTUP: std::sync::OnceLock<Startup> = std::sync::OnceLock::new();

/// The `RESIDENCY_STARTUP` botd started with, for `GET /api/regions`.
pub fn startup() -> Startup {
    STARTUP.get().copied().unwrap_or_default()
}

pub fn set_startup(policy: Startup) {
    let _ = STARTUP.set(policy);
}

/// At startup: the residency warnings to log, or, with `Startup::Refuse` and a pin this
/// server can't keep, why botd won't start, audited as `residency.startup_refused`.
pub fn at_startup(app: &App, cp: &ControlPlane, policy: Startup) -> Result<Vec<String>, String> {
    let unkept = match policy {
        Startup::Refuse => unkept(app, cp),
        Startup::Warn => Vec::new(),
    };
    if unkept.is_empty() {
        return Ok(warnings(app, cp));
    }
    let pins: Vec<Value> = unkept
        .iter()
        .map(|(p, why)| json!({ "subjectType": p.subject_type, "subjectId": p.subject_id, "region": p.region, "reference": p.reference, "error": why }))
        .collect();
    let by = Who::system("startup");
    app.db.record(&by.event("residency.startup_refused").outcome(Outcome::Denied).details(json!({ "policy": policy.as_str(), "pins": pins })));
    let lines: Vec<&str> = unkept.iter().map(|(_, why)| why.as_str()).collect();
    Err(format!(
        "RESIDENCY_STARTUP=refuse, and this server can't keep {} residency pin{}: {} Put back the regions, host tags, backup stores or server data region they need, or start with RESIDENCY_STARTUP=warn to unpin with a reason (botctl user|team residency ... unpin) (ADR 0171).",
        unkept.len(),
        if unkept.len() == 1 { "" } else { "s" },
        lines.join(" ")
    ))
}

/// A leaver's data, kept under their former team's pin as a pin of their own (ADR 0171):
/// audited as `user.residency_pin_kept`.
pub fn kept_for_leaver(app: &App, by: &Who, team_id: &str, user_id: &str, reason: &str, p: &ResidencyPin) {
    let d = json!({
        "region": p.region, "reference": p.reference, "team": team_id, "teamName": app.db.team(team_id).map(|t| t.name),
        "reason": reason, "userEmail": app.db.user(user_id).and_then(|u| u.email),
    });
    app.db.record(&by.event("user.residency_pin_kept").target("user", user_id).details(d));
}

/// Warnings for startup and admins: pins whose region this server can't keep now, or
/// whose data is outside it. Their backups and restores are refused until fixed. Also
/// pins whose people's plans have no model route there (ADR 0139), whose runs are refused.
pub fn warnings(app: &App, cp: &ControlPlane) -> Vec<String> {
    let mut out: Vec<String> = app.tiers().unknown_regions(&cp.regions).into_iter().map(|w| format!("The tiers file's {w} (ADR 0139).")).collect();
    for p in app.db.residency_pins() {
        let Some((name, people)) = held_by(app, &p) else { continue };
        out.extend(unkept_line(app, cp, &p, &name, &people));
        let gaps = route_gaps(app, &people, &p.region);
        if !gaps.is_empty() {
            out.push(format!(
                "{name} is {}, but {}. Their Bots' runs are refused until the tiers file routes them through a provider whose regions include {} (ADR 0139).",
                pinned_to(&p),
                gaps.join("; "),
                p.region
            ));
        }
    }
    out
}

/// Every pin, with the name of whom it is on, for `GET /api/regions`.
pub fn pins_view(app: &App) -> Vec<Value> {
    app.db
        .residency_pins()
        .into_iter()
        .filter_map(|p| {
            let name = match p.subject_type {
                PinOn::User => app.db.user(&p.subject_id)?.name,
                PinOn::Team => app.db.team(&p.subject_id)?.name,
            };
            let mut v = json!(p);
            v["name"] = json!(name);
            Some(v)
        })
        .collect()
}

/// `{"region": "<id>", "reference": "<the agreement>"}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinBody {
    region: String,
    reference: String,
}

/// `{"reason": "<why>"}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnpinBody {
    reason: String,
}

/// Trimmed, not empty, at most `max` characters, no control characters.
fn text(raw: &str, what: &str, max: usize) -> Res<String> {
    let s = raw.trim();
    if s.is_empty() || s.chars().count() > max || s.chars().any(char::is_control) {
        return Err(bad(format!("{what} must be 1 to {max} characters, with no control characters")));
    }
    Ok(s.to_string())
}

fn pin_body(cp: &ControlPlane, body: Result<Json<PinBody>, JsonRejection>) -> Res<(String, String)> {
    let Ok(Json(b)) = body else {
        return Err(bad("Send {\"region\": \"<id>\", \"reference\": \"<the agreement it is under>\"}."));
    };
    let region = b.region.trim().to_string();
    if !cp.regions.contains(&region) {
        return Err(bad(format!("region must be one of {}", cp.regions.join(", "))));
    }
    Ok((region, text(&b.reference, "reference", 200)?))
}

/// Why a pin to `region` is refused for botd's own data (RESIDENCY_SERVER_DATA=require,
/// ADR 0184). None: it isn't.
fn server_data_refusal(cp: &ControlPlane, region: &str) -> Option<String> {
    let why = cp.server_data.refuses(region);
    (!why.is_empty()).then(|| {
        format!(
            "{region} can't hold pinned data on this server: {}. RESIDENCY_SERVER_DATA=require holds every pin to the region botd's own database and server backups are in (ADR 0184).",
            why.join("; ")
        )
    })
}

/// A pin or unpin that wasn't saved: nothing changed, and nothing is audited as done.
fn not_saved(e: String) -> ApiError {
    ApiError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("The residency pin couldn't be saved, so nothing changed: {e}"))
}

fn unpin_body(body: Result<Json<UnpinBody>, JsonRejection>) -> Res<String> {
    let Ok(Json(b)) = body else { return Err(bad("Send {\"reason\": \"<why the pin ends>\"}.")) };
    text(&b.reason, "reason", 500)
}

/// `PUT /api/users/{key}/residency` `{region, reference}`: pins the user's data to
/// `region`, setting their own data region to it. Again with the same region replaces
/// the reference. Refused while the region can't keep it or any of their data is
/// elsewhere.
pub async fn pin_user(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(key): Path<String>, body: Result<Json<PinBody>, JsonRejection>) -> Res {
    let cp = &*a.machines;
    cp.need()?;
    let (region, reference) = pin_body(cp, body)?;
    let u = need_user_key(&app, &key)?;
    let _g = cp.lock_ops().await;
    let u = app.db.user(&u.id).ok_or_else(|| not_found("User"))?;
    let refuse = |reason: &str, why: String| -> ApiError {
        let d = json!({ "reason": reason, "region": region, "reference": reference, "userEmail": u.email, "error": why });
        app.db.record(&by.event("user.residency_pin_refused").target("user", &u.id).outcome(Outcome::Denied).details(d));
        conflict(why)
    };
    let team = app.db.team_id_of(&u.id).and_then(|t| app.db.team(&t));
    if let Some(tp) = team.as_ref().and_then(|t| app.db.residency_pin(PinOn::Team, &t.id)).filter(|p| p.region != region) {
        return Err(refuse("team_pinned", format!("{}'s team is {}; their own pin can only agree with it (ADR 0129).", u.name, pinned_to(&tp))));
    }
    let own = app.db.residency_pin(PinOn::User, &u.id);
    if let Some(o) = own.as_ref().filter(|o| o.region != region) {
        return Err(refuse("pinned", format!("{} is {}. Unpin first, with a reason, to pin elsewhere (ADR 0129).", u.name, pinned_to(o))));
    }
    let why = unready(cp, &region);
    if !why.is_empty() {
        return Err(refuse("region_not_ready", format!("{region} can't keep pinned data on this server yet: {} (ADR 0129).", why.join("; "))));
    }
    if let Some(why) = server_data_refusal(cp, &region) {
        return Err(refuse("server_data_outside", why));
    }
    let why = outside(&app, cp, &u.id, &region);
    if !why.is_empty() {
        return Err(refuse(
            "data_outside",
            format!(
                "Not all of {}'s data is in {region}: {}. Destroy the machine and delete its backups (botctl machine delete-backups), or wait for old backups' retention to end once new ones are in {region} (ADR 0129).",
                u.name,
                why.join("; ")
            ),
        ));
    }
    let from = u.region.clone();
    app.db.pin_residency(PinOn::User, &u.id, &region, &reference, by.actor.id.as_deref()).map_err(not_saved)?;
    let d = json!({ "region": region, "reference": reference, "regionFrom": from, "renewed": own.is_some(), "userEmail": u.email });
    app.db.record(&by.event("user.residency_pinned").target("user", &u.id).details(d));
    let u = app.db.user(&u.id).ok_or_else(|| not_found("User"))?;
    Ok(Json(region::user_view(&app, cp, &u)))
}

/// `DELETE /api/users/{key}/residency` `{reason}`: ends the user's own pin. Their data
/// region stays as it is (still binding, ADR 0117); it can be changed from now on.
pub async fn unpin_user(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(key): Path<String>, body: Result<Json<UnpinBody>, JsonRejection>) -> Res {
    let cp = &*a.machines;
    cp.need()?;
    let reason = unpin_body(body)?;
    let u = need_user_key(&app, &key)?;
    let _g = cp.lock_ops().await;
    let p = app.db.residency_pin(PinOn::User, &u.id).ok_or_else(|| not_found("Residency pin on this user"))?;
    if !app.db.unpin_residency(PinOn::User, &u.id).map_err(not_saved)? {
        return Err(not_found("Residency pin on this user"));
    }
    let d = json!({ "region": p.region, "reference": p.reference, "pinnedAt": p.pinned_at, "pinnedBy": p.pinned_by, "reason": reason, "userEmail": u.email });
    app.db.record(&by.event("user.residency_unpinned").target("user", &u.id).details(d));
    Ok(Json(region::user_view(&app, cp, &u)))
}

/// `PUT /api/teams/{id}/residency` `{region, reference}`: pins the team's data to
/// `region`, setting the team's data region to it. Refused while the region can't keep
/// it, or any member has their own region or pin elsewhere, or data outside it.
pub async fn pin_team(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(id): Path<String>, body: Result<Json<PinBody>, JsonRejection>) -> Res {
    let cp = &*a.machines;
    cp.need()?;
    let (region, reference) = pin_body(cp, body)?;
    let _g = cp.lock_ops().await;
    let t = app.db.team(id.trim()).ok_or_else(|| not_found("Team"))?;
    let refuse = |reason: &str, why: String, extra: Value| -> ApiError {
        let d = json!({ "reason": reason, "region": region, "reference": reference, "error": why, "blocked": extra });
        app.db.record(&crate::teams::team_event(&by, "team.residency_pin_refused", &t.id, d).outcome(Outcome::Denied));
        conflict(why)
    };
    if crate::teams::being_deleted(&t.id) {
        return Err(refuse("team_deleting", format!("Team {} is being deleted (ADR 0129).", t.name), Value::Null));
    }
    let own = app.db.residency_pin(PinOn::Team, &t.id);
    if let Some(o) = own.as_ref().filter(|o| o.region != region) {
        return Err(refuse("pinned", format!("Team {} is {}. Unpin first, with a reason, to pin elsewhere (ADR 0129).", t.name, pinned_to(o)), Value::Null));
    }
    let why = unready(cp, &region);
    if !why.is_empty() {
        return Err(refuse("region_not_ready", format!("{region} can't keep pinned data on this server yet: {} (ADR 0129).", why.join("; ")), Value::Null));
    }
    if let Some(why) = server_data_refusal(cp, &region) {
        return Err(refuse("server_data_outside", why, Value::Null));
    }
    let mut blocked = Vec::new();
    for m in app.db.team_members(&t.id) {
        let Some(u) = app.db.user(&m.user_id) else { continue };
        let mut why = Vec::new();
        if let Some(r) = u.region.as_deref().filter(|r| *r != region) {
            why.push(format!("their own data region is {r}"));
        }
        if let Some(p) = app.db.residency_pin(PinOn::User, &u.id).filter(|p| p.region != region) {
            why.push(format!("they are {}", pinned_to(&p)));
        }
        why.extend(outside(&app, cp, &u.id, &region));
        if !why.is_empty() {
            blocked.push((u.id, u.name, why));
        }
    }
    if !blocked.is_empty() {
        let names: Vec<String> = blocked.iter().map(|(_, n, w)| format!("{n} ({})", w.join("; "))).collect();
        let extra = json!(blocked.iter().map(|(id, _, w)| json!({ "userId": id, "why": w })).collect::<Vec<_>>());
        let why = format!(
            "Not all of team {}'s data is in {region}: {}. Clear or change those members' own regions, or destroy their machines and delete the backups first (ADR 0129).",
            t.name,
            names.join(", ")
        );
        return Err(refuse("data_outside", why, extra));
    }
    let from = t.region.clone();
    app.db.pin_residency(PinOn::Team, &t.id, &region, &reference, by.actor.id.as_deref()).map_err(not_saved)?;
    let d = json!({ "region": region, "reference": reference, "regionFrom": from, "renewed": own.is_some(), "members": app.db.team_members(&t.id).len() });
    app.db.record(&crate::teams::team_event(&by, "team.residency_pinned", &t.id, d));
    let t = app.db.team(&t.id).ok_or_else(|| not_found("Team"))?;
    Ok(Json(region::team_region_view(&app, cp, &t)))
}

/// `DELETE /api/teams/{id}/residency` `{reason}`: ends the team's pin. Its data region
/// stays as it is.
pub async fn unpin_team(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(id): Path<String>, body: Result<Json<UnpinBody>, JsonRejection>) -> Res {
    let cp = &*a.machines;
    cp.need()?;
    let reason = unpin_body(body)?;
    let _g = cp.lock_ops().await;
    let t = app.db.team(id.trim()).ok_or_else(|| not_found("Team"))?;
    let p = app.db.residency_pin(PinOn::Team, &t.id).ok_or_else(|| not_found("Residency pin on this team"))?;
    if !app.db.unpin_residency(PinOn::Team, &t.id).map_err(not_saved)? {
        return Err(not_found("Residency pin on this team"));
    }
    let d = json!({ "region": p.region, "reference": p.reference, "pinnedAt": p.pinned_at, "pinnedBy": p.pinned_by, "reason": reason });
    app.db.record(&crate::teams::team_event(&by, "team.residency_unpinned", &t.id, d));
    Ok(Json(region::team_region_view(&app, cp, &t)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_bodies_need_an_offered_region_and_a_reference() {
        let cp = ControlPlane { regions: vec!["gb-lon".into(), "de-fra-2".into()], ..ControlPlane::default() };
        let b = |s: &str| serde_json::from_str::<PinBody>(s);
        let p = |s: &str| pin_body(&cp, Ok(Json(b(s).unwrap())));
        assert_eq!(p(r#"{"region":" gb-lon ","reference":" DPA-2026-014 "}"#).unwrap(), ("gb-lon".to_string(), "DPA-2026-014".to_string()));
        assert!(p(r#"{"region":"us-east","reference":"x"}"#).unwrap_err().1.contains("gb-lon, de-fra-2"));
        for r in [r#""  ""#, r#""a\nb""#, &format!("\"{}\"", "x".repeat(201))] {
            assert!(p(&format!(r#"{{"region":"gb-lon","reference":{r}}}"#)).is_err(), "{r}");
        }
        for body in [r#"{"region":"gb-lon"}"#, r#"{"region":"gb-lon","reference":"x","y":1}"#, "nope"] {
            assert!(b(body).is_err(), "{body}");
        }
        let u = |s: &str| unpin_body(serde_json::from_str::<UnpinBody>(s).map(Json).map_err(|_| unreachable!()));
        assert_eq!(u(r#"{"reason":" contract ended "}"#).unwrap(), "contract ended");
        assert!(u(r#"{"reason":""}"#).is_err());
    }

    #[test]
    fn a_region_keeps_pinned_data_only_once_it_is_offered() {
        let cp = ControlPlane { regions: vec!["gb-lon".into()], ..ControlPlane::default() };
        assert!(unready(&cp, "gb-lon").is_empty(), "no hosts and no off-host backups: nothing else to check");
        assert!(unready(&cp, "de-fra-2")[0].contains("isn't one of MACHINE_REGIONS (gb-lon)"));
    }

    #[test]
    fn residency_startup_is_warn_unless_set_to_refuse() {
        assert_eq!(Startup::parse(""), Ok(Startup::Warn));
        assert_eq!(Startup::parse(" Warn "), Ok(Startup::Warn));
        assert_eq!(Startup::parse("REFUSE"), Ok(Startup::Refuse));
        assert!(Startup::parse("strict").unwrap_err().contains("must be warn or refuse, not \"strict\""));
        assert_eq!(Startup::default().as_str(), "warn");
    }

    #[test]
    fn a_backup_is_in_a_region_by_its_recorded_store() {
        assert!(stored_in(None, Some("gb-lon"), "gb-lon"));
        assert!(!stored_in(None, Some("de-fra-2"), "gb-lon"));
        assert!(!stored_in(None, None, "gb-lon"), "the default store, with no store said to be anywhere");
    }
}
