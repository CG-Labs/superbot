//! Data regions (ADR 0117): where a user's machine and its off-host backups live. A
//! server admin sets one for a user or a team, from MACHINE_REGIONS; the most specific
//! wins: the user's own, else their team's, else the server's default (the first
//! region). New machines are made there: a Linode in that region, an Incus container
//! only on a host tagged with it (INCUS_REGION), and their backups go to that region's
//! store (`backup::Offsite::store_for`). A region set for someone is binding: a request
//! for another is refused, never placed elsewhere.
//!
//! Changing it is refused while their machine lives elsewhere. Moving a machine takes
//! its data across a border, so it is done on purpose (destroy it, delete its backups,
//! request a new one), never as a side effect of a setting. Every change and refusal is
//! audited: `user.region_changed`, `team.region_changed`, and `*_refused`.

use super::{ControlPlane, conflict};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, Team, User};
use crate::runner::App;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Auth, Res, bad, not_found};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, State as AppS};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

/// Where someone's effective region comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    User,
    Team,
    Default,
}

/// The region someone's machine and backups belong in.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Effective {
    pub region: String,
    pub source: Source,
    /// Whether this server still offers it (MACHINE_REGIONS).
    pub offered: bool,
}

impl Effective {
    /// Set for them or their team, so a request may not ask for another.
    pub fn binding(&self) -> bool {
        self.source != Source::Default
    }
}

fn resolve(cp: &ControlPlane, own: Option<&str>, team: Option<&str>) -> Effective {
    let (region, source) = match (own, team) {
        (Some(r), _) => (r, Source::User),
        (None, Some(r)) => (r, Source::Team),
        (None, None) => (cp.regions.first().map_or("", String::as_str), Source::Default),
    };
    Effective { region: region.into(), source, offered: cp.regions.iter().any(|r| r == region) }
}

fn team_of(app: &App, user_id: &str) -> Option<Team> {
    app.db.team_id_of(user_id).and_then(|t| app.db.team(&t))
}

/// `u`'s region now.
pub fn effective(app: &App, cp: &ControlPlane, u: &User) -> Effective {
    let team = team_of(app, &u.id).and_then(|t| t.region);
    resolve(cp, u.region.as_deref(), team.as_deref())
}

/// The user's machine, if they have one that isn't destroyed and isn't in `region`.
fn elsewhere(app: &App, user_id: &str, region: &str) -> Option<Machine> {
    app.db.user_machine(user_id).filter(|m| m.region != region)
}

/// Whether `user` may join `team` without their region moving away from their machine.
pub fn check_join(app: &App, team: &Team, user: &User) -> Result<(), String> {
    let (None, Some(r)) = (&user.region, &team.region) else { return Ok(()) };
    match elsewhere(app, &user.id, r) {
        None => Ok(()),
        Some(m) => Err(format!(
            "{}'s machine is in {}, and team {} keeps its data in {r}. Destroy their machine first, or set their own data region to {} (ADR 0117).",
            user.name, m.region, team.name, m.region
        )),
    }
}

/// A request for a machine in `asked`, against the region set for `u`: refused, and audited.
pub fn refuse_request(app: &App, by: &Who, u: &User, eff: &Effective, asked: &str) -> ApiError {
    let details = json!({ "reason": "data_region", "action": "request", "userEmail": u.email, "askedRegion": asked, "region": eff.region, "source": eff.source });
    app.db.record(&by.event("machine.refused").target("user", &u.id).outcome(Outcome::Denied).details(details));
    let whose = match eff.source {
        Source::Team => "their team's data region",
        _ => "their data region",
    };
    conflict(format!(
        "{}'s machine belongs in {} ({whose}), not {asked}. Leave the region out, or change their data region first (botctl user region).",
        u.name, eff.region
    ))
}

/// A region change's body: `{"region": "<id>"}`, or `{"region": null}`; the field is required.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pick {
    #[serde(deserialize_with = "nullable")]
    region: Option<String>,
}

fn nullable<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}

/// `null`, or one of MACHINE_REGIONS.
fn pick(cp: &ControlPlane, body: Result<Json<Pick>, JsonRejection>) -> Res<Option<String>> {
    let Ok(Json(Pick { region })) = body else {
        return Err(bad("Send {\"region\": \"<id>\"}, or {\"region\": null} for the server's default."));
    };
    match region.as_deref().map(str::trim) {
        None => Ok(None),
        Some(r) if cp.regions.iter().any(|x| x == r) => Ok(Some(r.to_string())),
        Some(_) => Err(bad(format!("region must be one of {}, or null for the server's default", cp.regions.join(", ")))),
    }
}

fn machine_view(m: Option<&Machine>, region: &str) -> Value {
    m.map_or(Value::Null, |m| json!({ "id": m.id, "state": m.state, "region": m.region, "inRegion": m.region == region }))
}

/// A user's region as admins see it: their own, their team's, and the one that applies.
pub fn user_view(app: &App, cp: &ControlPlane, u: &User) -> Value {
    let team = team_of(app, &u.id);
    let eff = effective(app, cp, u);
    let m = app.db.user_machine(&u.id);
    json!({
        "own": u.region,
        "team": team.map(|t| json!({ "id": t.id, "name": t.name, "region": t.region })),
        "effective": eff,
        "machine": machine_view(m.as_ref(), &eff.region),
    })
}

/// Backups a user's earlier machines left outside `region`, which a change leaves where they are.
fn kept_elsewhere(app: &App, cp: &ControlPlane, user_id: &str, region: &str) -> usize {
    let mine = app.db.user_machine(user_id).map(|m| m.id);
    app.db
        .user_machine_backups_kept(user_id)
        .iter()
        .filter(|b| Some(&b.machine_id) != mine.as_ref())
        .filter(|b| match (&b.store_region, cp.offsite.as_deref()) {
            (Some(r), _) => r != region,
            (None, Some(off)) => off.s.default_region.as_deref() != Some(region),
            (None, None) => true,
        })
        .count()
}

/// `GET /api/users/{key}/region`.
pub async fn get_user(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Path(key): Path<String>) -> Res {
    a.machines.need()?;
    let u = need_user_key(&app, &key)?;
    Ok(Json(user_view(&app, &a.machines, &u)))
}

/// `PUT /api/users/{key}/region` `{region: id | null}`: sets or clears a user's data
/// region. Refused while their machine is somewhere the new region isn't.
pub async fn set_user(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<crate::audit::Who>, Path(key): Path<String>, body: Result<Json<Pick>, JsonRejection>) -> Res {
    let cp = &*a.machines;
    cp.need()?;
    let to = pick(cp, body)?;
    let u = need_user_key(&app, &key)?;
    // Under the lock requests take, so no machine is made meanwhile in the old region.
    let _g = cp.lock_ops().await;
    let u = app.db.user(&u.id).ok_or_else(|| not_found("User"))?;
    let before = effective(&app, cp, &u);
    let team = team_of(&app, &u.id).and_then(|t| t.region);
    let after = resolve(cp, to.as_deref(), team.as_deref());
    let mut v = user_view(&app, cp, &u);
    if u.region == to {
        return Ok(Json(v));
    }
    let details = json!({ "from": u.region, "to": to, "effectiveFrom": before.region, "effectiveTo": after.region, "userEmail": u.email });
    if let Some(m) = elsewhere(&app, &u.id, &after.region) {
        let mut d = details;
        (d["reason"], d["machineId"], d["machineRegion"]) = (json!("machine_elsewhere"), json!(m.id), json!(m.region));
        app.db.record(&by.event("user.region_change_refused").target("user", &u.id).outcome(Outcome::Denied).details(d));
        return Err(conflict(format!(
            "{}'s machine is in {}. Moving their data to {} is done on purpose: destroy the machine, delete its backups if they must go too (botctl machine backups delete), then set the region and request a new machine (ADR 0117).",
            u.name, m.region, after.region
        )));
    }
    app.db.set_user_region(&u.id, to.as_deref());
    app.db.record(&by.event("user.region_changed").target("user", &u.id).details(details));
    let u = app.db.user(&u.id).ok_or_else(|| not_found("User"))?;
    v = user_view(&app, cp, &u);
    let left = kept_elsewhere(&app, cp, &u.id, &after.region);
    if left > 0 {
        v["warnings"] = json!([format!(
            "{left} backups of an earlier machine stay in their store outside {} until their retention ends or they are deleted (botctl machine backups delete).",
            after.region
        )]);
    }
    Ok(Json(v))
}

/// `GET /api/teams/{id}/region`.
pub async fn get_team(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Path(id): Path<String>) -> Res {
    a.machines.need()?;
    let t = app.db.team(id.trim()).ok_or_else(|| not_found("Team"))?;
    Ok(Json(team_region_view(&app, &a.machines, &t)))
}

/// `PUT /api/teams/{id}/region` `{region: id | null}`: sets or clears a team's data
/// region, for its members with none of their own. Refused while any of them has a
/// machine somewhere the new region isn't.
pub async fn set_team(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<crate::audit::Who>, Path(id): Path<String>, body: Result<Json<Pick>, JsonRejection>) -> Res {
    let cp = &*a.machines;
    cp.need()?;
    let to = pick(cp, body)?;
    let _g = cp.lock_ops().await;
    let t = app.db.team(id.trim()).ok_or_else(|| not_found("Team"))?;
    let before = resolve(cp, None, t.region.as_deref());
    let after = resolve(cp, None, to.as_deref());
    if t.region == to {
        return Ok(Json(team_region_view(&app, cp, &t)));
    }
    let (mut moved, mut blocked) = (0, Vec::new());
    for m in app.db.team_members(&t.id) {
        let Some(u) = app.db.user(&m.user_id).filter(|u| u.region.is_none()) else { continue };
        moved += 1;
        if let Some(machine) = elsewhere(&app, &u.id, &after.region) {
            blocked.push(json!({ "userId": u.id, "name": u.name, "machineId": machine.id, "machineRegion": machine.region }));
        }
    }
    let details = json!({ "from": t.region, "to": to, "effectiveFrom": before.region, "effectiveTo": after.region, "members": moved });
    if !blocked.is_empty() {
        let names: Vec<String> = blocked.iter().map(|b| format!("{} ({})", b["name"].as_str().unwrap_or(""), b["machineRegion"].as_str().unwrap_or(""))).collect();
        let mut d = details;
        (d["reason"], d["blocked"]) = (json!("machine_elsewhere"), json!(blocked));
        app.db.record(&crate::teams::team_event(&by, "team.region_change_refused", &t.id, d).outcome(Outcome::Denied));
        return Err(conflict(format!(
            "These members have machines outside {}: {}. Destroy those machines first, or give those members their own data region (ADR 0117).",
            after.region,
            names.join(", ")
        )));
    }
    app.db.set_team_region(&t.id, to.as_deref());
    app.db.record(&crate::teams::team_event(&by, "team.region_changed", &t.id, details));
    let t = app.db.team(&t.id).ok_or_else(|| not_found("Team"))?;
    Ok(Json(team_region_view(&app, cp, &t)))
}

/// A team's region and how many of its members it applies to.
pub fn team_region_view(app: &App, cp: &ControlPlane, t: &Team) -> Value {
    let members = app.db.team_members(&t.id);
    let own = members.iter().filter(|m| app.db.user(&m.user_id).is_some_and(|u| u.region.is_some())).count();
    json!({
        "teamId": t.id, "region": t.region, "effective": resolve(cp, None, t.region.as_deref()),
        "members": members.len(), "membersWithOwnRegion": own,
    })
}

/// `GET /api/regions`: the regions this server offers, the default, where each one's
/// machines and backups go, and how many users, teams and machines are in each.
pub async fn list(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>) -> Res {
    let cp = &*a.machines;
    let p = cp.need()?;
    let users = app.db.users();
    let teams = app.db.teams();
    let machines: Vec<Machine> = app.db.machines(None).into_iter().filter(|m| m.state != super::State::Destroyed).collect();
    let hosts = cp.hosts().filter(|h| h.tagged()).map(|h| h.configured());
    let backups = cp.offsite.as_deref().map(|off| off.regions_view());
    let mut ids: Vec<String> = cp.regions.clone();
    for r in users.iter().filter_map(|u| u.region.clone()).chain(teams.iter().filter_map(|t| t.region.clone())).chain(machines.iter().map(|m| m.region.clone())) {
        if !ids.contains(&r) {
            ids.push(r);
        }
    }
    let regions: Vec<Value> = ids
        .iter()
        .map(|r| {
            let mut v = json!({
                "id": r,
                "default": cp.regions.first() == Some(r),
                "offered": cp.regions.contains(r),
                "users": users.iter().filter(|u| u.region.as_deref() == Some(r.as_str())).count(),
                "teams": teams.iter().filter(|t| t.region.as_deref() == Some(r.as_str())).count(),
                "machines": machines.iter().filter(|m| m.region == *r).count(),
            });
            if let Some(h) = &hosts {
                v["hosts"] = json!(h.iter().filter(|h| h.region.as_deref() == Some(r.as_str())).map(|h| h.name.clone()).collect::<Vec<_>>());
            }
            if let Some(b) = backups.as_ref().and_then(|b| b.as_array()).and_then(|b| b.iter().find(|x| x["region"] == json!(r))) {
                v["backups"] = b.clone();
            }
            v
        })
        .collect();
    Ok(Json(json!({
        "provider": p.name(),
        "default": cp.regions.first(),
        "hostRegions": hosts.is_some(),
        "regions": regions,
        "backups": cp.offsite.as_deref().map(|off| json!({ "residency": off.s.residency, "dataRegion": off.s.default_region, "warnings": off.warnings() })),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_most_specific_region_wins() {
        let cp = ControlPlane { regions: vec!["gb-lon".into(), "de-fra-2".into()], ..ControlPlane::default() };
        let e = resolve(&cp, None, None);
        assert_eq!((e.region.as_str(), e.source, e.offered, e.binding()), ("gb-lon", Source::Default, true, false));
        let e = resolve(&cp, None, Some("de-fra-2"));
        assert_eq!((e.region.as_str(), e.source, e.binding()), ("de-fra-2", Source::Team, true));
        let e = resolve(&cp, Some("gb-lon"), Some("de-fra-2"));
        assert_eq!((e.region.as_str(), e.source), ("gb-lon", Source::User));
        let e = resolve(&cp, Some("eu-central"), None);
        assert!(!e.offered, "a region taken out of MACHINE_REGIONS still applies, and says it isn't offered");
    }

    #[test]
    fn a_region_is_null_or_one_offered() {
        let cp = ControlPlane { regions: vec!["gb-lon".into(), "de-fra-2".into()], ..ControlPlane::default() };
        let b = |s: &str| serde_json::from_str::<Pick>(s);
        let p = |s: &str| pick(&cp, Ok(Json(b(s).unwrap())));
        assert_eq!(p(r#"{"region":" de-fra-2 "}"#).unwrap().as_deref(), Some("de-fra-2"));
        assert_eq!(p(r#"{"region":null}"#).unwrap(), None);
        assert!(p(r#"{"region":"us-east"}"#).unwrap_err().1.contains("gb-lon, de-fra-2"));
        for body in [r#"{}"#, r#"{"region":"gb-lon","x":1}"#, r#"{"region":7}"#, "nope"] {
            assert!(b(body).is_err(), "{body}");
        }
    }
}
