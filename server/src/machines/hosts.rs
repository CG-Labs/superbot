//! Incus hosts (ADR 0076): where each machine's container is, which hosts answer, and
//! making a lost host's machines again on another host from their off-host backups.
//!
//! botd asks every host whether it answers each reconcile interval. One that hasn't for
//! INCUS_HOST_DOWN_MINUTES is down: audited (`machine.host_down`) and alerted, and
//! nothing new goes there; it is up again the first time it answers. botd never decides
//! by itself that a host is gone: a host that is down for a while may come back with
//! its containers, and restoring them elsewhere would leave two of each. An admin who
//! knows it is gone declares it lost (`POST /api/machines/hosts/{name}/recover`): its
//! machines' certificates are revoked, and each is restored from its newest off-host
//! backup onto a host that is up, a few at a time, enrolling anew with a fresh token.
//! Those with no backup are in error, to be destroyed and made again. A lost host is
//! never called again, so a name once lost isn't used for another host.
//!
//! Each host's certificate is recorded the first time it is configured; a host whose
//! certificate changes is refused at startup, so a name can't quietly point at another
//! host. At startup, provider ids from before there were several hosts (`<container>`)
//! become `<first host>/<container>`.

use super::backup::{self, Move};
use super::enroll;
use super::placement::{self, Tenant};
use super::provider::{HostStatus, Hosts, ProviderError};
use super::{ControlPlane, SYSTEM, State, Step, conflict, event, next};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, MachineHost, now};
use crate::notify::{self, Alert};
use crate::runner::App;
use crate::{AppState, Auth, Res, bad, not_found};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, Query, State as AppS};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub const HOST_LOST: &str = "host_lost";
/// Restores at once after a host is lost: each streams a whole disk.
const AT_ONCE: usize = 2;
const PAGE: &str = "machines";

fn machine_host(h: &dyn Hosts, m: &Machine) -> Option<String> {
    m.provider_id.as_deref().map(|p| h.host_of(p))
}

/// The host `m` is on, where the provider has several.
pub fn of(cp: &ControlPlane, m: &Machine) -> Option<String> {
    cp.owns(m).then(|| machine_host(cp.hosts()?, m)).flatten()
}

/// Why `m` can't be reached at its host now, if its host is down or lost.
pub(super) fn unreachable(cp: &ControlPlane, m: &Machine) -> Option<String> {
    let host = of(cp, m)?;
    match cp.hosts()?.status(&host)? {
        HostStatus::Up => None,
        HostStatus::Down => Some(format!("Its host {host} isn't answering.")),
        HostStatus::Lost => Some(format!("Its host {host} was declared lost.")),
    }
}

/// Why a machine whose earlier create went unanswered can't be made, or found gone,
/// now: that create may have reached a host that is down, and would be a second copy.
/// botd doesn't know which host it went to, so it waits until every host answers or
/// is declared lost.
pub(super) fn create_unsure(p: &dyn super::provider::MachineProvider, m: &Machine) -> Option<String> {
    if m.provider_id.is_some() || m.create_sent_at.is_none() {
        return None;
    }
    let down = p.hosts()?.configured().into_iter().find(|c| c.status == HostStatus::Down)?;
    Some(format!(
        "An earlier create may have reached Incus host {}, which isn't answering. Waiting until it answers or is declared lost.",
        down.name
    ))
}

/// Machines on `host` that are still to be dealt with.
fn on(app: &App, cp: &ControlPlane, h: &dyn Hosts, host: &str) -> Vec<Machine> {
    app.db
        .machines(None)
        .into_iter()
        .filter(|m| cp.owns(m) && !matches!(m.state, State::Destroyed) && machine_host(h, m).as_deref() == Some(host))
        .collect()
}

/// At startup: records each configured host and what botd found of it before, refuses
/// one whose certificate changed, and names the first host in provider ids from before
/// there were several. Returns how many ids it changed.
pub fn load(app: &App, cp: &ControlPlane) -> Result<usize, String> {
    let Some(h) = cp.hosts() else { return Ok(0) };
    let configured = h.configured();
    for c in &configured {
        if let Some(row) = app.db.machine_host(&c.name)
            && row.fingerprint != c.fingerprint
        {
            return Err(format!(
                "Incus host {}: its certificate ({}) isn't the one botd first saw for it ({}). If it is another host, give it a new name in INCUS_HOSTS; if it is the same one, set its certificate back.",
                c.name, c.fingerprint, row.fingerprint
            ));
        }
        let row = app.db.machine_host_add(&c.name, &c.url, &c.fingerprint);
        h.set_status(&c.name, HostStatus::parse(&row.state).unwrap_or(HostStatus::Up));
    }
    for row in app.db.machine_hosts() {
        if row.state == "lost" {
            h.set_status(&row.name, HostStatus::Lost);
        } else if !configured.iter().any(|c| c.name == row.name) {
            let n = on(app, cp, h, &row.name).len();
            if n > 0 {
                crate::obs::log::log_warn!("WARNING: Incus host {} isn't in INCUS_HOSTS any more, and {n} machines are on it. Put it back, or declare it lost to restore them elsewhere (botctl machine host recover {}).", row.name, row.name);
            }
        }
    }
    let first = &configured[0].name;
    let mut moved = 0;
    for m in app.db.machines(None).into_iter().filter(|m| cp.owns(m) && m.state != State::Destroyed) {
        if let Some(pid) = m.provider_id.as_deref().filter(|p| !p.contains('/')) {
            app.db.set_machine_provider_id(&m.id, &h.id_on(first, pid));
            moved += 1;
        }
    }
    if moved > 0 {
        crate::obs::log::log_info!("Incus hosts: {moved} machines from before there were several hosts are on {first} (INCUS_HOST_NAME).");
    }
    for w in dedication_warnings(app, cp) {
        crate::obs::log::log_warn!("WARNING: {w}");
    }
    Ok(moved)
}

/// What an admin should fix about dedicated hosts (ADR 0166): hosts dedicated to a team
/// that is gone, which take nothing, and machines on hosts they shouldn't be on.
pub fn dedication_warnings(app: &App, cp: &ControlPlane) -> Vec<String> {
    let Some(h) = cp.hosts() else { return Vec::new() };
    let mut out: Vec<String> = app
        .db
        .machine_hosts()
        .into_iter()
        .filter(|r| r.state != "lost" && r.dedicated_team.as_deref().is_some_and(|t| app.db.team(t).is_none()))
        .map(|r| format!("Incus host {} is dedicated to a team that no longer exists, so no new machine goes there. Share it: botctl machine host share {} --reason <text>.", r.name, r.name))
        .collect();
    let misplaced = placement::misplaced(app, cp, h);
    if !misplaced.is_empty() {
        let first = &misplaced[0];
        out.push(format!(
            "{} machines are on hosts their team's dedication doesn't allow, such as {} ({}); `botctl machine hosts` lists them. Move each with botctl machine restore <user> <backup-id> --host <name> --yes.",
            misplaced.len(),
            first.machine_id,
            first.reason
        ));
    }
    out
}

fn record(app: &App, by: &Who, action: &str, host: &str, outcome: Outcome, details: Value) {
    app.db.record(&by.event(action).target("host", host).outcome(outcome).details(details));
}

fn alert(app: &AppState, action: &str, host: &str, title: String, lines: Vec<String>) {
    let a = Alert { event: action.into(), title, lines, target_type: "host".into(), target_id: host.into(), link: None };
    notify::alert(app, a, PAGE);
}

fn time(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default()
}

/// One check of every host that isn't lost: down after INCUS_HOST_DOWN_MINUTES without
/// an answer, up again at the first. Each change is audited and alerted once. Returns
/// how many hosts are down.
pub async fn watch(app: &AppState, cp: &ControlPlane) -> usize {
    let Some(h) = cp.hosts() else { return 0 };
    let by = Who::system(SYSTEM);
    let mut down = 0;
    for c in h.configured().into_iter().filter(|c| c.status != HostStatus::Lost) {
        match h.probe(&c.name).await {
            Ok(_) => {
                if app.db.machine_host_answered(&c.name) {
                    h.set_status(&c.name, HostStatus::Up);
                    let n = on(app, cp, h, &c.name).len();
                    record(app, &by, "machine.host_up", &c.name, Outcome::Success, json!({ "url": c.url, "machines": n }));
                    alert(app, "machine.host_up", &c.name, format!("Incus host {} answers again", c.name), vec![format!("{n} machines are on it; new machines can go there again.")]);
                }
            }
            Err(e) => {
                let since = app.db.machine_host_failed(&c.name, &e.to_string());
                if c.status == HostStatus::Down {
                    down += 1;
                } else if since.is_some_and(|s| now() - s >= h.down_after_ms()) && app.db.machine_host_down(&c.name) {
                    down += 1;
                    h.set_status(&c.name, HostStatus::Down);
                    let n = on(app, cp, h, &c.name).len();
                    let since = since.unwrap_or_else(now);
                    record(app, &by, "machine.host_down", &c.name, Outcome::Failure, json!({ "url": c.url, "since": since, "error": e.to_string(), "machines": n }));
                    let lines = vec![
                        format!("It hasn't answered since {}: {e}", time(since)),
                        format!("{n} machines are on it. Nothing new goes there until it answers."),
                        format!("If it is gone for good, `botctl machine host recover {}` restores its machines from their newest off-host backups onto another host.", c.name),
                    ];
                    alert(app, "machine.host_down", &c.name, format!("Incus host {} isn't answering", c.name), lines);
                }
            }
        }
    }
    down
}

/// How long a host may take to say what it uses (ADR 0106).
pub const READ_WITHIN: Duration = Duration::from_secs(10);

/// With `/metrics` on, what each host that is up has and uses now (ADR 0106): all at
/// once, each given `within`. It runs apart from host checks and reconciling, so a host
/// slow to answer holds up neither. A read that fails keeps the last one, whose age
/// shows on `/metrics`; it is logged once until a read works again, and never makes
/// the host down.
pub async fn read_uses(app: &AppState, cp: &ControlPlane, within: Duration) {
    let metrics = app.db.metrics();
    let Some(h) = cp.hosts().filter(|_| metrics.wants_host_use()) else { return };
    let up = h.configured().into_iter().filter(|c| c.status == HostStatus::Up);
    let reads = up.map(|c| async move { (tokio::time::timeout(within, h.host_use(&c.name)).await, c.name) });
    for (read, host) in futures_util::future::join_all(reads).await {
        let e = match read {
            Ok(Ok(u)) => {
                metrics.host_read(&host, now(), u);
                continue;
            }
            Ok(Err(e)) => e.to_string(),
            Err(_) => format!("no answer within {}s", within.as_secs_f64()),
        };
        if metrics.host_read_failed(&host) {
            crate::obs::log::log_warn!("WARNING: Incus host {host} didn't say what it uses ({e}); its capacity metrics keep their last reading.");
        }
    }
}

/// Where a restore of `m` goes: `host` if given, else its own host, or the host
/// placement picks (ADR 0081) when its own was lost. Onto another host, its own must
/// be up (its old container is deleted) or lost, and the new one open with room.
pub(super) fn restore_move(app: &App, cp: &ControlPlane, m: &Machine, host: Option<&str>) -> Res<Move> {
    let Some(h) = cp.hosts() else {
        return match host {
            Some(_) => Err(bad("This server has one Incus host, so there's nowhere else to restore onto (INCUS_HOSTS, ADR 0076).")),
            None => Ok(Move::default()),
        };
    };
    let from = machine_host(h, m).unwrap_or_else(|| h.host_of(&m.label));
    let tenant = Tenant::of(app, &m.user_id);
    let to = match host {
        Some(t) => t.to_string(),
        None if h.status(&from) == Some(HostStatus::Lost) => placement::choose(app, cp, &m.plan, &m.region, &tenant, Some(&from))
            .map_err(|why| conflict(format!("Its host {from} was declared lost, and there's nowhere to restore it. {why}")))?,
        None => from.clone(),
    };
    let names: Vec<String> = h.configured().into_iter().map(|c| c.name).collect();
    if !names.contains(&to) {
        return Err(bad(format!("There's no Incus host \"{}\": one of {}.", crate::audit::clip(&to, 40), names.join(", "))));
    }
    if let Some(s) = h.status(&to).filter(|s| *s != HostStatus::Up) {
        return Err(conflict(format!("Host {to} is {}; restore onto a host that is up.", s.as_str())));
    }
    if to != from && h.status(&from) == Some(HostStatus::Down) {
        return Err(conflict(format!(
            "Its host {from} is down, so its container there can't be deleted. If that host is gone for good, declare it lost: botctl machine host recover {from}."
        )));
    }
    if to != from {
        placement::fits(app, cp, &m.plan, &m.region, &tenant, &to).map_err(conflict)?;
    }
    Ok(Move { from: Some(from), to: Some(to), reason: None })
}

fn row_view(app: &App, cp: &ControlPlane, h: &dyn Hosts, row: &MachineHost, configured: bool) -> Value {
    let mut v = json!(row);
    v["configured"] = json!(configured);
    v["machines"] = json!(on(app, cp, h, &row.name).len());
    v
}

/// Every host botd has known, configured ones first, with each configured one's load
/// and where a new machine of the first tier would go now.
pub fn view(app: &App, cp: &ControlPlane) -> Option<Value> {
    let h = cp.hosts()?;
    let rows: HashMap<String, MachineHost> = app.db.machine_hosts().into_iter().map(|r| (r.name.clone(), r)).collect();
    let configured = h.configured();
    let loads = placement::loads(app, cp, h);
    let mut out: Vec<Value> = configured
        .iter()
        .map(|c| {
            let mut v = match rows.get(&c.name) {
                Some(r) => row_view(app, cp, h, r, true),
                None => json!({ "name": c.name, "url": c.url, "fingerprint": c.fingerprint, "state": c.status, "configured": true, "machines": on(app, cp, h, &c.name).len() }),
            };
            v["load"] = loads.iter().find(|l| l.name == c.name).map_or(Value::Null, |l| l.view());
            v["region"] = json!(c.region);
            v
        })
        .collect();
    let mut rest: Vec<&MachineHost> = rows.values().filter(|r| !configured.iter().any(|c| c.name == r.name)).collect();
    rest.sort_by_key(|r| (r.created_at, r.name.clone()));
    out.extend(rest.into_iter().map(|r| row_view(app, cp, h, r, false)));
    let mut v = json!({ "hosts": out, "policy": h.policy(), "downMinutes": h.down_after_ms() / 60_000 });
    v["misplaced"] = json!(placement::misplaced(app, cp, h).iter().map(placement::Misplaced::view).collect::<Vec<_>>());
    v["dedicationWarnings"] = json!(dedication_warnings(app, cp));
    if let (Some((tier, plan)), Some(region)) = (cp.tiers.first(), cp.regions.first()) {
        // For someone in no team; each team with hosts of its own below.
        let nobody = Tenant::default();
        match placement::choose(app, cp, plan, region, &nobody, None) {
            Ok(host) => v["placement"] = json!(host),
            Err(why) => (v["placement"], v["placementRefused"]) = (Value::Null, json!(why)),
        }
        v["placementFor"] = json!({ "tier": tier, "plan": plan, "region": region });
        let mut teams: Vec<String> = rows.values().filter_map(|r| r.dedicated_team.clone()).collect();
        teams.sort();
        teams.dedup();
        v["dedicated"] = json!(teams
            .iter()
            .map(|team| {
                let t = Tenant { team: Some(team.clone()), own_hosts: true };
                let mut names: Vec<&str> = rows.values().filter(|r| r.dedicated_team.as_deref() == Some(team)).map(|r| r.name.as_str()).collect();
                names.sort();
                let mut d = json!({ "team": team, "name": app.db.team(team).map(|t| t.name), "hosts": names });
                match placement::choose(app, cp, plan, region, &t, None) {
                    Ok(host) => d["placement"] = json!(host),
                    Err(why) => (d["placement"], d["placementRefused"]) = (Value::Null, json!(why)),
                }
                d
            })
            .collect::<Vec<_>>());
        if h.tagged() {
            v["regions"] = json!(cp
                .regions
                .iter()
                .map(|r| match placement::choose(app, cp, plan, r, &nobody, None) {
                    Ok(host) => json!({ "region": r, "placement": host }),
                    Err(why) => json!({ "region": r, "placement": null, "placementRefused": why }),
                })
                .collect::<Vec<_>>());
        }
    }
    Some(v)
}

/// `{reason?}`: why the host is drained, for whoever looks next.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DrainBody {
    #[serde(default)]
    reason: Option<String>,
}

/// The configured host `name` that isn't lost, for draining.
fn drainable(app: &App, h: &dyn Hosts, name: &str) -> Res<MachineHost> {
    let row = app.db.machine_host(name.trim()).ok_or_else(|| not_found("Incus host"))?;
    if row.state == "lost" {
        return Err(conflict(format!("Host {} was declared lost; nothing goes there anyway.", row.name)));
    }
    if !h.configured().iter().any(|c| c.name == row.name) {
        return Err(conflict(format!("Host {} isn't in INCUS_HOSTS any more; nothing goes there anyway.", row.name)));
    }
    Ok(row)
}

fn host_view(app: &App, cp: &ControlPlane, name: &str) -> Value {
    view(app, cp)
        .and_then(|v| v["hosts"].as_array().and_then(|hs| hs.iter().find(|x| x["name"] == name).cloned()))
        .unwrap_or_default()
}

/// `PUT /api/machines/hosts/{name}/drain` `{reason?}`: nothing new is placed on the
/// host (ADR 0081): no new machines, and no restores onto it from elsewhere. Its
/// machines stay; move them one at a time with a restore `--host`. Again, nothing
/// changes.
pub async fn drain(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(name): Path<String>,
    Json(req): Json<DrainBody>,
) -> Res {
    let cp = need_hosts(&a)?;
    let h = cp.hosts().ok_or_else(|| not_found("Incus host"))?;
    let reason = one_line(req.reason.as_deref())?;
    let _g = cp.ops.lock().await;
    let row = drainable(&app, h, &name)?;
    if app.db.machine_host_drain(&row.name, by.actor.id.as_deref(), reason.as_deref()) {
        let n = on(&app, cp, h, &row.name).len();
        record(&app, &by, "machine.host_drained", &row.name, Outcome::Success, json!({ "reason": reason, "machines": n }));
    }
    Ok(Json(host_view(&app, cp, &row.name)))
}

/// `DELETE /api/machines/hosts/{name}/drain`: new machines may go there again.
pub async fn undrain(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(name): Path<String>) -> Res {
    let cp = need_hosts(&a)?;
    let h = cp.hosts().ok_or_else(|| not_found("Incus host"))?;
    let _g = cp.ops.lock().await;
    let row = drainable(&app, h, &name)?;
    if app.db.machine_host_undrain(&row.name) {
        let d = json!({ "drainedAt": row.drained_at, "drainedBy": row.drained_by, "reason": row.drain_reason });
        record(&app, &by, "machine.host_undrained", &row.name, Outcome::Success, d);
    }
    Ok(Json(host_view(&app, cp, &row.name)))
}

/// `{team, reason?}`: the team a host is dedicated to, and why, such as the agreement.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DedicateBody {
    team: String,
    #[serde(default)]
    reason: Option<String>,
}

/// `{reason}`: why a dedicated host is shared again.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShareBody {
    #[serde(default)]
    reason: Option<String>,
}

/// One line of up to 200 characters, or none.
fn one_line(raw: Option<&str>) -> Res<Option<String>> {
    let r = raw.map(str::trim).filter(|r| !r.is_empty()).map(|r| crate::audit::clip(r, 200).to_string());
    if r.as_deref().is_some_and(|r| r.chars().any(char::is_control)) {
        return Err(bad("reason: one line of text"));
    }
    Ok(r)
}

/// Every machine that isn't destroyed and is on `host`, was sent there, or is being
/// restored onto it.
fn occupants(app: &App, cp: &ControlPlane, h: &dyn Hosts, host: &str) -> Vec<Machine> {
    let mut out: Vec<Machine> = app
        .db
        .machines(None)
        .into_iter()
        .filter(|m| cp.owns(m) && m.state != State::Destroyed)
        .filter(|m| match machine_host(h, m) {
            Some(on) => on == host,
            None => m.placed_on.as_deref() == Some(host),
        })
        .collect();
    for r in ["importing", "replacing"].into_iter().flat_map(|s| app.db.machine_restores_in(s)) {
        if r.to_host.as_deref() == Some(host)
            && !out.iter().any(|m| m.id == r.machine_id)
            && let Some(m) = app.db.machine(&r.machine_id)
        {
            out.push(m);
        }
    }
    out
}

/// How long dedicating may spend, under the ops lock, asking a host about leftover copies.
const LEFTOVER_CHECKS: Duration = Duration::from_millis(if cfg!(test) { 500 } else { 20_000 });

/// The machines of people not on `team` whose failed restore onto `host` may have left
/// its imported copy there, with the copy's id. Cleanup keeps a copy that is all that's
/// left of its machine, and may fail to delete one, so each counts until the provider
/// says it is gone, and so does each not asked about by `deadline`.
async fn leftover_copies(app: &App, cp: &ControlPlane, host: &str, team: &str, deadline: tokio::time::Instant) -> Vec<(Machine, String)> {
    let Some(p) = cp.provider.as_deref() else { return Vec::new() };
    let mut out: Vec<(Machine, String)> = Vec::new();
    let mut gone: Vec<String> = Vec::new();
    for r in app.db.machine_restores_in("failed") {
        if r.to_host.as_deref() != Some(host) {
            continue;
        }
        let Some(m) = app.db.machine(&r.machine_id) else { continue };
        if app.db.team_id_of(&m.user_id).as_deref() == Some(team) {
            continue;
        }
        let copy = backup::staging(p, &m, &r);
        if gone.contains(&copy) || out.iter().any(|(_, c)| *c == copy) {
            continue;
        }
        match tokio::time::timeout_at(deadline, p.get(&copy)).await {
            Ok(Err(ProviderError::NotFound)) => gone.push(copy),
            _ => out.push((m, copy)),
        }
    }
    out
}

/// `PUT /api/machines/hosts/{name}/dedication` `{team, reason?}`: only the team's
/// machines go on the host from now on, and the team's go only on hosts dedicated to it
/// (ADR 0166): new machines, retries, restores onto another host, and a lost host's
/// recovery. Refused while anyone else's machine is on it, sent there, or being restored
/// there: move those first. Refused too while a failed restore of theirs may have left
/// its copy there. Server admins only (rbac leaves it to Admin).
pub async fn dedicate(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(name): Path<String>,
    Json(req): Json<DedicateBody>,
) -> Res {
    let cp = need_hosts(&a)?;
    let h = cp.hosts().ok_or_else(|| not_found("Incus host"))?;
    let reason = one_line(req.reason.as_deref())?;
    let _g = cp.ops.lock().await;
    let row = drainable(&app, h, &name)?;
    let team = app.db.team(req.team.trim()).ok_or_else(|| not_found("Team"))?;
    match row.dedicated_team.as_deref() {
        Some(t) if t == team.id => return Ok(Json(host_view(&app, cp, &row.name))),
        Some(_) => {
            return Err(conflict(format!(
                "Host {} is dedicated to another team. Share it first (botctl machine host share {} --reason <text>).",
                row.name, row.name
            )));
        }
        None => {}
    }
    let here = occupants(&app, cp, h, &row.name);
    let others: Vec<&Machine> = here.iter().filter(|m| app.db.team_id_of(&m.user_id).as_deref() != Some(team.id.as_str())).collect();
    if !others.is_empty() {
        let ids: Vec<&str> = others.iter().map(|m| m.id.as_str()).collect();
        let d = json!({ "team": team.id, "reason": "other_tenants", "machines": ids.len(), "machineIds": ids.iter().take(20).collect::<Vec<_>>() });
        record(&app, &by, "machine.host_dedication_refused", &row.name, Outcome::Denied, d);
        return Err(conflict(format!(
            "Host {} has {} machines of people not on team {}, such as {}. Move them to other hosts first (botctl machine restore <user> <backup-id> --host <name> --yes), or wait for restores onto it to finish.",
            row.name,
            others.len(),
            team.name,
            ids.iter().take(5).copied().collect::<Vec<_>>().join(", ")
        )));
    }
    let others = leftover_copies(&app, cp, &row.name, &team.id, tokio::time::Instant::now() + LEFTOVER_CHECKS).await;
    if !others.is_empty() {
        let ids: Vec<&str> = others.iter().map(|(m, _)| m.id.as_str()).collect();
        let d = json!({ "team": team.id, "reason": "leftover_copies", "machines": ids.len(), "machineIds": ids.iter().take(20).collect::<Vec<_>>() });
        record(&app, &by, "machine.host_dedication_refused", &row.name, Outcome::Denied, d);
        return Err(conflict(format!(
            "Host {} may still hold copies that failed restores left of {} machines of people not on team {}: {}. Delete them on the host first, or bring it back up if it isn't answering.",
            row.name,
            others.len(),
            team.name,
            others.iter().take(5).map(|(_, c)| c.as_str()).collect::<Vec<_>>().join(", ")
        )));
    }
    if app.db.machine_host_dedicate(&row.name, &team.id, by.actor.id.as_deref(), reason.as_deref()) {
        let d = json!({ "team": team.id, "teamName": team.name, "reason": reason, "machines": here.len() });
        record(&app, &by, "machine.host_dedicated", &row.name, Outcome::Success, d);
    }
    Ok(Json(host_view(&app, cp, &row.name)))
}

/// `DELETE /api/machines/hosts/{name}/dedication` `{reason}`: anyone's new machines may
/// go on the host again, and its team's may go on shared hosts if it has no other. The
/// reason is required: a dedication is often a promise to a customer. Works on a lost
/// host or one no longer configured too, so a team whose only host was lost can be let
/// onto shared ones.
pub async fn share(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(name): Path<String>,
    body: Result<Json<ShareBody>, JsonRejection>,
) -> Res {
    let cp = need_hosts(&a)?;
    let h = cp.hosts().ok_or_else(|| not_found("Incus host"))?;
    let raw = body.ok().and_then(|Json(b)| b.reason);
    let reason = one_line(raw.as_deref())?.ok_or_else(|| bad("Send {\"reason\": \"<why the host is shared again>\"}."))?;
    let _g = cp.ops.lock().await;
    let row = app.db.machine_host(name.trim()).ok_or_else(|| not_found("Incus host"))?;
    if app.db.machine_host_share(&row.name) {
        let d = json!({
            "team": row.dedicated_team, "dedicatedAt": row.dedicated_at, "dedicatedBy": row.dedicated_by,
            "dedicationReason": row.dedication_reason, "reason": reason, "machines": occupants(&app, cp, h, &row.name).len(),
        });
        record(&app, &by, "machine.host_shared", &row.name, Outcome::Success, d);
    }
    Ok(Json(host_view(&app, cp, &row.name)))
}

fn need_hosts(a: &Auth) -> Res<&ControlPlane> {
    let cp = &*a.machines;
    cp.need()?;
    cp.hosts().map(|_| cp).ok_or_else(|| conflict("Machines here aren't on Incus hosts (MACHINE_PROVIDER=incus, ADR 0076).".into()))
}

/// `GET /api/machines/hosts?check=true`: every host, its state and machines. `check`
/// asks each host that isn't lost now, as the reconciler does.
pub async fn list(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Query(q): Query<HashMap<String, String>>) -> Res {
    let cp = need_hosts(&a)?;
    if q.get("check").is_some_and(|c| matches!(c.as_str(), "1" | "true" | "yes")) {
        watch(&app, cp).await;
    }
    Ok(Json(view(&app, cp).unwrap_or_default()))
}

/// `{to?, identity?}`: the host to restore onto (the first other host that is up by
/// default), and the age identity for encrypted backups, used for these restores only.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoverBody {
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    identity: Option<String>,
}

/// Refuses a recovery of `host` with nowhere open to restore onto: `to`, or any other host.
fn open_targets(app: &App, cp: &ControlPlane, h: &dyn Hosts, host: &str, to: Option<&str>) -> Res<()> {
    let loads = placement::loads(app, cp, h);
    match to {
        Some(t) => {
            if let Some(s) = h.status(t).filter(|s| *s != HostStatus::Up) {
                return Err(conflict(format!("Host {t} is {}; restore onto a host that is up.", s.as_str())));
            }
            if let Some(why) = loads.iter().find(|l| l.name == t).and_then(|l| l.closed()) {
                return Err(conflict(format!("Host {why}; restore onto a host that is open.")));
            }
        }
        None if !loads.iter().any(|l| l.name != host && l.closed().is_none()) => {
            return Err(conflict(
                "No other Incus host is up and open to restore onto. Add one to INCUS_HOSTS and restart botd, or undrain one (botctl machine host undrain <name>).".into(),
            ));
        }
        None => {}
    }
    Ok(())
}

/// `POST /api/machines/hosts/{name}/recover`: declares the host lost and restores each
/// of its machines from its newest off-host backup onto another host. Refused while the
/// host answers. Again later, it picks up machines it couldn't do before. 202.
pub async fn recover(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(name): Path<String>,
    Json(req): Json<RecoverBody>,
) -> Res<(StatusCode, Json<Value>)> {
    let cp = need_hosts(&a)?;
    backup::need(&a)?;
    if cp.enrollment.is_none() {
        return Err(conflict("Restored machines enroll again, so they need enrollment on (MACHINE_CONTROL_URL).".into()));
    }
    let h = cp.hosts().ok_or_else(|| not_found("Incus host"))?;
    let name = name.trim().to_string();
    let row = app.db.machine_host(&name).ok_or_else(|| not_found("Incus host"))?;
    // Onto `to` if given, else each machine where placement puts it (ADR 0081).
    let to = req.to.as_deref().map(str::trim).filter(|t| !t.is_empty()).map(String::from);
    match &to {
        Some(t) if *t == name => return Err(bad("A host's machines are restored onto another host.")),
        Some(t) if !h.configured().iter().any(|c| c.name == *t) => {
            return Err(bad(format!("There's no Incus host \"{}\".", crate::audit::clip(t, 40))));
        }
        _ => open_targets(&app, cp, h, &name, to.as_deref())?,
    }
    if row.state != "lost" && h.configured().iter().any(|c| c.name == name) && h.probe(&name).await.is_ok() {
        if app.db.machine_host_answered(&name) {
            h.set_status(&name, HostStatus::Up);
        }
        let to = to.as_deref().unwrap_or("<host>");
        return Err(conflict(format!(
            "Host {name} answers, so its containers are still there. Move its machines one at a time (botctl machine restore <user> <backup-id> --host {to}), which deletes each old container, or try again once it doesn't answer."
        )));
    }
    let ids = match req.identity.as_deref().filter(|i| !i.trim().is_empty()) {
        Some(raw) => backup::identities(raw).map_err(bad)?,
        None => Vec::new(),
    };

    let _g = cp.ops.lock().await;
    // Again under the lock: a target may have been drained or gone down meanwhile.
    open_targets(&app, cp, h, &name, to.as_deref())?;
    let machines = on(&app, cp, h, &name);
    if ids.is_empty()
        && let Some(m) = machines
            .iter()
            .find(|m| backup::cannot_restore(&app, m).is_none() && app.db.machine_last_backup(&m.id).is_some_and(|b| b.encrypted))
    {
        return Err(bad(format!("{}'s newest backup is encrypted: send the age identity as \"identity\" (--identity <file>). Nothing was changed.", m.id)));
    }
    let declared = app.db.machine_host_lost(&name, by.actor.id.as_deref());
    h.set_status(&name, HostStatus::Lost);
    if declared {
        let d = json!({ "url": row.url, "machines": machines.len(), "to": to, "placement": h.policy() });
        record(&app, &by, "machine.host_lost", &name, Outcome::Failure, d);
    }
    let (mut restoring, mut unrestorable, mut skipped) = (Vec::new(), Vec::new(), Vec::new());
    let mut onto: Vec<String> = Vec::new();
    let mut runs = Vec::new();
    for m in machines {
        // Nothing from that host's disks is trusted again, even while a restore is underway.
        enroll::revoke_all(&app, &by, &m, HOST_LOST);
        if let Some(r) = app.db.machine_restoring(&m.id) {
            skipped.push(json!({ "machineId": m.id, "userId": m.user_id, "reason": format!("A restore is {} already.", r.state) }));
            continue;
        }
        if m.state == State::Destroying {
            continue;
        }
        if let Some(why) = backup::cannot_restore(&app, &m) {
            skipped.push(json!({ "machineId": m.id, "userId": m.user_id, "reason": why }));
            continue;
        }
        match app.db.machine_last_backup(&m.id) {
            Some(b) => {
                // A pinned user's machine is restored only from a backup, and onto a host, in their region (ADR 0129).
                let pinned = |t: Option<&str>| super::residency::check_restore(&app, cp, &m, &b, t);
                if let Err((p, why)) = pinned(to.as_deref()) {
                    super::residency::refused(&app, &by, &m, "recover", &p, &why);
                    skipped.push(json!({ "machineId": m.id, "userId": m.user_id, "reason": why }));
                    continue;
                }
                // Each placed with the ones before it counted, so a host isn't filled past its room.
                // A team with hosts of its own gets only those (ADR 0166).
                let tenant = Tenant::of(&app, &m.user_id);
                let target = match &to {
                    Some(t) => placement::fits(&app, cp, &m.plan, &m.region, &tenant, t).map(|()| t.clone()),
                    None => placement::choose(&app, cp, &m.plan, &m.region, &tenant, Some(&name)),
                };
                let t = match target {
                    Ok(t) => t,
                    Err(why) => {
                        skipped.push(json!({ "machineId": m.id, "userId": m.user_id, "reason": why }));
                        continue;
                    }
                };
                if let Err((p, why)) = pinned(Some(&t)) {
                    super::residency::refused(&app, &by, &m, "recover", &p, &why);
                    skipped.push(json!({ "machineId": m.id, "userId": m.user_id, "reason": why }));
                    continue;
                }
                let mv = Move { from: Some(name.clone()), to: Some(t.clone()), reason: Some(HOST_LOST) };
                match backup::begin_restore(&app, cp, &m, &b, &by, &mv) {
                    Some(r) => {
                        restoring.push(json!({ "machineId": m.id, "userId": m.user_id, "toHost": t, "restore": r }));
                        runs.push((r, b));
                        if !onto.contains(&t) {
                            onto.push(t);
                        }
                    }
                    None => skipped.push(json!({ "machineId": m.id, "userId": m.user_id, "reason": "A restore began meanwhile." })),
                }
            }
            None => {
                unrestorable.push(json!({ "machineId": m.id, "userId": m.user_id }));
                let why = format!("Its host {name} was lost, and it has no off-host backup to restore. Destroy it and request a new one.");
                if m.last_error.as_deref() == Some(why.as_str()) {
                    continue;
                }
                let (mut m, from) = (m.clone(), m.state);
                m.state = next(from, Step::Fail).unwrap_or(State::Error);
                m.last_error = Some(why);
                if app.db.save_machine(&m, from) {
                    let d = json!({ "providerId": m.provider_id, "was": from, "reason": HOST_LOST, "host": name, "restorable": false });
                    app.db.record(&event(&by, "machine.lost", &m, d).outcome(Outcome::Failure));
                }
            }
        }
    }
    if declared {
        let where_to = if onto.is_empty() { to.clone().unwrap_or_else(|| "other hosts".into()) } else { onto.join(", ") };
        let mut lines = vec![format!("{} machines are being restored onto {where_to} from their newest off-host backups.", restoring.len())];
        if !unrestorable.is_empty() {
            lines.push(format!("{} have no off-host backup and are in error: destroy them and request new ones.", unrestorable.len()));
        }
        if !skipped.is_empty() {
            lines.push(format!("{} were left for now; recover the host again to retry them.", skipped.len()));
        }
        alert(&app, "machine.host_lost", &name, format!("Incus host {name} was declared lost"), lines);
    }
    let cp_arc = a.machines.clone();
    let (task_app, task_by) = (app.clone(), by.clone());
    tokio::spawn(async move {
        use futures_util::StreamExt;
        futures_util::stream::iter(runs)
            .for_each_concurrent(AT_ONCE, |(r, b)| backup::restore(task_app.clone(), cp_arc.clone(), r, b, ids.clone(), task_by.clone()))
            .await;
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "host": name, "to": to, "toHosts": onto, "placement": h.policy(), "declaredLost": declared,
            "restoring": restoring, "unrestorable": unrestorable, "skipped": skipped,
        })),
    ))
}
