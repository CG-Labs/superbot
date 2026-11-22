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
use super::placement;
use super::provider::{HostStatus, Hosts};
use super::{ControlPlane, SYSTEM, State, Step, conflict, event, next};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, MachineHost, now};
use crate::notify::{self, Alert};
use crate::runner::App;
use crate::{AppState, Auth, Res, bad, not_found};
use axum::Json;
use axum::extract::{Extension, Path, Query, State as AppS};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

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
    Ok(moved)
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
                read_use(app, h, &c.name).await;
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

/// With `/metrics` on, what a host that answered has and uses now (ADR 0106). A read
/// that fails keeps the last one, whose age shows on `/metrics`; it is logged once
/// until a read works again, and never makes the host down.
async fn read_use(app: &AppState, h: &dyn Hosts, host: &str) {
    let metrics = app.db.metrics();
    if !metrics.wants_host_use() {
        return;
    }
    match h.host_use(host).await {
        Ok(u) => metrics.host_read(host, now(), u),
        Err(e) => {
            if metrics.host_read_failed(host) {
                crate::obs::log::log_warn!("WARNING: Incus host {host} didn't say what it uses ({e}); its capacity metrics keep their last reading.");
            }
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
    let to = match host {
        Some(t) => t.to_string(),
        None if h.status(&from) == Some(HostStatus::Lost) => placement::choose(app, cp, &m.plan, Some(&from))
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
        placement::fits(app, cp, &m.plan, &to).map_err(conflict)?;
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
            v
        })
        .collect();
    let mut rest: Vec<&MachineHost> = rows.values().filter(|r| !configured.iter().any(|c| c.name == r.name)).collect();
    rest.sort_by_key(|r| (r.created_at, r.name.clone()));
    out.extend(rest.into_iter().map(|r| row_view(app, cp, h, r, false)));
    let mut v = json!({ "hosts": out, "policy": h.policy(), "downMinutes": h.down_after_ms() / 60_000 });
    if let Some((tier, plan)) = cp.tiers.first() {
        match placement::choose(app, cp, plan, None) {
            Ok(host) => v["placement"] = json!(host),
            Err(why) => (v["placement"], v["placementRefused"]) = (Value::Null, json!(why)),
        }
        v["placementFor"] = json!({ "tier": tier, "plan": plan });
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
    let reason = req.reason.as_deref().map(str::trim).filter(|r| !r.is_empty()).map(|r| crate::audit::clip(r, 200).to_string());
    if reason.as_deref().is_some_and(|r| r.chars().any(char::is_control)) {
        return Err(bad("reason: one line of text"));
    }
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
                // Each placed with the ones before it counted, so a host isn't filled past its room.
                let target = match &to {
                    Some(t) => placement::fits(&app, cp, &m.plan, t).map(|()| t.clone()),
                    None => placement::choose(&app, cp, &m.plan, Some(&name)),
                };
                let t = match target {
                    Ok(t) => t,
                    Err(why) => {
                        skipped.push(json!({ "machineId": m.id, "userId": m.user_id, "reason": why }));
                        continue;
                    }
                };
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
