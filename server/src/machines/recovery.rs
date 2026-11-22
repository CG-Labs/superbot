//! Recovery objectives for machines with off-host backups (ADR 0074). Each tier has an
//! RPO (how old the newest off-host copy of a machine may get) and an RTO (how long a
//! restore may take, from the request to the machine enrolling again), set beside its
//! backup schedule (`backup::Settings`). Machines backed up by their provider instead
//! (Linode Backups, ADR 0110) are held to one RPO, `ProviderBackups`, and no RTO.
//!
//! botd checks every running machine against its RPO every reconcile interval. A
//! machine past it opens a breach: audited (`machine.rpo_breached`), alerted to the
//! global notification channels (ADR 0061), and shown to admins until a newer backup
//! closes it (`machine.rpo_recovered`). Every restore records how long it took against
//! its RTO; one that takes longer, or is still underway past it, is audited
//! (`machine.restore_rto_exceeded`) and alerted once.

use super::backup::{self, Offsite};
use super::{ControlPlane, State, event, system};
use crate::audit::Outcome;
use crate::db::{Machine, MachineRestore, now};
use crate::notify::{self, Alert};
use crate::runner::App;
use crate::{AppState, Auth, Res};
use axum::Json;
use axum::extract::{Extension, State as AppS};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

const HOUR_MS: i64 = 3_600_000;
/// The console page alerts link to.
const PAGE: &str = "machines";

/// The newest moment of `m` whose data is off the host: its newest finished backup was
/// taken, or its newest finished restore ended (what's on it then came from a backup),
/// or it was made (nothing on it yet).
pub fn covered_since(app: &App, m: &Machine) -> i64 {
    let backup = app.db.machine_last_backup(&m.id).map(|b| b.created_at);
    let restore = app.db.machine_last_restore_done(&m.id).and_then(|r| r.finished_at);
    [backup, restore].into_iter().flatten().fold(m.created_at, i64::max)
}

/// Why `m` isn't held to its RPO now, if it isn't: only machines that can be changing
/// are. A suspended machine's disk doesn't change; a restore is held to the RTO instead.
fn untracked(app: &App, cp: &ControlPlane, m: &Machine) -> Option<&'static str> {
    if m.state == State::Destroyed {
        return Some("destroyed");
    }
    if !cp.owns(m) {
        return Some("other_provider");
    }
    match m.state {
        State::Running => {}
        State::Error if m.enrolled_at.is_some() => {}
        State::Suspended => return Some("suspended"),
        _ => return Some("not_running"),
    }
    if app.db.machine_restoring(&m.id).is_some() {
        return Some("restoring");
    }
    None
}

/// One machine against its tier's objectives.
pub struct Status {
    pub untracked: Option<&'static str>,
    pub covered_since: i64,
    pub rpo_ms: i64,
    pub breach: bool,
}

pub fn status(app: &App, cp: &ControlPlane, off: &Offsite, m: &Machine) -> Status {
    let untracked = untracked(app, cp, m);
    let covered_since = covered_since(app, m);
    let rpo_ms = off.s.rpo_ms(&m.tier);
    Status { untracked, covered_since, rpo_ms, breach: untracked.is_none() && now() - covered_since > rpo_ms }
}

/// What admins see of `m`'s objectives: in its view and `GET /api/machines/recovery`.
pub fn view(app: &App, cp: &ControlPlane, off: &Offsite, m: &Machine) -> Value {
    let st = status(app, cp, off, m);
    let last = app.db.machine_last_backup(&m.id);
    let restore = app.db.machine_last_restore(&m.id);
    let open = app.db.machine_rpo_breach_open(&m.id);
    json!({
        "machineId": m.id,
        "host": super::hosts::of(cp, m),
        "userId": m.user_id,
        "tier": m.tier,
        "state": m.state,
        "tracked": st.untracked.is_none(),
        "untrackedReason": st.untracked,
        "lastBackupAt": last.as_ref().map(|b| b.created_at),
        "coveredSince": st.covered_since,
        "ageMs": (now() - st.covered_since).max(0),
        "intervalHours": off.s.interval_ms(&m.tier) / HOUR_MS,
        "rpoHours": st.rpo_ms / HOUR_MS,
        "rtoMinutes": off.s.rto_ms(&m.tier) / 60_000,
        "breach": st.breach,
        "breachedAt": open.map(|b| b.breached_at),
        "lastRestore": restore.map(|r| json!({
            "id": r.id, "state": r.state, "createdAt": r.created_at, "durationMs": r.duration_ms,
            "rtoMs": r.rto_ms, "withinRto": within(&r), "fromHost": r.from_host, "toHost": r.to_host,
            "reason": r.reason,
        })),
    })
}

/// Machines held to an RPO by their provider's own backups (ADR 0110): Linode Backups,
/// taken once a day in a window Linode picks, so the RPO allows a day and the window.
/// botd doesn't take or restore these backups, so it times no restores against an RTO.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProviderBackups {
    pub rpo_ms: i64,
}

/// MACHINE_BACKUPS_RPO_HOURS when it isn't set: a day and Linode's two-hour window.
pub const PROVIDER_RPO_HOURS: i64 = 26;

impl ProviderBackups {
    /// MACHINE_BACKUPS_RPO_HOURS, 25 to 168. `on`: MACHINE_BACKUPS is on and the provider
    /// says when its backups succeed; otherwise the setting stops botd starting.
    pub fn from_env(var: &dyn Fn(&str) -> String, on: bool) -> Result<Option<ProviderBackups>, String> {
        let raw = var("MACHINE_BACKUPS_RPO_HOURS");
        let raw = raw.trim();
        if !on {
            return match raw {
                "" => Ok(None),
                _ => Err("MACHINE_BACKUPS_RPO_HOURS needs MACHINE_BACKUPS=on and Linode machines; Incus machines' RPO is MACHINE_BACKUP_RPO_HOURS".into()),
            };
        }
        let hours = match raw {
            "" => PROVIDER_RPO_HOURS,
            _ => raw.parse::<i64>().ok().filter(|h| (25..=168).contains(h)).ok_or(format!(
                "MACHINE_BACKUPS_RPO_HOURS must be 25 to 168 hours (Linode backs up once a day), not \"{}\"",
                crate::audit::clip(raw, 20)
            ))?,
        };
        Ok(Some(ProviderBackups { rpo_ms: hours * HOUR_MS }))
    }
}

/// `linode` as people write it.
fn provider_name(p: &str) -> String {
    let mut c = p.chars();
    c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
}

/// Why `m` isn't held to its provider backups' RPO now, if it isn't. As off-host
/// backups': a suspended machine's disk doesn't change.
fn provider_untracked(cp: &ControlPlane, m: &Machine) -> Option<&'static str> {
    match m.state {
        State::Destroyed => Some("destroyed"),
        _ if !cp.owns(m) => Some("other_provider"),
        State::Running if m.provider_backup_at.is_none() && !cp.provider_saw(&m.id) => Some("not_checked_yet"),
        State::Running => None,
        State::Suspended => Some("suspended"),
        _ => Some("not_running"),
    }
}

/// `m` against its provider backups' RPO: covered since its newest backup the provider
/// reported, or since it was made.
pub fn provider_status(_app: &App, cp: &ControlPlane, pb: ProviderBackups, m: &Machine) -> Status {
    let untracked = provider_untracked(cp, m);
    let covered_since = m.provider_backup_at.unwrap_or(0).max(m.created_at);
    Status { untracked, covered_since, rpo_ms: pb.rpo_ms, breach: untracked.is_none() && now() - covered_since > pb.rpo_ms }
}

/// What admins see of `m`'s provider backups against their RPO, in its view.
pub fn provider_view(app: &App, cp: &ControlPlane, pb: ProviderBackups, m: &Machine) -> Value {
    let st = provider_status(app, cp, pb, m);
    json!({
        "machineId": m.id,
        "backups": "provider",
        "provider": m.provider,
        "backupsOn": m.backups,
        "tracked": st.untracked.is_none(),
        "untrackedReason": st.untracked,
        "lastBackupAt": m.provider_backup_at,
        "coveredSince": st.covered_since,
        "ageMs": (now() - st.covered_since).max(0),
        "rpoHours": st.rpo_ms / HOUR_MS,
        "breach": st.breach,
        "breachedAt": app.db.machine_rpo_breach_open(&m.id).map(|b| b.breached_at),
    })
}

/// Whether a finished restore met its RTO. None: not finished, or from before ADR 0074.
fn within(r: &MachineRestore) -> Option<bool> {
    Some(r.duration_ms? <= r.rto_ms?)
}

fn who(app: &App, m: &Machine) -> String {
    app.db.user(&m.user_id).and_then(|u| u.email).unwrap_or_else(|| m.user_id.clone())
}

fn ago(ms: i64) -> String {
    let h = ms as f64 / HOUR_MS as f64;
    if h < 1.0 { format!("{} minutes", (ms / 60_000).max(0)) } else { format!("{h:.1} hours") }
}

fn time(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default()
}

fn alert(app: &AppState, m: &Machine, action: &str, title: String, lines: Vec<String>) {
    let a = Alert { event: action.into(), title, lines, target_type: "machine".into(), target_id: m.id.clone(), link: None };
    notify::alert(app, a, PAGE);
}

/// What machines are held to: off-host backups' RPO per tier (ADR 0074), or their
/// provider's own backups' (ADR 0110).
#[derive(Clone, Copy)]
enum Held<'a> {
    Offsite(&'a Offsite),
    Provider(ProviderBackups),
}

impl Held<'_> {
    fn of(cp: &ControlPlane) -> Option<Held<'_>> {
        match (cp.offsite.as_deref(), cp.provider_backups) {
            (Some(off), _) => Some(Held::Offsite(off)),
            (None, Some(pb)) => Some(Held::Provider(pb)),
            (None, None) => None,
        }
    }

    fn status(self, app: &App, cp: &ControlPlane, m: &Machine) -> Status {
        match self {
            Held::Offsite(off) => status(app, cp, off, m),
            Held::Provider(pb) => provider_status(app, cp, pb, m),
        }
    }

    /// What its backups are called in alerts: `off-host`, or the provider's name.
    fn kind(self, m: &Machine) -> String {
        match self {
            Held::Offsite(_) => "off-host".into(),
            Held::Provider(_) => provider_name(&m.provider),
        }
    }

    /// A new breach's audit details, alert lines and title.
    fn breached(self, app: &AppState, cp: &ControlPlane, m: &Machine, st: &Status, b: &crate::db::MachineRpoBreach) -> (Value, Vec<String>, String) {
        let rpo = st.rpo_ms / HOUR_MS;
        let title = format!("{}'s machine has no {} backup within its RPO", who(app, m), self.kind(m));
        match self {
            Held::Offsite(off) => {
                let last = app.db.machine_last_backup(&m.id);
                let failed = app.db.machine_backups(&m.id).into_iter().find(|x| x.state == "failed" && x.created_at > st.covered_since);
                let d = json!({
                    "breachId": b.id, "rpoHours": rpo, "intervalHours": off.s.interval_ms(&m.tier) / HOUR_MS,
                    "lastBackupAt": last.as_ref().map(|x| x.created_at), "coveredSince": st.covered_since, "breachedAt": b.breached_at,
                    "lastError": failed.as_ref().and_then(|f| f.error.clone()),
                });
                let mut lines = vec![
                    format!("Tier {}: RPO {rpo} hours, backed up every {} hours.", m.tier, off.s.interval_ms(&m.tier) / HOUR_MS),
                    match &last {
                        Some(x) => format!("Newest off-host backup: {} ({} ago).", time(x.created_at), ago(now() - x.created_at)),
                        None => "No off-host backup of it yet.".into(),
                    },
                ];
                if let Some(e) = failed.and_then(|f| f.error) {
                    lines.push(format!("Its last backup failed: {e}"));
                }
                if let Some(why) = backup::unable_now(app, cp, m) {
                    lines.push(format!("It can't be backed up now: {why}"));
                }
                (d, lines, title)
            }
            Held::Provider(_) => {
                let name = provider_name(&m.provider);
                let d = json!({
                    "breachId": b.id, "rpoHours": rpo, "backups": "provider", "provider": m.provider, "backupsOn": m.backups,
                    "lastBackupAt": m.provider_backup_at, "coveredSince": st.covered_since, "breachedAt": b.breached_at,
                });
                let mut lines = vec![
                    format!("Tier {}: RPO {rpo} hours, by {name}'s own daily backups.", m.tier),
                    match m.provider_backup_at {
                        Some(at) => format!("Newest {name} backup: {} ({} ago).", time(at), ago(now() - at)),
                        None => format!("No {name} backup of it yet."),
                    },
                ];
                if !m.backups {
                    lines.push(format!("Its {name} backups are off. botd turns them on each reconcile once it can; machine.backups_failed in the audit log says why it couldn't."));
                }
                (d, lines, title)
            }
        }
    }
}

/// One check of every machine: breaches open and close, audited and alerted. Returns how
/// many are open after it.
pub fn watch(app: &AppState, cp: &ControlPlane) -> usize {
    let Some(held) = Held::of(cp) else { return 0 };
    let open: HashMap<String, crate::db::MachineRpoBreach> = app.db.machine_rpo_breaches_open().into_iter().map(|b| (b.machine_id.clone(), b)).collect();
    let mut breaching = 0;
    for m in app.db.machines(None) {
        let was = open.get(&m.id);
        if m.state == State::Destroyed && was.is_none() {
            continue;
        }
        let st = held.status(app, cp, &m);
        match (st.breach, was) {
            (true, Some(_)) => breaching += 1,
            (true, None) => {
                let id = format!("rb{}", crate::random_hex(8));
                let Some(b) = app.db.machine_rpo_breach_start(&id, &m, st.rpo_ms, st.covered_since) else { continue };
                breaching += 1;
                let (d, lines, title) = held.breached(app, cp, &m, &st, &b);
                app.db.record(&event(&system(&m), "machine.rpo_breached", &m, d).outcome(Outcome::Failure));
                alert(app, &m, "machine.rpo_breached", title, lines);
            }
            (false, Some(b)) => {
                let reason = match st.untracked {
                    Some(why) => why,
                    None if st.covered_since > b.covered_since => "backed_up",
                    None => "objective_changed",
                };
                if !app.db.machine_rpo_breach_end(&b.id, reason) {
                    continue;
                }
                let d = json!({ "breachId": b.id, "reason": reason, "breachedAt": b.breached_at, "durationMs": now() - b.breached_at, "coveredSince": st.covered_since });
                app.db.record(&event(&system(&m), "machine.rpo_recovered", &m, d));
                if reason == "backed_up" {
                    let lines = vec![format!("It was past its RPO for {}.", ago(now() - b.breached_at)), format!("Newest {} backup: {}.", held.kind(&m), time(st.covered_since))];
                    alert(app, &m, "machine.rpo_recovered", format!("{}'s machine is back within its RPO", who(app, &m)), lines);
                }
            }
            (false, None) => {}
        }
    }
    breaching
}

/// How long a restore took: from the request until the machine enrolled, not until botd
/// next looked.
pub fn took(m: &Machine, r: &MachineRestore) -> i64 {
    (m.enrolled_at.unwrap_or_else(now) - r.created_at).max(0)
}

/// A restore that finished, recorded as done with `took`: checks it against its RTO and
/// returns that for its `machine.restored` event.
pub fn restored(app: &AppState, m: &Machine, r: &MachineRestore, took: i64) -> Value {
    let ok = r.rto_ms.is_none_or(|rto| took <= rto);
    if !ok {
        exceeded(app, m, r, took, false);
    }
    json!({ "durationMs": took, "rtoMs": r.rto_ms, "withinRto": ok })
}

fn exceeded(app: &AppState, m: &Machine, r: &MachineRestore, took: i64, underway: bool) {
    if !app.db.machine_restore_rto_exceeded(&r.id) {
        return;
    }
    let rto = r.rto_ms.unwrap_or(0);
    let d = json!({ "restoreId": r.id, "backupId": r.backup_id, "rtoMs": rto, "elapsedMs": took, "underway": underway });
    app.db.record(&event(&system(m), "machine.restore_rto_exceeded", m, d).outcome(Outcome::Failure));
    let lines = vec![
        format!("RTO {} minutes; {} {} minutes.", rto / 60_000, if underway { "it has taken" } else { "it took" }, took / 60_000),
        format!("Restore {} from backup {}{}.", r.id, r.backup_id, if underway { ", still underway" } else { "" }),
    ];
    alert(app, m, "machine.restore_rto_exceeded", format!("Restoring {}'s machine took longer than its RTO", who(app, m)), lines);
}

/// Whether the restore's machine has enrolled since it was swapped in, so it is done
/// whenever botd next looks, and timed then.
pub fn enrolled(m: &Machine, r: &MachineRestore) -> bool {
    r.state == "enrolling" && m.enrollment == "enrolled" && m.enrolled_at.is_some_and(|t| t >= r.replaced_at.unwrap_or(r.created_at))
}

/// Restores still underway past their RTO: audited and alerted once each.
pub fn overdue(app: &AppState) {
    let at = now();
    for st in ["importing", "replacing", "enrolling"] {
        for r in app.db.machine_restores_in(st) {
            if r.rto_exceeded_at.is_none()
                && r.rto_ms.is_some_and(|rto| at - r.created_at > rto)
                && let Some(m) = app.db.machine(&r.machine_id)
                && !enrolled(&m, &r)
            {
                exceeded(app, &m, &r, at - r.created_at, true);
            }
        }
    }
}

/// A restore that failed: alerted, since the machine is still to be brought back.
pub fn restore_failed(app: &AppState, m: &Machine, r: &MachineRestore, error: &str) {
    let lines = vec![format!("Restore {} from backup {}: {error}", r.id, r.backup_id), "Its old container is left as it was where it could be.".into()];
    alert(app, m, "machine.restore_failed", format!("Restoring {}'s machine failed", who(app, m)), lines);
}

/// `GET /api/machines/recovery` (admins): each tier's objectives, every live machine
/// against them, the newest 100 breaches (open or ended) and the newest 50 restores with
/// how long each took.
pub async fn get(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>) -> Res {
    let (cp, off) = backup::need(&a)?;
    let tiers: Vec<String> = cp.tiers.iter().map(|(t, _)| t.clone()).collect();
    let machines: Vec<Value> = app
        .db
        .machines(None)
        .into_iter()
        .filter(|m| m.state != State::Destroyed)
        .map(|m| {
            let mut v = view(&app, cp, off, &m);
            v["userEmail"] = json!(app.db.user(&m.user_id).and_then(|u| u.email));
            v
        })
        .collect();
    let tracked = machines.iter().filter(|v| v["tracked"] == true).count();
    let breaching = machines.iter().filter(|v| v["breach"] == true).count();
    let restores: Vec<Value> = app
        .db
        .machine_restores_recent(50)
        .into_iter()
        .map(|r| {
            let ok = within(&r);
            let mut v = json!(r);
            v["withinRto"] = json!(ok);
            v
        })
        .collect();
    let mut out = json!({
        "objectives": off.s.objectives(&tiers),
        "tracked": tracked,
        "breaching": breaching,
        "machines": machines,
        "breaches": app.db.machine_rpo_breaches(100),
        "restores": restores,
    });
    if let Some(h) = super::hosts::view(&app, cp) {
        out["hosts"] = h["hosts"].clone();
    }
    Ok(Json(out))
}
