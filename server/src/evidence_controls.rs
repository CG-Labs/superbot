//! `egress.json` and `secrets.json` in botd's evidence bundle (ADR 0285): whether two
//! product controls held through the period, not only whether they exist now. Machines'
//! outbound allow-lists (ADR 0135) for checklist row CC6.8-2, and the external secrets
//! manager (ADR 0125, ADR 0136, ADR 0146) for CC6.1-4. Read from the same pass over the
//! period's events as the rest of the bundle, with a few reads around it.
//!
//! As with `audit-integrity.json` (ADR 0261), each file's manifest entry names its row
//! only while the period shows the control held, so a month it didn't is a gap in the
//! coverage report: CC6.8-2 while a machine is running and every
//! run in the period was held to an allow-list (the server's policy an allow-list all
//! through it, and nobody with a machine let out on their own); CC6.1-4 while every botd
//! start in force in the period read its secrets from an external manager.
//!
//! Never in them: hosts, addresses or paths from an allow-list or a backend's settings,
//! only counts, modes and the policy's id (a digest).

use crate::audit::Filter;
use crate::db::AuditEvent;
use crate::evidence::{Tally, rfc3339};
use crate::evidence_period::Period;
use crate::machines::egress_policy;
use crate::machines::wire::{EGRESS_ALLOW_LIST, EGRESS_OPEN, EgressReport};
use crate::runner::App;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const EGRESS_FILE: &str = "egress.json";
/// What `egress.json` can be evidence for; the manifest names the row only while it held.
pub const EGRESS_CRITERIA: [&str; 2] = ["CC6.6", "CC6.8"];
pub const EGRESS_ROWS: [&str; 1] = ["CC6.8-2"];
pub const EGRESS_ACTIONS: [&str; 5] = [SERVER_CHANGED, USER_CHANGED, "machine.egress_policy_*", "machine.run_limits_unavailable", "machine.run_limited"];

pub const SECRETS_FILE: &str = "secrets.json";
/// What `secrets.json` can be evidence for; the manifest names the row only while it held.
pub const SECRETS_CRITERIA: [&str; 1] = ["CC6.1"];
pub const SECRETS_ROWS: [&str; 1] = ["CC6.1-4"];
pub const SECRETS_ACTIONS: [&str; 1] = ["secret.*"];

const SERVER_CHANGED: &str = "server.egress_policy_changed";
const USER_CHANGED: &str = "user.egress_policy_changed";
const LOAD_FAILED: &str = "machine.egress_policy_failed";
const DROPPED: &str = "secret.read_events_dropped";
const STARTED: &str = "server.started";
/// Changes read from the period's start on; past this the file can't say the control held.
const MAX_CHANGES: i64 = 10_000;
/// Event ids listed per exception; the rest are only counted.
const MAX_IDS: i64 = 1_000;

/// A user's own policy that defers to the server's.
const INHERIT: &str = egress_policy::INHERIT;

/// One change of a policy's mode, from its audit event.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Change {
    pub(crate) at: i64,
    pub(crate) from: String,
    pub(crate) to: String,
}

impl Change {
    fn of(e: &AuditEvent) -> Change {
        let mode = |k: &str| e.details[k]["mode"].as_str().unwrap_or(INHERIT).to_string();
        Change { at: e.at, from: mode("from"), to: mode("to") }
    }
}

/// A policy's mode through `p`, as `(from, to, mode)` spans in order: the first change at
/// or after the period's start says what it was before (`now` when nothing changed since),
/// then each change in the period starts a new span. `changes` are oldest first.
pub(crate) fn timeline(changes: &[Change], now: &str, p: &Period) -> Vec<(i64, i64, String)> {
    let (start, end) = (p.start_ms(), p.end_ms());
    let later: Vec<&Change> = changes.iter().filter(|c| c.at >= start).collect();
    let mut mode = later.first().map_or(now.to_string(), |c| c.from.clone());
    let mut since = start;
    let mut out = Vec::new();
    for c in later.iter().take_while(|c| c.at < end) {
        if c.at > since {
            out.push((since, c.at, mode.clone()));
        }
        since = c.at;
        mode = c.to.clone();
    }
    out.push((since, end, mode));
    out
}

fn span(from: i64, to: i64) -> Value {
    json!({ "from": rfc3339(from), "to": rfc3339(to) })
}

fn ids(app: &App, action: &str, p: &Period) -> (Vec<i64>, bool) {
    let f = Filter { actions: vec![action.into()], from: Some(p.start_ms()), to: Some(p.end_ms()), ..Default::default() };
    let events = app.db.audit_events(&f, MAX_IDS + 1, true);
    let more = events.len() as i64 > MAX_IDS;
    (events.iter().take(MAX_IDS as usize).map(|e| e.id).collect(), more)
}

/// A running machine's allow-list now: what botd sends it and what its agent last said.
struct MachineNow {
    id: String,
    user: String,
    mode: String,
    policy_id: String,
    entries: usize,
    loaded: Option<EgressReport>,
    in_place: bool,
}

/// `egress.json`, and the rows its manifest entry names.
pub fn egress(app: &App, p: &Period, t: &Tally) -> (Value, Vec<&'static str>) {
    let on = app.control_plane.get().is_some_and(|cp| cp.enabled());
    let server = egress_policy::server(app);
    let f = Filter { actions: vec![SERVER_CHANGED.into(), USER_CHANGED.into()], from: Some(p.start_ms()), ..Default::default() };
    let events = app.db.audit_events(&f, MAX_CHANGES + 1, true);
    let truncated = events.len() as i64 > MAX_CHANGES;
    let server_changes: Vec<Change> = events.iter().filter(|e| e.action == SERVER_CHANGED).map(Change::of).collect();
    let mut user_changes: BTreeMap<String, Vec<Change>> = BTreeMap::new();
    for e in events.iter().filter(|e| e.action == USER_CHANGED) {
        if let Some(u) = &e.target_id {
            user_changes.entry(u.clone()).or_default().push(Change::of(e));
        }
    }

    let server_open: Vec<Value> = timeline(&server_changes, &server.mode, p).into_iter().filter(|(_, _, m)| m != EGRESS_ALLOW_LIST).map(|(f, t, _)| span(f, t)).collect();
    let people: Vec<_> = app.db.users().into_iter().filter(|u| u.erased_at.is_none()).collect();
    let own_now = |id: &str| egress_policy::own(app, id).map_or(INHERIT.to_string(), |s| s.mode);
    let mut own_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for u in &people {
        if let Some(s) = egress_policy::own(app, &u.id) {
            *own_counts.entry(if s.mode == EGRESS_OPEN { "open" } else { "allowList" }).or_default() += 1;
        }
    }
    // Everyone whose own policy changed since the period began, or is their own now.
    let mut who: BTreeSet<String> = user_changes.keys().cloned().collect();
    who.extend(people.iter().filter(|u| egress_policy::own(app, &u.id).is_some()).map(|u| u.id.clone()));
    let users_open: Vec<Value> = who
        .iter()
        .filter(|id| app.db.user_machine(id).is_some())
        .filter_map(|id| {
            let spans: Vec<Value> = timeline(user_changes.get(id).map_or(&[][..], Vec::as_slice), &own_now(id), p).into_iter().filter(|(_, _, m)| m == EGRESS_OPEN).map(|(f, t, _)| span(f, t)).collect();
            (!spans.is_empty()).then(|| json!({ "user": id, "open": spans }))
        })
        .collect();

    let running: Vec<MachineNow> = if on {
        app.db
            .machines(Some(crate::machines::State::Running))
            .into_iter()
            .filter(|m| m.enrollment == "enrolled")
            .map(|m| {
                let p = egress_policy::effective(app, &m.user_id);
                let loaded: Option<EgressReport> = m.agent_upkeep.as_ref().and_then(|u| serde_json::from_value(u["egressPolicy"].clone()).ok());
                let in_place = egress_policy::in_place(&p, loaded.as_ref());
                MachineNow { id: m.id, user: m.user_id, mode: p.mode, policy_id: p.id, entries: p.allow.len(), loaded, in_place }
            })
            .collect()
    } else {
        Vec::new()
    };
    let machines_open: Vec<&str> = running.iter().filter(|m| m.mode != EGRESS_ALLOW_LIST).map(|m| m.id.as_str()).collect();
    let not_in_place: Vec<&str> = running.iter().filter(|m| m.mode == EGRESS_ALLOW_LIST && !m.in_place).map(|m| m.id.as_str()).collect();
    let (failed, more_failed) = ids(app, LOAD_FAILED, p);

    let held = on && !running.is_empty() && !truncated && server_open.is_empty() && users_open.is_empty() && machines_open.is_empty();
    let whole = egress_policy::resolve(&server, None);
    let v = json!({
        "machinesOn": on,
        "server": { "mode": server.mode, "entries": server.allow.len(), "policyId": whole.id },
        "usersWithOwnPolicy": { "open": own_counts.get("open").copied().unwrap_or(0), "allowList": own_counts.get("allowList").copied().unwrap_or(0) },
        "machines": running.iter().map(|m| json!({
            "id": m.id,
            "user": m.user,
            "policy": { "id": m.policy_id, "mode": m.mode, "entries": m.entries },
            "loaded": m.loaded.as_ref().map(|r| json!({ "id": r.id, "mode": r.mode, "state": r.state, "addresses": r.addresses, "unresolvedHosts": r.unresolved.len() })),
            "inPlace": m.in_place,
        })).collect::<Vec<_>>(),
        "summary": {
            "running": running.len(),
            "allowList": running.len() - machines_open.len(),
            "open": machines_open.len(),
            "notInPlace": not_in_place.len(),
            "loadFailures": t.counts.get(LOAD_FAILED).map_or(0, |o| o.values().sum::<u64>()),
        },
        "changesTruncated": truncated,
        "everyRunHeldToAnAllowList": held,
        "exceptions": {
            "serverOpen": server_open,
            "usersOpen": users_open,
            "machinesOpen": machines_open,
            "notInPlace": not_in_place,
            "loadFailures": failed,
        },
        "loadFailuresTruncated": more_failed,
        "period": t.totals(),
    });
    (v, if held { EGRESS_ROWS.to_vec() } else { Vec::new() })
}

/// The backend each botd start recorded (`server.started`'s `vaultBackend`), and
/// whether that is an external manager. Starts from before the field are `unknown`.
fn backend_of(e: &AuditEvent) -> String {
    e.details["vaultBackend"].as_str().unwrap_or("unknown").to_string()
}

fn external(backend: &str) -> bool {
    !matches!(backend, "local" | "unknown")
}

/// The starts in force in `p`: the last one before it, then each in it, as `(at, backend)`.
/// With none before it on record (never, or pruned), whatever ran from the period's start
/// is unknown: `(None, "unknown")`.
pub(crate) fn starts_in_force(before: Option<(i64, String)>, during: &[(i64, String)]) -> Vec<(Option<i64>, String)> {
    let first = before.map_or((None, "unknown".to_string()), |(at, b)| (Some(at), b));
    std::iter::once(first).chain(during.iter().map(|(at, b)| (Some(*at), b.clone()))).collect()
}

/// `secrets.json`, and the rows its manifest entry names.
pub fn secrets(app: &App, p: &Period, t: &Tally) -> (Value, Vec<&'static str>) {
    let start = Filter { actions: vec![STARTED.into()], to: Some(p.start_ms()), ..Default::default() };
    let before = app.db.audit_events(&start, 1, false).pop().map(|e| (e.at, backend_of(&e)));
    let during = Filter { actions: vec![STARTED.into()], from: Some(p.start_ms()), to: Some(p.end_ms()), ..Default::default() };
    let mut during: Vec<(i64, String)> = app.db.audit_events(&during, MAX_CHANGES + 1, true).iter().map(|e| (e.at, backend_of(e))).collect();
    let truncated = during.len() as i64 > MAX_CHANGES;
    during.truncate(MAX_CHANGES as usize);
    let starts = starts_in_force(before, &during);
    let start = |at: &Option<i64>, b: &str| json!({ "startedAt": at.map(rfc3339), "backend": b, "external": external(b) });
    let without: Vec<Value> = starts.iter().filter(|(_, b)| !external(b)).map(|(at, b)| start(at, b)).collect();
    let (dropped, more_dropped) = ids(app, DROPPED, p);
    let count = |action: &str, outcome: &str| t.counts.get(action).and_then(|o| o.get(outcome)).copied().unwrap_or(0);
    let held = !truncated && without.is_empty();
    let v = json!({
        "now": crate::secrets::external::configured(),
        "starts": starts.iter().map(|(at, b)| start(at, b)).collect::<Vec<_>>(),
        "startsTruncated": truncated,
        "summary": {
            "reads": count("secret.read", "success"),
            "readFailures": count("secret.read", "failure"),
            "signIns": count("secret.backend_login", "success") + count("secret.vault_login", "success"),
            "signInFailures": count("secret.backend_login", "failure") + count("secret.vault_login", "failure"),
            "leasesIssued": count("secret.lease_issued", "success"),
            "leaseFailures": count("secret.lease_issued", "failure"),
        },
        "everyStartUsedAnExternalManager": held,
        "exceptions": {
            "startsWithoutExternalManager": without,
            "readEventsDropped": dropped,
        },
        "readEventsDroppedTruncated": more_dropped,
        "period": t.totals(),
    });
    (v, if held { SECRETS_ROWS.to_vec() } else { Vec::new() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn period() -> Period {
        Period { from: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(), to: NaiveDate::from_ymd_opt(2027, 2, 1).unwrap() }
    }

    fn change(at: i64, from: &str, to: &str) -> Change {
        Change { at, from: from.into(), to: to.into() }
    }

    #[test]
    fn a_policys_modes_through_the_period_come_from_its_changes() {
        let p = period();
        let (s, e) = (p.start_ms(), p.end_ms());
        let day = 86_400_000;
        // Nothing changed: what it is now, all through.
        assert_eq!(timeline(&[], "allow_list", &p), [(s, e, "allow_list".to_string())]);
        // Changed before the period: those changes don't say what it was in it.
        assert_eq!(timeline(&[change(s - day, "open", "allow_list")], "allow_list", &p), [(s, e, "allow_list".to_string())]);
        // Opened for three days in the period, then listed again.
        let tl = timeline(&[change(s + 2 * day, "allow_list", "open"), change(s + 5 * day, "open", "allow_list")], "allow_list", &p);
        assert_eq!(tl, [(s, s + 2 * day, "allow_list".into()), (s + 2 * day, s + 5 * day, "open".into()), (s + 5 * day, e, "allow_list".into())]);
        // Open at the start, listed only after the period: its first change says so, whatever it is now.
        assert_eq!(timeline(&[change(e + day, "open", "allow_list")], "allow_list", &p), [(s, e, "open".to_string())]);
        // A change at the very start takes over at once.
        assert_eq!(timeline(&[change(s, "open", "allow_list")], "allow_list", &p), [(s, e, "allow_list".to_string())]);
    }

    #[test]
    fn only_starts_with_an_external_manager_count() {
        assert!(external("vault") && external("aws") && external("azure-keyvault") && external("gcp-secret-manager"));
        assert!(!external("local") && !external("unknown"));
        let s = starts_in_force(Some((1, "unknown".into())), &[(2, "vault".into())]);
        assert_eq!(s, [(Some(1), "unknown".to_string()), (Some(2), "vault".to_string())]);
        // No start before the period on record, as when retention pruned it: what ran
        // until the first start in it is unknown.
        assert_eq!(starts_in_force(None, &[(2, "vault".into())]), [(None, "unknown".to_string()), (Some(2), "vault".to_string())]);
        assert_eq!(starts_in_force(None, &[]), [(None, "unknown".to_string())]);
    }
}
