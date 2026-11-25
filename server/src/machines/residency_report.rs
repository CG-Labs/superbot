//! The residency report (ADR 0155): for one pin (ADR 0129), where the data it holds is
//! now, what in the period the pin refused or held to its region, and what it doesn't
//! cover, as JSON or Markdown, sealed with a SHA-256 digest a customer can check. Admins
//! only, by RBAC's default arm; the people a pin holds get theirs from the app through
//! `residency_me` (ADR 0168). Each report is audited as `residency.report_generated`.

use super::ControlPlane;
use super::residency::{self, PINNED};
use crate::audit::{self, Who};
use crate::db::{AuditEvent, PinOn, ResidencyPin};
use crate::runner::App;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Auth, bad, not_found};
use axum::extract::{Extension, Path, Query, State as AppS};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

pub const GENERATED: &str = "residency.report_generated";
pub const FORMAT: &str = "superbot.residency-report/1";
const DAY_MS: i64 = 86_400_000;
const DEFAULT_DAYS: i64 = 90;
const MAX_DAYS: i64 = 400;
/// Events read for one report. Past this the activity is marked `truncated`.
const MAX_EVENTS: usize = 100_000;

const PIN_CHANGES: [&str; 8] = [
    "user.residency_pinned",
    "user.residency_pin_kept",
    residency::KEPT_PIN_ENDED,
    "user.residency_unpinned",
    "user.residency_pin_refused",
    "team.residency_pinned",
    "team.residency_unpinned",
    "team.residency_pin_refused",
];
const KEPT: &str = "user.residency_pin_kept";
const REFUSALS: [&str; 6] = ["machine.residency_refused", "bot.run_refused", "user.region_change_refused", "team.region_change_refused", "team.join_refused", "team.delete_refused"];

const NOT_COVERED: [&str; 3] = [
    "What a Bot's own tools send over the network; outbound allow-lists are the control for that (ADR 0135).",
    "Push, email, webhooks, payments and sign-in providers, as the DPA's subprocessor annex lists them.",
    "People who have left a pinned team: their data is held by a pin of their own, kept from the team's when they left, with its own report, until botd holds none of their machine data unless the operator keeps such pins (ADR 0171, ADR 0205).",
];

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)).unwrap_or_default()
}

/// JSON with every object's keys sorted and no spaces: what the digest is over. The same
/// bytes as `jq -cjS` writes for the report, so a customer can check it without botd.
pub fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys.iter().map(|k| format!("{}:{}", Value::String((*k).clone()), canonical(&m[k.as_str()]))).collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(canonical).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

/// The SHA-256, in hex, of the report without its `digest`.
pub fn digest(report: &Value) -> String {
    let mut body = report.clone();
    if let Some(o) = body.as_object_mut() {
        o.remove("digest");
    }
    crate::users::hash(&canonical(&body))
}

/// `?from=&to=` (unix ms, RFC 3339 or YYYY-MM-DD; a date as `to` is the end of that
/// day): by default the last 90 days, never past `now` and at most 400 days long.
fn period(q: &HashMap<String, String>, now: i64) -> Result<(i64, i64), String> {
    let to = q.get("to").map(|v| audit::parse_time(v, true)).transpose()?.unwrap_or(now).min(now);
    let from = match q.get("from") {
        Some(v) => audit::parse_time(v, false)?,
        None => to.checked_sub(DEFAULT_DAYS * DAY_MS).ok_or("to is out of range")?,
    };
    if from >= to {
        return Err("from must be before to, and before now".into());
    }
    if to.checked_sub(from).is_none_or(|span| span > MAX_DAYS * DAY_MS) {
        return Err(format!("A report covers at most {MAX_DAYS} days"));
    }
    Ok((from, to))
}

fn on_subject(e: &AuditEvent, p: &ResidencyPin) -> bool {
    e.target_type.as_deref() == Some(p.subject_type.as_str()) && e.target_id.as_deref() == Some(p.subject_id.as_str())
}

fn has_region(v: &Value, region: &str) -> bool {
    v.as_array().is_some_and(|r| r.iter().any(|r| r.as_str() == Some(region)))
}

/// Whether any of the people a run carried when it was recorded (`people`, else its
/// owner and asker) is one of `covered`.
fn carried(d: &Value, people: &Value, covered: &HashSet<String>) -> bool {
    let named = |v: &Value| v.as_str().is_some_and(|u| covered.contains(u));
    match people.as_array() {
        Some(list) => list.iter().any(named),
        None => named(&d["owner"]) || named(&d["forUser"]),
    }
}

/// Whether a refusal was this pin's: on the pinned user or team, a run that carried one
/// of its people and was refused over its region (whichever pin the run named: a
/// member's own and their team's can agree), or about one of its people's machines or
/// regions in its region.
fn refused_here(e: &AuditEvent, p: &ResidencyPin, people: &HashSet<String>) -> bool {
    let d = &e.details;
    if d["reason"].as_str() != Some(PINNED) {
        return false;
    }
    if on_subject(e, p) {
        return true;
    }
    let names_pin = |v: &Value| v["subjectId"].as_str() == Some(p.subject_id.as_str()) && v["pinnedOn"].as_str() == Some(p.subject_type.as_str());
    if d["pins"].as_array().is_some_and(|a| a.iter().any(names_pin)) {
        return true;
    }
    if has_region(&d["pinnedRegions"], &p.region) && carried(d, &d["people"], people) {
        return true;
    }
    let person = |s: Option<&str>| s.is_some_and(|s| people.contains(s));
    d["pinnedRegion"].as_str() == Some(p.region.as_str()) && (person(d["userId"].as_str()) || (e.target_type.as_deref() == Some("user") && person(e.target_id.as_deref())))
}

/// Whether a run was held to this pin's region for one of its people, by the people it
/// carried as recorded then. Runs recorded before `residency.people` fall back to the
/// asker and the Bot's owner now.
fn held_here(app: &App, e: &AuditEvent, p: &ResidencyPin, people: &HashSet<String>, owners: &mut HashMap<String, Option<String>>) -> bool {
    let d = &e.details;
    if !has_region(&d["residency"]["regions"], &p.region) {
        return false;
    }
    if d["residency"]["people"].is_array() {
        return carried(d, &d["residency"]["people"], people);
    }
    if d["forUser"].as_str().is_some_and(|u| people.contains(u)) {
        return true;
    }
    let Some(bot) = e.bot_id.as_deref() else { return false };
    let owner = owners.entry(bot.to_string()).or_insert_with(|| app.db.bot(bot).map(|b| b.owner_id));
    owner.as_deref().is_some_and(|o| people.contains(o))
}

/// With `reference` false, the reference is left out (null).
fn change_view(e: &AuditEvent, reference: bool) -> Value {
    json!({
        "at": e.at, "time": e.time, "action": e.action, "outcome": e.outcome,
        "actor": { "kind": e.actor_kind, "id": e.actor_id, "name": e.actor_name },
        "region": e.details["region"], "reference": if reference { e.details["reference"].clone() } else { Value::Null }, "reason": e.details["reason"],
    })
}

/// `self_service`: for someone the pin holds, who never sees the reference a pin kept
/// from their former team carries, even once it has been renewed (ADR 0129, 0171).
fn activity(app: &App, p: &ResidencyPin, people: &HashSet<String>, from: i64, to: i64, self_service: bool) -> Result<Value, String> {
    let hidden = self_service && p.kept_from.is_some();
    let actions: Vec<&str> = PIN_CHANGES.iter().chain(REFUSALS.iter()).copied().collect();
    let events = app.db.residency_audit(from, to, &actions, MAX_EVENTS as i64 + 1).map_err(|e| e.to_string())?;
    let truncated = events.len() > MAX_EVENTS;
    let mut owners = HashMap::new();
    let (mut changes, mut refusals, mut held) = (Vec::new(), BTreeMap::<(String, String), u64>::new(), 0u64);
    for e in events.iter().take(MAX_EVENTS) {
        if PIN_CHANGES.contains(&e.action.as_str()) {
            if on_subject(e, p) {
                let team_reference = e.action == KEPT || e.action == residency::KEPT_PIN_ENDED;
                changes.push(change_view(e, !hidden && !(self_service && team_reference)));
            }
        } else if e.action == "harness.invoked" {
            held += u64::from(held_here(app, e, p, people, &mut owners));
        } else if refused_here(e, p, people) {
            let kind = match (e.details["action"].as_str(), e.details["whileQueued"].as_bool()) {
                (Some(a), _) => a.to_string(),
                (None, Some(true)) => "run, pinned while queued".to_string(),
                (None, _) if e.action == "bot.run_refused" => "run".to_string(),
                _ => String::new(),
            };
            *refusals.entry((e.action.clone(), kind)).or_default() += 1;
        }
    }
    let refusals: Vec<Value> = refusals.into_iter().map(|((action, kind), n)| json!({ "action": action, "kind": (!kind.is_empty()).then_some(kind), "count": n })).collect();
    Ok(json!({ "pinChanges": changes, "refusals": refusals, "heldRuns": held, "truncated": truncated }))
}

pub(super) fn person(app: &App, cp: &ControlPlane, id: &str, region: &str) -> Option<Value> {
    let u = app.db.user(id)?;
    let machine = app.db.user_machine(id).map(|m| {
        let host = residency::host_of(cp, &m);
        let host_in = host.as_ref().is_none_or(|(_, r)| r.as_deref() == Some(region));
        json!({
            "id": m.id, "provider": m.provider, "state": m.state.as_str(), "region": m.region,
            "host": host.as_ref().map(|h| &h.0), "hostRegion": host.as_ref().and_then(|h| h.1.clone()),
            "inRegion": m.region == region && host_in,
        })
    });
    let backups = app.db.user_machine_backups_kept(id);
    let inside = backups.iter().filter(|b| residency::stored_in(cp.offsite.as_deref(), b.store_region.as_deref(), region)).count();
    let tier = app.tier_of(id);
    let gap = app.tiers().residency_gap(tier, region);
    let (on, runs_in) = residency::runs_of(app, cp, id, region);
    Some(json!({
        "id": u.id, "name": u.name, "email": u.email, "machine": machine,
        "backups": { "kept": backups.len(), "inRegion": inside, "outside": backups.len() - inside },
        "modelRoutes": { "plan": tier.label, "inRegion": gap.is_none(), "gap": gap },
        "runs": { "on": on, "inRegion": runs_in },
    }))
}

/// What the pin doesn't cover. botd's own data is listed, with why, unless the operator
/// states it is in the pin's region (ADR 0184); without chats, routines, approvals, Bots'
/// memory, owners' facts, sign-ins and own secrets when they are all in the region's own
/// chat store (ADR 0215, ADR 0228, ADR 0276, ADR 0277, ADR 0283, ADR 0293).
fn not_covered(server_data: &Value, chats: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if server_data["inRegion"] != true {
        let why: Vec<&str> = server_data["outside"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        let what = if chats["store"] == true && chats["inRegion"] == true {
            "botd's own database apart from chats, routines, approvals, Bots' memory, owners' facts, sign-ins and own secrets, which are in the region's chat store (accounts, the audit log; its server backups also hold chats, routines, approvals, Bots' memory, owners' facts, sign-ins and own secrets from before they moved there)"
        } else {
            "botd's own database (accounts, chats, routines, approvals, sign-ins, own secrets, the audit log; its files hold Bots' memory and the facts they keep about their owners)"
        };
        out.push(format!("{what}, its files and server backups, which are where the operator runs botd: {} (ADR 0129, ADR 0184).", why.join("; ")));
    }
    out.extend(NOT_COVERED.iter().map(|s| s.to_string()));
    out
}

/// The report on `p` for `from`..`to`, generated at `now`, with its digest. For
/// `self_service` (someone the pin holds, ADR 0168), a team's reference on a pin kept
/// from it is left out (null): only the team's owners and admins see it (ADR 0129, 0171).
pub fn build(app: &App, cp: &ControlPlane, p: &ResidencyPin, from: i64, to: i64, now: i64, self_service: bool) -> Result<Value, String> {
    let reference = !(self_service && p.kept_from.is_some());
    let (name, ids) = residency::held_by(app, p).ok_or("Whom this pin is on is gone")?;
    let region = p.region.as_str();
    let people: Vec<Value> = ids.iter().filter_map(|id| person(app, cp, id, region)).collect();
    let mut outside = Vec::new();
    for v in &people {
        let who = v["name"].as_str().unwrap_or_default();
        let id = v["id"].as_str().unwrap_or_default();
        outside.extend(residency::outside(app, cp, id, region).into_iter().chain(super::chat_stores::outside(app, region, id)).map(|w| format!("{who}: {w}")));
    }
    let mut warnings = residency::unready(cp, region);
    warnings.extend(residency::route_gaps(app, &ids, region).into_iter().map(|g| format!("{g}, so their Bots' runs are refused (ADR 0139)")));
    if let Some((names, why)) = residency::server_run_gaps(app, cp, &ids, region) {
        warnings.push(format!("{} Bots run on botd's own server, and {why}, so their runs are refused (ADR 0267)", residency::possessive(&names)));
    }
    let server_data = cp.server_data.against(app, region);
    outside.extend(cp.server_data.refuses(region).into_iter().map(|w| format!("botd: {w} (RESIDENCY_SERVER_DATA=require, ADR 0184)")));
    if let Some(n) = server_data["earlierCopies"].as_i64().filter(|n| *n > 0) {
        warnings.push(format!("{n} server backup copies were made to a store botd no longer copies to; botd doesn't delete them or know their region (ADR 0184)"));
    }
    let server_in = server_data["inRegion"] == true;
    let chats = super::chat_stores::against(app, cp, region, &ids, server_in);
    warnings.extend(super::chat_stores::report_warnings(&chats, region, crate::db::now()));
    let hosts = cp.hosts().map(|h| h.configured().into_iter().filter(|c| c.region.as_deref() == Some(region)).map(|c| c.name).collect::<Vec<_>>());
    let pinned_by = p.pinned_by.as_deref().map(|id| json!({ "id": id, "name": app.db.user(id).map(|u| u.name) }));
    let kept_from = p.kept_from.as_deref().map(|t| json!({ "id": t, "name": app.db.team(t).map(|t| t.name) }));
    let set: HashSet<String> = ids.into_iter().collect();
    let mut report = json!({
        "format": FORMAT,
        "generatedAt": now, "generatedTime": rfc3339(now),
        "period": { "from": from, "to": to, "fromTime": rfc3339(from), "toTime": rfc3339(to) },
        "subject": { "type": p.subject_type.as_str(), "id": p.subject_id, "name": name },
        "pin": {
            "region": p.region, "reference": reference.then_some(&p.reference), "pinnedAt": p.pinned_at, "pinnedTime": rfc3339(p.pinned_at),
            "pinnedBy": pinned_by, "keptFrom": kept_from,
        },
        "status": if outside.is_empty() { "kept" } else { "data_outside" },
        "outside": outside,
        "warnings": warnings,
        "region": { "id": region, "offered": cp.regions.iter().any(|r| r == region), "hosts": hosts, "backupStore": cp.offsite.as_deref().map(|o| o.in_region(region)) },
        "people": people,
        "serverData": server_data,
        "chats": chats,
        "activity": activity(app, p, &set, from, to, self_service)?,
        "notCovered": not_covered(&server_data, &chats),
    });
    report["digest"] = json!(digest(&report));
    Ok(report)
}

fn cell(v: &Value) -> String {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        other => other.to_string(),
    };
    s.replace('|', "\\|").replace(['\r', '\n'], " ")
}

/// The report as Markdown, for a customer to read; the JSON is what the digest seals.
pub fn markdown(r: &Value) -> String {
    let c = |v: &Value| cell(v);
    let mut out = String::from("# Data residency report\n\n");
    let pin = &r["pin"];
    out += &format!("- **Subject:** {} ({} `{}`)\n", c(&r["subject"]["name"]), c(&r["subject"]["type"]), c(&r["subject"]["id"]));
    out += &format!("- **Pinned to:** {}", c(&pin["region"]));
    if pin["reference"].is_string() {
        out += &format!(" under {}", c(&pin["reference"]));
    }
    out += &format!(", since {}", c(&pin["pinnedTime"]));
    if let Some(by) = pin["pinnedBy"]["name"].as_str().or(pin["pinnedBy"]["id"].as_str()) {
        out += &format!(", by {}", cell(&json!(by)));
    }
    if let Some(t) = pin["keptFrom"]["name"].as_str().or(pin["keptFrom"]["id"].as_str()) {
        out += &format!(", kept from team {}'s pin when they left it", cell(&json!(t)));
    }
    out += &format!("\n- **Period:** {} to {}\n- **Generated:** {}\n", c(&r["period"]["fromTime"]), c(&r["period"]["toTime"]), c(&r["generatedTime"]));
    let kept = r["status"] == "kept";
    out += &format!("- **Status:** {}\n\n", if kept { "all of their data is in the region" } else { "some of their data is outside the region" });
    let list = |out: &mut String, title: &str, v: &Value, none: &str| {
        *out += &format!("## {title}\n\n");
        match v.as_array().filter(|a| !a.is_empty()) {
            Some(a) => a.iter().for_each(|w| *out += &format!("- {}\n", cell(w))),
            None => *out += &format!("{none}\n"),
        }
        out.push('\n');
    };
    list(&mut out, "Data outside the region", &r["outside"], "None.");
    list(&mut out, "Warnings", &r["warnings"], "None.");
    out += "## Where their data is\n\n| Person | Machine | Machine region | Host (region) | Backups in region | Backups outside | Model routes | Bots run on |\n|---|---|---|---|---|---|---|---|\n";
    for p in r["people"].as_array().into_iter().flatten() {
        let m = &p["machine"];
        let host = if m["host"].is_string() { format!("{} ({})", c(&m["host"]), c(&m["hostRegion"])) } else { "-".into() };
        let routes = if p["modelRoutes"]["inRegion"] == true { format!("{}: in region", c(&p["modelRoutes"]["plan"])) } else { c(&p["modelRoutes"]["gap"]) };
        out += &format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            c(&p["name"]),
            if m.is_object() { format!("{} ({})", c(&m["id"]), c(&m["state"])) } else { "none".into() },
            c(&m["region"]),
            host,
            c(&p["backups"]["inRegion"]),
            c(&p["backups"]["outside"]),
            routes,
            runs_cell(&p["runs"])
        );
    }
    out += &server_data_markdown(&r["serverData"]);
    out += &chats_markdown(&r["chats"], &r["region"]["id"]);
    let a = &r["activity"];
    out += "\n## In the period\n\n### Pin changes\n\n";
    match a["pinChanges"].as_array().filter(|x| !x.is_empty()) {
        Some(x) => x.iter().for_each(|e| {
            let why = e["reason"].as_str().map(|w| format!(", reason: {}", cell(&json!(w)))).unwrap_or_default();
            out += &format!("- {} `{}` ({}) by {}{why}\n", c(&e["time"]), c(&e["action"]), c(&e["outcome"]), c(&e["actor"]["name"]));
        }),
        None => out += "None.\n",
    }
    out += "\n### Refused because of the pin\n\n";
    match a["refusals"].as_array().filter(|x| !x.is_empty()) {
        Some(x) => {
            out += "| Event | Kind | Count |\n|---|---|---|\n";
            x.iter().for_each(|e| out += &format!("| `{}` | {} | {} |\n", c(&e["action"]), c(&e["kind"]), c(&e["count"])));
        }
        None => out += "None.\n",
    }
    out += &format!("\n### Bot runs held to in-region model routes\n\n{}\n", c(&a["heldRuns"]));
    if a["truncated"] == true {
        out += &format!("\nThe period has more audit events than one report reads ({MAX_EVENTS}); ask for a shorter one.\n");
    }
    list(&mut out, "\nNot covered by the pin", &r["notCovered"], "");
    out += &format!(
        "---\n\nDigest: `{}`\n\nThe SHA-256 of the JSON report ({}) below without its `digest`, keys sorted, no spaces. To check it, save the JSON as `report.json` and run `jq -cjS 'del(.digest)' report.json | sha256sum`.\n\n## The JSON report\n\n",
        c(&r["digest"]),
        FORMAT
    );
    let json = serde_json::to_string_pretty(r).unwrap_or_default();
    let fence = "`".repeat(longest_backtick_run(&json).max(2) + 1);
    out += &format!("{fence}json\n{json}\n{fence}\n");
    out
}

/// Where a person's own Bots run, against the region (ADR 0267). "-" for reports without it.
fn runs_cell(r: &Value) -> String {
    let at = match r["on"].as_str() {
        Some("server") => "botd's server",
        Some("machine") => "their machine",
        Some("nowhere") => return "nowhere yet (refused)".into(),
        _ => return "-".into(),
    };
    match r["inRegion"].as_bool() {
        Some(true) => format!("{at}, in region"),
        _ => format!("{at}, outside (refused)"),
    }
}

/// The report's "botd's own data" section (ADR 0184). Empty for reports without one.
fn server_data_markdown(s: &Value) -> String {
    if !s.is_object() {
        return String::new();
    }
    let region = s["region"].as_str().map_or("not stated by the operator".to_string(), |r| format!("{} (as the operator states it)", cell(&json!(r))));
    let b = &s["backups"];
    let copies = match (b["offHost"].as_bool(), b["region"].as_str()) {
        (Some(true), Some(r)) => format!("copied off the host to a store in {}", cell(&json!(r))),
        (Some(true), None) => "copied off the host to a store in no stated region".to_string(),
        _ => "kept on botd's host".to_string(),
    };
    let mut out = format!(
        "\n## botd's own data\n\nAccounts, chats, routines, approvals and the audit log, in botd's database and files.\n\n- **Region:** {region}\n- **Server backups:** {copies}\n- **In the pinned region:** {}\n- **Held to it:** {}\n",
        if s["inRegion"] == true { "yes" } else { "no" },
        if s["policy"] == "require" { "yes, every pin on this server is (RESIDENCY_SERVER_DATA=require)" } else { "no, it is shown, not enforced (RESIDENCY_SERVER_DATA=report)" }
    );
    for w in s["outside"].as_array().into_iter().flatten() {
        out += &format!("- Outside: {}\n", cell(w));
    }
    out
}

/// The report's "Chats" section (ADR 0215), with routines and approvals (ADR 0228) when the
/// report has them. Empty for reports without one.
fn chats_markdown(c: &Value, region: &Value) -> String {
    if !c.is_object() {
        return String::new();
    }
    let store = if c["store"] == true {
        format!("yes, {} has a chat store of its own", cell(region))
    } else {
        format!("no, {} has none, so chats, routines, approvals, Bots' memory, owners' facts, sign-ins and own secrets are in botd's own database and files", cell(region))
    };
    let backup = c["lastBackupAt"].as_i64().map_or("-".to_string(), rfc3339);
    let mut out = format!("\n## Chats, routines, approvals and memory\n\nTheir Bots' chat messages, routines, approvals and memory, the facts their Bots keep about them, their sign-ins and their own secrets, by where they are kept.\n\n- **Regional chat store:** {store}\n");
    for (key, what) in [("messages", "Messages"), ("routines", "Routines"), ("approvals", "Approvals"), ("memories", "Bots' memory"), ("facts", "Owners' facts"), ("sessions", "Sign-in sessions"), ("samlSessions", "SAML sign-ins"), ("pushDevices", "Push devices"), ("personalKeys", "Personal secrets")] {
        let m = &c[key];
        if m.is_object() {
            out += &format!(
                "- **{what} in it:** {}\n- **{what} in botd's own database:** {}\n- **{what} in another region's store:** {}\n",
                cell(&m["inStore"]),
                cell(&m["inServerDatabase"]),
                cell(&m["elsewhere"])
            );
        }
    }
    out += &format!("- **In the pinned region:** {}\n- **Newest backup of the store:** {backup}\n", if c["inRegion"] == true { "yes" } else { "no" });
    match c.get("offHost") {
        Some(Value::Null) if c["store"] == true => out += "- **Store's backups copied off the host:** no, they are on the store's own volume\n",
        Some(o) if o.is_object() => {
            let newest = o["newestCopyAt"].as_i64().map_or("-".to_string(), rfc3339);
            let state = if o["failing"] == true { ", though botd's last copy failed" } else { "" };
            out += &format!("- **Store's backups copied off the host:** {} to a bucket in {}, newest {newest}{state}\n", cell(&o["copies"]), cell(region));
        }
        _ => {}
    }
    out
}

/// The longest run of backticks in `s`, so a fence around it is longer.
fn longest_backtick_run(s: &str) -> usize {
    s.split(|c| c != '`').map(str::len).max().unwrap_or(0)
}

/// `GET /api/users/{key}/residency/report[?from=&to=&format=markdown]`: the report on
/// the user's own pin.
pub async fn user(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(key): Path<String>, Query(q): Query<HashMap<String, String>>) -> Result<Response, ApiError> {
    let cp = &*a.machines;
    cp.need()?;
    let u = need_user_key(&app, &key)?;
    let p = app.db.residency_pin(PinOn::User, &u.id).ok_or_else(|| match app.db.team_id_of(&u.id).filter(|t| app.db.residency_pin(PinOn::Team, t).is_some()) {
        Some(t) => ApiError(StatusCode::NOT_FOUND, format!("{} has no residency pin of their own. Their team's pin has its own report: botctl team residency {t} report", u.name)),
        None => not_found("Residency pin on this user"),
    })?;
    respond(&app, cp, &by, &p, &q, false)
}

/// `GET /api/teams/{id}/residency/report[?from=&to=&format=markdown]`.
pub async fn team(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Result<Response, ApiError> {
    let cp = &*a.machines;
    cp.need()?;
    let t = app.db.team(id.trim()).ok_or_else(|| not_found("Team"))?;
    let p = app.db.residency_pin(PinOn::Team, &t.id).ok_or_else(|| not_found("Residency pin on this team"))?;
    respond(&app, cp, &by, &p, &q, false)
}

/// `?format=` (Markdown or not) and the period, as of `now`.
pub(super) fn query(q: &HashMap<String, String>, now: i64) -> Result<(bool, i64, i64), ApiError> {
    let md = match q.get("format").map(String::as_str) {
        None | Some("json") => false,
        Some("markdown" | "md") => true,
        Some(_) => return Err(bad("format must be json or markdown")),
    };
    let (from, to) = period(q, now).map_err(bad)?;
    Ok((md, from, to))
}

/// The report on `p` in the format `q` asks for, audited. `self_service`: asked for by
/// someone the pin holds, from the app (ADR 0168), not by an admin.
pub(super) fn respond(app: &App, cp: &ControlPlane, by: &Who, p: &ResidencyPin, q: &HashMap<String, String>, self_service: bool) -> Result<Response, ApiError> {
    let now = crate::db::now();
    let (md, from, to) = query(q, now)?;
    let r = build(app, cp, p, from, to, now, self_service).map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("The residency report couldn't be made: {e}")))?;
    let d = json!({
        "region": p.region, "reference": p.reference, "from": from, "to": to, "status": r["status"], "digest": r["digest"],
        "format": if md { "markdown" } else { "json" }, "truncated": r["activity"]["truncated"], "selfService": self_service,
    });
    app.db.record(&by.event(GENERATED).target(p.subject_type.as_str(), &p.subject_id).details(d));
    if !md {
        return Ok(Json(r).into_response());
    }
    let stamp = chrono::DateTime::from_timestamp_millis(now).unwrap_or_default().format("%Y%m%d");
    let headers = [
        (header::CONTENT_TYPE, "text/markdown; charset=utf-8".to_string()),
        (header::CONTENT_DISPOSITION, format!("attachment; filename=\"superbot-residency-{}-{}-{stamp}.md\"", p.subject_type.as_str(), file_safe(&p.subject_id))),
        (header::CACHE_CONTROL, "no-store".into()),
    ];
    Ok((headers, markdown(&r)).into_response())
}

fn file_safe(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_is_over_sorted_compact_json_without_itself() {
        let v = json!({ "b": [1, { "z": null, "a": "x|y\n" }], "a": true, "digest": "old" });
        let mut body = v.clone();
        body.as_object_mut().unwrap().remove("digest");
        assert_eq!(canonical(&body), r#"{"a":true,"b":[1,{"a":"x|y\n","z":null}]}"#);
        assert_eq!(digest(&v), crate::users::hash(r#"{"a":true,"b":[1,{"a":"x|y\n","z":null}]}"#));
        let mut changed = v.clone();
        changed["digest"] = json!("other");
        assert_eq!(digest(&v), digest(&changed), "the digest field itself isn't covered");
        changed["a"] = json!(false);
        assert_ne!(digest(&v), digest(&changed));
    }

    #[test]
    fn a_period_defaults_to_90_days_and_stays_before_now() {
        let q = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>();
        let now = 1_795_093_200_000;
        assert_eq!(period(&q(&[]), now), Ok((now - 90 * DAY_MS, now)));
        assert_eq!(period(&q(&[("from", "2026-11-01"), ("to", "2026-11-01")]), now), Ok((1_793_491_200_000, 1_793_577_600_000)), "a date as to is the end of that day");
        assert_eq!(period(&q(&[("to", "2030-01-01")]), now).unwrap().1, now, "never past now");
        assert!(period(&q(&[("from", "2026-11-02"), ("to", "2026-11-01")]), now).is_err());
        assert!(period(&q(&[("from", "2024-01-01")]), now).unwrap_err().contains("400 days"));
        assert!(period(&q(&[("from", "yesterday")]), now).is_err());
        let (min, max) = (i64::MIN.to_string(), i64::MAX.to_string());
        assert!(period(&q(&[("from", &min)]), now).unwrap_err().contains("400 days"), "no overflow past the cap");
        assert!(period(&q(&[("to", &min)]), now).is_err(), "no overflow working out the default start");
        assert!(period(&q(&[("from", &min), ("to", &max)]), now).is_err());
    }

    #[test]
    fn botds_own_data_is_not_covered_unless_it_is_in_the_region() {
        let inside = json!({ "inRegion": true, "outside": [] });
        let none = Value::Null;
        assert_eq!(not_covered(&inside, &none).len(), NOT_COVERED.len());
        let out = json!({ "inRegion": false, "outside": ["botd's own data region isn't stated (SERVER_DATA_REGION)"] });
        let lines = not_covered(&out, &none);
        assert!(lines[0].starts_with("botd's own database (accounts, chats,") && lines[0].contains(": botd's own data region isn't stated (SERVER_DATA_REGION) (ADR 0129, ADR 0184)."), "{lines:?}");
        assert_eq!(not_covered(&Value::Null, &none).len(), NOT_COVERED.len() + 1, "no server data section: not covered");
        // Chats all in the region's own store are left out of what isn't covered (ADR 0215).
        let held = not_covered(&out, &json!({ "store": true, "inRegion": true }));
        assert!(held[0].starts_with("botd's own database apart from chats, routines, approvals, Bots' memory, owners' facts, sign-ins and own secrets, which are in the region's chat store (accounts, the audit log"), "{held:?}");
        assert!(!held[0].contains("its files hold"), "owners' facts are in the store too (ADR 0277): {held:?}");
        let moving = not_covered(&out, &json!({ "store": true, "inRegion": false }));
        assert!(moving[0].starts_with("botd's own database (accounts, chats, routines, approvals,"), "{moving:?}");
        assert_eq!(chats_markdown(&Value::Null, &json!("gb-lon")), "", "reports from before ADR 0215 have no section");
        let md = chats_markdown(&json!({ "store": true, "inRegion": true, "lastBackupAt": null, "messages": { "inStore": 4, "inServerDatabase": 0, "elsewhere": 0 } }), &json!("gb-lon"));
        assert!(md.contains("## Chats") && md.contains("- **Regional chat store:** yes, gb-lon has a chat store of its own\n- **Messages in it:** 4") && md.contains("- **Newest backup of the store:** -"), "{md}");
        assert!(!md.contains("Routines in it"), "reports from before ADR 0228 have no routine or approval lines: {md}");
        let md = chats_markdown(
            &json!({ "store": true, "inRegion": false, "lastBackupAt": null,
                "messages": { "inStore": 4, "inServerDatabase": 0, "elsewhere": 0 },
                "routines": { "inStore": 1, "inServerDatabase": 0, "elsewhere": 0 },
                "approvals": { "inStore": 2, "inServerDatabase": 1, "elsewhere": 0 } }),
            &json!("gb-lon"),
        );
        assert!(md.contains("- **Routines in it:** 1\n") && md.contains("- **Approvals in it:** 2\n- **Approvals in botd's own database:** 1\n") && md.contains("- **In the pinned region:** no"), "{md}");
        assert!(!md.contains("copied off the host"), "reports from before ADR 0246 have no off-host line: {md}");
        let off = |o: Value| chats_markdown(&json!({ "store": true, "inRegion": true, "lastBackupAt": null, "offHost": o }), &json!("gb-lon"));
        assert!(off(Value::Null).contains("- **Store's backups copied off the host:** no, they are on the store's own volume\n"));
        let md = off(json!({ "copies": 7, "newestCopyAt": 1_795_417_200_000_i64, "lastCopiedAt": 1_795_417_300_000_i64, "failing": true }));
        assert!(md.contains("- **Store's backups copied off the host:** 7 to a bucket in gb-lon, newest 2026-11-23T07:00:00.000Z, though botd's last copy failed\n"), "{md}");
        assert_eq!(server_data_markdown(&Value::Null), "", "reports from before ADR 0184 have no section");
        let md = server_data_markdown(&json!({ "region": null, "backups": { "offHost": true, "region": null }, "inRegion": false, "policy": "report", "outside": ["a|b"] }));
        assert!(md.contains("- **Region:** not stated by the operator\n- **Server backups:** copied off the host to a store in no stated region\n- **In the pinned region:** no"), "{md}");
        assert!(md.contains("- Outside: a\\|b\n"), "{md}");
    }

    #[test]
    fn markdown_cells_cant_break_the_table() {
        assert_eq!(cell(&json!("a|b\nc")), "a\\|b c");
        assert_eq!(cell(&Value::Null), "-");
        assert_eq!(cell(&json!(3)), "3");
    }

    #[test]
    fn the_markdown_carries_the_json_it_seals_in_a_fence_nothing_inside_can_close() {
        let mut r = json!({ "subject": { "name": "a ```` b" }, "notCovered": [] });
        r["digest"] = json!(digest(&r));
        let md = markdown(&r);
        let start = md.find("`````json\n").expect(&md) + "`````json\n".len();
        let end = start + md[start..].find("\n`````\n").expect(&md);
        let back: Value = serde_json::from_str(&md[start..end]).unwrap();
        assert_eq!(back, r);
        assert_eq!(digest(&back), r["digest"].as_str().unwrap());
    }
}
