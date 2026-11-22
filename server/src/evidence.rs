//! Type II evidence bundles (ADR 0142): one dated tarball per observation period holding
//! what the server already records about its controls: an access review snapshot (users,
//! roles, admins, second factors), the versions deployed and configuration changes,
//! backup and restore runs, retention settings and passes, sign-in and alert events, a
//! summary of the period's audit log with a digest, and a manifest with every file's
//! SHA-256. Made on request by `GET /api/evidence/bundle` (admins), which `botctl evidence
//! bundle` saves, and, with `EVIDENCE_BUNDLES=monthly`, by botd itself for each month
//! into `EVIDENCE_DIR`, with retention. Each bundle is audited with its digests.
//!
//! Never in it: secret values, chats, prompts, tool inputs, files, names, emails, IP
//! addresses or free-text notes and reasons. People and things are named by their opaque
//! ids, which the access-review CSV (ADR 0099) maps to people. Audit details keep numbers,
//! booleans and a few code-like fields only; then every string goes through the support
//! bundle's redaction (ADR 0131) before it is written.

use crate::access_review;
use crate::audit::{self, Actor, Event, Outcome, Who};
use crate::db::{AuditEvent, now};
use crate::mfa;
use crate::runner::App;
use crate::secrets::redact;
use crate::support;
use crate::users::SessionConfig;
use crate::{ApiError, AppState, Auth, Res, bad};
use axum::Json;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{Datelike, NaiveDate};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Bumped when a file's shape changes, so tools reading bundles can tell them apart.
pub const FORMAT: u32 = 1;
pub const CREATED: &str = "evidence.bundle_created";
pub const FAILED: &str = "evidence.bundle_failed";
pub const PRUNED: &str = "evidence.bundles_pruned";
const ACTOR: &str = "evidence";
const PREFIX: &str = "superbot-evidence-";
const PAGE: i64 = 5_000;
/// Events read for one bundle; past this the summary says it is truncated.
const MAX_SCAN: u64 = 5_000_000;
/// Events listed one by one per file; the rest are only counted.
const MAX_LISTED: usize = 5_000;
/// The longest period one bundle covers: a year's observation period and some.
pub const MAX_DAYS: i64 = 400;
/// The observation period plus a year, and a month's grace (ADR 0130's evidence plan).
pub const DEFAULT_KEEP_DAYS: u32 = 760;

/// One file of the bundle: the audit actions it lists, and the Trust Services criteria and
/// readiness checklist rows it is evidence for. The evidence plan's bundle table must match.
pub struct Section {
    pub file: &'static str,
    pub criteria: &'static [&'static str],
    pub rows: &'static [&'static str],
    /// Exact actions, `prefix*` or `*suffix`.
    actions: &'static [&'static str],
}

pub const SECTIONS: [Section; 5] = [
    Section {
        file: "access-review.json",
        criteria: &["CC1.3", "CC6.1", "CC6.2", "CC6.3"],
        rows: &["CC6.1-1", "CC6.2-1", "CC6.3-1", "CC6.3-2"],
        actions: &["user.*", "session.revoked*", "role.*", "team.invited", "team.member_*", "team.role_changed", "scim.*", "signup.approved", "signup.rejected", "access_review.*", "auth.mfa_policy_updated"],
    },
    Section {
        file: "changes.json",
        criteria: &["CC5.1", "CC5.2", "CC8.1"],
        rows: &["CC5.1-1", "CC8.1-2"],
        actions: &[
            "server.started",
            "machine.agent_upgrade*",
            "policy.updated",
            "policy.reset",
            "policy.initialized",
            "policy.sandbox_initialized",
            "server.backup_encryption_changed",
            "server.database_encryption_changed",
            "server.egress_policy_changed",
            "secret.master_key_rotated",
            "license.installed",
            "license.removed",
            "tier.*",
        ],
    },
    Section {
        file: "backups.json",
        criteria: &["A1.2", "A1.3", "CC6.7", "CC7.5", "CC9.1"],
        rows: &["A1.2-1", "A1.2-2", "CC6.7-2"],
        actions: &["server.backup_*", "machine.backup*", "machine.rpo_*", "machine.restore*", "machine.restored"],
    },
    Section {
        file: "retention.json",
        criteria: &["C1.2", "CC6.5"],
        rows: &["C1.2-1", "CC6.5-1", "CC6.5-2"],
        actions: &["*.pruned", "*.retention_changed", "chat.hold_*", "user.erased", "user.erase_refused", "machine.backups_delete*", "machine.teammate_files_purge*", "machine.user_data_clear*"],
    },
    Section {
        file: "sign-ins-and-alerts.json",
        criteria: &["CC6.1", "CC6.6", "CC7.2"],
        rows: &["CC6.1-1", "CC7.2-1"],
        actions: &["auth.*", "mfa.*", "notification.*", "status.incident_*", "server.panic", "machine.host_*", "machine.lost", "machine.hardening_failed", "machine.reboot_required"],
    },
];

/// `audit-summary.json`: every event in the period, counted, with a digest.
pub const SUMMARY_CRITERIA: [&str; 3] = ["CC2.1", "CC4.1", "CC7.2"];

/// Detail fields kept as text when they hold a code (`admin`, `sso`, `burst_ip`), never free text.
const CODE_KEYS: [&str; 26] = [
    "from", "to", "before", "after", "method", "firstFactor", "kind", "pattern", "mode", "encryption", "policy", "policyMode", "mfaPolicy", "state", "source", "harness", "defaultHarness",
    "tier", "provider", "store", "digest", "isolation", "auth", "level", "channel", "target",
];
/// Detail fields kept as text when they hold a version or build.
const VERSION_KEYS: [&str; 5] = ["version", "fromVersion", "toVersion", "fromBuild", "toBuild"];

const README: &str = "SuperBot evidence bundle
========================

Made by botd for a SOC 2 Type II evidence store (docs/security/soc2-evidence-plan.md,
ADR 0142). It covers the period in manifest.json: events from its first day (00:00 UTC)
up to, not including, its last. Snapshots (who has access now, today's settings) are as
of createdAt, which is after the period.

  access-review.json        everyone who can sign in: role, status, admin, second factor,
                            last sign-in, Bot access, sessions, machine; the period's
                            account, role and access-review events
  changes.json              botd versions started in the period, and configuration and
                            agent upgrade events
  backups.json              server and machine backup settings now; every backup, copy,
                            RPO breach and restore in the period, by day
  retention.json            retention settings, last passes and holds now; every pruning
                            pass, hold, erasure and deletion in the period
  sign-ins-and-alerts.json  sign-ins, failures, suspicious sign-ins and alerts, by day
  audit-summary.json        every audit event in the period, counted, and a digest of them
  manifest.json             what is in this bundle, the period, and each file's SHA-256
  SHA256SUMS                the same digests, for `sha256sum -c SHA256SUMS`

Never in it: secret values, chats, prompts, tool inputs, files, names, emails, IP addresses
or free-text notes and reasons. People, Bots and machines are named by their ids; the
access-review CSV (botctl audit and GET /api/access-review/export.csv) says who they are.
The audit log records this bundle's name and manifest digest as evidence.bundle_created.
";

// Periods

/// A run of whole UTC days, `from` included, `to` not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Period {
    pub from: NaiveDate,
    pub to: NaiveDate,
}

impl Period {
    /// The calendar month before `today`.
    pub fn month_before(today: NaiveDate) -> Period {
        let to = today.with_day(1).unwrap_or(today);
        let from = to.pred_opt().and_then(|d| d.with_day(1)).unwrap_or(to);
        Period { from, to }
    }

    /// `from` and `to` as `YYYY-MM-DD`, both or neither (the month before `today`).
    pub fn parse(from: Option<&str>, to: Option<&str>, today: NaiveDate) -> Result<Period, String> {
        let day = |s: &str| NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").map_err(|_| format!("{s} isn't a date: use YYYY-MM-DD (UTC)"));
        let p = match (from, to) {
            (None, None) => return Ok(Period::month_before(today)),
            (Some(f), Some(t)) => Period { from: day(f)?, to: day(t)? },
            _ => return Err("Give both from and to (YYYY-MM-DD, UTC; to is not included), or neither for last month.".into()),
        };
        if p.to <= p.from {
            return Err("to must be after from.".into());
        }
        if p.days() > MAX_DAYS {
            return Err(format!("A bundle covers at most {MAX_DAYS} days; make one per month or quarter."));
        }
        if p.to > today.succ_opt().unwrap_or(today) {
            return Err("to can be tomorrow at the latest: the period can't end in the future.".into());
        }
        Ok(p)
    }

    pub fn days(&self) -> i64 {
        (self.to - self.from).num_days()
    }

    fn ms(d: NaiveDate) -> i64 {
        d.and_hms_opt(0, 0, 0).map(|t| t.and_utc().timestamp_millis()).unwrap_or_default()
    }

    pub fn start_ms(&self) -> i64 {
        Period::ms(self.from)
    }

    pub fn end_ms(&self) -> i64 {
        Period::ms(self.to)
    }

    pub fn label(&self) -> String {
        format!("{}_{}", self.from, self.to)
    }
}

fn date_of(ms: i64) -> NaiveDate {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.date_naive()).unwrap_or_default()
}

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default()
}

/// A bundle's file name, without `.tar`.
pub fn name(p: &Period, now_ms: i64) -> String {
    let stamp = chrono::DateTime::from_timestamp_millis(now_ms).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default();
    format!("{PREFIX}{}-{stamp}", p.label())
}

/// The period a bundle's file name says it covers.
pub fn period_of(file: &str) -> Option<Period> {
    let rest = file.strip_prefix(PREFIX)?.strip_suffix(".tar")?;
    let (from, rest) = (rest.get(..10)?, rest.get(10..)?);
    let to = rest.strip_prefix('_')?.get(..10)?;
    let day = |s: &str| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok();
    Some(Period { from: day(from)?, to: day(to)? })
}

// What leaves the audit log

fn matches(pattern: &str, action: &str) -> bool {
    match (pattern.strip_prefix('*'), pattern.strip_suffix('*')) {
        (Some(suffix), _) => action.ends_with(suffix),
        (_, Some(prefix)) => action.starts_with(prefix),
        _ => pattern == action,
    }
}

/// An id as the bundle shows it: one word of id characters, else `[text]`.
fn ident(s: &str) -> String {
    let id = !s.is_empty() && s.len() <= 128 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:-/+=|@".contains(&c));
    if id { s.to_string() } else { "[text]".into() }
}

fn version_like(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().any(|c| c.is_ascii_digit()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || b".-+_".contains(&c))
}

/// An event's details with only what can't be free text: numbers, booleans, codes in
/// [`CODE_KEYS`], versions in [`VERSION_KEYS`], a reason's code, and nested objects of
/// numbers and booleans (counts, summaries). Notes, names, paths and messages go.
pub fn safe_details(v: &Value) -> Value {
    fn nested(v: &Value) -> Option<Value> {
        match v {
            Value::Number(_) | Value::Bool(_) => Some(v.clone()),
            Value::Object(o) => {
                let kept: Map<String, Value> = o.iter().filter_map(|(k, v)| Some((k.clone(), nested(v)?))).collect();
                (!kept.is_empty()).then_some(Value::Object(kept))
            }
            _ => None,
        }
    }
    let Value::Object(o) = v else { return json!({}) };
    let kept = o.iter().filter_map(|(k, v)| {
        let keep = match v {
            Value::Number(_) | Value::Bool(_) | Value::Null => Some(v.clone()),
            Value::String(s) if k == "reason" => Some(json!(support::reason_code(s))),
            Value::String(s) if CODE_KEYS.contains(&k.as_str()) && support::reason_code(s) == s => Some(v.clone()),
            Value::String(s) if VERSION_KEYS.contains(&k.as_str()) && version_like(s) => Some(v.clone()),
            Value::Array(a) if !a.is_empty() && a.iter().all(|x| x.is_number() || x.is_boolean()) => Some(v.clone()),
            Value::Object(_) => nested(v),
            _ => None,
        };
        Some((k.clone(), keep?))
    });
    Value::Object(kept.collect())
}

/// One audit event as a bundle lists it: what, when, how it ended, and who and what by id.
pub fn entry(e: &AuditEvent) -> Value {
    let id = |s: &Option<String>| s.as_deref().map(ident);
    json!({
        "id": e.id,
        "time": e.time,
        "action": e.action,
        "outcome": e.outcome,
        "actor": {
            "kind": e.actor_kind, "id": id(&e.actor_id), "role": id(&e.actor_role), "method": id(&e.auth_method),
            "idp": id(&e.idp), "idpProvider": id(&e.idp_provider), "onBehalfOf": id(&e.on_behalf_of),
        },
        "target": e.target_type.as_ref().map(|t| json!({ "type": ident(t), "id": id(&e.target_id) })),
        "botId": id(&e.bot_id),
        "details": safe_details(&e.details),
    })
}

/// Every string through the support bundle's redaction (ADR 0131), then botd's own.
fn scrub(v: Value) -> Value {
    fn walk(v: Value) -> Value {
        match v {
            Value::String(s) => Value::String(support::scrub_text(&s)),
            Value::Array(a) => Value::Array(a.into_iter().map(walk).collect()),
            Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (k, walk(v))).collect()),
            other => other,
        }
    }
    redact::value(walk(v))
}

fn json_file(v: Value) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(&scrub(v)).unwrap_or_default();
    s.push('\n');
    redact::text(&s).into_owned().into_bytes()
}

fn sha256(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|b| format!("{b:02x}")).collect()
}

// Reading the period's audit log once

#[derive(Default)]
struct Tally {
    counts: BTreeMap<String, BTreeMap<String, u64>>,
    daily: BTreeMap<String, BTreeMap<String, u64>>,
    events: Vec<Value>,
    total: u64,
}

impl Tally {
    fn add(&mut self, e: &AuditEvent) {
        *self.counts.entry(e.action.clone()).or_default().entry(e.outcome.clone()).or_default() += 1;
        let day = e.time.get(..10).unwrap_or_default().to_string();
        *self.daily.entry(day).or_default().entry(format!("{} {}", e.action, e.outcome)).or_default() += 1;
        if self.events.len() < MAX_LISTED {
            self.events.push(entry(e));
        }
        self.total += 1;
    }

    fn view(&self) -> Value {
        json!({
            "counts": self.counts,
            "daily": self.daily,
            "eventsTotal": self.total,
            "eventsListed": self.events.len(),
            "events": self.events,
        })
    }
}

struct Scan {
    total: u64,
    first_id: Option<i64>,
    last_id: Option<i64>,
    digest: String,
    truncated: bool,
    all: BTreeMap<String, BTreeMap<String, u64>>,
    sections: Vec<Tally>,
}

/// The period's audit events, oldest first, a page at a time: counted, digested, and
/// each matching section's tally fed.
fn scan(app: &App, p: &Period) -> Scan {
    let mut hash = Sha256::new();
    let mut s = Scan { total: 0, first_id: None, last_id: None, digest: String::new(), truncated: false, all: BTreeMap::new(), sections: SECTIONS.iter().map(|_| Tally::default()).collect() };
    let mut after = None;
    loop {
        let f = audit::Filter { from: Some(p.start_ms()), to: Some(p.end_ms()), after, ..Default::default() };
        let page = app.db.audit_events(&f, PAGE, true);
        for e in &page {
            hash.update(format!("{}\t{}\t{}\t{}\n", e.id, e.at, e.action, e.outcome).as_bytes());
            *s.all.entry(e.action.clone()).or_default().entry(e.outcome.clone()).or_default() += 1;
            s.first_id.get_or_insert(e.id);
            s.last_id = Some(e.id);
            s.total += 1;
            for (sec, t) in SECTIONS.iter().zip(s.sections.iter_mut()) {
                if sec.actions.iter().any(|a| matches(a, &e.action)) {
                    t.add(e);
                }
            }
        }
        if (page.len() as i64) < PAGE {
            break;
        }
        if s.total >= MAX_SCAN {
            s.truncated = true;
            break;
        }
        after = page.last().map(|e| e.id);
    }
    s.digest = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    s
}

// The files

/// What a bundle is built from besides the database.
#[derive(Clone, Copy)]
pub struct Inputs {
    pub sessions: SessionConfig,
    pub mfa: mfa::Policy,
}

fn person(p: &Value) -> Value {
    let len = |k: &str| p[k].as_array().map_or(0, Vec::len);
    let custom = |c: &Value| c.is_object().then(|| json!({ "id": c["id"], "permissions": c["permissions"] }));
    json!({
        "id": p["id"],
        "role": p["role"],
        "customRole": custom(&p["customRole"]),
        "status": p["status"],
        "admin": p["role"] == "admin",
        "breakGlass": p["breakGlass"],
        "tier": p["tier"].as_str().map(ident),
        "createdAt": p["createdAt"].as_i64().map(rfc3339),
        "scim": p["scim"].is_object().then(|| json!({ "tenant": p["scim"]["tenant"].as_str().map(ident), "deleted": p["scim"]["deleted"] })),
        "team": p["team"].is_object().then(|| json!({ "id": p["team"]["id"], "role": p["team"]["role"], "customRole": custom(&p["team"]["customRole"]) })),
        "mfa": { "enabled": p["mfa"]["enabled"], "enabledAt": p["mfa"]["enabledAt"].as_i64().map(rfc3339) },
        "lastSignIn": p["lastLogin"].is_object().then(|| json!({
            "at": p["lastLogin"]["at"].as_i64().map(rfc3339),
            "method": p["lastLogin"]["method"].as_str().map(ident),
            "idpProvider": p["lastLogin"]["idpProvider"].as_str().map(ident),
        })),
        "botAccess": { "all": p["botAccess"]["all"], "bots": p["botAccess"]["bots"].as_array().map_or(0, Vec::len) },
        "browserSessions": len("sessions"),
        "apiTokens": len("apiTokens"),
        "machine": p["machine"].is_object().then(|| json!({ "id": p["machine"]["id"], "state": p["machine"]["state"], "assignedAt": p["machine"]["assignedAt"].as_i64().map(rfc3339) })),
    })
}

fn access(app: &App, inputs: &Inputs, t: &Tally) -> Value {
    let r = access_review::build_with(app, &inputs.sessions);
    let reviews = t.counts.get(access_review::COMPLETED).map_or(0, |o| o.values().sum::<u64>());
    json!({
        "snapshotAt": rfc3339(r.generated_at),
        "reportDigest": r.digest,
        "mfaPolicy": inputs.mfa.as_str(),
        "summary": r.summary(),
        "people": r.people().map(person).collect::<Vec<_>>(),
        "reviewsSignedOffInPeriod": reviews,
        "period": t.view(),
    })
}

fn changes(app: &App, p: &Period, t: &Tally) -> Value {
    let start = audit::Filter { actions: vec!["server.started".into()], to: Some(p.start_ms()), ..Default::default() };
    let before = app.db.audit_events(&start, 1, false).pop();
    let version = |e: &Value| e["details"]["version"].as_str().map(String::from);
    let mut current = before.as_ref().and_then(|e| e.details["version"].as_str().map(String::from));
    let (mut starts, mut upgrades) = (Vec::new(), Vec::new());
    for e in t.events.iter().filter(|e| e["action"] == "server.started") {
        let v = version(e);
        starts.push(json!({ "time": e["time"], "version": v }));
        if v != current {
            upgrades.push(json!({ "time": e["time"], "from": current, "to": v }));
            current = v;
        }
    }
    json!({
        "botdNow": env!("CARGO_PKG_VERSION"),
        "versionAtPeriodStart": before.as_ref().and_then(|e| e.details["version"].as_str()),
        "starts": starts,
        "versionChanges": upgrades,
        "period": t.view(),
    })
}

fn backups(app: &App, t: &Tally) -> Value {
    let server = app.server_backups.get().map(|sb| {
        let v = crate::server_backups::view(app, sb);
        json!({
            "offHost": v["offHost"], "mode": v["mode"], "store": v["target"]["source"], "rpoHours": v["rpoHours"], "retentionDays": v["retentionDays"],
            "encryptsPlainArchives": v["target"]["encryptsPlainArchives"],
            "newestArchive": { "createdAt": v["newestArchive"]["createdAt"].as_i64().map(rfc3339), "encrypted": v["newestArchive"]["encrypted"] },
            "lastCopyAt": v["lastBackupAt"].as_i64().map(rfc3339),
            "pastRpo": v["breach"], "pastRpoSince": v["breachedAt"].as_i64().map(rfc3339),
        })
    });
    let enc = crate::backup_encryption::view(app);
    let db = crate::database_encryption::view(app);
    let machines = app.control_plane.get().filter(|cp| cp.enabled()).map(|_| json!({ "rpoBreachesOpen": app.db.machine_rpo_breaches_open().len() }));
    json!({
        "server": server,
        "encryption": enc.is_object().then(|| json!({
            "policy": enc["policy"], "allEncrypted": enc["allEncrypted"],
            "targets": enc["targets"].as_array().map(|ts| ts.iter().map(|x| json!({ "id": x["id"], "encrypted": x["encrypted"] })).collect::<Vec<_>>()),
        })),
        "database": db.is_object().then(|| json!({ "policy": db["policy"], "encrypted": db["encrypted"] })),
        "machines": machines,
        "period": t.view(),
    })
}

fn retention(app: &App, p: &Period, t: &Tally) -> Value {
    let last = |key: &str| app.db.setting(key).and_then(|s| serde_json::from_str::<Value>(&s).ok()).map(|v| safe_details(&v));
    let audit_days = app.db.audit_retention();
    json!({
        "settings": {
            "auditDays": audit_days,
            "chatDays": app.db.chat_retention(),
            "harnessSessionsDays": app.db.retention_days(crate::file_retention::SESSIONS_KEY),
            "teammateFilesDays": app.db.retention_days(crate::file_retention::FILES_KEY),
        },
        "auditKeepsPeriodPlusYear": audit_days.is_none_or(|d| i64::from(d) >= p.days() + 365),
        "lastPasses": {
            "chat": last(crate::retention::LAST_PASS),
            "harnessSessions": last(crate::file_retention::SESSIONS_LAST),
            "teammateFiles": last(crate::file_retention::FILES_LAST),
        },
        "holds": app.db.retention_holds().iter().map(|h| json!({ "botId": ident(&h.bot_id), "heldBy": h.held_by.as_deref().map(ident), "heldAt": rfc3339(h.held_at) })).collect::<Vec<_>>(),
        "period": t.view(),
    })
}

fn summary(app: &App, p: &Period, s: &Scan) -> Value {
    json!({
        "events": s.total,
        "firstId": s.first_id,
        "lastId": s.last_id,
        "truncated": s.truncated,
        "digest": s.digest,
        "digestOf": "SHA-256 of one line per event, oldest first: id, unix ms, action and outcome, tab-separated, each ending in a newline",
        "retentionDays": app.db.audit_retention(),
        "byAction": s.all,
        "period": { "from": p.from.to_string(), "to": p.to.to_string() },
    })
}

pub struct Bundle {
    pub name: String,
    pub tar: Vec<u8>,
    pub sha256: String,
    pub manifest_sha256: String,
    pub files: Vec<String>,
    pub events: u64,
}

/// The whole bundle for `p`, as botd's database stands at `now_ms`.
pub fn build(app: &App, inputs: &Inputs, p: &Period, now_ms: i64, scheduled: bool) -> Bundle {
    let name = name(p, now_ms);
    let s = scan(app, p);
    let tally = |file: &str| SECTIONS.iter().position(|x| x.file == file).map(|i| &s.sections[i]).expect("a section");
    let period = json!({ "from": p.from.to_string(), "to": p.to.to_string(), "days": p.days() });
    let with_period = |mut v: Value| {
        v["periodCovered"] = period.clone();
        v
    };
    let mut files: Vec<(&str, Vec<u8>)> = vec![
        ("README.txt", README.as_bytes().to_vec()),
        ("access-review.json", json_file(with_period(access(app, inputs, tally("access-review.json"))))),
        ("changes.json", json_file(with_period(changes(app, p, tally("changes.json"))))),
        ("backups.json", json_file(with_period(backups(app, tally("backups.json"))))),
        ("retention.json", json_file(with_period(retention(app, p, tally("retention.json"))))),
        ("sign-ins-and-alerts.json", json_file(with_period(tally("sign-ins-and-alerts.json").view()))),
        ("audit-summary.json", json_file(summary(app, p, &s))),
    ];
    let controls = |file: &str| -> (Vec<&str>, Vec<&str>) {
        match SECTIONS.iter().find(|x| x.file == file) {
            Some(x) => (x.criteria.to_vec(), x.rows.to_vec()),
            None if file == "audit-summary.json" => (SUMMARY_CRITERIA.to_vec(), Vec::new()),
            None => (Vec::new(), Vec::new()),
        }
    };
    let listed: Vec<Value> = files
        .iter()
        .map(|(n, b)| {
            let (criteria, rows) = controls(n);
            json!({ "name": n, "bytes": b.len(), "sha256": sha256(b), "criteria": criteria, "checklist": rows })
        })
        .collect();
    let manifest = json!({
        "product": "SuperBot",
        "format": FORMAT,
        "botd": env!("CARGO_PKG_VERSION"),
        "createdAt": rfc3339(now_ms),
        "scheduled": scheduled,
        "period": period,
        "auditEvents": s.total,
        "auditDigest": s.digest,
        "files": listed,
        "notIncluded": "secret values, chats, prompts, tool inputs, files, names, emails, IP addresses, free-text notes and reasons",
    });
    files.push(("manifest.json", json_file(manifest)));
    let sums: String = files.iter().map(|(n, b)| format!("{}  {n}\n", sha256(b))).collect();
    let manifest_sha256 = sha256(&files.last().expect("the manifest").1);
    files.push(("SHA256SUMS", sums.into_bytes()));
    let entries: Vec<(String, Vec<u8>)> = files.iter().map(|(n, b)| (format!("{name}/{n}"), b.clone())).collect();
    let tar = support::tar(&entries, (now_ms / 1000).max(0) as u64);
    Bundle { sha256: sha256(&tar), manifest_sha256, files: files.iter().map(|(n, _)| n.to_string()).collect(), events: s.total, name, tar }
}

fn created(b: &Bundle, p: &Period, scheduled: bool) -> Value {
    json!({
        "name": b.name, "from": p.from.to_string(), "to": p.to.to_string(), "bytes": b.tar.len(), "sha256": b.sha256,
        "manifestSha256": b.manifest_sha256, "auditEvents": b.events, "files": b.files, "scheduled": scheduled,
    })
}

// Writing them on a schedule

/// `EVIDENCE_BUNDLES`, `EVIDENCE_DIR` and `EVIDENCE_RETENTION_DAYS`.
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub monthly: bool,
    pub dir: PathBuf,
    /// Days after a bundle's period ends that it is kept. None: forever.
    pub keep_days: Option<u32>,
}

impl Settings {
    pub fn from_env(get: &dyn Fn(&str) -> String, data_dir: &Path) -> Result<Settings, String> {
        let monthly = match get("EVIDENCE_BUNDLES").trim().to_ascii_lowercase().as_str() {
            "" | "off" => false,
            "monthly" => true,
            other => return Err(format!("EVIDENCE_BUNDLES must be monthly or off, not {other}")),
        };
        let dir = match get("EVIDENCE_DIR").trim() {
            "" => data_dir.join("evidence"),
            d => PathBuf::from(d),
        };
        let keep_days = match get("EVIDENCE_RETENTION_DAYS").trim() {
            "" => Some(DEFAULT_KEEP_DAYS),
            "0" => None,
            d => Some(d.parse::<u32>().ok().filter(|d| (1..=36_500).contains(d)).ok_or_else(|| format!("EVIDENCE_RETENTION_DAYS must be days from 1 to 36500, or 0 to keep bundles forever, not {d}"))?),
        };
        Ok(Settings { monthly, dir, keep_days })
    }
}

/// The bundles in `dir`, by name: their size and the period each covers.
pub fn bundles(dir: &Path) -> Vec<(String, u64, Period)> {
    let mut out: Vec<(String, u64, Period)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let p = period_of(&name)?;
            let meta = e.metadata().ok().filter(|m| m.is_file())?;
            Some((name, meta.len(), p))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Writes `b` into `dir` as `<name>.tar`, private to botd, never over another file and
/// never half-written.
pub fn save(dir: &Path, b: &Bundle) -> std::io::Result<PathBuf> {
    use std::io::Write;
    let mut d = std::fs::DirBuilder::new();
    d.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut d, 0o700);
    d.create(dir)?;
    let path = dir.join(format!("{}.tar", b.name));
    if path.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, format!("{} exists", path.display())));
    }
    let part = dir.join(format!(".{}.tar.partial", b.name));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let written = o.open(&part).and_then(|mut f| f.write_all(&b.tar).and_then(|_| f.sync_all()));
    if let Err(e) = written.and_then(|_| std::fs::rename(&part, &path)) {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    Ok(path)
}

/// One pass of the schedule at `now_ms`: last month's bundle if `dir` has none, then
/// bundles past their retention deleted. `failed` holds the period that last failed, so a
/// failure is audited once, not every hour.
pub fn tick(app: &App, s: &Settings, inputs: &Inputs, now_ms: i64, failed: &mut Option<Period>) {
    let today = date_of(now_ms);
    let p = Period::month_before(today);
    let have = bundles(&s.dir);
    if !have.iter().any(|(_, _, q)| *q == p) {
        let b = build(app, inputs, &p, now_ms, true);
        match save(&s.dir, &b) {
            Ok(path) => {
                crate::obs::log::log_info!("Evidence: wrote {} for {} to {} (ADR 0142).", b.name, p.label(), path.display());
                app.db.record(&Event::new(Actor::system(ACTOR), CREATED).target("evidence_bundle", &b.name).details(created(&b, &p, true)));
                *failed = None;
            }
            Err(e) => {
                crate::obs::log::log_warn!("Evidence: couldn't write the bundle for {} to {}: {e}", p.label(), s.dir.display());
                if *failed != Some(p) {
                    let d = json!({ "from": p.from.to_string(), "to": p.to.to_string(), "reason": "write_failed", "error": e.kind().to_string() });
                    app.db.record(&Event::new(Actor::system(ACTOR), FAILED).outcome(Outcome::Failure).details(d));
                    *failed = Some(p);
                }
            }
        }
    }
    let Some(keep) = s.keep_days else { return };
    let mut deleted = Vec::new();
    for (name, _, q) in bundles(&s.dir) {
        if q.to + chrono::Days::new(u64::from(keep)) < today && std::fs::remove_file(s.dir.join(&name)).is_ok() {
            deleted.push(name);
        }
    }
    if !deleted.is_empty() {
        app.db.record(&Event::new(Actor::system(ACTOR), PRUNED).details(json!({ "deleted": deleted.len(), "names": deleted, "keepDays": keep })));
    }
}

/// With `EVIDENCE_BUNDLES=monthly`, checks hourly that last month's bundle is written.
pub fn start(app: Arc<App>, s: Settings, sessions: SessionConfig, pinned: Option<mfa::Policy>) {
    let s = Arc::new(s);
    let _ = app.evidence.set(s.clone());
    if !s.monthly {
        return;
    }
    crate::obs::log::log_info!("Evidence: a bundle for each month goes to {}, kept {} (ADR 0142).", s.dir.display(), s.keep_days.map_or("forever".into(), |d| format!("{d} days after its month")));
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let mut failed = None;
        loop {
            let (app, s) = (app.clone(), s.clone());
            failed = tokio::task::spawn_blocking(move || {
                let inputs = Inputs { sessions, mfa: pinned.unwrap_or_else(|| app.db.setting(mfa::POLICY_KEY).as_deref().and_then(mfa::Policy::parse).unwrap_or(mfa::Policy::Off)) };
                tick(&app, &s, &inputs, now(), &mut failed);
                failed
            })
            .await
            .unwrap_or(None);
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });
}

// HTTP

/// `GET /api/evidence` (admins): the schedule, the bundles written, and the newest made.
pub async fn get(State(app): State<AppState>) -> Json<Value> {
    let s = app.evidence.get();
    let today = date_of(now());
    let newest = app.db.audit_events(&audit::Filter { actions: vec![CREATED.into()], ..Default::default() }, 1, false).pop();
    Json(json!({
        "schedule": if s.is_some_and(|s| s.monthly) { "monthly" } else { "off" },
        "dir": s.map(|s| s.dir.display().to_string()),
        "keepDays": s.and_then(|s| s.keep_days),
        "nextPeriod": Period::month_before(today.checked_add_months(chrono::Months::new(1)).unwrap_or(today)).label(),
        "bundles": s.map(|s| bundles(&s.dir)).unwrap_or_default().iter().map(|(n, bytes, p)| json!({ "name": n, "bytes": bytes, "from": p.from.to_string(), "to": p.to.to_string() })).collect::<Vec<_>>(),
        "newest": newest.map(|e| json!({ "time": e.time, "actor": e.actor_kind, "name": e.details["name"], "manifestSha256": e.details["manifestSha256"], "scheduled": e.details["scheduled"] })),
    }))
}

/// `GET /api/evidence/bundle[?from=YYYY-MM-DD&to=YYYY-MM-DD]` (admins): a bundle for the
/// period (last month by default) as a tarball to save. Audited with its digests.
pub async fn bundle(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Query(q): Query<HashMap<String, String>>) -> Res<Response> {
    let now_ms = now();
    let p = Period::parse(q.get("from").map(String::as_str), q.get("to").map(String::as_str), date_of(now_ms)).map_err(bad)?;
    let inputs = Inputs { sessions: a.sessions, mfa: mfa::policy(&a, &app.db) };
    let built = {
        let app = app.clone();
        tokio::task::spawn_blocking(move || build(&app, &inputs, &p, now_ms, false)).await
    }
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't make the evidence bundle: {e}")))?;
    app.db.record(&by.event(CREATED).target("evidence_bundle", &built.name).details(created(&built, &p, false)));
    let (name, manifest) = (built.name.clone(), built.manifest_sha256.clone());
    let mut res = built.tar.into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/x-tar"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}.tar\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Ok(v) = HeaderValue::from_str(&manifest) {
        h.insert("x-evidence-manifest-sha256", v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn periods_are_whole_utc_days_and_default_to_last_month() {
        assert_eq!(Period::month_before(d("2026-11-22")), Period { from: d("2026-10-01"), to: d("2026-11-01") });
        assert_eq!(Period::month_before(d("2026-01-01")), Period { from: d("2025-12-01"), to: d("2026-01-01") });
        assert_eq!(Period::month_before(d("2024-03-31")), Period { from: d("2024-02-01"), to: d("2024-03-01") });
        let today = d("2026-11-22");
        assert_eq!(Period::parse(None, None, today), Ok(Period::month_before(today)));
        let q = Period::parse(Some("2026-07-01"), Some("2026-10-01"), today).unwrap();
        assert_eq!((q.days(), q.label()), (92, "2026-07-01_2026-10-01".to_string()));
        assert_eq!(q.start_ms(), 1_782_864_000_000);
        assert_eq!(Period::parse(Some("2026-11-01"), Some("2026-11-23"), today).unwrap().to, d("2026-11-23"), "up to tomorrow");
        for (f, t) in [(Some("2026-11-01"), None), (None, Some("2026-11-01")), (Some("2026-11-01"), Some("2026-11-01")), (Some("2026-11-02"), Some("2026-11-01")), (Some("2025-01-01"), Some("2026-11-01")), (Some("2026-11-01"), Some("2026-11-24")), (Some("1 Nov"), Some("2026-11-02"))] {
            assert!(Period::parse(f, t, today).is_err(), "{f:?} {t:?}");
        }
    }

    #[test]
    fn a_bundles_name_says_its_period() {
        let p = Period { from: d("2026-10-01"), to: d("2026-11-01") };
        let n = name(&p, 1_795_000_000_000);
        assert!(n.starts_with("superbot-evidence-2026-10-01_2026-11-01-") && n.ends_with('Z'), "{n}");
        assert!(n.len() + "/sign-ins-and-alerts.json".len() <= 100, "fits a ustar name");
        assert_eq!(period_of(&format!("{n}.tar")), Some(p));
        for other in [n.clone(), "superbot-support-20261122T120000Z.tar".into(), "superbot-evidence-2026-10-01.tar".into(), ".superbot-evidence-2026-10-01_2026-11-01-x.tar.partial".into()] {
            assert_eq!(period_of(&other), None, "{other}");
        }
    }

    #[test]
    fn actions_match_exactly_or_by_prefix_or_suffix() {
        assert!(matches("user.*", "user.created") && matches("*.pruned", "chat.pruned") && matches("server.started", "server.started"));
        assert!(!matches("user.*", "users.x") && !matches("*.pruned", "chat.pruned_x") && !matches("server.started", "server.started2"));
    }

    #[test]
    fn details_keep_codes_and_counts_never_free_text() {
        let v = json!({
            "reason": "Deletes /home/jane/notes.txt", "notes": "Reviewed with Jane", "from": "member", "to": "admin",
            "email": "jane@example.com", "name": "ada", "ip": "203.0.113.9", "count": 3, "ok": true, "toVersion": "0.2.0+abc",
            "summary": { "people": 4, "admins": 1, "who": "jane" }, "changes": { "name": { "from": "ada", "to": "bea" } },
            "pattern": "burst_ip", "kind": "Free Text Here", "digest": "ab12", "ids": [1, 2], "names": ["a"], "fromVersion": "a b",
        });
        assert_eq!(
            safe_details(&v),
            json!({ "reason": "[text]", "from": "member", "to": "admin", "count": 3, "ok": true, "toVersion": "0.2.0+abc", "summary": { "people": 4, "admins": 1 }, "pattern": "burst_ip", "digest": "ab12", "ids": [1, 2] })
        );
        assert_eq!(safe_details(&json!({ "reason": "not_linked", "to": "jane@example.com" })), json!({ "reason": "not_linked" }));
        assert_eq!(safe_details(&json!("text")), json!({}));
        assert_eq!(ident("u1a2b3c4"), "u1a2b3c4");
        assert_eq!(ident("Jane Smith"), "[text]");
    }

    #[test]
    fn settings_default_to_off_in_the_data_folder_for_25_months() {
        fn from(vars: &[(&str, &str)]) -> Result<Settings, String> {
            Settings::from_env(&|k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()).unwrap_or_default(), Path::new("/data"))
        }
        assert_eq!(from(&[]), Ok(Settings { monthly: false, dir: Path::new("/data").join("evidence"), keep_days: Some(760) }));
        let s = from(&[("EVIDENCE_BUNDLES", "Monthly"), ("EVIDENCE_DIR", "/srv/evidence"), ("EVIDENCE_RETENTION_DAYS", "0")]).unwrap();
        assert_eq!(s, Settings { monthly: true, dir: "/srv/evidence".into(), keep_days: None });
        assert!(from(&[("EVIDENCE_BUNDLES", "daily")]).unwrap_err().contains("monthly or off"));
        for bad in ["-1", "x", "36501"] {
            assert!(from(&[("EVIDENCE_RETENTION_DAYS", bad)]).is_err(), "{bad}");
        }
    }

    /// Every file maps to criteria the control mapping has and checklist rows the readiness
    /// checklist has, each under one of its criteria, and the evidence plan's bundle table
    /// lists each file with them.
    #[test]
    fn every_file_maps_to_real_controls_and_the_evidence_plan_says_so() {
        let mapping = include_str!("../../docs/security/soc2-control-mapping.md");
        let checklist = include_str!("../../docs/security/soc2-readiness-checklist.md");
        let plan = include_str!("../../docs/security/soc2-evidence-plan.md");
        let files: Vec<(&str, Vec<&str>, Vec<&str>)> = SECTIONS.iter().map(|s| (s.file, s.criteria.to_vec(), s.rows.to_vec())).chain([("audit-summary.json", SUMMARY_CRITERIA.to_vec(), Vec::new())]).collect();
        for (file, criteria, rows) in files {
            for c in &criteria {
                assert!(mapping.contains(&format!("| {c} ")), "{file}: {c} isn't a criterion of the control mapping");
            }
            for r in &rows {
                assert!(checklist.contains(&format!("| {r} |")), "{file}: {r} isn't a row of the readiness checklist");
                assert!(criteria.iter().any(|c| r.starts_with(&format!("{c}-"))), "{file}: {r} isn't under one of its criteria");
            }
            let line = plan.lines().find(|l| l.starts_with(&format!("| `{file}` |"))).unwrap_or_else(|| panic!("the evidence plan's bundle table has no row for `{file}`"));
            for id in criteria.iter().chain(&rows) {
                assert!(line.contains(id), "the evidence plan's row for `{file}` doesn't name {id}");
            }
        }
    }
}
