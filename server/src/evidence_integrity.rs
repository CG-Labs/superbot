//! `audit-integrity.json` in botd's evidence bundle (ADR 0261): whether the audit log's
//! tamper-evidence (the hash chain checked daily, ADR 0122; signed checkpoints, ADR 0149)
//! and its export off the server (ADR 0122, ADR 0173) kept working through the period,
//! not only whether they are turned on now. Read from the same pass over the period's
//! events as the rest of the bundle, with a few reads from just before it.
//!
//! A stretch only counts against a control while botd was writing events: a server that
//! was down wrote none and checked nothing, which uptime evidence covers, not this file.
//! Its manifest entry names CC2.1-2 only while every export took every event of the
//! period, and CC7.2-2 only while, as well, the chain was checked within a day all
//! through it, the last check passed and checkpoints kept up, so a month the log wasn't
//! guarded is a gap in the coverage report.

use crate::audit::Filter;
use crate::audit_checkpoint::{self, CHECKPOINT, FAILING, OWN, TIMESTAMPED};
use crate::db::AuditEvent;
use crate::evidence::{Tally, matches, rfc3339};
use crate::evidence_period::Period;
use crate::runner::App;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const FILE: &str = "audit-integrity.json";
/// What the file can be evidence for; the manifest names each only while it held.
pub const CRITERIA: [&str; 2] = ["CC2.1", "CC7.2"];
pub const ROWS: [&str; 2] = ["CC2.1-2", "CC7.2-2"];
/// The audit log's own events, listed in the file.
pub const ACTIONS: [&str; 5] = ["audit.verified", "audit.checkpoint*", "audit.timestamp_*", "audit.export_*", "audit.erased"];

pub const VERIFIED: &str = "audit.verified";
const EXPORT_FAILING: &str = "audit.export_failing";
const STARTED: &str = "server.started";
const HOUR_MS: i64 = 3_600_000;
/// The daily check starts a day after the last one ended and a minute after botd
/// starts; an hour more allows for a long check.
pub const CHECK_WITHIN_MS: i64 = 25 * HOUR_MS;
/// A checkpoint is due `AUDIT_CHECKPOINT_MINUTES` after the last once there are new
/// events, on a one-minute tick; a quarter of an hour more allows for a busy server.
pub const CHECKPOINT_GRACE_MS: i64 = 15 * 60_000;

/// A stretch past a deadline: from the last check or the oldest unsealed event, through
/// the first event written after the deadline, to what ended it, if anything did.
struct Gap {
    from: i64,
    late: i64,
    to: Option<i64>,
}

impl Gap {
    fn view(&self, ended: &str) -> Value {
        json!({ "from": rfc3339(self.from), "firstEventPastDeadline": rfc3339(self.late), ended: self.to.map(rfc3339) })
    }
}

/// A check of the whole chain.
#[derive(Clone)]
struct Check {
    id: i64,
    at: i64,
    ok: bool,
    reason: Option<String>,
}

impl Check {
    fn view(&self) -> Value {
        json!({ "id": self.id, "time": rfc3339(self.at), "ok": self.ok, "reason": self.reason })
    }
}

/// Fed every event of the period in order, after [`begin`] read where things stood.
pub struct Integrity {
    every_ms: i64,
    listed: Tally,
    checks: Vec<Value>,
    last_check: Option<Check>,
    /// When the next full check was due from: the last one, or botd's last start.
    check_from: i64,
    check_gaps: Vec<Gap>,
    unsealed_since: Option<i64>,
    seal_gaps: Vec<Gap>,
    daily: BTreeMap<String, BTreeMap<&'static str, u64>>,
    export_failures: Vec<Value>,
    timestamp_failures: Vec<Value>,
}

fn whole(e: &AuditEvent) -> bool {
    e.details.get("range").is_none_or(|r| r.is_null() || (r["from"].is_null() && r["to"].is_null()))
}

fn code(v: &Value) -> Option<String> {
    v.as_str().map(|s| crate::support::reason_code(s).to_string())
}

fn check_of(e: &AuditEvent) -> Check {
    Check { id: e.id, at: e.at, ok: e.outcome == "success" && e.details["ok"] != false, reason: code(&e.details["reason"]) }
}

/// Where things stood when the period began: the last whole check and botd start
/// before it, and the oldest event the last checkpoint before it didn't sign.
pub fn begin(app: &App, p: &Period) -> Integrity {
    let start = p.start_ms();
    let before = |actions: &[&str], limit| app.db.audit_events(&Filter { actions: actions.iter().map(|a| a.to_string()).collect(), to: Some(start), ..Default::default() }, limit, false);
    let last_check = before(&[VERIFIED], 50).iter().find(|e| whole(e)).map(check_of);
    let started = before(&[STARTED], 1).pop().map(|e| e.at);
    let check_from = last_check.as_ref().map(|c| c.at).max(started).unwrap_or(start);
    let checkpoint = before(&[CHECKPOINT], 1).pop().map(|e| e.id);
    let after = app.db.audit_events(&Filter { after: checkpoint, to: Some(start), ..Default::default() }, 200, true);
    let unsealed = after.iter().find(|e| !OWN.contains(&e.action.as_str())).map(|e| e.at.max(started.unwrap_or(i64::MIN)));
    Integrity {
        every_ms: audit_checkpoint::state(app).settings.every as i64 * 60_000,
        listed: Tally::default(),
        checks: Vec::new(),
        last_check,
        check_from,
        check_gaps: Vec::new(),
        unsealed_since: unsealed,
        seal_gaps: Vec::new(),
        daily: BTreeMap::new(),
        export_failures: Vec::new(),
        timestamp_failures: Vec::new(),
    }
}

impl Integrity {
    fn day(&mut self, e: &AuditEvent, what: &'static str) {
        *self.daily.entry(e.time.get(..10).unwrap_or_default().to_string()).or_default().entry(what).or_default() += 1;
    }

    fn open(gaps: &[Gap]) -> bool {
        gaps.last().is_some_and(|g| g.to.is_none())
    }

    fn close(gaps: &mut [Gap], at: i64) {
        if let Some(g) = gaps.last_mut().filter(|g| g.to.is_none()) {
            g.to = Some(at);
        }
    }

    pub fn feed(&mut self, e: &AuditEvent) {
        let action = e.action.as_str();
        if ACTIONS.iter().any(|a| matches(a, action)) {
            self.listed.add(e);
        }
        match action {
            STARTED => {
                // Both loops start again with botd: what was due before it stopped isn't late.
                if !Self::open(&self.check_gaps) {
                    self.check_from = e.at;
                }
                if !Self::open(&self.seal_gaps) && self.unsealed_since.is_some() {
                    self.unsealed_since = Some(e.at);
                }
            }
            VERIFIED => {
                let c = check_of(e);
                self.day(e, if c.ok { "checksPassed" } else { "checksFailed" });
                let mut v = c.view();
                v["whole"] = json!(whole(e));
                v["by"] = json!(e.actor_kind);
                v["checked"] = e.details["checked"].clone();
                v["broken"] = e.details["broken"].clone();
                v["headId"] = e.details["head"]["id"].clone();
                self.checks.push(v);
                if whole(e) {
                    Self::close(&mut self.check_gaps, e.at);
                    self.check_from = e.at;
                    self.last_check = Some(c);
                }
            }
            CHECKPOINT => {
                self.day(e, "checkpoints");
                Self::close(&mut self.seal_gaps, e.at);
                self.unsealed_since = None;
            }
            TIMESTAMPED => self.day(e, "timestamped"),
            FAILING => self.timestamp_failures.push(json!({ "id": e.id, "time": rfc3339(e.at) })),
            EXPORT_FAILING => {
                self.day(e, "exportFailures");
                self.export_failures.push(json!({ "id": e.id, "time": rfc3339(e.at), "kind": code(&e.details["kind"]), "reason": code(&e.details["reason"]), "pending": e.details["pending"] }));
            }
            _ => {}
        }
        if action != VERIFIED && !Self::open(&self.check_gaps) && e.at > self.check_from + CHECK_WITHIN_MS {
            self.check_gaps.push(Gap { from: self.check_from, late: e.at, to: None });
        }
        if let Some(t) = self.unsealed_since.filter(|t| {
            self.every_ms > 0 && action != CHECKPOINT && !Self::open(&self.seal_gaps) && e.at > t + self.every_ms + CHECKPOINT_GRACE_MS
        }) {
            self.seal_gaps.push(Gap { from: t, late: e.at, to: None });
        }
        if self.unsealed_since.is_none() && !OWN.contains(&action) {
            self.unsealed_since = Some(e.at);
        }
    }

    /// The file, and the criteria and rows its manifest entry names. `last_id` is the
    /// period's last event, which every export must have taken.
    pub fn finish(self, app: &App, last_id: Option<i64>, snapshot_ms: i64) -> (Value, Vec<&'static str>, Vec<&'static str>) {
        let now = audit_checkpoint::view(app).unwrap_or_else(|e| json!({ "error": e.to_string() }));
        let through = last_id.unwrap_or(0);
        let export = &now["export"];
        let sinks: Vec<Value> = export["sinks"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|s| {
                let name = s["name"].as_str().filter(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
                json!({
                    "kind": s["kind"], "name": name, "delivered": s["delivered"], "pending": s["pending"],
                    "deliveredThroughPeriod": s["delivered"].as_i64().is_some_and(|d| d >= through),
                    "deliveredAt": s["deliveredAt"].as_i64().map(rfc3339), "failing": s["failing"],
                    "failingSince": s["failingSince"].as_i64().map(rfc3339), "failedTries": s["failedTries"], "compress": s["compress"],
                })
            })
            .collect();
        let behind: Vec<Value> = sinks.iter().filter(|s| s["deliveredThroughPeriod"] != true).map(|s| json!({ "kind": s["kind"], "name": s["name"], "delivered": s["delivered"], "pending": s["pending"] })).collect();
        let exported = !sinks.is_empty() && behind.is_empty();
        let checkpoints_on = self.every_ms > 0;
        let last_failed: Vec<Value> = self.last_check.iter().filter(|c| !c.ok).map(Check::view).collect();
        let failed: Vec<Value> = self.checks.iter().filter(|c| c["ok"] != true).cloned().collect();
        let sealed = exported && checkpoints_on && self.check_gaps.is_empty() && self.seal_gaps.is_empty() && self.last_check.as_ref().is_some_and(|c| c.ok);
        let mut off = Vec::new();
        if !checkpoints_on {
            off.push("checkpoints");
        }
        if sinks.is_empty() {
            off.push("export");
        }
        let pin = last_id.and_then(|id| app.db.with_conn(|c| audit_checkpoint::list(c, id + 1, 1)).ok()).and_then(|mut l| l.pop()).map(|c| {
            json!({
                "event": c.id, "at": rfc3339(c.at), "seq": c.seq, "hash": c.hash, "keyId": c.key_id, "publicKey": c.public_key,
                "signature": c.signature, "algorithm": "Ed25519", "timestamp": { "status": c.tsa_status, "time": c.tsa_time.map(rfc3339) },
            })
        });
        let cp = &now["checkpoints"];
        let ts = &now["timestamps"];
        let passed = self.checks.iter().filter(|c| c["ok"] == true).count();
        let file = json!({
            "snapshotAt": rfc3339(snapshot_ms),
            "summary": {
                "exportedEveryEvent": exported,
                "guardedThroughout": sealed,
                "checks": self.checks.len(),
                "checksPassed": passed,
                "checksFailed": self.checks.len() - passed,
                "checkpointsSigned": self.listed.counts.get(CHECKPOINT).map_or(0, |o| o.values().sum::<u64>()),
                "checkWithinHours": CHECK_WITHIN_MS / HOUR_MS,
                "checkpointEveryMinutes": self.every_ms / 60_000,
                "checkpointGraceMinutes": CHECKPOINT_GRACE_MS / 60_000,
            },
            "chain": {
                "head": now["head"].get("id").map(|_| json!({ "id": now["head"]["id"], "hash": now["head"]["hash"] })),
                "events": now["events"],
                "anchor": now["anchor"].get("id").map(|_| json!({ "id": now["anchor"]["id"], "hash": now["anchor"]["hash"] })),
                "lastCheck": self.last_check.as_ref().map(Check::view),
            },
            "periodEndCheckpoint": pin,
            "checkpoints": {
                "everyMinutes": cp["everyMinutes"], "count": cp["count"], "keyId": cp["key"]["id"], "publicKey": cp["key"]["publicKey"], "behind": cp["behind"],
                "last": cp["last"].get("id").map(|_| json!({ "event": cp["last"]["id"], "at": cp["last"]["at"].as_i64().map(rfc3339), "seq": cp["last"]["seq"], "hash": cp["last"]["hash"] })),
            },
            "timestamps": {
                "enabled": ts["enabled"], "trustAnchors": ts["trustAnchors"], "stamped": ts["stamped"], "pending": ts["pending"],
                "failing": ts["failing"], "failingSince": ts["failingSince"].as_i64().map(rfc3339),
            },
            "export": { "enabled": !sinks.is_empty(), "periodLastEvent": last_id, "sinks": sinks },
            "checks": self.checks,
            "daily": self.daily,
            "exceptions": {
                "off": off,
                "failedChecks": failed,
                "lastCheckFailed": last_failed,
                "checkGaps": self.check_gaps.iter().map(|g| g.view("nextCheck")).collect::<Vec<_>>(),
                "checkpointGaps": self.seal_gaps.iter().map(|g| g.view("nextCheckpoint")).collect::<Vec<_>>(),
                "exportBehind": behind,
                "exportFailures": self.export_failures,
                "timestampFailures": self.timestamp_failures,
            },
            "period": self.listed.view(),
        });
        let (mut criteria, mut rows) = (Vec::new(), Vec::new());
        if exported {
            criteria.push(CRITERIA[0]);
            rows.push(ROWS[0]);
        }
        if sealed {
            criteria.push(CRITERIA[1]);
            rows.push(ROWS[1]);
        }
        (file, criteria, rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: i64 = HOUR_MS;

    fn event(id: i64, at: i64, action: &str, outcome: &str, details: Value) -> AuditEvent {
        AuditEvent {
            id,
            at,
            time: rfc3339(at),
            actor_kind: "system".into(),
            actor_id: None,
            actor_name: None,
            actor_subject: None,
            action: action.into(),
            target_type: None,
            target_id: None,
            bot_id: None,
            outcome: outcome.into(),
            ip: None,
            user_agent: None,
            details,
            actor_email: None,
            actor_role: None,
            auth_method: None,
            idp: None,
            idp_provider: None,
            session_id: None,
            on_behalf_of: None,
            chain_prev: None,
            chain_hash: None,
            chain_digest: None,
            chain_salt: None,
        }
    }

    fn fresh(every_minutes: i64) -> Integrity {
        Integrity {
            every_ms: every_minutes * 60_000,
            listed: Tally::default(),
            checks: Vec::new(),
            last_check: None,
            check_from: 0,
            check_gaps: Vec::new(),
            unsealed_since: None,
            seal_gaps: Vec::new(),
            daily: BTreeMap::new(),
            export_failures: Vec::new(),
            timestamp_failures: Vec::new(),
        }
    }

    /// Feeds `(hour, action)` pairs, with checks passing unless their outcome says so.
    fn run(i: &mut Integrity, events: &[(i64, &str)]) {
        for (n, (hour, action)) in events.iter().enumerate() {
            let (action, outcome) = action.split_once(':').unwrap_or((action, "success"));
            let details = if action == VERIFIED { json!({ "ok": outcome == "success", "reason": if outcome == "success" { Value::Null } else { json!("link") } }) } else { json!({}) };
            i.feed(&event(n as i64 + 1, hour * H, action, outcome, details));
        }
    }

    #[test]
    fn a_daily_check_and_hourly_checkpoints_leave_no_gaps() {
        let mut i = fresh(60);
        let mut events = Vec::new();
        for h in 0..72 {
            events.push((h, "user.created"));
            events.push((h, CHECKPOINT));
            if h % 24 == 1 {
                events.push((h, VERIFIED));
            }
        }
        run(&mut i, &events);
        assert!(i.check_gaps.is_empty() && i.seal_gaps.is_empty());
        assert_eq!((i.checks.len(), i.last_check.as_ref().map(|c| c.ok)), (3, Some(true)));
        assert_eq!(i.daily["1970-01-01"]["checkpoints"], 24);
    }

    #[test]
    fn events_written_a_day_past_the_last_check_are_a_gap_until_the_next() {
        let mut i = fresh(60);
        run(&mut i, &[(1, VERIFIED), (20, "user.created"), (27, "user.created"), (30, "user.updated"), (40, VERIFIED), (50, "user.created")]);
        assert_eq!(i.check_gaps.len(), 1);
        let g = &i.check_gaps[0];
        assert_eq!((g.from, g.late, g.to), (H, 27 * H, Some(40 * H)), "from the last check, through the first late event, to the next check");
        assert!(!Integrity::open(&i.check_gaps));
    }

    #[test]
    fn a_server_that_was_down_isnt_a_gap_but_one_that_ran_without_checking_is() {
        let mut i = fresh(60);
        run(&mut i, &[(1, VERIFIED), (2, "user.created"), (2, CHECKPOINT), (80, STARTED), (80, VERIFIED), (81, CHECKPOINT)]);
        assert!(i.check_gaps.is_empty() && i.seal_gaps.is_empty(), "stopped for three days, then checked and sealed at once");
        let mut i = fresh(60);
        run(&mut i, &[(1, VERIFIED), (80, STARTED), (106, "user.created")]);
        assert_eq!(i.check_gaps.iter().map(|g| (g.from, g.to)).collect::<Vec<_>>(), [(80 * H, None)], "started, then a day without its check");
    }

    #[test]
    fn a_failed_check_is_kept_and_a_partial_one_never_counts_as_the_daily_check() {
        let mut i = fresh(60);
        run(&mut i, &[(1, VERIFIED), (5, "audit.verified:failure")]);
        assert_eq!((i.checks.len(), i.last_check.as_ref().map(|c| (c.ok, c.reason.clone()))), (2, Some((false, Some("link".into())))));
        i.feed(&event(9, 20 * H, VERIFIED, "success", json!({ "ok": true, "range": { "from": 3, "to": 4 } })));
        assert_eq!(i.last_check.as_ref().map(|c| c.ok), Some(false), "a check of a range isn't the whole chain");
        i.feed(&event(10, 31 * H, "user.created", "success", json!({})));
        assert_eq!(i.check_gaps.len(), 1, "due from the last whole check");
    }

    #[test]
    fn events_left_unsigned_past_the_checkpoint_interval_are_a_gap() {
        let mut i = fresh(60);
        run(&mut i, &[(0, "user.created"), (1, CHECKPOINT), (2, "user.created"), (3, TIMESTAMPED), (4, "user.updated"), (5, CHECKPOINT)]);
        assert_eq!(i.seal_gaps.iter().map(|g| (g.from, g.late, g.to)).collect::<Vec<_>>(), [(2 * H, 4 * H, Some(5 * H))]);
        let mut i = fresh(60);
        run(&mut i, &[(0, CHECKPOINT), (1, TIMESTAMPED), (3, TIMESTAMPED), (4, CHECKPOINT)]);
        assert!(i.seal_gaps.is_empty(), "checkpoints' own events need no checkpoint");
        let mut i = fresh(0);
        run(&mut i, &[(0, "user.created"), (30, "user.created")]);
        assert!(i.seal_gaps.is_empty(), "off is reported as off, not as gaps");
    }

    #[test]
    fn export_failures_keep_only_codes() {
        let mut i = fresh(60);
        i.feed(&event(1, H, EXPORT_FAILING, "failure", json!({ "kind": "webhook", "reason": "status", "pending": 12, "sink": "https://siem.example.com", "error": "HTTP 503 from siem.example.com" })));
        let text = json!(i.export_failures).to_string();
        assert!(text.contains("\"pending\":12") && text.contains("webhook") && !text.contains("example.com"), "{text}");
    }
}
