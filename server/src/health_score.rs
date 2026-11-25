//! The customer health score (ADR 0144): a number from 0 to 100 and the six signals behind
//! it, for a technical account manager's monthly health check and quarterly business
//! review (docs/support/health-score.md). Built from what botd already records: who signed
//! in, how Bot runs ended, single sign-on and SCIM failures, approvals left to expire,
//! backups, and the license. `GET /api/support/health-score` (admins), `botctl
//! health-score`, and `health-score.json` in the support bundle.
//!
//! Counts and reason codes only: never a name, email, address, chat or free-text reason,
//! so the report can go in a review deck as it is.

use crate::db::AuditCount;
use crate::obs::metrics::RUN_FAILURES;
use crate::runner::App;
use crate::support::reason_code;
use crate::{AppState, Res, bad};
use axum::Json;
use axum::extract::{Query, State};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};

pub const DEFAULT_DAYS: i64 = 30;
pub const MIN_DAYS: i64 = 7;
pub const MAX_DAYS: i64 = 90;
const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;
/// A share of fewer events than this says little, so it isn't judged.
pub const MIN_SAMPLE: u64 = 10;
/// Failed SCIM requests (from a token, or a revoked one, still in use) in the window that
/// make identity worth a look, and at risk.
pub const SCIM_WATCH: u64 = 1;
pub const SCIM_RISK: u64 = 10;
/// Seats in use, as a percentage of the license's, that make it worth a look.
pub const SEATS_WATCH: u64 = 90;
/// The lowest score of each band: at or above `HEALTHY` is healthy, at or above `WATCH`
/// is watch, below is at risk.
pub const HEALTHY: u32 = 80;
pub const WATCH: u32 = 50;
/// Reason codes listed per signal, most frequent first.
const TOP: usize = 5;
/// The reason given to failures the audit log throttled: logged as a count, not each with its reason.
pub const THROTTLED: &str = "throttled";

/// A signal's verdict, from best to worst (`NotApplicable` when there's nothing to judge).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    NotApplicable,
    Ok,
    Watch,
    Risk,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::NotApplicable => "n/a",
            Status::Ok => "ok",
            Status::Watch => "watch",
            Status::Risk => "risk",
        }
    }

    /// Points towards the score; a signal with nothing to judge doesn't count.
    pub fn points(self) -> Option<u32> {
        match self {
            Status::NotApplicable => None,
            Status::Ok => Some(100),
            Status::Watch => Some(50),
            Status::Risk => Some(0),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Better {
    Higher,
    Lower,
}

/// A share's thresholds, in percent.
#[derive(Clone, Copy, Debug)]
pub struct Rule {
    pub better: Better,
    pub watch: u32,
    pub risk: u32,
}

impl Rule {
    pub fn judge(self, percent: f64) -> Status {
        let (watch, risk) = (f64::from(self.watch), f64::from(self.risk));
        match self.better {
            Better::Higher if percent < risk => Status::Risk,
            Better::Higher if percent < watch => Status::Watch,
            Better::Lower if percent >= risk => Status::Risk,
            Better::Lower if percent >= watch => Status::Watch,
            _ => Status::Ok,
        }
    }

    /// Its watch and at-risk thresholds as the playbook writes them.
    #[cfg(test)]
    pub fn words(self) -> (String, String) {
        match self.better {
            Better::Higher => (format!("below {}%", self.watch), format!("below {}%", self.risk)),
            Better::Lower => (format!("{}% or more", self.watch), format!("{}% or more", self.risk)),
        }
    }
}

pub struct Signal {
    pub id: &'static str,
    pub label: &'static str,
    pub weight: u32,
    /// The share it's judged by, if one; backups and the license are judged by state.
    pub rule: Option<Rule>,
}

/// The signals, their weights (summing to 100) and thresholds. docs/support/health-score.md
/// has a row for each, checked against this.
pub const SIGNALS: [Signal; 6] = [
    Signal { id: "adoption", label: "Adoption", weight: 25, rule: Some(Rule { better: Better::Higher, watch: 60, risk: 30 }) },
    Signal { id: "runs", label: "Bot runs", weight: 20, rule: Some(Rule { better: Better::Lower, watch: 5, risk: 15 }) },
    Signal { id: "identity", label: "Sign-in and SCIM", weight: 20, rule: Some(Rule { better: Better::Lower, watch: 10, risk: 25 }) },
    Signal { id: "backups", label: "Backups", weight: 20, rule: None },
    Signal { id: "approvals", label: "Approvals", weight: 10, rule: Some(Rule { better: Better::Lower, watch: 10, risk: 30 }) },
    Signal { id: "license", label: "License", weight: 5, rule: None },
];

/// Counts by code (a run's result, or a reason code).
pub type Tally = BTreeMap<String, u64>;

#[derive(Clone, Debug, Default)]
pub struct ServerBackups {
    pub off_host: bool,
    pub breach: bool,
    /// Since the newest archive copied off the host was made; None before the first copy.
    pub age_hours: Option<i64>,
    pub rpo_hours: i64,
}

#[derive(Clone, Debug, Default)]
pub struct License {
    pub mode: String,
    pub usable: bool,
    pub seats_used: u32,
    pub seat_cap: Option<u32>,
    /// Until it ends; negative once it has.
    pub days_left: Option<i64>,
}

/// Everything the score is computed from, so the judging is a pure function.
#[derive(Clone, Debug, Default)]
pub struct Inputs {
    pub days: i64,
    pub people: u64,
    pub active_people: u64,
    /// Finished runs by result.
    pub runs: Tally,
    /// Refused runs by reason.
    pub refused: Tally,
    pub run_limited: u64,
    pub sso_ok: u64,
    /// Failed single sign-on attempts by reason.
    pub sso_failed: Tally,
    /// Whether a SCIM token was used in the window.
    pub scim_token_used: bool,
    /// SCIM requests with a valid token that were refused or failed, by reason, and
    /// requests with a revoked or expired token (`revoked_token`, `expired_token`).
    pub scim_failed: Tally,
    /// SCIM tenants whose every working token ends within `scim::WARN_DAYS` (ADR 0196).
    pub scim_expiring: Vec<String>,
    /// Requests with no token or an unknown one: anyone can send those, so they're only counted.
    pub scim_unauthenticated: u64,
    pub approvals_requested: u64,
    pub approvals_expired: u64,
    pub approvals_pending: i64,
    /// None when botd doesn't make server backups.
    pub server_backups: Option<ServerBackups>,
    /// Users' machines' open RPO breaches, when botd manages machines.
    pub machine_rpo_breaches: Option<usize>,
    pub machine_backups_failed: u64,
    /// None when there's no license to judge: testing mode with none installed.
    pub license: Option<License>,
}

const ACTIONS: [&str; 10] = [
    "bot.run_finished",
    "bot.run_refused",
    "machine.run_limited",
    "auth.login",
    "auth.login_failed",
    "scim.auth_failed",
    "scim.request_failed",
    "approval.requested",
    "approval.expired",
    "machine.backup_failed",
];

impl Inputs {
    pub(crate) fn add(&mut self, c: &AuditCount) {
        let code = c.code.as_deref().map_or("none", reason_code).to_string();
        let bump = |t: &mut Tally, k: String| *t.entry(k).or_default() += c.n;
        let sso = c.method.as_deref() == Some("sso");
        match (c.action.as_str(), c.outcome.as_str()) {
            ("bot.run_finished", _) => bump(&mut self.runs, code),
            ("bot.run_refused", _) => bump(&mut self.refused, code),
            ("machine.run_limited", _) => self.run_limited += c.n,
            ("auth.login", "success") if sso => self.sso_ok += c.n,
            ("auth.login_failed", _) if sso => {
                bump(&mut self.sso_failed, code);
                if c.skipped > 0 {
                    *self.sso_failed.entry(THROTTLED.into()).or_default() += c.skipped;
                }
            }
            // Bad tokens are throttled per address whatever the reason, so the ones not
            // logged may be guesses as well as a revoked token: they're only counted.
            ("scim.auth_failed", _) if code == "revoked" || code == "expired" => {
                bump(&mut self.scim_failed, format!("{code}_token"));
                self.scim_unauthenticated += c.skipped;
            }
            ("scim.auth_failed", _) => self.scim_unauthenticated += c.n + c.skipped,
            ("scim.request_failed", _) => bump(&mut self.scim_failed, code),
            ("approval.requested", _) => self.approvals_requested += c.n,
            ("approval.expired", _) => self.approvals_expired += c.n,
            ("machine.backup_failed", _) => self.machine_backups_failed += c.n,
            _ => {}
        }
    }
}

/// The inputs for the `days` before `now_ms`, from the database and botd's state.
pub fn gather(app: &App, now_ms: i64, days: i64) -> Inputs {
    let from = now_ms - days * DAY_MS;
    let (people, active_people) = app.db.people_active_since(from);
    let mut i = Inputs { days, people, active_people, ..Default::default() };
    for c in app.db.audit_counts(from, &ACTIONS) {
        i.add(&c);
    }
    i.approvals_pending = app.db.approvals_pending().0;
    let tokens = app.db.scim_tokens();
    i.scim_token_used = tokens.iter().any(|t| t.last_used_at.is_some_and(|u| u >= from));
    i.scim_expiring = crate::scim::tenants_expiring(&tokens, now_ms);
    i.server_backups = app.server_backups.get().map(|sb| {
        let st = crate::server_backups::status(app, sb);
        ServerBackups {
            off_host: sb.target.is_some(),
            breach: st.breach,
            age_hours: st.last.as_ref().map(|b| (now_ms - b.created_at).max(0) / HOUR_MS),
            rpo_hours: sb.rpo_ms / HOUR_MS,
        }
    });
    i.machine_rpo_breaches = app.control_plane.get().filter(|cp| cp.enabled()).map(|_| app.db.machine_rpo_breaches_open().len());
    let l = app.license.status_at(now_ms);
    if l.claims.is_some() || !l.testing_mode {
        i.license = Some(License {
            mode: serde_json::to_value(l.mode).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(),
            usable: l.usable(),
            seats_used: app.db.active_seats(),
            seat_cap: l.seat_cap(),
            days_left: l.expires_at().map(|e| (e - now_ms).div_euclid(DAY_MS)),
        });
    }
    i
}

fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 { 0.0 } else { part as f64 * 100.0 / whole as f64 }
}

fn one_place(p: f64) -> f64 {
    (p * 10.0).round() / 10.0
}

fn shown(p: f64) -> String {
    if p > 0.0 && p < 1.0 { "under 1%".into() } else { format!("{p:.0}%") }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The `TOP` most frequent codes, most frequent first.
fn top(t: &Tally) -> Value {
    let mut v: Vec<(&String, &u64)> = t.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    Value::Array(v.into_iter().take(TOP).map(|(code, n)| json!({ "code": code, "count": n })).collect())
}

struct Judged {
    status: Status,
    summary: String,
    facts: Value,
}

fn rule(id: &str) -> Rule {
    SIGNALS.iter().find(|s| s.id == id).and_then(|s| s.rule).expect("a signal with a rule")
}

fn adoption(i: &Inputs) -> Judged {
    let p = percent(i.active_people, i.people);
    let facts = json!({ "people": i.people, "active": i.active_people, "activePercent": one_place(p) });
    if i.people == 0 {
        return Judged { status: Status::NotApplicable, summary: "Nobody but the owner account has a seat yet.".into(), facts };
    }
    let summary = format!("{} of {} ({}) signed in or used SuperBot in the last {} days.", i.active_people, plural(i.people, "person", "people"), shown(p), i.days);
    Judged { status: rule("adoption").judge(p), summary, facts }
}

fn runs(i: &Inputs) -> Judged {
    let finished: u64 = i.runs.values().sum();
    let failed: u64 = RUN_FAILURES.iter().filter_map(|r| i.runs.get(*r)).sum();
    let refused: u64 = i.refused.values().sum();
    let p = percent(failed, finished);
    let facts = json!({
        "finished": finished, "failed": failed, "failedPercent": one_place(p), "byResult": i.runs,
        "refused": refused, "refusedReasons": top(&i.refused), "runLimited": i.run_limited,
    });
    if finished < MIN_SAMPLE {
        let summary = format!("{} finished in the last {} days: too few to judge.", plural(finished, "run", "runs"), i.days);
        return Judged { status: Status::NotApplicable, summary, facts };
    }
    let mut summary = format!("{failed} of {finished} runs ({}) failed or timed out in the last {} days.", shown(p), i.days);
    if refused > 0 {
        summary.push_str(&format!(" {} refused before starting.", plural(refused, "was", "were")));
    }
    Judged { status: rule("runs").judge(p), summary, facts }
}

fn identity(i: &Inputs) -> Judged {
    let sso_failed: u64 = i.sso_failed.values().sum();
    let attempts = i.sso_ok + sso_failed;
    let scim_failed: u64 = i.scim_failed.values().sum();
    let p = percent(sso_failed, attempts);
    let facts = json!({
        "ssoAttempts": attempts, "ssoFailed": sso_failed, "ssoFailedPercent": one_place(p), "ssoReasons": top(&i.sso_failed),
        "scimTokenUsed": i.scim_token_used, "scimFailed": scim_failed, "scimReasons": top(&i.scim_failed), "scimUnauthenticated": i.scim_unauthenticated,
        "scimTenantsExpiring": i.scim_expiring.len(),
    });
    let scim_used = i.scim_token_used || scim_failed > 0 || !i.scim_expiring.is_empty();
    if attempts == 0 && !scim_used {
        return Judged { status: Status::NotApplicable, summary: format!("No single sign-on or SCIM in the last {} days.", i.days), facts };
    }
    let sso = if attempts >= MIN_SAMPLE { rule("identity").judge(p) } else { Status::NotApplicable };
    let scim = match scim_failed {
        n if n >= SCIM_RISK => Status::Risk,
        n if n >= SCIM_WATCH => Status::Watch,
        _ if !i.scim_expiring.is_empty() => Status::Watch,
        _ if scim_used => Status::Ok,
        _ => Status::NotApplicable,
    };
    let mut parts = Vec::new();
    if attempts > 0 {
        let judged = if attempts < MIN_SAMPLE { ", too few to judge" } else { "" };
        parts.push(format!("{sso_failed} of {} ({}) failed{judged}", plural(attempts, "single sign-on attempt", "single sign-on attempts"), shown(p)));
    }
    if scim_used {
        parts.push(format!("{} failed", plural(scim_failed, "SCIM request", "SCIM requests")));
    }
    if !i.scim_expiring.is_empty() {
        parts.push(format!("every SCIM token of {} ends within {} days", plural(i.scim_expiring.len() as u64, "tenant", "tenants"), crate::scim::WARN_DAYS));
    }
    let summary = format!("In the last {} days, {}.", i.days, parts.join("; "));
    Judged { status: sso.max(scim), summary, facts }
}

fn backups(i: &Inputs) -> Judged {
    let mut status = Status::NotApplicable;
    let mut notes = Vec::new();
    let mut worse = |s: Status, note: String| {
        status = status.max(s);
        notes.push(note);
    };
    match &i.server_backups {
        None => worse(Status::Watch, "server backups aren't set up".into()),
        Some(sb) if !sb.off_host => worse(Status::Watch, "server backups stay on this host".into()),
        Some(sb) if sb.breach => worse(Status::Risk, format!("the newest server backup off the host is older than its RPO of {} hours", sb.rpo_hours)),
        Some(sb) => match sb.age_hours {
            Some(h) => worse(Status::Ok, format!("the newest server backup off the host is {h} hours old, within its RPO of {} hours", sb.rpo_hours)),
            None => worse(Status::Watch, format!("no server backup has been copied off the host yet (RPO {} hours)", sb.rpo_hours)),
        },
    }
    if let Some(open) = i.machine_rpo_breaches {
        match open {
            0 => worse(Status::Ok, "no machine is past its RPO".into()),
            n => worse(Status::Risk, format!("{} past {} RPO", plural(n as u64, "machine is", "machines are"), if n == 1 { "its" } else { "their" })),
        }
        if i.machine_backups_failed > 0 {
            worse(Status::Watch, format!("{} failed in the last {} days", plural(i.machine_backups_failed, "machine backup", "machine backups"), i.days));
        }
    }
    let mut summary = notes.join("; ");
    if let Some(c) = summary.get(..1) {
        summary = format!("{}{}.", c.to_uppercase(), &summary[1..]);
    }
    let server = i.server_backups.as_ref().map(|sb| json!({ "offHost": sb.off_host, "breach": sb.breach, "ageHours": sb.age_hours, "rpoHours": sb.rpo_hours }));
    let facts = json!({ "server": server, "machineRpoBreaches": i.machine_rpo_breaches, "machineBackupsFailed": i.machine_backups_failed });
    Judged { status, summary, facts }
}

fn approvals(i: &Inputs) -> Judged {
    let p = percent(i.approvals_expired, i.approvals_requested);
    let facts = json!({ "requested": i.approvals_requested, "expired": i.approvals_expired, "expiredPercent": one_place(p), "pendingNow": i.approvals_pending });
    if i.approvals_requested < MIN_SAMPLE {
        let summary = format!("{} asked for in the last {} days: too few to judge.", plural(i.approvals_requested, "approval", "approvals"), i.days);
        return Judged { status: Status::NotApplicable, summary, facts };
    }
    let summary = format!("{} of {} approvals ({}) expired unanswered in the last {} days; {} waiting now.", i.approvals_expired, i.approvals_requested, shown(p), i.days, i.approvals_pending);
    Judged { status: rule("approvals").judge(p), summary, facts }
}

fn license(i: &Inputs) -> Judged {
    let Some(l) = &i.license else {
        return Judged { status: Status::NotApplicable, summary: "Testing mode, with no license installed.".into(), facts: Value::Null };
    };
    let facts = json!({ "mode": l.mode, "usable": l.usable, "seatsUsed": l.seats_used, "seats": l.seat_cap, "daysLeft": l.days_left });
    let seats = match l.seat_cap {
        Some(cap) => format!("{} of {cap} seats in use", l.seats_used),
        None => format!("{} in use, no seat limit", plural(u64::from(l.seats_used), "seat", "seats")),
    };
    let (status, said) = match (l.mode.as_str(), l.days_left) {
        _ if !l.usable => (Status::Risk, "There's no usable license, so Bots don't run".to_string()),
        ("grace", _) => (Status::Risk, "The license has ended and is in its grace period".into()),
        (_, Some(d)) if d < crate::license::WARN_DAYS => (Status::Watch, format!("The license ends in {}", plural(d.max(0) as u64, "day", "days"))),
        (_, Some(d)) => (Status::Ok, format!("The license has {} left", plural(d as u64, "day", "days"))),
        _ => (Status::Ok, "The license is active".into()),
    };
    let crowded = match l.seat_cap {
        Some(cap) if l.seats_used > cap => Status::Risk,
        Some(cap) if u64::from(l.seats_used) * 100 >= u64::from(cap) * SEATS_WATCH => Status::Watch,
        _ => Status::Ok,
    };
    Judged { status: status.max(crowded), summary: format!("{said}; {seats}."), facts }
}

/// The report: the score, its band, and each signal with what it saw.
pub fn report(i: &Inputs, now_ms: i64) -> Value {
    let judged: HashMap<&str, Judged> =
        [("adoption", adoption(i)), ("runs", runs(i)), ("identity", identity(i)), ("backups", backups(i)), ("approvals", approvals(i)), ("license", license(i))].into_iter().collect();
    let (mut got, mut of) = (0u32, 0u32);
    let mut signals = Vec::new();
    let mut at_risk = Vec::new();
    let mut watch = Vec::new();
    for s in &SIGNALS {
        let j = &judged[s.id];
        if let Some(p) = j.status.points() {
            got += p * s.weight;
            of += s.weight;
        }
        match j.status {
            Status::Risk => at_risk.push(s.id),
            Status::Watch => watch.push(s.id),
            _ => {}
        }
        signals.push(json!({
            "id": s.id, "label": s.label, "weight": s.weight, "status": j.status.as_str(), "points": j.status.points(),
            "summary": j.summary, "facts": j.facts, "playbook": format!("docs/support/health-score.md#{}", s.id),
        }));
    }
    let score = (of > 0).then(|| (f64::from(got) / f64::from(of)).round() as u32);
    json!({
        "generatedAt": rfc3339(now_ms),
        "windowDays": i.days,
        "from": rfc3339(now_ms - i.days * DAY_MS),
        "score": score,
        "band": band(score, !at_risk.is_empty()),
        "atRisk": at_risk,
        "watch": watch,
        "signals": signals,
    })
}

/// The score's band. A signal at risk keeps it out of healthy, whatever the others say.
pub fn band(score: Option<u32>, any_at_risk: bool) -> &'static str {
    match score {
        None => "unknown",
        Some(s) if s >= HEALTHY && !any_at_risk => "healthy",
        Some(s) if s >= WATCH => "watch",
        Some(_) => "at_risk",
    }
}

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default()
}

/// The report for the last `days`, with a note when the audit log keeps less than that.
pub fn build(app: &App, now_ms: i64, days: i64) -> Value {
    let mut v = report(&gather(app, now_ms, days), now_ms);
    let kept = app.db.audit_retention();
    v["auditRetentionDays"] = json!(kept);
    v["partial"] = json!(kept.is_some_and(|d| i64::from(d) < days));
    v
}

/// The window asked for: `days` from `MIN_DAYS` to `MAX_DAYS`, `DEFAULT_DAYS` if not given.
pub fn days(q: &HashMap<String, String>) -> Result<i64, String> {
    match q.get("days") {
        None => Ok(DEFAULT_DAYS),
        Some(d) => match d.parse::<i64>() {
            Ok(n) if (MIN_DAYS..=MAX_DAYS).contains(&n) => Ok(n),
            _ => Err(format!("days must be a whole number from {MIN_DAYS} to {MAX_DAYS}")),
        },
    }
}

/// `GET /api/support/health-score[?days=30]` (admins).
pub async fn get(State(app): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Res {
    let days = days(&q).map_err(bad)?;
    let v = tokio::task::spawn_blocking(move || build(&app, crate::db::now(), days))
        .await
        .map_err(|e| crate::ApiError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't work out the health score: {e}")))?;
    Ok(Json(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tally(pairs: &[(&str, u64)]) -> Tally {
        pairs.iter().map(|(k, n)| (k.to_string(), *n)).collect()
    }

    /// A customer with nothing wrong: most people active, few failures, backups off the host.
    fn healthy() -> Inputs {
        Inputs {
            days: 30,
            people: 20,
            active_people: 18,
            runs: tally(&[("done", 190), ("error", 4), ("stopped", 6)]),
            sso_ok: 100,
            sso_failed: tally(&[("not_linked", 2)]),
            scim_token_used: true,
            approvals_requested: 50,
            approvals_expired: 2,
            server_backups: Some(ServerBackups { off_host: true, breach: false, age_hours: Some(3), rpo_hours: 26 }),
            machine_rpo_breaches: Some(0),
            license: Some(License { mode: "active".into(), usable: true, seats_used: 20, seat_cap: Some(50), days_left: Some(200) }),
            ..Default::default()
        }
    }

    fn signal<'a>(r: &'a Value, id: &str) -> &'a Value {
        r["signals"].as_array().unwrap().iter().find(|s| s["id"] == id).unwrap()
    }

    #[test]
    fn weights_sum_to_a_hundred_and_ids_are_unique() {
        assert_eq!(SIGNALS.iter().map(|s| s.weight).sum::<u32>(), 100);
        let ids: std::collections::HashSet<_> = SIGNALS.iter().map(|s| s.id).collect();
        assert_eq!(ids.len(), SIGNALS.len());
    }

    #[test]
    fn rules_judge_at_their_thresholds() {
        let higher = Rule { better: Better::Higher, watch: 60, risk: 30 };
        assert_eq!([higher.judge(60.0), higher.judge(59.9), higher.judge(30.0), higher.judge(29.9)], [Status::Ok, Status::Watch, Status::Watch, Status::Risk]);
        let lower = Rule { better: Better::Lower, watch: 5, risk: 15 };
        assert_eq!([lower.judge(4.9), lower.judge(5.0), lower.judge(14.9), lower.judge(15.0)], [Status::Ok, Status::Watch, Status::Watch, Status::Risk]);
        assert_eq!(higher.words(), ("below 60%".into(), "below 30%".into()));
        assert_eq!(lower.words(), ("5% or more".into(), "15% or more".into()));
    }

    #[test]
    fn a_healthy_customer_scores_a_hundred() {
        let r = report(&healthy(), 1_800_000_000_000);
        assert_eq!(r["score"], 100, "{r:#}");
        assert_eq!(r["band"], "healthy");
        assert_eq!(r["atRisk"], json!([]));
        assert_eq!(signal(&r, "adoption")["summary"], "18 of 20 people (90%) signed in or used SuperBot in the last 30 days.");
        assert_eq!(signal(&r, "runs")["facts"]["failed"], 4, "stopped runs aren't failures");
        assert_eq!(signal(&r, "identity")["summary"], "In the last 30 days, 2 of 102 single sign-on attempts (2%) failed; 0 SCIM requests failed.");
        assert_eq!(signal(&r, "backups")["summary"], "The newest server backup off the host is 3 hours old, within its RPO of 26 hours; no machine is past its RPO.");
        assert_eq!(signal(&r, "license")["summary"], "The license has 200 days left; 20 of 50 seats in use.");
        assert_eq!(signal(&r, "adoption")["playbook"], "docs/support/health-score.md#adoption");
    }

    #[test]
    fn the_score_is_the_weighted_mean_of_what_can_be_judged() {
        let mut i = healthy();
        i.active_people = 10; // 50%: watch, 25 points of 25 * 100 lost by half
        let r = report(&i, 0);
        assert_eq!((r["score"].as_u64(), r["band"].as_str()), (Some(88), Some("healthy")), "{r:#}");
        assert_eq!(r["watch"], json!(["adoption"]));
        i.runs = tally(&[("done", 5)]);
        i.approvals_requested = 3;
        let r = report(&i, 0);
        assert_eq!(signal(&r, "runs")["status"], "n/a");
        assert_eq!(signal(&r, "runs")["points"], Value::Null);
        assert_eq!(signal(&r, "approvals")["summary"], "3 approvals asked for in the last 30 days: too few to judge.");
        // 25 * 50 + (20 + 20 + 5) * 100 over 70
        assert_eq!(r["score"], 82, "{r:#}");
    }

    #[test]
    fn one_signal_at_risk_keeps_the_customer_out_of_healthy() {
        let mut i = healthy();
        i.license.as_mut().unwrap().seats_used = 51;
        let r = report(&i, 0);
        assert_eq!(r["score"], 95);
        assert_eq!((r["band"].as_str(), r["atRisk"].clone()), (Some("watch"), json!(["license"])));
        assert_eq!(band(Some(49), false), "at_risk");
        assert_eq!(band(Some(50), true), "watch");
        assert_eq!(band(None, false), "unknown");
    }

    #[test]
    fn failed_runs_are_errors_and_timeouts() {
        let mut i = healthy();
        i.runs = tally(&[("done", 80), ("error", 12), ("timeout", 8)]);
        i.refused = tally(&[("egress_policy_pending", 3), ("license", 1)]);
        i.run_limited = 2;
        let r = report(&i, 0);
        let s = signal(&r, "runs");
        assert_eq!(s["status"], "risk", "{s:#}");
        assert_eq!(s["summary"], "20 of 100 runs (20%) failed or timed out in the last 30 days. 4 were refused before starting.");
        assert_eq!(s["facts"]["refusedReasons"], json!([{ "code": "egress_policy_pending", "count": 3 }, { "code": "license", "count": 1 }]));
        assert_eq!(s["facts"]["runLimited"], 2);
    }

    #[test]
    fn identity_takes_the_worse_of_sso_and_scim() {
        let mut i = healthy();
        i.scim_failed = tally(&[("revoked_token", 3)]);
        i.scim_unauthenticated = 500;
        let r = report(&i, 0);
        assert_eq!(signal(&r, "identity")["status"], "watch", "a revoked token still in use");
        assert_eq!(signal(&r, "identity")["facts"]["scimUnauthenticated"], 500);
        i.scim_failed.clear();
        let r = report(&i, 0);
        assert_eq!(signal(&r, "identity")["status"], "ok", "unauthenticated requests are anyone's");
        i.scim_failed = tally(&[("uniqueness", 7), ("status_403", 3)]);
        let r = report(&i, 0);
        assert_eq!(signal(&r, "identity")["status"], "risk", "10 refused provisioning requests");
        assert_eq!(signal(&r, "identity")["facts"]["scimReasons"][0], json!({ "code": "uniqueness", "count": 7 }));
        i.scim_failed.clear();
        i.sso_failed = tally(&[("bad_signature", 30), ("not_linked", 4)]);
        let r = report(&i, 0);
        let s = signal(&r, "identity");
        assert_eq!(s["status"], "risk", "34 of 134 is 25% or more");
        assert_eq!(s["facts"]["ssoReasons"][0], json!({ "code": "bad_signature", "count": 30 }));
        let none = Inputs { days: 30, ..Default::default() };
        assert_eq!(signal(&report(&none, 0), "identity")["status"], "n/a");
    }

    #[test]
    fn backups_take_the_worst_of_the_server_and_machines() {
        let mut i = healthy();
        i.machine_backups_failed = 2;
        assert_eq!(signal(&report(&i, 0), "backups")["status"], "watch");
        i.machine_rpo_breaches = Some(2);
        let r = report(&i, 0);
        assert_eq!(signal(&r, "backups")["status"], "risk");
        assert!(signal(&r, "backups")["summary"].as_str().unwrap().contains("2 machines are past their RPO"), "{r:#}");
        i = healthy();
        i.server_backups.as_mut().unwrap().off_host = false;
        assert_eq!(signal(&report(&i, 0), "backups")["status"], "watch");
        i.server_backups = None;
        i.machine_rpo_breaches = None;
        assert_eq!(signal(&report(&i, 0), "backups")["summary"], "Server backups aren't set up.");
        i.server_backups = Some(ServerBackups { off_host: true, breach: true, age_hours: Some(40), rpo_hours: 26 });
        assert_eq!(signal(&report(&i, 0), "backups")["status"], "risk");
        i.server_backups = Some(ServerBackups { off_host: true, breach: false, age_hours: None, rpo_hours: 26 });
        let r = report(&i, 0);
        assert_eq!(signal(&r, "backups")["status"], "watch", "copies on, none made yet");
        assert_eq!(signal(&r, "backups")["summary"], "No server backup has been copied off the host yet (RPO 26 hours).");
    }

    #[test]
    fn the_license_is_judged_by_its_end_and_its_seats() {
        let mut i = healthy();
        let l = i.license.as_mut().unwrap();
        l.days_left = Some(12);
        l.seats_used = 46;
        let r = report(&i, 0);
        assert_eq!((signal(&r, "license")["status"].as_str(), signal(&r, "license")["summary"].as_str()), (Some("watch"), Some("The license ends in 12 days; 46 of 50 seats in use.")));
        let l = i.license.as_mut().unwrap();
        (l.mode, l.days_left) = ("grace".into(), Some(-3));
        assert_eq!(signal(&report(&i, 0), "license")["status"], "risk");
        i.license = Some(License { mode: "unlicensed".into(), usable: false, seats_used: 4, seat_cap: Some(0), days_left: None });
        assert_eq!(signal(&report(&i, 0), "license")["status"], "risk");
        i.license = None;
        assert_eq!(signal(&report(&i, 0), "license")["status"], "n/a");
    }

    #[test]
    fn a_new_server_is_judged_on_what_it_has() {
        let r = report(&Inputs { days: 30, ..Default::default() }, 0);
        assert_eq!((r["score"].as_u64(), r["band"].as_str()), (Some(50), Some("watch")), "only backups, not set up: {r:#}");
        for id in ["adoption", "runs", "identity", "approvals", "license"] {
            assert_eq!(signal(&r, id)["status"], "n/a", "{id}");
        }
        let mut i = Inputs { days: 30, ..Default::default() };
        i.server_backups = Some(ServerBackups { off_host: true, age_hours: Some(1), ..Default::default() });
        let r = report(&i, 0);
        assert_eq!((r["score"].as_u64(), r["band"].as_str()), (Some(100), Some("healthy")));
    }

    #[test]
    fn audit_counts_become_inputs() {
        let mut i = Inputs::default();
        let c = |action: &str, outcome: &str, method: Option<&str>, code: Option<&str>, n| AuditCount { action: action.into(), outcome: outcome.into(), method: method.map(String::from), code: code.map(String::from), n, skipped: 0 };
        for x in [
            c("bot.run_finished", "success", None, Some("done"), 7),
            c("bot.run_finished", "failure", None, Some("error"), 2),
            c("bot.run_refused", "denied", None, Some("Deletes /home/Jane Smith/x"), 1),
            c("auth.login", "success", Some("sso"), None, 5),
            c("auth.login", "success", Some("password"), None, 9),
            c("auth.login_failed", "failure", Some("sso"), Some("not_linked"), 3),
            c("auth.login_failed", "failure", Some("password"), Some("bad_password"), 4),
            c("scim.auth_failed", "failure", Some("scim_token"), Some("unknown"), 6),
            c("scim.auth_failed", "failure", Some("scim_token"), Some("revoked"), 1),
            AuditCount { skipped: 10, ..c("scim.auth_failed", "failure", Some("scim_token"), Some("revoked"), 1) },
            AuditCount { skipped: 7, ..c("auth.login_failed", "failure", Some("sso"), Some("bad_signature"), 1) },
            c("scim.request_failed", "failure", Some("scim_token"), Some("uniqueness"), 2),
            c("scim.group_member_refused", "denied", Some("scim_token"), Some("other_team"), 2),
            c("scim.user_linked", "success", Some("scim_token"), None, 8),
            c("approval.requested", "success", None, None, 11),
            c("approval.expired", "success", None, None, 4),
            c("machine.backup_failed", "failure", None, Some("upload failed: s3 said no"), 1),
        ] {
            i.add(&x);
        }
        assert_eq!(i.runs, tally(&[("done", 7), ("error", 2)]));
        assert_eq!(i.refused, tally(&[("[text]", 1)]), "free-text reasons never leave");
        assert_eq!((i.sso_ok, i.sso_failed.clone()), (5, tally(&[("bad_signature", 1), ("not_linked", 3), (THROTTLED, 7)])), "password sign-ins aren't single sign-on; skipped failures aren't given a reason");
        assert_eq!(i.scim_failed, tally(&[("revoked_token", 2), ("uniqueness", 2)]), "each failed request once, not its own event too");
        assert_eq!(i.scim_unauthenticated, 16, "bad tokens not logged may be guesses, so they're only counted");
        assert_eq!((i.approvals_requested, i.approvals_expired, i.machine_backups_failed), (11, 4, 1));
    }

    #[test]
    fn the_window_is_checked() {
        let q = |d: &str| HashMap::from([("days".to_string(), d.to_string())]);
        assert_eq!(days(&HashMap::new()), Ok(30));
        assert_eq!(days(&q("7")), Ok(7));
        assert_eq!(days(&q("90")), Ok(90));
        for d in ["6", "91", "x", "-30", "30.5"] {
            assert!(days(&q(d)).is_err(), "{d}");
        }
    }

    /// The playbook names every signal with its weight and thresholds, and the bands.
    #[test]
    fn the_playbook_matches_the_code() {
        let md = include_str!("../../docs/support/health-score.md");
        for s in &SIGNALS {
            let row = md.lines().find(|l| l.starts_with(&format!("| [`{}`](#{})", s.id, s.id))).unwrap_or_else(|| panic!("health-score.md has no row for {}", s.id));
            let cells: Vec<&str> = row.trim_matches('|').split('|').map(str::trim).collect();
            assert_eq!(cells[1], s.weight.to_string(), "{}'s weight", s.id);
            if let Some(r) = s.rule {
                let (watch, risk) = r.words();
                assert!(cells[3].contains(&watch) && cells[4].contains(&risk), "{}'s thresholds: {row}", s.id);
            }
            assert!(md.contains(&format!("\n### `{}`\n", s.id)), "health-score.md has no section for {}", s.id);
        }
        for needle in [format!("{HEALTHY} or more"), format!("{WATCH} to {}", HEALTHY - 1), format!("below {WATCH}"), format!("fewer than {MIN_SAMPLE}"), format!("{MIN_DAYS} to {MAX_DAYS}")] {
            assert!(md.contains(&needle), "health-score.md doesn't say \"{needle}\"");
        }
    }
}
