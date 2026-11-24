//! The quarterly business review draft (ADR 0262): the parts of
//! `docs/support/qbr-template.md` botd can fill in from its own records, for the technical
//! account manager's review with an Enterprise customer. Three calendar months (UTC), each
//! with the score botd recorded at its end (ADR 0157), the month's health checks
//! (`support.health_checked`, ADR 0252), Bot runs and refusals at a plan's limit, sign-in
//! and SCIM failures, approvals left to expire, machine backups and residency refusals; and
//! for the quarter, the score's trend, runs by harness, status page incidents with whether
//! each has a review drafted (ADR 0201), access reviews, configuration changes and machine
//! restores. Goals, tickets, what's next and actions are left for people, marked
//! "To fill in", with the commands that fill them where there is one.
//!
//! `GET /api/support/business-review[?to=YYYY-MM&format=markdown]` (admins, audited as
//! `support.business_review_drafted`) and `botctl business-review`. Codes, counts, dates,
//! harness names, region ids and incident ids only: never a person's name or email, an
//! incident's title, an address or a bucket, so the draft can go to the customer as it is.

use crate::audit::{Filter, Who};
use crate::db::AuditCount;
use crate::health_check::{LIMIT_REASONS, REVIEWED_IMPACTS};
use crate::health_score::{self, SIGNALS};
use crate::obs::metrics::RUN_FAILURES;
use crate::runner::App;
use crate::{ApiError, AppState, Auth, Res, bad};
use axum::Json;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Datelike;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::sync::Arc;

/// Bumped when the JSON's shape changes.
pub const FORMAT: u32 = 1;
pub const DRAFTED: &str = "support.business_review_drafted";
pub const TEMPLATE: &str = "docs/support/qbr-template.md";
const TODO: &str = "_To fill in._";
const MINUTE: i64 = 60_000;
const DAY_MS: i64 = 86_400_000;
/// SQLite's `LIMIT -1`: every row that matches.
const ALL: i64 = -1;
/// Runs with no record of their harness whose Bot is gone.
pub const UNRECORDED: &str = "unrecorded";

/// Counted for each month; the health score's own reading of them (ADR 0144).
const MONTH_ACTIONS: [&str; 12] = [
    "bot.run_finished",
    "bot.run_refused",
    "usage.token_limit_reached",
    "auth.login",
    "auth.login_failed",
    "scim.auth_failed",
    "scim.request_failed",
    "approval.requested",
    "approval.expired",
    "machine.backup_failed",
    "machine.residency_refused",
    "machine.run_limited",
];

/// Successful configuration changes the review lists, by kind.
pub const CHANGES: [(&str, &[&str]); 5] = [
    (
        "saml",
        &["sso.saml_metadata_imported", "sso.saml_sp_key_created", "sso.saml_sp_key_promoted", "sso.saml_sp_key_retired", "sso.saml_role_mapped", "sso.saml_role_unmapped"],
    ),
    ("scimTokens", &["scim.token_created", "scim.token_rotated", "scim.token_revoked"]),
    ("customRoles", &["role.created", "role.updated", "role.deleted"]),
    ("roleGrants", &["role.assigned", "role.unassigned"]),
    ("residencyPins", &["user.residency_pinned", "user.residency_unpinned", "team.residency_pinned", "team.residency_unpinned"]),
];

const MONTH_NAMES: [&str; 12] = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

/// A calendar month, UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ym {
    pub y: i32,
    /// 1 to 12.
    pub m: u32,
}

impl Ym {
    pub fn of_ms(ms: i64) -> Ym {
        let d = chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default();
        Ym { y: d.year(), m: d.month() }
    }

    /// `YYYY-MM`, from 2000 on.
    pub fn parse(s: &str) -> Option<Ym> {
        let (y, m) = s.split_once('-')?;
        if y.len() != 4 || m.len() != 2 || !s.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
            return None;
        }
        let (y, m) = (y.parse::<i32>().ok()?, m.parse::<u32>().ok()?);
        ((2000..=9999).contains(&y) && (1..=12).contains(&m)).then_some(Ym { y, m })
    }

    pub fn plus(self, months: i32) -> Ym {
        let i = self.y * 12 + self.m as i32 - 1 + months;
        Ym { y: i.div_euclid(12), m: i.rem_euclid(12) as u32 + 1 }
    }

    pub fn start_ms(self) -> i64 {
        chrono::NaiveDate::from_ymd_opt(self.y, self.m, 1).and_then(|d| d.and_hms_opt(0, 0, 0)).map_or(0, |t| t.and_utc().timestamp_millis())
    }

    pub fn id(self) -> String {
        format!("{:04}-{:02}", self.y, self.m)
    }

    fn name(self) -> &'static str {
        MONTH_NAMES[(self.m as usize - 1) % 12]
    }

    /// "Aug 2026".
    pub fn short(self) -> String {
        format!("{} {}", &self.name()[..3], self.y)
    }
}

/// The three months ending with `to`, and how the review names them: a calendar quarter
/// by its number, else its months.
pub fn label(to: Ym) -> String {
    let from = to.plus(-2);
    if from.m % 3 == 1 {
        format!("Q{} {} ({} to {})", to.m / 3, to.y, from.name(), to.name())
    } else if from.y == to.y {
        format!("{} to {} {}", from.name(), to.name(), to.y)
    } else {
        format!("{} {} to {} {}", from.name(), from.y, to.name(), to.y)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Markdown,
}

/// `?to=YYYY-MM&format=json|markdown`. `to` is the quarter's last month: the last whole
/// month by default, this month at the latest. Anything else is refused without echoing
/// what isn't an id.
pub fn parse_query(q: &HashMap<String, String>, now_ms: i64) -> Result<(Ym, Format), String> {
    if let Some(k) = q.keys().find(|k| !["to", "format"].contains(&k.as_str())) {
        let shown = if k.len() <= 40 && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') { k.as_str() } else { "[text]" };
        return Err(format!("Unknown parameter \"{shown}\". The business review takes to=YYYY-MM (the quarter's last month) and format=json or markdown."));
    }
    let this = Ym::of_ms(now_ms);
    let to = match q.get("to").map(|v| v.trim()).filter(|v| !v.is_empty()) {
        None => this.plus(-1),
        Some(v) => Ym::parse(v).ok_or("to must be a month, YYYY-MM")?,
    };
    if to > this {
        return Err(format!("to can't be after this month ({}).", this.id()));
    }
    let format = match q.get("format").map(|v| v.trim()) {
        None | Some("" | "json") => Format::Json,
        Some("markdown" | "md") => Format::Markdown,
        Some(_) => return Err("format must be json or markdown".into()),
    };
    Ok((to, format))
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DayScore {
    pub date: String,
    pub score: Option<u32>,
    pub band: String,
    pub at_risk: Vec<String>,
    pub watch: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub date: String,
    pub score: Option<u32>,
    pub band: String,
    pub open: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Month {
    /// `YYYY-MM`.
    pub month: String,
    /// This month: its figures run to now.
    pub so_far: bool,
    /// The last score botd recorded in the month.
    pub score: Option<DayScore>,
    pub days_recorded: usize,
    pub health_checks: usize,
    /// The month's newest health check.
    pub last_check: Option<Check>,
    pub runs_finished: u64,
    pub runs_failed: u64,
    pub refused_at_limit: u64,
    pub run_limited: u64,
    pub token_limits_reached: u64,
    pub sso_attempts: u64,
    pub sso_failed: u64,
    pub scim_failed: u64,
    pub approvals_requested: u64,
    pub approvals_expired: u64,
    pub machine_backups_failed: u64,
    pub residency_refusals: u64,
}

impl Month {
    /// The month's audit counts, read as the health score reads them.
    pub fn count(&mut self, counts: &[AuditCount]) {
        let mut i = health_score::Inputs::default();
        for c in counts {
            i.add(c);
            match c.action.as_str() {
                "usage.token_limit_reached" => self.token_limits_reached += c.n,
                "machine.residency_refused" => self.residency_refusals += c.n,
                _ => {}
            }
        }
        self.runs_finished = i.runs.values().sum();
        self.runs_failed = RUN_FAILURES.iter().filter_map(|r| i.runs.get(*r)).sum();
        self.refused_at_limit = LIMIT_REASONS.iter().filter_map(|r| i.refused.get(*r)).sum();
        self.residency_refusals += i.refused.get(crate::machines::residency::PINNED).copied().unwrap_or(0);
        self.run_limited = i.run_limited;
        self.sso_failed = i.sso_failed.values().sum();
        self.sso_attempts = i.sso_ok + self.sso_failed;
        self.scim_failed = i.scim_failed.values().sum();
        self.approvals_requested = i.approvals_requested;
        self.approvals_expired = i.approvals_expired;
        self.machine_backups_failed = i.machine_backups_failed;
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Harness {
    pub harness: String,
    pub finished: u64,
    pub failed: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Incident {
    pub id: String,
    pub impact: String,
    pub posted_at: i64,
    pub resolved_at: Option<i64>,
    /// From the first post to resolved, or to now while open.
    pub minutes: i64,
    pub reviewed: bool,
}

impl Incident {
    /// Of an impact whose incidents need a review, with none drafted.
    pub fn needs_review(&self) -> bool {
        REVIEWED_IMPACTS.contains(&self.impact.as_str()) && !self.reviewed
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Adoption {
    pub people: u64,
    pub active: u64,
    /// The license's seats, when there is one.
    pub seats_used: Option<u64>,
    pub seat_cap: Option<u64>,
    /// None in testing mode with no license.
    pub license_mode: Option<String>,
    pub license_usable: bool,
    /// When the license ends, unix ms.
    pub license_ends_at: Option<i64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Machines {
    pub restores: usize,
    pub restores_past_rto: usize,
    /// None when the server offers no data regions.
    pub residency_warnings: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Draft {
    pub format: u32,
    pub drafted_at: i64,
    pub template: &'static str,
    /// The first and last months, `YYYY-MM`.
    pub from: String,
    pub to: String,
    pub label: String,
    /// The quarter runs to now.
    pub so_far: bool,
    /// The audit log's retention, when it keeps less than the quarter reaches back.
    pub audit_kept_days: Option<u32>,
    pub history_recording: bool,
    pub version: String,
    /// The data regions offered, when botd runs users' machines.
    pub regions: Vec<String>,
    pub months: Vec<Month>,
    /// `health_history::trend` across the days recorded in the quarter.
    pub trend: Value,
    pub adoption: Adoption,
    /// Most runs first.
    pub harnesses: Vec<Harness>,
    /// Posted in the quarter or still open from before it, oldest first.
    pub incidents: Vec<Incident>,
    /// Days an access review was signed off in the quarter.
    pub access_reviews: Vec<String>,
    /// Successful changes in the quarter, by `CHANGES` kind.
    pub changes: BTreeMap<String, u64>,
    /// The health score's backups summary now.
    pub backups: String,
    /// None when botd runs no users' machines.
    pub machines: Option<Machines>,
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn share(part: u64, whole: u64) -> String {
    (part * 100).checked_div(whole).map_or_else(|| part.to_string(), |pct| format!("{part} ({pct}%)"))
}

fn cell(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|").replace(['\r', '\n'], " ")
}

/// A code, an id or a harness name as botd keeps them, or `[text]`.
fn code(s: &str) -> &str {
    let plain = !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b));
    if plain { s } else { "[text]" }
}

fn date(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%Y-%m-%d").to_string()).unwrap_or_default()
}

fn utc(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default()
}

fn duration(m: i64) -> String {
    match (m / 60, m % 60) {
        (0, m) => format!("{m} min"),
        (h, _) if h >= 48 => format!("{} days {} h", h / 24, h % 24),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

fn band_words(b: &str) -> &str {
    match b {
        "at_risk" => "at risk",
        b => code(b),
    }
}

fn ids(v: &[String]) -> String {
    v.iter().map(|s| format!("`{}`", code(s))).collect::<Vec<_>>().join(", ")
}

/// A recorded day's signals at watch and at risk, in the playbook's order.
pub fn day_score(d: &crate::db::HealthScoreDay) -> DayScore {
    let statuses: BTreeMap<String, String> = serde_json::from_str(&d.signals).unwrap_or_default();
    let with = |want: &str| SIGNALS.iter().filter(|s| statuses.get(s.id).map(String::as_str) == Some(want)).map(|s| s.id.to_string()).collect();
    DayScore { date: d.day.clone(), score: d.score, band: d.band.clone(), at_risk: with("risk"), watch: with("watch") }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|s| s.as_str().map(|s| code(s).to_string())).collect()
}

/// The draft for the quarter ending with `to`, from botd's records as of `now_ms`.
pub fn build(app: &App, a: &Auth, to: Ym, now_ms: i64) -> rusqlite::Result<Draft> {
    let first = to.plus(-2);
    let (start, end) = (first.start_ms(), to.plus(1).start_ms().min(now_ms));
    let history = app.db.health_scores_since(&date(start))?;
    let last_day = date(end - 1);
    let in_quarter: Vec<crate::db::HealthScoreDay> = history.into_iter().filter(|d| d.day <= last_day).collect();

    let months: Vec<Month> = (0..3)
        .map(|n| {
            let ym = first.plus(n);
            let (from, until) = (ym.start_ms(), ym.plus(1).start_ms().min(now_ms));
            let prefix = format!("{}-", ym.id());
            let days: Vec<&crate::db::HealthScoreDay> = in_quarter.iter().filter(|d| d.day.starts_with(&prefix)).collect();
            let checked = Filter { from: Some(from), to: Some(until), actions: vec![crate::health_check::CHECKED.into()], ..Default::default() };
            let checks: u64 = app.db.audit_counts_between(from, until, &[crate::health_check::CHECKED]).iter().map(|c| c.n).sum();
            let last = app.db.audit_events(&checked, 1, false);
            let mut m = Month {
                month: ym.id(),
                so_far: ym.plus(1).start_ms() > now_ms,
                score: days.last().map(|d| day_score(d)),
                days_recorded: days.len(),
                health_checks: checks as usize,
                last_check: last.first().map(|e| Check {
                    date: date(e.at),
                    score: e.details["score"].as_u64().and_then(|s| u32::try_from(s).ok()),
                    band: code(e.details["band"].as_str().unwrap_or("unknown")).to_string(),
                    open: strings(&e.details["open"]),
                }),
                ..Default::default()
            };
            m.count(&app.db.audit_counts_between(from, until, &MONTH_ACTIONS));
            m
        })
        .collect();

    let bots: HashMap<String, String> = app.db.bots().into_iter().map(|b| (b.id, b.harness)).collect();
    let mut by: BTreeMap<String, Harness> = BTreeMap::new();
    for (bot, ran, result, n) in app.db.run_results_by_harness(start, end) {
        // Runs from before botd kept each run's harness fall back to their Bot's harness now.
        let name = ran.or_else(|| bot.and_then(|b| bots.get(&b).cloned())).map_or_else(|| UNRECORDED.to_string(), |h| code(&h).to_string());
        let h = by.entry(name.clone()).or_insert_with(|| Harness { harness: name, ..Default::default() });
        h.finished += n;
        if result.as_deref().is_some_and(|r| RUN_FAILURES.contains(&r)) {
            h.failed += n;
        }
    }
    let mut harnesses: Vec<Harness> = by.into_values().collect();
    harnesses.sort_by(|a, b| b.finished.cmp(&a.finished).then(a.harness.cmp(&b.harness)));

    let posted = app.db.status_incidents_between(start, end)?;
    let reviewed = |id: &str| {
        let f = Filter { from: posted.first().map(|i| i.created_at), actions: vec!["status.incident_reviewed".into()], target_id: Some(id.into()), ..Default::default() };
        !app.db.audit_events(&f, 1, false).is_empty()
    };
    let mut incidents: Vec<Incident> = posted
        .iter()
        .map(|i| Incident {
            id: i.id.clone(),
            impact: i.impact.clone(),
            posted_at: i.created_at,
            resolved_at: i.resolved_at,
            minutes: (i.resolved_at.unwrap_or(now_ms) - i.created_at).max(0) / MINUTE,
            reviewed: reviewed(&i.id),
        })
        .collect();
    incidents.sort_by_key(|i| i.posted_at);

    let access_reviews: Vec<String> = app
        .db
        .audit_events(&Filter { from: Some(start), to: Some(end), actions: vec![crate::access_review::COMPLETED.into()], ..Default::default() }, ALL, true)
        .iter()
        .map(|e| date(e.at))
        .collect();

    let all: Vec<&str> = CHANGES.iter().flat_map(|(_, actions)| actions.iter().copied()).collect();
    let counted = app.db.audit_counts_between(start, end, &all);
    let mut changes: BTreeMap<String, u64> = CHANGES
        .iter()
        .map(|(kind, actions)| (kind.to_string(), counted.iter().filter(|c| c.outcome == "success" && actions.contains(&c.action.as_str())).map(|c| c.n).sum()))
        .collect();
    *changes.entry("roleGrants".into()).or_default() += app.db.built_in_role_changes(start, end);

    let report = health_score::build(app, now_ms, health_score::DEFAULT_DAYS);
    let signal = |id: &str| report["signals"].as_array().into_iter().flatten().find(|s| s["id"] == id).cloned().unwrap_or(Value::Null);
    let (adoption, license, backups) = (signal("adoption"), signal("license"), signal("backups"));
    let lf = &license["facts"];
    let cp = &a.machines;
    let machines = cp.enabled().then(|| {
        let restores = app.db.machine_restores_between(start, end);
        Machines {
            restores: restores.len(),
            restores_past_rto: restores.iter().filter(|r| r.rto_exceeded_at.is_some()).count(),
            residency_warnings: (!cp.regions.is_empty()).then(|| crate::machines::residency::warnings(app, cp).len()),
        }
    });

    Ok(Draft {
        format: FORMAT,
        drafted_at: now_ms,
        template: TEMPLATE,
        from: first.id(),
        to: to.id(),
        label: label(to),
        so_far: to.plus(1).start_ms() > now_ms,
        audit_kept_days: app.db.audit_retention().filter(|d| i64::from(*d) * DAY_MS < now_ms - start),
        history_recording: crate::health_history::recording(),
        version: env!("CARGO_PKG_VERSION").into(),
        regions: if cp.enabled() { cp.regions.iter().map(|r| code(r).to_string()).collect() } else { Vec::new() },
        months,
        trend: crate::health_history::trend(&in_quarter),
        adoption: Adoption {
            people: adoption["facts"]["people"].as_u64().unwrap_or(0),
            active: adoption["facts"]["active"].as_u64().unwrap_or(0),
            seats_used: lf["seatsUsed"].as_u64(),
            seat_cap: lf["seats"].as_u64(),
            license_mode: lf["mode"].as_str().map(|m| code(m).to_string()),
            license_usable: lf["usable"] == true,
            license_ends_at: lf.is_object().then(|| app.license.status_at(now_ms).expires_at()).flatten(),
        },
        harnesses,
        incidents,
        access_reviews,
        changes,
        backups: backups["summary"].as_str().unwrap_or_default().to_string(),
        machines,
    })
}

impl Draft {
    pub fn json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    fn months_ym(&self) -> Vec<Ym> {
        self.months.iter().filter_map(|m| Ym::parse(&m.month)).collect()
    }

    /// A table row with a cell per month.
    fn row(&self, title: &str, f: impl Fn(&Month) -> String) -> String {
        let cells: Vec<String> = self.months.iter().map(|m| cell(&f(m))).collect();
        format!("| {title} | {} |", cells.join(" | "))
    }

    fn header(&self) -> String {
        let names: Vec<String> = self.months.iter().zip(self.months_ym()).map(|(m, ym)| if m.so_far { format!("{} (so far)", ym.short()) } else { ym.short() }).collect();
        format!("| | {} |\n|---|---|---|---|", names.join(" | "))
    }

    /// Each signal at watch or at risk in a month's last recorded score, with those months.
    pub fn flagged(&self) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        for s in &SIGNALS {
            let when: Vec<String> = self
                .months
                .iter()
                .zip(self.months_ym())
                .filter_map(|(m, ym)| {
                    let d = m.score.as_ref()?;
                    let state = if d.at_risk.iter().any(|x| x == s.id) {
                        "at risk"
                    } else if d.watch.iter().any(|x| x == s.id) {
                        "watch"
                    } else {
                        return None;
                    };
                    Some(format!("{state} at the end of {}", ym.short()))
                })
                .collect();
            if !when.is_empty() {
                out.push((s.id.to_string(), when));
            }
        }
        out
    }

    /// What the review asks for, laid out as the template has it, with what botd can't
    /// see left for people.
    pub fn markdown(&self) -> String {
        let mut m = String::new();
        let _ = writeln!(m, "# `<customer>`: business review, {}\n", cell(&self.label));
        let _ = writeln!(
            m,
            "Draft made by botd on {} UTC from its own records, for the [quarterly business review template](https://github.com/CG-Labs/superbot/blob/main/{TEMPLATE}) \
             ([ADR 0262](https://github.com/CG-Labs/superbot/blob/main/docs/adr/0262-business-review-draft.md)). Months are UTC. \
             Replace every \"{TODO}\" before sending, and keep people to their roles: botd names nobody.\n",
            utc(self.drafted_at)
        );
        if self.so_far {
            let _ = writeln!(m, "**The quarter isn't over**: this month's figures run to now. Make the draft again once it ends.\n");
        }
        if let Some(d) = self.audit_kept_days {
            let _ = writeln!(m, "The audit log keeps {d} days (`AUDIT_RETENTION_DAYS`), less than this quarter reaches back, so its earliest months show fewer events than happened.\n");
        }
        let regions = if self.regions.is_empty() { "none offered".to_string() } else { ids(&self.regions) };
        let _ = writeln!(m, "**Attendees:** {TODO} The sponsor, the customer's owner, the TAM, and anyone invited for an agenda item.");
        let _ = writeln!(m, "**Deployment:** {TODO} Managed shared, dedicated, VPC or on-premises; connected or air-gapped. botd {}, data regions {regions}.\n", code(&self.version));

        let _ = writeln!(m, "## 1. Their goals\n");
        let _ = writeln!(m, "{TODO} What they said they wanted at kickoff or the last review, in their words, and where each stands: met, on track, or not yet (and why).\n");
        let _ = writeln!(m, "| Goal | Measure | Last quarter | This quarter |\n|---|---|---|---|\n| {TODO} | | | |\n");

        let _ = writeln!(m, "## 2. Health\n");
        let _ = writeln!(m, "{}", self.header());
        let _ = writeln!(
            m,
            "{}",
            self.row("Health score and band", |mo| match &mo.score {
                Some(d) => format!("{}, {} on {}", d.score.map_or("no score".into(), |s| s.to_string()), band_words(&d.band), &d.date),
                None => "not recorded".into(),
            })
        );
        let _ = writeln!(
            m,
            "{}",
            self.row("Signals at watch or at risk", |mo| match &mo.score {
                None => "-".into(),
                Some(d) if d.at_risk.is_empty() && d.watch.is_empty() => "none".into(),
                Some(d) => {
                    let mut parts = Vec::new();
                    if !d.at_risk.is_empty() {
                        parts.push(format!("at risk: {}", ids(&d.at_risk)));
                    }
                    if !d.watch.is_empty() {
                        parts.push(format!("watch: {}", ids(&d.watch)));
                    }
                    parts.join("; ")
                }
            })
        );
        let _ = writeln!(
            m,
            "{}",
            self.row("Monthly health checks", |mo| match (&mo.last_check, mo.health_checks) {
                (None, _) => "none".into(),
                (Some(c), n) => {
                    let score = c.score.map_or("no score".into(), |s| format!("score {s}"));
                    let open = if c.open.is_empty() { "nothing open".to_string() } else { format!("open: {}", ids(&c.open)) };
                    format!("{n}; the last on {}: {score}, {open}", c.date)
                }
            })
        );
        let _ = writeln!(m);
        if !self.history_recording {
            let _ = writeln!(m, "botd doesn't record the score (`HEALTH_SCORE_HISTORY_DAYS=0`): take each month's from the health checks' records.\n");
        }
        let t = &self.trend;
        if t.is_null() {
            let _ = writeln!(m, "botd recorded too few days this quarter for a trend: `botctl health-score history --days 90`.\n");
        } else {
            let score = |v: &Value| v.as_u64().map_or("no score".to_string(), |s| s.to_string());
            let list = |v: &Value| ids(&strings(v));
            let mut moved = format!(
                "Over the quarter the score went from {} on {} to {} on {}",
                score(&t["fromScore"]),
                code(t["from"].as_str().unwrap_or_default()),
                score(&t["toScore"]),
                code(t["to"].as_str().unwrap_or_default())
            );
            if t["worse"].as_array().is_some_and(|w| !w.is_empty()) {
                moved.push_str(&format!("; worse: {}", list(&t["worse"])));
            }
            if t["better"].as_array().is_some_and(|w| !w.is_empty()) {
                moved.push_str(&format!("; better: {}", list(&t["better"])));
            }
            let _ = writeln!(m, "{moved}. Day by day: `botctl health-score history --days 90`.\n");
        }
        let flagged = self.flagged();
        if flagged.is_empty() {
            let _ = writeln!(m, "No signal was at watch or at risk at the end of a month.\n");
        } else {
            let _ = writeln!(m, "For each signal at watch or at risk this quarter, what was done, and whether it's fixed ([the signals](https://github.com/CG-Labs/superbot/blob/main/docs/support/health-score.md#the-signals)):\n");
            for (id, when) in &flagged {
                let _ = writeln!(m, "- `{id}`: {}. {TODO}", when.join(", "));
            }
            let _ = writeln!(m);
        }

        let _ = writeln!(m, "## 3. Adoption and usage\n");
        let a = &self.adoption;
        let seats = match (a.seats_used, a.seat_cap) {
            (Some(used), Some(cap)) => format!("; {used} of {cap} licensed seats in use"),
            (Some(used), None) => format!("; {}, no seat limit", plural(used, "seat in use", "seats in use")),
            _ => String::new(),
        };
        let _ = writeln!(m, "- Now: {} of {} signed in or used SuperBot in the last 30 days{seats}. {TODO} Against seats bought.", a.active, plural(a.people, "person", "people"));
        let _ = writeln!(m, "\n{}", self.header());
        let _ = writeln!(m, "{}", self.row("Bot runs finished", |mo| mo.runs_finished.to_string()));
        let _ = writeln!(m, "{}", self.row("Failed or timed out", |mo| share(mo.runs_failed, mo.runs_finished)));
        let _ = writeln!(m, "{}", self.row("Refused at a plan's limit", |mo| mo.refused_at_limit.to_string()));
        let _ = writeln!(m, "{}", self.row("Monthly token limit reached", |mo| mo.token_limits_reached.to_string()));
        if self.machines.is_some() {
            let _ = writeln!(m, "{}", self.row("Held to run limits", |mo| mo.run_limited.to_string()));
        }
        let _ = writeln!(m);
        if self.harnesses.is_empty() {
            let _ = writeln!(m, "- No Bot run finished this quarter.");
        } else {
            let by: Vec<String> = self
                .harnesses
                .iter()
                .map(|h| {
                    let name = if h.harness == UNRECORDED { "Deleted Bots, harness not recorded:".to_string() } else { format!("`{}`", code(&h.harness)) };
                    format!("{name} {}, {} failed or timed out", plural(h.finished, "run", "runs"), share(h.failed, h.finished))
                })
                .collect();
            let _ = writeln!(m, "- By harness, over the quarter: {}.", by.join("; "));
        }
        let _ = writeln!(m, "- Usage against the plan's limits, and who was at a limit: `botctl usage`.");
        let _ = writeln!(m, "- {TODO} Teams or uses that grew, and ones that stopped.\n");

        let _ = writeln!(m, "## 4. Support and incidents\n");
        let _ = writeln!(
            m,
            "- Tickets by severity, and response targets met and missed: botd can't see the ticket system. Run `botctl support-report <export> --customer \"<customer>\" --from {} --to {} --markdown` on its export, with the customer's agreed `--target`s, and paste it here.",
            self.from, self.to
        );
        if self.incidents.is_empty() {
            let _ = writeln!(m, "- No status page incident this quarter.");
        } else {
            let _ = writeln!(m, "- Status page incidents this quarter (UTC):\n");
            let _ = writeln!(m, "| Incident | Impact | Posted | Resolved | Duration | Review drafted |\n|---|---|---|---|---|---|");
            for i in &self.incidents {
                let resolved = i.resolved_at.map_or("still open".to_string(), utc);
                let review = match (i.reviewed, REVIEWED_IMPACTS.contains(&i.impact.as_str())) {
                    (true, _) => "yes".to_string(),
                    (false, true) => format!("**no**: `botctl incident review {}`", code(&i.id)),
                    (false, false) => "no".to_string(),
                };
                let _ = writeln!(m, "| `{}` | {} | {} | {resolved} | {} | {review} |", code(&i.id), code(&i.impact), utc(i.posted_at), duration(i.minutes));
            }
            let _ = writeln!(m);
        }
        let _ = writeln!(m, "- {TODO} For each Severity 1 and 2: the ticket, the cause, and the review's actions with their state. Tickets on the same thing more than once, and what would stop them.\n");

        let _ = writeln!(m, "## 5. Security, compliance and data\n");
        match self.access_reviews.as_slice() {
            [] => _ = writeln!(m, "- Access review: none signed off this quarter. If their policy asks for one each quarter, it's due."),
            days => _ = writeln!(m, "- Access review signed off on {}.", days.join(", ")),
        }
        let n = |k: &str| self.changes.get(k).copied().unwrap_or(0);
        let _ = writeln!(
            m,
            "- Changes this quarter: {} to native SAML, {} to SCIM tokens, {} to custom roles, {}, {} to residency pins. `botctl audit --from {} --to {}` lists them.",
            n("saml"),
            n("scimTokens"),
            n("customRoles"),
            plural(n("roleGrants"), "role given or taken away", "roles given or taken away"),
            n("residencyPins"),
            self.from.clone() + "-01",
            self.months_ym().last().map_or(String::new(), |ym| date(ym.plus(1).start_ms() - DAY_MS))
        );
        let _ = writeln!(m, "\n{}", self.header());
        let _ = writeln!(m, "{}", self.row("Single sign-on attempts failed", |mo| format!("{} of {}", share(mo.sso_failed, mo.sso_attempts), mo.sso_attempts)));
        let _ = writeln!(m, "{}", self.row("SCIM requests failed", |mo| mo.scim_failed.to_string()));
        let _ = writeln!(m, "{}", self.row("Approvals expired unanswered", |mo| format!("{} of {}", share(mo.approvals_expired, mo.approvals_requested), mo.approvals_requested)));
        if self.machines.is_some() {
            let _ = writeln!(m, "{}", self.row("Machine backups failed", |mo| mo.machine_backups_failed.to_string()));
        }
        let _ = writeln!(m, "{}", self.row("Refused to keep data in its region", |mo| mo.residency_refusals.to_string()));
        let _ = writeln!(m);
        if !self.backups.is_empty() {
            let _ = writeln!(m, "- Backups now: {}", cell(&self.backups));
        }
        if let Some(ma) = &self.machines {
            let _ = writeln!(m, "- Machine restores this quarter: {}, {} past the RTO.", ma.restores, ma.restores_past_rto);
            if let Some(w) = ma.residency_warnings {
                let _ = writeln!(m, "- Residency warnings now: {w} (`botctl regions`).");
            }
        }
        let _ = writeln!(m, "- {TODO} The last restore drill and its times against the RTO; changes to the security pack, DPA or subprocessors they were told about.\n");

        let _ = writeln!(m, "## 6. What's next\n");
        let _ = writeln!(m, "- botd {} now. {TODO} Releases since the last review that matter to them, and the next upgrade window.", code(&self.version));
        match (a.license_mode.as_deref(), a.license_ends_at) {
            (None, _) => {}
            (Some(mode), _) if !a.license_usable => _ = writeln!(m, "- There's no usable license ({mode}), so Bots don't run: `botctl license`."),
            (Some("grace"), _) => _ = writeln!(m, "- The license has ended and is in its grace period: the renewal is with the account owner."),
            (Some(_), Some(end)) if end > self.drafted_at => {
                let days = (end - self.drafted_at).div_euclid(DAY_MS);
                let _ = writeln!(m, "- The license ends in {}, on {}.", plural(days as u64, "day", "days"), date(end));
            }
            (Some(_), Some(_)) => _ = writeln!(m, "- The license has ended."),
            (Some("active"), None) => _ = writeln!(m, "- The license doesn't end."),
            (Some(_), None) => {}
        }
        let _ = writeln!(m, "- {TODO} Roadmap items they asked for, with what the Provider can say about them (no dates that aren't committed).");
        let _ = writeln!(m, "- {TODO} Their plans for next quarter: new teams, regions, identity provider or network changes, renewals and seats.\n");

        let _ = writeln!(m, "## 7. Actions\n");
        let _ = writeln!(m, "| Action | Owner | Due |\n|---|---|---|");
        if let Some(last) = self.months.last().and_then(|mo| mo.score.as_ref()) {
            for id in last.at_risk.iter().chain(last.watch.iter()) {
                let state = if last.at_risk.contains(id) { "at risk" } else { "at watch" };
                let _ = writeln!(m, "| Act on the `{}` signal, {state} at the quarter's end | {TODO} | |", code(id));
            }
        }
        for i in &self.incidents {
            if i.resolved_at.is_none() {
                let _ = writeln!(m, "| Resolve incident `{}`, still open | {TODO} | |", code(&i.id));
            }
            if i.needs_review() {
                let _ = writeln!(m, "| Draft and hold the review of incident `{}` | {TODO} | |", code(&i.id));
            }
        }
        let _ = writeln!(m, "| {TODO} | | |");
        let _ = writeln!(m, "\nSend the filled-in review and its actions to the attendees within 3 business days, and put the actions in the support system with their owners.");
        m
    }

    /// What `support.business_review_drafted` records: the months and counts only.
    pub fn audit_details(&self, format: Format) -> Value {
        json!({
            "from": self.from,
            "to": self.to,
            "soFar": self.so_far,
            "format": if format == Format::Markdown { "markdown" } else { "json" },
            "incidents": self.incidents.len(),
            "healthChecks": self.months.iter().map(|m| m.health_checks).sum::<usize>(),
        })
    }
}

/// `GET /api/support/business-review[?to=YYYY-MM&format=markdown]` (admins). Audited,
/// so the quarterly reviews show in the log.
pub async fn get(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Query(q): Query<HashMap<String, String>>) -> Res<Response> {
    let now_ms = crate::db::now();
    let (to, format) = parse_query(&q, now_ms).map_err(bad)?;
    let d = {
        let app = app.clone();
        tokio::task::spawn_blocking(move || build(&app, &a, to, now_ms))
            .await
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't draft the business review: {e}")))?
            // A record botd can't read isn't one it doesn't have: no draft, rather than one saying "none".
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't read botd's records for the business review: {e}")))?
    };
    app.db.record(&by.event(DRAFTED).target("setup", "server").details(d.audit_details(format)));
    if format == Format::Json {
        return Ok(Json(d.json()).into_response());
    }
    let mut res = d.markdown().into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/markdown; charset=utf-8"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"business-review-{}-to-{}.md\"", d.from, d.to)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-24T22:00:00Z.
    const NOW: i64 = 1_795_557_600_000;

    fn ym(s: &str) -> Ym {
        Ym::parse(s).unwrap()
    }

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn count(action: &str, outcome: &str, method: Option<&str>, code: Option<&str>, n: u64) -> AuditCount {
        AuditCount { action: action.into(), outcome: outcome.into(), method: method.map(String::from), code: code.map(String::from), n, skipped: 0 }
    }

    fn day(date: &str, score: u32, band: &str, at_risk: &[&str], watch: &[&str]) -> DayScore {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect();
        DayScore { date: date.into(), score: Some(score), band: band.into(), at_risk: v(at_risk), watch: v(watch) }
    }

    /// A quarter with a little of everything: a signal that went to watch and came back, a
    /// health check each month, one reviewed major incident and one unreviewed, machines.
    fn draft() -> Draft {
        let month = |id: &str, score: Option<DayScore>, runs: u64, failed: u64| Month {
            month: id.into(),
            score,
            days_recorded: 30,
            health_checks: 1,
            last_check: Some(Check { date: format!("{id}-03"), score: Some(88), band: "healthy".into(), open: Vec::new() }),
            runs_finished: runs,
            runs_failed: failed,
            sso_attempts: 100,
            sso_failed: 2,
            approvals_requested: 40,
            approvals_expired: 1,
            ..Default::default()
        };
        let mut months = vec![
            month("2026-08", Some(day("2026-08-31", 90, "healthy", &[], &[])), 200, 4),
            month("2026-09", Some(day("2026-09-30", 70, "watch", &[], &["runs"])), 210, 20),
            month("2026-10", Some(day("2026-10-31", 64, "watch", &["backups"], &[])), 220, 5),
        ];
        months[1].last_check = Some(Check { date: "2026-09-02".into(), score: Some(70), band: "watch".into(), open: vec!["runs".into(), "setup".into()] });
        months[2].refused_at_limit = 3;
        Draft {
            format: FORMAT,
            drafted_at: NOW,
            template: TEMPLATE,
            from: "2026-08".into(),
            to: "2026-10".into(),
            label: label(ym("2026-10")),
            history_recording: true,
            version: "0.1.0".into(),
            regions: vec!["uk".into(), "eu".into()],
            months,
            trend: json!({ "from": "2026-08-01", "to": "2026-10-31", "fromScore": 92, "toScore": 64, "worse": ["backups"], "better": [] }),
            adoption: Adoption {
                people: 40,
                active: 31,
                seats_used: Some(40),
                seat_cap: Some(60),
                license_mode: Some("active".into()),
                license_usable: true,
                license_ends_at: Some(NOW + 200 * DAY_MS + 3 * 3_600_000),
            },
            harnesses: vec![Harness { harness: "hermes".into(), finished: 500, failed: 25 }, Harness { harness: "claude".into(), finished: 130, failed: 4 }],
            incidents: vec![
                Incident { id: "inc_a1".into(), impact: "major".into(), posted_at: NOW - 60 * DAY_MS, resolved_at: Some(NOW - 60 * DAY_MS + 95 * MINUTE), minutes: 95, reviewed: true },
                Incident { id: "inc_b2".into(), impact: "critical".into(), posted_at: NOW - 40 * DAY_MS, resolved_at: Some(NOW - 40 * DAY_MS + 30 * MINUTE), minutes: 30, reviewed: false },
            ],
            access_reviews: vec!["2026-09-14".into()],
            changes: [("saml", 2), ("scimTokens", 1), ("customRoles", 0), ("roleGrants", 4), ("residencyPins", 0)].into_iter().map(|(k, n)| (k.to_string(), n)).collect(),
            backups: "The newest server backup off the host is 3 hours old, within its RPO of 26 hours.".into(),
            machines: Some(Machines { restores: 2, restores_past_rto: 1, residency_warnings: Some(0) }),
            ..Default::default()
        }
    }

    #[test]
    fn months_parse_add_and_name() {
        assert_eq!(ym("2026-11"), Ym { y: 2026, m: 11 });
        for bad in ["2026-13", "2026-00", "1999-12", "2026-1", "26-11", "2026/11", "2026-11-01", "-2026-1", ""] {
            assert_eq!(Ym::parse(bad), None, "{bad}");
        }
        assert_eq!((ym("2026-01").plus(-2).id(), ym("2026-11").plus(2).id(), ym("2026-12").plus(1).id()), ("2025-11".into(), "2027-01".into(), "2027-01".into()));
        assert_eq!(Ym::of_ms(NOW), ym("2026-11"));
        assert_eq!(ym("2026-11").start_ms(), 1_793_491_200_000, "2026-11-01T00:00:00Z");
        assert_eq!(ym("2026-08").short(), "Aug 2026");
        assert_eq!(label(ym("2026-09")), "Q3 2026 (July to September)");
        assert_eq!(label(ym("2026-12")), "Q4 2026 (October to December)");
        assert_eq!(label(ym("2026-10")), "August to October 2026");
        assert_eq!(label(ym("2027-01")), "November 2026 to January 2027");
    }

    #[test]
    fn the_query_takes_a_month_and_a_format() {
        assert_eq!(parse_query(&q(&[]), NOW), Ok((ym("2026-10"), Format::Json)), "the last whole month by default");
        assert_eq!(parse_query(&q(&[("to", "2026-11"), ("format", "markdown")]), NOW), Ok((ym("2026-11"), Format::Markdown)), "this month, so far");
        assert_eq!(parse_query(&q(&[("to", "2025-03"), ("format", "md")]), NOW), Ok((ym("2025-03"), Format::Markdown)));
        assert!(parse_query(&q(&[("to", "2026-12")]), NOW).unwrap_err().starts_with("to can't be after this month (2026-11)"));
        assert_eq!(parse_query(&q(&[("to", "last quarter")]), NOW), Err("to must be a month, YYYY-MM".into()));
        assert_eq!(parse_query(&q(&[("format", "pdf")]), NOW), Err("format must be json or markdown".into()));
        assert!(parse_query(&q(&[("days", "90")]), NOW).unwrap_err().starts_with("Unknown parameter \"days\""));
        assert!(parse_query(&q(&[("jane@example.com", "1")]), NOW).unwrap_err().contains("\"[text]\""), "a typed address is never echoed");
    }

    #[test]
    fn a_month_reads_its_counts_as_the_health_score_does() {
        let mut m = Month::default();
        m.count(&[
            count("bot.run_finished", "success", None, Some("done"), 90),
            count("bot.run_finished", "failure", None, Some("error"), 6),
            count("bot.run_finished", "failure", None, Some("timeout"), 4),
            count("bot.run_refused", "denied", None, Some("tier_limit"), 3),
            count("bot.run_refused", "denied", None, Some("storage_limit"), 1),
            count("bot.run_refused", "denied", None, Some("residency_pinned"), 2),
            count("bot.run_refused", "denied", None, Some("egress_policy_pending"), 5),
            count("machine.residency_refused", "denied", None, Some("residency_pinned"), 1),
            count("machine.run_limited", "denied", None, None, 7),
            count("usage.token_limit_reached", "success", None, None, 2),
            count("auth.login", "success", Some("sso"), None, 95),
            count("auth.login", "success", Some("password"), None, 50),
            count("auth.login_failed", "failure", Some("sso"), Some("not_linked"), 5),
            count("scim.request_failed", "failure", None, Some("uniqueness"), 2),
            count("scim.auth_failed", "failure", None, Some("revoked"), 1),
            count("scim.auth_failed", "failure", None, Some("unknown"), 40),
            count("approval.requested", "success", None, None, 20),
            count("approval.expired", "failure", None, None, 3),
            count("machine.backup_failed", "failure", None, None, 1),
        ]);
        assert_eq!((m.runs_finished, m.runs_failed, m.refused_at_limit, m.run_limited, m.token_limits_reached), (100, 10, 4, 7, 2));
        assert_eq!((m.sso_attempts, m.sso_failed), (100, 5), "password sign-ins aren't single sign-on");
        assert_eq!(m.scim_failed, 3, "an unknown token is anyone's guess, so it isn't the customer's failure");
        assert_eq!((m.approvals_requested, m.approvals_expired, m.machine_backups_failed, m.residency_refusals), (20, 3, 1, 3));
    }

    #[test]
    fn a_recorded_day_keeps_its_signals_in_the_playbooks_order() {
        let d = crate::db::HealthScoreDay {
            day: "2026-10-31".into(),
            at: NOW,
            window_days: 30,
            score: Some(55),
            band: "watch".into(),
            signals: r#"{"runs":"watch","backups":"risk","adoption":"watch","license":"ok","identity":"n/a"}"#.into(),
        };
        assert_eq!(day_score(&d), day("2026-10-31", 55, "watch", &["backups"], &["adoption", "runs"]));
    }

    #[test]
    fn signals_flagged_at_a_months_end_are_listed_with_the_months() {
        let d = draft();
        assert_eq!(d.flagged(), [("runs".to_string(), vec!["watch at the end of Sep 2026".to_string()]), ("backups".to_string(), vec!["at risk at the end of Oct 2026".to_string()])]);
    }

    #[test]
    fn the_draft_follows_the_template() {
        let md = draft().markdown();
        let headings: Vec<&str> = md.lines().filter(|l| l.starts_with("## ")).collect();
        assert_eq!(headings, ["## 1. Their goals", "## 2. Health", "## 3. Adoption and usage", "## 4. Support and incidents", "## 5. Security, compliance and data", "## 6. What's next", "## 7. Actions"]);
        assert!(md.starts_with("# `<customer>`: business review, August to October 2026\n"), "{md}");
        for want in [
            "botd 0.1.0, data regions `uk`, `eu`.",
            "| | Aug 2026 | Sep 2026 | Oct 2026 |",
            "| Health score and band | 90, healthy on 2026-08-31 | 70, watch on 2026-09-30 | 64, watch on 2026-10-31 |",
            "| Signals at watch or at risk | none | watch: `runs` | at risk: `backups` |",
            "| Monthly health checks | 1; the last on 2026-08-03: score 88, nothing open | 1; the last on 2026-09-02: score 70, open: `runs`, `setup` | 1; the last on 2026-10-03: score 88, nothing open |",
            "Over the quarter the score went from 92 on 2026-08-01 to 64 on 2026-10-31; worse: `backups`.",
            "- `runs`: watch at the end of Sep 2026. _To fill in._",
            "- Now: 31 of 40 people signed in or used SuperBot in the last 30 days; 40 of 60 licensed seats in use.",
            "| Failed or timed out | 4 (2%) | 20 (9%) | 5 (2%) |",
            "| Refused at a plan's limit | 0 | 0 | 3 |",
            "| Held to run limits | 0 | 0 | 0 |",
            "- By harness, over the quarter: `hermes` 500 runs, 25 (5%) failed or timed out; `claude` 130 runs, 4 (3%) failed or timed out.",
            "`botctl support-report <export> --customer \"<customer>\" --from 2026-08 --to 2026-10 --markdown`",
            "| `inc_a1` | major |",
            "| 1 h 35 min | yes |",
            "| 30 min | **no**: `botctl incident review inc_b2` |",
            "- Access review signed off on 2026-09-14.",
            "- Changes this quarter: 2 to native SAML, 1 to SCIM tokens, 0 to custom roles, 4 roles given or taken away, 0 to residency pins. `botctl audit --from 2026-08-01 --to 2026-10-31` lists them.",
            "| Single sign-on attempts failed | 2 (2%) of 100 | 2 (2%) of 100 | 2 (2%) of 100 |",
            "| Machine backups failed | 0 | 0 | 0 |",
            "- Backups now: The newest server backup off the host is 3 hours old",
            "- Machine restores this quarter: 2, 1 past the RTO.",
            "- Residency warnings now: 0 (`botctl regions`).",
            "- The license ends in 200 days, on 2027-06-13.",
            "| Act on the `backups` signal, at risk at the quarter's end | _To fill in._ | |",
            "| Draft and hold the review of incident `inc_b2` | _To fill in._ | |",
        ] {
            assert!(md.contains(want), "no {want:?} in:\n{md}");
        }
        assert!(!md.contains("review of incident `inc_a1`"), "a reviewed incident needs no action");
        assert!(!md.contains("isn't over"), "a whole quarter");
    }

    #[test]
    fn a_quarter_so_far_and_an_empty_server_say_so() {
        let mut d = Draft {
            from: "2026-09".into(),
            to: "2026-11".into(),
            label: label(ym("2026-11")),
            so_far: true,
            audit_kept_days: Some(30),
            months: ["2026-09", "2026-10", "2026-11"].iter().map(|m| Month { month: m.to_string(), so_far: *m == "2026-11", ..Default::default() }).collect(),
            trend: Value::Null,
            ..Default::default()
        };
        let md = d.markdown();
        for want in [
            "**The quarter isn't over**",
            "The audit log keeps 30 days",
            "botd doesn't record the score (`HEALTH_SCORE_HISTORY_DAYS=0`)",
            "| | Sep 2026 | Oct 2026 | Nov 2026 (so far) |",
            "| Health score and band | not recorded | not recorded | not recorded |",
            "| Monthly health checks | none | none | none |",
            "botd recorded too few days this quarter for a trend",
            "No signal was at watch or at risk at the end of a month.",
            "data regions none offered",
            "- No Bot run finished this quarter.",
            "- No status page incident this quarter.",
            "- Access review: none signed off this quarter.",
            "| Failed or timed out | 0 | 0 | 0 |",
        ] {
            assert!(md.contains(want), "no {want:?} in:\n{md}");
        }
        for absent in ["Held to run limits", "Machine backups failed", "Machine restores", "The license", "Backups now"] {
            assert!(!md.contains(absent), "{absent} without machines, a license or a backups summary:\n{md}");
        }
        assert!(md.ends_with("| _To fill in._ | | |\n\nSend the filled-in review and its actions to the attendees within 3 business days, and put the actions in the support system with their owners.\n"));
        d.incidents = vec![Incident { id: "inc_c3".into(), impact: "minor".into(), posted_at: NOW - DAY_MS, resolved_at: None, minutes: 1440, reviewed: false }];
        let md = d.markdown();
        assert!(md.contains("| still open | 24 h | no |"), "{md}");
        assert!(md.contains("| Resolve incident `inc_c3`, still open |"), "{md}");
        assert!(!md.contains("review of incident `inc_c3`"), "a minor incident needs no review");
    }

    #[test]
    fn text_from_records_cant_break_the_markdown() {
        let mut d = draft();
        d.harnesses[0].harness = "evil | ![x](https://e.example/a@b)".into();
        d.incidents[0].id = "inc_1 | <script>".into();
        d.regions = vec!["uk\n# heading".into()];
        d.backups = "a | b\nc".into();
        let md = d.markdown();
        for leak in ["e.example", "<script>", "\n# heading", "a | b"] {
            assert!(!md.contains(leak), "{leak} in:\n{md}");
        }
        assert!(md.contains("`[text]` 500 runs") && md.contains("data regions `[text]`") && md.contains("- Backups now: a \\| b c"), "{md}");
    }

    #[test]
    fn the_json_and_audit_hold_months_ids_and_counts() {
        let d = draft();
        let v = d.json();
        assert_eq!((v["format"].clone(), v["from"].clone(), v["to"].clone(), v["template"].clone()), (json!(FORMAT), json!("2026-08"), json!("2026-10"), json!(TEMPLATE)));
        assert_eq!(v["months"].as_array().unwrap().len(), 3);
        assert_eq!(v["months"][1]["lastCheck"]["open"], json!(["runs", "setup"]));
        assert_eq!(v["incidents"][1], json!({ "id": "inc_b2", "impact": "critical", "postedAt": NOW - 40 * DAY_MS, "resolvedAt": NOW - 40 * DAY_MS + 30 * MINUTE, "minutes": 30, "reviewed": false }));
        assert_eq!(d.audit_details(Format::Markdown), json!({ "from": "2026-08", "to": "2026-10", "soFar": false, "format": "markdown", "incidents": 2, "healthChecks": 3 }));
        let text = v.to_string() + &d.markdown();
        for leak in ["@", "s3://", "http://"] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
    }

    #[test]
    fn the_license_line_says_what_the_license_is() {
        let line = |mode: Option<&str>, usable: bool, ends_at: Option<i64>| {
            let mut d = draft();
            d.adoption.license_mode = mode.map(String::from);
            d.adoption.license_usable = usable;
            d.adoption.license_ends_at = ends_at;
            d.markdown().lines().find(|l| l.contains("license") && l.starts_with("- ") && !l.contains("seats")).map(String::from)
        };
        assert_eq!(line(Some("active"), true, Some(NOW + 2 * 3_600_000)).as_deref(), Some("- The license ends in 0 days, on 2026-11-25."), "the day it ends, not the days left from today");
        assert_eq!(line(Some("active"), true, None).as_deref(), Some("- The license doesn't end."));
        assert_eq!(line(Some("grace"), true, Some(NOW - DAY_MS)).as_deref(), Some("- The license has ended and is in its grace period: the renewal is with the account owner."));
        for mode in ["unlicensed", "expired", "invalid"] {
            assert_eq!(line(Some(mode), false, None), Some(format!("- There's no usable license ({mode}), so Bots don't run: `botctl license`.")), "{mode} never reads as a license that doesn't end");
        }
        assert_eq!(line(None, true, None), None, "testing mode with no license");
    }

    #[test]
    fn runs_with_no_harness_left_to_name_say_so() {
        let mut d = draft();
        d.harnesses.push(Harness { harness: UNRECORDED.into(), finished: 3, failed: 1 });
        let md = d.markdown();
        assert!(md.contains("; Deleted Bots, harness not recorded: 3 runs, 1 (33%) failed or timed out."), "{md}");
        assert!(!md.contains("[text]"), "{md}");
    }

    /// Each section of the draft is a section of the template, in its order.
    #[test]
    fn the_sections_are_the_templates() {
        let template = include_str!("../../docs/support/qbr-template.md");
        let theirs: Vec<String> = template.lines().filter_map(|l| l.strip_prefix("### ")).filter(|l| l.chars().next().is_some_and(|c| c.is_ascii_digit())).map(String::from).collect();
        let md = draft().markdown();
        let ours: Vec<String> = md.lines().filter_map(|l| l.strip_prefix("## ")).map(String::from).collect();
        assert_eq!(ours, theirs);
    }
}
