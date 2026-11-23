//! Incident reviews (ADR 0201): a draft of the review the incident commander writes after
//! a Severity 1 (docs/support/escalation.md), from what botd already recorded. It lays the
//! status page's public timeline beside botd's own: restarts and configuration changes
//! before and during the incident, runs, sign-ins and denials while it lasted against the
//! same time just before, and whether the status page's targets were kept (posted within
//! 15 minutes of detection, updated at least hourly). Cause, impact, lessons and actions
//! are left for people to write.
//!
//! `GET /api/status/incidents/{id}/review` (admins, like every `/api/status` route) as
//! JSON, or as Markdown with `?format=markdown`. Like the support bundle, it never names
//! anyone: actors are kinds (user, bot, system), targets are types, and the only free text
//! is what admins posted for the public.

use crate::audit::{self, Who};
use crate::db::{AuditEvent, StatusIncident};
use crate::runner::App;
use crate::{ApiError, AppState, Res, bad, not_found};
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

/// Bumped when the JSON's shape changes.
pub const FORMAT: u32 = 1;
pub const DEFAULT_LEAD_HOURS: i64 = 24;
pub const MAX_LEAD_HOURS: i64 = 168;
/// The SLO's status page targets (docs/slo.md#status-page-and-incidents).
pub const POST_WITHIN_MINUTES: i64 = 15;
pub const UPDATE_EVERY_MINUTES: i64 = 60;
/// Events read for each of the lead-in and the incident itself.
const AUDIT_SCAN: i64 = 20_000;
/// Changes listed, those nearest the start first.
const CHANGES_SHOWN: usize = 50;
const FAILURES_SHOWN: usize = 10;
const MINUTE: i64 = 60_000;

/// Successful actions that change how botd behaves, as the timeline lists them. A
/// trailing `*` matches a prefix, only for prefixes with no routine traffic under them:
/// `policy.allowed` is every auto-approved tool call and `sso.saml_role_skipped` a
/// sign-in, so those families are listed one by one.
pub const CHANGES: [&str; 29] = [
    "server.started",
    "policy.updated",
    "policy.reset",
    "policy.initialized",
    "policy.sandbox_initialized",
    "rule.*",
    "role.*",
    "sso.saml_metadata_imported",
    "sso.saml_role_mapped",
    "sso.saml_role_unmapped",
    "sso.saml_sp_key_created",
    "sso.saml_sp_key_promoted",
    "sso.saml_sp_key_retired",
    "auth.mfa_policy_updated",
    "license.installed",
    "license.removed",
    "notifications.updated",
    "server.egress_policy_changed",
    "user.egress_policy_changed",
    "setup.*",
    "tier.*",
    "scim.token_*",
    "service_token.*",
    "secret.set",
    "secret.deleted",
    "billing.email_settings_updated",
    "user.role_changed",
    "user.tier_changed",
    "bot.updated",
];

fn is_change(action: &str) -> bool {
    CHANGES.iter().any(|c| match c.strip_suffix('*') {
        Some(prefix) => action.starts_with(prefix),
        None => action == *c,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opts {
    pub lead_hours: i64,
    pub detected: Option<i64>,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts { lead_hours: DEFAULT_LEAD_HOURS, detected: None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Markdown,
}

/// `?lead=<hours>&detected=<time>&format=json|markdown`.
pub fn parse_query(q: &HashMap<String, String>) -> Result<(Opts, Format), String> {
    let get = |k: &str| q.get(k).map(|v| v.trim()).filter(|v| !v.is_empty());
    let lead_hours = match get("lead") {
        None => DEFAULT_LEAD_HOURS,
        Some(v) => v.parse::<i64>().ok().filter(|h| (1..=MAX_LEAD_HOURS).contains(h)).ok_or(format!("lead must be 1 to {MAX_LEAD_HOURS} hours"))?,
    };
    let detected = get("detected").map(|v| audit::parse_time(v, false)).transpose()?;
    let format = match get("format") {
        None | Some("json") => Format::Json,
        Some("markdown" | "md") => Format::Markdown,
        Some(_) => return Err("format must be json or markdown".into()),
    };
    Ok((Opts { lead_hours, detected }, format))
}

/// What botd saw in one stretch of time: counts only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Seen {
    pub minutes: i64,
    pub events: u64,
    pub runs_finished: u64,
    pub runs_failed: u64,
    pub sign_in_failures: u64,
    pub denied: u64,
    pub failures: u64,
}

/// How many events one row stands for: a throttled failure also counts the ones it
/// didn't log since the last (ADR 0144).
fn weight(e: &AuditEvent) -> u64 {
    1 + e.details.get("unloggedSinceLast").and_then(Value::as_u64).unwrap_or(0)
}

impl Seen {
    fn add(&mut self, e: &AuditEvent) {
        let n = weight(e);
        self.events += 1;
        if e.action == "bot.run_finished" {
            self.runs_finished += 1;
            if e.outcome != "success" {
                self.runs_failed += 1;
            }
        }
        if e.action == "auth.login_failed" {
            self.sign_in_failures += n;
        }
        if e.outcome == "denied" {
            self.denied += n;
        }
        if e.outcome != "success" {
            self.failures += n;
        }
    }
}

/// One line of the merged timeline: a status page post, a botd start, or a change.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub at: i64,
    pub time: String,
    /// `status_page`, `botd` (a start) or `change`.
    pub source: &'static str,
    pub state: Option<String>,
    pub body: Option<String>,
    pub action: Option<String>,
    pub actor_kind: Option<String>,
    pub target_type: Option<String>,
    pub version: Option<String>,
    /// For botd's own entries: before the incident started, or while it lasted.
    pub phase: Option<&'static str>,
}

/// A stretch between two status page posts, longer than the update target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Gap {
    pub from: String,
    pub to: String,
    pub minutes: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Targets {
    pub post_within_minutes: i64,
    /// From detection to the first post, when the detection time was given.
    pub posted_after_minutes: Option<i64>,
    pub posted_late: Option<bool>,
    /// None for maintenance, which the SLO's hourly updates don't cover.
    pub update_every_minutes: Option<i64>,
    pub longest_gap_minutes: i64,
    pub late_updates: Vec<Gap>,
    pub to_identified_minutes: Option<i64>,
    pub to_monitoring_minutes: Option<i64>,
    pub to_resolved_minutes: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureCount {
    pub action: String,
    pub outcome: String,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    pub format: u32,
    pub created_at: String,
    pub incident: Value,
    pub detected_at: Option<String>,
    pub started_at: String,
    pub ended_at: String,
    pub open: bool,
    pub duration_minutes: i64,
    pub lead_hours: i64,
    pub timeline: Vec<Entry>,
    pub changes_before: usize,
    pub changes_during: usize,
    pub changes_not_shown: usize,
    pub targets: Targets,
    pub during: Seen,
    pub before: Seen,
    pub top_failures: Vec<FailureCount>,
    /// The audit log had more events than were read, for the lead-in or the incident.
    pub truncated: bool,
}

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default()
}

fn utc(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default()
}

fn minutes(ms: i64) -> i64 {
    ms.max(0) / MINUTE
}

/// When the incident started for the review: its detection if earlier than its first post.
pub fn start_of(i: &StatusIncident, opts: &Opts) -> i64 {
    opts.detected.map_or(i.created_at, |d| d.min(i.created_at))
}

pub fn end_of(i: &StatusIncident, now_ms: i64) -> i64 {
    i.resolved_at.unwrap_or(now_ms)
}

/// Stretches between posts while the incident was open longer than `every`: from each
/// post to the next, and from the last to `now_ms` while it's still open. Time it spent
/// resolved before being reopened isn't counted. Returns the longest such stretch too.
pub fn gaps(i: &StatusIncident, now_ms: i64, every_ms: i64) -> (i64, Vec<Gap>) {
    let mut posts: Vec<(i64, &str)> = i.updates.iter().map(|u| (u.created_at, u.state.as_str())).collect();
    posts.sort_by_key(|p| p.0);
    if i.resolved_at.is_none() {
        posts.push((now_ms.max(posts.last().map_or(i.created_at, |p| p.0)), "now"));
    }
    let (mut longest, mut late) = (0, Vec::new());
    for w in posts.windows(2) {
        let ((a, state), (b, _)) = (w[0], w[1]);
        if state == "resolved" {
            continue;
        }
        longest = longest.max(b - a);
        if b - a > every_ms {
            late.push(Gap { from: rfc3339(a), to: rfc3339(b), minutes: minutes(b - a) });
        }
    }
    (minutes(longest), late)
}

/// Minutes from `start` to the first post in `state`.
fn first_in(i: &StatusIncident, state: &str, start: i64) -> Option<i64> {
    i.updates.iter().filter(|u| u.state == state).map(|u| u.created_at).min().map(|t| minutes(t - start))
}

pub fn targets(i: &StatusIncident, opts: &Opts, now_ms: i64) -> Targets {
    let start = start_of(i, opts);
    let every = (i.impact != "maintenance").then_some(UPDATE_EVERY_MINUTES);
    let (longest, late) = gaps(i, now_ms, every.unwrap_or(i64::MAX / MINUTE) * MINUTE);
    let posted_after = opts.detected.map(|d| minutes(i.created_at - d));
    Targets {
        post_within_minutes: POST_WITHIN_MINUTES,
        posted_after_minutes: posted_after,
        posted_late: opts.detected.map(|d| i.created_at - d > POST_WITHIN_MINUTES * MINUTE),
        update_every_minutes: every,
        longest_gap_minutes: longest,
        late_updates: late,
        to_identified_minutes: first_in(i, "identified", start),
        to_monitoring_minutes: first_in(i, "monitoring", start),
        to_resolved_minutes: i.resolved_at.map(|r| minutes(r - start)),
    }
}

/// The review, from the incident and botd's audit events `before` its start (newest
/// first, from `lead_hours` before it) and `during` it (oldest first).
pub fn review(i: &StatusIncident, before: &[AuditEvent], during: &[AuditEvent], opts: &Opts, now_ms: i64, truncated: bool) -> Review {
    let start = start_of(i, opts);
    let end = end_of(i, now_ms);
    let length = (end - start).max(0);
    let lead_from = start - opts.lead_hours * 3_600_000;
    let baseline_from = start - length.min(opts.lead_hours * 3_600_000);
    let before: Vec<&AuditEvent> = before.iter().filter(|e| e.at >= lead_from && e.at < start).collect();
    let during: Vec<&AuditEvent> = during.iter().filter(|e| e.at >= start && e.at <= end).collect();

    let mut timeline: Vec<Entry> = i
        .updates
        .iter()
        .map(|u| Entry {
            at: u.created_at,
            time: rfc3339(u.created_at),
            source: "status_page",
            state: Some(u.state.clone()),
            body: Some(u.body.clone()),
            action: None,
            actor_kind: None,
            target_type: None,
            version: None,
            phase: None,
        })
        .collect();

    let mut changes: Vec<Entry> = before
        .iter()
        .chain(&during)
        .filter(|e| e.outcome == "success" && is_change(&e.action))
        .map(|e| {
            let started = e.action == "server.started";
            Entry {
                at: e.at,
                time: rfc3339(e.at),
                source: if started { "botd" } else { "change" },
                state: None,
                body: None,
                action: Some(e.action.clone()),
                actor_kind: Some(e.actor_kind.clone()),
                target_type: e.target_type.clone(),
                version: started.then(|| e.details.get("version").and_then(Value::as_str).map(String::from)).flatten(),
                phase: Some(if e.at < start { "before" } else { "during" }),
            }
        })
        .collect();
    let changes_before = changes.iter().filter(|c| c.phase == Some("before")).count();
    let changes_during = changes.len() - changes_before;
    changes.sort_by_key(|c| ((c.at - start).abs(), c.at));
    let changes_not_shown = changes.len().saturating_sub(CHANGES_SHOWN);
    changes.truncate(CHANGES_SHOWN);
    timeline.extend(changes);
    timeline.sort_by(|a, b| a.at.cmp(&b.at).then((a.source == "status_page").cmp(&(b.source == "status_page"))));

    let mut seen_during = Seen { minutes: minutes(length), ..Default::default() };
    let mut failures: BTreeMap<(String, String), u64> = BTreeMap::new();
    for e in &during {
        seen_during.add(e);
        if e.outcome != "success" {
            *failures.entry((e.action.clone(), e.outcome.clone())).or_default() += weight(e);
        }
    }
    let mut seen_before = Seen { minutes: minutes(start - baseline_from), ..Default::default() };
    for e in before.iter().filter(|e| e.at >= baseline_from) {
        seen_before.add(e);
    }
    let mut top: Vec<FailureCount> = failures.into_iter().map(|((action, outcome), count)| FailureCount { action, outcome, count }).collect();
    top.sort_by(|a, b| b.count.cmp(&a.count).then(a.action.cmp(&b.action)));
    top.truncate(FAILURES_SHOWN);

    let components: Vec<&str> = i.components.iter().map(|c| crate::status::COMPONENTS.iter().find(|(id, _)| id == c).map_or(c.as_str(), |(_, name)| name)).collect();
    Review {
        format: FORMAT,
        created_at: rfc3339(now_ms),
        incident: json!({
            "id": i.id,
            "title": i.title,
            "impact": i.impact,
            "components": components,
            "state": i.state,
            "postedAt": rfc3339(i.created_at),
            "resolvedAt": i.resolved_at.map(rfc3339),
        }),
        detected_at: opts.detected.map(rfc3339),
        started_at: rfc3339(start),
        ended_at: rfc3339(end),
        open: i.resolved_at.is_none(),
        duration_minutes: minutes(length),
        lead_hours: opts.lead_hours,
        timeline,
        changes_before,
        changes_during,
        changes_not_shown,
        targets: targets(i, opts, now_ms),
        during: seen_during,
        before: seen_before,
        top_failures: top,
        truncated,
    }
}

fn duration(m: i64) -> String {
    match (m / 60, m % 60) {
        (0, m) => format!("{m} min"),
        (h, 0) => format!("{h} h"),
        (h, m) => format!("{h} h {m} min"),
    }
}

/// Text safe in one Markdown table cell.
fn cell(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn share(part: u64, whole: u64) -> String {
    (part * 100).checked_div(whole).map_or_else(|| part.to_string(), |pct| format!("{part} ({pct}%)"))
}

const TODO: &str = "_To fill in._";

impl Review {
    pub fn json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// The draft in the shape escalation.md asks for: timeline in UTC, impact, cause,
    /// what went well and badly, and actions with owners.
    pub fn markdown(&self) -> String {
        let i = &self.incident;
        let t = &self.targets;
        let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
        let mut m = String::new();
        let _ = writeln!(m, "# Incident review: {}\n", s(&i["title"]));
        let _ = writeln!(
            m,
            "Draft made by botd on {} UTC from its own records ([ADR 0201](https://github.com/CG-Labs/superbot/blob/main/docs/adr/0201-incident-review-drafts.md)). \
             Replace every \"{TODO}\" before sharing, and keep people to their roles: botd names nobody, and the status page text is what was posted for the public.\n",
            utc(chrono::DateTime::parse_from_rfc3339(&self.created_at).map(|d| d.timestamp_millis()).unwrap_or_default())
        );
        if self.open {
            let _ = writeln!(m, "**The incident is still open**: this draft runs to now. Make it again once it's resolved.\n");
        }
        let at = |v: &str| chrono::DateTime::parse_from_rfc3339(v).map(|d| utc(d.timestamp_millis())).unwrap_or_default();
        let comps = i["components"].as_array().map(|c| c.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).filter(|c| !c.is_empty()).unwrap_or_else(|| "none named".into());
        let _ = writeln!(m, "| | |\n|---|---|");
        let _ = writeln!(m, "| Incident | `{}` |", s(&i["id"]));
        let _ = writeln!(m, "| Severity | {TODO} |");
        let _ = writeln!(m, "| Status page impact | {} |", s(&i["impact"]));
        let _ = writeln!(m, "| Components | {} |", cell(&comps));
        match &self.detected_at {
            Some(d) => _ = writeln!(m, "| Detected | {} UTC |", at(d)),
            None => _ = writeln!(m, "| Detected | {TODO} When the alert fired or the first report came in (`--detected`) |"),
        }
        let _ = writeln!(m, "| Posted | {} UTC |", at(&s(&i["postedAt"])));
        let from = if self.detected_at.is_some() { "detection" } else { "the first post" };
        if let Some(n) = t.to_identified_minutes {
            let _ = writeln!(m, "| Identified | {} after {from} |", duration(n));
        }
        match i["resolvedAt"].as_str() {
            Some(r) => _ = writeln!(m, "| Resolved | {} UTC |", at(r)),
            None => _ = writeln!(m, "| Resolved | not yet |"),
        }
        let _ = writeln!(m, "| Duration | {}, from {from} |", duration(self.duration_minutes));

        let _ = writeln!(m, "\n## Timeline (UTC)\n");
        let _ = writeln!(m, "Status page posts, botd's starts, and changes to its configuration from {} h before the start. Add what people did and decided.\n", self.lead_hours);
        let _ = writeln!(m, "| Time | Source | What |\n|---|---|---|");
        for e in &self.timeline {
            let what = match e.source {
                "status_page" => format!("**{}**: {}", e.state.as_deref().unwrap_or_default(), cell(e.body.as_deref().unwrap_or_default())),
                "botd" => format!("botd started{}", e.version.as_deref().map(|v| format!(", version {}", cell(v))).unwrap_or_default()),
                _ => format!(
                    "`{}` by a {}{}",
                    e.action.as_deref().unwrap_or_default(),
                    e.actor_kind.as_deref().unwrap_or("system"),
                    e.target_type.as_deref().map(|t| format!(", on a {}", cell(t))).unwrap_or_default()
                ),
            };
            let source = match e.source {
                "status_page" => "Status page",
                "botd" => "botd",
                _ => "Change",
            };
            let _ = writeln!(m, "| {} | {source} | {what} |", at(&e.time));
        }
        if self.changes_not_shown > 0 {
            let _ = writeln!(m, "\n{} more changes aren't listed: `botctl audit --from <time> --to <time>` has them all.", self.changes_not_shown);
        }

        let _ = writeln!(m, "\n## Status page targets\n");
        match (t.posted_after_minutes, t.posted_late) {
            (Some(n), Some(late)) => _ = writeln!(m, "- Posted {} after detection: {} (target {POST_WITHIN_MINUTES} min).", duration(n), if late { "**late**" } else { "on time" }),
            _ => _ = writeln!(m, "- Posting within {POST_WITHIN_MINUTES} min of detection: not judged; give the detection time to judge it."),
        }
        match t.update_every_minutes {
            Some(every) if t.late_updates.is_empty() => _ = writeln!(m, "- Updated at least every {every} min: kept. Longest gap {}.", duration(t.longest_gap_minutes)),
            Some(every) => {
                let _ = writeln!(m, "- Updated at least every {every} min: **missed {} time{}**. Longest gap {}.", t.late_updates.len(), if t.late_updates.len() == 1 { "" } else { "s" }, duration(t.longest_gap_minutes));
                for g in &t.late_updates {
                    let _ = writeln!(m, "  - {} to {} UTC: {}", at(&g.from), at(&g.to), duration(g.minutes));
                }
            }
            None => _ = writeln!(m, "- Maintenance: no update target. Longest gap {}.", duration(t.longest_gap_minutes)),
        }

        let _ = writeln!(m, "\n## What botd saw\n");
        let (d, b) = (&self.during, &self.before);
        let _ = writeln!(m, "| | While it lasted ({}) | The same time before ({}) |\n|---|---|---|", duration(d.minutes), duration(b.minutes));
        let _ = writeln!(m, "| Bot runs finished | {} | {} |", d.runs_finished, b.runs_finished);
        let _ = writeln!(m, "| Bot runs failed | {} | {} |", share(d.runs_failed, d.runs_finished), share(b.runs_failed, b.runs_finished));
        let _ = writeln!(m, "| Sign-in failures | {} | {} |", d.sign_in_failures, b.sign_in_failures);
        let _ = writeln!(m, "| Requests denied | {} | {} |", d.denied, b.denied);
        let _ = writeln!(m, "| All failures and denials | {} | {} |", d.failures, b.failures);
        let _ = writeln!(m, "| Audit events | {} | {} |", d.events, b.events);
        if !self.top_failures.is_empty() {
            let _ = writeln!(m, "\nMost frequent failures while it lasted:\n");
            for f in &self.top_failures {
                let _ = writeln!(m, "- `{}` ({}): {}", f.action, f.outcome, f.count);
            }
        }
        if self.truncated {
            let _ = writeln!(m, "\nThe audit log had more events than this draft reads ({AUDIT_SCAN} for each part), so these counts are low; `botctl audit` has them all.");
        }

        let _ = writeln!(m, "\n## Impact\n\n{TODO} Who and how many were affected (customers, teams, people, Bots), for how long, and any data lost against the plan's RPO.");
        let _ = writeln!(m, "\n## Cause\n\n{TODO} What went wrong and why, down to the cause that, fixed, stops it happening again.");
        let _ = writeln!(m, "\n## What went well\n\n- {TODO}");
        let _ = writeln!(m, "\n## What went badly\n");
        let mut badly = Vec::new();
        if t.posted_late == Some(true) {
            badly.push(format!("The status page was posted {} after detection (target {POST_WITHIN_MINUTES} min).", duration(t.posted_after_minutes.unwrap_or_default())));
        }
        if !t.late_updates.is_empty() {
            badly.push(format!("Status page updates went past the hourly target {} time{}.", t.late_updates.len(), if t.late_updates.len() == 1 { "" } else { "s" }));
        }
        badly.push(TODO.into());
        for line in badly {
            let _ = writeln!(m, "- {line}");
        }
        let _ = writeln!(m, "\n## Actions\n\n| Action | Owner (role) | Due | Ticket |\n|---|---|---|---|\n| {TODO} | | | |");
        m
    }
}

fn db_err(e: rusqlite::Error) -> ApiError {
    crate::obs::log::line(crate::obs::log::Level::Warn, &format!("WARNING: incident review: {e}"));
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Couldn't read the incident. Try again.".into())
}

/// The review of incident `id` as of `now_ms`, or why not.
pub fn build(app: &App, id: &str, opts: &Opts, now_ms: i64) -> Result<Review, ApiError> {
    let i = app.db.status_incident(id).map_err(db_err)?.ok_or_else(|| not_found("Incident"))?;
    if opts.detected.is_some_and(|d| d > i.created_at) {
        return Err(bad("detected must be at or before the incident was posted"));
    }
    let start = start_of(&i, opts);
    let end = end_of(&i, now_ms);
    let lead_from = start - opts.lead_hours * 3_600_000;
    let before = app.db.audit_events(&audit::Filter { from: Some(lead_from), to: Some(start), ..Default::default() }, AUDIT_SCAN, false);
    let during = app.db.audit_events(&audit::Filter { from: Some(start), to: Some(end + 1), ..Default::default() }, AUDIT_SCAN, true);
    let truncated = before.len() as i64 >= AUDIT_SCAN || during.len() as i64 >= AUDIT_SCAN;
    Ok(review(&i, &before, &during, opts, now_ms, truncated))
}

/// `GET /api/status/incidents/{id}/review[?lead=24&detected=<time>&format=markdown]`.
pub async fn get(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Res<Response> {
    let (opts, format) = parse_query(&q).map_err(bad)?;
    let r = {
        let (app, id) = (app.clone(), id.clone());
        tokio::task::spawn_blocking(move || build(&app, &id, &opts, crate::db::now())).await
    }
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't draft the review: {e}")))??;
    app.db.record(&by.event("status.incident_reviewed").target("status_incident", &id).details(json!({
        "format": if format == Format::Markdown { "markdown" } else { "json" },
        "leadHours": opts.lead_hours,
        "detected": opts.detected.is_some(),
        "open": r.open,
    })));
    if format == Format::Json {
        return Ok(Json(r.json()).into_response());
    }
    let mut res = r.markdown().into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/markdown; charset=utf-8"));
    let name: String = id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"incident-review-{name}.md\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::StatusUpdate;

    const T0: i64 = 1_795_000_000_000;

    fn incident(impact: &str, posts: &[(i64, &str)], resolved: bool) -> StatusIncident {
        let updates: Vec<StatusUpdate> = posts
            .iter()
            .enumerate()
            .rev()
            .map(|(n, (min, state))| StatusUpdate { id: n as i64 + 1, state: state.to_string(), body: format!("Post {n} | with a pipe\nand a line"), created_by: Some("usr_x".into()), created_at: T0 + min * MINUTE })
            .collect();
        StatusIncident {
            id: "inc_abc".into(),
            title: "Bot runs fail".into(),
            impact: impact.into(),
            components: vec!["runners".into(), "api".into()],
            state: posts.last().unwrap().1.into(),
            created_by: Some("usr_x".into()),
            created_at: T0,
            updated_at: T0,
            resolved_at: resolved.then(|| T0 + posts.last().unwrap().0 * MINUTE),
            updates,
        }
    }

    fn event(min: i64, action: &str, outcome: &str, details: Value) -> AuditEvent {
        let at = T0 + min * MINUTE;
        AuditEvent {
            id: at,
            at,
            time: rfc3339(at),
            actor_kind: "user".into(),
            actor_id: Some("usr_secret".into()),
            actor_name: Some("Ada Lovelace".into()),
            actor_subject: Some("https://idp|ada".into()),
            action: action.into(),
            target_type: Some("policy".into()),
            target_id: Some("tgt_1".into()),
            bot_id: None,
            outcome: outcome.into(),
            ip: Some("203.0.113.9".into()),
            user_agent: Some("Mozilla".into()),
            details,
            actor_email: Some("ada@customer.example.com".into()),
            actor_role: Some("admin".into()),
            auth_method: Some("sso".into()),
            idp: Some("saml".into()),
            idp_provider: Some("okta-prod".into()),
            session_id: Some("ses_1".into()),
            on_behalf_of: None,
            chain_prev: None,
            chain_hash: None,
        }
    }

    #[test]
    fn hourly_updates_are_judged_while_open_and_not_while_resolved() {
        let i = incident("critical", &[(0, "investigating"), (50, "identified"), (130, "monitoring"), (150, "resolved")], true);
        let (longest, late) = gaps(&i, T0 + 999 * MINUTE, UPDATE_EVERY_MINUTES * MINUTE);
        assert_eq!(longest, 80);
        assert_eq!(late, vec![Gap { from: rfc3339(T0 + 50 * MINUTE), to: rfc3339(T0 + 130 * MINUTE), minutes: 80 }]);

        let open = incident("major", &[(0, "investigating"), (30, "identified")], false);
        let (longest, late) = gaps(&open, T0 + 120 * MINUTE, UPDATE_EVERY_MINUTES * MINUTE);
        assert_eq!((longest, late.len()), (90, 1), "an open incident's last post runs to now");

        let reopened = incident("major", &[(0, "investigating"), (20, "resolved"), (500, "investigating"), (520, "resolved")], true);
        assert_eq!(gaps(&reopened, T0, UPDATE_EVERY_MINUTES * MINUTE), (20, vec![]), "the time it was resolved isn't a late update");
    }

    #[test]
    fn targets_need_a_detection_time_to_judge_the_first_post() {
        let i = incident("critical", &[(0, "investigating"), (45, "identified"), (100, "resolved")], true);
        let t = targets(&i, &Opts::default(), T0);
        assert_eq!((t.posted_after_minutes, t.posted_late), (None, None));
        assert_eq!((t.to_identified_minutes, t.to_monitoring_minutes, t.to_resolved_minutes), (Some(45), None, Some(100)));
        let t = targets(&i, &Opts { detected: Some(T0 - 20 * MINUTE), ..Default::default() }, T0);
        assert_eq!((t.posted_after_minutes, t.posted_late), (Some(20), Some(true)));
        assert_eq!(t.to_resolved_minutes, Some(120), "from detection");
        let t = targets(&i, &Opts { detected: Some(T0 - 15 * MINUTE), ..Default::default() }, T0);
        assert_eq!(t.posted_late, Some(false), "15 minutes is on time");
        let t = targets(&i, &Opts { detected: Some(T0 - 15 * MINUTE - 59_000), ..Default::default() }, T0);
        assert_eq!((t.posted_after_minutes, t.posted_late), (Some(15), Some(true)), "15 minutes 59 seconds is late");
        let m = incident("maintenance", &[(0, "investigating"), (300, "resolved")], true);
        let t = targets(&m, &Opts::default(), T0);
        assert_eq!((t.update_every_minutes, t.late_updates.len(), t.longest_gap_minutes), (None, 0, 300));
    }

    #[test]
    fn the_review_sets_botds_records_beside_the_timeline() {
        let i = incident("critical", &[(0, "investigating"), (40, "identified"), (90, "resolved")], true);
        let before = vec![
            event(-30, "bot.run_finished", "success", json!({})),
            event(-20, "policy.updated", "success", json!({})),
            event(-10, "server.started", "success", json!({ "version": "0.2.0" })),
            event(-5, "policy.updated", "failure", json!({})),
            event(-2000, "rule.added", "success", json!({})),
        ];
        let during = vec![
            event(5, "bot.run_finished", "failure", json!({ "result": "error" })),
            event(6, "bot.run_finished", "failure", json!({ "result": "error" })),
            event(7, "bot.run_finished", "success", json!({})),
            event(8, "auth.login_failed", "failure", json!({ "unloggedSinceLast": 4 })),
            event(9, "access.denied", "denied", json!({})),
            event(60, "role.updated", "success", json!({})),
        ];
        let r = review(&i, &before, &during, &Opts::default(), T0 + 999 * MINUTE, false);
        let sources: Vec<&str> = r.timeline.iter().map(|e| e.source).collect();
        assert_eq!(sources, ["change", "botd", "status_page", "status_page", "change", "status_page"], "{:#?}", r.timeline);
        assert_eq!(r.timeline[1].version.as_deref(), Some("0.2.0"));
        assert_eq!((r.changes_before, r.changes_during), (2, 1), "a failed change isn't one, nor one before the lead-in");
        assert_eq!(r.during, Seen { minutes: 90, events: 6, runs_finished: 3, runs_failed: 2, sign_in_failures: 5, denied: 1, failures: 8 });
        assert_eq!(r.before, Seen { minutes: 90, events: 4, runs_finished: 1, runs_failed: 0, sign_in_failures: 0, denied: 0, failures: 1 }, "the same 90 minutes before");
        assert_eq!(r.top_failures[0], FailureCount { action: "auth.login_failed".into(), outcome: "failure".into(), count: 5 }, "a throttled failure counts what it stands for");
        assert_eq!(r.top_failures[1], FailureCount { action: "bot.run_finished".into(), outcome: "failure".into(), count: 2 });
        assert_eq!(r.incident["components"], json!(["Harness runners", "API"]));

        let all = r.json().to_string() + &r.markdown();
        for never in ["usr_secret", "usr_x", "Ada", "ada@", "203.0.113.9", "https://idp", "tgt_1", "Mozilla"] {
            assert!(!all.contains(never), "names nobody: {never}");
        }
    }

    #[test]
    fn changes_nearest_the_start_are_kept() {
        let i = incident("major", &[(0, "investigating"), (30, "resolved")], true);
        let before: Vec<AuditEvent> = (1..=60).map(|n| event(-n, "bot.updated", "success", json!({}))).collect();
        let r = review(&i, &before, &[], &Opts::default(), T0, false);
        assert_eq!((r.changes_before, r.changes_not_shown), (60, 10));
        let earliest = r.timeline.iter().filter(|e| e.source == "change").map(|e| e.at).min().unwrap();
        assert_eq!(earliest, T0 - 50 * MINUTE);
    }

    #[test]
    fn the_markdown_has_the_reviews_sections_and_flags_missed_targets() {
        let i = incident("critical", &[(0, "investigating"), (90, "resolved")], true);
        let opts = Opts { detected: Some(T0 - 30 * MINUTE), ..Default::default() };
        let md = review(&i, &[], &[event(1, "bot.run_finished", "failure", json!({}))], &opts, T0, false).markdown();
        for heading in ["# Incident review: Bot runs fail", "## Timeline (UTC)", "## Status page targets", "## What botd saw", "## Impact", "## Cause", "## What went well", "## What went badly", "## Actions"] {
            assert!(md.lines().any(|l| l == heading), "{heading}:\n{md}");
        }
        assert!(md.contains("Posted 30 min after detection: **late**"), "{md}");
        assert!(md.contains("**missed 1 time**. Longest gap 1 h 30 min."), "{md}");
        assert!(md.contains("Post 0 \\| with a pipe and a line"), "one table cell: {md}");
        assert!(md.contains("| Bot runs failed | 1 (100%) | 0 |"), "{md}");
        assert!(md.contains("| Duration | 2 h, from detection |"), "{md}");
        assert!(md.contains("- The status page was posted 30 min after detection"), "{md}");
        assert!(!md.contains("still open"));
        let open = incident("minor", &[(0, "investigating")], false);
        let md = review(&open, &[], &[], &Opts::default(), T0 + 10 * MINUTE, false).markdown();
        assert!(md.contains("**The incident is still open**") && md.contains("| Resolved | not yet |") && md.contains("not judged"), "{md}");
    }

    #[test]
    fn query_options() {
        let q = |pairs: &[(&str, &str)]| parse_query(&pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());
        assert_eq!(q(&[]), Ok((Opts::default(), Format::Json)));
        assert_eq!(q(&[("lead", "6"), ("format", "markdown")]), Ok((Opts { lead_hours: 6, detected: None }, Format::Markdown)));
        assert_eq!(q(&[("detected", "2026-11-20T10:00:00Z")]).unwrap().0.detected, Some(1_795_168_800_000));
        for bad in [("lead", "0"), ("lead", "169"), ("lead", "x"), ("format", "pdf"), ("detected", "yesterday")] {
            assert!(q(&[bad]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn changes_are_configuration_not_traffic() {
        for yes in ["server.started", "policy.updated", "sso.saml_sp_key_promoted", "scim.token_rotated", "user.role_changed", "license.installed"] {
            assert!(is_change(yes), "{yes}");
        }
        for no in ["bot.run_finished", "auth.login", "license.refused", "scim.user_deleted", "status.incident_updated", "secret.lease_issued", "policy.allowed", "policy.denied", "sso.saml_role_skipped", "sso.saml_metadata_refused"] {
            assert!(!is_change(no), "{no}");
        }
    }
}
