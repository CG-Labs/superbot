//! The public status page (ADR 0090): `/status` (HTML) and `/status.json`, with the
//! health of botd's core components, judged from live checks and the last minutes of
//! ADR 0089's counters, and incident notes admins write in the console or at
//! `/api/status/incidents`.
//!
//! Both pages are open to anyone, like `/healthz`, so they show only fixed component
//! names, fixed sentences, and what admins wrote for the public: no counts, ids,
//! hostnames, errors, tenant data or tokens. `STATUS_PAGE=off` turns them off.

use crate::audit::Who;
use crate::db::{StatusIncident, now};
use crate::obs::metrics::{RECENT_MINUTES, Recent};
use crate::runner::App;
use crate::secrets::redact;
use crate::{AppState, Res, bad, not_found};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Every component the page can show, in order: its id and its public name.
pub const COMPONENTS: [(&str, &str); 5] = [
    ("api", "API"),
    ("database", "Database"),
    ("machines", "Machines and control plane"),
    ("runners", "Harness runners"),
    ("notifications", "Notifications"),
];
pub const IMPACTS: [&str; 5] = ["none", "minor", "major", "critical", "maintenance"];
pub const STATES: [&str; 4] = ["investigating", "identified", "monitoring", "resolved"];
pub const MAX_TITLE: usize = 120;
pub const MAX_BODY: usize = 2000;
/// Resolved incidents stay on the public page this long.
pub const HISTORY_DAYS: i64 = 14;
/// The most incidents the public page lists, and updates it shows of each.
const PUBLIC_INCIDENTS: i64 = 20;
const PUBLIC_UPDATES: i64 = 10;
/// How long one snapshot answers every caller, so the open pages cost a few queries a
/// few times a minute however often they are fetched.
pub const CACHE: Duration = Duration::from_secs(10);

/// API: the 5xx share of the last `API_MINUTES` of requests, once there are `API_MIN_REQUESTS`.
pub const API_MINUTES: i64 = 5;
pub const API_MIN_REQUESTS: u64 = 20;
/// Runs: the failed share of the last `RECENT_MINUTES` of finished runs, once there are `RUNS_MIN`.
pub const RUNS_MIN: u64 = 4;
/// Database: a trivial query slower than this is degraded.
pub const DB_SLOW: Duration = Duration::from_millis(500);
/// The reconciler is behind when its last pass is older than this many intervals plus a minute.
pub const RECONCILE_LATE_INTERVALS: u32 = 3;

/// A component's status, worst last. The names are the ones status page tools use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Operational,
    UnderMaintenance,
    DegradedPerformance,
    PartialOutage,
    MajorOutage,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Operational => "operational",
            Level::UnderMaintenance => "under_maintenance",
            Level::DegradedPerformance => "degraded_performance",
            Level::PartialOutage => "partial_outage",
            Level::MajorOutage => "major_outage",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Level::Operational => "Operational",
            Level::UnderMaintenance => "Under maintenance",
            Level::DegradedPerformance => "Degraded performance",
            Level::PartialOutage => "Partial outage",
            Level::MajorOutage => "Major outage",
        }
    }

    fn summary(self) -> &'static str {
        match self {
            Level::Operational => "All systems operational",
            Level::UnderMaintenance => "Maintenance underway",
            Level::DegradedPerformance => "Degraded performance",
            Level::PartialOutage => "Partial outage",
            Level::MajorOutage => "Major outage",
        }
    }

    /// What an open incident's impact makes the components it names, at least.
    pub fn of_impact(impact: &str) -> Level {
        match impact {
            "minor" => Level::DegradedPerformance,
            "major" => Level::PartialOutage,
            "critical" => Level::MajorOutage,
            "maintenance" => Level::UnderMaintenance,
            _ => Level::Operational,
        }
    }
}

/// One component's health: a level and, when it isn't operational, a fixed sentence.
pub type Health = (Level, Option<&'static str>);

const OK: Health = (Level::Operational, None);

/// The share of `part` in `whole` is at least `num/den`.
fn at_least(part: u64, whole: u64, num: u64, den: u64) -> bool {
    whole > 0 && part * den >= whole * num
}

pub fn api_health(r: &Recent) -> Health {
    if r.requests < API_MIN_REQUESTS {
        return OK;
    }
    if at_least(r.errors, r.requests, 1, 2) {
        (Level::MajorOutage, Some("Most requests are failing."))
    } else if at_least(r.errors, r.requests, 1, 4) {
        (Level::PartialOutage, Some("Many requests are failing."))
    } else if at_least(r.errors, r.requests, 1, 20) {
        (Level::DegradedPerformance, Some("Some requests are failing."))
    } else {
        OK
    }
}

pub fn database_health(ping: Result<Duration, ()>) -> Health {
    match ping {
        Err(()) => (Level::MajorOutage, Some("The database isn't answering.")),
        Ok(t) if t > DB_SLOW => (Level::DegradedPerformance, Some("The database is slow.")),
        Ok(_) => OK,
    }
}

pub fn runners_health(r: &Recent) -> Health {
    let finished = r.runs_done + r.runs_failed;
    if finished < RUNS_MIN {
        return OK;
    }
    if at_least(r.runs_failed, finished, 1, 2) {
        (Level::PartialOutage, Some("Many Bot runs are failing."))
    } else if at_least(r.runs_failed, finished, 1, 4) {
        (Level::DegradedPerformance, Some("Some Bot runs are failing."))
    } else {
        OK
    }
}

pub fn notifications_health(r: &Recent) -> Health {
    let tried = r.notices_sent + r.notices_failed;
    if r.notices_failed >= 5 && r.notices_sent == 0 {
        (Level::PartialOutage, Some("Notifications aren't being delivered."))
    } else if r.notices_failed >= 2 && at_least(r.notices_failed, tried, 1, 2) {
        (Level::DegradedPerformance, Some("Some notifications aren't being delivered."))
    } else {
        OK
    }
}

/// What the machines component looks at, gathered from the database and the reconciler.
#[derive(Default, Debug)]
pub struct MachineFacts {
    /// Hosts not declared lost, and how many of them are down.
    pub hosts: usize,
    pub hosts_down: usize,
    /// Live machines, and how many are in error.
    pub machines: i64,
    pub machines_error: i64,
    pub rpo_breaches: usize,
    /// How long since the reconciler's last pass, and its interval; None before the first.
    pub reconcile_age: Option<Duration>,
    pub reconcile_every: Duration,
}

pub fn machines_health(f: &MachineFacts) -> Health {
    let late = f.reconcile_every * RECONCILE_LATE_INTERVALS + Duration::from_secs(60);
    if f.hosts > 0 && f.hosts_down == f.hosts {
        (Level::MajorOutage, Some("Machine hosts aren't answering."))
    } else if f.hosts_down > 0 {
        (Level::PartialOutage, Some("Some machine hosts aren't answering."))
    } else if f.reconcile_age.is_some_and(|a| a > late) {
        (Level::DegradedPerformance, Some("Machine changes are delayed."))
    } else if f.machines_error > 0 && f.machines_error * 10 >= f.machines {
        (Level::DegradedPerformance, Some("Some machines need attention."))
    } else if f.rpo_breaches > 0 {
        (Level::DegradedPerformance, Some("Some machine backups are behind schedule."))
    } else {
        OK
    }
}

fn machine_facts(app: &App, cp: &crate::machines::ControlPlane, now_ms: i64) -> MachineFacts {
    let hosts: Vec<_> = app.db.machine_hosts().into_iter().filter(|h| h.state != "lost").collect();
    let counts = app.db.machine_state_counts();
    MachineFacts {
        hosts: hosts.len(),
        hosts_down: hosts.iter().filter(|h| h.state == "down").count(),
        machines: counts.values().sum(),
        machines_error: counts.get("error").copied().unwrap_or(0),
        rpo_breaches: if cp.offsite.is_some() { app.db.machine_rpo_breaches_open().len() } else { 0 },
        reconcile_age: app.db.metrics().last_reconcile().map(|at| Duration::from_millis((now_ms - at).max(0) as u64)),
        reconcile_every: cp.reconcile_every,
    }
}

/// Each component this server uses, with its health from the checks alone. Machines
/// show only with the control plane on, and notifications only when set up.
pub fn checks(app: &App, now_ms: i64) -> Vec<(&'static str, Health)> {
    let m = app.db.metrics();
    let mut out = vec![
        ("api", api_health(&m.recent(now_ms, API_MINUTES))),
        ("database", database_health(app.db.ping().map_err(|_| ()))),
    ];
    if let Some(cp) = app.control_plane.get().filter(|cp| cp.enabled()) {
        out.push(("machines", machines_health(&machine_facts(app, cp, now_ms))));
    }
    out.push(("runners", runners_health(&m.recent(now_ms, RECENT_MINUTES))));
    if app.notifier.get().is_some() {
        out.push(("notifications", notifications_health(&m.recent(now_ms, RECENT_MINUTES))));
    }
    out
}

fn name_of(id: &str) -> &'static str {
    COMPONENTS.iter().find(|(c, _)| *c == id).map_or("Other", |(_, n)| n)
}

/// An incident as the public sees it: no author, no update ids.
fn public_incident(i: &StatusIncident) -> Value {
    json!({
        "id": i.id,
        "title": i.title,
        "impact": i.impact,
        "state": i.state,
        "components": i.components,
        "createdAt": i.created_at,
        "updatedAt": i.updated_at,
        "resolvedAt": i.resolved_at,
        "updates": i.updates.iter().map(|u| json!({ "state": u.state, "body": u.body, "createdAt": u.created_at })).collect::<Vec<_>>(),
    })
}

/// The whole page's data: checks, raised by open incidents, and recent incidents.
pub fn snapshot(app: &App, now_ms: i64) -> Value {
    let incidents = app.db.status_incidents(now_ms - HISTORY_DAYS * 86_400_000, PUBLIC_INCIDENTS, PUBLIC_UPDATES);
    let open: Vec<&StatusIncident> = incidents.iter().filter(|i| i.resolved_at.is_none()).collect();
    let mut overall = Level::Operational;
    let components: Vec<Value> = checks(app, now_ms)
        .into_iter()
        .map(|(id, (mut level, mut note))| {
            for i in open.iter().filter(|i| i.components.iter().any(|c| c == id)) {
                let raised = Level::of_impact(&i.impact);
                if raised > level {
                    level = raised;
                    note = None;
                }
            }
            overall = overall.max(level);
            json!({ "id": id, "name": name_of(id), "status": level, "note": note })
        })
        .collect();
    // An open incident that names no component still says how bad things are.
    for i in &open {
        overall = overall.max(Level::of_impact(&i.impact));
    }
    json!({
        "status": overall,
        "description": overall.summary(),
        "updatedAt": now_ms,
        "components": components,
        "incidents": incidents.iter().map(public_incident).collect::<Vec<_>>(),
    })
}

/// STATUS_PAGE, and the snapshot both pages share for `CACHE`.
pub struct Page {
    enabled: AtomicBool,
    cache: Mutex<Option<(Instant, Value)>>,
}

impl Default for Page {
    fn default() -> Page {
        Page { enabled: AtomicBool::new(true), cache: Mutex::new(None) }
    }
}

impl Page {
    /// STATUS_PAGE: on (the default) or off.
    pub fn parse(v: &str) -> Result<bool, String> {
        match v.trim().to_ascii_lowercase().as_str() {
            "" | "1" | "on" | "true" | "yes" => Ok(true),
            "0" | "off" | "false" | "no" => Ok(false),
            _ => Err(format!("STATUS_PAGE must be on or off, not \"{v}\"")),
        }
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Drops the shared snapshot, so an incident change shows at once.
    pub fn invalidate(&self) {
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn get(&self, app: &App) -> Value {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, v)) = c.as_ref().filter(|(at, _)| at.elapsed() < CACHE) {
            return v.clone();
        }
        let v = snapshot(app, now());
        *c = Some((Instant::now(), v.clone()));
        v
    }
}

fn public_headers(res: &mut Response, csp: &'static str) {
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=10"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(csp));
}

fn off() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "The status page is off (STATUS_PAGE=off)." }))).into_response()
}

/// `GET /status.json`: open to anyone.
pub async fn json_page(State(app): State<AppState>) -> Response {
    if !app.status.enabled() {
        return off();
    }
    let mut res = Json(app.status.get(&app)).into_response();
    public_headers(&mut res, "default-src 'none'; frame-ancestors 'none'");
    res
}

/// `GET /status`: the same, as a page with no script that reloads itself every minute.
pub async fn html_page(State(app): State<AppState>) -> Response {
    if !app.status.enabled() {
        return off();
    }
    let mut res = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], render_html(&app.status.get(&app))).into_response();
    public_headers(&mut res, "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    res
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn when(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%-d %b %Y, %H:%M UTC").to_string()).unwrap_or_default()
}

fn level_of(v: &Value) -> Level {
    serde_json::from_value(v.clone()).unwrap_or(Level::Operational)
}

const STYLE: &str = "body{font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#fafafa;color:#171717}\
main{max-width:720px;margin:0 auto;padding:32px 20px}h1{font-size:22px;margin:0 0 20px}h2{font-size:17px;margin:32px 0 12px}\
.banner{padding:16px 20px;border-radius:10px;color:#fff;font-weight:600}.list{background:#fff;border:1px solid #e5e5e5;border-radius:10px}\
.row{display:flex;justify-content:space-between;gap:12px;padding:12px 16px;border-top:1px solid #eee}.row:first-child{border-top:0}\
.note{color:#666;font-size:14px}.inc{background:#fff;border:1px solid #e5e5e5;border-radius:10px;padding:14px 16px;margin-bottom:12px}\
.inc h3{font-size:16px;margin:0 0 6px}.upd{margin:8px 0 0;font-size:15px;white-space:pre-wrap}.upd b{text-transform:capitalize}\
small,.muted{color:#737373;font-size:13px}.operational{color:#15803d}.under_maintenance{color:#1d4ed8}.degraded_performance{color:#a16207}\
.partial_outage{color:#c2410c}.major_outage{color:#b91c1c}.b-operational{background:#15803d}.b-under_maintenance{background:#1d4ed8}\
.b-degraded_performance{background:#a16207}.b-partial_outage{background:#c2410c}.b-major_outage{background:#b91c1c}\
@media(prefers-color-scheme:dark){body{background:#111;color:#ececec}.list,.inc{background:#1a1a1a;border-color:#2a2a2a}.row{border-color:#262626}.note{color:#a3a3a3}}";

pub fn render_html(s: &Value) -> String {
    let overall = level_of(&s["status"]);
    let mut h = String::new();
    let _ = write!(
        h,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta http-equiv=\"refresh\" content=\"60\"><title>SuperBot status</title><style>{STYLE}</style></head><body><main>\
         <h1>SuperBot status</h1><div class=\"banner b-{}\">{}</div><h2>Components</h2><div class=\"list\">",
        overall.as_str(),
        esc(s["description"].as_str().unwrap_or_default())
    );
    for c in s["components"].as_array().into_iter().flatten() {
        let level = level_of(&c["status"]);
        let note = c["note"].as_str().map(|n| format!("<div class=\"note\">{}</div>", esc(n))).unwrap_or_default();
        let _ = write!(
            h,
            "<div class=\"row\"><div>{}{note}</div><div class=\"{}\">{}</div></div>",
            esc(c["name"].as_str().unwrap_or_default()),
            level.as_str(),
            level.label()
        );
    }
    h.push_str("</div><h2>Incidents</h2>");
    let incidents = s["incidents"].as_array().cloned().unwrap_or_default();
    if incidents.is_empty() {
        let _ = write!(h, "<p class=\"muted\">No incidents in the last {HISTORY_DAYS} days.</p>");
    }
    for i in &incidents {
        let affected: Vec<&str> = i["components"].as_array().into_iter().flatten().filter_map(|c| c.as_str()).map(name_of).collect();
        let _ = write!(
            h,
            "<div class=\"inc\"><h3>{}</h3><small>{}{}{}</small>",
            esc(i["title"].as_str().unwrap_or_default()),
            esc(&i["state"].as_str().unwrap_or_default().replace('_', " ")),
            i["resolvedAt"].as_i64().map(|t| format!(" · resolved {}", when(t))).unwrap_or_default(),
            if affected.is_empty() { String::new() } else { format!(" · {}", esc(&affected.join(", "))) }
        );
        for u in i["updates"].as_array().into_iter().flatten() {
            let _ = write!(
                h,
                "<p class=\"upd\"><b>{}</b> — {} <small>{}</small></p>",
                esc(u["state"].as_str().unwrap_or_default()),
                esc(u["body"].as_str().unwrap_or_default()),
                when(u["createdAt"].as_i64().unwrap_or_default())
            );
        }
        h.push_str("</div>");
    }
    let _ = write!(
        h,
        "<p class=\"muted\">Updated {}. This page reloads every minute. <a href=\"/status.json\">JSON</a></p></main></body></html>",
        when(s["updatedAt"].as_i64().unwrap_or_default())
    );
    h
}

// Admin: incident notes. Every `/api/status/...` route is admin-only (rbac::classify).

fn text(v: &Value, field: &str, max: usize, multiline: bool) -> Result<Option<String>, crate::ApiError> {
    let Some(raw) = v.get(field) else { return Ok(None) };
    let s = raw.as_str().ok_or_else(|| bad(format!("{field} must be text")))?;
    let s: String = s.chars().filter(|c| !c.is_control() || (multiline && *c == '\n')).collect();
    let s = redact::text(s.trim()).into_owned();
    if s.is_empty() || s.chars().count() > max {
        return Err(bad(format!("{field} must be 1 to {max} characters")));
    }
    Ok(Some(s))
}

fn one_of(v: &Value, field: &str, list: &[&str]) -> Result<Option<String>, crate::ApiError> {
    let Some(raw) = v.get(field) else { return Ok(None) };
    match raw.as_str().filter(|s| list.contains(s)) {
        Some(s) => Ok(Some(s.to_string())),
        None => Err(bad(format!("{field} must be one of: {}", list.join(", ")))),
    }
}

fn components(v: &Value) -> Result<Option<Vec<String>>, crate::ApiError> {
    let Some(raw) = v.get("components") else { return Ok(None) };
    let ids = COMPONENTS.map(|(id, _)| id);
    let err = || bad(format!("components must be a list of: {}", ids.join(", ")));
    let mut out: Vec<String> = Vec::new();
    for c in raw.as_array().ok_or_else(err)? {
        let id = c.as_str().filter(|c| ids.contains(c)).ok_or_else(err)?;
        if !out.iter().any(|o| o == id) {
            out.push(id.to_string());
        }
    }
    Ok(Some(out))
}

fn need_incident(app: &App, id: &str) -> Res<StatusIncident> {
    app.db.status_incident(id).ok_or_else(|| not_found("Incident"))
}

fn incident_event(by: &Who, action: &str, i: &StatusIncident) -> crate::audit::Event {
    by.event(action)
        .target("status_incident", &i.id)
        .details(json!({ "title": i.title, "impact": i.impact, "state": i.state, "components": i.components }))
}

/// `GET /api/status/incidents`: the newest 100, open or not, with their authors.
pub async fn list(State(app): State<AppState>) -> Res {
    Ok(Json(json!({ "incidents": app.db.status_incidents(0, 100, i64::MAX), "components": COMPONENTS.map(|(id, name)| json!({ "id": id, "name": name })), "enabled": app.status.enabled() })))
}

/// `POST /api/status/incidents` `{title, body, impact?, components?, state?}`.
pub async fn create(State(app): State<AppState>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    let title = text(&v, "title", MAX_TITLE, false)?.ok_or_else(|| bad("Send a title."))?;
    let body = text(&v, "body", MAX_BODY, true)?.ok_or_else(|| bad("Send a body: what's happening, for the public."))?;
    let impact = one_of(&v, "impact", &IMPACTS)?.unwrap_or_else(|| "minor".into());
    let state = one_of(&v, "state", &STATES)?.unwrap_or_else(|| "investigating".into());
    let comps = components(&v)?.unwrap_or_default();
    let id = format!("inc_{}", crate::random_hex(6));
    let i = app.db.status_incident_create(&id, &title, &impact, &comps, &state, &body, by.actor.id.as_deref());
    app.db.record(&incident_event(&by, "status.incident_created", &i));
    app.status.invalidate();
    Ok((StatusCode::CREATED, Json(json!(i))))
}

/// `PATCH /api/status/incidents/{id}` `{title?, impact?, components?}`.
pub async fn edit(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    need_incident(&app, &id)?;
    let title = text(&v, "title", MAX_TITLE, false)?;
    let impact = one_of(&v, "impact", &IMPACTS)?;
    let comps = components(&v)?;
    app.db.status_incident_edit(&id, title.as_deref(), impact.as_deref(), comps.as_deref());
    let i = need_incident(&app, &id)?;
    app.db.record(&incident_event(&by, "status.incident_updated", &i));
    app.status.invalidate();
    Ok(Json(json!(i)))
}

/// `POST /api/status/incidents/{id}/updates` `{state, body}`: a new entry on its timeline.
pub async fn add_update(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    need_incident(&app, &id)?;
    let state = one_of(&v, "state", &STATES)?.ok_or_else(|| bad(format!("Send a state: one of {}", STATES.join(", "))))?;
    let body = text(&v, "body", MAX_BODY, true)?.ok_or_else(|| bad("Send a body."))?;
    app.db.status_incident_add_update(&id, &state, &body, by.actor.id.as_deref());
    let i = need_incident(&app, &id)?;
    app.db.record(&incident_event(&by, "status.incident_updated", &i));
    app.status.invalidate();
    Ok((StatusCode::CREATED, Json(json!(i))))
}

/// `DELETE /api/status/incidents/{id}`: for one posted by mistake. Resolve real ones.
pub async fn delete(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let i = need_incident(&app, &id)?;
    app.db.status_incident_delete(&id);
    app.db.record(&incident_event(&by, "status.incident_deleted", &i));
    app.status.invalidate();
    Ok(Json(json!({ "deleted": id })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(f: impl FnOnce(&mut Recent)) -> Recent {
        let mut r = Recent::default();
        f(&mut r);
        r
    }

    #[test]
    fn api_health_needs_enough_requests_and_grows_with_errors() {
        assert_eq!(api_health(&r(|r| (r.requests, r.errors) = (10, 10))).0, Level::Operational, "too few to judge");
        assert_eq!(api_health(&r(|r| (r.requests, r.errors) = (100, 4))).0, Level::Operational);
        assert_eq!(api_health(&r(|r| (r.requests, r.errors) = (100, 5))).0, Level::DegradedPerformance);
        assert_eq!(api_health(&r(|r| (r.requests, r.errors) = (100, 25))).0, Level::PartialOutage);
        assert_eq!(api_health(&r(|r| (r.requests, r.errors) = (100, 50))).0, Level::MajorOutage);
    }

    #[test]
    fn runners_and_notifications_judge_their_own_failures() {
        assert_eq!(runners_health(&r(|r| (r.runs_done, r.runs_failed) = (0, 3))).0, Level::Operational, "too few to judge");
        assert_eq!(runners_health(&r(|r| (r.runs_done, r.runs_failed) = (3, 1))).0, Level::DegradedPerformance);
        assert_eq!(runners_health(&r(|r| (r.runs_done, r.runs_failed) = (2, 2))).0, Level::PartialOutage);
        assert_eq!(runners_health(&r(|r| (r.runs_done, r.runs_failed) = (20, 1))).0, Level::Operational);
        assert_eq!(notifications_health(&r(|r| r.notices_failed = 1)).0, Level::Operational);
        assert_eq!(notifications_health(&r(|r| (r.notices_sent, r.notices_failed) = (2, 2))).0, Level::DegradedPerformance);
        assert_eq!(notifications_health(&r(|r| r.notices_failed = 5)).0, Level::PartialOutage);
    }

    #[test]
    fn database_health_is_down_slow_or_fine() {
        assert_eq!(database_health(Err(())).0, Level::MajorOutage);
        assert_eq!(database_health(Ok(Duration::from_secs(2))).0, Level::DegradedPerformance);
        assert_eq!(database_health(Ok(Duration::from_millis(1))), OK);
    }

    #[test]
    fn machines_health_puts_hosts_first() {
        let every = Duration::from_secs(60);
        let f = |g: fn(&mut MachineFacts)| {
            let mut m = MachineFacts { hosts: 2, machines: 20, reconcile_every: every, reconcile_age: Some(Duration::from_secs(30)), ..Default::default() };
            g(&mut m);
            machines_health(&m).0
        };
        assert_eq!(f(|_| {}), Level::Operational);
        assert_eq!(f(|m| m.hosts_down = 1), Level::PartialOutage);
        assert_eq!(f(|m| m.hosts_down = 2), Level::MajorOutage);
        assert_eq!(f(|m| m.reconcile_age = Some(Duration::from_secs(300))), Level::DegradedPerformance);
        assert_eq!(f(|m| m.reconcile_age = None), Level::Operational, "before the first pass");
        assert_eq!(f(|m| m.machines_error = 1), Level::Operational, "one in twenty");
        assert_eq!(f(|m| m.machines_error = 2), Level::DegradedPerformance);
        assert_eq!(f(|m| m.rpo_breaches = 1), Level::DegradedPerformance);
        assert_eq!(f(|m| m.hosts = 0), Level::Operational, "no hosts of its own (Linode)");
    }

    #[test]
    fn impacts_rank_and_maintenance_is_mildest() {
        assert!(Level::of_impact("maintenance") < Level::of_impact("minor"));
        assert!(Level::of_impact("minor") < Level::of_impact("major"));
        assert!(Level::of_impact("major") < Level::of_impact("critical"));
        assert_eq!(Level::of_impact("none"), Level::Operational);
        assert_eq!(serde_json::to_value(Level::PartialOutage).unwrap(), "partial_outage");
    }

    #[test]
    fn the_html_escapes_what_admins_wrote() {
        let s = json!({
            "status": "major_outage", "description": "Major outage", "updatedAt": 0,
            "components": [{ "id": "api", "name": "API", "status": "major_outage", "note": "Most requests are failing." }],
            "incidents": [{ "title": "<script>alert(1)</script>", "state": "investigating", "components": ["api"], "resolvedAt": null,
                "updates": [{ "state": "investigating", "body": "a \"quote\" & <b>", "createdAt": 0 }] }],
        });
        let h = render_html(&s);
        assert!(!h.contains("<script>") && h.contains("&lt;script&gt;"), "{h}");
        assert!(h.contains("a &quot;quote&quot; &amp; &lt;b&gt;"), "{h}");
        assert!(h.contains("Most requests are failing.") && h.contains("b-major_outage"), "{h}");
    }

    #[test]
    fn status_page_setting() {
        assert_eq!(Page::parse(""), Ok(true));
        assert_eq!(Page::parse("off"), Ok(false));
        assert!(Page::parse("maybe").is_err());
    }
}
