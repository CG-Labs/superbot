//! Observability (ADR 0089): a Prometheus `/metrics` endpoint on a listener of its own,
//! off unless `METRICS_LISTEN` is set, and structured JSON logs (`LOG_FORMAT=json`) with
//! a request id on every request and a run id on every run.
//!
//! `/metrics` never shares botd's main port: Caddy proxies that one to the internet, and
//! machines' Bots reach it through the machine port as if from loopback. Its own
//! listener is reachable only where the operator binds it. Off loopback it needs a
//! bearer token (`METRICS_TOKEN`), and botd refuses to start without one.

pub mod capacity;
pub mod errors;
pub mod log;
pub mod metrics;

use crate::machines::route::Routing;
use crate::machines::{self, ControlPlane, State};
use crate::storage::Report;
use crate::secrets::{self, SecretStore};
use crate::{AppState, same};
use axum::extract::{MatchedPath, Request, State as AxState};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use log::Level;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Instant;

pub use metrics::Metrics;

/// Where `METRICS_LISTEN=on` listens.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:9464";
/// The shortest `METRICS_TOKEN` botd takes.
pub const MIN_TOKEN: usize = 24;
pub const REQUEST_ID: &str = "x-request-id";

tokio::task_local! {
    static CURRENT_REQUEST: String;
}

/// The id of the request this task is answering, if it is answering one.
pub fn request_id() -> Option<String> {
    CURRENT_REQUEST.try_with(Clone::clone).ok()
}

#[derive(Debug)]
pub struct Settings {
    pub log: log::Format,
    pub metrics: Option<Listen>,
    pub errors: errors::Settings,
}

#[derive(Debug)]
pub struct Listen {
    pub addr: SocketAddr,
    pub token: Option<secrets::Secret>,
}

impl Settings {
    pub fn from_env(get: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Settings, String> {
        let log = log::Format::parse(&get("LOG_FORMAT"))?;
        let errors = errors::Settings::from_env(get, store)?;
        let raw = get("METRICS_LISTEN");
        let addr = match raw.trim().to_ascii_lowercase().as_str() {
            "" | "off" => None,
            "on" => Some(DEFAULT_LISTEN.parse().unwrap()),
            _ => Some(raw.trim().parse::<SocketAddr>().map_err(|_| format!("METRICS_LISTEN must be off, on, or an address and port such as {DEFAULT_LISTEN}, not \"{raw}\""))?),
        };
        let Some(addr) = addr else {
            return Ok(Settings { log, metrics: None, errors });
        };
        let token = store.get("METRICS_TOKEN").map_err(|e| e.to_string())?;
        if let Some(t) = &token {
            if t.expose().len() < MIN_TOKEN {
                return Err(format!("METRICS_TOKEN must be at least {MIN_TOKEN} characters (openssl rand -hex 32 makes one)"));
            }
            secrets::redact::register(t.expose());
        } else if !addr.ip().is_loopback() {
            return Err(format!("METRICS_LISTEN={addr} is off loopback, so set METRICS_TOKEN (or METRICS_TOKEN_FILE) for scrapers to send"));
        }
        Ok(Settings { log, metrics: Some(Listen { addr, token }), errors })
    }

    pub fn describe(&self) -> String {
        let logs = format!("logs as {} (LOG_FORMAT); {}", self.log.as_str(), self.errors.describe());
        match &self.metrics {
            None => format!("{logs}; metrics off (METRICS_LISTEN)"),
            Some(l) => format!(
                "{logs}; metrics at http://{}/metrics, {}",
                l.addr,
                if l.token.is_some() { "with a bearer token (METRICS_TOKEN)" } else { "loopback only, no token" }
            ),
        }
    }
}

/// The class `/metrics` counts a request under. A fixed list, from the path's first
/// segments only, so no id, email or query in a path can become a label.
pub fn route_class(path: &str) -> &'static str {
    let api = |p: &str| path == p || path.strip_prefix(p).is_some_and(|r| r.starts_with('/'));
    match path {
        "/healthz" => "healthz",
        "/status" | "/status.json" => "status",
        "/login" => "auth",
        "/api/events" => "events",
        "/api/approvals/check" => "approval_hook",
        "/api/ask" | "/api/handoff" => "bot_calls",
        "/billing/stripe/webhook" => "billing_webhook",
        _ if api("/api/auth") || api("/api/sessions") => "auth",
        _ if api("/api/bots") || api("/api/routines") || api("/api/harnesses") || api("/api/state") => "bots",
        _ if api("/api/approvals") || api("/api/policy") => "approvals",
        _ if api("/api/machines") || api("/api/machine") => "machines",
        _ if api("/api/users") || api("/api/me") || api("/api/scim") => "users",
        _ if api("/api/teams") || api("/api/team") => "teams",
        _ if api("/api/audit") => "audit",
        _ if api("/api/billing") || api("/api/usage") || api("/api/tiers") || api("/api/license") => "billing",
        _ if api("/api/signups") => "signups",
        _ if api("/api/status") => "status",
        _ if api("/scim") => "scim",
        _ if api("/api") => "api_other",
        _ => "web",
    }
}

/// An id the caller (or Caddy) sent, if it's plain enough to log; else a new one.
fn request_id_for(req: &Request) -> String {
    req.headers()
        .get(REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
        .map(String::from)
        .unwrap_or_else(|| crate::random_hex(8))
}

/// The route a request matched, for its log line: a template like
/// `/api/bots/{id}/messages`, never the path as sent. `track` puts it on the request
/// and reads it after, so it's known even when the handler panics.
#[derive(Clone, Default)]
struct Route(std::sync::Arc<std::sync::OnceLock<String>>);

/// On the API's routes: notes the template they matched, for `track`.
pub async fn note_route(req: Request, next: Next) -> Response {
    if let (Some(slot), Some(m)) = (req.extensions().get::<Route>(), req.extensions().get::<MatchedPath>()) {
        let _ = slot.0.set(m.as_str().to_string());
    }
    next.run(req).await
}

/// Inside `track`: a handler that panics answers 500, so the request is counted, logged
/// and reported like any other 5xx instead of dropping the connection.
pub fn catch_panics() -> tower_http::catch_panic::CatchPanicLayer<fn(Box<dyn std::any::Any + Send>) -> Response> {
    fn answer(_: Box<dyn std::any::Any + Send>) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({ "error": "Internal error" }))).into_response()
    }
    tower_http::catch_panic::CatchPanicLayer::custom(answer as fn(_) -> _)
}

/// Outermost: gives every request an id (`X-Request-Id`, echoed back), counts it and
/// its latency by route class, and logs it in JSON format.
pub async fn track(AxState(app): AxState<AppState>, mut req: Request, next: Next) -> Response {
    let started = Instant::now();
    let slot = Route::default();
    req.extensions_mut().insert(slot.clone());
    let id = request_id_for(&req);
    let class = route_class(req.uri().path());
    let method = metrics::method(req.method().as_str());
    let mut res = CURRENT_REQUEST.scope(id.clone(), next.run(req)).await;
    let took = started.elapsed().as_secs_f64();
    let code = res.status().as_u16();
    app.db.metrics().request(class, method, code, took);
    if let Ok(v) = HeaderValue::from_str(&id) {
        res.headers_mut().insert(REQUEST_ID, v);
    }
    let route = slot.0.get().cloned();
    // The status page answers 503 in a major outage, on purpose.
    if code >= 500 && !matches!(class, "healthz" | "status") {
        errors::http_error(method, route.as_deref(), class, code, &id);
    }
    if !(class == "healthz" && res.status().is_success()) {
        let level = if code >= 500 { Level::Warn } else { Level::Info };
        log::event(
            level,
            "http.request",
            json!({
                "requestId": id, "method": method, "route": route, "routeClass": class, "status": code,
                "durationMs": (took * 1000.0).round() as u64,
            }),
        );
    }
    res
}

/// The metrics listener's router: `/metrics`, and nothing else.
pub fn metrics_router(app: AppState, token: Option<secrets::Secret>) -> Router {
    let token = std::sync::Arc::new(token);
    Router::new()
        .route(
            "/metrics",
            get(move |AxState(app): AxState<AppState>, req: Request| {
                let token = token.clone();
                async move { scrape(&app, token.as_ref().as_ref(), &req) }
            }),
        )
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(app)
}

fn scrape(app: &AppState, token: Option<&secrets::Secret>, req: &Request) -> Response {
    if let Some(t) = token {
        let sent = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
        if !same(sent.trim().as_bytes(), t.expose().as_bytes()) {
            return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Bearer")], "A bearer token (METRICS_TOKEN) is needed.\n").into_response();
        }
    }
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], render(app)).into_response()
}

/// Everything `/metrics` shows: the counters, and gauges read now.
pub fn render(app: &AppState) -> String {
    let mut out = String::new();
    metrics::family(&mut out, "superbot_build_info", "gauge", "botd's version.");
    metrics::sample(&mut out, "superbot_build_info", &[("version", env!("CARGO_PKG_VERSION"))], 1.0);
    app.db.metrics().render(&mut out);
    let (held, waiting) = app.slots.totals();
    metrics::family(&mut out, "superbot_run_slots_held", "gauge", "Run slots held now, across this server and machines (ADR 0073).");
    metrics::sample(&mut out, "superbot_run_slots_held", &[], held as f64);
    metrics::family(&mut out, "superbot_runs_waiting", "gauge", "Runs waiting for a slot now.");
    metrics::sample(&mut out, "superbot_runs_waiting", &[], waiting as f64);
    let (pending, oldest) = app.db.approvals_pending();
    metrics::family(&mut out, "superbot_approvals_pending", "gauge", "Approvals waiting for a decision.");
    metrics::sample(&mut out, "superbot_approvals_pending", &[], pending as f64);
    metrics::family(&mut out, "superbot_approvals_oldest_pending_age_seconds", "gauge", "How long the oldest pending approval has waited; 0 when none is.");
    let age = oldest.map_or(0, |at| (crate::db::now() - at).max(0));
    metrics::sample(&mut out, "superbot_approvals_oldest_pending_age_seconds", &[], age as f64 / 1000.0);
    if let Some(cp) = app.control_plane.get().filter(|cp| cp.enabled()) {
        render_machines(app, cp, &mut out);
    }
    capacity::render(app, &mut out);
    crate::server_backups::render(app, &mut out);
    crate::backup_encryption::render(app, &mut out);
    errors::render(&mut out);
    out
}

/// Machines by state, and each tier's RPO status (ADR 0074), when the control plane is on.
fn render_machines(app: &AppState, cp: &ControlPlane, out: &mut String) {
    let all = app.db.machines(None);
    let mut by_state: BTreeMap<&'static str, u64> = machines::STATES.iter().filter(|s| **s != State::Destroyed).map(|s| (s.as_str(), 0)).collect();
    for m in &all {
        if let Some(n) = by_state.get_mut(m.state.as_str()) {
            *n += 1;
        }
    }
    metrics::family(out, "superbot_machines", "gauge", "Users' machines by state (destroyed ones aren't counted).");
    for (s, n) in &by_state {
        metrics::sample(out, "superbot_machines", &[("state", s)], *n as f64);
    }
    // Storage limits count these reports while the user's Bots work there (ADR 0105).
    let now = crate::db::now();
    let mut reports: BTreeMap<&'static str, u64> = [Report::Fresh, Report::Stale, Report::Missing].iter().map(|r| (r.as_str(), 0)).collect();
    for m in all.iter().filter(|m| m.state != State::Destroyed && m.assigned_at.is_some() && cp.routing != Routing::Off) {
        *reports.entry(crate::storage::on_machine(m, now).report.as_str()).or_default() += 1;
    }
    metrics::family(out, "superbot_machine_storage_reports", "gauge", "Machines users' Bots work on, by how recent their agent's report of what the homes hold is: fresh, stale or missing (ADR 0105).");
    for (r, n) in &reports {
        metrics::sample(out, "superbot_machine_storage_reports", &[("report", r)], *n as f64);
    }
    let tier = |t: &str| if cp.tiers.iter().any(|(n, _)| n == t) { t.to_string() } else { "other".to_string() };
    if cp.offsite.is_some() || cp.provider_backups.is_some() {
        metrics::family(out, "superbot_machine_rpo_breaches_open", "gauge", "Machines past their RPO now, as botd last recorded (ADR 0074, ADR 0110).");
        metrics::sample(out, "superbot_machine_rpo_breaches_open", &[], app.db.machine_rpo_breaches_open().len() as f64);
    }
    render_provider_backups(app, cp, &all, &tier, out);
    let Some(off) = cp.offsite.as_deref() else { return };
    // Per tier: machines held to their RPO, those past it, and the oldest coverage age.
    let mut tiers: BTreeMap<String, (u64, u64, i64)> = BTreeMap::new();
    for m in all.iter().filter(|m| m.state != State::Destroyed) {
        let st = machines::recovery::status(app, cp, off, m);
        if st.untracked.is_some() {
            continue;
        }
        let e = tiers.entry(tier(&m.tier)).or_default();
        e.0 += 1;
        e.1 += st.breach as u64;
        e.2 = e.2.max(now - st.covered_since);
    }
    metrics::family(out, "superbot_machines_rpo_tracked", "gauge", "Machines held to their tier's RPO now, by tier.");
    for (t, (n, _, _)) in &tiers {
        metrics::sample(out, "superbot_machines_rpo_tracked", &[("tier", t)], *n as f64);
    }
    metrics::family(out, "superbot_machines_past_rpo", "gauge", "Machines whose newest off-host copy is older than their tier's RPO now, by tier.");
    for (t, (_, b, _)) in &tiers {
        metrics::sample(out, "superbot_machines_past_rpo", &[("tier", t)], *b as f64);
    }
    metrics::family(out, "superbot_machine_backup_age_max_seconds", "gauge", "Age of the oldest newest off-host copy among tracked machines, by tier.");
    for (t, (_, _, age)) in &tiers {
        metrics::sample(out, "superbot_machine_backup_age_max_seconds", &[("tier", t)], *age as f64 / 1000.0);
    }
    metrics::family(out, "superbot_machine_rpo_seconds", "gauge", "Each tier's RPO.");
    for t in tiers.keys() {
        let rpo = if t == "other" { off.s.rpo_ms("") } else { off.s.rpo_ms(t) };
        metrics::sample(out, "superbot_machine_rpo_seconds", &[("tier", t)], rpo as f64 / 1000.0);
    }
}

/// Running machines' provider backups (Linode Backups, ADR 0110), by tier: on or off at
/// the provider and, while botd holds them to an RPO, those past it, the oldest age of
/// the newest backup (since creation when there's none yet) and the RPO. Read from what
/// the reconciler last saw, so a scrape never calls the provider.
fn render_provider_backups(app: &AppState, cp: &ControlPlane, all: &[crate::db::Machine], tier: &dyn Fn(&str) -> String, out: &mut String) {
    let Some(provider) = cp.reporting_backups() else { return };
    let now = crate::db::now();
    let mut tiers: BTreeMap<String, (u64, u64, u64, i64)> = BTreeMap::new();
    for m in all.iter().filter(|m| m.state == State::Running && m.provider == provider) {
        let e = tiers.entry(tier(&m.tier)).or_default();
        e.0 += m.backups as u64;
        e.1 += !m.backups as u64;
        if let Some(pb) = cp.provider_backups {
            let st = machines::recovery::provider_status(app, cp, pb, m);
            if st.untracked.is_none() {
                e.2 += st.breach as u64;
                e.3 = e.3.max(now - st.covered_since);
            }
        }
    }
    metrics::family(out, "superbot_machines_provider_backups", "gauge", "Running machines by whether their provider's own backups are on, by provider and tier (ADR 0110).");
    for (t, (on, off, _, _)) in &tiers {
        metrics::sample(out, "superbot_machines_provider_backups", &[("provider", provider), ("tier", t), ("backups", "on")], *on as f64);
        metrics::sample(out, "superbot_machines_provider_backups", &[("provider", provider), ("tier", t), ("backups", "off")], *off as f64);
    }
    let Some(pb) = cp.provider_backups else { return };
    metrics::family(out, "superbot_machines_past_provider_backup_rpo", "gauge", "Running machines whose newest provider backup is older than the RPO now, by provider and tier.");
    for (t, (_, _, past, _)) in &tiers {
        metrics::sample(out, "superbot_machines_past_provider_backup_rpo", &[("provider", provider), ("tier", t)], *past as f64);
    }
    metrics::family(out, "superbot_machine_provider_backup_age_max_seconds", "gauge", "Age of the oldest newest provider backup among running machines (since creation if none yet), by provider and tier.");
    for (t, (_, _, _, age)) in &tiers {
        metrics::sample(out, "superbot_machine_provider_backup_age_max_seconds", &[("provider", provider), ("tier", t)], *age as f64 / 1000.0);
    }
    metrics::family(out, "superbot_machine_provider_backup_rpo_seconds", "gauge", "The RPO machines are held to by their provider's backups (MACHINE_BACKUPS_RPO_HOURS).");
    for t in tiers.keys() {
        metrics::sample(out, "superbot_machine_provider_backup_rpo_seconds", &[("provider", provider), ("tier", t)], pb.rpo_ms as f64 / 1000.0);
    }
}

/// Serves `/metrics` on its own listener until botd exits.
pub async fn serve(listener: tokio::net::TcpListener, app: AppState, token: Option<secrets::Secret>) {
    let router = metrics_router(app, token);
    if let Err(e) = axum::serve(listener, router).await {
        log::line(Level::Warn, &format!("WARNING: metrics listener stopped: {e}"));
    }
}
