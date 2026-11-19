//! botd: the server. Owns Bots, chats, memory files, and routines; runs each Bot
//! on its harness (Claude Code, Codex, Pi, or Hermes Agent); serves the web app and its API.

mod acl;
#[cfg(test)]
mod acl_http_tests;
mod adapters;
mod approvals;
mod audit;
#[cfg(test)]
mod audit_http_tests;
#[cfg(test)]
mod auth_review_http_tests;
mod cron;
mod db;
mod paths;
mod policy;
mod rbac;
mod runner;
mod screen;
mod secrets;
mod shell;
mod signups;
#[cfg(test)]
mod signups_http_tests;
mod sso;
mod users;
#[cfg(test)]
mod users_http_tests;
#[cfg(test)]
mod sso_http_tests;
#[cfg(test)]
mod sso_saml_http_tests;
#[cfg(test)]
mod sso_social_http_tests;

use acl::{Access, Viewer, Visibility};
use approvals::{DecideError, Remember};
use audit::{Actor, Event, Outcome, Source, Who};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Query, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use std::collections::HashMap;
use db::{BotPatch, Db};
use rbac::{Perm, Principal, Role};
use runner::{App, Config};
use users::{Caller, SessionConfig};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use tower_http::cors::{AllowOrigin, CorsLayer};

type AppState = Arc<App>;
type EventStream = std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<SseEvent, Infallible>> + Send>>;

static WEB_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
static SITE_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

const COLORS: [&str; 11] = ["#f5f5f5", "#9a6b3f", "#e5484d", "#e8702e", "#e9a23b", "#4cc06a", "#4fb5a5", "#3b82f6", "#8b5cf6", "#e64a9c", "#7a7a7a"];
const SHAPES: [&str; 12] = ["waddle", "drop", "cloud", "bean", "onigiri", "peanut", "pebble", "square", "jelly", "gem", "gear", "heart"];

fn env(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.into())
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut b = vec![0u8; n];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("read /dev/urandom");
    b
}

fn random_hex(n: usize) -> String {
    random_bytes(n).iter().map(|x| format!("{x:02x}")).collect()
}

pub fn short_id() -> String {
    random_hex(4)
}

fn is_loopback_host(host: &str) -> bool {
    ["127.0.0.1", "localhost", "::1"].contains(&host)
}

fn pick<'a>(a: &[&'a str]) -> &'a str {
    a[random_bytes(1)[0] as usize % a.len()]
}

#[tokio::main]
async fn main() {
    let port: u16 = env("PORT", "3000").parse().expect("PORT must be a number");
    let host = env("HOST", "127.0.0.1");
    let password = auth_password();
    let default_harness = env("DEFAULT_HARNESS", "claude");
    let exit = |e: String| -> ! {
        eprintln!("{e}");
        std::process::exit(1);
    };
    let break_glass = users::break_glass_flag(&env("AUTH_BREAK_GLASS", "")).unwrap_or_else(|e| exit(e));
    let sessions = SessionConfig::from_env(&env("SESSION_IDLE_TIMEOUT", ""), &env("SESSION_MAX_AGE", "")).unwrap_or_else(|e| exit(e));
    let sso = sso::Sso::from_env().unwrap_or_else(|e| exit(format!("SSO: {e}")));
    let signups = signups::Signups::from_env(&secrets::env::EnvStore::process(), &env("SIGNUPS", ""), &env("TURNSTILE_SITE_KEY", ""))
        .unwrap_or_else(|e| exit(format!("Sign-ups: {e}")));
    let allow_no_auth = auth_startup(&host, &password, break_glass);
    secrets::redact::register(&password);
    if adapters::get(&default_harness).is_none() {
        eprintln!("DEFAULT_HARNESS must be one of: {}", adapters::NAMES.join(", "));
        std::process::exit(1);
    }
    let retention = audit::retention_days(&env("AUDIT_RETENTION_DAYS", "")).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    let bot_token = random_hex(24);
    secrets::redact::register(&bot_token);
    WEB_DIR.set(std::env::var("WEB_DIR").ok().map(PathBuf::from)).unwrap();
    SITE_DIR.set(std::env::var("SITE_DIR").ok().map(PathBuf::from)).unwrap();

    let root = |key: &str, default: &str| {
        paths::root(&env(key, default)).unwrap_or_else(|e| {
            eprintln!("{key}: {e}");
            std::process::exit(1);
        })
    };
    let data_dir = root("DATA_DIR", "data");
    let workspace = root("WORKSPACE_DIR", "workspace");
    let db_path = paths::child(&data_dir, "app.sqlite").unwrap();
    let db = Db::open(&db_path).expect("open database");
    match secrets::init(&db_path) {
        Ok(r) => {
            println!("Master key: {}{}.", r.key_source, if r.created { " (new)" } else { "" });
            if r.sealed + r.redacted + r.discarded > 0 {
                println!("Secrets: sealed {} saved tool inputs, redacted {} saved rows, discarded {} sealed values.", r.sealed, r.redacted, r.discarded);
            }
            println!("Stored secrets: {}.", r.stored);
        }
        Err(e) => {
            eprintln!("Secrets: {e}");
            std::process::exit(1);
        }
    }

    let screens = paths::child(&data_dir, "screens").and_then(screen::Screens::from_env);
    let app = App::new(db, Config {
        data_dir,
        workspace,
        user_name: env("USER_NAME", "the user"),
        // `botctl` ships next to `botd`.
        bin_dir: std::env::current_exe().unwrap().parent().unwrap().to_path_buf(),
        api_url: format!("http://127.0.0.1:{port}"),
        bot_token: bot_token.clone(),
        run_timeout: Duration::from_secs(60 * env("RUN_TIMEOUT_MINUTES", "60").parse::<u64>().unwrap_or(60)),
        default_harness,
    }, screens);

    // First start: create the primary Bot.
    if app.db.bots().is_empty() {
        let name = env("PRIMARY_BOT_NAME", "Assistant");
        let bot = app.db.create_bot(&name, "#f5f5f5", "waddle", &app.cfg.default_harness, None, true);
        app.init_bot_files(&bot);
    }
    // First start, or the first after upgrading to users: the owner becomes the admin
    // that break-glass signs in as.
    users::ensure_operator(&app.db, &env("USER_NAME", "Owner"), std::env::var("OWNER_EMAIL").ok().as_deref());

    let auth_state = Arc::new(Auth {
        password: password.clone(),
        break_glass,
        allow_no_auth,
        bot_token,
        hosts: allowed_hosts(&host, port, &env("ALLOWED_HOSTS", "")),
        trust_forwarded: env("TRUST_FORWARDED_FOR", "") == "1",
        sessions,
        sso,
        signups,
        ..Auth::new(Some(app.clone()))
    });
    println!(
        "Sign-ups: {}.",
        match (auth_state.signups.enabled, auth_state.signups.turnstile.is_some()) {
            (false, _) => "off (SIGNUPS=off)",
            (true, true) => "on, with Turnstile",
            (true, false) => "on (set TURNSTILE_SECRET and TURNSTILE_SITE_KEY to add a bot check)",
        }
    );
    for p in &auth_state.sso.providers {
        let ready = p.not_ready().unwrap_or_else(|| "ready".into());
        println!("SSO: {} ({}, {}), {ready}; {}; just-in-time sign-up {}.", p.id, p.label, p.type_name(), p.audience(), p.jit_role.map_or("off", |r| r.as_str()));
    }
    let sso_ids: Vec<String> = auth_state.sso.providers.iter().map(|p| p.id.clone()).collect();
    let router = router(app.clone(), auth_state);
    let policy = app.db.global_policy();
    app.db.record(&Event::new(Actor::system("server"), "server.started").details(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "defaultHarness": app.cfg.default_harness,
        "policyMode": policy.mode,
        "auth": match (break_glass, password.is_empty()) {
            (true, false) => "sessions+password",
            (true, true) => "none",
            (false, _) => "sessions",
        },
        "sessionIdleMinutes": sessions.idle_ms / 60_000,
        "sessionMaxMinutes": sessions.max_ms / 60_000,
        "auditRetentionDays": retention,
        "screens": app.screens.is_some(),
        "sso": sso_ids,
    })));
    audit::start_retention(app.clone(), retention);
    users::start_pruning(app.clone(), sessions);
    if policy.mode == policy::Mode::Bypass {
        eprintln!(
            "WARNING: harness policy is bypass: Bots run every tool without asking. \
             Opt in to approvals with `botctl policy set global mode=ask` (see docs/backend.md)."
        );
    }

    app.recover();
    cron::start(app.clone());
    if app.screens.is_some() {
        let app = app.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                app.screens.as_ref().unwrap().reap(|id| app.is_running(id)).await;
            }
        });
    }

    let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await.expect("bind");
    println!("Listening on http://{host}:{port}");
    println!("Harnesses on PATH: {}. Default: {}.", adapters::installed().join(", "), app.cfg.default_harness);
    println!("Screens: {}.", if app.screens.is_some() { "on" } else { "off (install Xvfb and openbox to turn them on)" });

    // On SIGTERM/SIGINT: stop agents (queued work runs after restart), then exit.
    let shutdown_app = app.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let (mut term, mut int) = (signal(SignalKind::terminate()).unwrap(), signal(SignalKind::interrupt()).unwrap());
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
        shutdown_app.shutdown();
        for _ in 0..60 {
            if shutdown_app.is_idle() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        std::process::exit(0);
    });

    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

fn router(app: AppState, auth_state: Arc<Auth>) -> Router {
    let api = Router::new()
        .route("/state", get(state))
        .route("/events", get(events))
        .route("/harnesses/{name}/models", get(list_models))
        .route("/bots", get(list_bots).post(create_bot))
        .route("/bots/{id}", patch(update_bot).delete(delete_bot))
        .route("/bots/{id}/access", get(get_access).patch(update_access))
        .route("/bots/{id}/grants/{user}", put(put_grant).delete(delete_grant))
        .route("/bots/{id}/messages", get(list_messages).post(send_message))
        .route("/bots/{id}/read", post(mark_read))
        .route("/bots/{id}/stop", post(stop_bot))
        .route("/bots/{id}/routines", get(list_routines).post(create_routine))
        .route("/routines/{id}", patch(update_routine).delete(delete_routine))
        .route("/bots/{id}/screen", get(screen_info))
        .route("/bots/{id}/policy", get(get_bot_policy).put(put_bot_policy).delete(delete_bot_policy))
        .route("/policy", get(get_policy).put(put_policy))
        .route("/policy/rules", get(list_rules).post(add_rule))
        .route("/policy/rules/{id}", delete(delete_rule))
        .route("/approvals", get(list_approvals))
        // A file write's full content passes through here, so allow big bodies.
        .route("/approvals/check", post(check_approval).layer(DefaultBodyLimit::max(32 * 1024 * 1024)))
        .route("/approvals/{id}/approve", post(approve))
        .route("/approvals/{id}/deny", post(deny))
        .route("/audit", get(list_audit))
        .route("/audit/export.csv", get(export_audit))
        .route("/secrets", get(list_secrets))
        .route("/secrets/{name}", put(put_secret).delete(delete_secret))
        .route("/ask", post(ask))
        .route("/handoff", post(handoff))
        .route("/auth/login", post(users::login))
        .route("/auth/logout", post(users::logout))
        .route("/auth/me", get(users::me))
        .route("/auth/sso", get(sso::list))
        .route("/auth/sso/{id}/start", get(sso::start))
        .route("/auth/sso/{id}/callback", get(sso::callback).post(sso::callback_post))
        .route("/users", get(users::list_users).post(users::create_user))
        .route("/users/{key}", get(users::get_user).patch(users::update_user))
        .route("/users/{key}/login-codes", post(users::create_login_code))
        .route("/users/{key}/sessions", delete(users::revoke_user_sessions))
        .route("/users/{key}/bots", get(users::user_bots))
        .route("/users/{key}/identities", get(sso::list_identities).post(sso::link_identity))
        .route("/users/{key}/identities/{id}", delete(sso::unlink_identity))
        .route("/sessions", get(users::list_sessions))
        .route("/sessions/{id}", delete(users::revoke_session))
        .route("/signups", get(signups::list).post(signups::submit).layer(DefaultBodyLimit::max(signups::MAX_BODY)))
        .route("/signups/config", get(signups::config))
        .route("/signups/{id}", get(signups::get))
        .route("/signups/{id}/approve", post(signups::approve))
        .route("/signups/{id}/reject", post(signups::reject));
    Router::new()
        .route("/healthz", get(|| async { Json(json!({ "ok": true })) }))
        .merge(
            Router::new()
                .nest("/api", api)
                .route("/login", get(login_page))
                .fallback(get(web))
                .layer(middleware::from_fn_with_state(auth_state.clone(), auth))
                .layer(Extension(auth_state)),
        )
        .layer(cors_layer())
        .with_state(app)
}

// Errors

#[derive(Debug)]
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn not_found(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, format!("{what} not found"))
}

type Res<T = Json<Value>> = Result<T, ApiError>;

// CORS for the SuperBot client (web/Electron). Native apps are not browser-bound.
fn cors_layer() -> CorsLayer {
    let raw = env("CORS_ORIGINS", "");
    let mut layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
        ]);
    layer = match raw.as_str() {
        "*" => layer.allow_origin(AllowOrigin::any()),
        "" => layer.allow_origin(AllowOrigin::list([
            HeaderValue::from_static("http://localhost:8081"),
            HeaderValue::from_static("http://localhost:19006"),
            HeaderValue::from_static("http://127.0.0.1:8081"),
            HeaderValue::from_static("http://127.0.0.1:19006"),
        ])),
        _ => {
            let origins: Vec<HeaderValue> = raw.split(',').filter_map(|o| o.trim().parse().ok()).collect();
            layer.allow_origin(AllowOrigin::list(origins))
        }
    };
    layer
}

// Auth: sessions (a cookie for the web app, a bearer token for the client and
// botctl), break-glass AUTH_PASSWORD (HTTP Basic, any username), or the Bots' token
// for `botctl`. Then one permission check per request (rbac::classify). ADR 0012.

struct Auth {
    password: String,
    /// AUTH_BREAK_GLASS: AUTH_PASSWORD signs in as the owner. Off: the password is ignored.
    break_glass: bool,
    /// Only when ALLOW_NO_AUTH=1 and loopback: empty password does not skip login on its own.
    allow_no_auth: bool,
    bot_token: String,
    /// Host headers we answer to, lowercase.
    hosts: Vec<String>,
    /// TRUST_FORWARDED_FOR=1: take the client IP from X-Forwarded-For from any peer,
    /// not only a proxy on loopback. Set when botd is reachable only through a proxy.
    trust_forwarded: bool,
    sessions: SessionConfig,
    logins: audit::Logins,
    limiter: users::Limiter,
    /// Single sign-on providers and sign-ins in progress (ADR 0014).
    sso: sso::Sso,
    /// The public "Get started" form (ADR 0022).
    signups: signups::Signups,
    /// The database: sessions and audit events. None in tests of auth alone.
    app: Option<AppState>,
}

impl Auth {
    fn new(app: Option<AppState>) -> Auth {
        Auth {
            password: String::new(),
            break_glass: true,
            allow_no_auth: false,
            bot_token: String::new(),
            hosts: Vec::new(),
            trust_forwarded: false,
            sessions: SessionConfig::default(),
            logins: audit::Logins::default(),
            limiter: users::Limiter::default(),
            sso: sso::Sso::default(),
            signups: signups::Signups::default(),
            app,
        }
    }

    fn record(&self, e: Event) {
        if let Some(app) = &self.app {
            app.db.record(&e);
        }
    }

    /// The owner account, which break-glass and ALLOW_NO_AUTH act as.
    fn operator(&self) -> Option<db::User> {
        self.app.as_ref()?.db.user(users::OPERATOR)
    }

    /// Logs the first good Basic-auth request of a client (see `audit::Logins`).
    /// Session sign-ins are logged once, by `users::login`.
    fn login_ok(&self, source: &Source, actor: &Actor, method: &str) {
        let client = format!("{}|{}", source.ip.as_deref().unwrap_or(""), source.user_agent.as_deref().unwrap_or(""));
        if self.logins.success(&client, db::now()) {
            let who = Who { actor: actor.clone(), source: source.clone() };
            self.record(who.event("auth.login").details(json!({ "method": method })));
        }
    }

    /// Logs a bad password, code, or token, throttled per IP. Never logs what was sent.
    fn login_failed(&self, source: &Source, method: &str, reason: Option<&str>) {
        let client = format!("{}|{method}", source.ip.as_deref().unwrap_or(""));
        let Some(missed) = self.logins.failure(&client, db::now()) else { return };
        let actor = if method == "bot_token" { Actor::bot(None, None) } else { Actor { id: None, ..Actor::operator() } };
        let actor = actor.method(method);
        let who = Who { actor, source: source.clone() };
        let mut details = json!({ "method": method, "unloggedSinceLast": missed });
        if let Some(r) = reason {
            details["reason"] = json!(r);
        }
        self.record(who.event("auth.login_failed").outcome(Outcome::Failure).details(details));
    }

    /// The live session for a token, or why there isn't one.
    fn session(&self, token: &str) -> Option<(db::Session, db::User)> {
        let app = self.app.as_ref()?;
        if !token.starts_with(users::SESSION_PREFIX) {
            return None;
        }
        let at = db::now();
        let found = app.db.live_session(&users::hash(token), at, self.sessions.idle_ms, self.sessions.max_ms)?;
        app.db.touch_session(&found.0.id, at);
        Some(found)
    }

    /// A Bot request names its Bot (`X-SuperBot-Bot`, from botctl's BOT_ID). All Bots
    /// share one token, so this is self-reported. A known Bot acts for its owner.
    fn bot_actor(&self, headers: &axum::http::HeaderMap) -> Actor {
        let id = headers.get("x-superbot-bot").and_then(|v| v.to_str().ok()).filter(|id| id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric()));
        match id.and_then(|id| self.app.as_ref()?.db.bot(id)) {
            Some(b) => Actor::for_bot(&b),
            None => Actor::bot(None, None),
        }
        .method("bot_token")
    }
}

/// The client's IP and user agent. Behind a proxy on loopback (Caddy on the same
/// host), the IP is the last X-Forwarded-For entry: the one the proxy added.
fn request_source(req: &Request, trust_forwarded: bool) -> Source {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_canonical());
    let forwarded = req
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .rfind(|v| !v.is_empty())
        .and_then(|v| v.parse::<IpAddr>().ok());
    let ip = match forwarded {
        Some(f) if trust_forwarded || peer.is_some_and(|p| p.is_loopback()) => Some(f.to_canonical()),
        _ => peer,
    };
    let user_agent = req.headers().get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|u| audit::clip(u.trim(), 256)).filter(|u| !u.is_empty());
    Source { ip: ip.map(|i| i.to_string()), user_agent }
}

/// AUTH_PASSWORD, or the file named by AUTH_PASSWORD_FILE. Empty when neither is set.
fn auth_password() -> String {
    use secrets::SecretStore;
    match secrets::env::EnvStore::process().get("AUTH_PASSWORD") {
        Ok(p) => p.map(|p| p.expose().to_string()).unwrap_or_default(),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// With break-glass on (the default), refuse to start without AUTH_PASSWORD unless
/// ALLOW_NO_AUTH=1 on loopback only. With it off, people sign in with sessions only.
fn auth_startup(host: &str, password: &str, break_glass: bool) -> bool {
    if !break_glass {
        println!(
            "Break-glass password sign-in is off (AUTH_BREAK_GLASS=0){}. People sign in with sessions; \
             set AUTH_BREAK_GLASS=1 and restart to get back in with AUTH_PASSWORD.",
            if password.is_empty() { "" } else { "; AUTH_PASSWORD is ignored" }
        );
        return false;
    }
    if !password.is_empty() {
        return false;
    }
    if !is_loopback_host(host) {
        eprintln!("Refusing to listen on a public address without AUTH_PASSWORD.");
        std::process::exit(1);
    }
    if env("ALLOW_NO_AUTH", "") == "1" {
        eprintln!(
            "WARNING: ALLOW_NO_AUTH=1 with empty AUTH_PASSWORD on {host}. \
             Any local process that passes the Host allowlist can use the API without login. \
             Set AUTH_PASSWORD for real use."
        );
        return true;
    }
    eprintln!(
        "Refusing to start: set AUTH_PASSWORD (recommended), or set ALLOW_NO_AUTH=1 only for \
         loopback development (HOST=127.0.0.1, localhost, or ::1)."
    );
    std::process::exit(1);
}

/// `host:port`, with brackets for IPv6.
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The server's own address and loopback names on its port, plus ALLOWED_HOSTS (comma separated).
pub fn allowed_hosts(host: &str, port: u16, extra: &str) -> Vec<String> {
    let names = [host, "localhost", "127.0.0.1", "::1"];
    let mut own: Vec<String> = names.map(|h| host_port(h, port)).into();
    if port == 80 {
        own.extend(names.map(|h| {
            if h.contains(':') {
                format!("[{h}]")
            } else {
                h.to_owned()
            }
        }));
    }
    let extra = extra
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(String::from);
    own.into_iter()
        .chain(extra)
        .map(|h| h.to_ascii_lowercase())
        .collect()
}

async fn auth(State(a): State<Arc<Auth>>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !a.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
        return (StatusCode::FORBIDDEN, "Unknown Host. Add it to ALLOWED_HOSTS.").into_response();
    }
    let source = request_source(&req, a.trust_forwarded);
    let (method, path) = (req.method().clone(), req.uri().path().to_string());
    let mut req = req;
    req.extensions_mut().insert(source.clone());
    // Signing in, the page to do it on, the public site, and asking for access need no credentials.
    let open = match method {
        Method::GET | Method::HEAD => path == "/login" || sso_path(&path).is_some() || site_file(&path).is_some() || path == "/api/signups/config",
        // Apple posts its answer to the callback (response_mode=form_post).
        Method::POST => path == "/api/auth/login" || sso_path(&path) == Some("callback") || path == "/api/signups",
        _ => false,
    };
    if open {
        return next.run(req).await;
    }
    let caller = match authenticate(&a, &req, &source) {
        Ok(c) => c,
        Err(res) => return *res,
    };
    let actor = match (&caller.principal, &caller.user) {
        (Principal::Bot, _) => a.bot_actor(req.headers()),
        (_, Some(u)) => users::actor(&a, u, caller.session.as_ref(), caller.method),
        (_, None) => Actor::operator().method(caller.method),
    };
    if caller.method != "session" && caller.principal != Principal::Bot {
        a.login_ok(&source, &actor, caller.method);
    }
    let by = Who { actor, source };
    let need = rbac::classify(&method, &path);
    let denied = |reason: &str, msg: String| {
        a.record(by.event("access.denied").outcome(Outcome::Denied).details(json!({ "method": method.as_str(), "path": path, "need": need.as_str(), "reason": reason })));
        ApiError(StatusCode::FORBIDDEN, msg).into_response()
    };
    if !rbac::allows(caller.principal, need) {
        let msg = match caller.principal {
            Principal::Bot => "Only a signed-in person can do this, not a Bot.".to_string(),
            Principal::User(r) => format!("Your role ({}) can't do this.", r.as_str()),
        };
        return denied("role", msg);
    }
    // A cookie, a password the browser cached, or ALLOW_NO_AUTH rides along on any request the
    // browser makes, so writes on them must come from our own pages. Only a Bearer token is sent on
    // purpose. Some GETs act too (opening a screen starts it), so only plain reads are exempt.
    let safe = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) && matches!(need, rbac::Perm::Account | rbac::Perm::Read | rbac::Perm::Review);
    let ambient = !req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).is_some_and(|h| h.starts_with("Bearer "));
    if ambient && !safe && !users::same_origin(req.headers()) {
        return denied("cross_site", "Cross-site request refused.".into());
    }
    let principal = caller.principal;
    req.extensions_mut().insert(principal);
    req.extensions_mut().insert(caller);
    req.extensions_mut().insert(by.clone());
    let res = next.run(req).await;
    if principal == Principal::Bot && res.status() == StatusCode::FORBIDDEN {
        a.record(by.event("access.denied").outcome(Outcome::Denied).details(json!({ "method": method.as_str(), "path": path })));
    }
    res
}

/// `/api/auth/sso` (the list), `/api/auth/sso/{id}/start`, and `/api/auth/sso/{id}/callback`: which one.
fn sso_path(path: &str) -> Option<&str> {
    match path.strip_prefix("/api/auth/sso")? {
        "" => Some("list"),
        rest => rest.strip_prefix('/').and_then(|r| r.split_once('/')).filter(|(id, step)| !id.is_empty() && !id.contains('/') && matches!(*step, "start" | "callback")).map(|(_, step)| step),
    }
}

/// Who sent this request, from (in order) the Authorization header, the session
/// cookie, or ALLOW_NO_AUTH. A request that sends bad credentials is refused even if
/// it also has good ones elsewhere.
fn authenticate(a: &Auth, req: &Request, source: &Source) -> Result<Caller, Box<Response>> {
    let h = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    let operator = |method: &'static str| Caller { principal: Principal::User(Role::Admin), user: a.operator(), session: None, method };
    let from_session = |(s, u): (db::Session, db::User)| Caller { principal: Principal::User(u.role), user: Some(u), session: Some(s), method: "session" };
    let fail = |method: &str, reason: Option<&str>, clear: bool| {
        a.login_failed(source, method, reason);
        Err(Box::new(unauthorized(a, req, clear)))
    };
    if let Some(t) = h.strip_prefix("Bearer ") {
        let t = t.trim();
        if !a.bot_token.is_empty() && same(t.as_bytes(), a.bot_token.as_bytes()) {
            return Ok(Caller { principal: Principal::Bot, user: None, session: None, method: "bot_token" });
        }
        return match a.session(t) {
            Some(found) => Ok(from_session(found)),
            None if t.starts_with(users::SESSION_PREFIX) => fail("session", Some("unknown_or_expired"), false),
            None => fail("bot_token", None, false),
        };
    }
    if let Some(b) = h.strip_prefix("Basic ") {
        if !a.break_glass {
            // Browsers keep sending a password they cached before break-glass was turned off.
            if let Some(found) = users::cookie_token(req.headers()).and_then(|t| a.session(&t)) {
                return Ok(from_session(found));
            }
            return fail("password", Some("break_glass_off"), false);
        }
        let ok = base64_decode(b).is_some_and(|creds| {
            let pass = creds.splitn(2, |c| *c == b':').nth(1).unwrap_or_default();
            !a.password.is_empty() && same(pass, a.password.as_bytes())
        });
        if a.allow_no_auth {
            return Ok(operator(if ok { "password" } else { "none" }));
        }
        // Every API route takes the password, so guesses here count against the sign-in limiter too.
        let (ip, at) = (source.ip.clone().unwrap_or_default(), db::now());
        if let Some(retry) = a.limiter.blocked(&ip, at) {
            return Err(Box::new(users::too_many(retry)));
        }
        if !ok {
            a.limiter.fail(&ip, at);
            return fail("password", None, false);
        }
        return Ok(operator("password"));
    }
    if !h.is_empty() {
        return fail("unknown_scheme", None, false);
    }
    if let Some(t) = users::cookie_token(req.headers()) {
        return match a.session(&t) {
            Some(found) => Ok(from_session(found)),
            None if a.allow_no_auth => Ok(operator("none")),
            None => fail("session", Some("unknown_or_expired"), true),
        };
    }
    if a.allow_no_auth {
        return Ok(operator("none"));
    }
    // No credentials at all: a browser's first visit, or a client that hasn't signed in.
    Err(Box::new(unauthorized(a, req, false)))
}

/// Not signed in. A browser opening a page without credentials goes to the
/// sign-in page instead of a 401. The Basic challenge (break-glass) is only offered
/// when the browser itself would show it to a person: not to the web app's own
/// fetches, or a cookie session that ended would pop up a password box.
fn unauthorized(a: &Auth, req: &Request, clear_cookie: bool) -> Response {
    let h = req.headers();
    let page = !req.uri().path().starts_with("/api/") && matches!(*req.method(), Method::GET | Method::HEAD);
    // With break-glass on, a page sent with a wrong password gets the browser's password box again.
    let mut res = if page && (!a.break_glass || !h.contains_key(header::AUTHORIZATION)) {
        (StatusCode::SEE_OTHER, [(header::LOCATION, "/login")]).into_response()
    } else {
        ApiError(StatusCode::UNAUTHORIZED, "Login required".into()).into_response()
    };
    let fetch = h.get("sec-fetch-mode").and_then(|v| v.to_str().ok()).is_some_and(|m| m != "navigate");
    if res.status() == StatusCode::UNAUTHORIZED && a.break_glass && !fetch && users::cookie_token(h).is_none() {
        res.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"Bots\""));
    }
    if clear_cookie {
        res.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_static(users::clear_cookie()));
    }
    res
}

/// Approvals and policy changes are for people. Bots hold a token too, so without
/// this a Bot could approve its own request. The auth middleware already refuses
/// these by role; this is the second lock.
fn need_user(p: Principal) -> Res<()> {
    match p {
        Principal::User(_) => Ok(()),
        Principal::Bot => Err(ApiError(StatusCode::FORBIDDEN, "Only a signed-in person can do this, not a Bot.".into())),
    }
}

/// Constant-time comparison. Both sides are hashed first, so the time taken doesn't show a secret's length either.
fn same(a: &[u8], b: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    let (a, b) = (Sha256::digest(a), Sha256::digest(b));
    std::hint::black_box(a.iter().zip(b.iter()).fold(0, |acc, (x, y)| acc | (x ^ y))) == 0
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in s.trim().bytes().filter(|c| *c != b'=') {
        buf = (buf << 6) | T.iter().position(|x| *x == c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

// The public site (`site/`: the landing page and the "Get started" form) and the
// built-in console (`web/`, at /console/). Both are embedded in the binary; set
// SITE_DIR or WEB_DIR to serve from disk while editing them. ADR 0022.

/// The `site/` file a public path serves.
fn site_file(path: &str) -> Option<&'static str> {
    Some(match path {
        "/" | "/index.html" => "index.html",
        "/get-started" | "/get-started/" => "get-started.html",
        "/site/site.css" => "assets/site.css",
        "/site/get-started.js" => "assets/get-started.js",
        "/site/mark.svg" => "assets/mark.svg",
        _ => return None,
    })
}

/// The public pages run only their own scripts, plus Cloudflare's when Turnstile is on.
pub const SITE_CSP: &str = "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; \
     style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

fn content_type(file: &str) -> &'static str {
    match file.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        _ => "text/css; charset=utf-8",
    }
}

fn site(file: &'static str) -> Response {
    let body = match SITE_DIR.get().and_then(|d| d.as_ref()) {
        Some(dir) => std::fs::read_to_string(dir.join(file)).unwrap_or_default(),
        None => match file {
            "index.html" => include_str!("../../site/index.html"),
            "get-started.html" => include_str!("../../site/get-started.html"),
            "assets/site.css" => include_str!("../../site/assets/site.css"),
            "assets/get-started.js" => include_str!("../../site/assets/get-started.js"),
            _ => include_str!("../../site/assets/mark.svg"),
        }
        .to_string(),
    };
    (
        [
            (header::CONTENT_TYPE, content_type(file)),
            (header::CACHE_CONTROL, "no-cache"),
            (header::CONTENT_SECURITY_POLICY, SITE_CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "strict-origin-when-cross-origin"),
        ],
        body,
    )
        .into_response()
}

async fn web(uri: axum::http::Uri) -> Response {
    let path = uri.path();
    if let Some(file) = site_file(path) {
        return site(file);
    }
    let file = match path {
        "/console" => return (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, "/console/")]).into_response(),
        // The web client is served by Caddy; without it, /app/ (the landing page's "Sign in") opens the console.
        p if p == "/app" || p.starts_with("/app/") => return (StatusCode::SEE_OTHER, [(header::LOCATION, "/console/")]).into_response(),
        "/console/" | "/console/index.html" => "index.html",
        "/console/app.js" => "app.js",
        "/console/styles.css" => "styles.css",
        _ => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let body = match WEB_DIR.get().and_then(|d| d.as_ref()) {
        Some(dir) => std::fs::read_to_string(dir.join(file)).unwrap_or_default(),
        None => match file {
            "index.html" => include_str!("../../web/index.html"),
            "app.js" => include_str!("../../web/app.js"),
            _ => include_str!("../../web/styles.css"),
        }
        .to_string(),
    };
    ([(header::CONTENT_TYPE, content_type(file)), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

// Live updates: one Server-Sent Events stream with everything.

async fn events(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>) -> impl IntoResponse {
    // Each stream carries only the Bots its caller can see (ADR 0017).
    let mut filter = acl::StreamFilter::new(viewer(&app, &c, &by));
    let session = c.session.map(|s| s.id);
    let user = c.user.filter(|_| session.is_some()).map(|u| u.id);
    // The stream outlives the request that opened it, so it closes within seconds of
    // its session being revoked, expiring, or its user being disabled, and follows
    // role changes.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<SseEvent, Infallible>>(64);
    let mut sub = app.tx.subscribe();
    let cfg = a.sessions;
    const RESYNC: &str = r#"{"type":"resync"}"#;
    tokio::spawn(async move {
        let mut check = tokio::time::interval(SESSION_RECHECK);
        loop {
            tokio::select! {
                r = sub.recv() => {
                    let data = match r {
                        Ok(d) => d,
                        // A slow client that missed events is told to reload its state.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => RESYNC.into(),
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    };
                    let Some(data) = filter.apply(&app.db, &data) else { continue };
                    if tx.send(Ok(SseEvent::default().data(data))).await.is_err() {
                        break;
                    }
                }
                _ = check.tick(), if session.is_some() => {
                    if !session.as_deref().is_some_and(|s| app.db.session_is_live(s, db::now(), cfg.idle_ms, cfg.max_ms)) {
                        break;
                    }
                    let now = match user.as_deref().and_then(|id| app.db.user(id)) {
                        Some(u) if u.role == Role::Admin => Viewer::All,
                        Some(u) => Viewer::User { id: u.id, role: u.role },
                        None => Viewer::Nobody,
                    };
                    if now != filter.viewer {
                        filter.reset(now);
                        if tx.send(Ok(SseEvent::default().data(RESYNC))).await.is_err() {
                            break;
                        }
                    }
                }
                _ = tx.closed() => break,
            }
        }
    });
    ([("x-accel-buffering", "no")], Sse::new(Box::pin(ReceiverStream::new(rx)) as EventStream).keep_alive(KeepAlive::default()))
}

#[cfg(not(test))]
const SESSION_RECHECK: Duration = Duration::from_secs(5);
#[cfg(test)]
const SESSION_RECHECK: Duration = Duration::from_millis(100);

async fn login_page() -> Response {
    let body = match WEB_DIR.get().and_then(|d| d.as_ref()) {
        Some(dir) => std::fs::read_to_string(dir.join("login.html")).unwrap_or_default(),
        None => include_str!("../../web/login.html").to_string(),
    };
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

// Bots

/// Every Bot the caller can see, each with their `access` to it.
fn visible_bots(app: &App, c: &Caller, by: &Who) -> Vec<Value> {
    viewer(app, c, by).bots(&app.db).iter().map(|(b, a)| bot_view_for(app, b, *a)).collect()
}

async fn state(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>) -> Json<Value> {
    let bots = visible_bots(&app, &c, &by);
    let approvals = if rbac::allows(c.principal, Perm::Review) { visible_approvals(&app, &c, &by, Some("pending"), None, 200) } else { vec![] };
    // The owner keeps USER_NAME, as before users existed.
    let name = match &c.user {
        Some(u) if u.id != users::OPERATOR => u.name.clone(),
        _ => env("USER_NAME", "You"),
    };
    let role = match c.principal {
        Principal::User(r) => json!(r),
        Principal::Bot => json!("bot"),
    };
    Json(json!({
        "me": { "name": name, "id": c.user.as_ref().map(|u| &u.id), "email": c.user.as_ref().and_then(|u| u.email.as_ref()), "role": role, "permissions": rbac::granted(c.principal), "session": c.session.is_some() },
        "harnesses": adapters::installed(),
        "defaultHarness": app.cfg.default_harness,
        "bots": bots,
        "policy": app.db.global_policy(),
        "approvals": approvals,
    }))
}

/// Models and reasoning efforts the harness offers on this server.
async fn list_models(Path(name): Path<String>) -> Res {
    if adapters::get(&name).is_none() {
        return Err(not_found("Harness"));
    }
    let list = tokio::task::spawn_blocking(move || adapters::models(&name)).await.unwrap_or_default();
    Ok(Json(json!(list)))
}

async fn list_bots(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>) -> Json<Value> {
    Json(json!(visible_bots(&app, &c, &by)))
}

fn need_bot(app: &App, id: &str) -> Res<db::Bot> {
    app.db.bot(id).ok_or_else(|| not_found("Bot"))
}

/// Whose Bot access a request has. A Bot that says who it is acts with its owner's.
/// Bots share one token, so that's a guardrail, not a boundary (ADR 0017).
fn viewer(app: &App, c: &Caller, by: &Who) -> Viewer {
    match (c.principal, by.actor.kind, by.actor.id.as_deref().and_then(|id| app.db.bot(id))) {
        (Principal::Bot, audit::ActorKind::Bot, Some(b)) => Viewer::owner_of(&app.db, &b),
        _ => Viewer::of(c),
    }
}

/// The Bot, when the caller has at least `need` on it (ADR 0017). A Bot they can't see
/// is a 404, the same as one that doesn't exist; one they can see but not use is a 403.
fn need_bot_access(app: &App, c: &Caller, by: &Who, id: &str, need: Access) -> Res<(db::Bot, Access)> {
    let bot = need_bot(app, id)?;
    let has = viewer(app, c, by).access(&app.db, &bot);
    if has >= need {
        return Ok((bot, has));
    }
    // The auth middleware already records every 403 a Bot gets.
    if c.principal != Principal::Bot || has == Access::None {
        let details = json!({ "reason": "bot_acl", "need": need, "has": has });
        app.db.record(&by.event("access.denied").target("bot", id).bot(id).outcome(Outcome::Denied).details(details));
    }
    Err(match (has, c.principal) {
        (Access::None, _) => not_found("Bot"),
        (_, Principal::User(Role::Readonly)) => ApiError(StatusCode::FORBIDDEN, "Your role (readonly) can only view Bots.".into()),
        (_, _) if need == Access::Manage => ApiError(StatusCode::FORBIDDEN, "Only this Bot's owner or an admin can do this.".into()),
        _ => ApiError(StatusCode::FORBIDDEN, "You can view this Bot but not use it. Ask its owner for operator access.".into()),
    })
}

/// Newest approvals for Bots the caller can see; `bot` narrows to one they can see.
fn visible_approvals(app: &App, c: &Caller, by: &Who, status: Option<&str>, bot: Option<&str>, limit: i64) -> Vec<db::Approval> {
    let viewer = viewer(app, c, by);
    if viewer == Viewer::All || bot.is_some() {
        return app.db.approvals(status, bot, limit);
    }
    let ids: Vec<String> = viewer.bots(&app.db).into_iter().map(|(b, _)| b.id).collect();
    app.db.approvals_among(status, &ids, limit)
}

/// A Bot view as this caller sees it.
fn bot_view_for(app: &App, b: &db::Bot, access: Access) -> Value {
    let mut v = app.bot_view(b);
    v["access"] = json!(access);
    v
}

fn bot_patch(v: &Value) -> Res<BotPatch> {
    let mut p = BotPatch::default();
    if let Some(n) = v["name"].as_str().map(str::trim).filter(|n| !n.is_empty()) {
        p.name = Some(n.chars().take(60).collect());
    }
    if let Some(c) = v["color"].as_str().filter(|c| c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|x| x.is_ascii_hexdigit())) {
        p.color = Some(c.into());
    }
    if let Some(s) = v["shape"].as_str().filter(|s| SHAPES.contains(s)) {
        p.shape = Some(s.into());
    }
    if let Some(h) = v["hidden"].as_bool() {
        p.hidden = Some(h);
    }
    match &v["model"] {
        Value::Null if v.get("model").is_some() => p.model = Some(None),
        Value::String(m) => p.model = Some(Some(m.trim().to_string()).filter(|m| !m.is_empty())),
        _ => {}
    }
    // Effort words like "high" or "xhigh". Null = the harness default.
    match &v["effort"] {
        Value::Null if v.get("effort").is_some() => p.effort = Some(None),
        Value::String(e) if e.is_empty() => p.effort = Some(None),
        Value::String(e) if e.len() <= 20 && e.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') => {
            p.effort = Some(Some(e.clone()))
        }
        Value::String(_) => return Err(bad("Invalid effort")),
        _ => {}
    }
    if let Some(h) = v.get("harness") {
        let h = h.as_str().filter(|h| adapters::get(h).is_some());
        let h = h.ok_or_else(|| bad(format!("Harness must be one of: {}", adapters::NAMES.join(", "))))?;
        p.harness = Some(h.into());
    }
    Ok(p)
}

fn visibility_field(v: &Value) -> Res<Option<Visibility>> {
    match v.get("visibility") {
        None | Some(Value::Null) => Ok(None),
        Some(x) => x.as_str().and_then(Visibility::parse).map(Some).ok_or_else(|| bad("Visibility must be private or shared")),
    }
}

async fn create_bot(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    let p = bot_patch(&v)?;
    let name = p.name.ok_or_else(|| bad("Name is required"))?;
    let harness = p.harness.unwrap_or_else(|| app.cfg.default_harness.clone());
    // Shared unless asked otherwise, as every Bot was before ACLs.
    let visibility = visibility_field(&v)?.unwrap_or(Visibility::Shared);
    // A person owns what they make. A Bot's new Bot belongs to that Bot's owner.
    let owner = match (&c.user, by.actor.kind) {
        (Some(u), _) => u.id.clone(),
        (None, audit::ActorKind::Bot) => by.actor.id.as_deref().and_then(|id| app.db.bot(id)).map_or(users::OPERATOR.into(), |b| b.owner_id),
        (None, _) => users::OPERATOR.into(),
    };
    let bot = app.db.create_bot_owned(
        &name,
        p.color.as_deref().unwrap_or(pick(&COLORS)),
        p.shape.as_deref().unwrap_or(pick(&SHAPES)),
        &harness,
        p.model.flatten().as_deref(),
        false,
        &owner,
        visibility,
    );
    app.init_bot_files(&bot);
    app.push_bot(&bot.id);
    let details = json!({ "name": bot.name, "harness": bot.harness, "model": bot.model, "owner": bot.owner_id, "visibility": bot.visibility });
    app.db.record(&by.event("bot.created").target("bot", &bot.id).bot(&bot.id).details(details));
    let access = viewer(&app, &c, &by).access(&app.db, &bot);
    Ok((StatusCode::CREATED, Json(bot_view_for(&app, &bot, access))))
}

/// Settings that changed, as `{field: {from, to}}`.
fn bot_changes(before: &db::Bot, after: &db::Bot) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    let mut diff = |k: &str, a: Value, b: Value| {
        if a != b {
            m.insert(k.into(), json!({ "from": a, "to": b }));
        }
    };
    diff("name", json!(before.name), json!(after.name));
    diff("color", json!(before.color), json!(after.color));
    diff("shape", json!(before.shape), json!(after.shape));
    diff("harness", json!(before.harness), json!(after.harness));
    diff("model", json!(before.model), json!(after.model));
    diff("effort", json!(before.effort), json!(after.effort));
    diff("hidden", json!(before.hidden), json!(after.hidden));
    m
}

async fn update_bot(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    let (bot, access) = need_bot_access(&app, &c, &by, &id, Access::Manage)?;
    let mut p = bot_patch(&v)?;
    if p.harness.as_ref().is_some_and(|h| *h != bot.harness) {
        p.session_id = Some(None); // sessions don't carry across harnesses
    }
    app.db.update_bot(&id, p);
    app.push_bot(&id);
    let after = need_bot(&app, &id)?;
    let changes = bot_changes(&bot, &after);
    if !changes.is_empty() {
        app.db.record(&by.event("bot.updated").target("bot", &id).bot(&id).details(json!({ "changes": changes })));
    }
    Ok(Json(bot_view_for(&app, &after, access)))
}

async fn delete_bot(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let (bot, _) = need_bot_access(&app, &c, &by, &id, Access::Manage)?;
    if bot.primary {
        return Err(bad("The primary Bot can't be deleted"));
    }
    app.stop(&id);
    if let Some(screens) = &app.screens {
        screens.remove(&id).await;
    }
    app.db.delete_bot(&id);
    app.db.record(&by.event("bot.deleted").target("bot", &id).bot(&id).details(json!({ "name": bot.name, "harness": bot.harness })));
    app.send(json!({ "type": "botDeleted", "botId": id }));
    Ok(Json(json!({ "ok": true })))
}

// Bot ACLs (ADR 0017): owner, visibility, and grants.

fn person(u: Option<db::User>, id: &str) -> Value {
    match u {
        Some(u) => json!({ "id": u.id, "name": u.name, "email": u.email }),
        None => json!({ "id": id, "name": null, "email": null }),
    }
}

/// Who can see a Bot. Grants are only shown to those who can change them.
fn access_view(app: &App, b: &db::Bot, access: Access) -> Value {
    let mut v = json!({
        "botId": b.id,
        "owner": person(app.db.user(&b.owner_id), &b.owner_id),
        "visibility": b.visibility,
        "access": access,
    });
    if access == Access::Manage {
        let grants: Vec<Value> = app
            .db
            .grants(&b.id)
            .into_iter()
            .map(|g| json!({ "user": person(app.db.user(&g.user_id), &g.user_id), "level": g.level, "createdAt": g.created_at, "createdBy": g.created_by }))
            .collect();
        v["grants"] = json!(grants);
    }
    v
}

/// After an ACL change: everyone's lists and live streams start over, since who
/// sees the Bot may have changed. The resync goes first: it clears each stream's
/// cached access, so the Bot's update reaches exactly who can now see it.
/// When someone may have lost access, its screen also gets a new token: the
/// proxy sends screen traffic straight to voxl, so an old link would keep working.
/// That waits on the screen, so it comes after the resync: streams must not run on
/// stale access meanwhile.
async fn acl_changed(app: &App, id: &str, narrowed: bool) {
    app.send(json!({ "type": "resync" }));
    app.push_bot(id);
    if narrowed && let Some(screens) = &app.screens {
        screens.rotate_token(id).await;
    }
}

async fn get_access(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let (bot, access) = need_bot_access(&app, &c, &by, &id, Access::View)?;
    Ok(Json(access_view(&app, &bot, access)))
}

/// Body: `{visibility?: "private" | "shared", owner?: <user id or email>}`. The owner
/// or an admin can change visibility; only an admin can give a Bot to someone else.
async fn update_access(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    need_user(c.principal)?;
    let (bot, _) = need_bot_access(&app, &c, &by, &id, Access::Manage)?;
    let visibility = visibility_field(&v)?;
    let owner = match v.get("owner") {
        None | Some(Value::Null) => None,
        Some(o) => {
            if c.principal != Principal::User(Role::Admin) {
                return Err(ApiError(StatusCode::FORBIDDEN, "Only an admin can change who owns a Bot.".into()));
            }
            let key = o.as_str().map(str::trim).filter(|k| !k.is_empty()).ok_or_else(|| bad("owner must be a user id or email"))?;
            let u = app.db.find_user(key).ok_or_else(|| not_found("User"))?;
            if !u.active() {
                return Err(bad("That user is disabled"));
            }
            Some(u)
        }
    };
    if visibility.is_none() && owner.is_none() {
        return Err(bad("Send visibility or owner"));
    }
    let mut narrowed = false;
    if let Some(to) = visibility.filter(|to| *to != bot.visibility) {
        app.db.set_bot_visibility(&id, to);
        app.db.record(&by.event("bot.visibility_changed").target("bot", &id).bot(&id).details(json!({ "from": bot.visibility, "to": to })));
        narrowed |= to == Visibility::Private;
    }
    if let Some(u) = owner.filter(|u| u.id != bot.owner_id) {
        app.db.set_bot_owner(&id, &u.id);
        // The new owner manages it anyway; a leftover grant would only confuse.
        app.db.remove_grant(&id, &u.id);
        app.db.record(&by.event("bot.owner_changed").target("bot", &id).bot(&id).details(json!({ "from": bot.owner_id, "to": u.id })));
        narrowed = true;
    }
    acl_changed(&app, &id, narrowed).await;
    let after = need_bot(&app, &id)?;
    let access = viewer(&app, &c, &by).access(&app.db, &after);
    Ok(Json(access_view(&app, &after, access)))
}

/// Body: `{level: "viewer" | "operator"}`. Adds or changes one user's grant.
async fn put_grant(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path((id, key)): Path<(String, String)>, Json(v): Json<Value>) -> Res {
    need_user(c.principal)?;
    let (bot, access) = need_bot_access(&app, &c, &by, &id, Access::Manage)?;
    let level = v["level"].as_str().and_then(acl::Grant::parse).ok_or_else(|| bad("level must be viewer or operator"))?;
    let u = app.db.find_user(&key).ok_or_else(|| not_found("User"))?;
    if u.id == bot.owner_id {
        return Err(ApiError(StatusCode::CONFLICT, "That user owns this Bot already.".into()));
    }
    let by_id = c.user.as_ref().map_or(users::OPERATOR, |u| u.id.as_str());
    let before = app.db.set_grant(&id, &u.id, level, by_id);
    if before != Some(level) {
        app.db.record(&by.event("bot.access_granted").target("bot", &id).bot(&id).details(json!({ "user": u.id, "level": level, "from": before })));
        acl_changed(&app, &id, before == Some(acl::Grant::Operator) && level == acl::Grant::Viewer).await;
    }
    Ok(Json(access_view(&app, &bot, access)))
}

async fn delete_grant(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path((id, key)): Path<(String, String)>) -> Res {
    need_user(c.principal)?;
    let (bot, access) = need_bot_access(&app, &c, &by, &id, Access::Manage)?;
    let u = app.db.find_user(&key).ok_or_else(|| not_found("User"))?;
    let level = app.db.remove_grant(&id, &u.id).ok_or_else(|| not_found("Grant"))?;
    app.db.record(&by.event("bot.access_revoked").target("bot", &id).bot(&id).details(json!({ "user": u.id, "level": level })));
    acl_changed(&app, &id, true).await;
    Ok(Json(access_view(&app, &bot, access)))
}

async fn mark_read(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_bot_access(&app, &c, &by, &id, Access::Operate)?;
    app.db.update_bot(&id, BotPatch { unread: Some(false), ..Default::default() });
    app.push_bot(&id);
    Ok(Json(json!({ "ok": true })))
}

async fn stop_bot(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_bot_access(&app, &c, &by, &id, Access::Operate)?;
    app.stop(&id);
    app.db.record(&by.event("bot.stopped").target("bot", &id).bot(&id));
    Ok(Json(json!({ "ok": true })))
}

// Messages

async fn list_messages(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_bot_access(&app, &c, &by, &id, Access::View)?;
    Ok(Json(json!(app.db.messages(&id, 200))))
}

async fn send_message(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    need_bot_access(&app, &c, &by, &id, Access::Operate)?;
    let text = v["text"].as_str().map(str::trim).filter(|t| !t.is_empty()).ok_or_else(|| bad("Text is required"))?;
    let text: String = text.chars().take(100_000).collect();
    // Answering a choice card: remember which option was picked.
    let mut handoff = None;
    let answered = v["answer"]["messageId"].as_i64().and_then(|mid| app.db.message(mid)).filter(|m| m.bot_id == id);
    let answered_id = answered.as_ref().map(|m| m.id);
    if let (Some(mid), Some(opt)) = (answered_id, v["answer"]["option"].as_u64())
        && let Some(mut q) = answered.and_then(|m| m.question)
    {
        if q["handoff"] == json!(true) && q["picked"].is_null() {
            handoff = Some((mid, q["options"][opt as usize].as_str().map(String::from)));
        }
        q["picked"] = json!(opt);
        app.db.set_question(mid, &q);
    }
    let waiter = answered_id.and_then(|mid| app.take_handoff(mid));
    if let Some((mid, option)) = handoff {
        let details = json!({ "option": option, "botWasWaiting": waiter.is_some() });
        app.db.record(&by.event("handoff.answered").target("handoff", &mid.to_string()).bot(&id).details(details));
    }
    // Answering a handoff card the Bot is still waiting on: hand the answer to it directly.
    if let Some(tx) = waiter {
        let msg = app.db.add_message(&id, "user", &text, None, false, Some("done"));
        app.push_message(&msg);
        let _ = tx.send(text);
        return Ok((StatusCode::ACCEPTED, Json(json!(msg))));
    }
    let mut msg = app.db.add_message(&id, "user", &text, None, false, Some("queued"));
    app.db.set_requested_by(msg.id, &by);
    msg.requested_by = Some(by.clone());
    app.push_message(&msg);
    app.enqueue(msg.clone());
    Ok((StatusCode::ACCEPTED, Json(json!(msg))))
}

// Bot to Bot: `botctl ask`. Waits for the reply and returns it as plain text.

async fn ask(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Result<String, ApiError> {
    let from_id = v["from"].as_str().unwrap_or("");
    let from = app.db.bot(from_id).ok_or_else(|| bad("Unknown asking Bot (BOT_ID)"))?;
    // A Bot asks with its owner's access. A person needs to be able to run both Bots.
    let viewer = match c.principal {
        Principal::Bot => Viewer::owner_of(&app.db, &from),
        Principal::User(_) => {
            need_bot_access(&app, &c, &by, from_id, Access::Operate)?;
            viewer(&app, &c, &by)
        }
    };
    let to_key = v["to"].as_str().map(str::trim).unwrap_or("");
    let bots: Vec<db::Bot> = viewer.bots(&app.db).into_iter().filter(|(_, a)| *a >= Access::Operate).map(|(b, _)| b).collect();
    let to = bots
        .iter()
        .find(|b| b.id == to_key)
        .or_else(|| bots.iter().find(|b| b.name.eq_ignore_ascii_case(to_key)))
        .ok_or_else(|| bad(format!("No Bot named \"{to_key}\". Run `botctl bots` to list them.")))?;
    if to.id == from.id {
        return Err(bad("You can't ask yourself"));
    }
    let text = v["text"].as_str().map(str::trim).filter(|t| !t.is_empty()).ok_or_else(|| bad("Message is required"))?;
    // A Bot asks as itself (whatever Bot botctl named), for its owner; a person as themselves.
    let by = match c.principal {
        Principal::Bot => Who { actor: Actor::for_bot(&from).method("bot_token"), source: by.source.clone() },
        Principal::User(_) => by,
    };
    app.db.record(&by.event("bot.asked").target("bot", &to.id).bot(&from.id).details(json!({ "to": to.name })));
    let wait = Duration::from_secs(9 * 60); // under the 10 minute max most harnesses allow a command
    Ok(match app.ask(&from, to, text, wait, &by).await {
        Some(reply) => reply,
        None => format!("{} is still working on it. Their reply will arrive later as a new message.", to.name),
    })
}

// Screens: the live view of a Bot's screen. Opening it starts the screen.

async fn screen_info(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    // The link gives control of the screen.
    need_bot_access(&app, &c, &by, &id, Access::Operate)?;
    let off = || ApiError(StatusCode::NOT_FOUND, "Screens are off on this server. Install Xvfb, openbox, and voxl.".into());
    let screens = app.screens.as_ref().filter(|_| screen::on_path("voxl")).ok_or_else(off)?;
    let info = screens.ensure(&id, |b| app.is_running(b)).await;
    let info = info.ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, "All screens are in use. Try again when a Bot finishes.".into()))?;
    // A frame loaded before voxl listens gets the proxy's 502 and stays blank, so only hand out a link that works.
    if !screen::wait_for_port(info.port, 50).await {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "The screen is still starting. Try again in a moment.".into()));
    }
    // The proxy in front serves /screen/<port>/ from that local voxl port.
    Ok(Json(json!({ "url": format!("/screen/{}/?token={}", info.port, info.token) })))
}

// A Bot hands its screen to the user: `botctl handoff`. Waits for "Done".

async fn handoff(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Result<String, ApiError> {
    let from_id = v["from"].as_str().unwrap_or("");
    let bot = app.db.bot(from_id).ok_or_else(|| bad("Unknown Bot (BOT_ID)"))?;
    if let Principal::User(_) = c.principal {
        need_bot_access(&app, &c, &by, from_id, Access::Operate)?;
    }
    let text = v["text"].as_str().map(str::trim).filter(|t| !t.is_empty()).ok_or_else(|| bad("Say what you need"))?;
    let text: String = text.chars().take(300).collect();
    let wait = Duration::from_secs(9 * 60); // under the 10 minute max most harnesses allow a command
    Ok(match app.handoff(&bot, &text, wait).await {
        Some(answer) => format!("The user answered: {answer}"),
        None => "The user hasn't answered yet. Stop here and tell them in one line what you need. You'll get their answer as a new message.".into(),
    })
}

// Routines

async fn list_routines(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_bot_access(&app, &c, &by, &id, Access::View)?;
    Ok(Json(json!(app.db.routines(Some(&id)))))
}

/// Routine fields from a create or edit body. Absent fields are None; present ones
/// must be non-empty strings (trimmed), a valid cron, and a boolean `enabled`.
#[derive(Debug, Default, PartialEq)]
struct RoutineFields {
    name: Option<String>,
    cron: Option<String>,
    instruction: Option<String>,
    enabled: Option<bool>,
}

fn routine_fields(v: &Value) -> Res<RoutineFields> {
    let text = |key: &str, max: usize| -> Res<Option<String>> {
        match v.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.trim().chars().take(max).collect())),
            Some(_) => Err(bad(format!("{key} can't be empty"))),
        }
    };
    let f = RoutineFields {
        name: text("name", 100)?,
        cron: text("cron", 100)?,
        instruction: text("instruction", 100_000)?,
        enabled: match v.get("enabled") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(b)) => Some(*b),
            Some(_) => return Err(bad("enabled must be true or false")),
        },
    };
    if let Some(c) = &f.cron {
        cron::parse(c).map_err(bad)?;
    }
    Ok(f)
}

async fn create_routine(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    need_bot_access(&app, &c, &by, &id, Access::Operate)?;
    let f = routine_fields(&v)?;
    let (Some(name), Some(cron_expr), Some(instruction)) = (f.name, f.cron, f.instruction) else {
        return Err(bad("name, cron, and instruction are required"));
    };
    let r = app.db.add_routine(&id, &name, &cron_expr, &instruction);
    if f.enabled == Some(false) {
        app.db.update_routine(&r.id, None, None, None, Some(false));
    }
    let r = app.db.routine(&r.id).ok_or_else(|| not_found("Routine"))?;
    app.db.record(&by.event("routine.created").target("routine", &r.id).bot(&id).details(json!({ "name": r.name, "cron": r.cron, "enabled": r.enabled })));
    Ok((StatusCode::CREATED, Json(json!(r))))
}

/// Logs `routine.enabled`/`routine.disabled`, and `routine.updated` for other changes.
/// The instruction is a message to the Bot, so only the fact that it changed is kept.
fn routine_events(by: &Who, before: &db::Routine, after: &db::Routine) -> Vec<Event> {
    let mut out = Vec::new();
    let ev = |action: &str| by.event(action).target("routine", &after.id).bot(&after.bot_id);
    if before.enabled != after.enabled {
        let action = if after.enabled { "routine.enabled" } else { "routine.disabled" };
        out.push(ev(action).details(json!({ "name": after.name })));
    }
    let mut changes = serde_json::Map::new();
    if before.name != after.name {
        changes.insert("name".into(), json!({ "from": before.name, "to": after.name }));
    }
    if before.cron != after.cron {
        changes.insert("cron".into(), json!({ "from": before.cron, "to": after.cron }));
    }
    if before.instruction != after.instruction {
        changes.insert("instruction".into(), json!("changed"));
    }
    if !changes.is_empty() {
        out.push(ev("routine.updated").details(json!({ "name": after.name, "changes": changes })));
    }
    out
}

/// The routine, when the caller can run its Bot. A routine on a hidden Bot is a 404.
fn need_routine(app: &App, c: &Caller, by: &Who, id: &str) -> Res<db::Routine> {
    let r = app.db.routine(id).ok_or_else(|| not_found("Routine"))?;
    need_bot_access(app, c, by, &r.bot_id, Access::Operate).map_err(|e| if e.0 == StatusCode::NOT_FOUND { not_found("Routine") } else { e })?;
    Ok(r)
}

async fn update_routine(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    let before = need_routine(&app, &c, &by, &id)?;
    let f = routine_fields(&v)?;
    app.db.update_routine(&id, f.name.as_deref(), f.cron.as_deref(), f.instruction.as_deref(), f.enabled);
    let after = app.db.routine(&id).ok_or_else(|| not_found("Routine"))?;
    for e in routine_events(&by, &before, &after) {
        app.db.record(&e);
    }
    Ok(Json(json!(after)))
}

async fn delete_routine(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let r = need_routine(&app, &c, &by, &id)?;
    app.db.delete_routine(&id);
    app.db.record(&by.event("routine.deleted").target("routine", &id).bot(&r.bot_id).details(json!({ "name": r.name, "cron": r.cron })));
    Ok(Json(json!({ "ok": true })))
}

// Harness policy: global default, per-Bot overrides, and allow/deny rules.
// Anyone signed in can read it; only a person can change it.

fn classes_view() -> Value {
    json!(policy::CLASSES.iter().map(|(id, label)| json!({ "id": id, "label": label })).collect::<Vec<_>>())
}

async fn get_policy(State(app): State<AppState>) -> Json<Value> {
    Json(json!({ "policy": app.db.global_policy(), "classes": classes_view(), "rules": app.db.rules(None) }))
}

async fn put_policy(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res {
    need_user(who)?;
    let before = app.db.global_policy();
    let after = policy::parse_patch(&v).map_err(bad)?.apply(&before);
    app.db.set_global_policy(&after);
    app.db.record(&by.event("policy.updated").target("policy", "global").details(json!({ "before": before, "after": after })));
    app.send(json!({ "type": "policy", "policy": after }));
    app.stop_unguarded_runs();
    for b in app.db.bots() {
        app.push_bot(&b.id);
    }
    Ok(Json(json!({ "policy": after })))
}

fn bot_policy_view(app: &App, id: &str) -> Value {
    json!({ "policy": app.db.effective_policy(id), "override": app.db.bot_override(id), "classes": classes_view(), "rules": app.db.rules(Some(id)) })
}

async fn get_bot_policy(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_bot_access(&app, &c, &by, &id, Access::View)?;
    Ok(Json(bot_policy_view(&app, &id)))
}

async fn put_bot_policy(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    need_user(who)?;
    need_bot(&app, &id)?;
    let before = app.db.bot_override(&id);
    let mut o = before.clone().unwrap_or_default();
    o.merge(policy::parse_patch(&v).map_err(bad)?);
    app.db.set_bot_override(&id, Some(&o));
    app.db.record(&by.event("policy.updated").target("policy", &id).bot(&id).details(json!({ "before": before, "after": o })));
    app.stop_unguarded_runs();
    app.push_bot(&id);
    Ok(Json(bot_policy_view(&app, &id)))
}

async fn delete_bot_policy(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_user(who)?;
    need_bot(&app, &id)?;
    let before = app.db.bot_override(&id);
    app.db.set_bot_override(&id, None);
    app.db.record(&by.event("policy.reset").target("policy", &id).bot(&id).details(json!({ "before": before })));
    app.stop_unguarded_runs();
    app.push_bot(&id);
    Ok(Json(bot_policy_view(&app, &id)))
}

async fn list_rules(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Query(q): Query<HashMap<String, String>>) -> Res {
    let bot = q.get("bot").map(String::as_str).filter(|b| !b.is_empty());
    if let Some(b) = bot {
        need_bot_access(&app, &c, &by, b, Access::View)?;
    }
    Ok(Json(json!(app.db.rules(bot))))
}

async fn add_rule(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    need_user(who)?;
    let bot = v["botId"].as_str().filter(|b| !b.is_empty());
    if let Some(b) = bot {
        need_bot(&app, b)?;
    }
    let action = match v["action"].as_str() {
        Some("allow") => policy::Action::Allow,
        Some("deny") => policy::Action::Deny,
        _ => return Err(bad("action must be \"allow\" or \"deny\"")),
    };
    let pattern = v["pattern"].as_str().map(str::trim).filter(|p| !p.is_empty()).ok_or_else(|| bad("pattern is required"))?;
    let tool = v["tool"].as_str().map(str::trim).filter(|t| !t.is_empty()).unwrap_or("*");
    let r = app.db.add_rule(bot, action, tool, pattern, v["note"].as_str());
    let added = by.event("rule.added").target("rule", &r.id).details(json!({ "rule": r }));
    app.db.record(&match bot {
        Some(b) => added.bot(b),
        None => added,
    });
    Ok((StatusCode::CREATED, Json(json!(r))))
}

async fn delete_rule(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_user(who)?;
    let r = app.db.rule(&id).ok_or_else(|| not_found("Rule"))?;
    app.db.delete_rule(&id);
    let removed = by.event("rule.removed").target("rule", &id).details(json!({ "rule": r }));
    app.db.record(&match r.bot_id.as_deref() {
        Some(b) => removed.bot(b),
        None => removed,
    });
    Ok(Json(json!({ "ok": true })))
}

// Approvals

async fn list_approvals(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Query(q): Query<HashMap<String, String>>) -> Res {
    need_user(c.principal)?;
    let limit = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100).clamp(1, 1000);
    let status = q.get("status").map(String::as_str).filter(|s| *s != "all");
    let bot = q.get("bot").map(String::as_str).filter(|b| !b.is_empty());
    if let Some(b) = bot {
        need_bot_access(&app, &c, &by, b, Access::View)?;
    }
    Ok(Json(json!(visible_approvals(&app, &c, &by, status, bot, limit))))
}

async fn approve(state: State<AppState>, c: Extension<Caller>, by: Extension<Who>, id: Path<String>, body: axum::body::Bytes) -> Res {
    decide(state, c, by, id, body, true).await
}

async fn deny(state: State<AppState>, c: Extension<Caller>, by: Extension<Who>, id: Path<String>, body: axum::body::Bytes) -> Res {
    decide(state, c, by, id, body, false).await
}

/// Body: `{remember?: "bot" | "global" | true, note?}`. Remember saves a rule for this
/// exact call, which is a policy change, so it needs an admin.
async fn decide(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, body: axum::body::Bytes, approve: bool) -> Res {
    let who = c.principal;
    need_user(who)?;
    // Answering lets the Bot act, so it takes operator access to that Bot.
    if let Some(a) = app.db.approval(&id) {
        need_bot_access(&app, &c, &by, &a.bot_id, Access::Operate).map_err(|e| if e.0 == StatusCode::NOT_FOUND { not_found("Approval") } else { e })?;
    }
    let v: Value = if body.iter().all(u8::is_ascii_whitespace) {
        Value::Null
    } else {
        serde_json::from_slice(&body).map_err(|e| bad(format!("Invalid JSON: {e}")))?
    };
    let remember = match &v["remember"] {
        Value::Bool(true) => Some(Remember::Bot),
        Value::String(s) if s == "bot" => Some(Remember::Bot),
        Value::String(s) if s == "global" => Some(Remember::Global),
        Value::Null | Value::Bool(false) => None,
        _ => return Err(bad("remember must be \"bot\", \"global\", or true")),
    };
    if remember.is_some() && !rbac::allows(who, rbac::Perm::Admin) {
        app.db.record(&by.event("access.denied").outcome(Outcome::Denied).details(json!({ "path": format!("/api/approvals/{id}"), "need": "admin", "reason": "remember" })));
        return Err(ApiError(StatusCode::FORBIDDEN, "Only an admin can save a lasting rule. Approve or deny just this call.".into()));
    }
    let note: Option<String> = v["note"].as_str().map(|n| n.trim().chars().take(500).collect()).filter(|n: &String| !n.is_empty());
    match app.decide(&id, approve, remember, note.as_deref(), &by) {
        Ok(a) => Ok(Json(json!(a))),
        Err(DecideError::NotFound) => Err(not_found("Approval")),
        Err(DecideError::Closed(s)) => Err(ApiError(StatusCode::CONFLICT, format!("This approval is already {s}"))),
        Err(DecideError::TooLong) => Err(bad("This call is too long to remember. Approve or deny it without remembering.")),
    }
}

/// The harness hook (`botctl hook <harness>`) asks here before each tool call.
/// Body: `{from, harness, event}` with the harness's PreToolUse payload. Waits while
/// the user decides. Replies in plain text: "allow" or "deny", then the reason.
async fn check_approval(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Response {
    let reply = |allow: bool, reason: &str| {
        let body = format!("{}\n{reason}", if allow { "allow" } else { "deny" });
        ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
    };
    let Some(bot) = v["from"].as_str().and_then(|id| app.db.bot(id)) else {
        return reply(false, "Unknown Bot (BOT_ID)");
    };
    if let Principal::User(_) = c.principal
        && let Err(e) = need_bot_access(&app, &c, &by, &bot.id, Access::Operate)
    {
        return e.into_response();
    }
    let e = &v["event"];
    let Some(tool) = e["tool_name"].as_str().filter(|t| !t.is_empty()) else {
        return reply(false, "The hook sent no tool name");
    };
    let harness = v["harness"].as_str().unwrap_or(&bot.harness).to_string();
    let cwd = e["cwd"].as_str().filter(|c| c.starts_with('/')).map(PathBuf::from);
    let verdict = app.check(&bot, &harness, tool, e["tool_input"].clone(), cwd).await;
    reply(verdict.action == policy::Action::Allow, &verdict.reason)
}

/// The append-only audit log, newest first, filtered (see `audit::Filter`).
/// `nextBefore` pages back: pass it as `?before=`.
async fn list_audit(State(app): State<AppState>, Extension(who): Extension<Principal>, Query(q): Query<HashMap<String, String>>) -> Res {
    need_user(who)?;
    let limit = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100).clamp(1, 1000);
    let f = audit_filter(&app, &q)?;
    let events = app.db.audit_events(&f, limit, false);
    let next = (events.len() as i64 == limit).then(|| events.last().map(|e| e.id)).flatten();
    Ok(Json(json!({ "events": events, "nextBefore": next })))
}

/// `?actor=user:<email>` and `?onBehalfOf=<email>` find the person by their email now.
fn audit_filter(app: &App, q: &HashMap<String, String>) -> Result<audit::Filter, ApiError> {
    let mut f = audit::Filter::from_query(q).map_err(bad)?;
    f.resolve_users(|key| app.db.find_user(key).map(|u| u.id));
    Ok(f)
}

/// The filtered log as RFC 4180 CSV, oldest first, streamed in batches.
async fn export_audit(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Query(q): Query<HashMap<String, String>>) -> Result<Response, ApiError> {
    need_user(who)?;
    let mut f = audit_filter(&app, &q)?;
    app.db.record(&by.event("audit.exported").target("audit", "csv").details(f.describe()));
    // A snapshot: events written while the export streams are left out.
    let newest = app.db.audit_events(&audit::Filter::default(), 1, false).first().map_or(0, |e| e.id);
    f.before = Some(f.before.map_or(newest + 1, |b| b.min(newest + 1)));
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, Infallible>>(4);
    tokio::task::spawn_blocking(move || {
        const BATCH: i64 = 500;
        if tx.blocking_send(Ok(audit::CSV_HEADER.into())).is_err() {
            return;
        }
        loop {
            let rows = app.db.audit_events(&f, BATCH, true);
            let Some(last) = rows.last() else { break };
            f.after = Some(last.id);
            if tx.blocking_send(Ok(rows.iter().map(audit::csv_row).collect())).is_err() || (rows.len() as i64) < BATCH {
                break;
            }
        }
    });
    let name = format!("attachment; filename=\"superbot-audit-{}.csv\"", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let headers = [(header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()), (header::CONTENT_DISPOSITION, name), (header::CACHE_CONTROL, "no-store".into())];
    Ok((headers, axum::body::Body::from_stream(ReceiverStream::new(rx))).into_response())
}

// Secrets: names only. Values go in and reach harnesses; they never come back out.

fn secret_error(e: secrets::Error) -> ApiError {
    match e {
        secrets::Error::Invalid(m) => bad(m),
        secrets::Error::ReadOnly => ApiError(StatusCode::CONFLICT, e.to_string()),
        secrets::Error::Store(m) => {
            eprintln!("secrets: {m}");
            ApiError(StatusCode::INTERNAL_SERVER_ERROR, "The secret store failed; see the server log.".into())
        }
    }
}

async fn list_secrets(Extension(who): Extension<Principal>) -> Res {
    need_user(who)?;
    Ok(Json(json!({ "secrets": secrets::global().list().map_err(secret_error)? })))
}

async fn put_secret(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Path(name): Path<String>, Json(v): Json<Value>) -> Res {
    need_user(who)?;
    let value = v["value"].as_str().ok_or_else(|| bad("Send {\"value\": \"...\"}."))?;
    let listed = secrets::global().put(&name, value).map_err(secret_error)?;
    app.db.record(&by.event("secret.set").target("secret", &name).details(json!({ "store": listed.store })));
    Ok(Json(json!({ "secret": listed })))
}

async fn delete_secret(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Path(name): Path<String>) -> Res {
    need_user(who)?;
    if !secrets::global().delete(&name).map_err(secret_error)? {
        return Err(not_found("Secret"));
    }
    app.db.record(&by.event("secret.deleted").target("secret", &name));
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Auth in front of a stub route. Returns the port and the Bots' bearer token.
    async fn serve(password: &str, allow_no_auth: bool, extra_hosts: &str) -> (u16, String) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let bot_token = random_hex(16);
        let state = Arc::new(Auth {
            password: password.into(),
            allow_no_auth,
            bot_token: bot_token.clone(),
            hosts: allowed_hosts("127.0.0.1", port, extra_hosts),
            ..Auth::new(None)
        });
        let router = Router::new()
            .route("/api/state", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(state, super::auth));
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (port, bot_token)
    }

    async fn status(port: u16, host: &str, authorization: &str) -> u16 {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let auth = if authorization.is_empty() {
            String::new()
        } else {
            format!("Authorization: {authorization}\r\n")
        };
        let req = format!("GET /api/state HTTP/1.1\r\nHost: {host}\r\n{auth}Connection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut res = String::new();
        s.read_to_string(&mut res).await.unwrap();
        res.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    pub(super) fn basic(password: &str) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in format!("anyone:{password}").as_bytes().chunks(3) {
            let n = c.iter().enumerate().fold(0u32, |n, (i, b)| n | ((*b as u32) << (16 - 8 * i)));
            for i in 0..4 {
                out.push(if i <= c.len() {
                    T[((n >> (18 - 6 * i)) & 63) as usize] as char
                } else {
                    '='
                });
            }
        }
        format!("Basic {out}")
    }

    #[test]
    fn startup_requires_password_or_opt_out() {
        assert!(!is_loopback_host("0.0.0.0"));
        assert!(is_loopback_host("127.0.0.1"));
    }

    #[tokio::test]
    async fn spoofed_host_is_refused() {
        let pw = random_hex(16);
        let (port, _) = serve(&pw, false, "bots.example.com").await;
        assert_eq!(status(port, "attacker.example", &basic(&pw)).await, 403);
        assert_eq!(status(port, &format!("attacker.example:{port}"), &basic(&pw)).await, 403);
        assert_eq!(status(port, "127.0.0.1:1", &basic(&pw)).await, 403);
    }

    #[tokio::test]
    async fn own_hosts_and_login() {
        let pw = random_hex(16);
        let (port, bot_token) = serve(&pw, false, "bots.example.com").await;
        let host = format!("127.0.0.1:{port}");
        assert_eq!(status(port, &host, &basic(&pw)).await, 200);
        assert_eq!(status(port, &host, &basic(&random_hex(16))).await, 401);
        assert_eq!(status(port, &host, &format!("Bearer {bot_token}")).await, 200);
        assert_eq!(status(port, "bots.example.com", &basic(&pw)).await, 200);
    }

    #[tokio::test]
    // An empty String, not "": code scanning reads a literal as a hard-coded password.
    #[allow(clippy::unnecessary_owned_empty_strings)]
    async fn empty_password_requires_opt_in_even_on_loopback() {
        let (port, _) = serve(&String::new(), false, "").await;
        let host = format!("127.0.0.1:{port}");
        assert_eq!(status(port, &host, "").await, 401);
        assert_eq!(status(port, &host, &basic(&String::new())).await, 401);
    }

    #[tokio::test]
    #[allow(clippy::unnecessary_owned_empty_strings)]
    async fn allow_no_auth_permits_anonymous_on_loopback() {
        let (port, _) = serve(&String::new(), true, "").await;
        let host = format!("127.0.0.1:{port}");
        assert_eq!(status(port, &host, "").await, 200);
    }

    /// The real router on a fresh install (policy: ask), with a random password.
    /// Returns the port, the app, and the Authorization headers of the person and of Bots.
    pub(super) async fn serve_app() -> (u16, AppState, String, String) {
        serve_app_with(|_| {}).await
    }

    /// `serve_app`, with Auth changed first (break-glass, session lifetimes).
    pub(super) async fn serve_app_with(tweak: impl FnOnce(&mut Auth)) -> (u16, AppState, String, String) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let password = random_hex(16);
        let app = runner::test_app();
        users::ensure_operator(&app.db, "Owner", None);
        let mut auth = Auth {
            password: password.clone(),
            bot_token: random_hex(16),
            hosts: allowed_hosts("127.0.0.1", port, ""),
            ..Auth::new(Some(app.clone()))
        };
        tweak(&mut auth);
        let password = auth.password.clone();
        let auth = Arc::new(auth);
        let bot = format!("Bearer {}", auth.bot_token);
        let r = router(app.clone(), auth);
        tokio::spawn(async move {
            axum::serve(listener, r.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
        });
        (port, app, basic(&password), bot)
    }

    pub(super) async fn call(port: u16, method: &str, path: &str, authorization: &str, body: &str) -> (u16, String) {
        let (code, _, body) = call_with(port, method, path, authorization, "", body).await;
        (code, body)
    }

    /// `extra` is more header lines, each ending in \r\n. HTTP/1.0, so bodies are never chunked.
    pub(super) async fn call_with(port: u16, method: &str, path: &str, authorization: &str, extra: &str, body: &str) -> (u16, String, String) {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let auth = if authorization.is_empty() { String::new() } else { format!("Authorization: {authorization}\r\n") };
        let req = format!(
            "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n{auth}{extra}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut res = String::new();
        s.read_to_string(&mut res).await.unwrap();
        let code = res.split_whitespace().nth(1).unwrap().parse().unwrap();
        let (head, body) = res.split_once("\r\n\r\n").unwrap_or((&res, ""));
        (code, head.to_string(), body.to_string())
    }

    pub(super) fn audit_list(body: &str) -> Vec<Value> {
        serde_json::from_str::<Value>(body).unwrap()["events"].as_array().cloned().unwrap_or_default()
    }

    #[tokio::test]
    async fn healthz_is_open_and_new_endpoints_need_login() {
        let (port, _, _, _) = serve_app().await;
        assert_eq!(call(port, "GET", "/healthz", "", "").await.0, 200);
        for (m, p) in [
            ("GET", "/api/policy"),
            ("PUT", "/api/policy"),
            ("GET", "/api/approvals"),
            ("POST", "/api/approvals/x/approve"),
            ("POST", "/api/approvals/check"),
            ("GET", "/api/audit"),
            ("GET", "/api/audit/export.csv"),
            ("GET", "/api/audit?action=bot.*"),
            ("GET", "/api/policy/rules"),
        ] {
            assert_eq!(call(port, m, p, "", "{}").await.0, 401, "{m} {p}");
        }
    }

    #[tokio::test]
    async fn bots_cannot_approve_or_change_policy() {
        let (port, app, user, bot_auth) = serve_app().await;
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        for (m, p, b) in [
            ("PUT", "/api/policy".to_string(), r#"{"mode":"bypass"}"#),
            ("PUT", format!("/api/bots/{}/policy", bot.id), r#"{"mode":"bypass"}"#),
            ("DELETE", format!("/api/bots/{}/policy", bot.id), ""),
            ("POST", "/api/policy/rules".to_string(), r#"{"action":"allow","pattern":"*"}"#),
            ("GET", "/api/approvals".to_string(), ""),
            ("POST", "/api/approvals/x/approve".to_string(), "{}"),
            ("POST", "/api/approvals/x/deny".to_string(), "{}"),
            ("GET", "/api/audit".to_string(), ""),
            ("GET", "/api/audit/export.csv".to_string(), ""),
        ] {
            assert_eq!(call(port, m, &p, &bot_auth, b).await.0, 403, "{m} {p}");
        }
        assert_eq!(app.db.global_policy().mode, policy::Mode::Ask);
        assert_eq!(call(port, "GET", "/api/policy", &bot_auth, "").await.0, 200);

        let (code, body) = call(port, "PUT", "/api/policy", &user, r#"{"timeoutMinutes":3}"#).await;
        assert_eq!((code, serde_json::from_str::<Value>(&body).unwrap()["policy"]["timeoutMinutes"].as_u64()), (200, Some(3)));
        assert_eq!(call(port, "PUT", "/api/policy", &user, r#"{"mode":"yolo"}"#).await.0, 400);
        let (_, audit) = call(port, "GET", "/api/audit?action=policy.*", &user, "").await;
        assert_eq!(audit_list(&audit)[0]["action"], "policy.updated");
        // Each refused Bot call is on the record.
        let (_, denied) = call(port, "GET", "/api/audit?action=access.denied&actor=bot", &user, "").await;
        let denied = audit_list(&denied);
        assert_eq!(denied.len(), 9);
        assert_eq!((denied[0]["outcome"].as_str(), denied[0]["details"]["path"].as_str()), (Some("denied"), Some("/api/audit/export.csv")));
    }

    #[tokio::test]
    async fn admin_actions_are_audited() {
        let (port, app, user, bot_auth) = serve_app().await;
        let browser = "User-Agent: TestBrowser/1.0\r\n";
        let (code, _, body) = call_with(port, "POST", "/api/bots", &user, browser, r#"{"name":"Helper","harness":"claude"}"#).await;
        assert_eq!(code, 201);
        let id = serde_json::from_str::<Value>(&body).unwrap()["id"].as_str().unwrap().to_string();
        call_with(port, "PATCH", &format!("/api/bots/{id}"), &user, browser, r#"{"name":"Helper 2","hidden":true}"#).await;
        call_with(port, "PATCH", &format!("/api/bots/{id}"), &user, browser, r#"{"name":"Helper 2"}"#).await; // no change, no event

        // botctl names its Bot; routine calls are logged with that Bot as the actor.
        let botctl = format!("User-Agent: botctl\r\nX-SuperBot-Bot: {id}\r\n");
        let body = r#"{"name":"Standup","cron":"0 9 * * 1-5","instruction":"secret plan: email the team"}"#;
        let (code, _, r) = call_with(port, "POST", &format!("/api/bots/{id}/routines"), &bot_auth, &botctl, body).await;
        assert_eq!(code, 201);
        let rid = serde_json::from_str::<Value>(&r).unwrap()["id"].as_str().unwrap().to_string();
        call_with(port, "PATCH", &format!("/api/routines/{rid}"), &bot_auth, &botctl, r#"{"enabled":false,"cron":"0 10 * * *"}"#).await;
        call_with(port, "PATCH", &format!("/api/routines/{rid}"), &user, browser, r#"{"enabled":true}"#).await;
        call_with(port, "DELETE", &format!("/api/routines/{rid}"), &bot_auth, &botctl, "").await;
        call_with(port, "POST", &format!("/api/bots/{id}/stop"), &user, browser, "").await;
        call_with(port, "DELETE", &format!("/api/bots/{id}"), &user, browser, "").await;
        let wrong_password = random_hex(16);
        let wrong = basic(&wrong_password);
        assert_eq!(call_with(port, "GET", "/api/state", &wrong, browser, "").await.0, 401);
        assert_eq!(call_with(port, "GET", "/api/state", &wrong, browser, "").await.0, 401);
        assert_eq!(call_with(port, "GET", "/api/state", "Bearer nope", "", "").await.0, 401);

        let (code, body) = call(port, "GET", "/api/audit?limit=1000", &user, "").await;
        assert_eq!(code, 200);
        let events = audit_list(&body);
        let mut seen: Vec<(String, String, Option<String>, String)> = events
            .iter()
            .filter(|e| !["policy.initialized", "audit.exported"].contains(&e["action"].as_str().unwrap()))
            .map(|e| {
                let s = |k: &str| e[k].as_str().map(String::from);
                (s("action").unwrap(), s("actorKind").unwrap(), s("actorId"), s("outcome").unwrap())
            })
            .collect();
        seen.reverse();
        let op = Some("operator".to_string());
        let me = Some(id.clone());
        assert_eq!(
            seen,
            [
                ("user.created".into(), "system".into(), Some("bootstrap".into()), "success".into()),
                ("auth.login".into(), "user".into(), op.clone(), "success".into()),
                ("bot.created".into(), "user".into(), op.clone(), "success".into()),
                ("bot.updated".into(), "user".into(), op.clone(), "success".into()),
                ("routine.created".into(), "bot".into(), me.clone(), "success".into()),
                ("routine.disabled".into(), "bot".into(), me.clone(), "success".into()),
                ("routine.updated".into(), "bot".into(), me.clone(), "success".into()),
                ("routine.enabled".into(), "user".into(), op.clone(), "success".into()),
                ("routine.deleted".into(), "bot".into(), me.clone(), "success".into()),
                ("bot.stopped".into(), "user".into(), op.clone(), "success".into()),
                ("bot.deleted".into(), "user".into(), op.clone(), "success".into()),
                ("auth.login_failed".into(), "user".into(), None, "failure".into()),
                ("auth.login_failed".into(), "bot".into(), None, "failure".into()),
                ("auth.login".into(), "user".into(), op.clone(), "success".into()),
            ],
            "the second wrong password from the same IP is throttled; the audit read is a new client (no user agent)"
        );
        let find = |a: &str| events.iter().find(|e| e["action"] == a).unwrap().clone();
        let created = find("bot.created");
        assert_eq!((created["ip"].as_str(), created["userAgent"].as_str()), (Some("127.0.0.1"), Some("TestBrowser/1.0")));
        assert_eq!((created["targetType"].as_str(), created["targetId"].as_str()), (Some("bot"), Some(id.as_str())));
        assert_eq!(find("bot.updated")["details"]["changes"]["name"], json!({ "from": "Helper", "to": "Helper 2" }));
        let routine = find("routine.created");
        assert_eq!((routine["actorName"].as_str(), routine["userAgent"].as_str()), (Some("Helper 2"), Some("botctl")));
        assert_eq!(find("routine.updated")["details"]["changes"]["cron"]["to"], "0 10 * * *");
        assert!(!body.contains("secret plan"), "routine instructions are messages, not audit data");
        assert!(!body.contains(&wrong_password), "passwords are never logged");
        assert_eq!(find("bot.deleted")["details"]["name"], "Helper 2");
        // The log outlives the Bot.
        assert!(app.db.bot(&id).is_none());

        let (_, page) = call(port, "GET", "/api/audit?limit=2", &user, "").await;
        let page: Value = serde_json::from_str(&page).unwrap();
        let next = page["nextBefore"].as_i64().unwrap();
        let (_, older) = call(port, "GET", &format!("/api/audit?limit=2&before={next}"), &user, "").await;
        assert!(audit_list(&older).iter().all(|e| e["id"].as_i64().unwrap() < next));
        let (_, mine) = call(port, "GET", &format!("/api/audit?actor=bot:{id}&action=routine.*"), &user, "").await;
        assert_eq!(audit_list(&mine).len(), 4);
        assert_eq!(call(port, "GET", "/api/audit?from=last-week", &user, "").await.0, 400);
        assert_eq!(call(port, "GET", "/api/audit/export.csv?actor=root", &user, "").await.0, 400);
    }

    #[tokio::test]
    async fn approvals_and_handoffs_are_audited() {
        let (port, app, user, bot_auth) = serve_app().await;
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let check = json!({ "from": bot.id, "harness": "claude", "event": { "tool_name": "Bash", "tool_input": { "command": "git push https://x:tok3n@example.com" }, "cwd": "/tmp" } }).to_string();
        let hook = tokio::spawn({
            let bot_auth = bot_auth.clone();
            async move { call(port, "POST", "/api/approvals/check", &bot_auth, &check).await }
        });
        let pending = loop {
            if let Some(a) = app.db.approvals(Some("pending"), None, 1).pop() {
                break a;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let (code, _, _) = call_with(port, "POST", &format!("/api/approvals/{}/deny", pending.id), &user, "X-Forwarded-For: 198.51.100.7\r\n", "{}").await;
        assert_eq!(code, 200);
        hook.await.unwrap();

        let handoff = tokio::spawn({
            let (app, bot) = (app.clone(), bot.clone());
            async move { app.handoff(&bot, "Log in to the bank", Duration::from_secs(30)).await }
        });
        let card = loop {
            if let Some(m) = app.db.messages(&bot.id, 10).into_iter().find(|m| m.question.is_some()) {
                break m;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let answer = json!({ "text": "Done", "answer": { "messageId": card.id, "option": 0 } }).to_string();
        assert_eq!(call(port, "POST", &format!("/api/bots/{}/messages", bot.id), &user, &answer).await.0, 202);
        assert_eq!(handoff.await.unwrap().as_deref(), Some("Done"));

        let (_, body) = call(port, "GET", "/api/audit?action=approval.*,handoff.*", &user, "").await;
        let ev = audit_list(&body);
        let actions: Vec<&str> = ev.iter().map(|e| e["action"].as_str().unwrap()).collect();
        assert_eq!(actions, ["handoff.answered", "handoff.requested", "approval.denied", "approval.requested"]);
        // Behind a proxy on loopback, the client IP is the forwarded one.
        assert_eq!((ev[2]["actorId"].as_str(), ev[2]["ip"].as_str()), (Some("operator"), Some("198.51.100.7")));
        assert_eq!(ev[0]["details"], json!({ "option": "Done", "botWasWaiting": true }));
        assert!(!body.contains("tok3n") && !body.contains("bank"), "{body}");
    }

    #[tokio::test]
    async fn csv_export_is_rfc4180_and_formula_safe() {
        let (port, app, user, _) = serve_app().await;
        let evil = r#"{"name":"=HYPERLINK(\"http://evil.example\",\"x\"), ok"}"#;
        let (code, created) = call(port, "POST", "/api/bots", &user, evil).await;
        assert_eq!(code, 201, "{created}");
        let (code, head, body) = call_with(port, "GET", "/api/audit/export.csv?action=bot.created", &user, "", "").await;
        assert_eq!(code, 200);
        let head = head.to_ascii_lowercase();
        assert!(head.contains("content-type: text/csv; charset=utf-8"), "{head}");
        assert!(head.contains("content-disposition: attachment; filename=\"superbot-audit-"), "{head}");
        let lines: Vec<&str> = body.split("\r\n").collect();
        assert_eq!(format!("{}\r\n", lines[0]), audit::CSV_HEADER);
        assert_eq!(lines.len(), 3, "header, one row, and the final CRLF: {body:?}");
        assert!(lines[1].contains(r#""{""harness"":""claude"",""model"":null,""name"":""=HYPERLINK"#), "{}", lines[1]);
        assert!(lines[1].split(',').nth(6) == Some("bot.created"));
        // The export itself is audited, and a cell that starts a formula is defused.
        let exported = &app.db.audit_events(&audit::Filter { actions: vec!["audit.exported".into()], ..Default::default() }, 10, false)[0];
        assert_eq!(exported.details["actions"], json!(["bot.created"]));
        let row = audit::csv_row(&db::AuditEvent { actor_name: Some("=1+2".into()), ..exported.clone() });
        assert!(row.contains(",'=1+2,"), "{row}");
        // Many rows stream in batches, oldest first.
        for i in 0..1200 {
            app.db.record(&Event::new(Actor::system("test"), "test.bulk").details(json!({ "i": i })));
        }
        let (_, _, body) = call_with(port, "GET", "/api/audit/export.csv?action=test.bulk", &user, "", "").await;
        let rows: Vec<&str> = body.trim_end().split("\r\n").skip(1).collect();
        assert_eq!(rows.len(), 1200);
        assert!(rows[0].ends_with(r#""{""i"":0}",,,,,,,"#), "{}", rows[0]);
        assert!(rows[1199].ends_with(r#""{""i"":1199}",,,,,,,"#), "{}", rows[1199]);
    }

    #[tokio::test]
    async fn hook_waits_for_a_person_then_runs() {
        let (port, app, user, bot_auth) = serve_app().await;
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let check = |cmd: &str| {
            json!({ "from": bot.id, "harness": "claude", "event": { "tool_name": "Bash", "tool_input": { "command": cmd }, "cwd": "/tmp" } }).to_string()
        };

        let (code, body) = call(port, "POST", "/api/approvals/check", &bot_auth, &check("ls -la")).await;
        assert_eq!((code, body.lines().next()), (200, Some("allow")));

        let hook = tokio::spawn({
            let body = check("git push origin main");
            let bot_auth = bot_auth.clone();
            async move { call(port, "POST", "/api/approvals/check", &bot_auth, &body).await }
        });
        let pending = loop {
            let (_, list) = call(port, "GET", "/api/approvals?status=pending", &user, "").await;
            let list: Vec<Value> = serde_json::from_str(&list).unwrap();
            if let Some(a) = list.into_iter().next() {
                break a;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(pending["class"], "git_push");
        let id = pending["id"].as_str().unwrap();
        assert_eq!(call(port, "POST", &format!("/api/approvals/{id}/approve"), &bot_auth, "{}").await.0, 403);
        let (code, done) = call(port, "POST", &format!("/api/approvals/{id}/approve"), &user, r#"{"remember":"bot"}"#).await;
        assert_eq!((code, serde_json::from_str::<Value>(&done).unwrap()["status"].as_str()), (200, Some("approved")));
        assert_eq!(hook.await.unwrap().1.lines().next(), Some("allow"));
        assert_eq!(call(port, "POST", &format!("/api/approvals/{id}/deny"), &user, "").await.0, 409);

        let (_, again) = call(port, "POST", "/api/approvals/check", &bot_auth, &check("git push origin main")).await;
        assert_eq!(again.lines().next(), Some("allow"), "remembered");

        let (_, unknown) = call(port, "POST", "/api/approvals/check", &bot_auth, r#"{"from":"nobody","event":{"tool_name":"Bash"}}"#).await;
        assert_eq!(unknown.lines().next(), Some("deny"));

        let deep = format!("echo \"{}{}\"", "$(".repeat(100_000), ")".repeat(100_000));
        for cmd in ["echo \"$(git push", deep.as_str()] {
            let (code, bad) = call(port, "POST", "/api/approvals/check", &bot_auth, &check(cmd)).await;
            assert_eq!((code, bad.lines().next()), (200, Some("deny")), "{cmd:.40}");
        }
        for input in [json!({}), json!({ "command": "ls", "cmd": "git push" })] {
            let body = json!({ "from": bot.id, "harness": "codex", "event": { "tool_name": "exec_command", "tool_input": input } }).to_string();
            let (_, bad) = call(port, "POST", "/api/approvals/check", &bot_auth, &body).await;
            assert_eq!(bad.lines().next(), Some("deny"), "{input}");
        }
        let (_, list) = call(port, "GET", "/api/approvals?status=pending", &user, "").await;
        assert_eq!(list.trim(), "[]", "refused without asking");
    }

    #[tokio::test]
    async fn secrets_api_takes_values_and_never_returns_them() {
        let (port, app, user, bot_auth) = serve_app().await;
        let name = format!("TEST_{}_API_KEY", random_hex(4).to_uppercase());
        let value = format!("sk-test-{}", random_hex(16));
        let path = format!("/api/secrets/{name}");
        let body = json!({ "value": value }).to_string();
        assert_eq!(call(port, "GET", "/api/secrets", "", "").await.0, 401);
        assert_eq!(call(port, "GET", "/api/secrets", &bot_auth, "").await.0, 403);
        assert_eq!(call(port, "PUT", &path, &bot_auth, &body).await.0, 403);
        assert_eq!(call(port, "PUT", "/api/secrets/PATH", &user, &body).await.0, 400);
        assert_eq!(call(port, "PUT", &path, &user, "{}").await.0, 400);

        let (code, res) = call(port, "PUT", &path, &user, &body).await;
        assert_eq!(code, 200, "{res}");
        assert!(!res.contains(&value));
        let (code, list) = call(port, "GET", "/api/secrets", &user, "").await;
        assert_eq!(code, 200);
        assert!(list.contains(&name) && !list.contains(&value), "{list}");
        assert_eq!(secrets::global().get(&name).unwrap().unwrap().expose(), value);
        assert!(secrets::global().harness_env().iter().any(|(k, v)| *k == name && v.expose() == value));

        // A Bot echoing the value: the saved chat and the audit log hold the mark instead.
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let m = app.db.add_message(&bot.id, "bot", &format!("key={value}"), None, false, None);
        assert_eq!(m.text, "key=[redacted]");
        app.db.record(&Event::new(Actor::bot(Some(&bot.id), None), "test.echo").bot(&bot.id).details(json!({ "said": value })));
        let (_, audit) = call(port, "GET", "/api/audit", &user, "").await;
        assert!(!audit.contains(&value) && audit.contains("secret.set") && audit.contains(&name), "{audit}");

        assert_eq!(call(port, "DELETE", &path, &bot_auth, "").await.0, 403);
        assert_eq!(call(port, "DELETE", &path, &user, "").await.0, 200);
        assert_eq!(call(port, "DELETE", &path, &user, "").await.0, 404);
        assert!(secrets::global().get(&name).unwrap().is_none());
    }

    #[test]
    fn routine_fields_validate_and_trim() {
        let f = routine_fields(&json!({ "name": "  Digest ", "cron": "0 9 * * 1-5", "instruction": " Sum up email ", "enabled": false })).unwrap();
        assert_eq!(
            f,
            RoutineFields { name: Some("Digest".into()), cron: Some("0 9 * * 1-5".into()), instruction: Some("Sum up email".into()), enabled: Some(false) }
        );
        assert_eq!(routine_fields(&json!({})).unwrap(), RoutineFields::default());
        assert_eq!(routine_fields(&json!({ "name": null })).unwrap(), RoutineFields::default());
        assert!(routine_fields(&json!({ "name": "   " })).is_err());
        assert!(routine_fields(&json!({ "instruction": "" })).is_err());
        assert!(routine_fields(&json!({ "name": 5 })).is_err());
        assert!(routine_fields(&json!({ "cron": "61 * * * *" })).is_err());
        assert!(routine_fields(&json!({ "cron": "* * *" })).is_err());
        assert!(routine_fields(&json!({ "enabled": "no" })).is_err());
        let long = routine_fields(&json!({ "name": "x".repeat(500) })).unwrap();
        assert_eq!(long.name.unwrap().len(), 100);
    }

    async fn serve_routines() -> (u16, Arc<App>, String, PathBuf) {
        let dir = std::env::temp_dir().join(format!("botd-test-{}", random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&dir.join("app.sqlite")).unwrap();
        let app = App::new(db, Config {
            data_dir: dir.clone(),
            workspace: dir.clone(),
            user_name: "the user".into(),
            bin_dir: dir.clone(),
            api_url: "http://127.0.0.1:0".into(),
            bot_token: "bot-token".into(),
            run_timeout: Duration::from_secs(60),
            default_harness: "claude".into(),
        }, None);
        let bot = app.db.create_bot("Tester", "#f5f5f5", "waddle", "claude", None, true);
        let router = Router::new()
            .route("/api/bots/{id}/routines", get(list_routines).post(create_routine))
            .route("/api/routines/{id}", patch(update_routine).delete(delete_routine))
            .layer(Extension(Who { actor: Actor::operator(), source: Source::default() }))
            .layer(Extension(Caller { principal: Principal::User(Role::Admin), user: None, session: None, method: "none" }))
            .with_state(app.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (port, app, bot.id, dir)
    }

    async fn call_json(port: u16, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let (code, res) = call(port, method, path, "", &body.map(|b| b.to_string()).unwrap_or_default()).await;
        (code, serde_json::from_str(&res).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn routine_create_edit_delete() {
        let (port, app, bot, dir) = serve_routines().await;
        let base = format!("/api/bots/{bot}/routines");

        let (code, _) = call_json(port, "POST", &base, Some(json!({ "name": "", "cron": "0 9 * * *", "instruction": "x" }))).await;
        assert_eq!(code, 400);
        let (code, _) = call_json(port, "POST", &base, Some(json!({ "name": "A", "cron": "nope", "instruction": "x" }))).await;
        assert_eq!(code, 400);
        let (code, _) = call_json(port, "POST", "/api/bots/missing/routines", Some(json!({ "name": "A", "cron": "0 9 * * *", "instruction": "x" }))).await;
        assert_eq!(code, 404);

        let (code, r) = call_json(port, "POST", &base, Some(json!({ "name": " Digest ", "cron": "0 9 * * *", "instruction": "Sum up" }))).await;
        assert_eq!(code, 201);
        assert_eq!(r["name"], "Digest");
        assert_eq!(r["enabled"], true);
        let id = r["id"].as_str().unwrap().to_string();
        let path = format!("/api/routines/{id}");

        let (code, paused) = call_json(port, "POST", &base, Some(json!({ "name": "B", "cron": "0 9 * * *", "instruction": "y", "enabled": false }))).await;
        assert_eq!(code, 201);
        assert_eq!(paused["enabled"], false);

        let (code, _) = call_json(port, "PATCH", &path, Some(json!({ "name": "   " }))).await;
        assert_eq!(code, 400);
        let (code, _) = call_json(port, "PATCH", &path, Some(json!({ "cron": "99 * * * *" }))).await;
        assert_eq!(code, 400);
        assert_eq!(app.db.routine(&id).unwrap().name, "Digest");
        assert_eq!(app.db.routine(&id).unwrap().cron, "0 9 * * *");

        let edit = json!({ "name": " Weekday digest ", "cron": "30 8 * * 1-5", "instruction": "Sum up email", "enabled": false });
        let (code, r) = call_json(port, "PATCH", &path, Some(edit)).await;
        assert_eq!(code, 200);
        assert_eq!(r["name"], "Weekday digest");
        assert_eq!(r["cron"], "30 8 * * 1-5");
        assert_eq!(r["instruction"], "Sum up email");
        assert_eq!(r["enabled"], false);

        let (code, list) = call_json(port, "GET", &base, None).await;
        assert_eq!(code, 200);
        assert_eq!(list.as_array().unwrap().len(), 2);

        let (code, _) = call_json(port, "DELETE", &path, None).await;
        assert_eq!(code, 200);
        assert!(app.db.routine(&id).is_none());
        let (code, _) = call_json(port, "PATCH", &path, Some(json!({ "enabled": true }))).await;
        assert_eq!(code, 404);
        let (code, _) = call_json(port, "DELETE", &path, None).await;
        assert_eq!(code, 404);

        let events = app.db.audit_events(&audit::Filter { actions: vec!["routine.*".into()], ..Default::default() }, 100, true);
        let seen: Vec<(&str, Option<&str>)> = events.iter().map(|e| (e.action.as_str(), e.target_id.as_deref())).collect();
        let paused_id = paused["id"].as_str();
        assert_eq!(
            seen,
            [
                ("routine.created", Some(id.as_str())),
                ("routine.created", paused_id),
                ("routine.disabled", Some(id.as_str())),
                ("routine.updated", Some(id.as_str())),
                ("routine.deleted", Some(id.as_str())),
            ],
            "rejected and missing-routine requests are not logged"
        );
        assert!(events.iter().all(|e| e.actor_id.as_deref() == Some("operator") && e.bot_id.as_deref() == Some(bot.as_str())));
        assert_eq!(events[1].details["enabled"], false);
        assert_eq!(events[3].details["changes"]["instruction"], "changed", "the instruction text is not logged");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn bot_view_reports_the_open_handoff() {
        let (_, app, bot, dir) = serve_routines().await;
        let card = |title: &str| json!({ "title": title, "options": ["Done", "I can't right now"], "handoff": true });
        let view = |app: &App| app.bot_view(&app.db.bot(&bot).unwrap())["handoff"].clone();
        assert_eq!(view(&app), Value::Null);

        app.db.add_message(&bot, "bot", "", Some(&json!({ "title": "Pick", "options": ["A", "B"] })), false, None);
        assert_eq!(view(&app), Value::Null);

        let first = app.db.add_message(&bot, "bot", "", Some(&card("Log in")), false, None);
        assert_eq!(view(&app), json!(first.id));
        app.db.add_message(&bot, "user", "later", None, false, None);
        assert_eq!(view(&app), Value::Null);

        let second = app.db.add_message(&bot, "bot", "", Some(&card("2FA")), false, None);
        assert_eq!(view(&app), json!(second.id));
        let mut q = card("2FA");
        q["picked"] = json!(0);
        app.db.set_question(second.id, &q);
        assert_eq!(view(&app), Value::Null);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn allowed_host_names() {
        assert_eq!(
            allowed_hosts("::1", 3000, "")[0..4],
            ["[::1]:3000", "localhost:3000", "127.0.0.1:3000", "[::1]:3000"]
        );
        let list = allowed_hosts("127.0.0.1", 3000, " Bots.Example.com ,");
        assert!(list.iter().any(|h| h == "bots.example.com"));
    }
}
