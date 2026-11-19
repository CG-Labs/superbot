//! botd: the server. Owns Bots, chats, memory files, and routines; runs each Bot
//! on its harness (Claude Code, Codex, or Pi); serves the web app and its API.

mod adapters;
mod approvals;
mod cron;
mod db;
mod paths;
mod policy;
mod runner;
mod screen;
mod shell;

use approvals::{DecideError, Remember};
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use std::collections::HashMap;
use db::{BotPatch, Db};
use runner::{App, Config};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::{AllowOrigin, CorsLayer};

type AppState = Arc<App>;

static WEB_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

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
    let password = std::env::var("AUTH_PASSWORD").unwrap_or_default();
    let default_harness = env("DEFAULT_HARNESS", "claude");
    let allow_no_auth = auth_startup(&host, &password);
    if adapters::get(&default_harness).is_none() {
        eprintln!("DEFAULT_HARNESS must be one of: {}", adapters::NAMES.join(", "));
        std::process::exit(1);
    }
    let auth_state = Arc::new(Auth {
        password: password.clone(),
        allow_no_auth,
        bot_token: random_hex(24),
        hosts: allowed_hosts(&host, port, &env("ALLOWED_HOSTS", "")),
    });
    WEB_DIR.set(std::env::var("WEB_DIR").ok().map(PathBuf::from)).unwrap();

    let root = |key: &str, default: &str| {
        paths::root(&env(key, default)).unwrap_or_else(|e| {
            eprintln!("{key}: {e}");
            std::process::exit(1);
        })
    };
    let data_dir = root("DATA_DIR", "data");
    let workspace = root("WORKSPACE_DIR", "workspace");
    let db = Db::open(&paths::child(&data_dir, "app.sqlite").unwrap()).expect("open database");

    let screens = paths::child(&data_dir, "screens").and_then(screen::Screens::from_env);
    let app = App::new(db, Config {
        data_dir,
        workspace,
        user_name: env("USER_NAME", "the user"),
        // `botctl` ships next to `botd`.
        bin_dir: std::env::current_exe().unwrap().parent().unwrap().to_path_buf(),
        api_url: format!("http://127.0.0.1:{port}"),
        bot_token: auth_state.bot_token.clone(),
        run_timeout: Duration::from_secs(60 * env("RUN_TIMEOUT_MINUTES", "60").parse::<u64>().unwrap_or(60)),
        default_harness,
    }, screens);

    // First start: create the primary Bot.
    if app.db.bots().is_empty() {
        let name = env("PRIMARY_BOT_NAME", "Assistant");
        let bot = app.db.create_bot(&name, "#f5f5f5", "waddle", &app.cfg.default_harness, None, true);
        app.init_bot_files(&bot);
    }

    let router = router(app.clone(), auth_state);
    let policy = app.db.global_policy();
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

    axum::serve(listener, router).await.unwrap();
}

fn router(app: AppState, auth_state: Arc<Auth>) -> Router {
    let api = Router::new()
        .route("/state", get(state))
        .route("/events", get(events))
        .route("/harnesses/{name}/models", get(list_models))
        .route("/bots", get(list_bots).post(create_bot))
        .route("/bots/{id}", patch(update_bot).delete(delete_bot))
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
        .route("/ask", post(ask))
        .route("/handoff", post(handoff));
    Router::new()
        .route("/healthz", get(|| async { Json(json!({ "ok": true })) }))
        .merge(
            Router::new()
                .nest("/api", api)
                .fallback(get(web))
                .layer(middleware::from_fn_with_state(auth_state, auth)),
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

// Auth: browser login with AUTH_PASSWORD (any username), or the Bots' token for `botctl`.

struct Auth {
    password: String,
    /// Only when ALLOW_NO_AUTH=1 and loopback: empty password does not skip login on its own.
    allow_no_auth: bool,
    bot_token: String,
    /// Host headers we answer to, lowercase.
    hosts: Vec<String>,
}

/// Refuse to start without AUTH_PASSWORD unless ALLOW_NO_AUTH=1 on loopback only.
fn auth_startup(host: &str, password: &str) -> bool {
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
    let h = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    let bot = h.strip_prefix("Bearer ").is_some_and(|t| same(t.as_bytes(), a.bot_token.as_bytes()));
    let user = h.strip_prefix("Basic ").and_then(base64_decode).is_some_and(|creds| {
        let pass = creds.splitn(2, |b| *b == b':').nth(1).unwrap_or_default();
        !a.password.is_empty() && same(pass, a.password.as_bytes())
    });
    let who = if bot {
        Principal::Bot
    } else if user || (a.allow_no_auth && a.password.is_empty()) {
        Principal::User
    } else {
        return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Basic realm=\"Bots\"")], "Login required").into_response();
    };
    let mut req = req;
    req.extensions_mut().insert(who);
    next.run(req).await
}

/// Who is calling: a person (the browser or client, with AUTH_PASSWORD) or a Bot
/// (`botctl`, with the per-start BOT_TOKEN that every Bot run can read).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Principal {
    User,
    Bot,
}

/// Approvals and policy changes are for people. Bots hold a token too, so without
/// this a Bot could approve its own request.
fn need_user(p: Principal) -> Res<()> {
    match p {
        Principal::User => Ok(()),
        Principal::Bot => Err(ApiError(StatusCode::FORBIDDEN, "Only a signed-in person can do this, not a Bot.".into())),
    }
}

/// Constant-time comparison.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
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

// Web app: embedded in the binary. Set WEB_DIR to serve from disk while editing it.

async fn web(uri: axum::http::Uri) -> Response {
    let path = uri.path();
    let file = match path {
        "/" | "/index.html" => "index.html",
        "/app.js" => "app.js",
        "/styles.css" => "styles.css",
        _ => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let kind = match file.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        _ => "text/css; charset=utf-8",
    };
    let body = match WEB_DIR.get().unwrap() {
        Some(dir) => std::fs::read_to_string(dir.join(file)).unwrap_or_default(),
        None => match file {
            "index.html" => include_str!("../../web/index.html"),
            "app.js" => include_str!("../../web/app.js"),
            _ => include_str!("../../web/styles.css"),
        }
        .to_string(),
    };
    ([(header::CONTENT_TYPE, kind), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

// Live updates: one Server-Sent Events stream with everything.

async fn events(State(app): State<AppState>) -> impl IntoResponse {
    let stream = BroadcastStream::new(app.tx.subscribe()).map(|r| {
        // A slow client that missed events is told to reload its state.
        Ok::<_, Infallible>(Event::default().data(r.unwrap_or_else(|_| r#"{"type":"resync"}"#.into())))
    });
    ([("x-accel-buffering", "no")], Sse::new(stream).keep_alive(KeepAlive::default()))
}

// Bots

async fn state(State(app): State<AppState>, Extension(who): Extension<Principal>) -> Json<Value> {
    let bots: Vec<Value> = app.db.bots().iter().map(|b| app.bot_view(b)).collect();
    let approvals = if who == Principal::User { app.db.approvals(Some("pending"), None, 200) } else { vec![] };
    Json(json!({
        "me": { "name": env("USER_NAME", "You") },
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

async fn list_bots(State(app): State<AppState>) -> Json<Value> {
    Json(app.db.bots().iter().map(|b| app.bot_view(b)).collect())
}

fn need_bot(app: &App, id: &str) -> Res<db::Bot> {
    app.db.bot(id).ok_or_else(|| not_found("Bot"))
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

async fn create_bot(State(app): State<AppState>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    let p = bot_patch(&v)?;
    let name = p.name.ok_or_else(|| bad("Name is required"))?;
    let harness = p.harness.unwrap_or_else(|| app.cfg.default_harness.clone());
    let bot = app.db.create_bot(
        &name,
        p.color.as_deref().unwrap_or(pick(&COLORS)),
        p.shape.as_deref().unwrap_or(pick(&SHAPES)),
        &harness,
        p.model.flatten().as_deref(),
        false,
    );
    app.init_bot_files(&bot);
    app.push_bot(&bot.id);
    Ok((StatusCode::CREATED, Json(app.bot_view(&bot))))
}

async fn update_bot(State(app): State<AppState>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    let bot = need_bot(&app, &id)?;
    let mut p = bot_patch(&v)?;
    if p.harness.as_ref().is_some_and(|h| *h != bot.harness) {
        p.session_id = Some(None); // sessions don't carry across harnesses
    }
    app.db.update_bot(&id, p);
    app.push_bot(&id);
    Ok(Json(app.bot_view(&need_bot(&app, &id)?)))
}

async fn delete_bot(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    if need_bot(&app, &id)?.primary {
        return Err(bad("The primary Bot can't be deleted"));
    }
    app.stop(&id);
    if let Some(screens) = &app.screens {
        screens.remove(&id).await;
    }
    app.db.delete_bot(&id);
    app.send(json!({ "type": "botDeleted", "botId": id }));
    Ok(Json(json!({ "ok": true })))
}

async fn mark_read(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    need_bot(&app, &id)?;
    app.db.update_bot(&id, BotPatch { unread: Some(false), ..Default::default() });
    app.push_bot(&id);
    Ok(Json(json!({ "ok": true })))
}

async fn stop_bot(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    need_bot(&app, &id)?;
    app.stop(&id);
    Ok(Json(json!({ "ok": true })))
}

// Messages

async fn list_messages(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    need_bot(&app, &id)?;
    Ok(Json(json!(app.db.messages(&id, 200))))
}

async fn send_message(State(app): State<AppState>, Path(id): Path<String>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    need_bot(&app, &id)?;
    let text = v["text"].as_str().map(str::trim).filter(|t| !t.is_empty()).ok_or_else(|| bad("Text is required"))?;
    let text: String = text.chars().take(100_000).collect();
    // Answering a choice card: remember which option was picked.
    if let (Some(mid), Some(opt)) = (v["answer"]["messageId"].as_i64(), v["answer"]["option"].as_u64()) {
        if let Some(mut q) = app.db.message(mid).filter(|m| m.bot_id == id).and_then(|m| m.question) {
            q["picked"] = json!(opt);
            app.db.set_question(mid, &q);
        }
    }
    // Answering a handoff card the Bot is still waiting on: hand the answer to it directly.
    if let Some(tx) = v["answer"]["messageId"].as_i64().and_then(|mid| app.take_handoff(mid)) {
        let msg = app.db.add_message(&id, "user", &text, None, false, Some("done"));
        app.push_message(&msg);
        let _ = tx.send(text);
        return Ok((StatusCode::ACCEPTED, Json(json!(msg))));
    }
    let msg = app.db.add_message(&id, "user", &text, None, false, Some("queued"));
    app.push_message(&msg);
    app.enqueue(msg.clone());
    Ok((StatusCode::ACCEPTED, Json(json!(msg))))
}

// Bot to Bot: `botctl ask`. Waits for the reply and returns it as plain text.

async fn ask(State(app): State<AppState>, Json(v): Json<Value>) -> Result<String, ApiError> {
    let from = v["from"].as_str().and_then(|id| app.db.bot(id)).ok_or_else(|| bad("Unknown asking Bot (BOT_ID)"))?;
    let to_key = v["to"].as_str().map(str::trim).unwrap_or("");
    let bots = app.db.bots();
    let to = bots
        .iter()
        .find(|b| b.id == to_key)
        .or_else(|| bots.iter().find(|b| b.name.eq_ignore_ascii_case(to_key)))
        .ok_or_else(|| bad(format!("No Bot named \"{to_key}\". Run `botctl bots` to list them.")))?;
    if to.id == from.id {
        return Err(bad("You can't ask yourself"));
    }
    let text = v["text"].as_str().map(str::trim).filter(|t| !t.is_empty()).ok_or_else(|| bad("Message is required"))?;
    let wait = Duration::from_secs(9 * 60); // under the 10 minute max most harnesses allow a command
    Ok(match app.ask(&from, to, text, wait).await {
        Some(reply) => reply,
        None => format!("{} is still working on it. Their reply will arrive later as a new message.", to.name),
    })
}

// Screens: the live view of a Bot's screen. Opening it starts the screen.

async fn screen_info(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    need_bot(&app, &id)?;
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

async fn handoff(State(app): State<AppState>, Json(v): Json<Value>) -> Result<String, ApiError> {
    let bot = v["from"].as_str().and_then(|id| app.db.bot(id)).ok_or_else(|| bad("Unknown Bot (BOT_ID)"))?;
    let text = v["text"].as_str().map(str::trim).filter(|t| !t.is_empty()).ok_or_else(|| bad("Say what you need"))?;
    let text: String = text.chars().take(300).collect();
    let wait = Duration::from_secs(9 * 60); // under the 10 minute max most harnesses allow a command
    Ok(match app.handoff(&bot, &text, wait).await {
        Some(answer) => format!("The user answered: {answer}"),
        None => "The user hasn't answered yet. Stop here and tell them in one line what you need. You'll get their answer as a new message.".into(),
    })
}

// Routines

async fn list_routines(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    need_bot(&app, &id)?;
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

async fn create_routine(State(app): State<AppState>, Path(id): Path<String>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    need_bot(&app, &id)?;
    let f = routine_fields(&v)?;
    let (Some(name), Some(cron_expr), Some(instruction)) = (f.name, f.cron, f.instruction) else {
        return Err(bad("name, cron, and instruction are required"));
    };
    let r = app.db.add_routine(&id, &name, &cron_expr, &instruction);
    if f.enabled == Some(false) {
        app.db.update_routine(&r.id, None, None, None, Some(false));
    }
    Ok((StatusCode::CREATED, Json(json!(app.db.routine(&r.id)))))
}

async fn update_routine(State(app): State<AppState>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    app.db.routine(&id).ok_or_else(|| not_found("Routine"))?;
    let f = routine_fields(&v)?;
    app.db.update_routine(&id, f.name.as_deref(), f.cron.as_deref(), f.instruction.as_deref(), f.enabled);
    Ok(Json(json!(app.db.routine(&id))))
}

async fn delete_routine(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    app.db.routine(&id).ok_or_else(|| not_found("Routine"))?;
    app.db.delete_routine(&id);
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

async fn put_policy(State(app): State<AppState>, Extension(who): Extension<Principal>, Json(v): Json<Value>) -> Res {
    need_user(who)?;
    let before = app.db.global_policy();
    let after = policy::parse_patch(&v).map_err(bad)?.apply(&before);
    app.db.set_global_policy(&after);
    app.db.audit("user", "policy.updated", None, Some("global"), json!({ "before": before, "after": after }));
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

async fn get_bot_policy(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    need_bot(&app, &id)?;
    Ok(Json(bot_policy_view(&app, &id)))
}

async fn put_bot_policy(State(app): State<AppState>, Extension(who): Extension<Principal>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    need_user(who)?;
    need_bot(&app, &id)?;
    let before = app.db.bot_override(&id);
    let mut o = before.clone().unwrap_or_default();
    o.merge(policy::parse_patch(&v).map_err(bad)?);
    app.db.set_bot_override(&id, Some(&o));
    app.db.audit("user", "policy.updated", Some(&id), Some(&id), json!({ "before": before, "after": o }));
    app.stop_unguarded_runs();
    app.push_bot(&id);
    Ok(Json(bot_policy_view(&app, &id)))
}

async fn delete_bot_policy(State(app): State<AppState>, Extension(who): Extension<Principal>, Path(id): Path<String>) -> Res {
    need_user(who)?;
    need_bot(&app, &id)?;
    let before = app.db.bot_override(&id);
    app.db.set_bot_override(&id, None);
    app.db.audit("user", "policy.reset", Some(&id), Some(&id), json!({ "before": before }));
    app.stop_unguarded_runs();
    app.push_bot(&id);
    Ok(Json(bot_policy_view(&app, &id)))
}

async fn list_rules(State(app): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    Json(json!(app.db.rules(q.get("bot").map(String::as_str))))
}

async fn add_rule(State(app): State<AppState>, Extension(who): Extension<Principal>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
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
    app.db.audit("user", "rule.added", bot, Some(&r.id), json!({ "rule": r }));
    Ok((StatusCode::CREATED, Json(json!(r))))
}

async fn delete_rule(State(app): State<AppState>, Extension(who): Extension<Principal>, Path(id): Path<String>) -> Res {
    need_user(who)?;
    let r = app.db.rule(&id).ok_or_else(|| not_found("Rule"))?;
    app.db.delete_rule(&id);
    app.db.audit("user", "rule.removed", r.bot_id.as_deref(), Some(&id), json!({ "rule": r }));
    Ok(Json(json!({ "ok": true })))
}

// Approvals

async fn list_approvals(State(app): State<AppState>, Extension(who): Extension<Principal>, Query(q): Query<HashMap<String, String>>) -> Res {
    need_user(who)?;
    let limit = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100).clamp(1, 1000);
    let status = q.get("status").map(String::as_str).filter(|s| *s != "all");
    Ok(Json(json!(app.db.approvals(status, q.get("bot").map(String::as_str), limit))))
}

async fn approve(state: State<AppState>, who: Extension<Principal>, id: Path<String>, body: axum::body::Bytes) -> Res {
    decide(state, who, id, body, true).await
}

async fn deny(state: State<AppState>, who: Extension<Principal>, id: Path<String>, body: axum::body::Bytes) -> Res {
    decide(state, who, id, body, false).await
}

/// Body: `{remember?: "bot" | "global" | true, note?}`. Remember saves a rule for this exact call.
async fn decide(State(app): State<AppState>, Extension(who): Extension<Principal>, Path(id): Path<String>, body: axum::body::Bytes, approve: bool) -> Res {
    need_user(who)?;
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
    let note: Option<String> = v["note"].as_str().map(|n| n.trim().chars().take(500).collect()).filter(|n: &String| !n.is_empty());
    match app.decide(&id, approve, remember, note.as_deref()) {
        Ok(a) => Ok(Json(json!(a))),
        Err(DecideError::NotFound) => Err(not_found("Approval")),
        Err(DecideError::Closed(s)) => Err(ApiError(StatusCode::CONFLICT, format!("This approval is already {s}"))),
        Err(DecideError::TooLong) => Err(bad("This call is too long to remember. Approve or deny it without remembering.")),
    }
}

/// The harness hook (`botctl hook <harness>`) asks here before each tool call.
/// Body: `{from, harness, event}` with the harness's PreToolUse payload. Waits while
/// the user decides. Replies in plain text: "allow" or "deny", then the reason.
async fn check_approval(State(app): State<AppState>, Json(v): Json<Value>) -> Response {
    let reply = |allow: bool, reason: &str| {
        let body = format!("{}\n{reason}", if allow { "allow" } else { "deny" });
        ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
    };
    let Some(bot) = v["from"].as_str().and_then(|id| app.db.bot(id)) else {
        return reply(false, "Unknown Bot (BOT_ID)");
    };
    let e = &v["event"];
    let Some(tool) = e["tool_name"].as_str().filter(|t| !t.is_empty()) else {
        return reply(false, "The hook sent no tool name");
    };
    let harness = v["harness"].as_str().unwrap_or(&bot.harness).to_string();
    let cwd = e["cwd"].as_str().filter(|c| c.starts_with('/')).map(PathBuf::from);
    let verdict = app.check(&bot, &harness, tool, e["tool_input"].clone(), cwd).await;
    reply(verdict.action == policy::Action::Allow, &verdict.reason)
}

/// The append-only audit log, newest first. `?before=<id>` pages back.
async fn list_audit(State(app): State<AppState>, Extension(who): Extension<Principal>, Query(q): Query<HashMap<String, String>>) -> Res {
    need_user(who)?;
    let limit = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100).clamp(1, 1000);
    let before = q.get("before").and_then(|b| b.parse().ok());
    Ok(Json(json!(app.db.audit_events(limit, before))))
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

    fn basic(password: &str) -> String {
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
    async fn empty_password_requires_opt_in_even_on_loopback() {
        let (port, _) = serve(&String::new(), false, "").await;
        let host = format!("127.0.0.1:{port}");
        assert_eq!(status(port, &host, "").await, 401);
        assert_eq!(status(port, &host, &basic(&String::new())).await, 401);
    }

    #[tokio::test]
    async fn allow_no_auth_permits_anonymous_on_loopback() {
        let (port, _) = serve(&String::new(), true, "").await;
        let host = format!("127.0.0.1:{port}");
        assert_eq!(status(port, &host, "").await, 200);
    }

    /// The real router on a fresh install (policy: ask), with a random password.
    /// Returns the port, the app, and the Authorization headers of the person and of Bots.
    async fn serve_app() -> (u16, AppState, String, String) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let password = random_hex(16);
        let auth = Arc::new(Auth {
            password: password.clone(),
            allow_no_auth: false,
            bot_token: random_hex(16),
            hosts: allowed_hosts("127.0.0.1", port, ""),
        });
        let bot = format!("Bearer {}", auth.bot_token);
        let app = runner::test_app();
        let r = router(app.clone(), auth);
        tokio::spawn(async move {
            axum::serve(listener, r).await.unwrap();
        });
        (port, app, basic(&password), bot)
    }

    async fn call(port: u16, method: &str, path: &str, authorization: &str, body: &str) -> (u16, String) {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let auth = if authorization.is_empty() { String::new() } else { format!("Authorization: {authorization}\r\n") };
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut res = String::new();
        s.read_to_string(&mut res).await.unwrap();
        let code = res.split_whitespace().nth(1).unwrap().parse().unwrap();
        (code, res.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default())
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
        ] {
            assert_eq!(call(port, m, &p, &bot_auth, b).await.0, 403, "{m} {p}");
        }
        assert_eq!(app.db.global_policy().mode, policy::Mode::Ask);
        assert_eq!(call(port, "GET", "/api/policy", &bot_auth, "").await.0, 200);

        let (code, body) = call(port, "PUT", "/api/policy", &user, r#"{"timeoutMinutes":3}"#).await;
        assert_eq!((code, serde_json::from_str::<Value>(&body).unwrap()["policy"]["timeoutMinutes"].as_u64()), (200, Some(3)));
        assert_eq!(call(port, "PUT", "/api/policy", &user, r#"{"mode":"yolo"}"#).await.0, 400);
        let (_, audit) = call(port, "GET", "/api/audit", &user, "").await;
        assert_eq!(serde_json::from_str::<Value>(&audit).unwrap()[0]["action"], "policy.updated");
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
