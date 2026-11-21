//! People and their sign-ins: the user store, server-side sessions, one-time
//! sign-in codes, and the break-glass owner account. Permission checks live in
//! `rbac.rs`; the auth middleware in `main.rs` ties both to each request.
//! Design: docs/adr/0012-users-sessions-rbac.md.

use crate::audit::{Actor, ActorKind, Event, Source, Who};
use crate::db::{self, NewSession, Session, User, UserError, UserPatch};
use crate::rbac::{self, Principal, Role};
use crate::{bad, not_found, ApiError, AppState, Auth, Res};
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The owner, made on first start. Break-glass (AUTH_PASSWORD) signs in as this user,
/// and it keeps the `operator` id that ADR 0009's audit rows already use.
pub const OPERATOR: &str = "operator";
pub const SESSION_PREFIX: &str = "sbs_";
pub const CODE_PREFIX: &str = "sbc_";
/// `__Host-` makes browsers refuse this cookie unless it is Secure, Path=/, and set by
/// this exact host, so a sibling subdomain can't plant or overwrite it.
pub const COOKIE: &str = "__Host-superbot_session";

/// A new random secret: `prefix` plus 256 bits as hex.
pub fn new_secret(prefix: &str) -> String {
    format!("{prefix}{}", crate::random_hex(32))
}

/// SHA-256 as hex. Tokens and codes are 256-bit random, so a plain fast hash is
/// enough: there is nothing to brute-force, and lookups by hash leak no timing.
pub fn hash(secret: &str) -> String {
    Sha256::digest(secret.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Session lifetimes, in ms. Idle: since the last request. Max: since sign-in.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SessionConfig {
    pub idle_ms: i64,
    pub max_ms: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig { idle_ms: 7 * DAY, max_ms: 30 * DAY }
    }
}

const MINUTE: i64 = 60_000;
const DAY: i64 = 24 * 60 * MINUTE;

/// `30m`, `12h`, or `7d`, from 5 minutes to 365 days. Empty = `default`.
pub fn parse_duration(key: &str, raw: &str, default: i64) -> Result<i64, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(default);
    }
    let err = || format!("{key} must be a duration like 30m, 12h, or 7d (5m to 365d), not \"{raw}\"");
    let Some((n, unit)) = raw.len().checked_sub(1).and_then(|i| raw.split_at_checked(i)) else { return Err(err()) };
    let n: i64 = n.parse().map_err(|_| err())?;
    let ms = match unit {
        "m" => n * MINUTE,
        "h" => n * 60 * MINUTE,
        "d" => n * DAY,
        _ => return Err(err()),
    };
    if !(5 * MINUTE..=365 * DAY).contains(&ms) {
        return Err(err());
    }
    Ok(ms)
}

impl SessionConfig {
    pub fn from_env(idle: &str, max: &str) -> Result<SessionConfig, String> {
        let d = SessionConfig::default();
        Ok(SessionConfig {
            idle_ms: parse_duration("SESSION_IDLE_TIMEOUT", idle, d.idle_ms)?,
            max_ms: parse_duration("SESSION_MAX_AGE", max, d.max_ms)?,
        })
    }
}

/// AUTH_BREAK_GLASS: on unless set to 0/false/off, so installs from before users
/// keep their shared password after an upgrade.
pub fn break_glass_flag(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        _ => Err(format!("AUTH_BREAK_GLASS must be 1 or 0, not \"{raw}\"")),
    }
}

// Sign-in rate limit: failed POST /api/auth/login attempts per client IP.

const FAIL_LIMIT: u32 = 10;
const FAIL_WINDOW_MS: i64 = 10 * MINUTE;
const MAX_TRACKED: usize = 10_000;

/// Counts per client IP in fixed windows: `limit` per `window_ms`.
pub struct Limiter {
    hits: Mutex<HashMap<String, (i64, u32)>>,
    limit: u32,
    window_ms: i64,
}

impl Default for Limiter {
    fn default() -> Self {
        Limiter::new(FAIL_LIMIT, FAIL_WINDOW_MS)
    }
}

impl Limiter {
    pub fn new(limit: u32, window_ms: i64) -> Limiter {
        Limiter { hits: Mutex::default(), limit, window_ms }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (i64, u32)>> {
        self.hits.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Seconds to wait, when this IP has hit the limit.
    pub fn blocked(&self, ip: &str, at: i64) -> Option<i64> {
        self.wait(&self.lock(), ip, at)
    }

    fn wait(&self, m: &HashMap<String, (i64, u32)>, ip: &str, at: i64) -> Option<i64> {
        m.get(ip).filter(|(start, n)| *n >= self.limit && at - start < self.window_ms).map(|(start, _)| (start + self.window_ms - at + 999) / 1000)
    }

    pub fn fail(&self, ip: &str, at: i64) {
        self.count(&mut self.lock(), ip, at);
    }

    fn count(&self, m: &mut HashMap<String, (i64, u32)>, ip: &str, at: i64) {
        if !m.contains_key(ip) && m.len() >= MAX_TRACKED {
            m.retain(|_, (start, _)| at - *start < self.window_ms);
            if m.len() >= MAX_TRACKED {
                m.clear();
            }
        }
        let e = m.entry(ip.to_string()).or_insert((at, 0));
        if at - e.0 >= self.window_ms {
            *e = (at, 0);
        }
        e.1 += 1;
    }

    /// Counts one request, unless the IP is over the limit: then the seconds to wait.
    /// One lock for both, so concurrent requests can't share the last slot.
    pub fn hit(&self, ip: &str, at: i64) -> Option<i64> {
        let mut m = self.lock();
        self.wait(&m, ip, at).or_else(|| {
            self.count(&mut m, ip, at);
            None
        })
    }
}

// Cookies and CSRF.

/// The session token from `Cookie: __Host-superbot_session=...`, if any.
pub fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.trim().to_string())
}

/// HttpOnly so page scripts can't read it, Secure so it never crosses plain http
/// (browsers allow it on http://localhost), SameSite=Strict so other sites can't send it.
pub fn session_cookie(token: &str, max_age_ms: i64) -> String {
    format!("{COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}", max_age_ms / 1000)
}

pub fn clear_cookie() -> &'static str {
    "__Host-superbot_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
}

/// For writes on credentials the browser sends by itself (the session cookie, a cached
/// break-glass password, or none at all with ALLOW_NO_AUTH): the browser says the request
/// comes from this site. `Origin` must name the Host we were reached on; without it,
/// `Sec-Fetch-Site` must not be cross-site. Browsers send one of them on every cross-site
/// write, so a request with neither isn't from a browser page.
pub fn same_origin(headers: &HeaderMap) -> bool {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(origin) = headers.get(header::ORIGIN) {
        let o = origin.to_str().unwrap_or("");
        let rest = o.strip_prefix("https://").or_else(|| o.strip_prefix("http://"));
        return rest.is_some_and(|r| !host.is_empty() && r.eq_ignore_ascii_case(host));
    }
    match headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        Some(site) => site == "same-origin" || site == "none",
        None => true,
    }
}

// The caller, as the auth middleware found it.

#[derive(Clone, Debug)]
pub struct Caller {
    pub principal: Principal,
    /// The signed-in person. None for Bots, and for anonymous loopback dev (ALLOW_NO_AUTH).
    pub user: Option<User>,
    /// Set when the request came with a session cookie or token.
    pub session: Option<Session>,
    /// "session", "password" (break-glass Basic), "none" (ALLOW_NO_AUTH), or "bot_token".
    pub method: &'static str,
    /// The Bot a Bot's token was issued to (ADR 0029). Only ever set for `Principal::Bot`.
    pub bot: Option<String>,
    /// The teammate a Bot's token is bound to (ADR 0048): it acts only while the Bot's
    /// latest run is still theirs.
    pub bot_for: Option<String>,
    /// The id of the run token a Bot's request came with (ADR 0083), live only while its run is.
    pub bot_token: Option<String>,
}

/// The audit actor: the person, their email and role now, and how this request was
/// signed in. `method` is the caller's ("password", "none", ...); a session's own
/// method ("password", "code", "sso") wins. The subject is the SSO identity this
/// session signed in with, else the user's own (first linked) identity.
pub fn actor(a: &Auth, u: &User, s: Option<&Session>, method: &str) -> Actor {
    let provider = s.and_then(|s| s.idp_provider.clone());
    Actor {
        kind: ActorKind::User,
        id: Some(u.id.clone()),
        name: Some(u.name.clone()),
        subject: match (s.and_then(|s| s.idp_subject.as_ref()), &u.idp_issuer, &u.idp_subject) {
            (Some(sub), _, _) => Some(sub.clone()),
            (None, Some(i), Some(s)) => Some(format!("{i}|{s}")),
            _ => None,
        },
        email: u.email.clone(),
        role: Some(u.role.as_str().into()),
        method: Some(s.map_or(method, |s| s.method.as_str()).into()),
        idp: provider.as_deref().and_then(|p| crate::sso::idp_type(a, p)).map(String::from),
        idp_provider: provider,
        session: s.map(|s| s.id.clone()),
        on_behalf_of: None,
        asker: None,
    }
}

/// The owner account. Made on first start (and after an upgrade) from USER_NAME and
/// OWNER_EMAIL; later starts leave it alone.
pub fn ensure_operator(db: &db::Db, name: &str, email: Option<&str>) -> User {
    if let Some(u) = db.user(OPERATOR) {
        return u;
    }
    let email = email.map(str::trim).filter(|e| valid_email(e));
    let u = db
        .create_user(Some(OPERATOR), email, name, Role::Admin)
        .or_else(|_| db.create_user(Some(OPERATOR), None, name, Role::Admin))
        .expect("create the owner account");
    db.record(&Event::new(Actor::system("bootstrap"), "user.created").target("user", OPERATOR).details(json!({
        "email": u.email, "name": u.name, "role": u.role, "reason": "owner account (break-glass)",
    })));
    u
}

pub fn valid_email(e: &str) -> bool {
    let Some((local, domain)) = e.split_once('@') else { return false };
    (3..=254).contains(&e.len())
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && e.chars().all(|c| c.is_ascii_graphic() || !c.is_ascii())
        && !e.chars().any(char::is_control)
}

fn clean_name(v: &Value) -> Res<Option<String>> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) if !s.trim().is_empty() => Ok(Some(s.trim().chars().filter(|c| !c.is_control()).take(100).collect())),
        _ => Err(bad("name can't be empty")),
    }
}

pub fn user_view(u: &User) -> Value {
    json!({
        "id": u.id, "email": u.email, "name": u.name, "role": u.role, "status": u.status,
        "breakGlass": u.id == OPERATOR, "idpIssuer": u.idp_issuer, "idpSubject": u.idp_subject,
        "createdAt": u.created_at, "updatedAt": u.updated_at, "lastLoginAt": u.last_login_at,
        "tier": u.tier,
    })
}

/// A user as the admin portal lists them: how they last signed in, in the audit log's
/// terms (`authMethod`, `idp`, `idpProvider`, ADR 0019), their linked sign-ins, and any
/// code still waiting to be used (never the code itself, only its count and expiry).
fn admin_view(a: &Auth, u: &User, identities: &[db::Identity], pending: Option<&(i64, i64)>) -> Value {
    let idp = |provider: &str| crate::sso::idp_type(a, provider);
    let mut v = user_view(u);
    v["lastLogin"] = match u.last_login_at {
        None => Value::Null,
        Some(at) => json!({
            "at": at, "authMethod": u.last_login_method, "idpProvider": u.last_login_idp_provider,
            "idp": u.last_login_idp_provider.as_deref().and_then(idp),
        }),
    };
    v["identities"] = json!(identities
        .iter()
        .map(|i| json!({
            "id": i.id, "provider": i.provider, "idp": idp(&i.provider), "subject": i.subject, "email": i.email,
            "createdAt": i.created_at, "lastLoginAt": i.last_login_at,
        }))
        .collect::<Vec<_>>());
    v["pendingCodes"] = pending.map_or(Value::Null, |(n, exp)| json!({ "count": n, "expiresAt": exp }));
    if let Some(app) = &a.app {
        v["plan"] = crate::tier_usage(app, &u.id);
    }
    v
}

fn session_view(s: &Session, cfg: &SessionConfig) -> Value {
    let ends = s.expires_at.min(s.created_at + cfg.max_ms).min(s.last_seen_at + cfg.idle_ms);
    json!({
        "id": s.id, "userId": s.user_id, "kind": s.kind, "method": s.method, "idpSubject": s.idp_subject, "idpProvider": s.idp_provider, "label": s.label,
        "ip": s.ip, "userAgent": s.user_agent, "createdAt": s.created_at, "lastSeenAt": s.last_seen_at,
        "expiresAt": s.expires_at, "endsAt": ends,
    })
}

// Sign in and out.

/// The new session's token and how it's handed over. `idp` is the SSO provider id and
/// `issuer|subject` for SSO sign-ins.
pub fn start_session(a: &Auth, user: &User, method: &str, idp: Option<(&str, &str)>, cookie: bool, label: Option<&str>, source: &Source) -> (Session, String) {
    let token = new_secret(SESSION_PREFIX);
    let app = a.app.as_ref().expect("sessions need the database");
    let s = app.db.create_session(&NewSession {
        user_id: &user.id,
        token_hash: &hash(&token),
        kind: if cookie { "cookie" } else { "token" },
        method,
        idp_subject: idp.map(|i| i.1),
        idp_provider: idp.map(|i| i.0),
        label,
        ip: source.ip.as_deref(),
        user_agent: source.user_agent.as_deref(),
        expires_at: db::now() + a.sessions.max_ms,
    });
    (s, token)
}

/// The sign-in reply: `{user, session, token}`, with the cookie set instead of the
/// token returned for the web app. Never cached.
pub fn session_response(a: &Auth, user: &User, s: &Session, token: &str) -> Response {
    let cookie = s.kind == "cookie";
    let body = json!({ "user": user_view(user), "session": session_view(s, &a.sessions), "token": if cookie { Value::Null } else { json!(token) } });
    let mut res = Json(body).into_response();
    if cookie {
        res.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&session_cookie(token, a.sessions.max_ms)).unwrap());
    }
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// A sign-in label from a request: secrets masked, at most 60 characters.
pub fn clean_label(v: &Value) -> Option<String> {
    v.as_str()
        .map(|l| crate::audit::clip(&crate::secrets::redact::text(&crate::audit::redact_text(l.trim())), 60))
        .filter(|l| !l.is_empty())
}

pub fn too_many(retry: i64) -> Response {
    let mut r = (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "Too many failed sign-ins. Try again later." }))).into_response();
    r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(retry.max(1)));
    r
}

/// `POST /api/auth/login` `{password | code, session?: "cookie" | "token", label?}`.
/// No credentials needed (the middleware only checks Host). A password is the
/// break-glass login for the owner; a code is a one-time code an admin made.
/// "cookie" sets an HttpOnly cookie for the web app; "token" (default) returns a
/// bearer token for the client and botctl.
pub async fn login(Extension(a): Extension<Arc<Auth>>, Extension(source): Extension<Source>, headers: HeaderMap, Json(v): Json<Value>) -> Response {
    let Some(app) = a.app.as_ref() else {
        return ApiError(StatusCode::SERVICE_UNAVAILABLE, "No database".into()).into_response();
    };
    let cookie = match v["session"].as_str() {
        None | Some("token") => false,
        Some("cookie") => true,
        Some(_) => return bad("session must be \"cookie\" or \"token\"").into_response(),
    };
    if cookie && !same_origin(&headers) {
        return ApiError(StatusCode::FORBIDDEN, "Cross-site sign-in refused".into()).into_response();
    }
    let ip = source.ip.clone().unwrap_or_default();
    let at = db::now();
    if let Some(retry) = a.limiter.blocked(&ip, at) {
        return too_many(retry);
    }
    let label = clean_label(&v["label"]);
    if let Some(handoff) = v["sso"].as_str() {
        return crate::sso::redeem(&a, source, handoff, v["verifier"].as_str().unwrap_or(""), cookie, label.as_deref());
    }
    let code = v["code"].as_str().map(str::trim).filter(|c| !c.is_empty());
    let password = v["password"].as_str().filter(|p| !p.is_empty());
    let (user, method) = match (code, password) {
        (Some(code), _) => match app.db.use_login_code(&hash(code), at) {
            Some(u) => (Some(u), "code"),
            // Clients send anything shaped like a code as one, but an older password may look like that too.
            None if a.break_glass && !a.password.is_empty() && v["code"].as_str().is_some_and(|c| crate::same(c.as_bytes(), a.password.as_bytes())) => {
                (app.db.user(OPERATOR), "password")
            }
            None => (None, "code"),
        },
        (None, Some(p)) if a.break_glass && !a.password.is_empty() => {
            (crate::same(p.as_bytes(), a.password.as_bytes()).then(|| app.db.user(OPERATOR)).flatten(), "password")
        }
        (None, Some(_)) if a.allow_no_auth => (app.db.user(OPERATOR), "none"),
        (None, Some(_)) => {
            a.login_failed(&source, "password", Some("break_glass_off"));
            return ApiError(StatusCode::UNAUTHORIZED, "Password sign-in is off on this server. Use a sign-in code.".into()).into_response();
        }
        (None, None) => return bad("Send a password or a sign-in code").into_response(),
    };
    let Some(user) = user.filter(User::active) else {
        a.limiter.fail(&ip, at);
        a.login_failed(&source, method, None);
        let msg = if method == "code" { "That sign-in code is wrong, used, or expired." } else { "Wrong password." };
        return ApiError(StatusCode::UNAUTHORIZED, msg.into()).into_response();
    };
    let (s, token) = start_session(&a, &user, method, None, cookie, label.as_deref(), &source);
    let who = Who { actor: actor(&a, &user, Some(&s), method), source };
    app.db.record(&who.event("auth.login").target("session", &s.id).details(json!({ "method": method, "kind": s.kind, "label": s.label })));
    session_response(&a, &user, &s, &token)
}

/// Ends the current session. Always clears the cookie.
pub async fn logout(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>) -> Response {
    if let Some(s) = &c.session
        && app.db.revoke_session(&s.id, &s.user_id, "logout")
    {
        app.db.record(&by.event("auth.logout").target("session", &s.id));
    }
    ([(header::SET_COOKIE, clear_cookie())], Json(json!({ "ok": true }))).into_response()
}

pub async fn me(Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>) -> Json<Value> {
    Json(json!({
        "user": c.user.as_ref().map(user_view),
        "role": match c.principal { Principal::User(r) => json!(r), Principal::Bot => json!("bot") },
        "permissions": rbac::granted(c.principal),
        "method": c.method,
        "session": c.session.as_ref().map(|s| session_view(s, &a.sessions)),
        "breakGlass": a.break_glass,
        "landing": crate::landing(c.principal),
    }))
}

// Users (admin).

pub fn need_user_key(app: &AppState, key: &str) -> Res<User> {
    app.db.find_user(key).ok_or_else(|| not_found("User"))
}

pub async fn list_users(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>) -> Json<Value> {
    let ids = app.db.all_identities();
    let codes = app.db.pending_codes(db::now());
    let users = app.db.users();
    crate::storage::warm(&app, &users.iter().map(|u| u.id.clone()).collect::<Vec<_>>()).await;
    let list: Vec<Value> = users.iter().map(|u| admin_view(&a, u, ids.get(&u.id).map_or(&[], Vec::as_slice), codes.get(&u.id))).collect();
    Json(json!(list))
}

pub async fn get_user(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Path(key): Path<String>) -> Res {
    let u = need_user_key(&app, &key)?;
    crate::storage::warm(&app, std::slice::from_ref(&u.id)).await;
    Ok(Json(admin_view(&a, &u, &app.db.identities(&u.id), app.db.pending_codes(db::now()).get(&u.id))))
}

/// `GET /api/users/{key}/bots`: the Bots this user can see, with their access and any
/// grant, as ADR 0017 decides it for their role now. Read-only; grants are changed per Bot.
pub async fn user_bots(State(app): State<AppState>, Path(key): Path<String>) -> Res {
    let u = need_user_key(&app, &key)?;
    let viewer = if u.role == Role::Admin { crate::acl::Viewer::All } else { crate::acl::Viewer::User { id: u.id.clone(), role: u.role } };
    let grants = app.db.user_grants(&u.id);
    let owners: HashMap<String, String> = app.db.users().into_iter().map(|o| (o.id, o.name)).collect();
    let list: Vec<Value> = viewer
        .bots(&app.db)
        .into_iter()
        .map(|(b, access)| {
            json!({
                "bot": { "id": b.id, "name": b.name, "color": b.color, "shape": b.shape },
                "owner": { "id": b.owner_id, "name": owners.get(&b.owner_id) },
                "visibility": b.visibility, "access": access, "grant": grants.get(&b.id),
            })
        })
        .collect();
    Ok(Json(json!({ "user": user_view(&u), "active": u.active(), "bots": list })))
}

/// `{email, name?, role?}`. Role defaults to member.
pub async fn create_user(State(app): State<AppState>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    let email = v["email"].as_str().map(str::trim).filter(|e| valid_email(e)).ok_or_else(|| bad("A valid email is required"))?;
    let name = clean_name(&v["name"])?.unwrap_or_else(|| email.split('@').next().unwrap_or(email).to_string());
    let role = match &v["role"] {
        Value::Null => Role::Member,
        r => r.as_str().and_then(Role::parse).ok_or_else(|| bad("role must be admin, member, or readonly"))?,
    };
    let u = app.db.create_user(None, Some(email), &name, role).map_err(|e| user_error(&app, &by, e, None, Some(email)))?;
    record_created(&app, &by, &u, None);
    Ok((StatusCode::CREATED, Json(user_view(&u))))
}

fn user_error(app: &AppState, by: &Who, e: UserError, id: Option<&str>, email: Option<&str>) -> ApiError {
    match e {
        UserError::EmailTaken => ApiError(StatusCode::CONFLICT, e.to_string()),
        UserError::NoSeat => ApiError(StatusCode::FORBIDDEN, crate::license::refuse_seat(app, by, if id.is_some() { "enable" } else { "admin" }, id, email)),
        UserError::Db(e) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// `user.created`, as every way of adding a user logs it. `reason` says why, when it isn't an admin's form.
pub fn record_created(app: &AppState, by: &Who, u: &User, reason: Option<&str>) {
    let mut details = json!({ "email": u.email, "name": u.name, "role": u.role });
    if let Some(r) = reason {
        details["reason"] = json!(r);
    }
    app.db.record(&by.event("user.created").target("user", &u.id).details(details));
}

/// `{name?, email?, role?, status?: "active" | "disabled", tier?: name | null}`. A
/// tier is one `TIERS_FILE` lists; null puts them back on the default. Disabling ends the
/// user's sessions. The owner account can't be demoted or disabled: it is the way
/// back in (turn off AUTH_BREAK_GLASS instead).
pub async fn update_user(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(key): Path<String>, Json(v): Json<Value>) -> Res {
    let before = need_user_key(&app, &key)?;
    let mut p = UserPatch { name: clean_name(&v["name"])?, ..Default::default() };
    match &v["email"] {
        Value::Null => {}
        Value::String(e) if valid_email(e.trim()) => p.email = Some(Some(e.trim().to_string())),
        _ => return Err(bad("A valid email is required")),
    }
    if !v["role"].is_null() {
        p.role = Some(v["role"].as_str().and_then(Role::parse).ok_or_else(|| bad("role must be admin, member, or readonly"))?);
    }
    p.status = match v["status"].as_str() {
        None if v["status"].is_null() => None,
        Some("active") => Some("active"),
        Some("disabled") => Some("disabled"),
        _ => return Err(bad("status must be active or disabled")),
    };
    p.tier = match v.get("tier") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(t) => {
            let names = || app.tiers().all().iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ");
            let t = t.as_str().and_then(|t| app.tiers().get(t.trim())).ok_or_else(|| bad(format!("tier must be one of: {}", names())))?;
            Some(Some(t.name.clone()))
        }
    };
    let demotes = p.role.is_some_and(|r| r != Role::Admin) || p.status == Some("disabled");
    if before.id == OPERATOR && demotes {
        return Err(ApiError(StatusCode::CONFLICT, "The owner (break-glass) account stays an active admin. Set AUTH_BREAK_GLASS=0 to turn password sign-in off.".into()));
    }
    if demotes && by.actor.id.as_deref() == Some(before.id.as_str()) {
        return Err(ApiError(StatusCode::CONFLICT, "You can't demote or disable yourself. Ask another admin.".into()));
    }
    app.db.update_user(&before.id, p).map_err(|e| user_error(&app, &by, e, Some(&before.id), before.email.as_deref()))?;
    let after = need_user_key(&app, &before.id)?;
    let ev = |action: &str| by.event(action).target("user", &after.id);
    let mut changes = serde_json::Map::new();
    if before.name != after.name {
        changes.insert("name".into(), json!({ "from": before.name, "to": after.name }));
    }
    if before.email != after.email {
        changes.insert("email".into(), json!({ "from": before.email, "to": after.email }));
    }
    if !changes.is_empty() {
        app.db.record(&ev("user.updated").details(json!({ "changes": changes })));
    }
    if before.role != after.role {
        app.db.record(&ev("user.role_changed").details(json!({ "from": before.role, "to": after.role })));
    }
    if before.tier != after.tier {
        // `effective` is the tier they're on: an unset one is the default.
        let effective = |t: &Option<String>| app.tiers().of(t.as_deref()).name.clone();
        let details = json!({ "from": before.tier, "to": after.tier, "effectiveFrom": effective(&before.tier), "effectiveTo": effective(&after.tier) });
        app.db.record(&ev("user.tier_changed").details(details));
        crate::machines::resize::follow(&app, &by, &after.id, "admin", None, true);
        app.send(json!({ "type": "resync" }));
    }
    if before.status != after.status {
        if after.active() {
            let resumed = crate::handover::user_enabled(&app, &by, &after.id);
            app.db.record(&ev("user.enabled").details(json!({ "routinesResumed": resumed })));
        } else {
            a.sso.forget_user(&after.id);
            let n = app.db.revoke_user_sessions(&after.id, by.actor.id.as_deref().unwrap_or(""), "user disabled");
            let paused = crate::handover::user_disabled(&app, &by, &after.id);
            app.db.record(&ev("user.disabled").details(json!({ "sessionsRevoked": n, "routinesPaused": paused })));
        }
    }
    // Screen links don't know who opened them, so anyone losing access closes them all.
    let lost = (before.role != after.role && after.role != Role::Admin) || (before.active() && !after.active());
    if lost && let Some(screens) = &app.screens {
        screens.rotate_all().await;
    }
    if lost {
        crate::machines::screens::rotate_all(&app).await;
        let reason = if after.active() { crate::machines::offboard::ACCESS_LOST } else { crate::machines::offboard::DISABLED };
        crate::machines::offboard::left(&app, &by, &after.id, reason);
    }
    Ok(Json(user_view(&after)))
}

/// `{ttlMinutes?, replace?}` (default 60, up to 7 days). Returns the code once; only its
/// hash is kept. `replace: true` first drops the user's unused codes, so a regenerated
/// invite is the only one that works.
pub async fn create_login_code(State(app): State<AppState>, Extension(by): Extension<Who>, Path(key): Path<String>, body: axum::body::Bytes) -> Res<Response> {
    let u = need_user_key(&app, &key)?;
    if !u.active() {
        return Err(ApiError(StatusCode::CONFLICT, "This user is disabled. Enable them first.".into()));
    }
    let v: Value = if body.iter().all(u8::is_ascii_whitespace) { Value::Null } else { serde_json::from_slice(&body).map_err(|e| bad(format!("Invalid JSON: {e}")))? };
    let ttl = code_ttl(&v["ttlMinutes"], 60)?;
    let replace = match &v["replace"] {
        Value::Null => false,
        Value::Bool(b) => *b,
        _ => return Err(bad("replace must be true or false")),
    };
    let (code, expires) = issue_code(&app, &by, &u, ttl, replace);
    let mut res = Json(json!({ "code": code, "expiresAt": expires, "user": user_view(&u) })).into_response();
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

/// `ttlMinutes` for a sign-in code: 1 minute to 7 days.
pub fn code_ttl(v: &Value, default: i64) -> Res<i64> {
    match v {
        Value::Null => Ok(default),
        t => t.as_i64().filter(|t| (1..=7 * 24 * 60).contains(t)).ok_or_else(|| bad("ttlMinutes must be 1 to 10080")),
    }
}

/// A new one-time sign-in code for `u`, good for `ttl` minutes. Returns the code (only
/// its hash is kept) and when it expires. `replace` drops the user's unused codes first.
pub fn issue_code(app: &AppState, by: &Who, u: &User, ttl: i64, replace: bool) -> (String, i64) {
    let code = new_secret(CODE_PREFIX);
    let expires = db::now() + ttl * MINUTE;
    let created_by = by.actor.id.as_deref().unwrap_or("");
    let mut details = json!({ "ttlMinutes": ttl });
    if replace {
        details["replaced"] = json!(app.db.replace_login_codes(&hash(&code), &u.id, created_by, expires));
    } else {
        app.db.add_login_code(&hash(&code), &u.id, created_by, expires);
    }
    app.db.record(&by.event("user.login_code_created").target("user", &u.id).details(details));
    (code, expires)
}

// Sessions (admin).

pub async fn list_sessions(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Query(q): Query<HashMap<String, String>>) -> Res {
    let user = match q.get("user").map(String::as_str).filter(|u| !u.is_empty()) {
        Some(k) => Some(need_user_key(&app, k)?.id),
        None => None,
    };
    let list = app.db.live_sessions(user.as_deref(), db::now(), a.sessions.idle_ms, a.sessions.max_ms);
    Ok(Json(json!(list.iter().map(|s| session_view(s, &a.sessions)).collect::<Vec<_>>())))
}

pub async fn revoke_session(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let s = app.db.session(&id).filter(|s| s.revoked_at.is_none()).ok_or_else(|| not_found("Session"))?;
    if !app.db.revoke_session(&id, by.actor.id.as_deref().unwrap_or(""), "revoked by admin") {
        return Err(not_found("Session"));
    }
    app.db.record(&by.event("session.revoked").target("session", &id).details(json!({ "userId": s.user_id, "kind": s.kind })));
    Ok(Json(json!({ "ok": true })))
}

pub async fn revoke_user_sessions(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res {
    let u = need_user_key(&app, &key)?;
    // Codes go first: a redemption holds them until its session exists, so either that
    // session is made in time to be revoked below or the code is already gone.
    a.sso.forget_user(&u.id);
    let n = app.db.revoke_user_sessions(&u.id, by.actor.id.as_deref().unwrap_or(""), "revoked by admin");
    // A screen link doesn't know who opened it, so they all change.
    if let Some(screens) = &app.screens {
        screens.rotate_all().await;
    }
    crate::machines::screens::rotate_all(&app).await;
    app.db.record(&by.event("session.revoked_all").target("user", &u.id).details(json!({ "count": n })));
    Ok(Json(json!({ "revoked": n })))
}

/// Deletes sessions and codes that ended over 30 days ago, hourly.
pub fn start_pruning(app: AppState, cfg: SessionConfig) {
    tokio::spawn(async move {
        loop {
            app.db.prune_sessions(db::now() - 30 * DAY, cfg.idle_ms, cfg.max_ms);
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_hits_never_pass_the_limit() {
        let limiter = std::sync::Arc::new(Limiter::new(5, MINUTE));
        let passed: usize = (0..32)
            .map(|_| {
                let l = limiter.clone();
                std::thread::spawn(move || l.hit("203.0.113.9", 1_000).is_none())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum();
        assert_eq!(passed, 5);
        assert_eq!(limiter.hit("203.0.113.9", 1_000), Some(60));
        assert_eq!(limiter.hit("203.0.113.9", 1_000 + MINUTE), None, "a new window");
    }

    #[test]
    fn secrets_are_prefixed_random_and_hashed() {
        let a = new_secret(SESSION_PREFIX);
        assert!(a.starts_with("sbs_") && a.len() == 4 + 64);
        assert_ne!(a, new_secret(SESSION_PREFIX));
        assert_eq!(hash("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(hash(&a).len(), 64);
        assert_ne!(hash(&a), a);
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("X", "", 7), Ok(7));
        assert_eq!(parse_duration("X", "30m", 0), Ok(30 * MINUTE));
        assert_eq!(parse_duration("X", "12h", 0), Ok(12 * 60 * MINUTE));
        assert_eq!(parse_duration("X", " 7d ", 0), Ok(7 * DAY));
        for bad in ["1m", "366d", "10", "x", "5s", "-1d", "d", "1.5h", "5é"] {
            assert!(parse_duration("X", bad, 0).is_err(), "{bad}");
        }
        assert_eq!(SessionConfig::from_env("", "").unwrap(), SessionConfig::default());
        assert!(SessionConfig::from_env("forever", "").is_err());
    }

    #[test]
    fn break_glass_defaults_on() {
        assert_eq!(break_glass_flag(""), Ok(true));
        assert_eq!(break_glass_flag("1"), Ok(true));
        assert_eq!(break_glass_flag("off"), Ok(false));
        assert_eq!(break_glass_flag("0"), Ok(false));
        assert!(break_glass_flag("maybe").is_err());
    }

    #[test]
    fn limiter_blocks_after_ten_failures_per_ip_for_the_window() {
        let l = Limiter::default();
        for i in 0..FAIL_LIMIT {
            assert_eq!(l.blocked("1.2.3.4", i as i64), None);
            l.fail("1.2.3.4", i as i64);
        }
        assert!(l.blocked("1.2.3.4", 100).is_some());
        assert_eq!(l.blocked("5.6.7.8", 100), None);
        assert_eq!(l.blocked("1.2.3.4", FAIL_WINDOW_MS), None);
        l.fail("1.2.3.4", FAIL_WINDOW_MS);
        assert_eq!(l.blocked("1.2.3.4", FAIL_WINDOW_MS + 1), None, "a new window starts over");
    }

    #[test]
    fn cookies_and_origins() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "a=1; __Host-superbot_session=sbs_x ; b=2".parse().unwrap());
        assert_eq!(cookie_token(&h).as_deref(), Some("sbs_x"));
        let mut h2 = HeaderMap::new();
        h2.insert(header::COOKIE, "x__Host-superbot_session=sbs_y".parse().unwrap());
        assert_eq!(cookie_token(&h2), None);
        // The old name, which a sibling subdomain could plant, is not read.
        let mut h3 = HeaderMap::new();
        h3.insert(header::COOKIE, "superbot_session=sbs_z".parse().unwrap());
        assert_eq!(cookie_token(&h3), None);
        let c = session_cookie("sbs_x", 3_600_000);
        for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age=3600"] {
            assert!(c.contains(attr), "{c}");
        }

        let hdrs = |pairs: &[(&str, &str)]| {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
            }
            h
        };
        assert!(same_origin(&hdrs(&[("host", "bots.example.com"), ("origin", "https://bots.example.com")])));
        assert!(same_origin(&hdrs(&[("host", "localhost:8080"), ("origin", "http://LOCALHOST:8080")])));
        assert!(!same_origin(&hdrs(&[("host", "bots.example.com"), ("origin", "https://evil.example")])));
        assert!(!same_origin(&hdrs(&[("host", "bots.example.com"), ("origin", "https://bots.example.com.evil.example")])));
        assert!(!same_origin(&hdrs(&[("host", "bots.example.com"), ("origin", "null")])));
        assert!(!same_origin(&hdrs(&[("host", "bots.example.com"), ("sec-fetch-site", "cross-site")])));
        assert!(!same_origin(&hdrs(&[("host", "bots.example.com"), ("sec-fetch-site", "same-site")])));
        assert!(same_origin(&hdrs(&[("host", "bots.example.com"), ("sec-fetch-site", "same-origin")])));
        assert!(same_origin(&hdrs(&[("host", "bots.example.com")])));
    }

    #[test]
    fn emails() {
        for ok in ["a@b.co", "Alex.Smith+bots@example.com", "ü@exämple.de"] {
            assert!(valid_email(ok), "{ok}");
        }
        for bad in ["", "a", "a@b", "@b.co", "a@.co", "a@b.", "a b@c.co", "a@b@c.co", "a\n@b.co"] {
            assert!(!valid_email(bad), "{bad:?}");
        }
    }

    #[test]
    fn sessions_expire_idle_absolute_and_on_revoke() {
        let db = db::Db::open(&db::temp_path("sessions").join("app.sqlite")).unwrap();
        let owner = ensure_operator(&db, "Owner", Some("owner@example.com"));
        assert_eq!((owner.id.as_str(), owner.role), (OPERATOR, Role::Admin));
        assert_eq!(ensure_operator(&db, "Someone else", None).name, "Owner", "made once");
        let cfg = SessionConfig { idle_ms: 10 * MINUTE, max_ms: 60 * MINUTE };
        let token = new_secret(SESSION_PREFIX);
        fn new(token_hash: &str, max_ms: i64) -> NewSession<'_> {
            NewSession { user_id: OPERATOR, token_hash, kind: "token", method: "password", idp_subject: None, idp_provider: None, label: None, ip: None, user_agent: None, expires_at: db::now() + max_ms }
        }
        let s = db.create_session(&new(&hash(&token), cfg.max_ms));
        let t0 = s.created_at;
        let live = |at: i64| db.live_session(&hash(&token), at, cfg.idle_ms, cfg.max_ms).map(|(s, _)| s.id);
        assert_eq!(live(t0).as_deref(), Some(s.id.as_str()));
        assert_eq!(db.live_session(&token, t0, cfg.idle_ms, cfg.max_ms).map(|x| x.0.id), None, "the raw token is not the key");
        assert_eq!(live(t0 + 10 * MINUTE), None, "idle");
        db.touch_session(&s.id, t0 + 30_000);
        assert_eq!(db.session(&s.id).unwrap().last_seen_at, t0, "touches are throttled to one a minute");
        db.touch_session(&s.id, t0 + 9 * MINUTE);
        assert!(live(t0 + 15 * MINUTE).is_some(), "use resets the idle clock");
        for m in [17, 25, 33, 41, 49, 57] {
            db.touch_session(&s.id, t0 + m * MINUTE);
        }
        assert_eq!(live(t0 + 60 * MINUTE), None, "absolute limit, however active");
        // A shorter max age applies to sessions made before the change.
        assert_eq!(db.live_session(&hash(&token), t0 + 30 * MINUTE, cfg.idle_ms, 20 * MINUTE).map(|x| x.0.id), None);
        assert!(db.revoke_session(&s.id, "x", "test"));
        assert!(!db.revoke_session(&s.id, "x", "test"), "once");
        assert_eq!(live(t0 + MINUTE), None);
        assert!(db.live_sessions(None, t0 + MINUTE, cfg.idle_ms, cfg.max_ms).is_empty());

        // Disabling the user ends every session, without touching them one by one.
        let other = new_secret(SESSION_PREFIX);
        let s2 = db.create_session(&new(&hash(&other), cfg.max_ms));
        assert!(db.session_is_live(&s2.id, s2.created_at, cfg.idle_ms, cfg.max_ms));
        db.update_user(OPERATOR, UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
        assert!(!db.session_is_live(&s2.id, s2.created_at, cfg.idle_ms, cfg.max_ms));
        db.update_user(OPERATOR, UserPatch { status: Some("active"), ..Default::default() }).unwrap();
        assert_eq!(db.revoke_user_sessions(OPERATOR, "x", "test"), 1);
        assert_eq!(db.prune_sessions(db::now() + 1, cfg.idle_ms, cfg.max_ms), 2);
    }

    #[test]
    fn replacing_codes_at_once_leaves_one() {
        let db = std::sync::Arc::new(db::Db::open(&db::temp_path("replace").join("app.sqlite")).unwrap());
        let u = db.create_user(None, Some("r@example.com"), "R", Role::Member).unwrap();
        let at = db::now();
        let codes: Vec<String> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|_| {
                    let (db, id) = (&db, &u.id);
                    s.spawn(move || {
                        let code = new_secret(CODE_PREFIX);
                        db.replace_login_codes(&hash(&code), id, OPERATOR, at + MINUTE);
                        code
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(db.pending_codes(at)[&u.id].0, 1);
        assert_eq!(codes.iter().filter(|c| db.use_login_code(&hash(c), at).is_some()).count(), 1);
    }

    #[test]
    fn codes_work_once_before_expiry_for_active_users() {
        let db = db::Db::open(&db::temp_path("codes").join("app.sqlite")).unwrap();
        let u = db.create_user(None, Some("m@example.com"), "M", Role::Member).unwrap();
        assert!(db.create_user(None, Some("M@EXAMPLE.COM"), "Dup", Role::Member).is_err(), "emails are unique, any case");
        assert_eq!(db.find_user("M@Example.com").map(|x| x.id), Some(u.id.clone()));
        let code = new_secret(CODE_PREFIX);
        let at = db::now();
        db.add_login_code(&hash(&code), &u.id, OPERATOR, at + MINUTE);
        assert!(db.use_login_code(&hash(&code), at + MINUTE).is_none(), "expired");
        assert_eq!(db.use_login_code(&hash(&code), at).map(|x| x.id), Some(u.id.clone()));
        assert!(db.use_login_code(&hash(&code), at).is_none(), "used");
        let code2 = new_secret(CODE_PREFIX);
        db.add_login_code(&hash(&code2), &u.id, OPERATOR, at + MINUTE);
        db.update_user(&u.id, UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
        assert!(db.use_login_code(&hash(&code2), at).is_none(), "disabled users can't sign in");
    }
}
