//! Single sign-on with OpenID Connect (ADR 0013): the authorization code flow with
//! PKCE, state, and nonce, ending in the same sessions as every other sign-in.
//!
//! Web app: `/start` sets a short-lived binder cookie and sends the browser to the IdP;
//! `/callback` checks it, then sets the session cookie. Client app: `/start` carries
//! the app's own PKCE challenge; `/callback` sends a one-time code (`sbh_`) to the
//! app's redirect URL, which the app trades for a token at `POST /api/auth/login`
//! `{sso, verifier}`. Nobody is found by email: an identity is linked by an admin, or
//! made just in time when the provider allows it.

pub mod jwt;
mod provider;

use crate::audit::{Actor, ActorKind, Event, Outcome, Source, Who};
use crate::db::{self, Identity, JitError, NewIdentity, User};
use crate::rbac::Role;
use crate::users::{self, hash};
use crate::{ApiError, AppState, Auth, Res, bad, not_found};
use axum::Json;
use axum::extract::{Extension, OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use provider::Claims;
pub use provider::{ENTRA_AUTHORITY, Kind, Provider, guid, secure_url};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use url::Url;

/// How long someone has at the IdP before the sign-in expires.
const PENDING_TTL_MS: i64 = 10 * 60_000;
/// How long the client app has to redeem its one-time code.
const HANDOFF_TTL_MS: i64 = 2 * 60_000;
const MAX_PENDING: usize = 10_000;
const MAX_PENDING_PER_IP: usize = 20;
pub const HANDOFF_PREFIX: &str = "sbh_";
const BINDER: &str = "superbot_sso";

#[derive(Clone)]
enum Return {
    /// The web app. `binder` is the hash of the cookie that ties the callback to the
    /// browser that started, so nobody can finish a sign-in in someone else's browser.
    Cookie { binder: String },
    /// The client app: a one-time code to `redirect`, bound to its PKCE `challenge`.
    App { redirect: String, challenge: String, state: String },
}

impl Return {
    /// Where to send someone when it didn't work. `code` is one of a fixed few, so
    /// nothing from the IdP or the request lands in the page.
    fn fail(&self, code: &str) -> Response {
        match self {
            Return::Cookie { .. } => see(&format!("/login?error={code}")),
            Return::App { redirect, state, .. } => see(&with_query(redirect, &[("error", code), ("state", state)])),
        }
    }
}

struct Pending {
    provider: String,
    nonce: String,
    verifier: String,
    ip: String,
    label: Option<String>,
    expires: i64,
    ret: Return,
}

struct Handoff {
    user_id: String,
    provider: String,
    claims: Claims,
    challenge: String,
    label: Option<String>,
    expires: i64,
}

pub struct Sso {
    pub providers: Vec<Arc<Provider>>,
    /// SSO_PUBLIC_URL: where the IdP sends people back to.
    public_url: String,
    /// Its `host[:port]`, to compare with Host headers.
    public_host: String,
    /// SSO_APP_REDIRECTS: where the client app may ask its one-time code to be sent.
    app_redirects: Vec<String>,
    pending: Mutex<HashMap<String, Pending>>,
    handoffs: Mutex<HashMap<String, Handoff>>,
    http: OnceLock<reqwest::Client>,
    /// Least time between JWKS fetches for a key id we don't know.
    pub refresh_gap: Duration,
}

impl Default for Sso {
    fn default() -> Sso {
        Sso {
            providers: Vec::new(),
            public_url: String::new(),
            public_host: String::new(),
            app_redirects: Vec::new(),
            pending: Mutex::default(),
            handoffs: Mutex::default(),
            http: OnceLock::new(),
            refresh_gap: Duration::from_secs(60),
        }
    }
}

fn random() -> String {
    B64.encode(crate::random_bytes(32))
}

fn s256(verifier: &str) -> String {
    B64.encode(Sha256::digest(verifier.as_bytes()))
}

/// RFC 3986 unreserved characters, as PKCE values and our state use.
fn unreserved(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

fn with_query(base: &str, pairs: &[(&str, &str)]) -> String {
    let mut u = Url::parse(base).expect("checked at startup");
    u.query_pairs_mut().extend_pairs(pairs);
    u.into()
}

fn see(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(l) => (StatusCode::SEE_OTHER, [(header::LOCATION, l)]).into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

fn no_store(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    r
}

fn binder_cookie(value: &str, max_age_s: i64) -> HeaderValue {
    HeaderValue::from_str(&format!("{BINDER}={value}; Path=/api/auth/sso; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age_s}")).unwrap()
}

fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim())
}

/// A redirect the client app may use: a custom scheme (`superbot://auth`), or an
/// https page (http only to this machine). No query or fragment: we add the query.
fn app_redirect_ok(r: &str) -> bool {
    let Ok(u) = Url::parse(r) else { return false };
    let scheme_ok = match u.scheme() {
        "http" | "https" => secure_url(r),
        "javascript" | "data" | "file" | "vbscript" | "blob" | "about" => false,
        _ => true,
    };
    scheme_ok && u.query().is_none() && u.fragment().is_none() && !r.contains(['?', '#'])
}

impl Sso {
    pub fn from_env() -> Result<Sso, String> {
        Sso::from_vars(&|k| std::env::var(k).ok())
    }

    /// Reads SSO_* settings (see docs/sso/entra.md). No SSO_PROVIDERS: SSO is off.
    pub fn from_vars(get: &dyn Fn(&str) -> Option<String>) -> Result<Sso, String> {
        let var = |k: &str| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let list = |k: &str| var(k).map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>()).unwrap_or_default();
        let ids: Vec<String> = list("SSO_PROVIDERS").iter().map(|s| s.to_ascii_lowercase()).collect();
        let mut sso = Sso::default();
        if ids.is_empty() {
            return Ok(sso);
        }
        let public = var("SSO_PUBLIC_URL").ok_or("SSO_PUBLIC_URL is required with SSO_PROVIDERS: the address people open SuperBot at, like https://superbot.example.com")?;
        let public = public.trim_end_matches('/').to_string();
        let u = Url::parse(&public).ok().filter(|u| secure_url(&public) && u.path() == "/" && u.query().is_none() && u.fragment().is_none());
        let u = u.ok_or("SSO_PUBLIC_URL must be an https address with no path, like https://superbot.example.com (http only on loopback)")?;
        sso.public_host = match u.port() {
            Some(p) => format!("{}:{p}", u.host_str().unwrap_or("")),
            None => u.host_str().unwrap_or("").to_string(),
        };
        sso.public_url = public;
        sso.app_redirects = match list("SSO_APP_REDIRECTS") {
            l if l.is_empty() => vec!["superbot://auth".into()],
            l => l,
        };
        if let Some(r) = sso.app_redirects.iter().find(|r| !app_redirect_ok(r)) {
            return Err(format!("SSO_APP_REDIRECTS: {r} is not an app redirect (a custom scheme like superbot://auth, or https; no query)"));
        }
        for id in ids {
            if id.is_empty() || id.len() > 32 || !id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
                return Err(format!("SSO_PROVIDERS: \"{id}\" must be lowercase letters and digits"));
            }
            if sso.provider(&id).is_some() {
                return Err(format!("SSO_PROVIDERS lists {id} twice"));
            }
            sso.providers.push(Arc::new(parse_provider(&id, &var, &list)?));
        }
        Ok(sso)
    }

    pub fn provider(&self, id: &str) -> Option<&Arc<Provider>> {
        self.providers.iter().find(|p| p.id == id)
    }

    fn http(&self) -> &reqwest::Client {
        self.http.get_or_init(|| {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(concat!("SuperBot/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("HTTP client")
        })
    }

    fn redirect_uri(&self, id: &str) -> String {
        format!("{}/api/auth/sso/{id}/callback", self.public_url)
    }

    /// Remembers a sign-in in progress. False when there are too many.
    fn hold(&self, state: &str, p: Pending, at: i64) -> bool {
        let mut m = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, p| p.expires > at);
        if m.len() >= MAX_PENDING || m.values().filter(|o| o.ip == p.ip).count() >= MAX_PENDING_PER_IP {
            return false;
        }
        m.insert(hash(state), p);
        true
    }

    /// Each state works once: a replayed callback finds nothing.
    fn take(&self, state: &str, at: i64) -> Option<Pending> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&hash(state)).filter(|p| p.expires > at)
    }
}

type Var<'a> = dyn Fn(&str) -> Option<String> + 'a;
type List<'a> = dyn Fn(&str) -> Vec<String> + 'a;

fn parse_provider(id: &str, var: &Var, list: &List) -> Result<Provider, String> {
    let key = |k: &str| format!("SSO_{}_{k}", id.to_ascii_uppercase());
    let ty = var(&key("TYPE")).map(|t| t.to_ascii_lowercase()).unwrap_or_else(|| if id == "entra" { "entra".into() } else { String::new() });
    let client_id = var(&key("CLIENT_ID")).ok_or_else(|| format!("{} is required", key("CLIENT_ID")))?;
    let jit_role = match var(&key("JIT_ROLE")).map(|r| r.to_ascii_lowercase()).as_deref() {
        None | Some("off") => None,
        Some(r) => Some(Role::parse(r).ok_or_else(|| format!("{} must be off, readonly, member, or admin", key("JIT_ROLE")))?),
    };
    let scopes = var(&key("SCOPES")).unwrap_or_else(|| "openid profile email".into());
    if !scopes.split_whitespace().any(|s| s == "openid") {
        return Err(format!("{} must include openid", key("SCOPES")));
    }
    let (kind, label) = match ty.as_str() {
        "entra" => {
            let authority = var(&key("AUTHORITY")).unwrap_or_else(|| ENTRA_AUTHORITY.into()).trim_end_matches('/').to_string();
            if !secure_url(&authority) {
                return Err(format!("{} must be an https URL", key("AUTHORITY")));
            }
            let tenant = var(&key("TENANT")).ok_or_else(|| format!("{} is required: your directory (tenant) id, or organizations with {}", key("TENANT"), key("ALLOWED_TENANTS")))?;
            let mut allowed = Vec::new();
            for t in list(&key("ALLOWED_TENANTS")) {
                allowed.push(guid(&t).ok_or_else(|| format!("{}: {t} is not a tenant id (a GUID)", key("ALLOWED_TENANTS")))?);
            }
            let tenant = match (guid(&tenant), tenant.to_ascii_lowercase().as_str()) {
                (Some(_), _) if !allowed.is_empty() => {
                    return Err(format!("{} is only for {}=organizations or common", key("ALLOWED_TENANTS"), key("TENANT")));
                }
                (Some(t), _) => t,
                (None, t @ ("organizations" | "common")) if !allowed.is_empty() => t.to_string(),
                (None, "organizations" | "common") => {
                    return Err(format!("{}=organizations or common accepts every Microsoft tenant: list the ones you trust in {}", key("TENANT"), key("ALLOWED_TENANTS")));
                }
                (None, "consumers") => return Err("Personal Microsoft accounts (consumers) are not supported".into()),
                (None, _) => return Err(format!("{} must be a tenant id (a GUID), organizations, or common", key("TENANT"))),
            };
            (Kind::Entra { authority, tenant, allowed }, "Microsoft")
        }
        "oidc" => {
            let issuer = var(&key("ISSUER")).ok_or_else(|| format!("{} is required", key("ISSUER")))?;
            if !secure_url(&issuer) {
                return Err(format!("{} must be an https URL", key("ISSUER")));
            }
            (Kind::Oidc { issuer }, id)
        }
        "" => return Err(format!("{} is required: entra or oidc", key("TYPE"))),
        t => return Err(format!("{}: unknown type {t} (entra or oidc)", key("TYPE"))),
    };
    let label = var(&key("LABEL")).map(|l| crate::audit::clip(&l, 40)).unwrap_or_else(|| label.to_string());
    Ok(Provider::new(id, &label, kind, &client_id, &scopes, jit_role))
}

// Audit

fn claim_details(d: &mut Value, c: &Claims) {
    d["issuer"] = json!(c.issuer);
    d["subject"] = json!(c.subject);
    d["tenant"] = json!(c.tenant);
}

/// Failures anyone can cause without the IdP's help, by opening a callback URL.
const UNVOUCHED: [&str; 5] = ["unknown_state", "wrong_provider", "binder_mismatch", "idp_error", "missing_code"];

/// A failed SSO sign-in. The ones in UNVOUCHED are throttled like other failed sign-ins.
fn failed(a: &Auth, source: &Source, provider: &str, reason: &str, c: Option<&Claims>, extra: Value) {
    let mut d = json!({ "method": "sso", "provider": provider, "reason": reason });
    if let Some(c) = c {
        claim_details(&mut d, c);
    }
    if UNVOUCHED.contains(&reason) {
        let client = format!("{}|sso", source.ip.as_deref().unwrap_or(""));
        let Some(missed) = a.logins.failure(&client, db::now()) else { return };
        d["unloggedSinceLast"] = json!(missed);
    }
    if let (Value::Object(d), Value::Object(e)) = (&mut d, extra) {
        d.extend(e);
    }
    let actor = Actor { kind: ActorKind::User, id: None, name: None, subject: c.map(Claims::key) };
    a.record(Who { actor, source: source.clone() }.event("auth.login_failed").outcome(Outcome::Failure).details(d));
}

fn signed_in(a: &Auth, user: &User, s: &db::Session, provider: &str, c: &Claims, source: &Source) {
    let mut d = json!({ "method": "sso", "provider": provider, "kind": s.kind, "label": s.label });
    claim_details(&mut d, c);
    let who = Who { actor: users::actor(user, Some(s)), source: source.clone() };
    a.record(who.event("auth.login").target("session", &s.id).details(d));
}

// The flow

/// `GET /api/auth/sso`: the providers the sign-in page offers.
pub async fn list(Extension(a): Extension<Arc<Auth>>) -> Json<Value> {
    let ready = a.sso.providers.iter().filter(|p| p.ready());
    Json(json!({ "providers": ready.map(|p| json!({ "id": p.id, "label": p.label, "type": p.type_name() })).collect::<Vec<_>>() }))
}

/// `GET /api/auth/sso/{id}/start?session=cookie` (web), or
/// `?session=token&redirect=&challenge=&state=&label=` (client app): off to the IdP.
pub async fn start(
    Extension(a): Extension<Arc<Auth>>,
    Extension(source): Extension<Source>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let sso = &a.sso;
    let ret = match q.get("session").map(String::as_str) {
        None | Some("cookie") => Return::Cookie { binder: String::new() },
        Some("token") => {
            let Some(redirect) = q.get("redirect").filter(|r| sso.app_redirects.contains(r)) else {
                return bad("redirect must be one of SSO_APP_REDIRECTS").into_response();
            };
            let challenge = q.get("challenge").filter(|c| c.len() == 43 && unreserved(c));
            let state = q.get("state").filter(|s| (1..=128).contains(&s.len()) && unreserved(s));
            let (Some(challenge), Some(state)) = (challenge, state) else {
                return bad("challenge (PKCE S256) and state are required").into_response();
            };
            Return::App { redirect: redirect.clone(), challenge: challenge.clone(), state: state.clone() }
        }
        Some(_) => return bad("session must be \"cookie\" or \"token\"").into_response(),
    };
    let Some(p) = sso.provider(&id).filter(|p| p.ready()) else { return no_store(ret.fail("sso_unavailable")) };
    // The binder cookie must be set on the host the IdP sends the browser back to.
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    if matches!(ret, Return::Cookie { .. }) && !host.eq_ignore_ascii_case(&sso.public_host) {
        return no_store(see(&format!("{}{}", sso.public_url, uri.path_and_query().map(|p| p.as_str()).unwrap_or(""))));
    }
    let (ip, at) = (source.ip.clone().unwrap_or_default(), db::now());
    if a.limiter.blocked(&ip, at).is_some() {
        return no_store(ret.fail("sso_too_many"));
    }
    let meta = match p.metadata(sso.http()).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("SSO {id}: discovery failed: {e}");
            return no_store(ret.fail("sso_failed"));
        }
    };
    let (state, nonce, verifier, binder) = (random(), random(), random(), random());
    let ret = match ret {
        Return::Cookie { .. } => Return::Cookie { binder: hash(&binder) },
        r => r,
    };
    let label = users::clean_label(&json!(q.get("label")));
    let pending = Pending { provider: id.clone(), nonce: nonce.clone(), verifier: verifier.clone(), ip, label, expires: at + PENDING_TTL_MS, ret: ret.clone() };
    if !sso.hold(&state, pending, at) {
        return no_store(ret.fail("sso_too_many"));
    }
    let mut url = Url::parse(&meta.authorization_endpoint).expect("checked by secure_url");
    url.query_pairs_mut().extend_pairs([
        ("client_id", p.client_id.as_str()),
        ("response_type", "code"),
        ("response_mode", "query"),
        ("redirect_uri", &sso.redirect_uri(&id)),
        ("scope", &p.scopes),
        ("state", &state),
        ("nonce", &nonce),
        ("code_challenge", &s256(&verifier)),
        ("code_challenge_method", "S256"),
    ]);
    if matches!(p.kind, Kind::Entra { .. }) {
        url.query_pairs_mut().append_pair("prompt", "select_account");
    }
    let mut res = see(url.as_str());
    if matches!(ret, Return::Cookie { .. }) {
        res.headers_mut().insert(header::SET_COOKIE, binder_cookie(&binder, PENDING_TTL_MS / 1000));
    }
    no_store(res)
}

const SIGNED_IN: &str = r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="refresh" content="0;url=/"><title>SuperBot</title><p style="font:16px system-ui;margin:2rem">Signed in. <a href="/">Continue to SuperBot</a></p>"#;

/// `GET /api/auth/sso/{id}/callback?code&state`: the IdP sends the browser back here.
pub async fn callback(
    Extension(a): Extension<Arc<Auth>>,
    Extension(source): Extension<Source>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let mut res = finish(&a, &source, &headers, &id, &q).await;
    res.headers_mut().append(header::SET_COOKIE, binder_cookie("", 0));
    no_store(res)
}

async fn finish(a: &Auth, source: &Source, headers: &HeaderMap, id: &str, q: &HashMap<String, String>) -> Response {
    let (sso, (ip, at)) = (&a.sso, (source.ip.clone().unwrap_or_default(), db::now()));
    let Some(app) = a.app.as_ref() else { return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    let Some(pending) = q.get("state").and_then(|s| sso.take(s, at)) else {
        a.limiter.fail(&ip, at);
        failed(a, source, id, "unknown_state", None, json!({}));
        return see("/login?error=sso_expired");
    };
    let ret = &pending.ret;
    if pending.provider != id {
        a.limiter.fail(&ip, at);
        failed(a, source, id, "wrong_provider", None, json!({}));
        return ret.fail("sso_failed");
    }
    if let Return::Cookie { binder } = ret
        && !read_cookie(headers, BINDER).is_some_and(|c| crate::same(hash(c).as_bytes(), binder.as_bytes()))
    {
        a.limiter.fail(&ip, at);
        failed(a, source, id, "binder_mismatch", None, json!({}));
        return ret.fail("sso_expired");
    }
    if let Some(err) = q.get("error") {
        failed(a, source, id, "idp_error", None, json!({ "idpError": crate::audit::clip(err, 64) }));
        return ret.fail(if err == "access_denied" { "sso_cancelled" } else { "sso_failed" });
    }
    let (Some(code), Some(p)) = (q.get("code").filter(|c| !c.is_empty() && c.len() <= 4096), sso.provider(id)) else {
        failed(a, source, id, "missing_code", None, json!({}));
        return ret.fail("sso_failed");
    };
    if a.limiter.blocked(&ip, at).is_some() {
        return ret.fail("sso_too_many");
    }
    let claims = match p.sign_in(sso.http(), code, &sso.redirect_uri(id), &pending.verifier, &pending.nonce, sso.refresh_gap).await {
        Ok(c) => c,
        Err(e) => {
            a.limiter.fail(&ip, at);
            failed(a, source, id, e.0, None, json!({}));
            return ret.fail("sso_failed");
        }
    };
    let user = match resolve(app, p, &claims) {
        Ok(u) => u,
        Err((reason, code)) => {
            failed(a, source, id, reason, Some(&claims), json!({}));
            return ret.fail(code);
        }
    };
    match ret {
        Return::Cookie { .. } => {
            let label = pending.label.as_deref().or(Some("Web"));
            let (s, token) = users::start_session(a, &user, "sso", Some(&claims.key()), true, label, source);
            signed_in(a, &user, &s, id, &claims, source);
            let mut res = Html(SIGNED_IN).into_response();
            res.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&users::session_cookie(&token, a.sessions.max_ms)).unwrap());
            res
        }
        Return::App { redirect, challenge, state } => {
            let code = users::new_secret(HANDOFF_PREFIX);
            let h = Handoff { user_id: user.id, provider: id.into(), claims, challenge: challenge.clone(), label: pending.label.clone(), expires: at + HANDOFF_TTL_MS };
            let mut m = sso.handoffs.lock().unwrap_or_else(|e| e.into_inner());
            m.retain(|_, h| h.expires > at);
            if m.len() >= MAX_PENDING {
                return ret.fail("sso_too_many");
            }
            m.insert(hash(&code), h);
            see(&with_query(redirect, &[("code", &code), ("state", state)]))
        }
    }
}

/// The user an identity belongs to: linked by an admin, or made now (just in time).
/// Err is (audit reason, page error code).
fn resolve(app: &AppState, p: &Provider, c: &Claims) -> Result<User, (&'static str, &'static str)> {
    let found = match app.db.identity(&c.issuer, &c.subject) {
        Some(f) => f,
        None => {
            let Some(role) = p.jit_role else { return Err(("not_linked", "sso_not_linked")) };
            let email = c.email.as_deref().map(str::trim).filter(|e| users::valid_email(e));
            let name = c.name.clone().or_else(|| email.map(String::from)).unwrap_or_else(|| format!("{} user", p.label));
            let new = NewIdentity { provider: &p.id, issuer: &c.issuer, subject: &c.subject, tenant: c.tenant.as_deref(), email, created_by: Some("sso") };
            match app.db.create_sso_user(email, &name, role, &new) {
                Ok(u) => {
                    let mut d = json!({ "email": u.email, "name": u.name, "role": role, "provider": p.id, "reason": "just-in-time sign-up" });
                    claim_details(&mut d, c);
                    app.db.record(&Event::new(Actor::system("sso"), "user.created").target("user", &u.id).details(d));
                }
                // Never merged by email: an admin links the identity to the existing user.
                Err(JitError::EmailTaken) => return Err(("email_taken", "sso_email_taken")),
                Err(JitError::IdentityTaken) => {}
                Err(JitError::Database) => return Err(("database", "sso_failed")),
            }
            app.db.identity(&c.issuer, &c.subject).ok_or(("database", "sso_failed"))?
        }
    };
    let (identity, user) = found;
    if !user.active() {
        return Err(("user_disabled", "sso_not_allowed"));
    }
    app.db.touch_identity(&identity.id, c.email.as_deref(), db::now());
    Ok(user)
}

/// `POST /api/auth/login {sso, verifier}`: the client app trades its one-time code
/// and PKCE verifier for a session.
pub fn redeem(a: &Auth, source: Source, code: &str, verifier: &str, cookie: bool, label: Option<&str>) -> Response {
    let Some(app) = a.app.as_ref() else { return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    let (ip, at) = (source.ip.clone().unwrap_or_default(), db::now());
    if let Some(retry) = a.limiter.blocked(&ip, at) {
        return users::too_many(retry);
    }
    // Taken out first, so a wrong verifier spends the code too.
    let h = a.sso.handoffs.lock().unwrap_or_else(|e| e.into_inner()).remove(&hash(code));
    let h = h.filter(|h| h.expires > at && crate::same(s256(verifier).as_bytes(), h.challenge.as_bytes()));
    let found = h.and_then(|h| Some((app.db.user(&h.user_id).filter(User::active)?, h)));
    let Some((user, h)) = found else {
        a.limiter.fail(&ip, at);
        a.login_failed(&source, "sso", Some("bad_handoff"));
        return ApiError(StatusCode::UNAUTHORIZED, "That sign-in expired or was already used. Try again.".into()).into_response();
    };
    let label = label.or(h.label.as_deref());
    let (s, token) = users::start_session(a, &user, "sso", Some(&h.claims.key()), cookie, label, &source);
    signed_in(a, &user, &s, &h.provider, &h.claims, &source);
    users::session_response(a, &user, &s, &token)
}

// Admin: linking identities

fn identity_view(i: &Identity) -> Value {
    json!(i)
}

/// `GET /api/users/{key}/identities`
pub async fn list_identities(State(app): State<AppState>, Path(key): Path<String>) -> Res {
    let u = users::need_user_key(&app, &key)?;
    Ok(Json(json!(app.db.identities(&u.id).iter().map(identity_view).collect::<Vec<_>>())))
}

/// `POST /api/users/{key}/identities {provider, subject, tenant?}`. For Entra the
/// subject is the user's object id; the tenant defaults to the provider's own.
pub async fn link_identity(
    State(app): State<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
    Json(v): Json<Value>,
) -> Res<(StatusCode, Json<Value>)> {
    let u = users::need_user_key(&app, &key)?;
    let pid = v["provider"].as_str().unwrap_or("");
    let p = a.sso.provider(pid).ok_or_else(|| {
        let known: Vec<&str> = a.sso.providers.iter().map(|p| p.id.as_str()).collect();
        bad(if known.is_empty() { "SSO is off: set SSO_PROVIDERS".to_string() } else { format!("provider must be one of: {}", known.join(", ")) })
    })?;
    let subject = p.subject(v["subject"].as_str().unwrap_or("")).map_err(bad)?;
    let (issuer, tenant) = p.issuer_for(v["tenant"].as_str().filter(|t| !t.trim().is_empty())).map_err(bad)?;
    let new = NewIdentity { provider: &p.id, issuer: &issuer, subject: &subject, tenant: tenant.as_deref(), email: None, created_by: by.actor.id.as_deref() };
    let i = app.db.link_identity(&u.id, &new).map_err(|e| ApiError(StatusCode::CONFLICT, e))?;
    app.db.record(&by.event("user.identity_linked").target("user", &u.id).details(json!({ "identity": i.id, "provider": i.provider, "issuer": i.issuer, "subject": i.subject, "tenant": i.tenant })));
    Ok((StatusCode::CREATED, Json(identity_view(&i))))
}

/// `DELETE /api/users/{key}/identities/{id}`. The user's sessions stay; revoke them separately.
pub async fn unlink_identity(State(app): State<AppState>, Extension(by): Extension<Who>, Path((key, id)): Path<(String, String)>) -> Res {
    let u = users::need_user_key(&app, &key)?;
    let i = app.db.unlink_identity(&u.id, &id).ok_or_else(|| not_found("Identity"))?;
    app.db.record(&by.event("user.identity_unlinked").target("user", &u.id).details(json!({ "identity": i.id, "provider": i.provider, "issuer": i.issuer, "subject": i.subject })));
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const T1: &str = "11111111-1111-1111-1111-111111111111";

    fn parse(vars: &[(&str, &str)]) -> Result<Sso, String> {
        let m: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Sso::from_vars(&|k| m.get(k).cloned())
    }

    fn entra(extra: &[(&'static str, &'static str)]) -> Result<Sso, String> {
        let mut v = vec![("SSO_PROVIDERS", "entra"), ("SSO_PUBLIC_URL", "https://bot.example.com/"), ("SSO_ENTRA_CLIENT_ID", "c1"), ("SSO_ENTRA_TENANT", T1)];
        for (k, val) in extra {
            v.retain(|(old, _)| old != k);
            v.push((k, val));
        }
        parse(&v)
    }

    #[test]
    fn off_without_providers() {
        assert!(parse(&[]).unwrap().providers.is_empty());
        assert!(parse(&[("SSO_PROVIDERS", " ")]).unwrap().providers.is_empty());
    }

    #[test]
    fn reads_an_entra_provider_with_safe_defaults() {
        let s = entra(&[]).unwrap();
        let p = s.provider("entra").unwrap();
        assert_eq!((p.label.as_str(), p.type_name(), p.jit_role, p.scopes.as_str()), ("Microsoft", "entra", None, "openid profile email"));
        assert_eq!((s.public_url.as_str(), s.public_host.as_str()), ("https://bot.example.com", "bot.example.com"));
        assert_eq!(s.app_redirects, ["superbot://auth"]);
        assert_eq!(s.redirect_uri("entra"), "https://bot.example.com/api/auth/sso/entra/callback");
        assert_eq!(entra(&[("SSO_ENTRA_JIT_ROLE", "member")]).unwrap().providers[0].jit_role, Some(Role::Member));
        let multi = entra(&[("SSO_ENTRA_TENANT", "organizations"), ("SSO_ENTRA_ALLOWED_TENANTS", "22222222-2222-2222-2222-222222222222")]).unwrap();
        assert!(matches!(&multi.providers[0].kind, Kind::Entra { tenant, allowed, .. } if tenant == "organizations" && allowed.len() == 1));
    }

    #[test]
    fn refuses_unsafe_or_unclear_settings() {
        for (vars, why) in [
            (vec![("SSO_ENTRA_TENANT", "common")], "common without an allow-list"),
            (vec![("SSO_ENTRA_TENANT", "organizations")], "organizations without an allow-list"),
            (vec![("SSO_ENTRA_TENANT", "consumers")], "personal accounts"),
            (vec![("SSO_ENTRA_TENANT", "contoso.onmicrosoft.com")], "a domain, not the tenant id"),
            (vec![("SSO_ENTRA_ALLOWED_TENANTS", "22222222-2222-2222-2222-222222222222")], "allow-list with a single tenant"),
            (vec![("SSO_ENTRA_TENANT", "common"), ("SSO_ENTRA_ALLOWED_TENANTS", "contoso")], "allow-list of non-ids"),
            (vec![("SSO_ENTRA_CLIENT_ID", "")], "no client id"),
            (vec![("SSO_ENTRA_JIT_ROLE", "root")], "unknown role"),
            (vec![("SSO_ENTRA_SCOPES", "profile")], "no openid scope"),
            (vec![("SSO_ENTRA_AUTHORITY", "http://login.example")], "plain http authority"),
            (vec![("SSO_PUBLIC_URL", "")], "no public URL"),
            (vec![("SSO_PUBLIC_URL", "http://bot.example.com")], "plain http public URL"),
            (vec![("SSO_PUBLIC_URL", "https://bot.example.com/superbot")], "public URL with a path"),
            (vec![("SSO_APP_REDIRECTS", "javascript://x")], "script redirect"),
            (vec![("SSO_APP_REDIRECTS", "superbot://auth?x=1")], "redirect with a query"),
            (vec![("SSO_APP_REDIRECTS", "http://app.example/auth")], "plain http redirect"),
            (vec![("SSO_PROVIDERS", "entra,entra")], "listed twice"),
            (vec![("SSO_PROVIDERS", "my-idp")], "bad id"),
            (vec![("SSO_PROVIDERS", "acme")], "unknown type"),
        ] {
            assert!(entra(&vars).is_err(), "{why}");
        }
    }

    #[test]
    fn reads_a_generic_oidc_provider() {
        let s = parse(&[
            ("SSO_PROVIDERS", "acme"),
            ("SSO_PUBLIC_URL", "http://127.0.0.1:3000"),
            ("SSO_ACME_TYPE", "oidc"),
            ("SSO_ACME_ISSUER", "https://idp.example"),
            ("SSO_ACME_CLIENT_ID", "c1"),
            ("SSO_APP_REDIRECTS", "superbot://auth, http://localhost:8081/auth"),
        ])
        .unwrap();
        assert_eq!((s.providers[0].label.as_str(), s.providers[0].type_name(), s.public_host.as_str()), ("acme", "oidc", "127.0.0.1:3000"));
        assert_eq!(s.app_redirects.len(), 2);
        assert_eq!(s.providers[0].secret_name(), "SSO_ACME_CLIENT_SECRET");
    }

    #[test]
    fn pending_sign_ins_are_single_use_expire_and_are_capped_per_ip() {
        let s = Sso::default();
        let p = |ip: &str, expires| Pending { provider: "entra".into(), nonce: "n".into(), verifier: "v".into(), ip: ip.into(), label: None, expires, ret: Return::Cookie { binder: String::new() } };
        assert!(s.hold("s1", p("1.1.1.1", 100), 0));
        assert!(s.take("s1", 50).is_some());
        assert!(s.take("s1", 50).is_none(), "replayed");
        assert!(s.hold("s2", p("1.1.1.1", 100), 0));
        assert!(s.take("s2", 100).is_none(), "expired");
        for i in 0..MAX_PENDING_PER_IP {
            assert!(s.hold(&format!("x{i}"), p("2.2.2.2", 100), 0));
        }
        assert!(!s.hold("y", p("2.2.2.2", 100), 0));
        assert!(s.hold("y", p("3.3.3.3", 100), 0), "others still can");
    }

    #[test]
    fn pkce_matches_rfc_7636() {
        assert_eq!(s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }
}
