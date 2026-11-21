//! Single sign-on with OpenID Connect (ADR 0014): the authorization code flow with
//! PKCE, state, and nonce, ending in the same sessions as every other sign-in.
//!
//! Web app: `/start` sets a short-lived binder cookie and sends the browser to the IdP;
//! `/callback` checks it, then sets the session cookie. Client app: `/start` carries
//! the app's own PKCE challenge; `/callback` sends a one-time code (`sbh_`) to the
//! app's redirect URL, which the app trades for a token at `POST /api/auth/login`
//! `{sso, verifier}`. Nobody is found by email: an identity is linked by an admin, or
//! made just in time when the provider allows it.
//!
//! GitHub is OAuth 2 without an ID token, and Apple posts its answer (ADR 0018); both
//! end in the same callback, checks, and sessions as the rest.
//!
//! SAML IdPs sign in through an OIDC broker (ADR 0020): botd never parses SAML itself.

pub mod apple;
mod github;
pub mod jwt;
mod provider;
mod saml;

use crate::audit::{Actor, ActorKind, Event, Outcome, Source, Who};
use crate::db::{self, Identity, JitError, NewIdentity, User};
use crate::rbac::Role;
use crate::users::{self, hash};
use crate::{ApiError, AppState, Auth, Res, bad, not_found};
use axum::Json;
use axum::extract::{Extension, Form, OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use provider::Claims;
pub use provider::{ClaimMap, ENTRA_AUTHORITY, GOOGLE_ISSUER, Kind, Provider, domain, guid, secure_url};
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
/// `__Host-` (so Path=/, no Domain): a sibling subdomain can't plant its own binder.
const BINDER: &str = "__Host-superbot_sso";

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
    /// The name Apple posted beside the code (first sign-in only).
    name: Option<String>,
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

impl Sso {
    /// Drops `user_id`'s one-time app codes not yet redeemed, when their sessions are revoked.
    pub fn forget_user(&self, user_id: &str) {
        self.handoffs.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, h| h.user_id != user_id);
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
    HeaderValue::from_str(&format!("{BINDER}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age_s}")).unwrap()
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

    /// Reads SSO_* settings (see docs/sso/). No SSO_PROVIDERS: SSO is off.
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
        // The default also covers the web client the installer and Compose serve at /app/.
        sso.app_redirects = match list("SSO_APP_REDIRECTS") {
            l if l.is_empty() => vec!["superbot://auth".into(), format!("{public}/app/auth")],
            l => l,
        };
        sso.public_url = public;
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

    /// SSO_PUBLIC_URL, when SSO is on.
    pub fn public_url(&self) -> Option<&str> {
        Some(self.public_url.as_str()).filter(|u| !u.is_empty())
    }

    /// The redirect URI to register at the IdP for provider `id`.
    pub fn callback_url(&self, id: &str) -> String {
        self.redirect_uri(id)
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

    /// Keeps a posted name with the sign-in it belongs to, for the callback that follows.
    fn note_name(&self, provider: &str, state: &str, name: Option<String>) {
        if let Some(p) = self.pending.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&hash(state)).filter(|p| p.provider == provider) {
            p.name = name.or(p.name.take());
        }
    }
}

type Var<'a> = dyn Fn(&str) -> Option<String> + 'a;
type List<'a> = dyn Fn(&str) -> Vec<String> + 'a;

const TYPES: [&str; 6] = ["entra", "google", "oidc", "apple", "github", "saml"];

/// Settings that only mean something for some types. Set on another, they would look like
/// a restriction that isn't there, so they are refused.
const ONLY_FOR: [(&str, &[&str]); 15] = [
    ("TENANT", &["entra"]),
    ("ALLOWED_TENANTS", &["entra"]),
    ("AUTHORITY", &["entra"]),
    ("HOSTED_DOMAINS", &["google"]),
    ("ALLOWED_DOMAINS", &["oidc", "apple", "saml"]),
    ("SUBJECT_CLAIM", &["oidc", "saml"]),
    ("EMAIL_CLAIM", &["oidc", "saml"]),
    ("NAME_CLAIM", &["oidc", "saml"]),
    ("TEAM_ID", &["apple"]),
    ("KEY_ID", &["apple"]),
    ("ALLOWED_ORGS", &["github"]),
    ("URL", &["github"]),
    ("API_URL", &["github"]),
    ("IDP_ALIAS", &["saml"]),
    ("IDP_ENTITY_ID", &["saml"]),
];

/// Claims people or their admins can change, so they can't be the subject.
const MUTABLE_CLAIMS: [&str; 9] = ["email", "preferred_username", "upn", "unique_name", "name", "nickname", "given_name", "family_name", "phone_number"];

fn parse_provider(id: &str, var: &Var, list: &List) -> Result<Provider, String> {
    let key = |k: &str| format!("SSO_{}_{k}", id.to_ascii_uppercase());
    let preset = match id {
        "entra" | "google" | "apple" | "github" => id,
        _ => "",
    };
    let ty = var(&key("TYPE")).map(|t| t.to_ascii_lowercase()).unwrap_or_else(|| preset.into());
    if TYPES.contains(&ty.as_str())
        && let Some((k, only)) = ONLY_FOR.iter().find(|(k, only)| !only.contains(&ty.as_str()) && var(&key(k)).is_some())
    {
        return Err(format!("{} is only for {}={}", key(k), key("TYPE"), only.join(" or ")));
    }
    let domains = |k: &str| -> Result<Vec<String>, String> { list(&key(k)).iter().map(|d| domain(d).ok_or_else(|| format!("{}: {d} is not a domain like example.com", key(k)))).collect() };
    let client_id = var(&key("CLIENT_ID")).ok_or_else(|| format!("{} is required", key("CLIENT_ID")))?;
    let jit_role = match var(&key("JIT_ROLE")).map(|r| r.to_ascii_lowercase()).as_deref() {
        None | Some("off") => None,
        Some(r) => Some(Role::parse(r).ok_or_else(|| format!("{} must be off, readonly, member, or admin", key("JIT_ROLE")))?),
    };
    let set_scopes = var(&key("SCOPES"));
    let has = |scopes: &str, any: &[&str]| scopes.split_whitespace().any(|s| any.contains(&s));
    let scopes = set_scopes.clone().unwrap_or_else(|| "openid profile email".into());
    if matches!(ty.as_str(), "entra" | "google" | "oidc" | "saml") && !has(&scopes, &["openid"]) {
        return Err(format!("{} must include openid", key("SCOPES")));
    }
    let mut scopes = scopes;
    let claim_map = |subject: &str| -> Result<ClaimMap, String> {
        let claim = |k: &str, default: &str| -> Result<String, String> {
            let c = var(&key(k)).unwrap_or_else(|| default.into());
            if c.len() > 128 || !c.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(format!("{} must be a claim name", key(k)));
            }
            Ok(c)
        };
        let map = ClaimMap { subject: claim("SUBJECT_CLAIM", subject)?, email: claim("EMAIL_CLAIM", "email")?, name: claim("NAME_CLAIM", "name")? };
        if MUTABLE_CLAIMS.contains(&map.subject.to_ascii_lowercase().as_str()) {
            return Err(format!("{}={}: people can change that claim, so it can't say who they are. Use sub or another id that never changes", key("SUBJECT_CLAIM"), map.subject));
        }
        Ok(map)
    };
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
        "google" => {
            let issuer = var(&key("ISSUER")).unwrap_or_else(|| GOOGLE_ISSUER.into());
            if !secure_url(&issuer) {
                return Err(format!("{} must be an https URL", key("ISSUER")));
            }
            let hosted_domains = domains("HOSTED_DOMAINS")?;
            if jit_role.is_some() && hosted_domains.is_empty() {
                return Err(format!("{} without {} would let any Google account in: list your Workspace domains, or link people instead", key("JIT_ROLE"), key("HOSTED_DOMAINS")));
            }
            if !scopes.split_whitespace().any(|s| s == "email") {
                return Err(format!("{} must include email: Google sign-in needs a verified email", key("SCOPES")));
            }
            (Kind::Google { issuer, hosted_domains }, "Google")
        }
        "oidc" => {
            let issuer = var(&key("ISSUER")).ok_or_else(|| format!("{} is required", key("ISSUER")))?;
            if !secure_url(&issuer) {
                return Err(format!("{} must be an https URL", key("ISSUER")));
            }
            (Kind::Oidc { issuer, map: claim_map("sub")?, allowed_domains: domains("ALLOWED_DOMAINS")? }, id)
        }
        "saml" => {
            let issuer = var(&key("ISSUER")).ok_or_else(|| format!("{} is required: the OIDC issuer of the broker that speaks SAML to your IdP, like https://sso.example.com/realms/superbot", key("ISSUER")))?;
            if !secure_url(&issuer) {
                return Err(format!("{} must be an https URL", key("ISSUER")));
            }
            let alias = var(&key("IDP_ALIAS")).ok_or_else(|| format!("{} is required: the SAML IdP's alias in the broker, like adfs", key("IDP_ALIAS")))?;
            let alias = saml::alias(&alias).ok_or_else(|| format!("{}: {alias} is not an alias (letters, digits, . _ -)", key("IDP_ALIAS")))?;
            let entity_id = var(&key("IDP_ENTITY_ID")).ok_or_else(|| format!("{} is required: the SAML IdP's entity ID, as in its metadata", key("IDP_ENTITY_ID")))?;
            let entity_id = saml::entity_id(&entity_id).ok_or_else(|| format!("{}: {entity_id} is not an entity ID (a URI, like http://adfs.example.com/adfs/services/trust)", key("IDP_ENTITY_ID")))?;
            let map = claim_map(saml::SUBJECT_CLAIM)?;
            if map.subject == saml::IDP_CLAIM {
                return Err(format!("{}={}: that claim names the IdP, not the person", key("SUBJECT_CLAIM"), map.subject));
            }
            (Kind::Saml { issuer, entity_id, alias, map, allowed_domains: domains("ALLOWED_DOMAINS")? }, saml::LABEL)
        }
        "apple" => {
            let issuer = var(&key("ISSUER")).unwrap_or_else(|| apple::ISSUER.into()).trim_end_matches('/').to_string();
            if !secure_url(&issuer) {
                return Err(format!("{} must be an https URL", key("ISSUER")));
            }
            let apple_id = |k: &str, what: &str| var(&key(k)).as_deref().and_then(apple::apple_id).ok_or_else(|| format!("{} is required: your {what} (ten letters and digits)", key(k)));
            let (team_id, key_id) = (apple_id("TEAM_ID", "Apple Developer Team ID")?, apple_id("KEY_ID", "Sign in with Apple key's Key ID")?);
            let allowed_domains = domains("ALLOWED_DOMAINS")?;
            if allowed_domains.iter().any(|d| d == apple::RELAY_DOMAIN) {
                return Err(format!("{}: {} is Apple's Hide My Email domain, which anyone can have", key("ALLOWED_DOMAINS"), apple::RELAY_DOMAIN));
            }
            if jit_role.is_some() && allowed_domains.is_empty() {
                return Err(format!("{} without {} would let any Apple Account in: list your email domains, or link people instead", key("JIT_ROLE"), key("ALLOWED_DOMAINS")));
            }
            scopes = set_scopes.unwrap_or_else(|| "name email".into());
            if scopes.split_whitespace().any(|s| !["openid", "name", "email"].contains(&s)) {
                return Err(format!("{} may only have name and email", key("SCOPES")));
            }
            if !allowed_domains.is_empty() && !has(&scopes, &["email"]) {
                return Err(format!("{} must include email to check {}", key("SCOPES"), key("ALLOWED_DOMAINS")));
            }
            (Kind::Apple { issuer, team_id, key_id, allowed_domains }, "Apple")
        }
        "github" => {
            let url = |k: &str, default: String| -> Result<String, String> {
                let u = var(&key(k)).unwrap_or(default).trim_end_matches('/').to_string();
                let clean = Url::parse(&u).is_ok_and(|p| p.query().is_none() && p.fragment().is_none());
                if secure_url(&u) && clean { Ok(u) } else { Err(format!("{} must be an https URL", key(k))) }
            };
            let web = url("URL", github::URL.into())?;
            let api = url("API_URL", github::api_for(&web))?;
            let mut allowed_orgs = Vec::new();
            for o in list(&key("ALLOWED_ORGS")) {
                allowed_orgs.push(github::org(&o).ok_or_else(|| format!("{}: {o} is not a GitHub organization name", key("ALLOWED_ORGS")))?);
            }
            if jit_role.is_some() && allowed_orgs.is_empty() {
                return Err(format!("{} without {} would let any GitHub account in: list your organizations, or link people instead", key("JIT_ROLE"), key("ALLOWED_ORGS")));
            }
            let orgs = !allowed_orgs.is_empty();
            let default = [Some("read:user"), Some(github::SCOPE_EMAIL), orgs.then_some(github::SCOPE_ORGS)];
            scopes = set_scopes.unwrap_or_else(|| default.into_iter().flatten().collect::<Vec<_>>().join(" "));
            if !has(&scopes, &[github::SCOPE_EMAIL, "user"]) {
                return Err(format!("{} must include {}: GitHub sign-in needs the verified primary email", key("SCOPES"), github::SCOPE_EMAIL));
            }
            if orgs && !has(&scopes, &[github::SCOPE_ORGS, "write:org", "admin:org"]) {
                return Err(format!("{} must include {} to check {}", key("SCOPES"), github::SCOPE_ORGS, key("ALLOWED_ORGS")));
            }
            let label = if web == github::URL { "GitHub" } else { "GitHub Enterprise" };
            (Kind::GitHub { web, api, allowed_orgs }, label)
        }
        "" => return Err(format!("{} is required: {}", key("TYPE"), TYPES.join(", "))),
        t => return Err(format!("{}: unknown type {t} ({})", key("TYPE"), TYPES.join(", "))),
    };
    let label = var(&key("LABEL")).map(|l| crate::audit::clip(&l, 40)).unwrap_or_else(|| label.to_string());
    Ok(Provider::new(id, &label, kind, &client_id, &scopes, jit_role))
}

// Audit

fn claim_details(d: &mut Value, c: &Claims) {
    d["issuer"] = json!(c.issuer);
    d["subject"] = json!(c.subject);
    d["tenant"] = json!(c.tenant);
    if let Some(u) = &c.username {
        d["username"] = json!(u);
    }
}

/// The IdP's type (entra, google, oidc, apple, github, saml), beside the configured id.
pub(crate) fn idp_type(a: &Auth, provider: &str) -> Option<&'static str> {
    a.sso.provider(provider).map(|p| p.type_name())
}

/// Failures anyone can cause without the IdP's help, by opening a callback URL.
const UNVOUCHED: [&str; 5] = ["unknown_state", "wrong_provider", "binder_mismatch", "idp_error", "missing_code"];

/// A failed SSO sign-in. The ones in UNVOUCHED are throttled like other failed sign-ins.
fn failed(a: &Auth, source: &Source, provider: &str, reason: &str, c: Option<&Claims>, extra: Value) {
    let mut d = json!({ "method": "sso", "provider": provider, "idp": idp_type(a, provider), "reason": reason });
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
    let idp = idp_type(a, provider).map(String::from);
    let idp_provider = idp.is_some().then(|| provider.to_string());
    let actor = Actor { kind: ActorKind::User, subject: c.map(Claims::key), method: Some("sso".into()), idp, idp_provider, ..Default::default() };
    a.record(Who { actor, source: source.clone() }.event("auth.login_failed").outcome(Outcome::Failure).details(d));
}

fn signed_in(a: &Auth, user: &User, s: &db::Session, provider: &str, c: &Claims, source: &Source) {
    let mut d = json!({ "method": "sso", "provider": provider, "idp": idp_type(a, provider), "kind": s.kind, "label": s.label });
    claim_details(&mut d, c);
    let who = Who { actor: users::actor(a, user, Some(s), "sso"), source: source.clone() };
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
    let endpoint = match p.authorization_endpoint(sso.http(), sso.refresh_gap).await {
        Ok(e) => e,
        Err(e) => {
            crate::obs::log::log_warn!("SSO {id}: discovery failed: {e}");
            return no_store(ret.fail("sso_failed"));
        }
    };
    let (state, nonce, verifier, binder) = (random(), random(), random(), random());
    let ret = match ret {
        Return::Cookie { .. } => Return::Cookie { binder: hash(&binder) },
        r => r,
    };
    let label = users::clean_label(&json!(q.get("label")));
    let pending = Pending { provider: id.clone(), nonce: nonce.clone(), verifier: verifier.clone(), ip, label, expires: at + PENDING_TTL_MS, ret: ret.clone(), name: None };
    if !sso.hold(&state, pending, at) {
        return no_store(ret.fail("sso_too_many"));
    }
    let mut url = Url::parse(&endpoint).expect("checked by secure_url");
    url.query_pairs_mut().extend_pairs([
        ("client_id", p.client_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", &sso.redirect_uri(&id)),
        ("scope", &p.scopes),
        ("state", &state),
        ("code_challenge", &s256(&verifier)),
        ("code_challenge_method", "S256"),
    ]);
    if p.oidc() {
        url.query_pairs_mut().extend_pairs([("response_mode", p.response_mode()), ("nonce", &nonce)]);
    }
    for (k, v) in p.auth_params() {
        url.query_pairs_mut().append_pair(k, &v);
    }
    let mut res = see(url.as_str());
    if matches!(ret, Return::Cookie { .. }) {
        res.headers_mut().insert(header::SET_COOKIE, binder_cookie(&binder, PENDING_TTL_MS / 1000));
    }
    no_store(res)
}

/// The page after a web sign-in, sending admins to the console and everyone else to the app.
fn signed_in_page(role: Role) -> String {
    let to = crate::landing(crate::rbac::Principal::User(role));
    // Clears the web app's signed-out mark (apps/client/src/auth.ts) so it takes up this new session.
    format!(
        r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><script>try{{localStorage.removeItem("superbot.signedOut")}}catch(e){{}}</script><meta http-equiv="refresh" content="0;url={to}"><title>SuperBot</title><p style="font:16px system-ui;margin:2rem">Signed in. <a href="{to}">Continue to SuperBot</a></p>"#
    )
}

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

/// `POST /api/auth/sso/{id}/callback`: Apple's `form_post`. A cross-site POST carries no
/// `SameSite=Lax` cookie, so the binder can't be checked here. Instead the answer moves to
/// the GET callback with a 303: a top-level GET, which carries it. The posted name is kept
/// with the pending sign-in; nothing else is trusted or done here.
pub async fn callback_post(Extension(a): Extension<Arc<Auth>>, Path(id): Path<String>, Form(f): Form<HashMap<String, String>>) -> Response {
    if !a.sso.provider(&id).is_some_and(|p| p.form_post()) {
        return no_store(see("/login?error=sso_failed"));
    }
    if let Some(state) = f.get("state") {
        a.sso.note_name(&id, state, f.get("user").and_then(|u| apple::posted_name(u)));
    }
    let pairs = ["code", "state", "error"].into_iter().filter_map(|k| f.get(k).map(|v| (k, v.as_str())));
    let query = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish();
    no_store(see(&format!("/api/auth/sso/{id}/callback?{query}")))
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
        // Apple says user_cancelled_authorize.
        return ret.fail(if matches!(err.as_str(), "access_denied" | "user_cancelled_authorize") { "sso_cancelled" } else { "sso_failed" });
    }
    let (Some(code), Some(p)) = (q.get("code").filter(|c| !c.is_empty() && c.len() <= 4096), sso.provider(id)) else {
        failed(a, source, id, "missing_code", None, json!({}));
        return ret.fail("sso_failed");
    };
    if a.limiter.blocked(&ip, at).is_some() {
        return ret.fail("sso_too_many");
    }
    let mut claims = match p.sign_in(sso.http(), code, &sso.redirect_uri(id), &pending.verifier, &pending.nonce, sso.refresh_gap).await {
        Ok(c) => c,
        Err(e) => {
            a.limiter.fail(&ip, at);
            failed(a, source, id, e.0, None, json!({}));
            // A real account the server doesn't take: say so, so people try another one.
            return ret.fail(if matches!(e.0, "wrong_domain" | "email_unverified" | "wrong_org" | "not_brokered") { "sso_wrong_account" } else { "sso_failed" });
        }
    };
    if claims.name.is_none() {
        claims.name = pending.name.clone();
    }
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
            let (s, token) = users::start_session(a, &user, "sso", Some((id, &claims.key())), true, label, source);
            signed_in(a, &user, &s, id, &claims, source);
            let mut res = Html(signed_in_page(user.role)).into_response();
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
                Err(JitError::NoSeat) => {
                    crate::license::refuse_seat(app, &crate::audit::Who::system("sso"), "sso", None, email);
                    return Err(("no_seat", "sso_no_seat"));
                }
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
    // Held until the session exists: revoking a user's sessions drops their codes first, so
    // it can't fall between taking the code and making its session.
    let mut handoffs = a.sso.handoffs.lock().unwrap_or_else(|e| e.into_inner());
    // Taken out first, so a wrong verifier spends the code too.
    let h = handoffs.remove(&hash(code));
    let h = h.filter(|h| h.expires > at && crate::same(s256(verifier).as_bytes(), h.challenge.as_bytes()));
    // Looked up again: an admin may have unlinked the identity or disabled the user since.
    let found = h.and_then(|h| {
        let (_, user) = app.db.identity(&h.claims.issuer, &h.claims.subject)?;
        (user.id == h.user_id && user.active()).then_some((user, h))
    });
    let Some((user, h)) = found else {
        drop(handoffs);
        a.limiter.fail(&ip, at);
        a.login_failed(&source, "sso", Some("bad_handoff"));
        return ApiError(StatusCode::UNAUTHORIZED, "That sign-in expired or was already used. Try again.".into()).into_response();
    };
    let label = label.or(h.label.as_deref());
    let (s, token) = users::start_session(a, &user, "sso", Some((&h.provider, &h.claims.key())), cookie, label, &source);
    drop(handoffs);
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
/// subject is the user's object id and the tenant defaults to the provider's own; for
/// GitHub the numeric user id; for Google, Apple, and generic OIDC the subject claim
/// (`sub` unless mapped); for SAML the IdP's NameID for the person, stored under its entity ID.
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
        assert_eq!(s.app_redirects, ["superbot://auth", "https://bot.example.com/app/auth"]);
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
        assert_eq!(s.providers[0].env_var(), "SSO_ACME_CLIENT_SECRET");
    }

    fn google(extra: &[(&'static str, &'static str)]) -> Result<Sso, String> {
        let mut v = vec![("SSO_PROVIDERS", "google"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_GOOGLE_CLIENT_ID", "c1.apps.googleusercontent.com")];
        for (k, val) in extra {
            v.retain(|(old, _)| old != k);
            v.push((k, val));
        }
        parse(&v)
    }

    #[test]
    fn reads_a_google_provider_with_safe_defaults() {
        let s = google(&[]).unwrap();
        let p = s.provider("google").unwrap();
        assert_eq!((p.label.as_str(), p.type_name(), p.jit_role, p.scopes.as_str()), ("Google", "google", None, "openid profile email"));
        assert!(matches!(&p.kind, Kind::Google { issuer, hosted_domains } if issuer == GOOGLE_ISSUER && hosted_domains.is_empty()));
        assert_eq!(p.issuer_for(None).unwrap(), (GOOGLE_ISSUER.to_string(), None));
        assert!(p.issuer_for(Some(T1)).is_err(), "tenant is Entra's");
        let ws = google(&[("SSO_GOOGLE_HOSTED_DOMAINS", "Example.com, example.org"), ("SSO_GOOGLE_JIT_ROLE", "readonly")]).unwrap();
        assert!(matches!(&ws.providers[0].kind, Kind::Google { hosted_domains, .. } if hosted_domains == &["example.com", "example.org"]));
        assert_eq!(ws.providers[0].jit_role, Some(Role::Readonly));
        let named = parse(&[("SSO_PROVIDERS", "work"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_WORK_TYPE", "google"), ("SSO_WORK_CLIENT_ID", "c")]).unwrap();
        assert_eq!(named.providers[0].type_name(), "google");
    }

    #[test]
    fn refuses_google_settings_that_would_let_strangers_in() {
        for (vars, why) in [
            (vec![("SSO_GOOGLE_JIT_ROLE", "member")], "just in time for every Google account"),
            (vec![("SSO_GOOGLE_SCOPES", "openid profile")], "no email scope"),
            (vec![("SSO_GOOGLE_HOSTED_DOMAINS", "*")], "wildcard domain"),
            (vec![("SSO_GOOGLE_HOSTED_DOMAINS", "ada@example.com")], "an email, not a domain"),
            (vec![("SSO_GOOGLE_ALLOWED_DOMAINS", "example.com")], "email domains are not Workspace membership"),
            (vec![("SSO_GOOGLE_TENANT", T1)], "an Entra setting"),
            (vec![("SSO_GOOGLE_ISSUER", "http://accounts.google.com")], "plain http issuer"),
            (vec![("SSO_GOOGLE_CLIENT_ID", "")], "no client id"),
        ] {
            assert!(google(&vars).is_err(), "{why}");
        }
    }

    #[test]
    fn reads_generic_oidc_claim_mapping_and_domains() {
        let base = [("SSO_PROVIDERS", "okta"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_OKTA_TYPE", "oidc"), ("SSO_OKTA_ISSUER", "https://acme.okta.example"), ("SSO_OKTA_CLIENT_ID", "c1")];
        let with = |extra: &[(&'static str, &'static str)]| parse(&[&base[..], extra].concat());
        let p = &with(&[]).unwrap().providers[0];
        assert!(matches!(&p.kind, Kind::Oidc { map, allowed_domains, .. } if *map == ClaimMap::default() && allowed_domains.is_empty()));
        assert!(p.auth_params().is_empty());
        let s = with(&[("SSO_OKTA_SUBJECT_CLAIM", "uid"), ("SSO_OKTA_EMAIL_CLAIM", "mail"), ("SSO_OKTA_NAME_CLAIM", "display_name"), ("SSO_OKTA_ALLOWED_DOMAINS", "example.com"), ("SSO_OKTA_LABEL", "Okta")]).unwrap();
        let p = &s.providers[0];
        assert_eq!(p.label, "Okta");
        assert!(matches!(&p.kind, Kind::Oidc { map, allowed_domains, .. } if map.subject == "uid" && map.email == "mail" && map.name == "display_name" && allowed_domains == &["example.com"]));
        for (vars, why) in [
            (vec![("SSO_OKTA_SUBJECT_CLAIM", "email")], "email as the subject"),
            (vec![("SSO_OKTA_SUBJECT_CLAIM", "preferred_username")], "username as the subject"),
            (vec![("SSO_OKTA_SUBJECT_CLAIM", "has space")], "not a claim name"),
            (vec![("SSO_OKTA_ALLOWED_DOMAINS", "example")], "not a domain"),
            (vec![("SSO_OKTA_HOSTED_DOMAINS", "example.com")], "a Google setting"),
            (vec![("SSO_OKTA_TENANT", T1)], "an Entra setting"),
            (vec![("SSO_OKTA_ISSUER", "http://acme.okta.example")], "plain http issuer"),
        ] {
            assert!(with(&vars).is_err(), "{why}");
        }
    }

    #[test]
    fn several_providers_at_once_keep_their_order() {
        let s = parse(&[
            ("SSO_PROVIDERS", "entra, google,keycloak"),
            ("SSO_PUBLIC_URL", "https://bot.example.com"),
            ("SSO_ENTRA_CLIENT_ID", "c1"),
            ("SSO_ENTRA_TENANT", T1),
            ("SSO_GOOGLE_CLIENT_ID", "c2"),
            ("SSO_KEYCLOAK_TYPE", "oidc"),
            ("SSO_KEYCLOAK_ISSUER", "https://sso.example.com/realms/acme"),
            ("SSO_KEYCLOAK_CLIENT_ID", "c3"),
            ("SSO_KEYCLOAK_LABEL", "Acme SSO"),
        ])
        .unwrap();
        let got: Vec<_> = s.providers.iter().map(|p| (p.id.as_str(), p.label.as_str(), p.type_name(), p.env_var())).collect();
        assert_eq!(
            got,
            [
                ("entra", "Microsoft", "entra", "SSO_ENTRA_CLIENT_SECRET".to_string()),
                ("google", "Google", "google", "SSO_GOOGLE_CLIENT_SECRET".to_string()),
                ("keycloak", "Acme SSO", "oidc", "SSO_KEYCLOAK_CLIENT_SECRET".to_string()),
            ]
        );
        assert!(s.providers.iter().all(|p| s.redirect_uri(&p.id) == format!("https://bot.example.com/api/auth/sso/{}/callback", p.id)));
        let who: Vec<String> = s.providers.iter().map(|p| p.audience()).collect();
        assert_eq!(who, [format!("tenant {T1}"), "any Google account".into(), "anyone the IdP signs in".into()]);
    }

    fn with_base(base: &[(&'static str, &'static str)], extra: &[(&'static str, &'static str)]) -> Result<Sso, String> {
        let mut v = base.to_vec();
        for (k, val) in extra {
            v.retain(|(old, _)| old != k);
            v.push((k, val));
        }
        parse(&v)
    }

    fn github(extra: &[(&'static str, &'static str)]) -> Result<Sso, String> {
        with_base(&[("SSO_PROVIDERS", "github"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_GITHUB_CLIENT_ID", "Iv1.abc")], extra)
    }

    #[test]
    fn reads_a_github_provider_with_safe_defaults() {
        let s = github(&[]).unwrap();
        let p = s.provider("github").unwrap();
        assert_eq!((p.label.as_str(), p.type_name(), p.jit_role, p.scopes.as_str(), p.oidc()), ("GitHub", "github", None, "read:user user:email", false));
        assert!(matches!(&p.kind, Kind::GitHub { web, api, allowed_orgs } if web == "https://github.com" && api == "https://api.github.com" && allowed_orgs.is_empty()));
        assert_eq!((p.env_var(), p.audience()), ("SSO_GITHUB_CLIENT_SECRET".to_string(), "any account on https://github.com".to_string()));
        assert_eq!(p.auth_params(), [("prompt", "select_account".to_string()), ("allow_signup", "false".to_string())]);
        assert_eq!(p.issuer_for(None).unwrap(), ("https://github.com".to_string(), None));
        assert_eq!(p.subject(" 583231 ").unwrap(), "583231");
        assert!(p.subject("octocat").is_err(), "the login is not the subject");

        let orgs = github(&[("SSO_GITHUB_ALLOWED_ORGS", "CG-Labs, acme"), ("SSO_GITHUB_JIT_ROLE", "member")]).unwrap();
        let p = &orgs.providers[0];
        assert!(matches!(&p.kind, Kind::GitHub { allowed_orgs, .. } if allowed_orgs == &["cg-labs", "acme"]));
        assert_eq!((p.scopes.as_str(), p.jit_role), ("read:user user:email read:org", Some(Role::Member)));
        assert_eq!(p.audience(), "members of cg-labs, acme on https://github.com");

        let ghes = github(&[("SSO_GITHUB_URL", "https://github.example.com/")]).unwrap();
        assert!(matches!(&ghes.providers[0].kind, Kind::GitHub { web, api, .. } if web == "https://github.example.com" && api == "https://github.example.com/api/v3"));
        assert_eq!(ghes.providers[0].label, "GitHub Enterprise");
    }

    #[test]
    fn refuses_github_settings_that_would_let_strangers_in() {
        for (vars, why) in [
            (vec![("SSO_GITHUB_JIT_ROLE", "member")], "just in time for every GitHub account"),
            (vec![("SSO_GITHUB_ALLOWED_ORGS", "acme/team")], "not an org"),
            (vec![("SSO_GITHUB_ALLOWED_ORGS", "-acme")], "not an org"),
            (vec![("SSO_GITHUB_SCOPES", "read:user")], "no email scope"),
            (vec![("SSO_GITHUB_ALLOWED_ORGS", "acme"), ("SSO_GITHUB_SCOPES", "read:user user:email")], "orgs without read:org"),
            (vec![("SSO_GITHUB_URL", "http://github.example.com")], "plain http"),
            (vec![("SSO_GITHUB_API_URL", "https://api.github.com?x=1")], "API URL with a query"),
            (vec![("SSO_GITHUB_ALLOWED_DOMAINS", "example.com")], "email domains are not org membership"),
            (vec![("SSO_GITHUB_HOSTED_DOMAINS", "example.com")], "a Google setting"),
            (vec![("SSO_GITHUB_TEAM_ID", "TEAM123456")], "an Apple setting"),
            (vec![("SSO_GITHUB_CLIENT_ID", "")], "no client id"),
        ] {
            assert!(github(&vars).is_err(), "{why}");
        }
        assert!(github(&[("SSO_GITHUB_SCOPES", "user")]).is_ok(), "user covers user:email");
    }

    fn apple(extra: &[(&'static str, &'static str)]) -> Result<Sso, String> {
        let base = [("SSO_PROVIDERS", "apple"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_APPLE_CLIENT_ID", "com.example.superbot.web"), ("SSO_APPLE_TEAM_ID", "TEAM123456"), ("SSO_APPLE_KEY_ID", "key1234567")];
        with_base(&base, extra)
    }

    #[test]
    fn reads_an_apple_provider_with_safe_defaults() {
        let s = apple(&[]).unwrap();
        let p = s.provider("apple").unwrap();
        assert_eq!((p.label.as_str(), p.type_name(), p.jit_role, p.scopes.as_str(), p.response_mode()), ("Apple", "apple", None, "name email", "form_post"));
        assert!(matches!(&p.kind, Kind::Apple { issuer, team_id, key_id, allowed_domains } if issuer == apple::ISSUER && team_id == "TEAM123456" && key_id == "KEY1234567" && allowed_domains.is_empty()));
        assert_eq!((p.env_var(), p.audience()), ("SSO_APPLE_PRIVATE_KEY".to_string(), "any Apple Account".to_string()));
        assert!(p.auth_params().is_empty() && p.oidc());
        assert_eq!(p.issuer_for(None).unwrap(), (apple::ISSUER.to_string(), None));
        let jit = apple(&[("SSO_APPLE_ALLOWED_DOMAINS", "example.com"), ("SSO_APPLE_JIT_ROLE", "readonly")]).unwrap();
        assert_eq!((jit.providers[0].jit_role, jit.providers[0].audience()), (Some(Role::Readonly), "verified emails at example.com".to_string()));
    }

    #[test]
    fn apple_says_why_it_isnt_offered() {
        let s = with_base(&[("SSO_PROVIDERS", "applekey"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_APPLEKEY_TYPE", "apple"), ("SSO_APPLEKEY_CLIENT_ID", "com.example.superbot.web"), ("SSO_APPLEKEY_TEAM_ID", "TEAM123456"), ("SSO_APPLEKEY_KEY_ID", "KEY1234567")], &[]).unwrap();
        let p = s.provider("applekey").unwrap();
        assert!(p.not_ready().unwrap().contains("until SSO_APPLEKEY_PRIVATE_KEY is set"));
        crate::secrets::global().put("SSO_APPLEKEY_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----").unwrap();
        assert!(p.not_ready().unwrap().contains("isn't a Sign in with Apple key"));
        crate::secrets::global().put("SSO_APPLEKEY_PRIVATE_KEY", &apple::test_key::p8().0).unwrap();
        assert!(p.not_ready().is_none() && p.ready());
    }

    #[test]
    fn refuses_apple_settings_that_are_missing_or_would_let_strangers_in() {
        for (vars, why) in [
            (vec![("SSO_APPLE_TEAM_ID", "")], "no team id"),
            (vec![("SSO_APPLE_KEY_ID", "KEY-123")], "not a key id"),
            (vec![("SSO_APPLE_JIT_ROLE", "member")], "just in time for every Apple Account"),
            (vec![("SSO_APPLE_ALLOWED_DOMAINS", "privaterelay.appleid.com"), ("SSO_APPLE_JIT_ROLE", "member")], "Hide My Email is everyone's"),
            (vec![("SSO_APPLE_SCOPES", "openid profile")], "a scope Apple doesn't have"),
            (vec![("SSO_APPLE_ALLOWED_DOMAINS", "example.com"), ("SSO_APPLE_SCOPES", "name")], "domains without the email"),
            (vec![("SSO_APPLE_ISSUER", "http://appleid.apple.com")], "plain http"),
            (vec![("SSO_APPLE_HOSTED_DOMAINS", "example.com")], "a Google setting"),
            (vec![("SSO_APPLE_ALLOWED_ORGS", "acme")], "a GitHub setting"),
        ] {
            assert!(apple(&vars).is_err(), "{why}");
        }
        assert!(parse(&[("SSO_PROVIDERS", "acme"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_ACME_TYPE", "google"), ("SSO_ACME_CLIENT_ID", "c"), ("SSO_ACME_KEY_ID", "KEY1234567")]).is_err(), "an Apple setting on Google");
    }

    const ADFS: &str = "http://adfs.example.com/adfs/services/trust";

    fn saml(extra: &[(&'static str, &'static str)]) -> Result<Sso, String> {
        let base = [
            ("SSO_PROVIDERS", "adfs"),
            ("SSO_PUBLIC_URL", "https://bot.example.com"),
            ("SSO_ADFS_TYPE", "saml"),
            ("SSO_ADFS_ISSUER", "https://sso.example.com/realms/superbot"),
            ("SSO_ADFS_CLIENT_ID", "superbot"),
            ("SSO_ADFS_IDP_ALIAS", "adfs"),
            ("SSO_ADFS_IDP_ENTITY_ID", ADFS),
        ];
        with_base(&base, extra)
    }

    #[test]
    fn reads_a_saml_bridge_provider_with_safe_defaults() {
        let s = saml(&[]).unwrap();
        let p = s.provider("adfs").unwrap();
        assert_eq!((p.label.as_str(), p.type_name(), p.jit_role, p.scopes.as_str(), p.oidc(), p.response_mode()), ("Company SSO", "saml", None, "openid profile email", true, "query"));
        assert!(matches!(&p.kind, Kind::Saml { issuer, entity_id, alias, map, allowed_domains }
            if issuer == "https://sso.example.com/realms/superbot" && entity_id == ADFS && alias == "adfs"
            && map.subject == "identity_provider_identity" && map.email == "email" && allowed_domains.is_empty()));
        assert_eq!(p.auth_params(), [("kc_idp_hint", "adfs".to_string())]);
        assert_eq!((p.env_var(), p.audience()), ("SSO_ADFS_CLIENT_SECRET".to_string(), format!("anyone SAML IdP {ADFS} signs in (broker alias adfs)")));
        assert_eq!(p.issuer_for(None).unwrap(), (ADFS.to_string(), None), "identities live under the SAML IdP, not the broker");
        assert!(p.issuer_for(Some(T1)).is_err());
        assert_eq!(p.subject(" G-A1b2C3 ").unwrap(), "g-a1b2c3");
        assert!(p.subject("").is_err() && p.subject(&"x".repeat(256)).is_err());
        assert_eq!(s.redirect_uri("adfs"), "https://bot.example.com/api/auth/sso/adfs/callback");

        let s = saml(&[("SSO_ADFS_ALLOWED_DOMAINS", "example.com"), ("SSO_ADFS_JIT_ROLE", "member"), ("SSO_ADFS_LABEL", "Contoso"), ("SSO_ADFS_SUBJECT_CLAIM", "saml_nameid")]).unwrap();
        let p = &s.providers[0];
        assert_eq!((p.label.as_str(), p.jit_role), ("Contoso", Some(Role::Member)));
        assert!(matches!(&p.kind, Kind::Saml { map, allowed_domains, .. } if map.subject == "saml_nameid" && allowed_domains == &["example.com"]));
        assert!(p.audience().starts_with("verified emails at example.com from SAML IdP"));
        assert!(saml(&[("SSO_ADFS_JIT_ROLE", "member")]).is_ok(), "your own IdP: just in time needs no domain list, like oidc");
    }

    #[test]
    fn refuses_saml_bridge_settings_that_are_missing_or_unclear() {
        for (vars, why) in [
            (vec![("SSO_ADFS_ISSUER", "")], "no broker"),
            (vec![("SSO_ADFS_ISSUER", "http://sso.example.com/realms/superbot")], "plain http broker"),
            (vec![("SSO_ADFS_IDP_ALIAS", "")], "no alias"),
            (vec![("SSO_ADFS_IDP_ALIAS", "ad fs")], "not an alias"),
            (vec![("SSO_ADFS_IDP_ENTITY_ID", "")], "no entity id"),
            (vec![("SSO_ADFS_IDP_ENTITY_ID", "adfs")], "not a URI"),
            (vec![("SSO_ADFS_SUBJECT_CLAIM", "email")], "email as the subject"),
            (vec![("SSO_ADFS_SUBJECT_CLAIM", "preferred_username")], "broker username as the subject"),
            (vec![("SSO_ADFS_SUBJECT_CLAIM", "identity_provider")], "the IdP's alias as the subject"),
            (vec![("SSO_ADFS_SCOPES", "profile email")], "no openid scope"),
            (vec![("SSO_ADFS_CLIENT_ID", "")], "no client id"),
            (vec![("SSO_ADFS_TENANT", T1)], "an Entra setting"),
            (vec![("SSO_ADFS_HOSTED_DOMAINS", "example.com")], "a Google setting"),
            (vec![("SSO_ADFS_ALLOWED_ORGS", "acme")], "a GitHub setting"),
            (vec![("SSO_ADFS_ALLOWED_DOMAINS", "example")], "not a domain"),
        ] {
            assert!(saml(&vars).is_err(), "{why}");
        }
        let okta = [("SSO_PROVIDERS", "okta"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_OKTA_TYPE", "oidc"), ("SSO_OKTA_ISSUER", "https://acme.okta.example"), ("SSO_OKTA_CLIENT_ID", "c1")];
        assert!(with_base(&okta, &[("SSO_OKTA_IDP_ALIAS", "adfs")]).is_err(), "a SAML setting on oidc would look like a check that isn't made");
        assert!(with_base(&okta, &[("SSO_OKTA_IDP_ENTITY_ID", ADFS)]).is_err());
    }

    #[test]
    fn all_six_types_side_by_side() {
        let s = parse(&[
            ("SSO_PROVIDERS", "entra,google,okta,github,apple,adfs"),
            ("SSO_PUBLIC_URL", "https://bot.example.com"),
            ("SSO_ENTRA_CLIENT_ID", "c1"),
            ("SSO_ENTRA_TENANT", T1),
            ("SSO_GOOGLE_CLIENT_ID", "c2"),
            ("SSO_OKTA_TYPE", "oidc"),
            ("SSO_OKTA_ISSUER", "https://acme.okta.example"),
            ("SSO_OKTA_CLIENT_ID", "c3"),
            ("SSO_GITHUB_CLIENT_ID", "c4"),
            ("SSO_APPLE_CLIENT_ID", "c5"),
            ("SSO_APPLE_TEAM_ID", "TEAM123456"),
            ("SSO_APPLE_KEY_ID", "KEY1234567"),
            ("SSO_ADFS_TYPE", "saml"),
            ("SSO_ADFS_ISSUER", "https://sso.example.com/realms/superbot"),
            ("SSO_ADFS_CLIENT_ID", "c6"),
            ("SSO_ADFS_IDP_ALIAS", "adfs"),
            ("SSO_ADFS_IDP_ENTITY_ID", ADFS),
        ])
        .unwrap();
        let types: Vec<&str> = s.providers.iter().map(|p| p.type_name()).collect();
        assert_eq!(types, ["entra", "google", "oidc", "github", "apple", "saml"]);
        assert_eq!(s.redirect_uri("apple"), "https://bot.example.com/api/auth/sso/apple/callback");
    }

    /// The installer and Compose copy these files; with nothing filled in, SSO is off.
    #[test]
    fn the_example_env_files_leave_sso_off() {
        for (name, text) in [(".env.example", include_str!("../../../.env.example")), ("deploy/docker/.env.example", include_str!("../../../deploy/docker/.env.example"))] {
            let vars: HashMap<String, String> = text.lines().filter(|l| !l.trim_start().starts_with('#')).filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
            let s = Sso::from_vars(&|k| vars.get(k).cloned()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(s.providers.is_empty(), "{name}");
        }
    }

    #[test]
    fn pending_sign_ins_are_single_use_expire_and_are_capped_per_ip() {
        let s = Sso::default();
        let p = |ip: &str, expires| Pending { provider: "entra".into(), nonce: "n".into(), verifier: "v".into(), ip: ip.into(), label: None, expires, ret: Return::Cookie { binder: String::new() }, name: None };
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
