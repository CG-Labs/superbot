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
//! SAML IdPs sign in either through an OIDC broker (ADR 0020), or natively (ADR 0127): botd
//! is the service provider, sends an AuthnRequest with the HTTP-Redirect binding, and checks
//! the signed response the IdP posts to `/acs` (`saml_sp`, `xmldsig`). Both end in the same
//! identities, checks, and sessions as the rest. Native SAML also signs AuthnRequests when a
//! provider asks, and does single logout at `/slo` (ADR 0137, `saml_slo`), can require
//! IdP groups and map them to custom roles (ADR 0160, `saml_roles`), and rolls its own keys
//! over without an outage (ADR 0181, `saml_keys`).

pub mod apple;
mod github;
pub mod jwt;
mod provider;
mod saml;
pub(crate) mod saml_expiry;
pub(crate) mod saml_keys;
pub(crate) mod saml_roles;
pub(crate) mod saml_slo;
pub(crate) mod saml_sp;
pub(crate) mod xmldsig;
pub(crate) mod xmlenc;

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
pub use provider::{ClaimMap, ENTRA_AUTHORITY, GOOGLE_ISSUER, IdpSource, Kind, Provider, domain, guid, secure_url};
use saml_sp::{AesCbc, Encryption, IdpInitiated, KeyUse, Refused, Sp, SpKey, SpSigning};
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
/// Native SAML's binder. The IdP posts the response cross-site, which carries no `SameSite=Lax`
/// cookie, so this one is `SameSite=None`. It only ties the post to the browser that started.
const SAML_BINDER: &str = "__Host-superbot_saml";
/// Set on a browser sent from an unsolicited response to start a sign-in (ADR 0175), so an
/// IdP that answers that sign-in unsolicited again is refused instead of sent round again.
/// Its value is the provider's id: another provider's tile isn't a loop.
const SAML_RESTART: &str = "__Host-superbot_saml_restart";
const RESTART_TTL_S: i64 = 120;
/// Where an IdP's metadata imported with botctl is kept (the `settings` table), by provider id.
const SAML_METADATA_SETTING: &str = "sso_saml_idp_metadata_";

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
    /// When the sign-in was sent to the IdP, and, for native SAML, whether its AuthnRequest
    /// asked for `ForceAuthn` (ADR 0225).
    requested: i64,
    forced: bool,
}

struct Handoff {
    user_id: String,
    provider: String,
    claims: Claims,
    /// Native SAML: kept with the session it becomes, for single logout.
    saml: Option<db::SamlLogin>,
    lifetime: Lifetime,
    challenge: String,
    label: Option<String>,
    expires: i64,
}

/// What a native SAML sign-in says about the session it makes (ADR 0225): when the IdP signed
/// the person in, when the IdP's session limit ends the session, and whether the IdP was asked
/// to sign them in again. Nothing, for other providers.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Lifetime {
    authn_instant: Option<i64>,
    ends: Option<i64>,
    forced: bool,
}

impl Lifetime {
    fn details(&self, d: &mut Value) {
        if let Some(t) = self.authn_instant {
            d["authnInstant"] = json!(t);
        }
        if let Some(t) = self.ends {
            d["idpSessionEnds"] = json!(t);
        }
        if self.forced {
            d["forceAuthn"] = json!(true);
        }
    }
}

/// A LogoutRequest we sent the IdP, until it answers.
struct PendingLogout {
    provider: String,
    session: String,
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
    /// SAML assertions and logout messages already used (hash of issuer and ID), until they expire.
    seen: Mutex<HashMap<String, i64>>,
    /// Native SAML: our LogoutRequests not answered yet, by ID.
    logouts: Mutex<HashMap<String, PendingLogout>>,
    http: OnceLock<reqwest::Client>,
    /// Least time between JWKS fetches for a key id we don't know.
    pub refresh_gap: Duration,
    /// Held while SAML group-to-role mappings change or a sign-in applies them (ADR 0160),
    /// so a grant can't land on a mapping being removed.
    pub(crate) role_writes: tokio::sync::Mutex<()>,
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
            seen: Mutex::default(),
            logouts: Mutex::default(),
            http: OnceLock::new(),
            refresh_gap: Duration::from_secs(60),
            role_writes: tokio::sync::Mutex::new(()),
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

fn saml_binder_cookie(value: &str, max_age_s: i64) -> HeaderValue {
    HeaderValue::from_str(&format!("{SAML_BINDER}={value}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age={max_age_s}")).unwrap()
}

fn saml_restart_cookie(value: &str, max_age_s: i64) -> HeaderValue {
    HeaderValue::from_str(&format!("{SAML_RESTART}={value}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age={max_age_s}")).unwrap()
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
            sso.providers.push(Arc::new(parse_provider(&id, &sso.public_url, &var, &list)?));
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

    /// The redirect URI to register at the IdP for provider `id` (native SAML: its ACS URL).
    pub fn callback_url(&self, id: &str) -> String {
        match self.provider(id).filter(|p| p.saml_sp()) {
            Some(_) => self.acs_url(id),
            None => self.redirect_uri(id),
        }
    }

    /// Native SAML: where the IdP posts its response (the AssertionConsumerService).
    pub fn acs_url(&self, id: &str) -> String {
        format!("{}/api/auth/sso/{id}/acs", self.public_url)
    }

    /// Native SAML: our SP metadata, which is also our default entity ID.
    pub fn sp_metadata_url(&self, id: &str) -> String {
        sp_metadata_url(&self.public_url, id)
    }

    /// Native SAML: where the IdP sends logout messages (ADR 0137).
    pub fn slo_url(&self, id: &str) -> String {
        format!("{}/api/auth/sso/{id}/slo", self.public_url)
    }

    /// Native SAML: where the IdP sends logout messages over SOAP, server to server (ADR 0208).
    pub fn slo_soap_url(&self, id: &str) -> String {
        format!("{}/api/auth/sso/{id}/slo/soap", self.public_url)
    }

    /// Loads IdP metadata imported with botctl, at startup.
    pub fn load_saved(&self, db: &db::Db) {
        for p in self.providers.iter().filter(|p| matches!(&p.kind, Kind::SamlSp { source: IdpSource::Saved, .. })) {
            let Kind::SamlSp { entity_id, sign_requests, metadata_trust, .. } = &p.kind else {
                continue;
            };
            let Some(xml) = db.setting(&format!("{SAML_METADATA_SETTING}{}", p.id)) else {
                continue;
            };
            match saml_sp::load_idp_metadata(&xml, entity_id, *sign_requests, metadata_trust.as_ref(), db::now()) {
                Ok(m) => p.set_idp(m),
                Err(e) => {
                    crate::obs::log::log_warn!("SSO {}: the imported IdP metadata no longer reads: {e}. Import it again: botctl sso saml {} import", p.id, p.id);
                    if e.untrusted() {
                        db.record(&metadata_refused(p, &e));
                    }
                }
            }
        }
    }

    /// A SAML assertion's or logout message's first use. Err: it was used before, or too many are held.
    fn first_use(&self, key: &str, until: i64, at: i64) -> Result<(), &'static str> {
        let mut m = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, until| *until > at);
        let k = hash(key);
        if m.contains_key(&k) {
            return Err("replayed");
        }
        if m.len() >= MAX_PENDING {
            return Err("sso_too_many");
        }
        m.insert(k, until);
        Ok(())
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

fn sp_metadata_url(public_url: &str, id: &str) -> String {
    format!("{public_url}/api/auth/sso/{id}/metadata")
}

type Var<'a> = dyn Fn(&str) -> Option<String> + 'a;
type List<'a> = dyn Fn(&str) -> Vec<String> + 'a;

const TYPES: [&str; 6] = ["entra", "google", "oidc", "apple", "github", "saml"];

/// Settings that only mean something for some types. Set on another, they would look like
/// a restriction that isn't there, so they are refused.
const ONLY_FOR: [(&str, &[&str]); 36] = [
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
    ("IDP_METADATA_URL", &["saml"]),
    ("IDP_METADATA_FILE", &["saml"]),
    ("SP_ENTITY_ID", &["saml"]),
    ("EMAIL_ATTRIBUTE", &["saml"]),
    ("NAME_ATTRIBUTE", &["saml"]),
    ("SIGN_REQUESTS", &["saml"]),
    ("SP_CERT_FILE", &["saml"]),
    ("ENCRYPTED_ASSERTIONS", &["saml"]),
    ("AES_CBC", &["saml"]),
    ("SP_ENCRYPTION_CERT_FILE", &["saml"]),
    ("METADATA_SIGNING_CERT_FILE", &["saml"]),
    ("SIGNED_METADATA", &["saml"]),
    ("GROUPS_ATTRIBUTE", &["saml"]),
    ("REQUIRED_GROUPS", &["saml"]),
    ("IDP_INITIATED", &["saml"]),
    ("AUTHN_CONTEXT", &["saml"]),
    ("AUTHN_METHODS_ATTRIBUTE", &["saml"]),
    ("REQUEST_AUTHN_CONTEXT", &["saml"]),
    ("FORCE_AUTHN", &["saml"]),
    ("MAX_AUTHN_AGE", &["saml"]),
    ("IDP_SESSION_LIMIT", &["saml"]),
];

/// The SAML bridge's settings (with `ISSUER`), and native SAML's (without), so each refuses the other's.
const SAML_BRIDGE_ONLY: [&str; 6] = ["CLIENT_ID", "IDP_ALIAS", "SCOPES", "SUBJECT_CLAIM", "EMAIL_CLAIM", "NAME_CLAIM"];
const SAML_NATIVE_ONLY: [&str; 21] = [
    "IDP_METADATA_URL",
    "IDP_METADATA_FILE",
    "SP_ENTITY_ID",
    "EMAIL_ATTRIBUTE",
    "NAME_ATTRIBUTE",
    "SIGN_REQUESTS",
    "SP_CERT_FILE",
    "ENCRYPTED_ASSERTIONS",
    "AES_CBC",
    "SP_ENCRYPTION_CERT_FILE",
    "METADATA_SIGNING_CERT_FILE",
    "SIGNED_METADATA",
    "GROUPS_ATTRIBUTE",
    "REQUIRED_GROUPS",
    "IDP_INITIATED",
    "AUTHN_CONTEXT",
    "AUTHN_METHODS_ATTRIBUTE",
    "REQUEST_AUTHN_CONTEXT",
    "FORCE_AUTHN",
    "MAX_AUTHN_AGE",
    "IDP_SESSION_LIMIT",
];

/// Claims people or their admins can change, so they can't be the subject.
const MUTABLE_CLAIMS: [&str; 9] = ["email", "preferred_username", "upn", "unique_name", "name", "nickname", "given_name", "family_name", "phone_number"];

fn parse_provider(id: &str, public_url: &str, var: &Var, list: &List) -> Result<Provider, String> {
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
    let native_saml = ty == "saml" && var(&key("ISSUER")).is_none();
    let client_id = if native_saml { String::new() } else { var(&key("CLIENT_ID")).ok_or_else(|| format!("{} is required", key("CLIENT_ID")))? };
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
            // Always pinned to a tenant id or ALLOWED_TENANTS: that list is what just in time needs here.
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
            let allowed_domains = domains("ALLOWED_DOMAINS")?;
            if jit_role.is_some() && allowed_domains.is_empty() {
                return Err(format!("{} without {} would let anyone the {id} IdP signs in get an account: list your email domains, or link people instead", key("JIT_ROLE"), key("ALLOWED_DOMAINS")));
            }
            (Kind::Oidc { issuer, map: claim_map("sub")?, allowed_domains }, id)
        }
        "saml" if native_saml => {
            if let Some(k) = SAML_BRIDGE_ONLY.iter().find(|k| var(&key(k)).is_some()) {
                return Err(format!("{} is only for the SAML bridge (with {}). Native SAML reads the IdP's metadata instead", key(k), key("ISSUER")));
            }
            let entity_id = var(&key("IDP_ENTITY_ID")).ok_or_else(|| format!("{} is required: the SAML IdP's entity ID, as in its metadata", key("IDP_ENTITY_ID")))?;
            let entity_id = saml::entity_id(&entity_id).ok_or_else(|| format!("{}: {entity_id} is not an entity ID (a URI, like http://www.okta.com/exk1abc)", key("IDP_ENTITY_ID")))?;
            let source = match (var(&key("IDP_METADATA_URL")), var(&key("IDP_METADATA_FILE"))) {
                (Some(_), Some(_)) => return Err(format!("Set {} or {}, not both", key("IDP_METADATA_URL"), key("IDP_METADATA_FILE"))),
                (Some(u), None) if secure_url(&u) => IdpSource::Url(u),
                (Some(_), None) => return Err(format!("{} must be an https URL", key("IDP_METADATA_URL"))),
                (None, Some(f)) => IdpSource::File(f),
                (None, None) => IdpSource::Saved,
            };
            let sp_entity_id = match var(&key("SP_ENTITY_ID")) {
                Some(e) => saml::entity_id(&e).ok_or_else(|| format!("{}: {e} is not an entity ID (a URI)", key("SP_ENTITY_ID")))?,
                None => sp_metadata_url(public_url, id),
            };
            let attribute = |k: &str| -> Result<Option<String>, String> {
                match var(&key(k)) {
                    Some(a) if a.len() <= 256 && a.bytes().all(|b| b.is_ascii_graphic()) => Ok(Some(a)),
                    Some(_) => Err(format!("{} must be an attribute name", key(k))),
                    None => Ok(None),
                }
            };
            let attributes = saml_sp::Attributes { email: attribute("EMAIL_ATTRIBUTE")?, name: attribute("NAME_ATTRIBUTE")?, groups: attribute("GROUPS_ATTRIBUTE")?, authn_methods: attribute("AUTHN_METHODS_ATTRIBUTE")? };
            let mut required_groups: Vec<String> = Vec::new();
            for g in list(&key("REQUIRED_GROUPS")) {
                let g = saml_roles::group_name(&g).map_err(|e| format!("{}: {e}", key("REQUIRED_GROUPS")))?;
                if !required_groups.contains(&g) {
                    required_groups.push(g);
                }
            }
            if !required_groups.is_empty() && attributes.groups.is_none() {
                return Err(format!("{} needs {}: the assertion attribute the IdP sends groups in, like groups", key("REQUIRED_GROUPS"), key("GROUPS_ATTRIBUTE")));
            }
            let allowed_domains = domains("ALLOWED_DOMAINS")?;
            if jit_role.is_some() && allowed_domains.is_empty() {
                return Err(format!("{} without {} would let anyone SAML IdP {entity_id} signs in get an account: list your email domains, or link people instead", key("JIT_ROLE"), key("ALLOWED_DOMAINS")));
            }
            let sign_requests = match var(&key("SIGN_REQUESTS")).map(|v| v.to_ascii_lowercase()).as_deref() {
                None | Some("false") => false,
                Some("true") => true,
                Some(_) => return Err(format!("{} must be true or false", key("SIGN_REQUESTS"))),
            };
            // The key itself is a secret, read when used; its certificate is checked now.
            let cert_file = |k: &str| -> Result<Option<String>, String> {
                let Some(path) = var(&key(k)) else { return Ok(None) };
                let pem = std::fs::read_to_string(&path).map_err(|e| format!("{}: {path}: {e}", key(k)))?;
                let body = saml_sp::pem_body(&pem);
                xmldsig::Cert::from_base64(&body).map_err(|e| format!("{}: {e}", key(k)))?;
                Ok(Some(body))
            };
            let sp_cert = cert_file("SP_CERT_FILE")?;
            let encryption = match var(&key("ENCRYPTED_ASSERTIONS")) {
                None => Encryption::Off,
                Some(v) => Encryption::parse(&v).ok_or_else(|| format!("{} must be off, allow, or require", key("ENCRYPTED_ASSERTIONS")))?,
            };
            let enc_cert = cert_file("SP_ENCRYPTION_CERT_FILE")?;
            if encryption == Encryption::Off && enc_cert.is_some() {
                return Err(format!("{} is only for {}=allow or require", key("SP_ENCRYPTION_CERT_FILE"), key("ENCRYPTED_ASSERTIONS")));
            }
            let aes_cbc = match var(&key("AES_CBC")) {
                None => AesCbc::Off,
                Some(v) => AesCbc::parse(&v).ok_or_else(|| format!("{} must be off or signed-response", key("AES_CBC")))?,
            };
            if encryption == Encryption::Off && aes_cbc != AesCbc::Off {
                return Err(format!("{} is only for {}=allow or require", key("AES_CBC"), key("ENCRYPTED_ASSERTIONS")));
            }
            let same_key = |a: &str, b: &str| matches!((xmldsig::Cert::from_base64(a), xmldsig::Cert::from_base64(b)), (Ok(a), Ok(b)) if a.same_key(&b));
            if let (Some(e), Some(s)) = (&enc_cert, &sp_cert)
                && same_key(e, s)
            {
                return Err(format!("{} must be another key than {}: one key for signing, another for encryption", key("SP_ENCRYPTION_CERT_FILE"), key("SP_CERT_FILE")));
            }
            if let Some(e) = &enc_cert
                && xmldsig::Cert::from_base64(e).is_ok_and(|c| c.kind != xmldsig::KeyKind::Rsa)
            {
                return Err(format!("{} must be an RSA certificate: IdPs encrypt to it with RSA-OAEP", key("SP_ENCRYPTION_CERT_FILE")));
            }
            let metadata_trust = metadata_trust(&key, var)?;
            let idp_initiated = match var(&key("IDP_INITIATED")) {
                None => IdpInitiated::Off,
                Some(v) => IdpInitiated::parse(&v).ok_or_else(|| format!("{} must be off or restart", key("IDP_INITIATED")))?,
            };
            let authn_context = authn_context(&key, var, list, &attributes)?;
            let freshness = freshness(&key, var)?;
            (Kind::SamlSp { entity_id, sp_entity_id, source, attributes, required_groups, allowed_domains, sign_requests, sp_cert, encryption, aes_cbc, enc_cert, metadata_trust, idp_initiated, authn_context, freshness }, saml::LABEL)
        }
        "saml" => {
            if let Some(k) = SAML_NATIVE_ONLY.iter().find(|k| var(&key(k)).is_some()) {
                return Err(format!("{} is only for native SAML (without {})", key(k), key("ISSUER")));
            }
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
            let allowed_domains = domains("ALLOWED_DOMAINS")?;
            if jit_role.is_some() && allowed_domains.is_empty() {
                return Err(format!("{} without {} would let anyone SAML IdP {entity_id} signs in get an account: list your email domains, or link people instead", key("JIT_ROLE"), key("ALLOWED_DOMAINS")));
            }
            (Kind::Saml { issuer, entity_id, alias, map, allowed_domains }, saml::LABEL)
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
    let p = Provider::new(id, &label, kind, &client_id, &scopes, jit_role);
    if let Kind::SamlSp { source: IdpSource::File(path), entity_id, sign_requests, metadata_trust, .. } = &p.kind {
        let xml = std::fs::read_to_string(path).map_err(|e| format!("{}: {path}: {e}", key("IDP_METADATA_FILE")))?;
        p.set_idp(saml_sp::load_idp_metadata(&xml, entity_id, *sign_requests, metadata_trust.as_ref(), db::now()).map_err(|e| format!("{}: {e}", key("IDP_METADATA_FILE")))?);
    }
    Ok(p)
}

/// Native SAML: `METADATA_SIGNING_CERT_FILE` and `SIGNED_METADATA` (ADR 0151). With the
/// certificates, signed metadata is required unless `SIGNED_METADATA=allow`; `off` (the
/// default without them) checks nothing.
fn metadata_trust(key: &dyn Fn(&str) -> String, var: &Var) -> Result<Option<saml_sp::MetadataTrust>, String> {
    let certs = match var(&key("METADATA_SIGNING_CERT_FILE")) {
        Some(path) => {
            let pem = std::fs::read_to_string(&path).map_err(|e| format!("{}: {path}: {e}", key("METADATA_SIGNING_CERT_FILE")))?;
            Some(xmldsig::certs_from_pem(&pem).map_err(|e| format!("{}: {e}", key("METADATA_SIGNING_CERT_FILE")))?)
        }
        None => None,
    };
    let mode = var(&key("SIGNED_METADATA")).map(|v| v.to_ascii_lowercase());
    match (mode.as_deref(), certs) {
        (None | Some("require"), Some(certs)) => Ok(Some(saml_sp::MetadataTrust { certs, require: true })),
        (Some("allow"), Some(certs)) => Ok(Some(saml_sp::MetadataTrust { certs, require: false })),
        (None | Some("off"), None) => Ok(None),
        (Some("off"), Some(_)) => Err(format!("{}=off would ignore {}: remove one of them", key("SIGNED_METADATA"), key("METADATA_SIGNING_CERT_FILE"))),
        (Some("allow" | "require"), None) => Err(format!("{} needs {}: the certificate the IdP signs its metadata with", key("SIGNED_METADATA"), key("METADATA_SIGNING_CERT_FILE"))),
        (Some(_), _) => Err(format!("{} must be off, allow, or require", key("SIGNED_METADATA"))),
    }
}

/// Native SAML: `AUTHN_CONTEXT`, and the two settings that only mean something with it,
/// `AUTHN_METHODS_ATTRIBUTE` and `REQUEST_AUTHN_CONTEXT` (ADR 0190).
fn authn_context(key: &dyn Fn(&str) -> String, var: &Var, list: &List, attributes: &saml_sp::Attributes) -> Result<Option<saml_sp::AuthnContext>, String> {
    let mut accepted: Vec<String> = Vec::new();
    for v in list(&key("AUTHN_CONTEXT")) {
        let v = saml_sp::authn_context_value(&v).map_err(|e| format!("{}: {e}", key("AUTHN_CONTEXT")))?;
        if !accepted.contains(&v) {
            accepted.push(v);
        }
    }
    if accepted.len() > saml_sp::MAX_AUTHN_CONTEXTS {
        return Err(format!("{}: at most {} values", key("AUTHN_CONTEXT"), saml_sp::MAX_AUTHN_CONTEXTS));
    }
    let request = match var(&key("REQUEST_AUTHN_CONTEXT")).map(|v| v.to_ascii_lowercase()).as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(format!("{} must be true or false", key("REQUEST_AUTHN_CONTEXT"))),
    };
    if accepted.is_empty() {
        // Without a requirement, reading the methods or asking for a class would look like a check that isn't made.
        for (k, set) in [("AUTHN_METHODS_ATTRIBUTE", attributes.authn_methods.is_some()), ("REQUEST_AUTHN_CONTEXT", var(&key("REQUEST_AUTHN_CONTEXT")).is_some())] {
            if set {
                return Err(format!("{} needs {}: the ways of signing in to require, like http://schemas.microsoft.com/claims/multipleauthn", key(k), key("AUTHN_CONTEXT")));
            }
        }
        return Ok(None);
    }
    Ok(Some(saml_sp::AuthnContext { accepted, request }))
}

/// Native SAML: `FORCE_AUTHN`, `MAX_AUTHN_AGE` and `IDP_SESSION_LIMIT` (ADR 0225).
fn freshness(key: &dyn Fn(&str) -> String, var: &Var) -> Result<saml_sp::Freshness, String> {
    let switch = |k: &str, yes: &str, no: &str, default: bool| match var(&key(k)).map(|v| v.to_ascii_lowercase()) {
        None => Ok(default),
        Some(v) if v == yes => Ok(true),
        Some(v) if v == no => Ok(false),
        Some(_) => Err(format!("{} must be {yes} or {no}", key(k))),
    };
    let force_authn = switch("FORCE_AUTHN", "true", "false", false)?;
    let idp_session_limit = switch("IDP_SESSION_LIMIT", "on", "off", true)?;
    let max_authn_age_ms = match var(&key("MAX_AUTHN_AGE")).filter(|v| !v.trim().is_empty()) {
        Some(raw) => Some(users::parse_duration(&key("MAX_AUTHN_AGE"), &raw, 0)?),
        None => None,
    };
    if force_authn && max_authn_age_ms.is_some() {
        return Err(format!("{} already asks for a new sign-in every time, newer than any {}: remove one of them", key("FORCE_AUTHN"), key("MAX_AUTHN_AGE")));
    }
    Ok(saml_sp::Freshness { force_authn, max_authn_age_ms, idp_session_limit })
}

// Audit

fn claim_details(d: &mut Value, c: &Claims) {
    d["issuer"] = json!(c.issuer);
    d["subject"] = json!(c.subject);
    d["tenant"] = json!(c.tenant);
    if let Some(u) = &c.username {
        d["username"] = json!(u);
    }
    if let Some(a) = &c.authn_context {
        d["authnContext"] = json!(a);
    }
    if let Some(e) = c.encryption {
        d["assertionEncryption"] = json!(e);
    }
}

/// The IdP's type (entra, google, oidc, apple, github, saml), beside the configured id.
pub(crate) fn idp_type(a: &Auth, provider: &str) -> Option<&'static str> {
    a.sso.provider(provider).map(|p| p.type_name())
}

/// Failures anyone can cause without the IdP's help, by opening a callback URL.
/// Native SAML's are the ones before the IdP's signature was checked.
const UNVOUCHED: [&str; 19] = [
    "unknown_state",
    "wrong_provider",
    "binder_mismatch",
    "idp_error",
    "missing_code",
    "missing_response",
    "bad_response",
    "missing_assertion",
    "encrypted_assertion",
    "unencrypted_assertion",
    "bad_encryption",
    "weak_key_transport",
    "cbc_unsigned_response",
    "no_sp_key",
    "unsigned",
    "bad_signature",
    "wrapped",
    "bad_algorithm",
    "weak_algorithm",
];

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

fn signed_in(a: &Auth, user: &User, s: &db::Session, provider: &str, c: &Claims, lifetime: &Lifetime, source: &Source) {
    let mut d = json!({ "method": "sso", "provider": provider, "idp": idp_type(a, provider), "kind": s.kind, "label": s.label });
    claim_details(&mut d, c);
    lifetime.details(&mut d);
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
    let endpoint = p.authorization_endpoint(sso.http(), sso.refresh_gap).await;
    audit_metadata_refusal(&a, p);
    let endpoint = match endpoint {
        Ok(e) => e,
        Err(e) => {
            crate::obs::log::log_warn!("SSO {id}: discovery failed: {e}");
            return no_store(ret.fail("sso_failed"));
        }
    };
    let (state, nonce, verifier, binder) = (random(), random(), random(), random());
    // Native SAML: the AuthnRequest's ID, which the response's InResponseTo must name.
    let nonce = if p.saml_sp() { saml_sp::request_id() } else { nonce };
    let ret = match ret {
        Return::Cookie { .. } => Return::Cookie { binder: hash(&binder) },
        r => r,
    };
    let label = users::clean_label(&json!(q.get("label")));
    let forced = matches!(&p.kind, Kind::SamlSp { freshness, .. } if freshness.force_authn);
    let pending = Pending { provider: id.clone(), nonce: nonce.clone(), verifier: verifier.clone(), ip, label, expires: at + PENDING_TTL_MS, ret: ret.clone(), name: None, requested: at, forced };
    if !sso.hold(&state, pending, at) {
        return no_store(ret.fail("sso_too_many"));
    }
    let mut url = Url::parse(&endpoint).expect("checked by secure_url");
    if p.saml_sp() {
        let binder = matches!(ret, Return::Cookie { .. }).then_some(binder.as_str());
        return saml_redirect(&a, p, &endpoint, &nonce, &state, &ret, binder, forced, at);
    }
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

/// Native SAML: the browser off to the IdP with an AuthnRequest whose ID is `request_id` and
/// whose RelayState is `state`, signed when the provider signs them, with `binder` set as a web
/// sign-in's cookie. `force` asks the IdP to sign the person in again (ADR 0225).
#[allow(clippy::too_many_arguments)]
fn saml_redirect(a: &Auth, p: &Provider, endpoint: &str, request_id: &str, state: &str, ret: &Return, binder: Option<&str>, force: bool, at: i64) -> Response {
    let Kind::SamlSp { sp_entity_id, sign_requests, authn_context, .. } = &p.kind else {
        return no_store(ret.fail("sso_failed"));
    };
    let key = match (sign_requests, a.app.as_ref()) {
        (false, _) => None,
        (true, Some(app)) => match sp_key(app, p) {
            Ok(k) => Some(k),
            Err(e) => {
                crate::obs::log::log_warn!("SSO {}: can't sign the AuthnRequest: {e}", p.id);
                return no_store(ret.fail("sso_failed"));
            }
        },
        (true, None) => return no_store(ret.fail("sso_failed")),
    };
    let request = saml_sp::authn_request(&Sp { entity_id: sp_entity_id, acs: &a.sso.acs_url(&p.id) }, request_id, endpoint, at, authn_context.as_ref(), force);
    let query = saml_sp::redirect_query("SAMLRequest", &request, Some(state), key.as_deref());
    let mut res = see(&saml_sp::with_redirect_query(endpoint, &query));
    if let Some(b) = binder {
        res.headers_mut().insert(header::SET_COOKIE, saml_binder_cookie(b, PENDING_TTL_MS / 1000));
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
    let claims = match p.sign_in(sso.http(), code, &sso.redirect_uri(id), &pending.verifier, &pending.nonce, sso.refresh_gap).await {
        Ok(c) => c,
        Err(e) => {
            a.limiter.fail(&ip, at);
            failed(a, source, id, e.0, None, json!({}));
            // A real account the server doesn't take: say so, so people try another one.
            return ret.fail(if matches!(e.0, "wrong_domain" | "email_unverified" | "wrong_org" | "not_brokered") { "sso_wrong_account" } else { "sso_failed" });
        }
    };
    complete(a, app, source, id, p, &pending, claims, None, None, Lifetime::default(), at).await
}

/// The end of every sign-in, once the IdP vouched for `claims`: the linked (or just-in-time)
/// user, if active, gets a session cookie, or a one-time code for the app that started.
/// `saml` is a native SAML sign-in's NameID and IdP session, kept with the session, and
/// `groups` the groups its assertion listed, which its role mappings follow (ADR 0160), and
/// `lifetime` when its session must end (ADR 0225).
#[allow(clippy::too_many_arguments)]
async fn complete(a: &Auth, app: &AppState, source: &Source, id: &str, p: &Provider, pending: &Pending, mut claims: Claims, saml: Option<db::SamlLogin>, groups: Option<&saml_sp::Groups>, lifetime: Lifetime, at: i64) -> Response {
    let (sso, ret) = (&a.sso, &pending.ret);
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
    let user = match groups {
        Some(g) => {
            saml_roles::signed_in(app, a, source, p, &user, g, true).await;
            app.db.user(&user.id).unwrap_or(user)
        }
        None => user,
    };
    match ret {
        Return::Cookie { .. } => {
            let label = pending.label.as_deref().or(Some("Web"));
            let (s, token) = users::start_session_ending(a, &user, "sso", Some((id, &claims.key())), None, true, label, source, lifetime.ends);
            if let Some(l) = &saml {
                app.db.add_saml_session(&s.id, l);
            }
            signed_in(a, &user, &s, id, &claims, &lifetime, source);
            let max_age = lifetime.ends.map_or(a.sessions.max_ms, |e| (e - at).min(a.sessions.max_ms));
            let mut res = Html(signed_in_page(user.role)).into_response();
            res.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&users::session_cookie(&token, max_age)).unwrap());
            res
        }
        Return::App { redirect, challenge, state } => {
            let code = users::new_secret(HANDOFF_PREFIX);
            let h = Handoff { user_id: user.id, provider: id.into(), claims, saml, lifetime, challenge: challenge.clone(), label: pending.label.clone(), expires: at + HANDOFF_TTL_MS };
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

/// `POST /api/auth/sso/{id}/acs`: the IdP posts its SAML response here (HTTP-POST binding).
pub async fn acs(Extension(a): Extension<Arc<Auth>>, Extension(source): Extension<Source>, headers: HeaderMap, Path(id): Path<String>, Form(f): Form<HashMap<String, String>>) -> Response {
    let mut res = finish_saml(&a, &source, &headers, &id, &f).await;
    let sets = |name: &str| res.headers().get_all(header::SET_COOKIE).iter().any(|c| c.as_bytes().starts_with(format!("{name}=").as_bytes()));
    let restarting = sets(SAML_RESTART);
    // Asked to sign in again (ADR 0225): the new binder stays, for the IdP's next answer.
    let reauthenticating = sets(SAML_BINDER);
    if !reauthenticating {
        res.headers_mut().append(header::SET_COOKIE, saml_binder_cookie("", 0));
    }
    if !restarting && !reauthenticating {
        res.headers_mut().append(header::SET_COOKIE, saml_restart_cookie("", 0));
    }
    no_store(res)
}

/// Checks a posted response against the provider's IdP metadata, with our key when it takes
/// encrypted assertions. `request_id` is the AuthnRequest's ID, or None for an unsolicited
/// response. A refusal says whether it counts against the client's address.
async fn check_saml(a: &Auth, app: &AppState, p: &Provider, posted: &str, request_id: Option<&str>, at: i64) -> Result<saml_sp::Checked, (Refused, bool)> {
    let idp = idp_metadata(a, p).await.map_err(|e| (Refused(e.0, None), false))?;
    let Kind::SamlSp { sp_entity_id, attributes, encryption, aes_cbc, .. } = &p.kind else {
        return Err((Refused("wrong_provider", None), true));
    };
    let (decrypt, held) = match encryption {
        Encryption::Off => (vec![], None),
        _ => match decrypt_keys(app, p) {
            Ok(k) => k,
            Err(e) => {
                crate::obs::log::log_warn!("SSO {}: can't decrypt assertions: {e}", p.id);
                return Err((Refused("no_sp_key", None), false));
            }
        },
    };
    let keys: Vec<&SpKey> = decrypt.iter().map(|(_, k)| k.as_ref()).collect();
    let acs = a.sso.acs_url(&p.id);
    let expect = saml_sp::Expect {
        sp: Sp { entity_id: sp_entity_id, acs: &acs },
        idp: &idp,
        request_id,
        attributes,
        now_ms: at,
        decrypt: &keys,
        require_encrypted: *encryption == Encryption::Require,
        aes_cbc: *aes_cbc,
    };
    let checked = saml_sp::check_response(posted, &expect).map_err(|r| {
        let counts = r.0 != "idp_error";
        (r, counts)
    })?;
    if let Some(h) = held {
        for stage in checked.decrypted_with.iter().filter_map(|&i| decrypt.get(i).and_then(|(s, _)| *s)) {
            h.used(stage, at);
        }
    }
    Ok(checked)
}

async fn finish_saml(a: &Auth, source: &Source, headers: &HeaderMap, id: &str, f: &HashMap<String, String>) -> Response {
    let (sso, (ip, at)) = (&a.sso, (source.ip.clone().unwrap_or_default(), db::now()));
    let Some(app) = a.app.as_ref() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Only answers to a sign-in this server started; anything else is IdP-initiated or stale.
    let Some(pending) = f.get("RelayState").and_then(|s| sso.take(s, at)) else {
        return unsolicited(a, app, source, headers, id, f, at).await;
    };
    let ret = &pending.ret;
    let Some(p) = sso.provider(id).filter(|p| p.saml_sp() && pending.provider == id) else {
        a.limiter.fail(&ip, at);
        failed(a, source, id, "wrong_provider", None, json!({}));
        return ret.fail("sso_failed");
    };
    if let Return::Cookie { binder } = ret
        && !read_cookie(headers, SAML_BINDER).is_some_and(|c| crate::same(hash(c).as_bytes(), binder.as_bytes()))
    {
        a.limiter.fail(&ip, at);
        failed(a, source, id, "binder_mismatch", None, json!({}));
        return ret.fail("sso_expired");
    }
    if a.limiter.blocked(&ip, at).is_some() {
        return ret.fail("sso_too_many");
    }
    let Some(posted) = f.get("SAMLResponse") else {
        failed(a, source, id, "missing_response", None, json!({}));
        return ret.fail("sso_failed");
    };
    let checked = match check_saml(a, app, p, posted, Some(&pending.nonce), at).await {
        Ok(c) => c,
        Err((Refused(reason, status), counts)) => {
            if counts {
                a.limiter.fail(&ip, at);
            }
            let cancelled = status.as_deref().is_some_and(|s| s.contains("AuthnFailed") || s.contains("RequestDenied"));
            // The IdP couldn't sign them in the way REQUEST_AUTHN_CONTEXT asked for (ADR 0190).
            let weak = status.as_deref().is_some_and(|s| s.contains("NoAuthnContext"));
            failed(a, source, id, reason, None, status.map_or(json!({}), |s| json!({ "idpStatus": s })));
            return ret.fail(if weak { "sso_mfa_required" } else if cancelled { "sso_cancelled" } else { "sso_failed" });
        }
    };
    let assertion = format!("{}|{}", checked.claims.issuer, checked.assertion_id);
    if let Err(reason) = sso.first_use(&assertion, checked.until_ms + saml_sp::SKEW_MS, at) {
        a.limiter.fail(&ip, at);
        failed(a, source, id, if reason == "replayed" { "replayed" } else { "too_many" }, Some(&checked.claims), json!({ "assertion": crate::audit::clip(&checked.assertion_id, 128) }));
        return ret.fail(if reason == "replayed" { "sso_failed" } else { reason });
    }
    if let Err(e) = p.check_email(checked.claims.email.as_deref()) {
        a.limiter.fail(&ip, at);
        failed(a, source, id, e.0, Some(&checked.claims), json!({}));
        return ret.fail("sso_wrong_account");
    }
    // Before anyone is made just in time: only people the IdP puts in a required group.
    if let Kind::SamlSp { required_groups, .. } = &p.kind
        && !required_groups.is_empty()
    {
        let refusal = match &checked.groups {
            saml_sp::Groups::Listed(g) if g.iter().any(|g| required_groups.contains(g)) => None,
            saml_sp::Groups::Listed(_) => Some(("not_in_group", json!({}))),
            saml_sp::Groups::Unknown(why) => Some(("groups_unknown", json!({ "groups": why }))),
            saml_sp::Groups::NotRead => Some(("groups_unknown", json!({ "groups": "not_read" }))),
        };
        if let Some((reason, extra)) = refusal {
            a.limiter.fail(&ip, at);
            failed(a, source, id, reason, Some(&checked.claims), extra);
            // The IdP still vouched for their groups: what a group they left gave goes now.
            if let Some((i, user)) = app.db.identity(&checked.claims.issuer, &checked.claims.subject)
                && i.provider == p.id
            {
                saml_roles::signed_in(app, a, source, p, &user, &checked.groups, false).await;
            }
            return ret.fail("sso_not_allowed");
        }
    }
    let mut claims = checked.claims;
    // Also before anyone is made just in time: only people who signed in the way the provider requires.
    if let Kind::SamlSp { authn_context: Some(required), .. } = &p.kind {
        match checked.authn.meets(required) {
            Some(met) => claims.authn_context = Some(met.to_string()),
            None => {
                a.limiter.fail(&ip, at);
                let seen = |v: &[String]| v.iter().map(|c| crate::audit::clip(c, 128)).collect::<Vec<_>>();
                let mut extra = json!({ "authnContexts": seen(&checked.authn.classes) });
                if let Kind::SamlSp { attributes: saml_sp::Attributes { authn_methods: Some(_), .. }, .. } = &p.kind {
                    extra["authnMethods"] = json!(seen(&checked.authn.methods));
                }
                failed(a, source, id, "authn_context", Some(&claims), extra);
                return ret.fail("sso_mfa_required");
            }
        }
    }
    // Last before anyone is made just in time: a sign-in recent enough, in an IdP session that
    // hasn't ended (ADR 0225). Otherwise the IdP is asked once to sign the person in again.
    let freshness = match &p.kind {
        Kind::SamlSp { freshness, .. } => freshness.clone(),
        _ => saml_sp::Freshness::default(),
    };
    let since = freshness.authn_since(pending.requested, pending.forced, at);
    let ends = saml_sp::idp_session_end(checked.idp_session_ends, freshness.idp_session_limit, at);
    let stale = if !saml_sp::authn_fresh(checked.authn_instant, since, at) {
        Some("stale_authn")
    } else if ends.is_err() {
        Some("idp_session_ended")
    } else {
        None
    };
    if let Some(reason) = stale {
        let extra = json!({ "authnInstant": checked.authn_instant, "authnSince": since, "idpSessionEnds": checked.idp_session_ends, "forceAuthn": pending.forced });
        if !pending.forced {
            reauthn_asked(a, source, id, reason, &claims, extra);
            return reauthenticate(a, p, &pending, at).await;
        }
        a.limiter.fail(&ip, at);
        failed(a, source, id, reason, Some(&claims), extra);
        return ret.fail("sso_reauth_required");
    }
    let lifetime = Lifetime { authn_instant: checked.authn_instant, ends: ends.ok().flatten(), forced: pending.forced };
    complete(a, app, source, id, p, &pending, claims, Some(checked.login), Some(&checked.groups), lifetime, at).await
}

/// `auth.saml_reauthn`: a sign-in's answer was too old, or its IdP session had ended, so the
/// IdP is asked to sign the person in again (ADR 0225).
fn reauthn_asked(a: &Auth, source: &Source, id: &str, reason: &str, claims: &Claims, extra: Value) {
    let mut d = json!({ "method": "sso", "provider": id, "idp": "saml", "reason": reason, "outcome": "asked_again" });
    claim_details(&mut d, claims);
    if let (Value::Object(d), Value::Object(e)) = (&mut d, extra) {
        d.extend(e);
    }
    let actor = Actor { kind: ActorKind::User, subject: Some(claims.key()), method: Some("sso".into()), idp: Some("saml".into()), idp_provider: Some(id.into()), ..Default::default() };
    a.record(Who { actor, source: source.clone() }.event("auth.saml_reauthn").target("sso_provider", id).details(d));
}

/// Sends the browser (or the app's) that started `pending` back to the IdP with a new
/// AuthnRequest asking for `ForceAuthn`, under a new state and binder. Its answer is held to
/// that request, and isn't asked again.
async fn reauthenticate(a: &Auth, p: &Provider, pending: &Pending, at: i64) -> Response {
    let endpoint = match p.authorization_endpoint(a.sso.http(), a.sso.refresh_gap).await {
        Ok(e) => e,
        Err(e) => {
            crate::obs::log::log_warn!("SSO {}: discovery failed: {e}", p.id);
            return pending.ret.fail("sso_failed");
        }
    };
    let (state, binder) = (random(), random());
    let ret = match &pending.ret {
        Return::Cookie { .. } => Return::Cookie { binder: hash(&binder) },
        r => r.clone(),
    };
    let request_id = saml_sp::request_id();
    let again = Pending {
        provider: pending.provider.clone(),
        nonce: request_id.clone(),
        verifier: random(),
        ip: pending.ip.clone(),
        label: pending.label.clone(),
        expires: at + PENDING_TTL_MS,
        ret: ret.clone(),
        name: None,
        requested: at,
        forced: true,
    };
    if !a.sso.hold(&state, again, at) {
        return ret.fail("sso_too_many");
    }
    let binder = matches!(ret, Return::Cookie { .. }).then_some(binder.as_str());
    saml_redirect(a, p, &endpoint, &request_id, &state, &ret, binder, true, at)
}

/// A post that answers no sign-in this server holds. Refused as `unknown_state`, unless the
/// provider restarts IdP-initiated sign-ins (ADR 0175) and this is an unsolicited response
/// that checks out in full. Then its assertion is spent, unused, and the browser starts an
/// SP-initiated sign-in: whoever the IdP signs in for that one is who gets a session.
async fn unsolicited(a: &Auth, app: &AppState, source: &Source, headers: &HeaderMap, id: &str, f: &HashMap<String, String>, at: i64) -> Response {
    let ip = source.ip.clone().unwrap_or_default();
    let expired = || {
        a.limiter.fail(&ip, at);
        failed(a, source, id, "unknown_state", None, json!({}));
        see("/login?error=sso_expired")
    };
    let Some(p) = a.sso.provider(id).filter(|p| matches!(p.kind, Kind::SamlSp { idp_initiated: IdpInitiated::Restart, .. })) else {
        return expired();
    };
    let Some(posted) = f.get("SAMLResponse") else { return expired() };
    if a.limiter.blocked(&ip, at).is_some() {
        return see("/login?error=sso_too_many");
    }
    let checked = match check_saml(a, app, p, posted, None, at).await {
        Ok(c) => c,
        // It answers a request: a sign-in that expired, or another browser's.
        Err((Refused("in_response_to_mismatch", _), _)) => return expired(),
        Err((Refused(reason, status), counts)) => {
            if counts {
                a.limiter.fail(&ip, at);
            }
            let mut extra = json!({ "idpInitiated": true });
            if let Some(s) = status {
                extra["idpStatus"] = json!(s);
            }
            failed(a, source, id, reason, None, extra);
            return see("/login?error=sso_failed");
        }
    };
    let assertion = format!("{}|{}", checked.claims.issuer, checked.assertion_id);
    if let Err(reason) = a.sso.first_use(&assertion, checked.until_ms + saml_sp::SKEW_MS, at) {
        a.limiter.fail(&ip, at);
        failed(a, source, id, if reason == "replayed" { "replayed" } else { "too_many" }, Some(&checked.claims), json!({ "assertion": crate::audit::clip(&checked.assertion_id, 128), "idpInitiated": true }));
        return see(&format!("/login?error={}", if reason == "replayed" { "sso_failed" } else { reason }));
    }
    // The IdP answered the sign-in this browser was just sent to start with another unsolicited
    // response: it ignores our AuthnRequests, and restarting again would go round forever.
    if read_cookie(headers, SAML_RESTART) == Some(id) {
        failed(a, source, id, "idp_initiated_loop", Some(&checked.claims), json!({ "idpInitiated": true }));
        return see("/login?error=sso_failed");
    }
    let mut d = json!({ "method": "sso", "provider": id, "idp": "saml", "outcome": "restarted", "assertion": crate::audit::clip(&checked.assertion_id, 128) });
    claim_details(&mut d, &checked.claims);
    let actor = Actor { kind: ActorKind::User, subject: Some(checked.claims.key()), method: Some("sso".into()), idp: Some("saml".into()), idp_provider: Some(id.into()), ..Default::default() };
    a.record(Who { actor, source: source.clone() }.event("auth.saml_idp_initiated").target("sso_provider", id).details(d));
    let mut res = see(&format!("{}/api/auth/sso/{id}/start", a.sso.public_url));
    res.headers_mut().insert(header::SET_COOKIE, saml_restart_cookie(id, RESTART_TTL_S));
    res
}

/// `GET /api/auth/sso/{id}/metadata`: our SAML SP metadata, for the IdP to import. With our
/// key, it has its certificate and the SLO URL; without one (no database), neither.
pub async fn saml_metadata(Extension(a): Extension<Arc<Auth>>, Path(id): Path<String>) -> Response {
    let Some(p) = a.sso.provider(&id).filter(|p| p.saml_sp()) else {
        return not_found("SAML provider").into_response();
    };
    let Kind::SamlSp { sp_entity_id, sign_requests, encryption, aes_cbc, .. } = &p.kind else {
        return not_found("SAML provider").into_response();
    };
    let keys = a.app.as_ref().and_then(|app| published_keys(app, p, KeyUse::Signing).map_err(|e| crate::obs::log::log_warn!("SSO {id}: no SP key for the metadata: {e}")).ok());
    let enc = match (encryption, a.app.as_ref()) {
        (Encryption::Off, _) | (_, None) => vec![],
        (_, Some(app)) => published_keys(app, p, KeyUse::Encryption).map_err(|e| crate::obs::log::log_warn!("SSO {id}: no SP encryption key for the metadata: {e}")).unwrap_or_default(),
    };
    let (acs, slo, slo_soap) = (a.sso.acs_url(&id), a.sso.slo_url(&id), a.sso.slo_soap_url(&id));
    let signing_certs: Vec<&str> = keys.iter().flatten().map(|k| k.cert.as_str()).collect();
    let signing = keys.as_ref().map(|_| SpSigning { certs: &signing_certs, slo: &slo, slo_soap: &slo_soap, sign_requests: *sign_requests });
    let enc_certs: Vec<&str> = enc.iter().map(|k| k.cert.as_str()).collect();
    let md = saml_sp::sp_metadata(&Sp { entity_id: sp_entity_id, acs: &acs }, signing.as_ref(), &enc_certs, *aes_cbc);
    ([(header::CONTENT_TYPE, "application/samlmetadata+xml")], md).into_response()
}

// Native SAML: our key and single logout (ADR 0137)

/// A native SAML provider's SP signing key: `SSO_<ID>_PRIVATE_KEY` with `SP_CERT_FILE`, else
/// made once and kept sealed in settings, so the certificate in our metadata stays the same
/// until an admin rolls it over (ADR 0181).
fn sp_key(app: &AppState, p: &Provider) -> Result<Arc<SpKey>, String> {
    sp_key_for(app, p, KeyUse::Signing)
}

/// The same for its encryption key (ADR 0150): `SSO_<ID>_ENCRYPTION_PRIVATE_KEY` with
/// `SP_ENCRYPTION_CERT_FILE`, else made once and kept like the signing key, beside it.
fn sp_encryption_key(app: &AppState, p: &Provider) -> Result<Arc<SpKey>, String> {
    sp_key_for(app, p, KeyUse::Encryption)
}

fn sp_key_for(app: &AppState, p: &Provider, u: KeyUse) -> Result<Arc<SpKey>, String> {
    if !p.saml_sp() {
        return Err("not a native SAML provider".into());
    }
    if p.sp_cert_for(u).is_some() {
        return p.configured_sp_key(u);
    }
    saml_keys::held(app, p, u).map(|h| h.current.clone())
}

/// The keys our metadata publishes for `u`: the one in use, then a rollover's next one.
fn published_keys(app: &AppState, p: &Provider, u: KeyUse) -> Result<Vec<Arc<SpKey>>, String> {
    if !p.saml_sp() || p.sp_cert_for(u).is_some() {
        return sp_key_for(app, p, u).map(|k| vec![k]);
    }
    saml_keys::held(app, p, u).map(|h| h.published())
}

/// The keys an encrypted assertion or NameID may be decrypted with, in the order they're tried,
/// each with its rollover stage when botd made it, and the rollover that holds them.
fn decrypt_keys(app: &AppState, p: &Provider) -> Result<(Vec<(Option<saml_keys::Stage>, Arc<SpKey>)>, Option<Arc<saml_keys::Held>>), String> {
    if !p.saml_sp() || p.sp_cert_for(KeyUse::Encryption).is_some() {
        return sp_encryption_key(app, p).map(|k| (vec![(None, k)], None));
    }
    let h = saml_keys::held(app, p, KeyUse::Encryption)?;
    Ok((h.decrypting().into_iter().map(|(s, k)| (Some(s), k)).collect(), Some(h)))
}

/// How signing out of SuperBot also signs the person out of their native SAML IdP.
pub enum IdpLogout {
    /// The browser follows `url`, a signed LogoutRequest over HTTP-Redirect (ADR 0137).
    Redirect { url: String, id: String },
    /// botd sent the LogoutRequest itself, over SOAP (ADR 0208); the answer is audited when it comes.
    BackChannel { id: String },
}

impl IdpLogout {
    pub fn id(&self) -> &str {
        match self {
            IdpLogout::Redirect { id, .. } | IdpLogout::BackChannel { id } => id,
        }
    }

    pub fn binding(&self) -> &'static str {
        match self {
            IdpLogout::Redirect { .. } => "redirect",
            IdpLogout::BackChannel { .. } => "soap",
        }
    }
}

/// Signing out of a session a native SAML IdP vouched for. The session is revoked already;
/// this ends the person's IdP session too. A browser session goes to the IdP's SLO URL with a
/// signed LogoutRequest. Without a browser to send (the phone app, `botctl`), or an IdP with
/// only a SOAP SLO URL, botd sends it over SOAP itself, in the background (ADR 0208). None when
/// the IdP has neither, or we can't sign.
pub async fn logout_request(a: &Arc<Auth>, app: &AppState, s: &db::Session) -> Option<IdpLogout> {
    let p = a.sso.provider(s.idp_provider.as_deref()?)?;
    let Kind::SamlSp { sp_entity_id, .. } = &p.kind else { return None };
    let login = app.db.saml_session(&s.id)?;
    // Cached metadata, even if stale, and a short fetch otherwise: clients wait 5 s for this answer.
    let idp = match p.idp_loaded() {
        Some(m) => m,
        None => tokio::time::timeout(Duration::from_secs(3), idp_metadata(a, p)).await.ok()?.ok()?,
    };
    let browser = s.kind == "cookie";
    let slo = match (&idp.slo, &idp.slo_soap) {
        (Some(slo), _) if browser => slo.clone(),
        (_, Some(soap)) => {
            let key = sp_key(app, p).map_err(|e| crate::obs::log::log_warn!("SSO {}: no back-channel logout: {e}", p.id)).ok()?;
            let id = saml_sp::request_id();
            let xml = saml_slo::logout_request(sp_entity_id, &id, soap, &login, db::now());
            let signed = key.sign_enveloped(&xml, &id).map_err(|e| crate::obs::log::log_warn!("SSO {}: no back-channel logout: {e}", p.id)).ok()?;
            let (a, provider, url, session, request) = (a.clone(), p.id.clone(), soap.clone(), s.id.clone(), id.clone());
            tokio::spawn(async move { back_channel_logout(&a, &provider, &idp, &url, &session, &request, &signed).await });
            return Some(IdpLogout::BackChannel { id });
        }
        _ => return None,
    };
    let key = sp_key(app, p).map_err(|e| crate::obs::log::log_warn!("SSO {}: no single logout: {e}", p.id)).ok()?;
    let (id, at) = (saml_sp::request_id(), db::now());
    {
        let mut m = a.sso.logouts.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, l| l.expires > at);
        if m.len() >= MAX_PENDING {
            return None;
        }
        m.insert(id.clone(), PendingLogout { provider: p.id.clone(), session: s.id.clone(), expires: at + PENDING_TTL_MS });
    }
    let xml = saml_slo::logout_request(sp_entity_id, &id, &slo.location, &login, at);
    let url = saml_sp::with_redirect_query(&slo.location, &saml_sp::redirect_query("SAMLRequest", &xml, None, Some(&key)));
    Some(IdpLogout::Redirect { url, id })
}

/// Posts our signed LogoutRequest `signed` (ID `request`) to the IdP's SOAP SLO URL and audits
/// its answer as `auth.slo_response`, against the session that was signed out. Its body is read
/// up to `MAX_RESPONSE`, and redirects aren't followed: the URL is the one the metadata names.
async fn back_channel_logout(a: &Auth, provider: &str, idp: &saml_sp::IdpMetadata, url: &str, session: &str, request: &str, signed: &str) {
    let sent = a
        .sso
        .http()
        .post(url)
        .header(header::CONTENT_TYPE, "text/xml; charset=utf-8")
        .header("SOAPAction", saml_slo::SOAP_ACTION)
        .body(saml_slo::soap_envelope(signed))
        .send()
        .await;
    let answer = match sent {
        Err(e) => Err(Refused("unreachable", Some(crate::audit::clip(&e.without_url().to_string(), 128)))),
        // SOAP 1.1 faults come with a 500, so the body is read either way.
        Ok(res) => match capped_body(res, saml_sp::MAX_RESPONSE).await {
            Some((code, body)) => saml_slo::receive_soap_response(&body, idp, request, db::now()).map_err(|r| if r.0 == "bad_message" && !code.is_success() { Refused("http_error", Some(code.as_u16().to_string())) } else { r }),
            None => Err(Refused("bad_message", None)),
        },
    };
    let (outcome, mut details) = match &answer {
        Ok(status) => (if status.is_none() { Outcome::Success } else { Outcome::Failure }, json!({ "status": status.as_deref().unwrap_or("Success") })),
        Err(Refused(reason, detail)) => {
            crate::obs::log::log_warn!("SSO {provider}: the IdP's back-channel logout answer: {reason}");
            (Outcome::Failure, json!({ "status": "none", "reason": reason, "detail": detail }))
        }
    };
    if let Value::Object(d) = &mut details {
        d.extend([("provider".into(), json!(provider)), ("idp".into(), json!("saml")), ("requestId".into(), json!(request)), ("binding".into(), json!("soap"))]);
    }
    let actor = Actor { idp: Some("saml".into()), idp_provider: Some(provider.into()), ..Actor::system("sso") };
    a.record(Event::new(actor, "auth.slo_response").target("session", session).outcome(outcome).details(details));
}

/// A response's status and body, or None when it's over `max` bytes or not UTF-8.
async fn capped_body(mut res: reqwest::Response, max: usize) -> Option<(StatusCode, String)> {
    let code = StatusCode::from_u16(res.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await.ok()? {
        if body.len() + chunk.len() > max {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).ok().map(|b| (code, b))
}

/// Refused logout messages anyone can send: the ones before the IdP's signature was checked.
const SLO_UNVOUCHED: [&str; 10] = ["not_ready", "no_slo", "no_sp_key", "bad_message", "must_understand", "wrapped", "unsigned", "bad_signature", "bad_algorithm", "weak_algorithm"];

fn slo_failed(a: &Auth, source: &Source, provider: &str, reason: &str, extra: Value) -> Response {
    slo_refused(a, source, provider, reason, extra);
    let body = "SuperBot couldn't use that logout message. Sign out of SuperBot itself to end your session there.";
    no_store((StatusCode::BAD_REQUEST, body).into_response())
}

/// The same over SOAP (ADR 0208): a SOAP 1.1 fault, which comes with a 500.
fn soap_failed(a: &Auth, source: &Source, provider: &str, reason: &str, mut extra: Value) -> Response {
    extra["binding"] = json!("soap");
    slo_refused(a, source, provider, reason, extra);
    no_store((StatusCode::INTERNAL_SERVER_ERROR, [(header::CONTENT_TYPE, "text/xml; charset=utf-8")], saml_slo::soap_fault(reason)).into_response())
}

/// `auth.slo_failed`, throttled per address for messages nobody vouched for.
fn slo_refused(a: &Auth, source: &Source, provider: &str, reason: &str, extra: Value) {
    let mut d = json!({ "provider": provider, "idp": idp_type(a, provider), "reason": reason });
    if let (Value::Object(d), Value::Object(e)) = (&mut d, extra) {
        d.extend(e);
    }
    let logged = !SLO_UNVOUCHED.contains(&reason) || {
        let client = format!("{}|slo", source.ip.as_deref().unwrap_or(""));
        a.logins.failure(&client, db::now()).map(|missed| d["unloggedSinceLast"] = json!(missed)).is_some()
    };
    if logged {
        let actor = Actor { kind: ActorKind::User, method: Some("sso".into()), idp: idp_type(a, provider).map(String::from), idp_provider: Some(provider.into()), ..Default::default() };
        a.record(Who { actor, source: source.clone() }.event("auth.slo_failed").outcome(Outcome::Failure).details(d));
    }
}

/// `GET /api/auth/sso/{id}/slo`: a logout message over the HTTP-Redirect binding.
pub async fn slo_get(Extension(a): Extension<Arc<Auth>>, Extension(source): Extension<Source>, Path(id): Path<String>, OriginalUri(uri): OriginalUri) -> Response {
    slo(&a, &source, &id, &saml_slo::Incoming::Redirect(uri.query().unwrap_or(""))).await
}

/// `POST /api/auth/sso/{id}/slo`: the same over HTTP-POST.
pub async fn slo_post(Extension(a): Extension<Arc<Auth>>, Extension(source): Extension<Source>, Path(id): Path<String>, Form(f): Form<HashMap<String, String>>) -> Response {
    slo(&a, &source, &id, &saml_slo::Incoming::Post(&f)).await
}

/// The IdP's LogoutRequest revokes the sessions its NameID and SessionIndexes name and is
/// answered with our signed LogoutResponse; its LogoutResponse to ours is audited.
async fn slo(a: &Auth, source: &Source, id: &str, incoming: &saml_slo::Incoming<'_>) -> Response {
    let Some(app) = a.app.as_ref() else { return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    let Some(p) = a.sso.provider(id).filter(|p| p.saml_sp()) else { return not_found("SAML provider").into_response() };
    let Kind::SamlSp { sp_entity_id, encryption, .. } = &p.kind else { return not_found("SAML provider").into_response() };
    // From a URL, the metadata may not be loaded since a restart: logouts can't wait for a sign-in.
    let Ok(idp) = idp_metadata(a, p).await else { return slo_failed(a, source, id, "not_ready", json!({})) };
    let Some(idp_slo) = idp.slo.clone() else { return slo_failed(a, source, id, "no_slo", json!({})) };
    let key = match sp_key(app, p) {
        Ok(k) => k,
        Err(e) => {
            crate::obs::log::log_warn!("SSO {id}: can't answer a logout: {e}");
            return slo_failed(a, source, id, "no_sp_key", json!({}));
        }
    };
    let (slo_url, at) = (a.sso.slo_url(id), db::now());
    let decrypt = logout_decrypt_keys(app, p, *encryption);
    let keys: Vec<&SpKey> = decrypt.iter().map(|(_, k)| k.as_ref()).collect();
    let received = match saml_slo::receive(incoming, &saml_slo::Expect { idp: &idp, slo_url: &slo_url, now_ms: at, decrypt: &keys }) {
        Ok(r) => r,
        Err(Refused(reason, detail)) => return slo_failed(a, source, id, reason, json!({ "detail": detail })),
    };
    match received {
        saml_slo::Received::Request { id: request_id, name_id, session_indexes, relay, issued_ms, until_ms } => {
            if let Err(reason) = a.sso.first_use(&format!("slo|{}|{request_id}", idp.entity_id), until_ms, at) {
                return slo_failed(a, source, id, reason, json!({ "requestId": request_id }));
            }
            let binding = if matches!(incoming, saml_slo::Incoming::Redirect(_)) { "redirect" } else { "post" };
            idp_signed_out(a, app, source, id, &idp, &request_id, &name_id, &session_indexes, issued_ms, binding);
            let answer = saml_slo::logout_response(sp_entity_id, &saml_sp::request_id(), Some(&idp_slo.response), &request_id, at);
            let query = saml_sp::redirect_query("SAMLResponse", &answer, relay.as_deref(), Some(&key));
            // The browser's own cookie is left alone: its session may not be one the IdP named.
            no_store(see(&saml_sp::with_redirect_query(&idp_slo.response, &query)))
        }
        saml_slo::Received::Response { id: response_id, in_response_to, status, until_ms } => {
            if let Err(reason) = a.sso.first_use(&format!("slo|{}|{response_id}", idp.entity_id), until_ms, at) {
                return slo_failed(a, source, id, reason, json!({ "responseId": response_id }));
            }
            let pending = a.sso.logouts.lock().unwrap_or_else(|e| e.into_inner()).remove(&in_response_to);
            let Some(pending) = pending.filter(|l| l.expires > at && l.provider == id) else {
                return slo_failed(a, source, id, "unknown_request", json!({ "inResponseTo": in_response_to }));
            };
            let outcome = if status.is_none() { Outcome::Success } else { Outcome::Failure };
            let details = json!({ "provider": id, "idp": "saml", "requestId": in_response_to, "status": status.as_deref().unwrap_or("Success"), "binding": "redirect" });
            a.record(Who { actor: slo_actor(id, None), source: source.clone() }.event("auth.slo_response").target("session", &pending.session).outcome(outcome).details(details));
            no_store(see("/login"))
        }
    }
}

/// `POST /api/auth/sso/{id}/slo/soap`: the IdP's LogoutRequest over SOAP, server to server
/// (ADR 0208), checked as on the front channel except that only an enveloped signature can
/// sign it. The sessions it names are revoked, and the answer is our signed LogoutResponse in
/// the SOAP response. Refusals are SOAP faults. The IdP needs no SLO URL of its own for this.
pub async fn slo_soap(Extension(a): Extension<Arc<Auth>>, Extension(source): Extension<Source>, Path(id): Path<String>, body: axum::body::Bytes) -> Response {
    let (a, id) = (a.as_ref(), id.as_str());
    let Some(app) = a.app.as_ref() else { return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    let Some(p) = a.sso.provider(id).filter(|p| p.saml_sp()) else { return not_found("SAML provider").into_response() };
    let Kind::SamlSp { sp_entity_id, encryption, .. } = &p.kind else { return not_found("SAML provider").into_response() };
    let Ok(idp) = idp_metadata(a, p).await else { return soap_failed(a, &source, id, "not_ready", json!({})) };
    let key = match sp_key(app, p) {
        Ok(k) => k,
        Err(e) => {
            crate::obs::log::log_warn!("SSO {id}: can't answer a SOAP logout: {e}");
            return soap_failed(a, &source, id, "no_sp_key", json!({}));
        }
    };
    let Ok(xml) = std::str::from_utf8(&body) else { return soap_failed(a, &source, id, "bad_message", json!({})) };
    let (slo_url, at) = (a.sso.slo_soap_url(id), db::now());
    let decrypt = logout_decrypt_keys(app, p, *encryption);
    let keys: Vec<&SpKey> = decrypt.iter().map(|(_, k)| k.as_ref()).collect();
    let (request_id, name_id, session_indexes, issued_ms) = match saml_slo::receive(&saml_slo::Incoming::Soap(xml), &saml_slo::Expect { idp: &idp, slo_url: &slo_url, now_ms: at, decrypt: &keys }) {
        Ok(saml_slo::Received::Request { id: request_id, name_id, session_indexes, issued_ms, until_ms, .. }) => {
            if let Err(reason) = a.sso.first_use(&format!("slo|{}|{request_id}", idp.entity_id), until_ms, at) {
                return soap_failed(a, &source, id, reason, json!({ "requestId": request_id }));
            }
            (request_id, name_id, session_indexes, issued_ms)
        }
        Ok(saml_slo::Received::Response { .. }) => return soap_failed(a, &source, id, "bad_message", json!({})),
        Err(Refused(reason, detail)) => return soap_failed(a, &source, id, reason, json!({ "detail": detail })),
    };
    idp_signed_out(a, app, &source, id, &idp, &request_id, &name_id, &session_indexes, issued_ms, "soap");
    let answer_id = saml_sp::request_id();
    let answer = saml_slo::logout_response(sp_entity_id, &answer_id, None, &request_id, at);
    match key.sign_enveloped(&answer, &answer_id) {
        Ok(signed) => no_store(([(header::CONTENT_TYPE, "text/xml; charset=utf-8")], saml_slo::soap_envelope(&signed)).into_response()),
        Err(e) => {
            // The sessions are revoked: only the answer is missing.
            crate::obs::log::log_warn!("SSO {id}: can't answer a SOAP logout: {e}");
            no_store((StatusCode::INTERNAL_SERVER_ERROR, [(header::CONTENT_TYPE, "text/xml; charset=utf-8")], saml_slo::soap_fault("no_sp_key")).into_response())
        }
    }
}

fn slo_actor(provider: &str, subject: Option<String>) -> Actor {
    Actor { kind: ActorKind::User, subject, method: Some("sso".into()), idp: Some("saml".into()), idp_provider: Some(provider.into()), ..Default::default() }
}

/// The keys an `EncryptedID` in a logout message is decrypted with: those assertions are
/// encrypted to, when the provider has encryption on.
fn logout_decrypt_keys(app: &AppState, p: &Provider, encryption: Encryption) -> Vec<(Option<saml_keys::Stage>, Arc<SpKey>)> {
    match encryption {
        Encryption::Off => vec![],
        _ => decrypt_keys(app, p).map(|(k, _)| k).unwrap_or_else(|e| {
            crate::obs::log::log_warn!("SSO {}: can't decrypt logout NameIDs: {e}", p.id);
            vec![]
        }),
    }
}

/// The IdP signed `name_id` out, in the IdP sessions `session_indexes` (all, if none): revokes
/// the SuperBot sessions they made and drops their unredeemed app codes, then audits `auth.slo`
/// with the binding it came over (`redirect`, `post` or `soap`).
#[allow(clippy::too_many_arguments)]
fn idp_signed_out(a: &Auth, app: &AppState, source: &Source, id: &str, idp: &saml_sp::IdpMetadata, request_id: &str, name_id: &str, session_indexes: &[String], issued_ms: i64, binding: &str) {
    let subject = format!("{}|{}", idp.entity_id, saml::subject(name_id));
    let named = |l: Option<&db::SamlLogin>| session_indexes.is_empty() || l.and_then(|l| l.session_index.as_ref()).is_none_or(|i| session_indexes.contains(i));
    // Codes first, as when an admin revokes: a redemption holds them until its session exists.
    a.sso.handoffs.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, h| !(h.provider == id && h.claims.key() == subject && named(h.saml.as_ref())));
    // Only sessions from before the request was issued: replayed after a restart, which
    // forgets used IDs, it finds nothing left to revoke.
    let revoked = app.db.revoke_saml_sessions(id, &subject, session_indexes, issued_ms + saml_sp::SKEW_MS, "saml_logout");
    let mut users: Vec<&str> = revoked.iter().map(|s| s.user_id.as_str()).collect();
    users.sort_unstable();
    users.dedup();
    let sessions: Vec<&str> = revoked.iter().map(|s| s.id.as_str()).collect();
    let details = json!({
        "provider": id, "idp": "saml", "issuer": idp.entity_id, "subject": saml::subject(name_id), "requestId": request_id,
        "sessionIndexes": session_indexes, "sessions": sessions, "users": users, "revoked": sessions.len(), "binding": binding,
    });
    let mut actor = slo_actor(id, Some(subject.clone()));
    actor.id = (users.len() == 1).then(|| users[0].to_string());
    a.record(Who { actor, source: source.clone() }.event("auth.slo").details(details));
}

/// The IdP metadata, auditing metadata from the URL refused for its signature or validity,
/// also when the last good copy is used instead.
async fn idp_metadata(a: &Auth, p: &Provider) -> Result<Arc<saml_sp::IdpMetadata>, jwt::Invalid> {
    let m = p.idp_metadata(a.sso.http(), a.sso.refresh_gap).await;
    audit_metadata_refusal(a, p);
    m
}

fn audit_metadata_refusal(a: &Auth, p: &Provider) {
    if let Some(e) = p.take_metadata_refusal() {
        a.record(metadata_refused(p, &e));
    }
}

/// `sso.saml_metadata_refused`: IdP metadata whose signature or validity didn't hold (ADR 0151).
/// The metadata loaded before, if any, stays in use.
fn metadata_refused(p: &Provider, e: &saml_sp::MetadataRefused) -> Event {
    let source = match &p.kind {
        Kind::SamlSp { source, .. } => source.name(),
        _ => "",
    };
    let details = json!({ "provider": p.id, "source": source, "reason": e.reason, "error": crate::audit::clip(&e.message, 256), "kept": p.idp_loaded().is_some() });
    Event::new(Actor::system("sso"), "sso.saml_metadata_refused").target("sso_provider", &p.id).outcome(Outcome::Failure).details(details)
}

fn saml_provider<'a>(a: &'a Auth, id: &str) -> Result<&'a Arc<Provider>, ApiError> {
    a.sso.provider(id).filter(|p| p.saml_sp()).ok_or_else(|| {
        let native: Vec<&str> = a.sso.providers.iter().filter(|p| p.saml_sp()).map(|p| p.id.as_str()).collect();
        bad(if native.is_empty() { "No native SAML provider: set SSO_<ID>_TYPE=saml and SSO_<ID>_IDP_ENTITY_ID".to_string() } else { format!("provider must be one of: {}", native.join(", ")) })
    })
}

fn saml_view(a: &Auth, p: &Provider) -> Value {
    let Kind::SamlSp { entity_id, sp_entity_id, source, attributes, required_groups, sign_requests, sp_cert, encryption, aes_cbc, enc_cert, metadata_trust, idp_initiated, authn_context, freshness, .. } = &p.kind else {
        return json!({});
    };
    let now = db::now();
    // Each certificate says whether it's ending (ADR 0198).
    let cert = |c: &xmldsig::Cert| {
        json!({ "sha256": c.sha256, "subject": c.subject, "notAfter": c.not_after * 1000, "expiry": saml_expiry::state(c.not_after, now).as_str(), "daysLeft": saml_expiry::days_left(c.not_after, now) })
    };
    let idp = p.idp_loaded().map(|m| {
        let certs: Vec<Value> = m.certs.iter().map(cert).collect();
        json!({ "entityId": m.entity_id, "ssoUrl": m.sso_url, "sloUrl": m.slo.as_ref().map(|s| &s.location), "sloSoapUrl": m.slo_soap, "certificates": certs, "loadedSecondsAgo": p.idp_age().map(|d| d.as_secs()) })
    });
    let key = a.app.as_ref().map(|app| sp_key(app, p));
    // botd's own keys show their rollover too (ADR 0181).
    let rollover = |v: &mut Value, u: KeyUse| {
        use saml_keys::Stage;
        let Some(app) = a.app.as_ref().filter(|_| p.sp_cert_for(u).is_none()) else { return };
        let Ok(h) = saml_keys::held(app, p, u) else { return };
        // From the same keys as the rest, should a promotion land between the two reads.
        v["certificate"] = cert(&h.current.info);
        v["next"] = saml_keys::view(&h, u, Stage::Next, now, cert);
        if u == KeyUse::Encryption {
            v["previous"] = saml_keys::view(&h, u, Stage::Previous, now, cert);
            v["lastUsedSecondsAgo"] = saml_keys::view(&h, u, Stage::Current, now, cert)["lastUsedSecondsAgo"].clone();
        }
    };
    let sp_key = match &key {
        Some(Ok(k)) => {
            let mut v = json!({ "certificate": cert(&k.info), "from": if sp_cert.is_some() { "secret" } else { "generated" } });
            rollover(&mut v, KeyUse::Signing);
            v
        }
        Some(Err(e)) => json!({ "problem": e }),
        None => Value::Null,
    };
    let enc_key = match (encryption, a.app.as_ref()) {
        (Encryption::Off, _) | (_, None) => Value::Null,
        (_, Some(app)) => match sp_encryption_key(app, p) {
            Ok(k) => {
                let mut v = json!({ "certificate": cert(&k.info), "from": if enc_cert.is_some() { "secret" } else { "generated" } });
                rollover(&mut v, KeyUse::Encryption);
                v
            }
            Err(e) => json!({ "problem": e }),
        },
    };
    let slo = p.idp_loaded().is_some_and(|m| m.slo.is_some()) && matches!(key, Some(Ok(_)));
    // Signing out where there's no browser reaches the IdP only over its SOAP URL (ADR 0208).
    let back_channel = p.idp_loaded().is_some_and(|m| m.slo_soap.is_some()) && matches!(key, Some(Ok(_)));
    let from = match source {
        IdpSource::Url(u) => Some(u.clone()),
        IdpSource::File(f) => Some(f.clone()),
        IdpSource::Saved => None,
    };
    json!({
        "provider": p.id, "label": p.label, "ready": p.ready(), "problem": p.not_ready(),
        "spEntityId": sp_entity_id, "acsUrl": a.sso.acs_url(&p.id), "metadataUrl": a.sso.sp_metadata_url(&p.id),
        "sloUrl": a.sso.slo_url(&p.id), "signRequests": sign_requests, "spKey": sp_key, "singleLogout": slo,
        "sloSoapUrl": a.sso.slo_soap_url(&p.id), "backChannelLogout": back_channel,
        "encryptedAssertions": encryption.as_str(), "aesCbc": aes_cbc.as_str(), "spEncryptionKey": enc_key,
        "signedMetadata": metadata_trust.as_ref().map_or("off", |t| if t.require { "require" } else { "allow" }),
        "metadataSigningCertificates": metadata_trust.as_ref().map(|t| t.certs.iter().map(cert).collect::<Vec<_>>()),
        "idpEntityId": entity_id, "source": source.name(), "from": from, "idp": idp,
        "audience": p.audience(), "jitRole": p.jit_role.map(Role::as_str),
        "groupsAttribute": attributes.groups, "requiredGroups": required_groups,
        "roleMappings": a.app.as_ref().map(|app| app.db.saml_role_mappings_of(&p.id).len()),
        "idpInitiated": idp_initiated.as_str(),
        "authnContext": authn_context.as_ref().map(|c| json!({ "required": c.accepted, "methodsAttribute": attributes.authn_methods, "requested": c.request })),
        "forceAuthn": freshness.force_authn, "maxAuthnAgeSeconds": freshness.max_authn_age_ms.map(|ms| ms / 1000), "idpSessionLimit": freshness.idp_session_limit,
        "certificateWarnings": a.app.as_ref().map_or_else(Vec::new, |app| saml_expiry::warnings(app, p, now)),
    })
}

/// `GET /api/sso/{id}/saml`: what to enter at the IdP, and the IdP metadata in use.
pub async fn saml_status(Extension(a): Extension<Arc<Auth>>, Path(id): Path<String>) -> Res {
    let p = saml_provider(&a, &id)?;
    if matches!(&p.kind, Kind::SamlSp { source: IdpSource::Url(_), .. })
        && let Err(e) = idp_metadata(&a, p).await
    {
        crate::obs::log::log_warn!("SSO {id}: IdP metadata: {e}");
    }
    Ok(Json(saml_view(&a, p)))
}

/// `PUT /api/sso/{id}/saml/idp-metadata {xml}`: imports the IdP's metadata (botctl), when
/// it isn't set in `.env`. Checked before it's kept: it must be for `IDP_ENTITY_ID`.
pub async fn saml_import(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    let p = saml_provider(&a, &id)?;
    let Kind::SamlSp { entity_id, source, sign_requests, metadata_trust, .. } = &p.kind else {
        return Err(bad("not a native SAML provider"));
    };
    if *source != IdpSource::Saved {
        let var = if matches!(source, IdpSource::Url(_)) { "IDP_METADATA_URL" } else { "IDP_METADATA_FILE" };
        return Err(ApiError(StatusCode::CONFLICT, format!("SSO_{}_{var} sets this provider's IdP metadata. Change it there, or remove it to import here.", id.to_ascii_uppercase())));
    }
    let xml = v["xml"].as_str().unwrap_or("");
    let m = match saml_sp::load_idp_metadata(xml, entity_id, *sign_requests, metadata_trust.as_ref(), db::now()) {
        Ok(m) => m,
        Err(e) => {
            if e.untrusted() {
                app.db.record(&by.event("sso.saml_metadata_refused").target("sso_provider", &p.id).outcome(Outcome::Failure).details(json!({
                    "provider": p.id, "source": "botctl", "reason": e.reason, "error": crate::audit::clip(&e.message, 256), "kept": p.idp_loaded().is_some(),
                })));
            }
            return Err(bad(format!("That IdP metadata can't be used: {e}.")));
        }
    };
    let certs: Vec<&str> = m.certs.iter().map(|c| c.sha256.as_str()).collect();
    let details = json!({ "provider": p.id, "entityId": m.entity_id, "ssoUrl": m.sso_url, "certificates": certs });
    app.db.set_setting(&format!("{SAML_METADATA_SETTING}{id}"), xml);
    p.set_idp(m);
    app.db.record(&by.event("sso.saml_metadata_imported").target("sso_provider", &p.id).details(details));
    Ok(Json(saml_view(&a, p)))
}

/// A step in rolling over one of botd's own SP keys (ADR 0181), then the provider as
/// `GET /api/sso/{id}/saml` shows it. `use` is `signing` or `encryption`.
fn saml_key_change(app: &AppState, a: &Auth, by: &Who, id: &str, u: &str, c: saml_keys::Change) -> Res {
    let p = saml_provider(a, id)?;
    let u = match u {
        "signing" => KeyUse::Signing,
        "encryption" => KeyUse::Encryption,
        _ => return Err(bad("the key must be signing or encryption")),
    };
    saml_keys::change(app, p, u, c, by)?;
    Ok(Json(saml_view(a, p)))
}

/// `POST /api/sso/{id}/saml/keys/{use}/next`: makes a next key, published beside the one in use.
pub async fn saml_key_next(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path((id, u)): Path<(String, String)>) -> Res {
    saml_key_change(&app, &a, &by, &id, &u, saml_keys::Change::Next)
}

/// `POST /api/sso/{id}/saml/keys/{use}/promote`: puts the next key in use.
pub async fn saml_key_promote(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path((id, u)): Path<(String, String)>) -> Res {
    saml_key_change(&app, &a, &by, &id, &u, saml_keys::Change::Promote)
}

/// `DELETE /api/sso/{id}/saml/keys/{use}/next`: drops a next key that wasn't promoted.
pub async fn saml_key_cancel(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path((id, u)): Path<(String, String)>) -> Res {
    saml_key_change(&app, &a, &by, &id, &u, saml_keys::Change::Cancel)
}

/// `DELETE /api/sso/{id}/saml/keys/{use}/previous`: retires the encryption key a promotion replaced.
pub async fn saml_key_retire(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path((id, u)): Path<(String, String)>) -> Res {
    saml_key_change(&app, &a, &by, &id, &u, saml_keys::Change::Retire)
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
    // A code outliving the IdP's session limit (ADR 0225) makes no session.
    let h = h.filter(|h| h.expires > at && h.lifetime.ends.is_none_or(|e| e > at) && crate::same(s256(verifier).as_bytes(), h.challenge.as_bytes()));
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
    let (s, token) = users::start_session_ending(a, &user, "sso", Some((&h.provider, &h.claims.key())), None, cookie, label, &source, h.lifetime.ends);
    if let Some(l) = &h.saml {
        app.db.add_saml_session(&s.id, l);
    }
    drop(handoffs);
    signed_in(a, &user, &s, &h.provider, &h.claims, &h.lifetime, &source);
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

/// `DELETE /api/users/{key}/identities/{id}`. The user's sessions stay; revoke them
/// separately. A role a SAML group gave them through that provider goes (ADR 0160).
pub async fn unlink_identity(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path((key, id)): Path<(String, String)>) -> Res {
    let u = users::need_user_key(&app, &key)?;
    let i = app.db.unlink_identity(&u.id, &id).ok_or_else(|| not_found("Identity"))?;
    app.db.record(&by.event("user.identity_unlinked").target("user", &u.id).details(json!({ "identity": i.id, "provider": i.provider, "issuer": i.issuer, "subject": i.subject })));
    saml_roles::unlinked(&app, &a, &by, &u.id, &i.provider).await;
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
    }

    /// SOC 2 CC6.2-1: no provider makes accounts just in time without a list of who may have one.
    #[test]
    fn every_type_refuses_just_in_time_without_an_allow_list() {
        let okta = [("SSO_PROVIDERS", "okta"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_OKTA_TYPE", "oidc"), ("SSO_OKTA_ISSUER", "https://acme.okta.example"), ("SSO_OKTA_CLIENT_ID", "c1")];
        let oidc = |extra: &[(&'static str, &'static str)]| with_base(&okta, extra);
        type Case = (&'static str, fn(&[(&'static str, &'static str)]) -> Result<Sso, String>, Vec<(&'static str, &'static str)>, &'static str, Vec<(&'static str, &'static str)>);
        let cases: [Case; 5] = [
            ("google", google, vec![("SSO_GOOGLE_JIT_ROLE", "member")], "SSO_GOOGLE_HOSTED_DOMAINS", vec![("SSO_GOOGLE_HOSTED_DOMAINS", "example.com")]),
            ("apple", apple, vec![("SSO_APPLE_JIT_ROLE", "member")], "SSO_APPLE_ALLOWED_DOMAINS", vec![("SSO_APPLE_ALLOWED_DOMAINS", "example.com")]),
            ("github", github, vec![("SSO_GITHUB_JIT_ROLE", "member")], "SSO_GITHUB_ALLOWED_ORGS", vec![("SSO_GITHUB_ALLOWED_ORGS", "acme")]),
            ("saml", saml, vec![("SSO_ADFS_JIT_ROLE", "member")], "SSO_ADFS_ALLOWED_DOMAINS", vec![("SSO_ADFS_ALLOWED_DOMAINS", "example.com")]),
            ("entra organizations", entra, vec![("SSO_ENTRA_JIT_ROLE", "member"), ("SSO_ENTRA_TENANT", "organizations")], "SSO_ENTRA_ALLOWED_TENANTS", vec![("SSO_ENTRA_ALLOWED_TENANTS", "22222222-2222-2222-2222-222222222222")]),
        ];
        for (name, build, jit, key, allow) in cases {
            let err = build(&jit).err().unwrap_or_else(|| panic!("{name}: just in time with no allow-list was accepted"));
            assert!(err.contains(key), "{name}: the error names {key}: {err}");
            let ok = build(&[jit.as_slice(), allow.as_slice()].concat()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(ok.providers[0].jit_role, Some(Role::Member), "{name}");
        }
        let err = oidc(&[("SSO_OKTA_JIT_ROLE", "member")]).err().expect("oidc: just in time with no allow-list was accepted");
        assert!(err.contains("SSO_OKTA_JIT_ROLE") && err.contains("SSO_OKTA_ALLOWED_DOMAINS") && err.contains("okta"), "{err}");
        let ok = oidc(&[("SSO_OKTA_JIT_ROLE", "admin"), ("SSO_OKTA_ALLOWED_DOMAINS", "example.com")]).unwrap();
        assert_eq!((ok.providers[0].jit_role, ok.providers[0].audience()), (Some(Role::Admin), "verified emails at example.com".to_string()));
        let err = saml(&[("SSO_ADFS_JIT_ROLE", "readonly")]).err().expect("saml: just in time with no allow-list was accepted");
        assert!(err.contains("SSO_ADFS_JIT_ROLE") && err.contains(ADFS), "the error names the SAML IdP: {err}");

        // Entra pinned to one tenant: the tenant is the allow-list.
        let pinned = entra(&[("SSO_ENTRA_JIT_ROLE", "member")]).unwrap();
        assert_eq!((pinned.providers[0].jit_role, pinned.providers[0].audience()), (Some(Role::Member), format!("tenant {T1}")));
        assert!(entra(&[("SSO_ENTRA_JIT_ROLE", "member"), ("SSO_ENTRA_TENANT", "common")]).is_err());

        // Without just in time, an admin links each person, so no list is needed.
        assert!(oidc(&[]).is_ok() && saml(&[]).is_ok() && google(&[]).is_ok() && github(&[]).is_ok() && apple(&[]).is_ok());
        assert!(oidc(&[("SSO_OKTA_JIT_ROLE", "off")]).is_ok() && saml(&[("SSO_ADFS_JIT_ROLE", "off")]).is_ok());
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

    fn native(extra: &[(&'static str, &'static str)]) -> Result<Sso, String> {
        let base = [("SSO_PROVIDERS", "corp"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_CORP_TYPE", "saml"), ("SSO_CORP_IDP_ENTITY_ID", ADFS)];
        with_base(&base, extra)
    }

    #[test]
    fn reads_a_native_saml_provider_without_a_broker_or_secret() {
        let s = native(&[]).unwrap();
        let p = s.provider("corp").unwrap();
        assert!(p.saml_sp() && !p.oidc() && !p.needs_secret());
        assert_eq!((p.type_name(), p.jit_role), ("saml", None), "audited as idp=saml, like the bridge");
        assert!(matches!(&p.kind, Kind::SamlSp { entity_id, sp_entity_id, source: IdpSource::Saved, attributes, required_groups, allowed_domains, sign_requests: false, sp_cert: None, encryption: Encryption::Off, aes_cbc: AesCbc::Off, enc_cert: None, metadata_trust: None, idp_initiated: IdpInitiated::Off, authn_context: None, freshness }
            if *freshness == saml_sp::Freshness::default() && entity_id == ADFS && sp_entity_id == "https://bot.example.com/api/auth/sso/corp/metadata" && attributes.email.is_none() && attributes.groups.is_none() && required_groups.is_empty() && allowed_domains.is_empty()));
        assert_eq!((p.env_var(), s.slo_url("corp")), ("SSO_CORP_PRIVATE_KEY".to_string(), "https://bot.example.com/api/auth/sso/corp/slo".to_string()));
        assert_eq!(s.callback_url("corp"), "https://bot.example.com/api/auth/sso/corp/acs");
        assert!(p.not_ready().unwrap().contains("botctl sso saml corp import"), "not offered until its metadata is imported");
        assert_eq!(p.issuer_for(None).unwrap(), (ADFS.to_string(), None));
        assert_eq!(p.subject(" 00u1ADA ").unwrap(), "00u1ada", "the same subjects as the bridge, so links carry over");

        let s = native(&[
            ("SSO_CORP_IDP_METADATA_URL", "https://idp.example/metadata"),
            ("SSO_CORP_SP_ENTITY_ID", "urn:superbot:corp"),
            ("SSO_CORP_EMAIL_ATTRIBUTE", "mail"),
            ("SSO_CORP_ALLOWED_DOMAINS", "example.com"),
            ("SSO_CORP_JIT_ROLE", "member"),
        ])
        .unwrap();
        let p = &s.providers[0];
        assert!(matches!(&p.kind, Kind::SamlSp { sp_entity_id, source: IdpSource::Url(u), attributes, .. }
            if sp_entity_id == "urn:superbot:corp" && u == "https://idp.example/metadata" && attributes.email.as_deref() == Some("mail")));
        assert_eq!(p.jit_role, Some(Role::Member));
        assert_eq!(p.check_email(Some("ada@example.com")), Ok(()));
        assert!(p.check_email(Some("eve@evil.example")).is_err() && p.check_email(None).is_err());
    }

    #[test]
    fn refuses_native_saml_settings_that_are_missing_or_mixed() {
        for (vars, why) in [
            (vec![("SSO_CORP_IDP_ENTITY_ID", "")], "no entity id"),
            (vec![("SSO_CORP_IDP_METADATA_URL", "http://idp.example/metadata")], "metadata over plain http"),
            (vec![("SSO_CORP_IDP_METADATA_URL", "https://idp.example/m"), ("SSO_CORP_IDP_METADATA_FILE", "/x.xml")], "two metadata sources"),
            (vec![("SSO_CORP_IDP_METADATA_FILE", "/nonexistent/idp.xml")], "an unreadable file"),
            (vec![("SSO_CORP_JIT_ROLE", "member")], "just in time with no allow-list"),
            (vec![("SSO_CORP_CLIENT_ID", "superbot")], "a bridge setting"),
            (vec![("SSO_CORP_IDP_ALIAS", "adfs")], "a bridge setting"),
            (vec![("SSO_CORP_EMAIL_CLAIM", "email")], "a bridge setting"),
            (vec![("SSO_CORP_TENANT", T1)], "an Entra setting"),
            (vec![("SSO_CORP_SIGN_REQUESTS", "yes")], "not true or false"),
            (vec![("SSO_CORP_SP_CERT_FILE", "/nonexistent/sp.pem")], "an unreadable certificate"),
        ] {
            assert!(native(&vars).is_err(), "{why}");
        }
        assert!(saml(&[("SSO_ADFS_IDP_METADATA_URL", "https://idp.example/m")]).is_err(), "a native setting on the bridge");
        assert!(saml(&[("SSO_ADFS_SP_ENTITY_ID", "urn:x")]).is_err());
        assert!(saml(&[("SSO_ADFS_SIGN_REQUESTS", "true")]).is_err(), "Keycloak signs the bridge's requests");
    }

    #[test]
    fn reads_the_idp_initiated_policy() {
        let idp_initiated = |s: &Sso| match &s.providers[0].kind {
            Kind::SamlSp { idp_initiated, .. } => *idp_initiated,
            _ => unreachable!(),
        };
        assert_eq!(idp_initiated(&native(&[]).unwrap()), IdpInitiated::Off, "off by default");
        assert_eq!(idp_initiated(&native(&[("SSO_CORP_IDP_INITIATED", "Restart")]).unwrap()), IdpInitiated::Restart);
        assert_eq!(idp_initiated(&native(&[("SSO_CORP_IDP_INITIATED", "off")]).unwrap()), IdpInitiated::Off);
        let e = native(&[("SSO_CORP_IDP_INITIATED", "allow")]).err().unwrap();
        assert!(e.contains("SSO_CORP_IDP_INITIATED must be off or restart"), "{e}");
        assert!(saml(&[("SSO_ADFS_IDP_INITIATED", "restart")]).is_err(), "the broker handles the bridge's");
        let e = with_base(&[("SSO_PROVIDERS", "corp"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_CORP_TYPE", "oidc"), ("SSO_CORP_ISSUER", "https://idp.example"), ("SSO_CORP_CLIENT_ID", "x")], &[("SSO_CORP_IDP_INITIATED", "restart")]).err().unwrap();
        assert!(e.contains("only for SSO_CORP_TYPE=saml"), "{e}");
    }

    #[test]
    fn reads_the_group_settings_and_refuses_unclear_ones() {
        let s = native(&[("SSO_CORP_GROUPS_ATTRIBUTE", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"), ("SSO_CORP_REQUIRED_GROUPS", "SuperBot Users, Admins ,SuperBot Users")]).unwrap();
        assert!(matches!(&s.providers[0].kind, Kind::SamlSp { attributes, required_groups, .. }
            if attributes.groups.as_deref() == Some("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups") && required_groups == &["SuperBot Users", "Admins"]));
        let s = native(&[("SSO_CORP_GROUPS_ATTRIBUTE", "groups")]).unwrap();
        assert!(matches!(&s.providers[0].kind, Kind::SamlSp { attributes, required_groups, .. } if attributes.groups.as_deref() == Some("groups") && required_groups.is_empty()), "groups read, nobody kept out");
        let long: &'static str = "g".repeat(saml_sp::MAX_GROUP_LEN + 1).leak();
        for (vars, why) in [
            (vec![("SSO_CORP_REQUIRED_GROUPS", "Admins")], "required groups with no attribute to read them from"),
            (vec![("SSO_CORP_GROUPS_ATTRIBUTE", "my groups")], "not an attribute name"),
            (vec![("SSO_CORP_GROUPS_ATTRIBUTE", "groups"), ("SSO_CORP_REQUIRED_GROUPS", long)], "a group longer than is ever read"),
            (vec![("SSO_CORP_GROUPS_ATTRIBUTE", "groups"), ("SSO_CORP_REQUIRED_GROUPS", "Admins\u{7}")], "a control character"),
        ] {
            assert!(native(&vars).is_err(), "{why}");
        }
        assert!(saml(&[("SSO_ADFS_GROUPS_ATTRIBUTE", "groups")]).is_err(), "native only: the bridge doesn't pass groups");
        assert!(entra(&[("SSO_ENTRA_REQUIRED_GROUPS", "Admins")]).is_err(), "SAML only");
    }

    #[test]
    fn reads_the_authn_context_settings_and_refuses_unclear_ones() {
        const MFA: &str = "http://schemas.microsoft.com/claims/multipleauthn";
        let required = |s: &Sso| match &s.providers[0].kind {
            Kind::SamlSp { authn_context, attributes, .. } => (authn_context.clone(), attributes.authn_methods.clone()),
            _ => unreachable!(),
        };
        assert_eq!(required(&native(&[]).unwrap()), (None, None), "nothing required by default");
        let s = native(&[("SSO_CORP_AUTHN_CONTEXT", "http://schemas.microsoft.com/claims/multipleauthn, urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract ,http://schemas.microsoft.com/claims/multipleauthn")]).unwrap();
        let (c, m) = required(&s);
        assert_eq!(c.unwrap(), saml_sp::AuthnContext { accepted: vec![MFA.into(), "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract".into()], request: false }, "in order, each once, not requested by default");
        assert_eq!(m, None);
        let s = native(&[("SSO_CORP_AUTHN_CONTEXT", "mfa"), ("SSO_CORP_AUTHN_METHODS_ATTRIBUTE", "amr"), ("SSO_CORP_REQUEST_AUTHN_CONTEXT", "True")]).unwrap();
        let (c, m) = required(&s);
        assert_eq!((c.unwrap().request, m.as_deref()), (true, Some("amr")));
        assert!(!required(&native(&[("SSO_CORP_AUTHN_CONTEXT", MFA), ("SSO_CORP_REQUEST_AUTHN_CONTEXT", "false")]).unwrap()).0.unwrap().request);
        let many: &'static str = (0..=saml_sp::MAX_AUTHN_CONTEXTS).map(|i| format!("urn:c{i}")).collect::<Vec<_>>().join(",").leak();
        for (vars, why) in [
            (vec![("SSO_CORP_AUTHN_METHODS_ATTRIBUTE", "amr")], "a methods attribute with nothing to require"),
            (vec![("SSO_CORP_REQUEST_AUTHN_CONTEXT", "true")], "asking for nothing"),
            (vec![("SSO_CORP_REQUEST_AUTHN_CONTEXT", "false")], "a setting that looks like a check, without one"),
            (vec![("SSO_CORP_AUTHN_CONTEXT", MFA), ("SSO_CORP_REQUEST_AUTHN_CONTEXT", "yes")], "not true or false"),
            (vec![("SSO_CORP_AUTHN_CONTEXT", "multi factor")], "not a URI or token"),
            (vec![("SSO_CORP_AUTHN_CONTEXT", many)], "too many"),
            (vec![("SSO_CORP_AUTHN_CONTEXT", MFA), ("SSO_CORP_AUTHN_METHODS_ATTRIBUTE", "my methods")], "not an attribute name"),
        ] {
            assert!(native(&vars).is_err(), "{why}");
        }
        let e = native(&[("SSO_CORP_AUTHN_METHODS_ATTRIBUTE", "amr")]).err().unwrap();
        assert!(e.contains("SSO_CORP_AUTHN_METHODS_ATTRIBUTE needs SSO_CORP_AUTHN_CONTEXT"), "{e}");
        assert!(saml(&[("SSO_ADFS_AUTHN_CONTEXT", MFA)]).is_err(), "native only: the broker decides how people sign in");
        assert!(entra(&[("SSO_ENTRA_AUTHN_CONTEXT", MFA)]).is_err(), "SAML only");
    }

    #[test]
    fn reads_how_fresh_a_sign_in_must_be_and_refuses_unclear_settings() {
        let freshness = |s: &Sso| match &s.providers[0].kind {
            Kind::SamlSp { freshness, .. } => freshness.clone(),
            _ => unreachable!(),
        };
        let f = freshness(&native(&[]).unwrap());
        assert_eq!(f, saml_sp::Freshness { force_authn: false, max_authn_age_ms: None, idp_session_limit: true }, "the IdP's session limit holds by default");
        assert!(freshness(&native(&[("SSO_CORP_FORCE_AUTHN", "True")]).unwrap()).force_authn);
        assert_eq!(freshness(&native(&[("SSO_CORP_MAX_AUTHN_AGE", "8h")]).unwrap()).max_authn_age_ms, Some(8 * 3_600_000));
        assert_eq!(freshness(&native(&[("SSO_CORP_MAX_AUTHN_AGE", " ")]).unwrap()).max_authn_age_ms, None, "empty is unset, not zero");
        assert!(!freshness(&native(&[("SSO_CORP_IDP_SESSION_LIMIT", "OFF")]).unwrap()).idp_session_limit);
        for (vars, why) in [
            (vec![("SSO_CORP_FORCE_AUTHN", "yes")], "not true or false"),
            (vec![("SSO_CORP_IDP_SESSION_LIMIT", "false")], "not on or off"),
            (vec![("SSO_CORP_MAX_AUTHN_AGE", "1m")], "shorter than a sign-in takes"),
            (vec![("SSO_CORP_MAX_AUTHN_AGE", "8 hours")], "not a duration"),
            (vec![("SSO_CORP_MAX_AUTHN_AGE", "400d")], "longer than a year"),
        ] {
            assert!(native(&vars).is_err(), "{why}");
        }
        let e = native(&[("SSO_CORP_FORCE_AUTHN", "true"), ("SSO_CORP_MAX_AUTHN_AGE", "1h")]).err().unwrap();
        assert!(e.contains("SSO_CORP_FORCE_AUTHN already asks for a new sign-in every time") && e.contains("remove one of them"), "{e}");
        for k in ["FORCE_AUTHN", "MAX_AUTHN_AGE", "IDP_SESSION_LIMIT"] {
            let v = if k == "MAX_AUTHN_AGE" { "1h" } else if k == "IDP_SESSION_LIMIT" { "off" } else { "true" };
            assert!(saml(&[(format!("SSO_ADFS_{k}").leak(), v)]).is_err(), "{k}: native only, the broker keeps its own session");
            assert!(entra(&[(format!("SSO_ENTRA_{k}").leak(), v)]).is_err(), "{k}: SAML only");
        }
    }

    #[test]
    fn reads_the_sp_signing_settings() {
        let s = native(&[("SSO_CORP_SIGN_REQUESTS", "TRUE")]).unwrap();
        assert!(matches!(&s.providers[0].kind, Kind::SamlSp { sign_requests: true, sp_cert: None, .. }));

        let dir = std::env::temp_dir().join(format!("superbot-sp-cert-{}", random_hex()));
        std::fs::create_dir_all(&dir).unwrap();
        let (key, _) = SpKey::generate("test").unwrap();
        let (good, junk) = (dir.join("sp.pem"), dir.join("junk.pem"));
        std::fs::write(&good, format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", key.cert)).unwrap();
        std::fs::write(&junk, "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n").unwrap();
        let leak = |p: &std::path::Path| -> &'static str { Box::leak(p.to_string_lossy().into_owned().into_boxed_str()) };
        let s = native(&[("SSO_CORP_SP_CERT_FILE", leak(&good)), ("SSO_CORP_IDP_METADATA_URL", "https://idp.example/metadata")]).unwrap();
        let p = &s.providers[0];
        assert!(matches!(&p.kind, Kind::SamlSp { sp_cert: Some(c), .. } if *c == key.cert));
        assert!(p.not_ready().is_some_and(|n| n.contains("SSO_CORP_PRIVATE_KEY")), "the key is the provider's secret: {:?}", p.not_ready());
        assert!(native(&[("SSO_CORP_SP_CERT_FILE", leak(&junk))]).is_err(), "not a certificate");

        // A key that isn't the certificate's keeps it off offer; the right one makes it ready.
        let id = format!("spk{}", random_hex());
        let up = id.to_ascii_uppercase();
        let var = |k: &str| -> &'static str { Box::leak(format!("SSO_{up}_{k}").into_boxed_str()) };
        let vars = [
            ("SSO_PROVIDERS", leak(std::path::Path::new(&id))),
            ("SSO_PUBLIC_URL", "https://bot.example.com"),
            (var("TYPE"), "saml"),
            (var("IDP_ENTITY_ID"), ADFS),
            (var("IDP_METADATA_URL"), "https://idp.example/metadata"),
            (var("SP_CERT_FILE"), leak(&good)),
        ];
        let s = parse(&vars).unwrap();
        let p = &s.providers[0];
        let pem = |der: &[u8]| rcgen::KeyPair::try_from(der).unwrap().serialize_pem();
        let (_, other) = SpKey::generate("other").unwrap();
        crate::secrets::global().put(var("PRIVATE_KEY"), &pem(&other)).unwrap();
        assert!(p.not_ready().is_some_and(|n| n.contains("isn't for the SP key")), "{:?}", p.not_ready());
        let (mine, der) = SpKey::generate("mine").unwrap();
        std::fs::write(&good, format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", mine.cert)).unwrap();
        let s = parse(&vars).unwrap();
        let p = &s.providers[0];
        crate::secrets::global().put(var("PRIVATE_KEY"), &pem(&der)).unwrap();
        assert_eq!(p.not_ready(), None);
        assert_eq!(p.configured_sp_key(KeyUse::Signing).unwrap().info.sha256, mine.info.sha256);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reads_the_encrypted_assertion_settings() {
        assert!(matches!(&native(&[]).unwrap().providers[0].kind, Kind::SamlSp { encryption: Encryption::Off, enc_cert: None, .. }), "off unless asked");
        for (v, want) in [("allow", Encryption::Allow), ("REQUIRE", Encryption::Require), ("off", Encryption::Off)] {
            let s = native(&[("SSO_CORP_ENCRYPTED_ASSERTIONS", v)]).unwrap();
            assert!(matches!(&s.providers[0].kind, Kind::SamlSp { encryption, enc_cert: None, .. } if *encryption == want), "{v}");
        }
        assert!(native(&[("SSO_CORP_ENCRYPTED_ASSERTIONS", "true")]).err().unwrap().contains("off, allow, or require"));
        assert!(saml(&[("SSO_ADFS_ENCRYPTED_ASSERTIONS", "allow")]).is_err(), "the bridge decrypts in Keycloak");

        // AES-CBC in signed responses (ADR 0218): off unless asked, and only with encryption on.
        let aes_cbc = |s: &Sso| match &s.providers[0].kind {
            Kind::SamlSp { aes_cbc, .. } => *aes_cbc,
            _ => unreachable!(),
        };
        assert_eq!(aes_cbc(&native(&[("SSO_CORP_ENCRYPTED_ASSERTIONS", "require")]).unwrap()), AesCbc::Off);
        for v in ["signed-response", "Signed-Response"] {
            assert_eq!(aes_cbc(&native(&[("SSO_CORP_ENCRYPTED_ASSERTIONS", "allow"), ("SSO_CORP_AES_CBC", v)]).unwrap()), AesCbc::SignedResponse, "{v}");
        }
        assert_eq!(aes_cbc(&native(&[("SSO_CORP_AES_CBC", "off")]).unwrap()), AesCbc::Off, "off needs nothing else");
        let err = native(&[("SSO_CORP_ENCRYPTED_ASSERTIONS", "allow"), ("SSO_CORP_AES_CBC", "true")]).err().unwrap();
        assert!(err.contains("SSO_CORP_AES_CBC must be off or signed-response"), "{err}");
        let err = native(&[("SSO_CORP_AES_CBC", "signed-response")]).err().unwrap();
        assert!(err.contains("SSO_CORP_AES_CBC is only for SSO_CORP_ENCRYPTED_ASSERTIONS=allow or require"), "{err}");
        assert!(saml(&[("SSO_ADFS_AES_CBC", "signed-response")]).is_err(), "native SAML only");

        let dir = std::env::temp_dir().join(format!("superbot-sp-enc-{}", random_hex()));
        std::fs::create_dir_all(&dir).unwrap();
        let (sign, _) = SpKey::generate("sign").unwrap();
        let (enc, enc_der) = SpKey::generate("enc").unwrap();
        let (sign_pem, enc_pem) = (dir.join("sign.pem"), dir.join("enc.pem"));
        let write = |p: &std::path::Path, k: &SpKey| std::fs::write(p, format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", k.cert)).unwrap();
        write(&sign_pem, &sign);
        write(&enc_pem, &enc);
        let leak = |p: &std::path::Path| -> &'static str { Box::leak(p.to_string_lossy().into_owned().into_boxed_str()) };
        let err = native(&[("SSO_CORP_SP_ENCRYPTION_CERT_FILE", leak(&enc_pem))]).err().unwrap();
        assert!(err.contains("only for SSO_CORP_ENCRYPTED_ASSERTIONS=allow or require"), "{err}");
        let err = native(&[("SSO_CORP_ENCRYPTED_ASSERTIONS", "allow"), ("SSO_CORP_SP_CERT_FILE", leak(&sign_pem)), ("SSO_CORP_SP_ENCRYPTION_CERT_FILE", leak(&sign_pem))]).err().unwrap();
        assert!(err.contains("one key for signing, another for encryption"), "{err}");
        // Another certificate, but for the signing certificate's key: still one key.
        let (_, sign_der) = SpKey::generate("sign").unwrap();
        let reissue = |cn: &str| {
            let kp = rcgen::KeyPair::try_from(sign_der.as_slice()).unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.distinguished_name.push(rcgen::DnType::CommonName, cn);
            format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", base64::engine::general_purpose::STANDARD.encode(params.self_signed(&kp).unwrap().der()))
        };
        let (first, second) = (dir.join("first.pem"), dir.join("second.pem"));
        std::fs::write(&first, reissue("signing")).unwrap();
        std::fs::write(&second, reissue("encryption")).unwrap();
        assert_ne!(std::fs::read(&first).unwrap(), std::fs::read(&second).unwrap());
        let err = native(&[("SSO_CORP_ENCRYPTED_ASSERTIONS", "allow"), ("SSO_CORP_SP_CERT_FILE", leak(&first)), ("SSO_CORP_SP_ENCRYPTION_CERT_FILE", leak(&second))]).err().unwrap();
        assert!(err.contains("one key for signing, another for encryption"), "{err}");
        assert!(native(&[("SSO_CORP_ENCRYPTED_ASSERTIONS", "allow"), ("SSO_CORP_SP_CERT_FILE", leak(&sign_pem)), ("SSO_CORP_SP_ENCRYPTION_CERT_FILE", leak(&enc_pem))]).is_ok(), "two keys");
        assert!(native(&[("SSO_CORP_ENCRYPTED_ASSERTIONS", "allow"), ("SSO_CORP_SP_ENCRYPTION_CERT_FILE", "/nonexistent/enc.pem")]).is_err());

        // Its own key, as its own secret: not offered until that is set and matches.
        let id = format!("enc{}", random_hex());
        let up = id.to_ascii_uppercase();
        let var = |k: &str| -> &'static str { Box::leak(format!("SSO_{up}_{k}").into_boxed_str()) };
        let vars = [
            ("SSO_PROVIDERS", leak(std::path::Path::new(&id))),
            ("SSO_PUBLIC_URL", "https://bot.example.com"),
            (var("TYPE"), "saml"),
            (var("IDP_ENTITY_ID"), ADFS),
            (var("IDP_METADATA_URL"), "https://idp.example/metadata"),
            (var("ENCRYPTED_ASSERTIONS"), "require"),
            (var("SP_ENCRYPTION_CERT_FILE"), leak(&enc_pem)),
        ];
        let s = parse(&vars).unwrap();
        let p = &s.providers[0];
        assert_eq!(p.sp_key_var(KeyUse::Encryption), format!("SSO_{up}_ENCRYPTION_PRIVATE_KEY"));
        assert!(p.not_ready().is_some_and(|n| n.contains("ENCRYPTION_PRIVATE_KEY") && n.contains("SP_ENCRYPTION_CERT_FILE")), "{:?}", p.not_ready());
        assert!(crate::secrets::server_secret(var("ENCRYPTION_PRIVATE_KEY")), "kept as a server secret, never in a bot's environment");
        let pem = |der: &[u8]| rcgen::KeyPair::try_from(der).unwrap().serialize_pem();
        let (_, other) = SpKey::generate("other").unwrap();
        crate::secrets::global().put(var("ENCRYPTION_PRIVATE_KEY"), &pem(&other)).unwrap();
        assert!(p.not_ready().is_some_and(|n| n.contains("isn't for the SP key")), "{:?}", p.not_ready());
        let s = parse(&vars).unwrap();
        let p = &s.providers[0];
        crate::secrets::global().put(var("ENCRYPTION_PRIVATE_KEY"), &pem(&enc_der)).unwrap();
        assert_eq!(p.not_ready(), None);
        assert_eq!(p.configured_sp_key(KeyUse::Encryption).unwrap().info.sha256, enc.info.sha256);
        assert!(p.configured_sp_key(KeyUse::Signing).is_err(), "the signing key is botd's own here");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sp_keys_may_be_ecdsa_for_signing_but_not_for_encryption() {
        let dir = std::env::temp_dir().join(format!("superbot-sp-ec-{}", random_hex()));
        std::fs::create_dir_all(&dir).unwrap();
        let leak = |p: &std::path::Path| -> &'static str { Box::leak(p.to_string_lossy().into_owned().into_boxed_str()) };
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "SuperBot SAML SP");
        let cert = dir.join("ec.pem");
        std::fs::write(&cert, params.self_signed(&key).unwrap().pem()).unwrap();
        let err = native(&[("SSO_CORP_ENCRYPTED_ASSERTIONS", "allow"), ("SSO_CORP_SP_ENCRYPTION_CERT_FILE", leak(&cert))]).err().unwrap();
        assert!(err.contains("must be an RSA certificate"), "{err}");

        let id = format!("ec{}", random_hex());
        let up = id.to_ascii_uppercase();
        let var = |k: &str| -> &'static str { Box::leak(format!("SSO_{up}_{k}").into_boxed_str()) };
        let vars = [
            ("SSO_PROVIDERS", leak(std::path::Path::new(&id))),
            ("SSO_PUBLIC_URL", "https://bot.example.com"),
            (var("TYPE"), "saml"),
            (var("IDP_ENTITY_ID"), ADFS),
            (var("IDP_METADATA_URL"), "https://idp.example/metadata"),
            (var("SP_CERT_FILE"), leak(&cert)),
        ];
        let s = parse(&vars).unwrap();
        let p = &s.providers[0];
        crate::secrets::global().put(var("PRIVATE_KEY"), &key.serialize_pem()).unwrap();
        assert_eq!(p.not_ready(), None);
        assert_eq!(p.configured_sp_key(KeyUse::Signing).unwrap().sig_alg(), xmldsig::ECDSA_SHA384, "signs with ecdsa-sha384");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reads_the_signed_metadata_settings() {
        use saml_sp::test_idp::{IDP, metadata, signed_metadata};
        use xmldsig::test_signer::signers;
        let dir = std::env::temp_dir().join(format!("superbot-md-trust-{}", random_hex()));
        std::fs::create_dir_all(&dir).unwrap();
        let leak = |p: &std::path::Path| -> &'static str { Box::leak(p.to_string_lossy().into_owned().into_boxed_str()) };
        let pem = |c: &str| format!("-----BEGIN CERTIFICATE-----\n{c}\n-----END CERTIFICATE-----\n");
        let (anchor, rollover, junk) = (dir.join("anchor.pem"), dir.join("both.pem"), dir.join("junk.pem"));
        std::fs::write(&anchor, pem(&signers()[1].cert)).unwrap();
        std::fs::write(&rollover, format!("{}{}", pem(&signers()[1].cert), pem(&signers()[0].cert))).unwrap();
        std::fs::write(&junk, pem("bm90IGEgY2VydA==")).unwrap();

        let trust = |s: &Sso| match &s.providers[0].kind {
            Kind::SamlSp { metadata_trust, .. } => metadata_trust.as_ref().map(|t| (t.certs.len(), t.require)),
            _ => unreachable!(),
        };
        assert_eq!(trust(&native(&[]).unwrap()), None, "off unless a certificate is set");
        assert_eq!(trust(&native(&[("SSO_CORP_METADATA_SIGNING_CERT_FILE", leak(&anchor))]).unwrap()), Some((1, true)), "required with a certificate");
        assert_eq!(trust(&native(&[("SSO_CORP_METADATA_SIGNING_CERT_FILE", leak(&rollover)), ("SSO_CORP_SIGNED_METADATA", "allow")]).unwrap()), Some((2, false)), "every certificate in the file");
        assert_eq!(trust(&native(&[("SSO_CORP_SIGNED_METADATA", "off")]).unwrap()), None);
        let err = |extra: &[(&'static str, &'static str)]| native(extra).err().unwrap();
        assert!(err(&[("SSO_CORP_SIGNED_METADATA", "require")]).contains("needs SSO_CORP_METADATA_SIGNING_CERT_FILE"));
        assert!(err(&[("SSO_CORP_SIGNED_METADATA", "allow")]).contains("needs SSO_CORP_METADATA_SIGNING_CERT_FILE"));
        assert!(err(&[("SSO_CORP_METADATA_SIGNING_CERT_FILE", leak(&anchor)), ("SSO_CORP_SIGNED_METADATA", "off")]).contains("would ignore"));
        assert!(err(&[("SSO_CORP_METADATA_SIGNING_CERT_FILE", leak(&anchor)), ("SSO_CORP_SIGNED_METADATA", "yes")]).contains("off, allow, or require"));
        assert!(err(&[("SSO_CORP_METADATA_SIGNING_CERT_FILE", leak(&junk))]).starts_with("SSO_CORP_METADATA_SIGNING_CERT_FILE: "));
        assert!(err(&[("SSO_CORP_METADATA_SIGNING_CERT_FILE", "/nonexistent/anchor.pem")]).contains("/nonexistent/anchor.pem"));
        assert!(saml(&[("SSO_ADFS_METADATA_SIGNING_CERT_FILE", leak(&anchor))]).is_err(), "the bridge reads metadata in Keycloak");
        assert!(with_base(&[("SSO_PROVIDERS", "okta"), ("SSO_OKTA_TYPE", "oidc"), ("SSO_OKTA_ISSUER", "https://okta.example"), ("SSO_OKTA_CLIENT_ID", "x")], &[("SSO_OKTA_SIGNED_METADATA", "allow")]).is_err());

        // A metadata file is checked at startup: unsigned or badly signed, botd won't start.
        let (unsigned, signed, forged) = (dir.join("unsigned.xml"), dir.join("signed.xml"), dir.join("forged.xml"));
        std::fs::write(&unsigned, metadata()).unwrap();
        std::fs::write(&signed, signed_metadata(&metadata(), &signers()[1])).unwrap();
        std::fs::write(&forged, signed_metadata(&metadata(), &signers()[0])).unwrap();
        let file = |f: &std::path::Path, mode: &'static str| {
            let base = [("SSO_PROVIDERS", "corp"), ("SSO_PUBLIC_URL", "https://bot.example.com"), ("SSO_CORP_TYPE", "saml"), ("SSO_CORP_IDP_ENTITY_ID", IDP)];
            with_base(&base, &[("SSO_CORP_IDP_METADATA_FILE", leak(f)), ("SSO_CORP_METADATA_SIGNING_CERT_FILE", leak(&anchor)), ("SSO_CORP_SIGNED_METADATA", mode)])
        };
        assert!(file(&signed, "require").unwrap().providers[0].idp_loaded().is_some());
        let e = file(&unsigned, "require").err().unwrap();
        assert!(e.contains("SSO_CORP_IDP_METADATA_FILE") && e.contains("isn't signed"), "{e}");
        assert!(file(&unsigned, "allow").is_ok());
        assert!(file(&forged, "allow").err().unwrap().contains("bad_signature"));
        let _ = std::fs::remove_dir_all(dir);
    }

    fn random_hex() -> String {
        crate::random_bytes(8).iter().map(|b| format!("{b:02x}")).collect()
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
        let p = |ip: &str, expires| Pending { provider: "entra".into(), nonce: "n".into(), verifier: "v".into(), ip: ip.into(), label: None, expires, ret: Return::Cookie { binder: String::new() }, name: None, requested: 0, forced: false };
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
