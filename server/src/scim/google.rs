//! Google Workspace provisioning (ADR 0162). Google pushes SCIM only to the apps in its
//! own catalog (and, in a limited beta, to custom ones), so botd reads the directory
//! instead: a service account lists the people in chosen groups through the Admin SDK
//! Directory API, read-only, and each pass sends what changed through SCIM's own
//! handlers, as if Google had pushed it. Off by default (GOOGLE_DIRECTORY_SYNC).
//!
//! Fail-closed: a pass that can't read every group and every page changes nobody, and
//! one that would remove or disable more people than GOOGLE_DIRECTORY_MAX_REMOVALS (or
//! everyone) waits for an admin's `--force`. A person an admin disabled stays disabled
//! even when Google has them active: the sync only enables people it disabled itself.
//!
//! With GOOGLE_DIRECTORY_PUSH=on, Google also tells botd when a user changes, and a pass
//! starts within seconds (`push`, ADR 0216).

pub mod push;

use super::*;
use crate::db::ScimGroup;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// The secret that holds the service account's JSON key: `botctl secret set`, or
/// `GOOGLE_DIRECTORY_CREDENTIALS_FILE`. One of botd's own, never given to Bots.
pub const CREDENTIALS: &str = "GOOGLE_DIRECTORY_CREDENTIALS";
/// Read-only: botd never writes to the directory.
pub const SCOPES: &str = "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.readonly";
/// The audit actor of every change a pass makes.
pub const ACTOR_ID: &str = "scim:google-directory";
const METHOD: &str = "google_directory";
const API: &str = "https://admin.googleapis.com";
const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const MAX_GROUPS: usize = 50;
/// Pages per list and bytes per page: a directory bigger than this is an error, never a
/// partial read that would look like people leaving.
const MAX_PAGES: usize = 2000;
const MAX_PAGE: usize = 16 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The first pass waits for botd to finish starting; a failed one is tried again sooner
/// than the interval.
const FIRST_PASS: Duration = Duration::from_secs(60);
const RETRY: Duration = Duration::from_secs(5 * 60);
/// Failures and held people named in a pass's audit event and status.
const MAX_LISTED: usize = 50;
const PAGE_USERS: usize = 1000;

/// GOOGLE_DIRECTORY_* settings.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The SCIM tenant the sync's users and teams belong to. No SCIM token may use it.
    pub tenant: String,
    /// `my_customer`, or the Workspace customer ID.
    pub customer: String,
    /// Group emails: their members (nested groups included) get an account.
    pub groups: Vec<String>,
    /// Group emails that are teams too (SCIM_GROUPS=on). Their members get an account.
    pub teams: Vec<String>,
    /// Group emails that are SCIM role groups (ADR 0180), once an admin declares them in
    /// the tenant by email. Being in one gives no account.
    pub role_groups: Vec<String>,
    /// A Google SSO provider: each user's Directory id is their subject there, so they
    /// sign in to the account the sync made.
    pub sso: Option<String>,
    /// The admin the service account acts as (domain-wide delegation). None: the service
    /// account has an admin role itself.
    pub admin: Option<String>,
    pub api: String,
    pub interval: Duration,
    pub max_removals: usize,
    /// GOOGLE_DIRECTORY_PUSH=on: the https address Google sends user changes to
    /// (`push::PATH` on PUBLIC_URL), each starting a pass at once (ADR 0216).
    pub push: Option<String>,
}

impl Settings {
    /// `sso_type` gives the type of an SSO provider by id (`google`, `entra`, ...).
    pub fn from_env(var: &dyn Fn(&str) -> String, scim: &Scim, sso_type: &dyn Fn(&str) -> Option<&'static str>) -> Result<Option<Settings>, String> {
        if !on_off("GOOGLE_DIRECTORY_SYNC", &var("GOOGLE_DIRECTORY_SYNC"))? {
            return Ok(None);
        }
        if !scim.enabled {
            return Err("GOOGLE_DIRECTORY_SYNC=on needs SCIM=on: the sync provisions people through SCIM, with SCIM_DEFAULT_ROLE.".into());
        }
        let tenant = match var("GOOGLE_DIRECTORY_TENANT").trim() {
            "" => "google".to_string(),
            t => tenant_name(&json!(t)).map_err(|e| format!("GOOGLE_DIRECTORY_TENANT: {}", e.1))?,
        };
        let customer = match var("GOOGLE_DIRECTORY_CUSTOMER").trim() {
            "" | "my_customer" => "my_customer".to_string(),
            c if c.len() <= 32 && c.starts_with('C') && c.len() > 1 && c.bytes().all(|b| b.is_ascii_alphanumeric()) => c.to_string(),
            c => return Err(format!("GOOGLE_DIRECTORY_CUSTOMER must be my_customer or your customer ID (C and letters or digits), not \"{c}\"")),
        };
        let groups = group_list("GOOGLE_DIRECTORY_GROUPS", &var("GOOGLE_DIRECTORY_GROUPS"))?;
        let teams = group_list("GOOGLE_DIRECTORY_TEAM_GROUPS", &var("GOOGLE_DIRECTORY_TEAM_GROUPS"))?;
        if groups.is_empty() && teams.is_empty() {
            return Err("GOOGLE_DIRECTORY_GROUPS must name at least one group by its email: only the people in these groups get an account.".into());
        }
        if !teams.is_empty() && !scim.groups {
            return Err("GOOGLE_DIRECTORY_TEAM_GROUPS needs SCIM_GROUPS=on: those groups become teams.".into());
        }
        let role_groups = group_list("GOOGLE_DIRECTORY_ROLE_GROUPS", &var("GOOGLE_DIRECTORY_ROLE_GROUPS"))?;
        if !role_groups.is_empty() && !(scim.groups && scim.group_roles) {
            return Err("GOOGLE_DIRECTORY_ROLE_GROUPS needs SCIM_GROUPS=on and SCIM_GROUP_ROLES=on: those groups give custom roles.".into());
        }
        if let Some(g) = role_groups.iter().find(|g| teams.contains(g)) {
            return Err(format!("{g} is in GOOGLE_DIRECTORY_TEAM_GROUPS and GOOGLE_DIRECTORY_ROLE_GROUPS: a group is a team or a role group, not both"));
        }
        if groups.len() + teams.len() + role_groups.len() > MAX_GROUPS {
            return Err(format!("GOOGLE_DIRECTORY_GROUPS, GOOGLE_DIRECTORY_TEAM_GROUPS and GOOGLE_DIRECTORY_ROLE_GROUPS name at most {MAX_GROUPS} groups together"));
        }
        let sso = match var("GOOGLE_DIRECTORY_SSO").trim().to_ascii_lowercase() {
            p if p.is_empty() => None,
            p => match sso_type(&p) {
                Some("google") => Some(p),
                Some(t) => return Err(format!("GOOGLE_DIRECTORY_SSO must be a Google SSO provider; {p} is {t}")),
                None => return Err(format!("GOOGLE_DIRECTORY_SSO must be one of SSO_PROVIDERS, not \"{p}\"")),
            },
        };
        let admin = match var("GOOGLE_DIRECTORY_ADMIN").trim() {
            "" => None,
            a if users::valid_email(a) => Some(a.to_ascii_lowercase()),
            a => return Err(format!("GOOGLE_DIRECTORY_ADMIN must be an admin's email address, not \"{a}\"")),
        };
        let api = match var("GOOGLE_DIRECTORY_API_URL").trim().trim_end_matches('/') {
            "" => API.to_string(),
            u => {
                let url = url::Url::parse(u).map_err(|e| format!("GOOGLE_DIRECTORY_API_URL {u:?}: {e}"))?;
                if !crate::tiers::encrypted_or_loopback(&url) || url.query().is_some() || url.path() != "/" {
                    return Err("GOOGLE_DIRECTORY_API_URL must be an https:// origin, with no path".into());
                }
                u.to_string()
            }
        };
        let minutes = number(var, "GOOGLE_DIRECTORY_INTERVAL_MINUTES", 30, 5, 1440)?;
        let max_removals = number(var, "GOOGLE_DIRECTORY_MAX_REMOVALS", 10, 1, 1_000_000)?;
        let push = push::address(var)?;
        Ok(Some(Settings { tenant, customer, groups, teams, role_groups, sso, admin, api, interval: Duration::from_secs(minutes as u64 * 60), max_removals, push }))
    }

    /// Whether the group `key` gives its members an account.
    fn gives_accounts(&self, key: &str) -> bool {
        self.groups.iter().chain(&self.teams).any(|g| g == key)
    }
}

/// Group emails, lowercase, each once, in order.
fn group_list(name: &str, v: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for g in v.split(',').map(str::trim).filter(|g| !g.is_empty()) {
        if !users::valid_email(g) {
            return Err(format!("{name} must be group emails, separated by commas; \"{g}\" isn't one"));
        }
        let g = g.to_ascii_lowercase();
        if !out.contains(&g) {
            out.push(g);
        }
    }
    Ok(out)
}

fn number(var: &dyn Fn(&str) -> String, name: &str, default: usize, min: usize, max: usize) -> Result<usize, String> {
    match var(name).trim() {
        "" => Ok(default),
        v => v.parse().ok().filter(|n| (min..=max).contains(n)).ok_or_else(|| format!("{name} must be a number from {min} to {max}, not \"{v}\"")),
    }
}

// The service account, and its access token (RFC 7523).

struct ServiceAccount {
    email: String,
    key_id: Option<String>,
    key: aws_lc_rs::signature::RsaKeyPair,
    token_uri: String,
}

fn service_account(json: &str) -> Result<ServiceAccount, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("{CREDENTIALS} isn't JSON (line {}, column {})", e.line(), e.column()))?;
    if v["type"] != "service_account" {
        return Err(format!("{CREDENTIALS} must be a service account key (\"type\": \"service_account\")"));
    }
    let email = v["client_email"].as_str().filter(|e| e.contains('@')).ok_or(format!("{CREDENTIALS} has no client_email"))?.to_string();
    let pem = v["private_key"].as_str().ok_or(format!("{CREDENTIALS} has no private_key"))?;
    let b64: Zeroizing<String> = Zeroizing::new(pem.lines().map(str::trim).filter(|l| !l.starts_with("-----")).collect());
    let der = Zeroizing::new(STANDARD.decode(b64.as_bytes()).map_err(|_| format!("{CREDENTIALS}: its private_key isn't a PEM key"))?);
    let key = aws_lc_rs::signature::RsaKeyPair::from_pkcs8(&der).map_err(|e| format!("{CREDENTIALS}: its private_key isn't an RSA PKCS#8 key ({e})"))?;
    let token_uri = match v["token_uri"].as_str() {
        None | Some("") => TOKEN_URI.to_string(),
        Some(u) => {
            let url = url::Url::parse(u).map_err(|e| format!("{CREDENTIALS} token_uri {u:?}: {e}"))?;
            if !crate::tiers::encrypted_or_loopback(&url) {
                return Err(format!("{CREDENTIALS} token_uri must use https://"));
            }
            u.to_string()
        }
    };
    let key_id = v["private_key_id"].as_str().filter(|k| !k.is_empty()).map(String::from);
    Ok(ServiceAccount { email, key_id, key, token_uri })
}

/// The signed assertion, as `subject` when the service account acts as an admin.
fn jwt(sa: &ServiceAccount, subject: Option<&str>) -> Result<Zeroizing<String>, String> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let mut header = json!({ "alg": "RS256", "typ": "JWT" });
    if let Some(kid) = &sa.key_id {
        header["kid"] = json!(kid);
    }
    let mut claims = json!({ "iss": sa.email, "scope": SCOPES, "aud": sa.token_uri, "iat": now, "exp": now + 3600 });
    if let Some(s) = subject {
        claims["sub"] = json!(s);
    }
    let signing_input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
    let mut sig = vec![0u8; sa.key.public_modulus_len()];
    sa.key
        .sign(&aws_lc_rs::signature::RSA_PKCS1_SHA256, &aws_lc_rs::rand::SystemRandom::new(), signing_input.as_bytes(), &mut sig)
        .map_err(|_| "couldn't sign the service account's JWT".to_string())?;
    Ok(Zeroizing::new(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))))
}

/// Where the key comes from: the secrets store, read again on every pass so a rotated
/// key works without a restart.
pub type KeySource = Box<dyn Fn() -> Result<Option<Zeroizing<String>>, String> + Send + Sync>;

fn stored_key() -> Result<Option<Zeroizing<String>>, String> {
    crate::secrets::global().get(CREDENTIALS).map(|v| v.map(|s| Zeroizing::new(s.expose().to_string()))).map_err(|e| e.to_string())
}

/// Why a pass changed nobody.
#[derive(Debug)]
pub struct Failure {
    pub reason: &'static str,
    pub detail: String,
}

fn fail(reason: &'static str, detail: impl Into<String>) -> Failure {
    Failure { reason, detail: detail.into() }
}

fn odd(what: &str) -> Failure {
    fail("odd_answer", format!("Google's answer for {what} isn't what the Directory API sends. Nobody was changed."))
}

// What the directory holds.

#[derive(Clone, Debug, Default, PartialEq)]
struct Person {
    id: String,
    email: String,
    given: Option<String>,
    family: Option<String>,
    full: Option<String>,
    active: bool,
    /// From the primary organization (else the first), and the `organization` external id.
    employee_number: Option<String>,
    organization: Option<String>,
    department: Option<String>,
    cost_center: Option<String>,
    /// The manager's primary email, from a `manager` relation.
    manager: Option<String>,
}

#[derive(Debug)]
struct Group {
    id: String,
    name: String,
    users: Vec<String>,
    /// The group holds the whole customer (a CUSTOMER member).
    everyone: bool,
    /// Members from outside the domain, who never get an account.
    outside: usize,
}

#[derive(Debug, Default)]
struct Snapshot {
    people: BTreeMap<String, Person>,
    groups: BTreeMap<String, Group>,
}

/// Google ids are digits (users) or letters and digits (groups).
fn ident(v: &Value) -> Option<String> {
    v.as_str().filter(|s| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric())).map(String::from)
}

/// Text SCIM accepts: no control characters, at most `max` characters.
fn clean(v: &Value, max: usize) -> Option<String> {
    let s: String = v.as_str()?.chars().filter(|c| !c.is_control()).collect::<String>().trim().chars().take(max).collect();
    Some(s.trim().to_string()).filter(|s| !s.is_empty())
}

fn person(v: &Value) -> Option<Person> {
    let id = ident(&v["id"])?;
    let email = v["primaryEmail"].as_str().map(str::to_ascii_lowercase).filter(|e| users::valid_email(e) && e.len() <= 254)?;
    let suspended = v["suspended"].as_bool().unwrap_or(false);
    let archived = v["archived"].as_bool().unwrap_or(false);
    let n = &v["name"];
    let list = |k: &str| v[k].as_array().map(Vec::as_slice).unwrap_or_default();
    let orgs = list("organizations");
    let org = orgs.iter().find(|o| o["primary"] == true).or_else(|| orgs.first()).unwrap_or(&Value::Null);
    let typed = |k: &str, t: &str| list(k).iter().find(|x| x["type"] == t).map(|x| &x["value"]).unwrap_or(&Value::Null);
    let manager = typed("relations", "manager").as_str().map(str::to_ascii_lowercase).filter(|e| users::valid_email(e));
    Some(Person {
        id,
        email,
        given: clean(&n["givenName"], 100),
        family: clean(&n["familyName"], 100),
        full: clean(&n["fullName"], 100),
        active: !suspended && !archived,
        employee_number: clean(typed("externalIds", "organization"), 128),
        organization: clean(&org["name"], 128),
        department: clean(&org["department"], 128),
        cost_center: clean(&org["costCenter"], 128),
        manager,
    })
}

/// A short, safe reason from an error body: Google's status and message, or OAuth's
/// `error` and `error_description`.
fn google_error(body: &[u8]) -> String {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let e = &v["error"];
    let (code, text) = match e {
        Value::Object(_) => (e["status"].as_str().or(e["errors"][0]["reason"].as_str()), e["message"].as_str()),
        Value::String(s) => (Some(s.as_str()), v["error_description"].as_str()),
        _ => (None, None),
    };
    let text: String = text.unwrap_or("").chars().filter(|c| !c.is_control()).take(200).collect();
    match (code, text.is_empty()) {
        (Some(c), false) => format!("{c}: {text}"),
        (Some(c), true) => c.to_string(),
        (None, false) => text,
        (None, true) => "no reason given".into(),
    }
}

/// Why the Directory API answered `status` (not 2xx) for `what`.
fn refused(status: reqwest::StatusCode, body: &[u8], what: &str) -> Failure {
    let why = google_error(body);
    match status.as_u16() {
        401 => fail("sign_in", format!("Google refused the access token for {what} ({why})")),
        403 => fail("forbidden", format!("Google won't let the service account read {what} ({why}). Check its scopes, and that GOOGLE_DIRECTORY_ADMIN is an admin who may.")),
        404 => fail("not_found", format!("Google has no {what}, or the service account can't see it ({why})")),
        429 => fail("rate_limited", format!("Google is rate limiting the Directory API ({why})")),
        _ => fail("google_error", format!("Google's Directory API answered {status} for {what} ({why})")),
    }
}

async fn read(mut res: reqwest::Response, what: &str) -> Result<Vec<u8>, Failure> {
    let mut out = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|e| fail("unreachable", format!("Google's answer for {what} was cut off: {}", e.without_url())))? {
        if out.len() + chunk.len() > MAX_PAGE {
            return Err(fail("too_large", format!("Google's answer for {what} is over {MAX_PAGE} bytes")));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// The sync: its settings, and what its passes did.
pub struct Directory {
    pub settings: Settings,
    key: KeySource,
    http: reqwest::Client,
    running: tokio::sync::Mutex<()>,
    last: std::sync::Mutex<Option<Value>>,
    last_success: std::sync::Mutex<Option<Value>>,
    pub push: push::Push,
}

impl Directory {
    /// Refuses to start when a SCIM token can write the sync's tenant, or the key is
    /// missing or isn't a service account key.
    pub fn new(app: &AppState, settings: Settings) -> Result<Directory, String> {
        Self::with_key(app, settings, Box::new(stored_key))
    }

    pub fn with_key(app: &AppState, settings: Settings, key: KeySource) -> Result<Directory, String> {
        if let Some(t) = app.db.scim_tokens().into_iter().find(|t| t.tenant == settings.tenant && t.revoked_at.is_none()) {
            return Err(format!(
                "the SCIM token {} writes the tenant {}, and the sync must be its only writer. Revoke the token, or set GOOGLE_DIRECTORY_TENANT to another name.",
                t.id, settings.tenant
            ));
        }
        let json = key()?.ok_or(format!("GOOGLE_DIRECTORY_SYNC=on needs the service account's JSON key: botctl secret set {CREDENTIALS} < key.json, or {CREDENTIALS}_FILE"))?;
        service_account(&json)?;
        let loopback = url::Url::parse(&settings.api).ok().and_then(|u| u.host_str().map(crate::is_loopback_host)).unwrap_or(false);
        let http = reqwest::Client::builder().https_only(!loopback).connect_timeout(CONNECT_TIMEOUT).timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none()).build().map_err(|e| e.to_string())?;
        let push = push::Push::new(settings.push.clone());
        Ok(Directory { settings, key, http, running: tokio::sync::Mutex::new(()), last: std::sync::Mutex::new(None), last_success: std::sync::Mutex::new(None), push })
    }

    pub fn describe(&self) -> String {
        let s = &self.settings;
        let groups = s.groups.iter().chain(&s.teams).chain(&s.role_groups).collect::<HashSet<_>>().len();
        format!(
            "on, every {} minutes into the SCIM tenant {}; {groups} group{}, {} of them teams and {} role groups; {}; at most {} removals a pass; {}",
            s.interval.as_secs() / 60,
            s.tenant,
            if groups == 1 { "" } else { "s" },
            s.teams.len(),
            s.role_groups.len(),
            match &s.sso {
                Some(p) => format!("users sign in with {p}"),
                None => "no SSO link (GOOGLE_DIRECTORY_SSO)".into(),
            },
            s.max_removals,
            match &s.push {
                Some(a) => format!("Google pushes user changes to {a} (ADR 0216)"),
                None => "no push (GOOGLE_DIRECTORY_PUSH=off)".into(),
            }
        )
    }

    async fn token(&self) -> Result<Zeroizing<String>, Failure> {
        let json = (self.key)().map_err(|e| fail("credentials", format!("{CREDENTIALS} couldn't be read: {e}")))?;
        let sa = service_account(&json.ok_or(fail("credentials", format!("{CREDENTIALS} is gone")))?).map_err(|e| fail("credentials", e))?;
        let assertion = jwt(&sa, self.settings.admin.as_deref()).map_err(|e| fail("credentials", e))?;
        let form = [("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", assertion.as_str())];
        let res = self.http.post(&sa.token_uri).form(&form).send().await.map_err(|e| fail("unreachable", format!("Google's token endpoint couldn't be reached: {}", e.without_url())))?;
        let status = res.status();
        let body = Zeroizing::new(read(res, "the access token").await?);
        if !status.is_success() {
            return Err(fail(
                "sign_in",
                format!("Google refused the service account ({status}, {}). Check domain-wide delegation of the two read-only scopes, and GOOGLE_DIRECTORY_ADMIN.", google_error(&body)),
            ));
        }
        let v: Value = serde_json::from_slice(&body).map_err(|_| odd("the access token"))?;
        let token = v["access_token"].as_str().filter(|t| !t.is_empty()).ok_or_else(|| odd("the access token"))?;
        Ok(Zeroizing::new(token.to_string()))
    }

    fn url(&self, segments: &[&str], query: &[(&str, &str)]) -> Result<url::Url, Failure> {
        let mut u = url::Url::parse(&self.settings.api).map_err(|e| fail("google_error", e.to_string()))?;
        u.path_segments_mut().map_err(|_| fail("google_error", "GOOGLE_DIRECTORY_API_URL can't have a path"))?.pop_if_empty().extend(["admin", "directory", "v1"]).extend(segments);
        u.query_pairs_mut().extend_pairs(query);
        Ok(u)
    }

    async fn get(&self, token: &str, url: url::Url, kind: &str, what: &str) -> Result<Value, Failure> {
        let res = self.http.get(url).bearer_auth(token).send().await.map_err(|e| fail("unreachable", format!("Google's Directory API couldn't be reached for {what}: {}", e.without_url())))?;
        let status = res.status();
        let body = read(res, what).await?;
        if !status.is_success() {
            return Err(refused(status, &body, what));
        }
        let v: Value = serde_json::from_slice(&body).map_err(|_| odd(what))?;
        if v["kind"] != kind {
            return Err(odd(what));
        }
        Ok(v)
    }

    /// Every page of a list, or an error: never part of one.
    async fn pages(&self, token: &str, base: url::Url, kind: &str, field: &str, what: &str) -> Result<Vec<Value>, Failure> {
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut u = base.clone();
            if let Some(t) = &next {
                u.query_pairs_mut().append_pair("pageToken", t);
            }
            let v = self.get(token, u, kind, what).await?;
            match &v[field] {
                Value::Null => {}
                Value::Array(l) => out.extend(l.iter().cloned()),
                _ => return Err(odd(what)),
            }
            match &v["nextPageToken"] {
                Value::Null => return Ok(out),
                Value::String(t) if t.is_empty() => return Ok(out),
                Value::String(t) if next.as_ref() != Some(t) && t.len() <= 4096 => next = Some(t.clone()),
                _ => return Err(odd(what)),
            }
        }
        Err(fail("too_large", format!("{what} has more than {MAX_PAGES} pages")))
    }

    /// The groups and the customer's users, all of them, or an error.
    async fn fetch(&self) -> Result<Snapshot, Failure> {
        let token = self.token().await?;
        let mut snap = Snapshot::default();
        for key in self.settings.groups.iter().chain(&self.settings.teams).chain(&self.settings.role_groups) {
            if snap.groups.contains_key(key) {
                continue;
            }
            let what = format!("the group {key}");
            let g = match self.get(&token, self.url(&["groups", key], &[("fields", "kind,id,email,name")])?, "admin#directory#group", &what).await {
                Err(f) if f.reason == "not_found" => return Err(fail("group_not_found", format!("{}. Nobody was changed.", f.detail))),
                r => r?,
            };
            let id = ident(&g["id"]).ok_or_else(|| odd(&what))?;
            let name = clean(&g["name"], 256).unwrap_or_else(|| key.clone());
            let query = [("includeDerivedMembership", "true"), ("maxResults", "200"), ("fields", "kind,nextPageToken,members(id,type)")];
            let what = format!("the members of {key}");
            let members = self.pages(&token, self.url(&["groups", &id, "members"], &query)?, "admin#directory#members", "members", &what).await?;
            let mut group = Group { id, name, users: Vec::new(), everyone: false, outside: 0 };
            for m in &members {
                match m["type"].as_str() {
                    Some("USER") => group.users.push(ident(&m["id"]).ok_or_else(|| odd(&what))?),
                    Some("CUSTOMER") => group.everyone = true,
                    Some("EXTERNAL") => group.outside += 1,
                    // With includeDerivedMembership, a nested group's people are listed too.
                    Some("GROUP") => {}
                    _ => return Err(odd(&what)),
                }
            }
            snap.groups.insert(key.clone(), group);
        }
        let fields = "kind,nextPageToken,users(id,primaryEmail,name(givenName,familyName,fullName),suspended,archived,organizations(primary,name,department,costCenter),externalIds(type,value),relations(type,value))";
        let query = [("customer", self.settings.customer.as_str()), ("maxResults", "500"), ("projection", "basic"), ("fields", fields)];
        let what = "the directory's users";
        for u in self.pages(&token, self.url(&["users"], &query)?, "admin#directory#users", "users", what).await? {
            let p = person(&u).ok_or_else(|| odd(what))?;
            if snap.people.insert(p.id.clone(), p).is_some() {
                return Err(odd(what));
            }
        }
        Ok(snap)
    }

    pub fn status(&self) -> Value {
        let s = &self.settings;
        json!({
            "enabled": true,
            "tenant": s.tenant,
            "customer": s.customer,
            "groups": s.groups,
            "teamGroups": s.teams,
            "roleGroups": s.role_groups,
            "sso": s.sso,
            "admin": s.admin,
            "intervalMinutes": s.interval.as_secs() / 60,
            "maxRemovals": s.max_removals,
            "running": self.running.try_lock().is_err(),
            "last": *self.last.lock().unwrap(),
            "lastSuccess": *self.last_success.lock().unwrap(),
            "push": self.push.status(),
        })
    }
}

// A pass.

/// What a pass will do to users, worked out before anything is written.
#[derive(Debug, Default, PartialEq)]
struct Plan {
    /// SCIM bodies for new people, and for people the tenant deleted that Google has back.
    create: Vec<Value>,
    /// User id and the SCIM body that replaces them.
    update: Vec<(String, Value)>,
    delete: Vec<String>,
    /// Users Google has active whom an admin disabled: they stay disabled.
    held: Vec<String>,
    enable: usize,
    disable: usize,
    /// Suspended or archived people who never had an account: none is made.
    skipped: usize,
}

impl Plan {
    /// People who lose access: deleted or disabled while active.
    fn removals(&self, live: &[ScimUser]) -> usize {
        self.disable + self.delete.iter().filter(|id| live.iter().any(|u| &u.user.id == *id && u.user.active())).count()
    }

    /// Users active once every write went through: held people stay disabled.
    fn active_after(&self, live: &[ScimUser]) -> usize {
        let set = |on: bool| -> HashSet<&str> { self.update.iter().filter(|(_, v)| v["active"] == on).map(|(id, _)| id.as_str()).collect() };
        let (on, off) = (set(true), set(false));
        let gone: HashSet<&str> = self.delete.iter().map(String::as_str).collect();
        let stays = |u: &ScimUser| {
            let id = u.user.id.as_str();
            (u.user.active() || on.contains(id)) && !off.contains(id) && !gone.contains(id)
        };
        live.iter().filter(|u| stays(u)).count() + self.create.iter().filter(|v| v["active"] == true).count()
    }
}

/// `manager`: the user id of their manager, when the tenant has them already.
fn user_body(p: &Person, active: bool, manager: Option<&str>) -> Value {
    let mut name = Map::new();
    for (k, v) in [("givenName", &p.given), ("familyName", &p.family), ("formatted", &p.full)] {
        if let Some(v) = v {
            name.insert(k.into(), json!(v));
        }
    }
    let mut ext = Map::new();
    for (k, v) in [("employeeNumber", &p.employee_number), ("organization", &p.organization), ("department", &p.department), ("costCenter", &p.cost_center)] {
        if let Some(v) = v {
            ext.insert(k.into(), json!(v));
        }
    }
    if let Some(m) = manager {
        ext.insert("manager".into(), json!({ "value": m }));
    }
    let mut body = json!({
        "schemas": [USER_SCHEMA],
        "userName": p.email,
        "externalId": p.id,
        "name": name,
        "emails": [{ "value": p.email, "type": "work", "primary": true }],
        "active": active,
    });
    if !ext.is_empty() {
        body["schemas"] = json!([USER_SCHEMA, ENTERPRISE_SCHEMA]);
        body[ENTERPRISE_SCHEMA] = Value::Object(ext);
    }
    body
}

/// `people`: who should have an account. `live`: the tenant's users now. `gone`: Google
/// id to user id, for disabled users a create takes back or on. `held`: whether a
/// disabled user stays so. A manager is set once both people have an account, so a
/// manager made in this pass is set on the next.
fn plan(people: &[&Person], live: &[ScimUser], gone: &HashMap<String, String>, held: &dyn Fn(&str) -> bool) -> Plan {
    let mut p = Plan::default();
    let by_ext: HashMap<&str, &ScimUser> = live.iter().filter_map(|u| u.external_id.as_deref().map(|x| (x, u))).collect();
    let by_email: HashMap<&str, &str> = people.iter().map(|p| (p.email.as_str(), p.id.as_str())).collect();
    let manager = |person: &Person| {
        let m = person.manager.as_deref().and_then(|e| by_email.get(e)).and_then(|id| by_ext.get(id)).map(|u| u.user.id.as_str());
        m.filter(|_| person.manager.as_deref() != Some(person.email.as_str()))
    };
    let mut kept: HashSet<&str> = HashSet::new();
    for person in people {
        if let Some(u) = by_ext.get(person.id.as_str()) {
            kept.insert(u.user.id.as_str());
            let mut active = person.active;
            if active && !u.user.active() && held(&u.user.id) {
                active = false;
                p.held.push(u.user.id.clone());
            }
            let body = user_body(person, active, manager(person));
            let now = Attrs::of(u);
            if from_resource(&body, Some(&now)).is_ok_and(|want| want == now) {
                continue;
            }
            match (u.user.active(), active) {
                (true, false) => p.disable += 1,
                (false, true) => p.enable += 1,
                _ => {}
            }
            p.update.push((u.user.id.clone(), body));
        } else if !person.active {
            p.skipped += 1;
        } else if let Some(id) = gone.get(&person.id).filter(|id| held(id)) {
            p.held.push(id.clone());
            p.create.push(user_body(person, false, manager(person)));
        } else {
            p.create.push(user_body(person, true, manager(person)));
        }
    }
    p.delete = live.iter().filter(|u| !kept.contains(u.user.id.as_str())).map(|u| u.user.id.clone()).collect();
    p
}

/// Whether a disabled user stays disabled: yes, unless the newest thing that disabled
/// them was this sync. An admin's disable, or one the log no longer shows, holds.
/// Taking a user back or on changes no status by itself (an enable is logged as its
/// own event), so the search goes on past it to whoever disabled them.
fn held(app: &AppState, user_id: &str) -> bool {
    let f = crate::audit::Filter {
        actions: ["user.enabled", "user.disabled", "user.created", "scim.user_deleted", "scim.user_restored", "scim.user_linked"].map(String::from).to_vec(),
        target_type: Some("user".into()),
        target_id: Some(user_id.into()),
        ..Default::default()
    };
    for e in app.db.audit_events(&f, 100, false) {
        let ours = e.actor_id.as_deref() == Some(ACTOR_ID);
        match e.action.as_str() {
            "user.enabled" => return false,
            "scim.user_deleted" | "scim.user_restored" | "scim.user_linked" if ours => continue,
            "user.disabled" if ours => return false,
            "user.created" if ours => return e.details["active"] == json!(false),
            _ => return true,
        }
    }
    true
}

/// The SCIM client a pass is: the sync's tenant, as no token.
fn caller(a: &Auth, s: &Settings) -> Caller {
    let token = ScimToken {
        id: "google-directory".into(),
        tenant: s.tenant.clone(),
        label: Some("Google Workspace directory sync".into()),
        sso_provider: s.sso.clone(),
        created_at: 0,
        created_by: None,
        last_used_at: None,
        revoked_at: None,
        revoked_by: None,
        expires_at: None,
        rotated_to: None,
        expiry_notice: None,
    };
    let actor = Actor {
        kind: ActorKind::System,
        id: Some(ACTOR_ID.into()),
        name: Some(format!("Google Workspace sync ({})", s.tenant)),
        method: Some(METHOD.into()),
        idp: s.sso.as_deref().and_then(|p| crate::sso::idp_type(a, p)).map(String::from),
        idp_provider: s.sso.clone(),
        ..Default::default()
    };
    Caller { token, who: Who { actor, source: Source::default() } }
}

/// What a pass wrote, and what SCIM refused.
#[derive(Default)]
struct Tally {
    created: usize,
    updated: usize,
    deleted: usize,
    enabled: usize,
    disabled: usize,
    linked: usize,
    teams_created: usize,
    teams_updated: usize,
    teams_deleted: usize,
    role_groups_created: usize,
    role_groups_updated: usize,
    role_groups_deleted: usize,
    /// Role groups listed that no admin declared: never pushed, or they'd be teams.
    undeclared: Vec<String>,
    failures: Vec<Value>,
    failed: usize,
}

impl Tally {
    fn note(&mut self, app: &AppState, c: &Caller, method: &str, path: &str, r: ScimRes) -> bool {
        match r {
            Ok(_) => true,
            Err(e) => {
                self.failed += 1;
                if self.failures.len() < MAX_LISTED {
                    self.failures.push(json!({ "method": method, "path": path, "status": e.status.as_u16(), "reason": e.scim_type, "detail": e.detail }));
                }
                request_failed(app, &c.who, &c.token.tenant, method, path, &e.into_response());
                false
            }
        }
    }
}

/// Who asked for a pass.
pub enum Trigger {
    Schedule,
    Admin { force: bool },
    /// Google said a user changed (ADR 0216).
    Push,
}

/// One pass: read the directory, then write what changed. The summary is audited as
/// `scim.google_sync`; an error means nobody was changed.
pub async fn run(a: &Arc<Auth>, d: &Directory, trigger: Trigger) -> Result<Value, Failure> {
    let Some(app) = a.app.clone() else { return Err(fail("not_ready", "botd isn't serving yet")) };
    // A pass already running may have read the directory before the change Google
    // pushed, so a pushed pass waits for it rather than being dropped.
    let _one = match trigger {
        Trigger::Push => d.running.lock().await,
        _ => d.running.try_lock().map_err(|_| fail("running", "A pass is running already. Try again when it's done."))?,
    };
    let started = Instant::now();
    let force = matches!(trigger, Trigger::Admin { force: true });
    let s = &d.settings;
    let c = caller(a, s);
    let name = match trigger {
        Trigger::Schedule => "schedule",
        Trigger::Admin { .. } => "admin",
        Trigger::Push => "push",
    };
    let mut base = json!({ "tenant": s.tenant, "trigger": name, "force": force });
    // Taken as the pass starts: a change pushed from here on gets a pass of its own.
    let pushed = d.push.take_pending();
    if !pushed.is_empty() {
        base["pushed"] = json!(pushed);
    }
    let result = match d.fetch().await {
        Ok(snap) => apply(a, &app, d, &c, snap, force).await,
        Err(f) => Err(f),
    };
    let mut details = base;
    details["ms"] = json!(started.elapsed().as_millis() as u64);
    details["at"] = json!(crate::db::now());
    let outcome = match &result {
        Ok(summary) => {
            for (k, v) in summary.as_object().into_iter().flatten() {
                details[k] = v.clone();
            }
            if summary["failed"].as_u64().unwrap_or(0) > 0 { Outcome::Failure } else { Outcome::Success }
        }
        Err(f) => {
            details["reason"] = json!(f.reason);
            details["detail"] = json!(f.detail);
            if matches!(f.reason, "too_many_removals" | "would_remove_everyone") { Outcome::Denied } else { Outcome::Failure }
        }
    };
    app.db.record(&c.who.event("scim.google_sync").target("scim_tenant", &s.tenant).outcome(outcome).details(details.clone()));
    match &result {
        Ok(_) => {
            if details["failed"].as_u64().unwrap_or(0) == 0 {
                *d.last_success.lock().unwrap() = Some(details.clone());
            }
            let changed = ["created", "updated", "deleted"].iter().map(|k| details[*k].as_u64().unwrap_or(0)).sum::<u64>();
            if changed > 0 || details["failed"].as_u64().unwrap_or(0) > 0 {
                crate::obs::log::log_info!("Google Workspace sync: {} created, {} updated, {} deleted, {} failed.", details["created"], details["updated"], details["deleted"], details["failed"]);
            }
        }
        Err(f) => crate::obs::log::log_warn!("Google Workspace sync: {}", f.detail),
    }
    *d.last.lock().unwrap() = Some(details);
    result
}

async fn apply(a: &Arc<Auth>, app: &AppState, d: &Directory, c: &Caller, snap: Snapshot, force: bool) -> Result<Value, Failure> {
    let s = &d.settings;
    let tenant = s.tenant.as_str();
    let scoped: Vec<&Group> = snap.groups.iter().filter(|(k, _)| s.gives_accounts(k)).map(|(_, g)| g).collect();
    let everyone = scoped.iter().any(|g| g.everyone);
    let members: HashSet<&str> = scoped.iter().flat_map(|g| g.users.iter().map(String::as_str)).collect();
    let outside = members.iter().filter(|id| !snap.people.contains_key(**id)).count() + scoped.iter().map(|g| g.outside).sum::<usize>();
    let people: Vec<&Person> = snap.people.values().filter(|p| everyone || members.contains(p.id.as_str())).collect();
    let live = all_users(app, tenant);
    // A create takes back a user the tenant deleted, or takes on the one their Google
    // identity is linked to already (as after a just-in-time sign-in).
    let taken = |p: &Person| -> Option<User> {
        if let Some(u) = app.db.scim_find(tenant, &ScimKey::ExternalId(p.id.clone())).filter(|u| u.deleted_at.is_some()) {
            return Some(u.user);
        }
        let l = sso_link(a, &c.token, Some(&p.id)).ok().flatten()?;
        app.db.identity(&l.issuer, &l.subject).map(|(_, u)| u)
    };
    let gone: HashMap<String, String> = people
        .iter()
        .filter(|p| p.active && !live.iter().any(|u| u.external_id.as_deref() == Some(p.id.as_str())))
        .filter_map(|p| taken(p).filter(|u| !u.active()).map(|u| (p.id.clone(), u.id)))
        .collect();
    let plan = plan(&people, &live, &gone, &|id| held(app, id));
    let active_now = live.iter().filter(|u| u.user.active()).count();
    if !force && active_now > 0 && plan.active_after(&live) == 0 {
        return Err(fail(
            "would_remove_everyone",
            format!(
                "Nobody in the groups would stay active, so this pass would remove all {active_now} of the tenant's active people. Nobody was changed. Check the groups, then run botctl scim google sync --force."
            ),
        ));
    }
    let removals = plan.removals(&live);
    if !force && removals > s.max_removals {
        return Err(fail(
            "too_many_removals",
            format!(
                "This pass would remove or disable {removals} people, more than GOOGLE_DIRECTORY_MAX_REMOVALS ({}). Nobody was changed. Check the groups in Google, then run botctl scim google sync --force.",
                s.max_removals
            ),
        ));
    }
    let mut t = Tally::default();
    let st = || State(app.clone());
    let ex = || Extension(a.clone());
    let ca = || Extension(c.clone());
    let headers = HeaderMap::new();
    let body = |v: &Value| Ok(Bytes::from(v.to_string()));
    for v in &plan.create {
        let ok = t.note(app, c, "POST", "/Users", create_user(st(), ex(), ca(), headers.clone(), body(v)).await);
        t.created += ok as usize;
    }
    for (id, v) in &plan.update {
        let path = format!("/Users/{id}");
        let ok = t.note(app, c, "PUT", &path, replace_user(st(), ex(), ca(), headers.clone(), Path(id.clone()), body(v)).await);
        t.updated += ok as usize;
        match (ok, live.iter().find(|u| &u.user.id == id).map(|u| u.user.active()), v["active"].as_bool()) {
            (true, Some(false), Some(true)) => t.enabled += 1,
            (true, Some(true), Some(false)) => t.disabled += 1,
            _ => {}
        }
    }
    if c.token.sso_provider.is_some() {
        link(a, app, c, &people, &all_users(app, tenant), &mut t);
    }
    if a.scim.groups {
        teams(a, app, d, c, &snap, &people, &mut t).await;
        push_role_groups(a, app, d, c, &snap, &people, &mut t).await;
    }
    let doomed: HashSet<&str> = plan.delete.iter().map(String::as_str).collect();
    let now = all_users(app, tenant);
    let last = now.iter().any(|u| u.user.active() && doomed.contains(u.user.id.as_str())) && !now.iter().any(|u| u.user.active() && !doomed.contains(u.user.id.as_str()));
    if !force && last {
        let e = ScimError::new(
            StatusCode::CONFLICT,
            None,
            "Nobody would stay active after these removals (writes before them failed), so nobody was removed. Run botctl scim google sync --force to remove them anyway.",
        );
        t.note(app, c, "DELETE", "/Users", Err(e));
    } else {
        for id in &plan.delete {
            let path = format!("/Users/{id}");
            let ok = t.note(app, c, "DELETE", &path, delete_user(st(), ex(), ca(), Path(id.clone())).await);
            t.deleted += ok as usize;
        }
    }
    Ok(json!({
        "people": people.len(),
        "outsideDomain": outside,
        "created": t.created,
        "updated": t.updated,
        "enabled": t.enabled,
        "disabled": t.disabled,
        "linked": t.linked,
        "deleted": t.deleted,
        "held": plan.held.iter().take(MAX_LISTED).collect::<Vec<_>>(),
        "heldCount": plan.held.len(),
        "skippedSuspended": plan.skipped,
        "teams": { "created": t.teams_created, "updated": t.teams_updated, "deleted": t.teams_deleted },
        "roleGroups": { "created": t.role_groups_created, "updated": t.role_groups_updated, "deleted": t.role_groups_deleted, "undeclared": t.undeclared },
        "failed": t.failed,
        "failures": t.failures,
    }))
}

/// Links each user in scope to their Google identity, if they don't have it yet: as
/// after GOOGLE_DIRECTORY_SSO is set on a tenant that already synced, or for a user
/// taken back. SCIM links only the users it creates.
fn link(a: &Auth, app: &AppState, c: &Caller, people: &[&Person], live: &[ScimUser], t: &mut Tally) {
    let ids: HashSet<&str> = people.iter().map(|p| p.id.as_str()).collect();
    for u in live.iter().filter(|u| u.external_id.as_deref().is_some_and(|x| ids.contains(x))) {
        let path = format!("/Users/{}", u.user.id);
        let l = match sso_link(a, &c.token, u.external_id.as_deref()) {
            Ok(Some(l)) => l,
            Ok(None) => return,
            Err(e) => {
                t.note(app, c, "PUT", &path, Err(e));
                continue;
            }
        };
        match app.db.identity(&l.issuer, &l.subject) {
            Some((_, owner)) if owner.id == u.user.id => continue,
            Some(_) => {
                t.note(app, c, "PUT", &path, Err(uniqueness("This person's Google identity is linked to another user. Unlink it there first.")));
                continue;
            }
            None => {}
        }
        let i = NewIdentity { provider: &l.provider, issuer: &l.issuer, subject: &l.subject, tenant: l.tenant.as_deref(), email: None, created_by: c.who.actor.id.as_deref() };
        match app.db.link_identity(&u.user.id, &i) {
            Ok(i) => {
                app.db.record(
                    &c.who
                        .event("user.identity_linked")
                        .target("user", &u.user.id)
                        .details(json!({ "identity": i.id, "provider": l.provider, "issuer": l.issuer, "subject": l.subject, "tenant": l.tenant })),
                );
                t.linked += 1;
            }
            Err(e) => _ = t.note(app, c, "PUT", &path, Err(ScimError::new(StatusCode::CONFLICT, Some("uniqueness"), e))),
        }
    }
}

/// The tenant's live users, every page.
fn all_users(app: &AppState, tenant: &str) -> Vec<ScimUser> {
    let mut out = Vec::new();
    loop {
        let (total, page) = app.db.scim_list(tenant, None, out.len() as i64, PAGE_USERS as i64);
        let n = page.len();
        out.extend(page);
        if n == 0 || out.len() as i64 >= total {
            return out;
        }
    }
}

/// The team groups: teams no longer wanted go and people leave first, so someone who
/// moved between two of them joins the new one in the same pass; then each team gets its
/// name and members. A person is on one team at most, so the first team group listed
/// wins, and someone on a team the sync doesn't manage stays there. Two addresses of one
/// Google group are one team.
async fn teams(a: &Arc<Auth>, app: &AppState, d: &Directory, c: &Caller, snap: &Snapshot, people: &[&Person], t: &mut Tally) {
    let s = &d.settings;
    let tenant = s.tenant.as_str();
    let user_of = |gid: &str| app.db.scim_find(tenant, &ScimKey::ExternalId(gid.to_string())).filter(|u| u.deleted_at.is_none()).map(|u| u.user.id);
    let in_scope: HashSet<&str> = people.iter().map(|p| p.id.as_str()).collect();
    let mut claimed: HashSet<String> = HashSet::new();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut wanted: Vec<(&Group, Option<ScimGroup>, Vec<String>)> = Vec::new();
    for key in &s.teams {
        let Some(g) = snap.groups.get(key) else { continue };
        if !seen.insert(g.id.as_str()) {
            continue;
        }
        let ids: Vec<&str> = if g.everyone { people.iter().map(|p| p.id.as_str()).collect() } else { g.users.iter().map(String::as_str).filter(|id| in_scope.contains(id)).collect() };
        let mut users: Vec<String> = Vec::new();
        for uid in ids.into_iter().filter_map(user_of) {
            if claimed.insert(uid.clone()) {
                users.push(uid);
            }
        }
        let existing = app.db.scim_group_find(tenant, Some(&g.id), None).filter(|x| x.provisioned_at.is_some());
        wanted.push((g, existing, users));
    }
    let st = || State(app.clone());
    let ex = || Extension(a.clone());
    let ca = || Extension(c.clone());
    let put = |g: &Group, members: &[String]| {
        let v = json!({ "schemas": [groups::GROUP_SCHEMA], "displayName": g.name, "externalId": g.id, "members": members.iter().map(|m| json!({ "value": m })).collect::<Vec<_>>() });
        Ok(Bytes::from(v.to_string()))
    };
    for x in app.db.scim_groups(tenant).into_iter().filter(|x| x.provisioned_at.is_some() && !x.external_id.as_deref().is_some_and(|e| seen.contains(e))) {
        let path = format!("/Groups/{}", x.team_id);
        let ok = t.note(app, c, "DELETE", &path, groups::delete(st(), ex(), ca(), Path(x.team_id.clone())).await);
        t.teams_deleted += ok as usize;
    }
    for (g, existing, users) in &wanted {
        let Some(x) = existing else { continue };
        let now: Vec<String> = app.db.scim_group_members(tenant, &x.team_id, true).into_iter().map(|u| u.id).collect();
        if now.iter().all(|m| users.contains(m)) {
            continue;
        }
        let staying: Vec<String> = now.iter().filter(|m| users.contains(m)).cloned().collect();
        let display = Group { id: g.id.clone(), name: x.display_name.clone(), users: vec![], everyone: false, outside: 0 };
        let path = format!("/Groups/{}", x.team_id);
        let ok = t.note(app, c, "PUT", &path, groups::replace(st(), ex(), ca(), HeaderMap::new(), Path(x.team_id.clone()), put(&display, &staying)).await);
        t.teams_updated += ok as usize;
    }
    for (g, existing, users) in &wanted {
        let team = existing.as_ref().map(|x| x.team_id.as_str());
        let members: Vec<String> = users.iter().filter(|u| app.db.team_id_of(u).is_none_or(|on| Some(on.as_str()) == team)).cloned().collect();
        match existing {
            Some(x) => {
                let mut now: Vec<String> = app.db.scim_group_members(tenant, &x.team_id, true).into_iter().map(|u| u.id).collect();
                let mut want = members.clone();
                now.sort();
                want.sort();
                if now == want && x.display_name == g.name {
                    continue;
                }
                let path = format!("/Groups/{}", x.team_id);
                let ok = t.note(app, c, "PUT", &path, groups::replace(st(), ex(), ca(), HeaderMap::new(), Path(x.team_id.clone()), put(g, &members)).await);
                t.teams_updated += ok as usize;
            }
            None => {
                let ok = t.note(app, c, "POST", "/Groups", groups::create(st(), ex(), ca(), HeaderMap::new(), put(g, &members)).await);
                t.teams_created += ok as usize;
            }
        }
    }
}

/// The role groups (ADR 0180): each one an admin declared in the tenant, by the group's
/// email (or its Directory id as externalId), is pushed with its members who have an
/// account; one nobody declared is never pushed, as it would become a team, and is named
/// in the summary instead. A declared group no longer listed is deleted, so its roles go
/// and the declaration waits again. Unlike teams, people can be in any number of them.
async fn push_role_groups(a: &Arc<Auth>, app: &AppState, d: &Directory, c: &Caller, snap: &Snapshot, people: &[&Person], t: &mut Tally) {
    let tenant = d.settings.tenant.as_str();
    let user_of = |gid: &str| app.db.scim_find(tenant, &ScimKey::ExternalId(gid.to_string())).filter(|u| u.deleted_at.is_none()).map(|u| u.user.id);
    let in_scope: HashSet<&str> = people.iter().map(|p| p.id.as_str()).collect();
    let st = || State(app.clone());
    let ex = || Extension(a.clone());
    let ca = || Extension(c.clone());
    let mut seen: HashSet<&str> = HashSet::new();
    let mut wanted = Vec::new();
    for key in &d.settings.role_groups {
        let Some(g) = snap.groups.get(key) else { continue };
        if !seen.insert(g.id.as_str()) {
            continue;
        }
        let declared = app.db.scim_role_group_find(tenant, Some(&g.id), None).or_else(|| app.db.scim_role_group_find(tenant, None, Some(key)));
        let Some(declared) = declared else {
            t.undeclared.push(key.clone());
            continue;
        };
        let ids: Vec<&str> = if g.everyone { people.iter().map(|p| p.id.as_str()).collect() } else { g.users.iter().map(String::as_str).filter(|id| in_scope.contains(id)).collect() };
        let mut members: Vec<String> = ids.into_iter().filter_map(user_of).collect();
        members.sort();
        members.dedup();
        wanted.push((key, g, declared, members));
    }
    for x in role_groups::all_pushed(app, tenant).into_iter().filter(|x| !x.external_id.as_deref().is_some_and(|e| seen.contains(e))) {
        let path = format!("/Groups/{}", x.id);
        let ok = t.note(app, c, "DELETE", &path, groups::delete(st(), ex(), ca(), Path(x.id.clone())).await);
        t.role_groups_deleted += ok as usize;
    }
    for (key, g, declared, members) in wanted {
        let Some(declared) = app.db.scim_role_group(&declared.id) else { continue };
        let v = json!({ "schemas": [groups::GROUP_SCHEMA], "displayName": key, "externalId": g.id, "members": members.iter().map(|m| json!({ "value": m })).collect::<Vec<_>>() });
        let body = Ok(Bytes::from(v.to_string()));
        if declared.provisioned_at.is_none() {
            let d = groups::Doc { display_name: key.clone(), external_id: Some(g.id.clone()), members: Some(members) };
            let ok = t.note(app, c, "POST", "/Groups", role_groups::push_declared(app, a, c, &declared.id, &d).await);
            t.role_groups_created += ok as usize;
            continue;
        }
        let now = role_groups::member_set(app, &declared);
        if now == members.iter().cloned().collect() && declared.display_name == *key {
            continue;
        }
        let path = format!("/Groups/{}", declared.id);
        let ok = t.note(app, c, "PUT", &path, groups::replace(st(), ex(), ca(), HeaderMap::new(), Path(declared.id.clone()), body).await);
        t.role_groups_updated += ok as usize;
    }
}

/// Passes every GOOGLE_DIRECTORY_INTERVAL_MINUTES, the first a minute after start,
/// sooner again after one that failed, and within seconds of Google pushing a change
/// (ADR 0216), whose channels this starts too.
pub fn start(a: Arc<Auth>) {
    let Some(d) = a.scim.google.clone() else { return };
    push::start(a.clone(), d.clone());
    tokio::spawn(async move {
        let mut trigger = d.push.wait(FIRST_PASS, None).await;
        loop {
            let started = tokio::time::Instant::now();
            let wait = next_wait(&run(&a, &d, trigger).await, d.settings.interval);
            trigger = d.push.wait(wait, Some(started)).await;
        }
    });
}

/// A pass that failed, or wrote with failures, is tried again sooner than the interval.
fn next_wait(result: &Result<Value, Failure>, interval: Duration) -> Duration {
    match result {
        Err(f) if f.reason != "running" => RETRY.min(interval),
        Ok(summary) if summary["failed"].as_u64().unwrap_or(0) > 0 => RETRY.min(interval),
        _ => interval,
    }
}

// Admin API.

/// `GET /api/scim/google`: the settings and the last passes.
pub async fn status(Extension(a): Extension<Arc<Auth>>) -> Json<Value> {
    Json(match &a.scim.google {
        Some(d) => d.status(),
        None => json!({ "enabled": false }),
    })
}

/// `POST /api/scim/google/sync` `{"force"?: true}`: a pass now. `force` lets one that
/// would remove more people than GOOGLE_DIRECTORY_MAX_REMOVALS go ahead. Send `{}` for none.
pub async fn sync(Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<Json<Value>> {
    let d = a.scim.google.clone().ok_or_else(|| ApiError(StatusCode::CONFLICT, "The Google Workspace sync is off: set GOOGLE_DIRECTORY_SYNC=on.".into()))?;
    let force = match &v["force"] {
        Value::Null => false,
        Value::Bool(b) => *b,
        _ => return Err(bad("force must be true or false")),
    };
    let app = a.app.clone().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, "botd isn't serving yet".into()))?;
    app.db.record(&by.event("scim.google_sync_requested").target("scim_tenant", &d.settings.tenant).details(json!({ "tenant": d.settings.tenant, "force": force })));
    match run(&a, &d, Trigger::Admin { force }).await {
        Ok(summary) => Ok(Json(summary)),
        Err(f) if f.reason == "running" => Err(ApiError(StatusCode::CONFLICT, f.detail)),
        Err(f) if matches!(f.reason, "too_many_removals" | "would_remove_everyone") => Err(ApiError(StatusCode::CONFLICT, f.detail)),
        Err(f) => Err(ApiError(StatusCode::BAD_GATEWAY, f.detail)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| m.get(k).cloned().unwrap_or_default()
    }

    fn scim(groups: bool) -> Scim {
        Scim { enabled: true, groups, ..Scim::default() }
    }

    fn no_sso(_: &str) -> Option<&'static str> {
        None
    }

    #[test]
    fn off_unless_turned_on() {
        assert!(Settings::from_env(&vars(&[]), &scim(true), &no_sso).unwrap().is_none());
        assert!(Settings::from_env(&vars(&[("GOOGLE_DIRECTORY_SYNC", "off"), ("GOOGLE_DIRECTORY_GROUPS", "x")]), &Scim::default(), &no_sso).unwrap().is_none());
        assert!(Settings::from_env(&vars(&[("GOOGLE_DIRECTORY_SYNC", "maybe")]), &scim(true), &no_sso).is_err());
    }

    #[test]
    fn settings_are_checked() {
        let on = |extra: &[(&str, &str)], s: &Scim| {
            let mut all = vec![("GOOGLE_DIRECTORY_SYNC", "on"), ("GOOGLE_DIRECTORY_GROUPS", "Staff@Example.com, staff@example.com,eng@example.com")];
            all.extend_from_slice(extra);
            Settings::from_env(&vars(&all), s, &|p| match p {
                "g" => Some("google"),
                "e" => Some("entra"),
                _ => None,
            })
        };
        let s = on(&[], &scim(false)).unwrap().unwrap();
        assert_eq!((s.tenant.as_str(), s.customer.as_str(), s.groups.clone()), ("google", "my_customer", vec!["staff@example.com".to_string(), "eng@example.com".to_string()]));
        assert_eq!((s.interval, s.max_removals, s.api.as_str(), s.sso.clone(), s.admin.clone()), (Duration::from_secs(1800), 10, API, None, None));
        assert!(on(&[], &Scim::default()).unwrap_err().contains("SCIM=on"));
        assert!(on(&[("GOOGLE_DIRECTORY_GROUPS", "")], &scim(false)).unwrap_err().contains("at least one group"));
        assert!(on(&[("GOOGLE_DIRECTORY_GROUPS", "not a group")], &scim(false)).is_err());
        assert!(on(&[("GOOGLE_DIRECTORY_TEAM_GROUPS", "eng@example.com")], &scim(false)).unwrap_err().contains("SCIM_GROUPS=on"));
        assert!(on(&[("GOOGLE_DIRECTORY_ROLE_GROUPS", "audit@example.com")], &scim(true)).unwrap_err().contains("SCIM_GROUP_ROLES=on"));
        let roles = Scim { group_roles: true, ..scim(true) };
        assert_eq!(on(&[("GOOGLE_DIRECTORY_ROLE_GROUPS", "Audit@example.com")], &roles).unwrap().unwrap().role_groups, vec!["audit@example.com".to_string()]);
        assert!(on(&[("GOOGLE_DIRECTORY_TEAM_GROUPS", "eng@example.com"), ("GOOGLE_DIRECTORY_ROLE_GROUPS", "eng@example.com")], &roles).unwrap_err().contains("not both"));
        let t = on(&[("GOOGLE_DIRECTORY_GROUPS", ""), ("GOOGLE_DIRECTORY_TEAM_GROUPS", "eng@example.com")], &scim(true)).unwrap().unwrap();
        assert_eq!((t.groups.len(), t.teams.clone()), (0, vec!["eng@example.com".to_string()]));
        assert_eq!(on(&[("GOOGLE_DIRECTORY_SSO", "G")], &scim(false)).unwrap().unwrap().sso.as_deref(), Some("g"));
        assert!(on(&[("GOOGLE_DIRECTORY_SSO", "e")], &scim(false)).unwrap_err().contains("is entra"));
        assert!(on(&[("GOOGLE_DIRECTORY_SSO", "nope")], &scim(false)).unwrap_err().contains("SSO_PROVIDERS"));
        assert_eq!(on(&[("GOOGLE_DIRECTORY_ADMIN", "Admin@Example.com")], &scim(false)).unwrap().unwrap().admin.as_deref(), Some("admin@example.com"));
        assert!(on(&[("GOOGLE_DIRECTORY_ADMIN", "admin")], &scim(false)).is_err());
        assert_eq!(on(&[("GOOGLE_DIRECTORY_CUSTOMER", "C01abc23")], &scim(false)).unwrap().unwrap().customer, "C01abc23");
        assert!(on(&[("GOOGLE_DIRECTORY_CUSTOMER", "C01 abc")], &scim(false)).is_err());
        assert!(on(&[("GOOGLE_DIRECTORY_TENANT", "Google Workspace")], &scim(false)).is_err());
        assert!(on(&[("GOOGLE_DIRECTORY_INTERVAL_MINUTES", "1")], &scim(false)).is_err());
        assert!(on(&[("GOOGLE_DIRECTORY_MAX_REMOVALS", "0")], &scim(false)).is_err());
        assert!(on(&[("GOOGLE_DIRECTORY_API_URL", "http://directory.example")], &scim(false)).is_err());
        assert!(on(&[("GOOGLE_DIRECTORY_API_URL", "https://directory.example/v1")], &scim(false)).is_err());
        assert!(on(&[("GOOGLE_DIRECTORY_API_URL", "http://127.0.0.1:9")], &scim(false)).is_ok());
    }

    #[test]
    fn the_key_is_a_server_secret() {
        assert!(crate::secrets::server_secret(CREDENTIALS));
    }

    #[test]
    fn people_and_errors_are_read_strictly() {
        let p = person(&json!({ "id": "1234", "primaryEmail": "Ada@Example.com", "name": { "givenName": "Ada\u{7}", "familyName": "L", "fullName": "x".repeat(300) }, "suspended": false })).unwrap();
        assert_eq!((p.email.as_str(), p.given.as_deref(), p.full.as_ref().map(|f| f.len()), p.active), ("ada@example.com", Some("Ada"), Some(100), true));
        assert!(!person(&json!({ "id": "1", "primaryEmail": "a@example.com", "archived": true })).unwrap().active);
        assert!(person(&json!({ "id": "1/2", "primaryEmail": "a@example.com" })).is_none());
        assert!(person(&json!({ "id": "1", "primaryEmail": "nope" })).is_none());
        assert_eq!(
            google_error(br#"{"error":{"code":403,"message":"Not Authorized to access this resource/api","status":"PERMISSION_DENIED"}}"#),
            "PERMISSION_DENIED: Not Authorized to access this resource/api"
        );
        assert_eq!(google_error(br#"{"error":"unauthorized_client","error_description":"Client is unauthorized"}"#), "unauthorized_client: Client is unauthorized");
        assert_eq!(google_error(b"<html>"), "no reason given");
    }

    /// A tenant user as the plan sees one: only the id, the externalId, the email, and
    /// whether they're active matter.
    fn scim_user(template: &ScimUser, id: &str, ext: &str, email: &str, active: bool) -> ScimUser {
        let mut u = template.clone();
        u.user.id = id.into();
        u.user.email = Some(email.into());
        u.user.status = if active { "active" } else { "disabled" }.into();
        u.external_id = Some(ext.into());
        u.user_name = email.into();
        u
    }

    fn template() -> ScimUser {
        let db = crate::db::Db::open(&crate::db::temp_path("google-plan").join("db.sqlite")).unwrap();
        let f = crate::db::ScimFields {
            user_name: "x@example.com",
            external_id: Some("0"),
            given_name: None,
            family_name: None,
            scim_display_name: None,
            formatted: None,
            display_name: "x",
            email: Some("x@example.com"),
            active: Some(true),
            enterprise: &Default::default(),
        };
        let u = db.create_scim_user("t", &f, Role::Member, None).unwrap();
        db.scim_user("t", &u.id).unwrap()
    }

    #[test]
    fn a_plan_creates_updates_holds_and_removes() {
        let ada = Person { id: "1".into(), email: "ada@example.com".into(), given: Some("Ada".into()), family: None, full: None, active: true, ..Default::default() };
        let bob = Person { id: "2".into(), email: "bob@example.com".into(), given: None, family: None, full: None, active: false, ..Default::default() };
        let cy = Person { id: "3".into(), email: "cy@example.com".into(), given: None, family: None, full: None, active: true, ..Default::default() };
        let new = Person { id: "4".into(), email: "new@example.com".into(), given: None, family: None, full: None, active: false, ..Default::default() };
        let back = Person { id: "5".into(), email: "back@example.com".into(), given: None, family: None, full: None, active: true, ..Default::default() };
        let t = template();
        let user = |id, ext, email, active| scim_user(&t, id, ext, email, active);
        let live = vec![user("u1", "1", "ada@example.com", true), user("u2", "2", "bob@example.com", true), user("u3", "3", "cy@example.com", false), user("u9", "9", "gone@example.com", true)];
        let gone = HashMap::from([("5".to_string(), "u5".to_string())]);
        let p = plan(&[&ada, &bob, &cy, &new, &back], &live, &gone, &|id| id == "u3" || id == "u5");
        assert_eq!(p.update.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(), vec!["u1", "u2"]);
        assert_eq!(p.update[1].1["active"], false);
        assert_eq!((p.disable, p.enable, p.skipped), (1, 0, 1));
        assert_eq!(p.held, vec!["u3".to_string(), "u5".to_string()]);
        assert_eq!(p.create.len(), 1);
        assert_eq!((p.create[0]["externalId"].as_str(), p.create[0]["active"].as_bool()), (Some("5"), Some(false)));
        assert_eq!(p.delete, vec!["u9".to_string()]);
        assert_eq!((p.removals(&live), p.active_after(&live)), (2, 1));
        let mut unchanged = user("u1", "1", "ada@example.com", true);
        unchanged.given_name = Some("Ada".into());
        assert_eq!(plan(&[&ada], &[unchanged], &HashMap::new(), &|_| true), Plan::default());
        let p2 = plan(&[&cy], &live[2..3], &HashMap::new(), &|_| false);
        assert_eq!((p2.enable, p2.update[0].1["active"].as_bool()), (1, Some(true)));
    }

    #[test]
    fn organizations_and_managers_become_the_enterprise_extension() {
        let p = person(&json!({
            "id": "7", "primaryEmail": "dee@example.com",
            "organizations": [{ "name": "Other", "department": "Sales" }, { "primary": true, "name": "Example Ltd", "department": "Platform\u{7}", "costCenter": "CC-42" }],
            "externalIds": [{ "type": "custom", "value": "x" }, { "type": "organization", "value": "E-0007" }],
            "relations": [{ "type": "assistant", "value": "x@example.com" }, { "type": "manager", "value": "Ada@Example.com" }],
        }))
        .unwrap();
        assert_eq!(
            (p.organization.as_deref(), p.department.as_deref(), p.cost_center.as_deref(), p.employee_number.as_deref(), p.manager.as_deref()),
            (Some("Example Ltd"), Some("Platform"), Some("CC-42"), Some("E-0007"), Some("ada@example.com"))
        );
        let bare = person(&json!({ "id": "8", "primaryEmail": "eve@example.com", "relations": [{ "type": "manager", "value": "not an email" }] })).unwrap();
        assert_eq!((bare.department, bare.manager), (None, None));

        // The manager is set once they have an account; never yourself.
        let ada = Person { id: "1".into(), email: "ada@example.com".into(), active: true, ..Default::default() };
        let dee = Person { manager: Some("ada@example.com".into()), ..p.clone() };
        let selfish = Person { id: "9".into(), email: "sam@example.com".into(), active: true, manager: Some("sam@example.com".into()), ..Default::default() };
        let first = plan(&[&ada, &dee], &[], &HashMap::new(), &|_| false);
        let made = first.create.iter().find(|b| b["externalId"] == "7").unwrap();
        assert_eq!(made[ENTERPRISE_SCHEMA], json!({ "employeeNumber": "E-0007", "organization": "Example Ltd", "department": "Platform", "costCenter": "CC-42" }));
        assert_eq!(made["schemas"], json!([USER_SCHEMA, ENTERPRISE_SCHEMA]));
        assert!(first.create.iter().find(|b| b["externalId"] == "1").unwrap().get(ENTERPRISE_SCHEMA).is_none());
        let t = template();
        let live = vec![scim_user(&t, "u1", "1", "ada@example.com", true), scim_user(&t, "u7", "7", "dee@example.com", true), scim_user(&t, "u9", "9", "sam@example.com", true)];
        let next = plan(&[&ada, &dee, &selfish], &live, &HashMap::new(), &|_| false);
        let ids: Vec<&str> = next.update.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, vec!["u7"], "Ada and Sam are unchanged: {:?}", next.update);
        assert_eq!(next.update[0].1[ENTERPRISE_SCHEMA]["manager"], json!({ "value": "u1" }));
    }

    #[test]
    fn failed_writes_are_retried_sooner() {
        let hour = Duration::from_secs(3600);
        assert_eq!(next_wait(&Ok(json!({ "failed": 0 })), hour), hour);
        assert_eq!(next_wait(&Ok(json!({ "failed": 2 })), hour), RETRY);
        assert_eq!(next_wait(&Err(fail("unreachable", "")), hour), RETRY);
        assert_eq!(next_wait(&Err(fail("running", "")), hour), hour);
        assert_eq!(next_wait(&Ok(json!({ "failed": 1 })), Duration::from_secs(60)), Duration::from_secs(60));
    }

    #[test]
    fn the_assertion_names_the_admin_and_the_scopes() {
        let der = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap().as_der().unwrap();
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", STANDARD.encode(der.as_ref()));
        let key = json!({ "type": "service_account", "client_email": "sync@project.iam.gserviceaccount.com", "private_key": pem, "private_key_id": "k1" }).to_string();
        let sa = service_account(&key).unwrap();
        assert_eq!(sa.token_uri, TOKEN_URI);
        let t = jwt(&sa, Some("admin@example.com")).unwrap();
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(t.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!((claims["sub"].as_str(), claims["scope"].as_str(), claims["aud"].as_str()), (Some("admin@example.com"), Some(SCOPES), Some(TOKEN_URI)));
        assert!(jwt(&sa, None).unwrap().split('.').nth(1).map(|c| !String::from_utf8(URL_SAFE_NO_PAD.decode(c).unwrap()).unwrap().contains("\"sub\"")).unwrap());
        assert!(service_account(&json!({ "type": "authorized_user" }).to_string()).is_err());
        assert!(service_account(&json!({ "type": "service_account", "client_email": "a@b", "private_key": pem, "token_uri": "http://token.example" }).to_string()).is_err());
    }
}
