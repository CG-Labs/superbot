//! Azure Key Vault as an external secrets `Provider` (ADR 0136), over its REST API.
//!
//! Key Vault names allow letters, digits and `-` only, and are case-insensitive, so
//! `<NAME>` in folder `<bots|server>` is the secret `<AZURE_KEYVAULT_PREFIX>-<bots|server>-<NAME>`
//! with each `_` written as `-` (`superbot-bots-OPENAI-API-KEY`). Secret names never hold a
//! `-`, so the mapping goes both ways. botd signs in to Microsoft Entra ID with a managed
//! identity (the VM's instance metadata service, or App Service's and Container Apps'
//! identity endpoint), a service principal's client secret, or a federated token file
//! (AKS workload identity), and gets a new token two thirds of the way through each one's
//! life and once more whenever Key Vault refuses it.

use super::external::{Provider, Scope};
use super::http::{self, Bearer, Worker};
use super::{Error, SecretStore};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const API_VERSION: &str = "7.4";
/// Key Vault's longest secret name.
const MAX_NAME: usize = 127;
const IMDS: &str = "http://169.254.169.254";
const AUTHORITY: &str = "https://login.microsoftonline.com";

pub enum Auth {
    /// A system-assigned identity, or the user-assigned one with this client id.
    ManagedIdentity { client_id: Option<String> },
    ClientSecret { tenant: String, client_id: String, secret: Zeroizing<String> },
    /// A token file the platform keeps fresh (AKS writes `AZURE_FEDERATED_TOKEN_FILE`),
    /// read again for every sign-in.
    WorkloadIdentity { tenant: String, client_id: String, token_file: PathBuf },
}

/// Where a managed identity's tokens come from.
pub enum Identity {
    /// The instance metadata service of a VM or VM scale set (and AKS nodes).
    Imds(String),
    /// App Service, Functions and Container Apps: `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`.
    Endpoint { url: String, header: Zeroizing<String> },
}

pub struct Config {
    /// `https://<vault>.vault.azure.net`, no trailing slash.
    pub url: String,
    /// What tokens are asked for: `https://vault.azure.net`, or a sovereign cloud's.
    pub resource: String,
    pub prefix: String,
    pub auth: Auth,
    pub authority: String,
    pub identity: Identity,
}

/// `superbot`: letters, digits and single `-`s inside, as Key Vault allows.
fn prefix_setting(raw: &str) -> Result<String, String> {
    let v = match raw.trim() {
        "" => "superbot",
        v => v,
    };
    if v.len() > 64 || v.starts_with('-') || v.ends_with('-') || v.contains("--") || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(format!("AZURE_KEYVAULT_PREFIX must be letters, digits and single hyphens, like \"superbot\", not {v:?}"));
    }
    Ok(v.to_ascii_lowercase())
}

/// A tenant or client id: a GUID, or a tenant's domain name.
fn id_setting(key: &str, raw: &str) -> Result<String, String> {
    let v = raw.trim();
    if v.is_empty() || v.len() > 128 || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)) {
        return Err(format!("{key} must be an id like 00000000-0000-0000-0000-000000000000, not {v:?}"));
    }
    Ok(v.to_string())
}

/// Tokens for `https://<name>.vault.azure.net` are for `https://vault.azure.net`; a
/// sovereign cloud's vault (`.vault.azure.cn`, `.vault.usgovcloudapi.net`) works the same.
fn resource_of(url: &url::Url) -> String {
    match url.host() {
        Some(url::Host::Domain(d)) if d.matches('.').count() >= 2 => format!("https://{}", d.split_once('.').map_or(d, |(_, rest)| rest)),
        _ => "https://vault.azure.net".into(),
    }
}

impl Config {
    /// `AZURE_*` settings; secrets come from `store` (the environment), so `_FILE` works.
    pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Config, String> {
        let raw = var("AZURE_KEYVAULT_URL");
        if raw.trim().is_empty() {
            return Err("SECRETS_BACKEND=azure-keyvault needs AZURE_KEYVAULT_URL, e.g. https://my-vault.vault.azure.net".into());
        }
        let url = http::base_url("AZURE_KEYVAULT_URL", &raw, "https://my-vault.vault.azure.net")?;
        let resource = resource_of(&url::Url::parse(&url).map_err(|e| e.to_string())?);
        let client_id = || id_setting("AZURE_CLIENT_ID", &var("AZURE_CLIENT_ID"));
        let tenant = || id_setting("AZURE_TENANT_ID", &var("AZURE_TENANT_ID"));
        let auth = match var("AZURE_KEYVAULT_AUTH").trim() {
            "" | "managed-identity" => Auth::ManagedIdentity { client_id: (!var("AZURE_CLIENT_ID").trim().is_empty()).then(client_id).transpose()? },
            "client-secret" => {
                let secret = store.get("AZURE_CLIENT_SECRET").map_err(|e| format!("AZURE_CLIENT_SECRET: {e}"))?;
                let secret = secret.ok_or("AZURE_KEYVAULT_AUTH=client-secret needs AZURE_CLIENT_SECRET (or AZURE_CLIENT_SECRET_FILE)")?;
                Auth::ClientSecret { tenant: tenant()?, client_id: client_id()?, secret: Zeroizing::new(secret.expose().to_string()) }
            }
            "workload-identity" => {
                let file = var("AZURE_FEDERATED_TOKEN_FILE");
                if file.trim().is_empty() {
                    return Err("AZURE_KEYVAULT_AUTH=workload-identity needs AZURE_FEDERATED_TOKEN_FILE (AKS sets it)".into());
                }
                Auth::WorkloadIdentity { tenant: tenant()?, client_id: client_id()?, token_file: PathBuf::from(file.trim()) }
            }
            other => return Err(format!("AZURE_KEYVAULT_AUTH must be managed-identity, client-secret or workload-identity, not {other:?}")),
        };
        let authority = match var("AZURE_AUTHORITY_HOST").trim() {
            "" => AUTHORITY.to_string(),
            a => http::base_url("AZURE_AUTHORITY_HOST", a, AUTHORITY)?,
        };
        let identity = match (var("IDENTITY_ENDPOINT").trim(), var("IDENTITY_HEADER")) {
            ("", _) => Identity::Imds(IMDS.into()),
            (endpoint, header) if !header.trim().is_empty() => {
                let u = url::Url::parse(endpoint).map_err(|e| format!("IDENTITY_ENDPOINT {endpoint:?}: {e}"))?;
                if !crate::tiers::encrypted_or_loopback(&u) && !matches!(u.host(), Some(url::Host::Ipv4(ip)) if ip.is_link_local()) {
                    return Err(format!("IDENTITY_ENDPOINT must be the platform's local identity endpoint, not {endpoint:?}"));
                }
                Identity::Endpoint { url: endpoint.to_string(), header: Zeroizing::new(header.trim().to_string()) }
            }
            _ => return Err("IDENTITY_ENDPOINT is set without IDENTITY_HEADER".into()),
        };
        Ok(Config { url, resource, prefix: prefix_setting(&var("AZURE_KEYVAULT_PREFIX"))?, auth, authority, identity })
    }
}

struct Inner {
    cfg: Config,
    http: reqwest::Client,
    /// For the managed identity endpoints: link-local, so never through a proxy.
    local: reqwest::Client,
    token: Mutex<Option<Bearer>>,
}

pub struct KeyVault {
    inner: Arc<Inner>,
    worker: Worker,
}

fn unavailable(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Unavailable(format!("Azure Key Vault: {what}: {e}"))
}

impl KeyVault {
    pub fn new(cfg: Config) -> Result<KeyVault, String> {
        let http = http::client("Azure Key Vault", None, false)?;
        let local = http::client("Azure Key Vault", None, true)?;
        Ok(KeyVault { inner: Arc::new(Inner { cfg, http, local, token: Mutex::new(None) }), worker: Worker::new("Azure Key Vault", "azure-keyvault")? })
    }
}

impl Inner {
    /// The Key Vault name for `name` in `scope`, or None if it would be too long to exist.
    fn vault_id(&self, scope: &Scope, name: &str) -> Option<String> {
        let n = format!("{}-{}-{}", self.cfg.prefix, scope.folder('-'), name.replace('_', "-"));
        (n.len() <= MAX_NAME).then_some(n)
    }

    /// The secret name back to botd's `NAME`, if it is in `scope`'s folder.
    fn name_in(&self, scope: &Scope, secret: &str) -> Option<String> {
        let head = format!("{}-{}-", self.cfg.prefix, scope.folder('-'));
        let rest = secret.get(..head.len()).filter(|h| h.eq_ignore_ascii_case(&head)).map(|_| &secret[head.len()..])?;
        (!rest.is_empty()).then(|| rest.replace('-', "_").to_ascii_uppercase())
    }

    fn method(&self) -> &'static str {
        match self.cfg.auth {
            Auth::ManagedIdentity { .. } => "managed-identity",
            Auth::ClientSecret { .. } => "client-secret",
            Auth::WorkloadIdentity { .. } => "workload-identity",
        }
    }

    /// The token to send; a new one if `fresh` (Key Vault refused the last) or it is due.
    async fn token(&self, fresh: bool) -> Result<Zeroizing<String>, Error> {
        if !fresh && let Some(t) = self.token.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|t| t.fresh()) {
            return Ok(t.value.clone());
        }
        let result = self.sign_in().await;
        http::audit_login("azure-keyvault", self.method(), &result);
        let t = result?;
        let value = t.value.clone();
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = Some(t);
        Ok(value)
    }

    async fn sign_in(&self) -> Result<Bearer, Error> {
        let c = &self.cfg;
        let scope = format!("{}/.default", c.resource);
        let req = match &c.auth {
            Auth::ManagedIdentity { client_id } => {
                let mut q = vec![("resource", c.resource.as_str())];
                if let Some(id) = client_id {
                    q.push(("client_id", id));
                }
                match &c.identity {
                    Identity::Imds(base) => {
                        q.push(("api-version", "2018-02-01"));
                        self.local.get(http::with_query(&format!("{base}/metadata/identity/oauth2/token"), &q)?).header("Metadata", "true")
                    }
                    Identity::Endpoint { url, header } => {
                        q.push(("api-version", "2019-08-01"));
                        self.local.get(http::with_query(url, &q)?).header("X-IDENTITY-HEADER", header.as_str())
                    }
                }
            }
            Auth::ClientSecret { tenant, client_id, secret } => {
                let form = [("grant_type", "client_credentials"), ("client_id", client_id), ("client_secret", secret), ("scope", &scope)];
                self.http.post(format!("{}/{tenant}/oauth2/v2.0/token", c.authority)).form(&form)
            }
            Auth::WorkloadIdentity { tenant, client_id, token_file } => {
                let text = Zeroizing::new(std::fs::read_to_string(token_file).map_err(|e| unavailable("AZURE_FEDERATED_TOKEN_FILE", e))?);
                let assertion = text.trim();
                if assertion.is_empty() {
                    return Err(Error::Unavailable("Azure Key Vault: AZURE_FEDERATED_TOKEN_FILE is empty".into()));
                }
                let form = [
                    ("grant_type", "client_credentials"),
                    ("client_id", client_id),
                    ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    ("client_assertion", assertion),
                    ("scope", &scope),
                ];
                self.http.post(format!("{}/{tenant}/oauth2/v2.0/token", c.authority)).form(&form)
            }
        };
        let what = format!("{} sign-in", self.method());
        let res = req.send().await.map_err(|e| unavailable(&what, e))?;
        let status = res.status();
        let body = Zeroizing::new(res.bytes().await.map_err(|e| unavailable(&what, e))?.to_vec());
        if !status.is_success() {
            return Err(Error::Unavailable(format!("Azure Key Vault: {what} answered {status}{}", http::error_code(&body))));
        }
        let v: Value = serde_json::from_slice(&body).map_err(|e| unavailable(&what, e))?;
        let token = v["access_token"].as_str().filter(|t| !t.is_empty()).ok_or_else(|| Error::Unavailable(format!("Azure Key Vault: {what} gave no token")))?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let lifetime = http::seconds(&v["expires_in"]).or_else(|| http::seconds(&v["expires_on"]).map(|at| at.saturating_sub(now)));
        Ok(Bearer::new(token, lifetime))
    }

    /// GETs `url`; when Key Vault refuses the token, gets a new one and asks once more.
    /// None for 404.
    async fn get(&self, url: &str, what: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        for fresh in [false, true] {
            let token = self.token(fresh).await?;
            let res = self.http.get(url).bearer_auth(token.as_str()).send().await.map_err(|e| unavailable(what, e))?;
            let status = res.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && !fresh {
                continue;
            }
            let body = Zeroizing::new(res.bytes().await.map_err(|e| unavailable(what, e))?.to_vec());
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(Error::Unavailable(format!("Azure Key Vault answered {status}{} for {what}", http::error_code(&body))));
            }
            return Ok(Some(body));
        }
        unreachable!("the second pass returns")
    }

    async fn read(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let Some(id) = self.vault_id(&scope, name) else { return Ok(None) };
        let url = format!("{}/secrets/{id}?api-version={API_VERSION}", self.cfg.url);
        let Some(body) = self.get(&url, &id).await? else { return Ok(None) };
        let v: Value = serde_json::from_slice(&body).map_err(|e| unavailable(&id, e))?;
        // A disabled secret is refused (403) before this; anything else odd fails closed
        // rather than being read as "not there", which would uncover the sealed copy.
        if v["attributes"]["enabled"] == false {
            return Err(Error::Unavailable(format!("Azure Key Vault: {id} is disabled")));
        }
        match v["value"].as_str() {
            Some("") => Ok(None),
            Some(s) => Ok(Some(Zeroizing::new(s.to_string()))),
            None => Err(Error::Unavailable(format!("Azure Key Vault: {id} gave an answer with no value"))),
        }
    }

    async fn list(&self, scope: Scope) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        let mut next = Some(format!("{}/secrets?api-version={API_VERSION}&maxresults=25", self.cfg.url));
        let mut pages = 0;
        while let Some(url) = next.take() {
            pages += 1;
            if pages > 1000 {
                return Err(Error::Unavailable("Azure Key Vault: listing secrets ran past 1000 pages".into()));
            }
            // A token is only ever sent to the configured vault.
            if !url.starts_with(&format!("{}/", self.cfg.url)) {
                return Err(Error::Unavailable("Azure Key Vault: the list's next page is on another host".into()));
            }
            let body = self.get(&url, "listing secrets").await?.ok_or_else(|| Error::Unavailable("Azure Key Vault: listing secrets answered 404".into()))?;
            let v: Value = serde_json::from_slice(&body).map_err(|e| unavailable("listing secrets", e))?;
            let items = v["value"].as_array().ok_or_else(|| Error::Unavailable("Azure Key Vault: listing secrets gave no list".into()))?;
            // A short list would hide cloud-only keys and uncover sealed copies, so odd entries fail closed.
            for item in items {
                let id = item["id"].as_str().and_then(|id| id.split_once("/secrets/")).map(|(_, s)| s).filter(|s| !s.is_empty() && !s.contains('/'));
                let id = id.ok_or_else(|| Error::Unavailable("Azure Key Vault: listing secrets gave an entry with no secret id".into()))?;
                if let Some(name) = self.name_in(&scope, id) {
                    out.push(name);
                }
            }
            next = match &v["nextLink"] {
                Value::Null => None,
                Value::String(s) if s.is_empty() => None,
                Value::String(s) => Some(s.clone()),
                _ => return Err(Error::Unavailable("Azure Key Vault: listing secrets gave a nextLink that isn't text".into())),
            };
        }
        Ok(out)
    }
}

impl Provider for KeyVault {
    fn kind(&self) -> &'static str {
        "azure-keyvault"
    }

    fn describe(&self) -> String {
        let c = &self.inner.cfg;
        let auth = match &c.auth {
            Auth::ManagedIdentity { client_id: Some(id) } => format!("user-assigned managed identity {id}"),
            Auth::ManagedIdentity { client_id: None } => "managed identity".to_string(),
            Auth::ClientSecret { tenant, client_id, .. } => format!("service principal {client_id} in tenant {tenant}"),
            Auth::WorkloadIdentity { tenant, client_id, .. } => format!("workload identity {client_id} in tenant {tenant}"),
        };
        format!("Azure Key Vault at {}, secrets {}-{{bots,server}}-<NAME>, {auth}", c.url, c.prefix)
    }

    fn read(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let (inner, name) = (Arc::clone(&self.inner), name.to_string());
        self.worker.run(async move { inner.read(scope, &name).await })
    }

    fn list(&self, scope: Scope) -> Result<Vec<String>, Error> {
        let inner = Arc::clone(&self.inner);
        self.worker.run(async move { inner.list(scope).await })
    }
}

#[cfg(test)]
mod tests {
    use super::super::env::EnvStore;
    use super::super::external::{tests::audited, ExternalStore};
    use super::super::http::tests::{serve, settings};
    use super::super::{redact, sealed, Secrets};
    use super::*;
    use crate::audit::Outcome;
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::{Form, Json};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    /// A stand-in for Key Vault, Entra ID's token endpoint and the managed identity
    /// endpoints: no real Azure, account or network.
    #[derive(Default)]
    struct Fake {
        /// Key Vault name → (value, enabled).
        secrets: Mutex<HashMap<String, (String, bool)>>,
        tokens: Mutex<Vec<String>>,
        sign_ins: AtomicUsize,
        reads: AtomicUsize,
        down: AtomicBool,
        /// Lists hand out a next page on another host.
        evil: AtomicBool,
        /// Lists answer oddly: 1 = an entry with no id, 2 = a nextLink that isn't text.
        odd_list: AtomicUsize,
        expires_in: AtomicUsize,
        /// What the last sign-in asked for.
        asked: Mutex<Vec<HashMap<String, String>>>,
    }

    type F = Arc<Fake>;

    fn issue(f: &Fake, asked: HashMap<String, String>) -> Json<Value> {
        let n = f.sign_ins.fetch_add(1, Ordering::SeqCst);
        let token = format!("eyJ.azure-{n}");
        f.tokens.lock().unwrap().push(token.clone());
        f.asked.lock().unwrap().push(asked);
        Json(json!({ "token_type": "Bearer", "access_token": token, "expires_in": f.expires_in.load(Ordering::SeqCst).to_string() }))
    }

    fn authorized(f: &Fake, h: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
        if f.down.load(Ordering::SeqCst) {
            return Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": { "code": "ServiceUnavailable", "message": "try later" } }))));
        }
        let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default();
        if !f.tokens.lock().unwrap().iter().any(|t| auth == format!("Bearer {t}")) {
            return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": { "code": "Unauthorized", "message": "AKV10000" } }))));
        }
        Ok(())
    }

    async fn imds(State(f): State<F>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if h.get("metadata").and_then(|v| v.to_str().ok()) != Some("true") || q.get("api-version").map(String::as_str) != Some("2018-02-01") {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_request" })));
        }
        (StatusCode::OK, issue(&f, q))
    }

    async fn app_service(State(f): State<F>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if h.get("x-identity-header").and_then(|v| v.to_str().ok()) != Some("identity-header-1") {
            return (StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden" })));
        }
        (StatusCode::OK, issue(&f, q))
    }

    async fn entra(State(f): State<F>, Path(tenant): Path<String>, Form(form): Form<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
        let ok = tenant == "tenant-1"
            && form.get("client_id").map(String::as_str) == Some("client-1")
            && form.get("grant_type").map(String::as_str) == Some("client_credentials")
            && (form.get("client_secret").map(String::as_str) == Some("sp-secret-1") || form.get("client_assertion").map(String::as_str) == Some("federated-jwt-1"));
        if !ok {
            return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided." })));
        }
        (StatusCode::OK, issue(&f, form))
    }

    async fn secret(State(f): State<F>, Path(name): Path<String>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if let Err(e) = authorized(&f, &h) {
            return e;
        }
        assert_eq!(q.get("api-version").map(String::as_str), Some(API_VERSION));
        f.reads.fetch_add(1, Ordering::SeqCst);
        if name == "superbot-bots-MALFORMED-TOKEN" {
            return (StatusCode::OK, Json(json!({ "id": "x" })));
        }
        // Key Vault's names are case-insensitive.
        let found = f.secrets.lock().unwrap().iter().find(|(k, _)| k.eq_ignore_ascii_case(&name)).map(|(_, v)| v.clone());
        match found {
            Some((_, false)) => (StatusCode::FORBIDDEN, Json(json!({ "error": { "code": "Forbidden", "message": "Operation get is not allowed on a disabled secret." } }))),
            Some((v, true)) => (StatusCode::OK, Json(json!({ "value": v, "id": format!("https://kv/secrets/{name}/abc"), "attributes": { "enabled": true } }))),
            None => (StatusCode::NOT_FOUND, Json(json!({ "error": { "code": "SecretNotFound", "message": "not found" } }))),
        }
    }

    async fn list(State(f): State<F>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if let Err(e) = authorized(&f, &h) {
            return e;
        }
        let mut names: Vec<String> = f.secrets.lock().unwrap().keys().cloned().collect();
        names.sort();
        // Two to a page, to follow nextLink.
        let skip: usize = q.get("skip").and_then(|s| s.parse().ok()).unwrap_or(0);
        let mut page: Vec<Value> = names.iter().skip(skip).take(2).map(|n| json!({ "id": format!("https://kv.example/secrets/{n}"), "attributes": { "enabled": true } })).collect();
        match f.odd_list.load(Ordering::SeqCst) {
            1 => page.push(json!({ "attributes": { "enabled": true } })),
            2 => return (StatusCode::OK, Json(json!({ "value": page, "nextLink": 7 }))),
            _ => {}
        }
        let base = h.get("host").and_then(|v| v.to_str().ok()).unwrap_or_default();
        let next = (skip + 2 < names.len()).then(|| match f.evil.load(Ordering::SeqCst) {
            true => "https://elsewhere.example/secrets?skip=2".to_string(),
            false => format!("http://{base}/secrets?api-version={API_VERSION}&skip={}", skip + 2),
        });
        (StatusCode::OK, Json(json!({ "value": page, "nextLink": next })))
    }

    fn stand_in() -> (String, F) {
        let f = F::default();
        f.expires_in.store(86_399, Ordering::SeqCst);
        let app = axum::Router::new()
            .route("/metadata/identity/oauth2/token", axum::routing::get(imds))
            .route("/msi/token", axum::routing::get(app_service))
            .route("/{tenant}/oauth2/v2.0/token", axum::routing::post(entra))
            .route("/secrets/{name}", axum::routing::get(secret))
            .route("/secrets", axum::routing::get(list))
            .with_state(Arc::clone(&f));
        (serve(app), f)
    }

    fn put(f: &Fake, name: &str, value: &str) {
        f.secrets.lock().unwrap().insert(name.to_string(), (value.to_string(), true));
    }

    fn config(url: &str, extra: &[(&str, &str)]) -> Config {
        let mut pairs = vec![("SECRETS_BACKEND", "azure-keyvault"), ("AZURE_KEYVAULT_URL", url), ("AZURE_AUTHORITY_HOST", url)];
        pairs.extend_from_slice(extra);
        let mut cfg = Config::from_env(&settings(&pairs), &EnvStore::fixed(extra)).unwrap();
        if let Identity::Imds(_) = cfg.identity {
            cfg.identity = Identity::Imds(url.to_string());
        }
        cfg
    }

    fn store(url: &str, extra: &[(&str, &str)], ttl: Duration) -> Arc<ExternalStore> {
        Arc::new(ExternalStore::new(Box::new(KeyVault::new(config(url, extra)).unwrap()), ttl))
    }

    #[test]
    fn reads_bot_and_server_secrets_with_a_managed_identity() {
        let (url, f) = stand_in();
        let bot_value = format!("sk-azure-{}", crate::random_hex(10));
        put(&f, "superbot-bots-OPENAI-API-KEY", &bot_value);
        put(&f, "superbot-bots-LINODE-TOKEN", "never-from-the-bots-folder");
        put(&f, "SuperBot-Server-linode-token", "linode-from-azure-1");
        put(&f, "other-app-SECRET", "not-ours");
        put(&f, "superbot-bots-", "no-name");
        let s = store(&url, &[("AZURE_CLIENT_ID", "user-assigned-1")], Duration::from_secs(60));
        assert_eq!(s.check().unwrap(), 2, "OPENAI_API_KEY and LINODE_TOKEN, each from its own folder, across pages");
        assert_eq!(s.get("OPENAI_API_KEY").unwrap().unwrap().expose(), bot_value);
        assert_eq!(s.get("LINODE_TOKEN").unwrap().unwrap().expose(), "linode-from-azure-1");
        assert!(s.get("NOT_THERE_TOKEN").unwrap().is_none());
        let reads = f.reads.load(Ordering::SeqCst);
        s.get("OPENAI_API_KEY").unwrap();
        assert_eq!(f.reads.load(Ordering::SeqCst), reads, "cached");
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 1, "the token is kept while it lasts");
        let asked = f.asked.lock().unwrap()[0].clone();
        assert_eq!((asked["resource"].as_str(), asked["client_id"].as_str()), ("https://vault.azure.net", "user-assigned-1"));
        assert_eq!(redact::text(&bot_value), redact::MARK);

        // Through `Secrets`: env, then Key Vault, then the sealed store.
        let path = crate::db::temp_path("azure-facade").join("app.sqlite");
        let sealed = sealed::SealedStore::new(sealed::connect(&path).unwrap(), sealed::cipher());
        let secrets = Secrets::new(vec![Box::new(EnvStore::fixed(&[])), Box::new(super::super::external::Shared(Arc::clone(&s))), Box::new(sealed)]);
        secrets.put("OPENAI_API_KEY", "sealed-but-shadowed-azure").unwrap();
        let env: Vec<(String, String)> = secrets.try_harness_env().unwrap().into_iter().map(|(k, v)| (k, v.expose().to_string())).collect();
        assert_eq!(env, [("OPENAI_API_KEY".to_string(), bot_value.clone())], "Key Vault's value wins, and botd's own never reach Bots");
        assert_eq!(secrets.source("LINODE_TOKEN").unwrap(), Some(("azure-keyvault", false)));
        let logins = audited("azure-keyvault");
        assert!(logins.iter().any(|e| e.action == "secret.backend_login" && e.details["method"] == "managed-identity" && e.outcome == Outcome::Success), "{logins:?}");
        for v in [bot_value.as_str(), "linode-from-azure-1", "sealed-but-shadowed-azure"] {
            redact::forget(v);
        }
    }

    #[test]
    fn a_service_principal_signs_in_again_when_refused() {
        let (url, f) = stand_in();
        put(&f, "superbot-server-SMTP-PASSWORD", "smtp-from-azure-1");
        let creds = [("AZURE_KEYVAULT_AUTH", "client-secret"), ("AZURE_TENANT_ID", "tenant-1"), ("AZURE_CLIENT_ID", "client-1"), ("AZURE_CLIENT_SECRET", "sp-secret-1")];
        let s = store(&url, &creds, Duration::ZERO);
        assert_eq!(s.get("SMTP_PASSWORD").unwrap().unwrap().expose(), "smtp-from-azure-1");
        s.get("SMTP_PASSWORD").unwrap();
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 1);
        assert_eq!(f.asked.lock().unwrap()[0]["scope"], "https://vault.azure.net/.default");
        f.tokens.lock().unwrap().clear();
        assert!(s.get("SMTP_PASSWORD").unwrap().is_some(), "refused: signs in once more and retries");
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 2);

        // A token that lasts 3 s is renewed after 2.
        f.expires_in.store(3, Ordering::SeqCst);
        let s = store(&url, &creds, Duration::ZERO);
        s.get("SMTP_PASSWORD").unwrap();
        let before = f.sign_ins.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(2100));
        s.get("SMTP_PASSWORD").unwrap();
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), before + 1);

        let bad = store(&url, &[("AZURE_KEYVAULT_AUTH", "client-secret"), ("AZURE_TENANT_ID", "tenant-1"), ("AZURE_CLIENT_ID", "client-1"), ("AZURE_CLIENT_SECRET", "wrong-1")], Duration::ZERO);
        let e = bad.check().unwrap_err().to_string();
        assert!(e.contains("401") && e.contains("invalid_client") && !e.contains("AADSTS"), "{e}");
        let logins = audited("azure-keyvault");
        assert!(logins.iter().any(|e| e.outcome == Outcome::Failure && e.details["method"] == "client-secret"));
        assert!(!format!("{logins:?}").contains("sp-secret-1"));
        redact::forget("smtp-from-azure-1");
    }

    #[test]
    fn workload_identity_and_app_service_identities_sign_in() {
        let (url, f) = stand_in();
        put(&f, "superbot-bots-FED-TOKEN", "fed-value-1");
        let file = crate::db::temp_path("azure-fed").join("token");
        std::fs::write(&file, "federated-jwt-1\n").unwrap();
        let s = store(&url, &[("AZURE_KEYVAULT_AUTH", "workload-identity"), ("AZURE_TENANT_ID", "tenant-1"), ("AZURE_CLIENT_ID", "client-1"), ("AZURE_FEDERATED_TOKEN_FILE", file.to_str().unwrap())], Duration::ZERO);
        assert_eq!(s.get("FED_TOKEN").unwrap().unwrap().expose(), "fed-value-1");
        assert_eq!(f.asked.lock().unwrap().last().unwrap()["client_assertion_type"], "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");

        let endpoint = format!("{url}/msi/token");
        let s = store(&url, &[("IDENTITY_ENDPOINT", &endpoint), ("IDENTITY_HEADER", "identity-header-1")], Duration::ZERO);
        assert_eq!(s.get("FED_TOKEN").unwrap().unwrap().expose(), "fed-value-1");
        assert_eq!(f.asked.lock().unwrap().last().unwrap()["api-version"], "2019-08-01");
        redact::forget("fed-value-1");
    }

    #[test]
    fn key_vault_down_disabled_or_odd_fails_closed() {
        let (url, f) = stand_in();
        put(&f, "superbot-bots-DOWN-API-KEY", "down-azure-value-1");
        f.secrets.lock().unwrap().insert("superbot-bots-DISABLED-TOKEN".into(), ("disabled-value-1".into(), false));
        let s = store(&url, &[], Duration::from_millis(200));
        let path = crate::db::temp_path("azure-down").join("app.sqlite");
        let sealed = sealed::SealedStore::new(sealed::connect(&path).unwrap(), sealed::cipher());
        let secrets = Secrets::new(vec![Box::new(EnvStore::fixed(&[])), Box::new(super::super::external::Shared(Arc::clone(&s))), Box::new(sealed)]);
        for n in ["DOWN_API_KEY", "DISABLED_TOKEN", "MALFORMED_TOKEN"] {
            secrets.put(n, "the-sealed-fallback-azure").unwrap();
        }
        assert_eq!(secrets.get("DOWN_API_KEY").unwrap().unwrap().expose(), "down-azure-value-1");
        let e = secrets.get("DISABLED_TOKEN").unwrap_err().to_string();
        assert!(e.contains("403") && e.contains("Forbidden"), "a disabled secret never uncovers the sealed copy: {e}");
        assert!(matches!(secrets.get("MALFORMED_TOKEN"), Err(Error::Unavailable(_))));
        f.down.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(250));
        assert!(matches!(secrets.get("DOWN_API_KEY"), Err(Error::Unavailable(_))), "never the sealed value under it");
        assert!(matches!(secrets.try_harness_env(), Err(Error::Unavailable(_))));
        assert!(audited("DOWN_API_KEY").iter().any(|e| e.outcome == Outcome::Failure && e.details["store"] == "azure-keyvault"));
        f.down.store(false, Ordering::SeqCst);
        assert!(secrets.get("DOWN_API_KEY").unwrap().is_some());
        redact::forget("down-azure-value-1");
        redact::forget("the-sealed-fallback-azure");
    }

    #[test]
    fn tokens_go_only_to_the_vault() {
        let (url, f) = stand_in();
        for n in ["A", "B", "C"] {
            put(&f, &format!("superbot-bots-{n}-TOKEN"), "v");
        }
        let s = store(&url, &[], Duration::ZERO);
        assert_eq!(s.check().unwrap(), 3);
        f.evil.store(true, Ordering::SeqCst);
        let e = s.check().unwrap_err().to_string();
        assert!(e.contains("another host"), "a next page elsewhere is refused before a token is sent there: {e}");
        f.evil.store(false, Ordering::SeqCst);
        for (odd, err) in [(1, "no secret id"), (2, "nextLink that isn't text")] {
            f.odd_list.store(odd, Ordering::SeqCst);
            let e = s.check().unwrap_err().to_string();
            assert!(e.contains(err), "an odd list fails closed rather than coming back short: {e}");
        }
    }

    #[test]
    fn names_map_onto_key_vaults_rules() {
        let (url, _) = stand_in();
        let kv = KeyVault::new(config(&url, &[("AZURE_KEYVAULT_PREFIX", "Acme-SuperBot")])).unwrap();
        let i = &kv.inner;
        assert_eq!(i.vault_id(&Scope::Bots, "OPENAI_API_KEY").as_deref(), Some("acme-superbot-bots-OPENAI-API-KEY"));
        assert_eq!(i.name_in(&Scope::Bots, "ACME-SUPERBOT-BOTS-openai-api-key").as_deref(), Some("OPENAI_API_KEY"));
        assert_eq!(i.name_in(&Scope::Server, "acme-superbot-bots-X"), None);
        assert_eq!(i.vault_id(&Scope::Server, &"A".repeat(120)), None, "too long to exist in Key Vault");
        let ua1 = Scope::user("ua1").unwrap();
        assert_eq!(i.vault_id(&ua1, "OPENAI_API_KEY").as_deref(), Some("acme-superbot-users-ua1-OPENAI-API-KEY"));
        assert_eq!(i.name_in(&ua1, "ACME-SUPERBOT-USERS-UA1-openai-api-key").as_deref(), Some("OPENAI_API_KEY"));
        assert_eq!(i.name_in(&ua1, "acme-superbot-users-ua10-OPENAI-API-KEY"), None, "another user's, whose id starts the same");
        assert_eq!(i.name_in(&Scope::Bots, "acme-superbot-users-ua1-X"), None);
        assert_eq!(resource_of(&url::Url::parse("https://kv1.vault.azure.cn").unwrap()), "https://vault.azure.cn");
        assert_eq!(resource_of(&url::Url::parse("https://kv1.vault.usgovcloudapi.net").unwrap()), "https://vault.usgovcloudapi.net");
    }

    #[test]
    fn settings_are_checked() {
        let env = EnvStore::fixed(&[("AZURE_CLIENT_SECRET", "s")]);
        let ok = |pairs: &[(&str, &str)]| Config::from_env(&settings(pairs), &env);
        let c = ok(&[("AZURE_KEYVAULT_URL", "https://kv1.vault.azure.net/")]).unwrap();
        assert_eq!((c.url.as_str(), c.resource.as_str(), c.prefix.as_str(), c.authority.as_str()), ("https://kv1.vault.azure.net", "https://vault.azure.net", "superbot", AUTHORITY));
        assert!(matches!(c.auth, Auth::ManagedIdentity { client_id: None }) && matches!(c.identity, Identity::Imds(_)));
        let kv = "https://kv1.vault.azure.net";
        for (pairs, err) in [
            (vec![], "needs AZURE_KEYVAULT_URL"),
            (vec![("AZURE_KEYVAULT_URL", "http://kv1.vault.azure.net")], "must use https"),
            (vec![("AZURE_KEYVAULT_URL", "https://kv1.vault.azure.net/secrets")], "just the scheme"),
            (vec![("AZURE_KEYVAULT_URL", kv), ("AZURE_KEYVAULT_PREFIX", "super_bot")], "AZURE_KEYVAULT_PREFIX"),
            (vec![("AZURE_KEYVAULT_URL", kv), ("AZURE_KEYVAULT_AUTH", "password")], "managed-identity, client-secret or workload-identity"),
            (vec![("AZURE_KEYVAULT_URL", kv), ("AZURE_KEYVAULT_AUTH", "client-secret")], "AZURE_TENANT_ID"),
            (vec![("AZURE_KEYVAULT_URL", kv), ("AZURE_KEYVAULT_AUTH", "client-secret"), ("AZURE_TENANT_ID", "t")], "AZURE_CLIENT_ID"),
            (vec![("AZURE_KEYVAULT_URL", kv), ("AZURE_KEYVAULT_AUTH", "workload-identity"), ("AZURE_TENANT_ID", "t"), ("AZURE_CLIENT_ID", "c")], "AZURE_FEDERATED_TOKEN_FILE"),
            (vec![("AZURE_KEYVAULT_URL", kv), ("AZURE_AUTHORITY_HOST", "http://login.example")], "AZURE_AUTHORITY_HOST must use https"),
            (vec![("AZURE_KEYVAULT_URL", kv), ("IDENTITY_ENDPOINT", "http://127.0.0.1:41000/msi/token")], "without IDENTITY_HEADER"),
            (vec![("AZURE_KEYVAULT_URL", kv), ("IDENTITY_ENDPOINT", "http://evil.example/t"), ("IDENTITY_HEADER", "h")], "local identity endpoint"),
        ] {
            let e = ok(&pairs).err().unwrap_or_default();
            assert!(e.contains(err), "{pairs:?}: {e}");
        }
        let none = EnvStore::fixed(&[]);
        let pairs = settings(&[("AZURE_KEYVAULT_URL", kv), ("AZURE_KEYVAULT_AUTH", "client-secret"), ("AZURE_TENANT_ID", "t"), ("AZURE_CLIENT_ID", "c")]);
        assert!(Config::from_env(&pairs, &none).err().unwrap().contains("AZURE_CLIENT_SECRET"));
        let c = Config::from_env(&settings(&[("AZURE_KEYVAULT_URL", kv), ("IDENTITY_ENDPOINT", "http://169.254.130.1:8081/msi/token"), ("IDENTITY_HEADER", "h")]), &none).unwrap();
        assert!(matches!(c.identity, Identity::Endpoint { .. }));
    }
}
