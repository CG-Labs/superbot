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
//!
//! It is also the `leases::Issuer` of `AZURE_RUN_CREDENTIALS` (ADR 0213): an access token
//! of an Entra app that trusts botd's user-assigned managed identity or workload identity
//! as a federated credential, made for each run by trading botd's own token for the
//! app's. Entra can't revoke one, so it is let go at its expiry. A multitenant app's token
//! may come from another tenant it is provisioned in, with the same assertion (ADR 0250).

use super::external::{self, Provider, Scope};
use super::http::{self, Bearer, Worker};
use super::leases::{Field, Issuer, Lease, Narrowed};
use super::{Error, SecretStore};
use crate::audit::{Event, Outcome};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

const API_VERSION: &str = "7.4";
/// Key Vault's longest secret name.
const MAX_NAME: usize = 127;
const IMDS: &str = "http://169.254.169.254";
const AUTHORITY: &str = "https://login.microsoftonline.com";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// The longest app token botd takes; Entra's are a few kilobytes.
const MAX_TOKEN: usize = 16_384;

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
    /// `AZURE_TENANT_ID` with a managed identity: where `AZURE_RUN_CREDENTIALS`' apps are.
    /// Checked only when that is set.
    pub tenant: Option<String>,
}

/// The audience a managed identity's token must have for Entra to trade it for an app's,
/// in the cloud `authority` signs in to.
fn exchange_audience(authority: &str) -> &'static str {
    match cloud(authority) {
        Cloud::UsGov => "api://AzureADTokenExchangeUSGov",
        Cloud::China => "api://AzureADTokenExchangeChina",
        Cloud::Global => "api://AzureADTokenExchange",
    }
}

/// Azure Resource Manager in that cloud: what an `AZURE_RUN_CREDENTIALS` entry with no
/// `@resource` gets tokens for.
fn arm_host(authority: &str) -> &'static str {
    match cloud(authority) {
        Cloud::UsGov => "management.usgovcloudapi.net",
        Cloud::China => "management.chinacloudapi.cn",
        Cloud::Global => "management.azure.com",
    }
}

enum Cloud {
    Global,
    UsGov,
    China,
}

fn cloud(authority: &str) -> Cloud {
    let host = url::Url::parse(authority).ok().and_then(|u| u.host_str().map(str::to_ascii_lowercase)).unwrap_or_default();
    if host.ends_with(".us") {
        Cloud::UsGov
    } else if host.ends_with(".cn") {
        Cloud::China
    } else {
        Cloud::Global
    }
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

/// How botd signs in to Entra ID as itself: the method `method_var` names (with `method`
/// its value) and the shared `AZURE_*` settings. Key Vault reads `AZURE_KEYVAULT_AUTH`;
/// the audit export's Azure Monitor sink, `AUDIT_EXPORT_AZURE_AUTH` (ADR 0217).
fn sign_in_settings(var: &dyn Fn(&str) -> String, store: &dyn SecretStore, method_var: &str, method: &str) -> Result<(Auth, String, Identity), String> {
    let client_id = || id_setting("AZURE_CLIENT_ID", &var("AZURE_CLIENT_ID"));
    let tenant = || id_setting("AZURE_TENANT_ID", &var("AZURE_TENANT_ID"));
    let auth = match method.trim() {
        "" | "managed-identity" => Auth::ManagedIdentity { client_id: (!var("AZURE_CLIENT_ID").trim().is_empty()).then(client_id).transpose()? },
        "client-secret" => {
            let secret = store.get("AZURE_CLIENT_SECRET").map_err(|e| format!("AZURE_CLIENT_SECRET: {e}"))?;
            let secret = secret.ok_or(format!("{method_var}=client-secret needs AZURE_CLIENT_SECRET (or AZURE_CLIENT_SECRET_FILE)"))?;
            super::redact::register(secret.expose());
            Auth::ClientSecret { tenant: tenant()?, client_id: client_id()?, secret: Zeroizing::new(secret.expose().to_string()) }
        }
        "workload-identity" => {
            let file = var("AZURE_FEDERATED_TOKEN_FILE");
            if file.trim().is_empty() {
                return Err(format!("{method_var}=workload-identity needs AZURE_FEDERATED_TOKEN_FILE (AKS sets it)"));
            }
            Auth::WorkloadIdentity { tenant: tenant()?, client_id: client_id()?, token_file: PathBuf::from(file.trim()) }
        }
        other => return Err(format!("{method_var} must be managed-identity, client-secret or workload-identity, not {other:?}")),
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
    Ok((auth, authority, identity))
}

fn method_of(auth: &Auth) -> &'static str {
    match auth {
        Auth::ManagedIdentity { .. } => "managed-identity",
        Auth::ClientSecret { .. } => "client-secret",
        Auth::WorkloadIdentity { .. } => "workload-identity",
    }
}

/// Who botd signs in as, for startup lines: never a credential.
fn signs_in_as(auth: &Auth) -> String {
    match auth {
        Auth::ManagedIdentity { client_id: Some(id) } => format!("user-assigned managed identity {id}"),
        Auth::ManagedIdentity { client_id: None } => "managed identity".to_string(),
        Auth::ClientSecret { tenant, client_id, .. } => format!("service principal {client_id} in tenant {tenant}"),
        Auth::WorkloadIdentity { tenant, client_id, .. } => format!("workload identity {client_id} in tenant {tenant}"),
    }
}

fn token_url(authority: &str, tenant: &str) -> String {
    format!("{authority}/{tenant}/oauth2/v2.0/token")
}

/// A request for the managed identity's token for `resource`, from the VM's instance
/// metadata service or the platform's identity endpoint.
fn managed_identity(local: &reqwest::Client, identity: &Identity, resource: &str, client_id: Option<&str>) -> Result<reqwest::RequestBuilder, Error> {
    let mut q = vec![("resource", resource)];
    if let Some(id) = client_id {
        q.push(("client_id", id));
    }
    Ok(match identity {
        Identity::Imds(base) => {
            q.push(("api-version", "2018-02-01"));
            local.get(http::with_query(&format!("{base}/metadata/identity/oauth2/token"), &q)?).header("Metadata", "true")
        }
        Identity::Endpoint { url, header } => {
            q.push(("api-version", "2019-08-01"));
            local.get(http::with_query(url, &q)?).header("X-IDENTITY-HEADER", header.as_str())
        }
    })
}

/// The federated token the platform keeps in `AZURE_FEDERATED_TOKEN_FILE`, read afresh.
fn federated_token(label: &str, token_file: &std::path::Path) -> Result<Zeroizing<String>, Error> {
    let text = Zeroizing::new(std::fs::read_to_string(token_file).map_err(|e| Error::Unavailable(format!("{label}: AZURE_FEDERATED_TOKEN_FILE: {e}")))?);
    let assertion = text.trim();
    if assertion.is_empty() {
        return Err(Error::Unavailable(format!("{label}: AZURE_FEDERATED_TOKEN_FILE is empty")));
    }
    Ok(Zeroizing::new(assertion.to_string()))
}

/// Sends a token request and reads the token and its lifetime from the answer.
async fn bearer(label: &str, req: reqwest::RequestBuilder, what: &str) -> Result<Bearer, Error> {
    let failed = |e: reqwest::Error| Error::Unavailable(format!("{label}: {what}: {e}"));
    let res = req.send().await.map_err(failed)?;
    let status = res.status();
    let body = Zeroizing::new(res.bytes().await.map_err(failed)?.to_vec());
    if !status.is_success() {
        return Err(Error::Unavailable(format!("{label}: {what} answered {status}{}", http::error_code(&body))));
    }
    let v: Value = serde_json::from_slice(&body).map_err(|e| Error::Unavailable(format!("{label}: {what}: {e}")))?;
    let token = v["access_token"].as_str().filter(|t| !t.is_empty()).ok_or_else(|| Error::Unavailable(format!("{label}: {what} gave no token")))?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let lifetime = http::seconds(&v["expires_in"]).or_else(|| http::seconds(&v["expires_on"]).map(|at| at.saturating_sub(now)));
    Ok(Bearer::new(token, lifetime))
}

/// botd's own token for `resource`, however it signs in.
async fn sign_in(label: &str, http: &reqwest::Client, local: &reqwest::Client, auth: &Auth, authority: &str, identity: &Identity, resource: &str) -> Result<Bearer, Error> {
    let scope = format!("{resource}/.default");
    let req = match auth {
        Auth::ManagedIdentity { client_id } => managed_identity(local, identity, resource, client_id.as_deref())?,
        Auth::ClientSecret { tenant, client_id, secret } => {
            let form = [("grant_type", "client_credentials"), ("client_id", client_id), ("client_secret", secret), ("scope", &scope)];
            http.post(token_url(authority, tenant)).form(&form)
        }
        Auth::WorkloadIdentity { tenant, client_id, token_file } => {
            let assertion = federated_token(label, token_file)?;
            let form = [("grant_type", "client_credentials"), ("client_id", client_id), ("client_assertion_type", ASSERTION_TYPE), ("client_assertion", &assertion), ("scope", &scope)];
            http.post(token_url(authority, tenant)).form(&form)
        }
    };
    bearer(label, req, &format!("{} sign-in", method_of(auth))).await
}

/// botd signed in to Entra ID as itself for one resource other than Key Vault, the token
/// kept while it lasts: the audit export's Azure Monitor sink (ADR 0217). It reads the
/// same `AZURE_*` settings as Key Vault, so it is the same identity.
pub struct Entra {
    label: &'static str,
    auth: Auth,
    authority: String,
    identity: Identity,
    resource: String,
    http: reqwest::Client,
    local: reqwest::Client,
    token: Mutex<Option<Bearer>>,
}

impl Entra {
    /// `label` names the service in errors; `resource` is what tokens are for, such as
    /// `https://monitor.azure.com`.
    pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore, method_var: &str, method: &str, label: &'static str, resource: &str) -> Result<Entra, String> {
        let (auth, authority, identity) = sign_in_settings(var, store, method_var, method)?;
        let http = http::client(label, None, false)?;
        let local = http::client(label, None, true)?;
        Ok(Entra { label, auth, authority, identity, resource: resource.to_string(), http, local, token: Mutex::new(None) })
    }

    pub fn method(&self) -> &'static str {
        method_of(&self.auth)
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Who botd signs in as, never a credential.
    pub fn describe(&self) -> String {
        signs_in_as(&self.auth)
    }

    /// The token to send; a new one if `fresh` (the service refused the last) or it is due.
    pub async fn token(&self, fresh: bool) -> Result<Zeroizing<String>, String> {
        if !fresh && let Some(t) = self.token.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|t| t.fresh()) {
            return Ok(t.value.clone());
        }
        let t = sign_in(self.label, &self.http, &self.local, &self.auth, &self.authority, &self.identity, &self.resource).await.map_err(|e| e.to_string())?;
        // Masked wherever an error might quote it, while this or another holder uses it:
        // Entra and the instance metadata service can hand out the same token again.
        super::redact::hold(&t.value);
        let value = t.value.clone();
        if let Some(old) = self.token.lock().unwrap_or_else(|e| e.into_inner()).replace(t) {
            super::redact::release(&old.value);
        }
        Ok(value)
    }

    /// Signs in at `base` instead: a stand-in for Entra ID and the instance metadata service.
    #[cfg(test)]
    pub fn point_at(&mut self, base: &str) {
        self.authority = base.to_string();
        if let Identity::Imds(_) = self.identity {
            self.identity = Identity::Imds(base.to_string());
        }
    }
}

impl Drop for Entra {
    fn drop(&mut self) {
        if let Some(t) = self.token.get_mut().unwrap_or_else(|e| e.into_inner()).take() {
            super::redact::release(&t.value);
        }
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
        let (auth, authority, identity) = sign_in_settings(var, store, "AZURE_KEYVAULT_AUTH", &var("AZURE_KEYVAULT_AUTH"))?;
        let tenant = Some(var("AZURE_TENANT_ID").trim().to_string()).filter(|t| !t.is_empty());
        Ok(Config { url, resource, prefix: prefix_setting(&var("AZURE_KEYVAULT_PREFIX"))?, auth, authority, identity, tenant })
    }

    /// Whether `AZURE_RUN_CREDENTIALS` can work with how botd signs in (ADR 0213): Entra
    /// trusts a user-assigned managed identity or a federated token as another app's
    /// credential, never a system-assigned identity or a client secret.
    pub fn run_credentials_ok(&self) -> Result<(), String> {
        match &self.auth {
            Auth::ManagedIdentity { client_id: None } => {
                Err("AZURE_RUN_CREDENTIALS needs a user-assigned managed identity (its client id in AZURE_CLIENT_ID): Entra trusts only those as an app's federated credential".into())
            }
            Auth::ManagedIdentity { .. } => match &self.tenant {
                None => Err("AZURE_RUN_CREDENTIALS needs AZURE_TENANT_ID, the tenant of the managed identity and its apps".into()),
                Some(t) => id_setting("AZURE_TENANT_ID", t).map(|_| ()),
            },
            Auth::ClientSecret { .. } => Err("AZURE_RUN_CREDENTIALS needs AZURE_KEYVAULT_AUTH=managed-identity (user-assigned) or workload-identity: Entra doesn't take a client secret as another app's credential".into()),
            Auth::WorkloadIdentity { .. } => Ok(()),
        }
    }

    /// The tenant `AZURE_RUN_CREDENTIALS`' apps are asked for tokens in.
    fn run_tenant(&self) -> Option<&str> {
        match &self.auth {
            Auth::ManagedIdentity { .. } => self.tenant.as_deref(),
            Auth::ClientSecret { tenant, .. } | Auth::WorkloadIdentity { tenant, .. } => Some(tenant),
        }
    }
}

struct Inner {
    cfg: Config,
    http: reqwest::Client,
    /// For the managed identity endpoints: link-local, so never through a proxy.
    local: reqwest::Client,
    token: Mutex<Option<Bearer>>,
    /// The managed identity's token for Entra's exchange audience, traded for apps'
    /// tokens (`AZURE_RUN_CREDENTIALS`); never sent anywhere but Entra.
    assertion: Mutex<Option<Bearer>>,
}

#[derive(Clone)]
pub struct KeyVault {
    inner: Arc<Inner>,
    worker: Arc<Worker>,
}

const KEY_VAULT: &str = "Azure Key Vault";

fn unavailable(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Unavailable(format!("{KEY_VAULT}: {what}: {e}"))
}

fn entra_unavailable(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Unavailable(format!("Azure Entra ID: {what}: {e}"))
}

impl KeyVault {
    pub fn new(cfg: Config) -> Result<KeyVault, String> {
        let http = http::client("Azure Key Vault", None, false)?;
        let local = http::client("Azure Key Vault", None, true)?;
        let inner = Inner { cfg, http, local, token: Mutex::new(None), assertion: Mutex::new(None) };
        Ok(KeyVault { inner: Arc::new(inner), worker: Arc::new(Worker::new("Azure Key Vault", "azure-keyvault")?) })
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
        method_of(&self.cfg.auth)
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
        sign_in(KEY_VAULT, &self.http, &self.local, &c.auth, &c.authority, &c.identity, &c.resource).await
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

    /// botd's own token to trade for an app's (ADR 0213): with a managed identity, its
    /// token for Entra's exchange audience, kept while it lasts unless `fresh`; with
    /// workload identity, the platform's federated token, read afresh.
    async fn assertion(&self, fresh: bool) -> Result<Zeroizing<String>, Error> {
        let client_id = match &self.cfg.auth {
            Auth::WorkloadIdentity { token_file, .. } => return federated_token(KEY_VAULT, token_file),
            Auth::ManagedIdentity { client_id: Some(id) } => id,
            _ => return Err(Error::Unavailable("Azure Entra ID: AZURE_RUN_CREDENTIALS needs a user-assigned managed identity or workload identity".into())),
        };
        if !fresh && let Some(t) = self.assertion.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|t| t.fresh()) {
            return Ok(t.value.clone());
        }
        let audience = exchange_audience(&self.cfg.authority);
        let result = match managed_identity(&self.local, &self.cfg.identity, audience, Some(client_id)) {
            Ok(req) => bearer(KEY_VAULT, req, &format!("managed-identity sign-in for {audience}")).await,
            Err(e) => Err(e),
        };
        let e = Event::new(external::actor(), "secret.backend_login").target("secrets_backend", "azure-keyvault");
        let d = json!({ "store": "azure-keyvault", "method": "managed-identity", "audience": audience });
        external::audit(match &result {
            Ok(_) => e.details(d),
            Err(err) => e.outcome(Outcome::Failure).details(json!({ "store": "azure-keyvault", "method": "managed-identity", "audience": audience, "error": err.kind() })),
        });
        let t = result?;
        let value = t.value.clone();
        *self.assertion.lock().unwrap_or_else(|e| e.into_inner()) = Some(t);
        Ok(value)
    }

    /// A new access token of the Entra app in `path` (`<client id>[@<resource host>]`) for
    /// one run of `bot_id`, traded for botd's own token, from `other` tenant if given (a
    /// multitenant app provisioned there) or botd's own. When Entra refuses a kept managed
    /// identity token, gets a new one and asks once more.
    async fn app_token(&self, path: &str, fields: &[String], run_for: Duration, bot_id: &str, other: Option<&str>) -> Result<Lease, Error> {
        let (app, resource) = path.split_once('@').unwrap_or((path, arm_host(&self.cfg.authority)));
        let home = self.cfg.run_tenant().ok_or_else(|| Error::Unavailable("Azure Entra ID: AZURE_RUN_CREDENTIALS needs AZURE_TENANT_ID".into()))?;
        let tenant = other.unwrap_or(home);
        let elsewhere = !tenant.eq_ignore_ascii_case(home);
        let scope = format!("https://{resource}/.default");
        let what = if elsewhere { format!("a token of app {app} for {resource} in tenant {tenant}") } else { format!("a token of app {app} for {resource}") };
        let kept = matches!(self.cfg.auth, Auth::ManagedIdentity { .. });
        for fresh in [false, true] {
            let assertion = self.assertion(fresh).await?;
            let form = [("grant_type", "client_credentials"), ("client_id", app), ("client_assertion_type", ASSERTION_TYPE), ("client_assertion", &assertion), ("scope", &scope)];
            let res = self.http.post(token_url(&self.cfg.authority, tenant)).form(&form).send().await.map_err(|e| entra_unavailable(&what, e))?;
            let status = res.status();
            let reply = Zeroizing::new(res.bytes().await.map_err(|e| entra_unavailable(&what, e))?.to_vec());
            if status.is_success() {
                return app_lease(&reply, path, fields, run_for.as_secs(), bot_id, &what);
            }
            let code = serde_json::from_slice::<Value>(&reply).ok().and_then(|v| v["error"].as_str().map(String::from)).unwrap_or_default();
            // A managed identity token past its time is refused as invalid_client too.
            if code == "invalid_client" && kept && !fresh {
                continue;
            }
            // The federated credential is on the app's registration in botd's own tenant,
            // whichever tenant the token comes from.
            let hint = match code.as_str() {
                "invalid_client" => format!(
                    "; the app needs a federated credential trusting botd's identity with audience {}: for a managed identity, issuer {}/{home}/v2.0 and the identity's object (principal) id as subject; for workload identity, the cluster's issuer and botd's service account",
                    exchange_audience(&self.cfg.authority),
                    self.cfg.authority
                ),
                "unauthorized_client" if elsewhere => {
                    format!("; is {app} a multitenant app registered in tenant {home}, and has an admin of tenant {tenant} consented to it there?")
                }
                "unauthorized_client" => format!("; is {app} an app registered in tenant {tenant}?"),
                "invalid_scope" | "invalid_resource" => format!("; is {resource} a resource in this cloud that the app may use?"),
                _ => String::new(),
            };
            return Err(Error::Unavailable(format!("Azure Entra ID answered {status}{} for {what}{hint}", http::error_code(&reply))));
        }
        unreachable!("the second pass returns")
    }
}

/// A run's lease from Entra's token answer: the token under each field asked for, and how
/// long it lasts. A token that ends before the run could is refused. Entra gives a token
/// no id SuperBot can use, so the lease's is the entry and `superbot-<bot id>-<random>`.
fn app_lease(body: &[u8], path: &str, fields: &[String], run_for: u64, bot_id: &str, what: &str) -> Result<Lease, Error> {
    let bad = |why: &str| Error::Unavailable(format!("Azure Entra ID: {what} {why}"));
    let v: Value = serde_json::from_slice(body).map_err(|_| bad("answered with something that isn't JSON"))?;
    let token = v["access_token"].as_str().filter(|t| !t.is_empty() && t.len() <= MAX_TOKEN && t.bytes().all(|b| b.is_ascii_graphic())).ok_or_else(|| bad("gave no access token"))?;
    let ttl = http::seconds(&v["expires_in"]).filter(|s| *s > 0).ok_or_else(|| bad("gave a token with no lifetime"))?;
    // A minute's slack for the request; Entra chooses the lifetime, not botd.
    if ttl + 60 < run_for {
        return Err(bad(&format!(
            "gave a token that lasts {ttl} s, but a run may last {run_for} s (RUN_TIMEOUT_MINUTES); Entra's tokens last 60 to 90 minutes unless a token lifetime policy on the app says otherwise, so keep RUN_TIMEOUT_MINUTES at 60 or less"
        )));
    }
    let fields = fields.iter().map(|f| if f == "accessToken" { Field::Value(Zeroizing::new(token.to_string())) } else { Field::Missing }).collect();
    Ok(Lease { id: format!("{path}/{}", super::aws::session_name(bot_id)), ttl, renewable: false, fields })
}

impl Issuer for KeyVault {
    fn kind(&self) -> &'static str {
        "azure-keyvault"
    }

    fn issue(&self, path: &str, fields: &[String], run_for: Duration, bot_id: &str) -> Result<Lease, Error> {
        self.issue_narrowed(path, fields, run_for, bot_id, &Narrowed::default())
    }

    fn issue_narrowed(&self, path: &str, fields: &[String], run_for: Duration, bot_id: &str, narrowed: &Narrowed) -> Result<Lease, Error> {
        if narrowed.narrows_session() || narrowed.boundary.is_some() {
            return Err(Error::Unavailable("Azure Entra ID: a token can't be narrowed with a session policy, tags or an access boundary".into()));
        }
        let (inner, path, fields, bot_id, tenant) = (Arc::clone(&self.inner), path.to_string(), fields.to_vec(), bot_id.to_string(), narrowed.tenant.clone());
        self.worker.run(async move { inner.app_token(&path, &fields, run_for, &bot_id, tenant.as_deref()).await })
    }

    fn revoke(&self, _lease_id: &str) -> Result<(), Error> {
        Err(Error::Unavailable("Azure Entra ID: an access token can't be revoked; it lasts until it expires".into()))
    }

    fn revocable(&self) -> bool {
        false
    }
}

impl Provider for KeyVault {
    fn kind(&self) -> &'static str {
        "azure-keyvault"
    }

    fn describe(&self) -> String {
        let c = &self.inner.cfg;
        let auth = signs_in_as(&c.auth);
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
        /// Managed identity tokens for Entra's exchange audience, which Entra trades for apps'.
        exchange_tokens: Mutex<Vec<String>>,
        /// Each app token asked for: the tenant and the form.
        exchanged: Mutex<Vec<(String, HashMap<String, String>)>>,
        /// The app tokens made for runs.
        run_tokens: Mutex<Vec<String>>,
    }

    type F = Arc<Fake>;

    /// Tenants other than botd's own (`tenant-1`), by id and by domain.
    const OTHER_TENANTS: [&str; 2] = ["fabrikam.onmicrosoft.com", "22222222-0000-0000-0000-000000000002"];

    fn issue(f: &Fake, asked: HashMap<String, String>) -> Json<Value> {
        let n = f.sign_ins.fetch_add(1, Ordering::SeqCst);
        let token = format!("eyJ.azure-{n}");
        let exchange = asked.get("resource").is_some_and(|r| r.starts_with("api://AzureADTokenExchange"));
        if exchange { &f.exchange_tokens } else { &f.tokens }.lock().unwrap().push(token.clone());
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
        if form.get("client_id").map(String::as_str) != Some("client-1") && form.contains_key("client_assertion") {
            return app_token(&f, &tenant, form);
        }
        let ok = tenant == "tenant-1"
            && form.get("client_id").map(String::as_str) == Some("client-1")
            && form.get("grant_type").map(String::as_str) == Some("client_credentials")
            && (form.get("client_secret").map(String::as_str) == Some("sp-secret-1") || form.get("client_assertion").map(String::as_str) == Some("federated-jwt-1"));
        if !ok {
            return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided." })));
        }
        (StatusCode::OK, issue(&f, form))
    }

    /// Entra trading botd's own token for an app's (ADR 0213). It takes only a managed
    /// identity token for the exchange audience that it made, or the federated token
    /// `federated-jwt-1`. Apps ending `dead` trust neither, `0bad` aren't registered,
    /// `0dd0` get an answer with no token and `f00d` a token of ten minutes; resources on
    /// `nowhere.example.com` don't exist. In `OTHER_TENANTS` only multitenant apps ending
    /// `cafe` (and `dead`, which trusts nothing) are provisioned, as an admin there consented.
    fn app_token(f: &Fake, tenant: &str, form: HashMap<String, String>) -> (StatusCode, Json<Value>) {
        f.exchanged.lock().unwrap().push((tenant.to_string(), form.clone()));
        let refuse = |code: StatusCode, error: &str| (code, Json(json!({ "error": error, "error_description": "AADSTS70021: quoting-the-request" })));
        if f.down.load(Ordering::SeqCst) {
            return refuse(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
        let get = |k: &str| form.get(k).map(String::as_str).unwrap_or_default();
        let elsewhere = OTHER_TENANTS.contains(&tenant);
        if !(tenant == "tenant-1" || elsewhere) || get("grant_type") != "client_credentials" || get("client_assertion_type") != ASSERTION_TYPE {
            return refuse(StatusCode::BAD_REQUEST, "invalid_request");
        }
        let assertion = get("client_assertion");
        let trusted = assertion == "federated-jwt-1" || f.exchange_tokens.lock().unwrap().iter().any(|t| t == assertion);
        let app = get("client_id");
        if app.ends_with("0bad") || (elsewhere && !app.ends_with("cafe") && !app.ends_with("dead")) {
            return refuse(StatusCode::BAD_REQUEST, "unauthorized_client");
        }
        if !trusted || app.ends_with("dead") {
            return refuse(StatusCode::UNAUTHORIZED, "invalid_client");
        }
        if get("scope").starts_with("https://nowhere.example.com/") {
            return refuse(StatusCode::BAD_REQUEST, "invalid_scope");
        }
        if app.ends_with("0dd0") {
            return (StatusCode::OK, Json(json!({ "token_type": "Bearer", "expires_in": 3599 })));
        }
        let lifetime = if app.ends_with("f00d") { 600 } else { 3599 };
        let token = format!("eyJ.run-{}", crate::random_hex(8));
        f.run_tokens.lock().unwrap().push(token.clone());
        (StatusCode::OK, Json(json!({ "token_type": "Bearer", "expires_in": lifetime, "ext_expires_in": lifetime, "access_token": token })))
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

    use super::super::leases::tests::RUN;
    use super::super::leases::{self, RunCredentials};

    const APP: &str = "11111111-2222-3333-4444-555555555555";
    const BLOB_APP: &str = "66666666-7777-8888-9999-aaaaaaaaaaaa";

    /// `AZURE_RUN_CREDENTIALS` on the stand-in, botd signing in with a user-assigned
    /// managed identity through the instance metadata service.
    fn run_credentials(url: &str, entries: &str) -> RunCredentials {
        let kv = KeyVault::new(config(url, &[("AZURE_CLIENT_ID", "user-assigned-1"), ("AZURE_TENANT_ID", "tenant-1")])).unwrap();
        kv.inner.cfg.run_credentials_ok().unwrap();
        RunCredentials::new(Arc::new(kv), leases::parse_as(&leases::AZURE, entries).unwrap())
    }

    fn values(env: &[(String, super::super::Secret)]) -> HashMap<String, String> {
        env.iter().map(|(k, v)| (k.clone(), v.expose().to_string())).collect()
    }

    #[test]
    fn each_run_gets_its_own_token_of_an_app_that_trusts_botds_identity() {
        let (url, f) = stand_in();
        let blob = format!("{BLOB_APP}@storage.azure.com");
        let rc = run_credentials(&url, &format!("{APP}; {blob} BLOB_TOKEN=accessToken"));
        assert!(rc.describe().contains(&format!("{APP}, {blob}")));
        let (e1, l1) = rc.issue("uaz7", "baz7", true, RUN).unwrap();
        let (e2, l2) = rc.issue("uaz7", "baz7", false, RUN).unwrap();
        let (v1, v2) = (values(&e1), values(&e2));
        let mut names: Vec<&str> = v1.keys().map(String::as_str).collect();
        names.sort();
        assert_eq!(names, ["AZURE_ACCESS_TOKEN", "BLOB_TOKEN"]);
        assert_ne!(v1["AZURE_ACCESS_TOKEN"], v1["BLOB_TOKEN"], "a token per app and resource");
        assert_ne!(v1["AZURE_ACCESS_TOKEN"], v2["AZURE_ACCESS_TOKEN"], "each run its own token");
        assert!(f.run_tokens.lock().unwrap().contains(&v1["BLOB_TOKEN"]), "the token Entra made");
        assert_eq!(redact::text(&format!("leaked {}", v1["BLOB_TOKEN"])), format!("leaked {}", redact::MARK));

        let calls = f.exchanged.lock().unwrap().clone();
        let asked: Vec<(&str, &str, &str)> = calls.iter().map(|(t, form)| (t.as_str(), form["client_id"].as_str(), form["scope"].as_str())).collect();
        let (arm, storage) = ("https://management.azure.com/.default", "https://storage.azure.com/.default");
        assert_eq!(asked, [("tenant-1", APP, arm), ("tenant-1", BLOB_APP, storage), ("tenant-1", APP, arm), ("tenant-1", BLOB_APP, storage)], "Resource Manager unless the entry names a resource");
        let mi = f.exchange_tokens.lock().unwrap().clone();
        assert_eq!(mi.len(), 1, "botd's managed identity token for the exchange, kept while it lasts");
        assert!(calls.iter().all(|(_, form)| form["client_assertion"] == mi[0] && form["client_assertion_type"] == ASSERTION_TYPE), "traded for the apps' tokens, checked by the stand-in");
        let exchange = f.asked.lock().unwrap().iter().find(|q| q.get("resource").map(String::as_str) == Some("api://AzureADTokenExchange")).cloned().unwrap();
        assert_eq!(exchange["client_id"], "user-assigned-1");
        assert!(!f.tokens.lock().unwrap().contains(&mi[0]), "not Key Vault's token");
        assert!(audited("azure-keyvault").iter().any(|e| e.action == "secret.backend_login" && e.details["audience"] == "api://AzureADTokenExchange" && e.outcome == Outcome::Success));

        let ev: Vec<_> = audited(APP).into_iter().filter(|e| e.bot_id.as_deref() == Some("baz7")).collect();
        let issued = ev.iter().find(|e| e.action == "secret.lease_issued").unwrap();
        let id = issued.details["leaseId"].as_str().unwrap();
        assert!(id.starts_with(&format!("{APP}/superbot-baz7-")), "{id}");
        assert_eq!((issued.details["store"].as_str(), issued.details["renewable"].as_bool(), issued.details["ttl"].as_u64()), (Some("azure-keyvault"), Some(false), Some(3599)));
        assert_eq!(issued.details["names"], json!(["AZURE_ACCESS_TOKEN"]));
        assert!(!format!("{ev:?}").contains(&v1["AZURE_ACCESS_TOKEN"]) && !format!("{:?}", audited("azure-keyvault")).contains(&mi[0]), "never a token");

        drop(l1);
        drop(l2);
        let released: Vec<_> = audited(&blob).into_iter().filter(|e| e.action == "secret.lease_released" && e.bot_id.as_deref() == Some("baz7")).collect();
        assert_eq!(released.len(), 2);
        assert!(released.iter().all(|e| e.details["revocable"] == false && e.details["expiresAt"].as_str().is_some()));
        assert_eq!(redact::text(&v1["BLOB_TOKEN"]), redact::MARK, "it works until it expires, so it stays redacted");
    }

    #[test]
    fn entra_refusing_or_odd_refuses_the_run() {
        let (url, f) = stand_in();
        let hint = "; the app needs a federated credential trusting botd's identity with audience api://AzureADTokenExchange";
        for (entry, err) in [
            ("aaaaaaaa-0000-0000-0000-00000000dead".to_string(), format!("401 Unauthorized (invalid_client) for a token of app aaaaaaaa-0000-0000-0000-00000000dead for management.azure.com{hint}")),
            ("aaaaaaaa-0000-0000-0000-000000000bad".to_string(), "400 Bad Request (unauthorized_client) for a token of app aaaaaaaa-0000-0000-0000-000000000bad for management.azure.com; is aaaaaaaa-0000-0000-0000-000000000bad an app registered in tenant tenant-1?".to_string()),
            (format!("{APP}@nowhere.example.com"), "(invalid_scope) for a token of app 11111111-2222-3333-4444-555555555555 for nowhere.example.com; is nowhere.example.com a resource".to_string()),
            ("aaaaaaaa-0000-0000-0000-00000000f00d".to_string(), "gave a token that lasts 600 s, but a run may last 3600 s (RUN_TIMEOUT_MINUTES)".to_string()),
            ("aaaaaaaa-0000-0000-0000-000000000dd0".to_string(), "gave no access token".to_string()),
        ] {
            let rc = run_credentials(&url, &entry);
            let e = rc.issue("uaz8", "baz8", true, RUN).err().unwrap().to_string();
            assert!(e.contains(&err) && !e.contains("quoting") && !e.contains("AADSTS"), "{entry}: {e}");
            assert!(audited(&entry).iter().any(|e| e.action == "secret.lease_issued" && e.outcome == Outcome::Failure), "{entry}");
        }

        // Entra no longer takes the kept managed identity token: botd gets a new one and asks once more.
        let rc = run_credentials(&url, APP);
        rc.issue("uaz8", "baz8", true, RUN).unwrap();
        f.exchange_tokens.lock().unwrap().clear();
        rc.issue("uaz8", "baz8", true, RUN).unwrap();
        let fresh = f.exchange_tokens.lock().unwrap().clone();
        assert_eq!(fresh.len(), 1, "one new managed identity token");
        assert_eq!(f.exchanged.lock().unwrap().last().unwrap().1["client_assertion"], fresh[0], "with the new token");

        f.down.store(true, Ordering::SeqCst);
        assert!(matches!(rc.issue("uaz8", "baz8", true, RUN), Err(Error::Unavailable(_))), "Entra down: refused, never a run without its token");
    }

    const CAFE_APP: &str = "cccccccc-0000-0000-0000-00000000cafe";

    #[test]
    fn a_multitenant_apps_token_comes_from_another_tenant_with_the_same_assertion() {
        let (url, f) = stand_in();
        let [fabrikam, by_id] = OTHER_TENANTS;
        let rc = run_credentials(&url, &format!("{CAFE_APP} tenant={fabrikam}; {CAFE_APP}@storage.azure.com tenant={by_id} BLOB_TOKEN=accessToken; {APP} HOME_TOKEN=accessToken"));
        assert!(rc.describe().contains(&format!("{CAFE_APP} (tenant {fabrikam}), {CAFE_APP}@storage.azure.com (tenant {by_id}), {APP}")), "{}", rc.describe());
        let (env, _l) = rc.issue("uaz10", "baz10", false, RUN).unwrap();
        let v = values(&env);
        assert_eq!(v.len(), 3, "a tenant isn't the owner's: runs for anyone get it");
        let calls = f.exchanged.lock().unwrap().clone();
        let asked: Vec<(&str, &str)> = calls.iter().map(|(t, form)| (t.as_str(), form["client_id"].as_str())).collect();
        assert_eq!(asked, [(fabrikam, CAFE_APP), (by_id, CAFE_APP), ("tenant-1", APP)], "each from its own tenant's token endpoint");
        let mi = f.exchange_tokens.lock().unwrap().clone();
        assert!(mi.len() == 1 && calls.iter().all(|(_, form)| form["client_assertion"] == mi[0]), "one managed identity token, from botd's own tenant, for every tenant");
        assert!(f.run_tokens.lock().unwrap().contains(&v["AZURE_ACCESS_TOKEN"]));

        let ev: Vec<_> = audited(CAFE_APP).into_iter().filter(|e| e.bot_id.as_deref() == Some("baz10") && e.action == "secret.lease_issued").collect();
        assert_eq!(ev[0].details["tenant"], fabrikam, "which tenant, in the audit");
        let home = audited(APP).into_iter().find(|e| e.bot_id.as_deref() == Some("baz10") && e.action == "secret.lease_issued").unwrap();
        assert!(home.details.get("tenant").is_none(), "botd's own tenant isn't named");

        // Not provisioned there (single-tenant, or no admin consented), or no federated credential.
        for (entry, err) in [
            (format!("{APP} tenant={fabrikam}"), format!("(unauthorized_client) for a token of app {APP} for management.azure.com in tenant {fabrikam}; is {APP} a multitenant app registered in tenant tenant-1, and has an admin of tenant {fabrikam} consented to it there?")),
            (
                format!("aaaaaaaa-0000-0000-0000-00000000dead tenant={fabrikam}"),
                format!("(invalid_client) for a token of app aaaaaaaa-0000-0000-0000-00000000dead for management.azure.com in tenant {fabrikam}; the app needs a federated credential trusting botd's identity with audience api://AzureADTokenExchange: for a managed identity, issuer {url}/tenant-1/v2.0"),
            ),
        ] {
            let e = run_credentials(&url, &entry).issue("uaz10", "baz10", true, RUN).err().unwrap().to_string();
            assert!(e.contains(&err) && !e.contains("quoting"), "{entry}: {e}");
        }
    }

    #[test]
    fn each_user_gets_their_own_app_from_the_apps_file() {
        let (url, f) = stand_in();
        let file = crate::db::temp_path("azure-apps").join("apps.json");
        let write = |v: Value| std::fs::write(&file, v.to_string()).unwrap();
        write(json!({ "uapp1": APP, "uapp2": { "app": CAFE_APP, "tenant": OTHER_TENANTS[0] } }));
        let rc = run_credentials(&url, &format!("{{owner}}@storage.azure.com apps={} USER_AZURE_TOKEN=accessToken; {BLOB_APP}", file.display()));
        assert!(rc.describe().contains(&format!("{{owner}}@storage.azure.com (each user's app from {})", file.display())), "{}", rc.describe());
        let made = || f.exchanged.lock().unwrap().iter().map(|(t, form)| (t.clone(), form["client_id"].clone(), form["scope"].clone())).collect::<Vec<_>>();
        let storage = "https://storage.azure.com/.default".to_string();

        let (e1, _l1) = rc.issue("uapp1", "bapp1", true, RUN).unwrap();
        assert!(values(&e1).contains_key("USER_AZURE_TOKEN") && values(&e1).contains_key("AZURE_ACCESS_TOKEN"));
        assert_eq!(made()[0], ("tenant-1".to_string(), APP.to_string(), storage.clone()), "the owner's app, for the entry's resource");
        let (e2, _l2) = rc.issue("uapp2", "bapp2", true, RUN).unwrap();
        assert_eq!(made()[2], (OTHER_TENANTS[0].to_string(), CAFE_APP.to_string(), storage.clone()), "in the user's own tenant");
        assert_ne!(values(&e1)["USER_AZURE_TOKEN"], values(&e2)["USER_AZURE_TOKEN"]);

        let ev = audited(&format!("{APP}@storage.azure.com"));
        let issued = ev.iter().find(|e| e.action == "secret.lease_issued" && e.bot_id.as_deref() == Some("bapp1")).unwrap();
        assert_eq!((issued.details["userId"].as_str(), issued.details.get("tenant")), (Some("uapp1"), None), "which user's app, in the audit");
        let theirs = audited(&format!("{CAFE_APP}@storage.azure.com")).into_iter().find(|e| e.bot_id.as_deref() == Some("bapp2")).unwrap();
        assert_eq!((theirs.details["userId"].as_str(), theirs.details["tenant"].as_str()), (Some("uapp2"), Some(OTHER_TENANTS[0])));

        // Someone the file doesn't name, or a run for someone else: no token from the entry, and none inherited.
        let before = made().len();
        let (e3, l3) = rc.issue("uapp3", "bapp3", true, RUN).unwrap();
        assert_eq!((values(&e3).contains_key("USER_AZURE_TOKEN"), l3.cleared()), (false, &["USER_AZURE_TOKEN".to_string()][..]));
        let (e4, _l4) = rc.issue("uapp1", "bapp1", false, RUN).unwrap();
        assert!(!values(&e4).contains_key("USER_AZURE_TOKEN"));
        assert_eq!(made().len(), before + 2, "only the shared app's tokens");

        // Edits apply from the next run, without a restart.
        write(json!({ "uapp2": CAFE_APP }));
        let (e1, _l1) = rc.issue("uapp1", "bapp1", true, RUN).unwrap();
        assert!(!values(&e1).contains_key("USER_AZURE_TOKEN"), "taken out of the file: no token from the next run");
        rc.issue("uapp2", "bapp2", true, RUN).unwrap();
        let m = made();
        assert_eq!((m[m.len() - 2].0.as_str(), m[m.len() - 2].1.as_str()), ("tenant-1", CAFE_APP), "no tenant in the file now: botd's own");

        // A file that no longer reads refuses the runs that need it, never the map it had.
        for broken in ["{\"uapp2\": ", "[]"] {
            std::fs::write(&file, broken).unwrap();
            let e = rc.issue("uapp2", "bapp2", true, RUN).err().unwrap().to_string();
            assert!(e.contains(&format!("{{owner}}@storage.azure.com: apps={}", file.display())), "{e}");
        }
        assert!(audited("{owner}@storage.azure.com").iter().any(|e| e.outcome == Outcome::Failure && e.details["error"] == "apps" && e.details["userId"] == "uapp2"));
        std::fs::remove_file(&file).unwrap();
        assert!(rc.issue("uapp2", "bapp2", true, RUN).err().unwrap().to_string().contains("can't be read"));
        rc.issue("uapp2", "bapp2", false, RUN).expect("a run for someone else never reads it");
    }

    #[test]
    fn workload_identity_trades_its_federated_token_and_settings_are_checked() {
        let (url, f) = stand_in();
        let file = crate::db::temp_path("azure-run-fed").join("token");
        std::fs::write(&file, "federated-jwt-1\n").unwrap();
        let wi = [
            ("SECRETS_BACKEND", "azure-keyvault"),
            ("AZURE_KEYVAULT_URL", url.as_str()),
            ("AZURE_AUTHORITY_HOST", url.as_str()),
            ("AZURE_KEYVAULT_AUTH", "workload-identity"),
            ("AZURE_TENANT_ID", "tenant-1"),
            ("AZURE_CLIENT_ID", "client-1"),
            ("AZURE_FEDERATED_TOKEN_FILE", file.to_str().unwrap()),
            ("AZURE_RUN_CREDENTIALS", "11111111-2222-3333-4444-555555555555 WI_RUN_TOKEN=accessToken"),
        ];
        let x = external::from_env(&settings(&wi), &EnvStore::fixed(&wi)).unwrap().unwrap();
        let rc = Arc::clone(x.run_credentials().expect("AZURE_RUN_CREDENTIALS is read with SECRETS_BACKEND=azure-keyvault"));
        assert_eq!(rc.names(), ["WI_RUN_TOKEN"]);
        let (e, _l) = rc.issue("uaz9", "baz9", true, RUN).unwrap();
        assert!(f.run_tokens.lock().unwrap().contains(&values(&e)["WI_RUN_TOKEN"]));
        let (_, form) = f.exchanged.lock().unwrap().last().cloned().unwrap();
        assert_eq!((form["client_id"].as_str(), form["client_assertion"].as_str()), (APP, "federated-jwt-1"), "the platform's federated token, traded for the app's");
        assert!(f.exchange_tokens.lock().unwrap().is_empty(), "no managed identity asked");
        std::fs::write(&file, "rotated-but-untrusted-jwt\n").unwrap();
        let before = f.exchanged.lock().unwrap().len();
        let err = rc.issue("uaz9", "baz9", true, RUN).err().unwrap().to_string();
        assert!(err.contains("invalid_client"), "{err}");
        assert_eq!(f.exchanged.lock().unwrap().len(), before + 1, "read afresh each run; nothing kept to retry with");

        let base = [("SECRETS_BACKEND", "azure-keyvault"), ("AZURE_KEYVAULT_URL", "https://kv1.vault.azure.net"), ("AZURE_CLIENT_SECRET", "s")];
        let with = |extra: &[(&str, &str)]| {
            let pairs = [&base[..], extra].concat();
            external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs))
        };
        let run = ("AZURE_RUN_CREDENTIALS", APP);
        let x = with(&[run, ("AZURE_CLIENT_ID", "user-assigned-1"), ("AZURE_TENANT_ID", "tenant-1")]).unwrap().unwrap();
        assert_eq!(x.run_credentials().unwrap().names(), ["AZURE_ACCESS_TOKEN"]);
        assert!(with(&[("AZURE_CLIENT_ID", "user-assigned-1")]).unwrap().unwrap().run_credentials().is_none(), "off unless set");
        assert!(with(&[("AZURE_TENANT_ID", "not a tenant")]).is_ok(), "AZURE_TENANT_ID is only checked for run credentials with a managed identity");
        for (extra, err) in [
            (vec![run], "user-assigned managed identity"),
            (vec![run, ("AZURE_CLIENT_ID", "user-assigned-1")], "needs AZURE_TENANT_ID"),
            (vec![run, ("AZURE_CLIENT_ID", "user-assigned-1"), ("AZURE_TENANT_ID", "not a tenant")], "AZURE_TENANT_ID must be"),
            (vec![run, ("AZURE_KEYVAULT_AUTH", "client-secret"), ("AZURE_CLIENT_ID", "c"), ("AZURE_TENANT_ID", "t")], "doesn't take a client secret"),
            (vec![("AZURE_RUN_CREDENTIALS", "superbot-bots@proj-1.iam.gserviceaccount.com")], "Entra app's client id"),
        ] {
            let e = with(&extra).err().unwrap_or_default();
            assert!(e.contains(err), "expected an error containing {err:?} for {extra:?}");
        }
        let var = settings(&[run]);
        assert_eq!(external::unused_settings(&var, "gcp-secret-manager"), ["AZURE_RUN_CREDENTIALS"], "only SECRETS_BACKEND=azure-keyvault reads it");
        assert!(external::unused_settings(&var, "azure-keyvault").is_empty());
    }

    #[test]
    fn another_resources_token_is_kept_until_it_is_refused() {
        let (url, f) = stand_in();
        let pairs = [("AZURE_AUTHORITY_HOST", url.as_str()), ("AZURE_TENANT_ID", "tenant-1"), ("AZURE_CLIENT_ID", "client-1"), ("AZURE_CLIENT_SECRET", "sp-secret-1")];
        let mut e = Entra::from_env(&settings(&pairs), &EnvStore::fixed(&pairs), "AUDIT_EXPORT_AZURE_AUTH", "client-secret", "Azure Monitor", "https://monitor.azure.com").unwrap();
        e.point_at(&url);
        assert_eq!((e.method(), e.describe().as_str()), ("client-secret", "service principal client-1 in tenant tenant-1"));
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let first = rt.block_on(e.token(false)).unwrap();
        assert_eq!(f.asked.lock().unwrap()[0]["scope"], "https://monitor.azure.com/.default");
        assert_eq!(*rt.block_on(e.token(false)).unwrap(), *first, "kept while it lasts");
        let second = rt.block_on(e.token(true)).unwrap();
        assert_ne!(*second, *first);
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 2);
        assert!(redact::text(&format!("x {} y", *second)).contains(redact::MARK), "the token in use is masked");
        assert!(!redact::text(&format!("x {} y", *first)).contains(redact::MARK), "and only that one");

        let wrong = [("AZURE_AUTHORITY_HOST", url.as_str()), ("AZURE_TENANT_ID", "tenant-1"), ("AZURE_CLIENT_ID", "client-1"), ("AZURE_CLIENT_SECRET", "not-the-secret")];
        let mut e = Entra::from_env(&settings(&wrong), &EnvStore::fixed(&wrong), "AUDIT_EXPORT_AZURE_AUTH", "client-secret", "Azure Monitor", "https://monitor.azure.com").unwrap();
        e.point_at(&url);
        let err = rt.block_on(e.token(false)).unwrap_err();
        assert!(err.contains("Azure Monitor: client-secret sign-in answered 401") && err.contains("invalid_client") && !err.contains("not-the-secret"), "{err}");
    }

    #[test]
    fn each_cloud_has_its_own_exchange_audience_and_resource_manager() {
        for (authority, audience, arm) in [
            (AUTHORITY, "api://AzureADTokenExchange", "management.azure.com"),
            ("https://login.microsoftonline.us", "api://AzureADTokenExchangeUSGov", "management.usgovcloudapi.net"),
            ("https://login.chinacloudapi.cn", "api://AzureADTokenExchangeChina", "management.chinacloudapi.cn"),
            ("http://127.0.0.1:8080", "api://AzureADTokenExchange", "management.azure.com"),
        ] {
            assert_eq!((exchange_audience(authority), arm_host(authority)), (audience, arm), "{authority}");
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
