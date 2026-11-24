//! Google Cloud Secret Manager as an external secrets `Provider` (ADR 0136), over its
//! REST API.
//!
//! Secret ids allow letters, digits, `_` and `-`, so `<NAME>` in folder `<bots|server>`
//! is the secret `<GCP_SECRET_MANAGER_PREFIX>-<bots|server>-<NAME>` as is
//! (`superbot-bots-OPENAI_API_KEY`), and botd reads its `latest` version. With
//! `GCP_SECRET_MANAGER_LOCATION`, regional secrets on that region's endpoint. botd signs
//! in with the metadata server's service account (Compute Engine, GKE workload identity,
//! Cloud Run) or a service account key, and gets a new token two thirds of the way
//! through each one's life and once more whenever Secret Manager refuses it.
//!
//! It is also the `leases::Issuer` of `GCP_RUN_CREDENTIALS` (ADR 0203): an access token
//! of a service account botd impersonates (IAM Credentials' `generateAccessToken`), made
//! for each run with botd's own token, lasting the longest the run may. Google can't
//! revoke one, so it is let go at its expiry. An entry with `boundary=` (ADR 0240) trades
//! that token at Google's Security Token Service for one limited by its Credential Access
//! Boundary, and the run gets only that one.

use super::external::{Provider, Scope};
use super::http::{self, Bearer, Worker};
use super::leases::{Field, Issuer, Lease, Narrowed};
use super::{Error, SecretStore};
use aws_lc_rs::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

/// Secret Manager's longest secret id.
const MAX_ID: usize = 255;
const METADATA_HOST: &str = "169.254.169.254";
const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
pub(crate) const IAM_CREDENTIALS: &str = "https://iamcredentials.googleapis.com";
const STS: &str = "https://sts.googleapis.com";
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// The longest downscoped token taken: Google's are at most 12 KB.
const MAX_DOWNSCOPED: usize = 16 * 1024;
/// An impersonated token's shortest life; its longest without the organization policy
/// `constraints/iam.allowServiceAccountCredentialLifetimeExtension`, and with it.
const MIN_LIFETIME: u64 = 300;
const DEFAULT_LIFETIME: u64 = 3600;
const MAX_LIFETIME: u64 = 43_200;
/// A service account id's longest: what `{owner}` may make of the part before the `@`.
const MAX_ACCOUNT_ID: usize = 30;

pub struct ServiceAccount {
    pub email: String,
    pub key_id: Option<String>,
    pub key: RsaKeyPair,
    pub token_uri: String,
}

pub enum Auth {
    /// The metadata server at `GCE_METADATA_HOST` (`169.254.169.254` by default).
    Metadata { host: String },
    Key(Box<ServiceAccount>),
}

pub struct Config {
    /// `https://secretmanager.googleapis.com`, or a region's endpoint; no trailing slash.
    pub endpoint: String,
    /// `projects/<project>`, or `projects/<project>/locations/<location>`.
    pub parent: String,
    pub prefix: String,
    pub auth: Auth,
    /// IAM Credentials, for `GCP_RUN_CREDENTIALS`; no trailing slash.
    pub iam_endpoint: String,
    /// The Security Token Service, for `GCP_RUN_CREDENTIALS` entries with `boundary=`; no
    /// trailing slash.
    pub sts_endpoint: String,
}

fn prefix_setting(raw: &str) -> Result<String, String> {
    let v = match raw.trim() {
        "" => "superbot",
        v => v,
    };
    if v.len() > 64 || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) {
        return Err(format!("GCP_SECRET_MANAGER_PREFIX must be letters, digits, _ and -, like \"superbot\", not {v:?}"));
    }
    Ok(v.to_string())
}

/// A project id (`my-project-123`) or number, or a location (`europe-west2`).
fn name_setting(key: &str, v: &str, example: &str) -> Result<String, String> {
    if v.is_empty() || v.len() > 63 || !v.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return Err(format!("{key} must be like {example:?}, not {v:?}"));
    }
    Ok(v.to_string())
}

/// The PKCS#8 key in a service account key's `private_key` PEM.
fn rsa_key(pem: &str) -> Result<RsaKeyPair, String> {
    let b64: Zeroizing<String> = Zeroizing::new(pem.lines().map(str::trim).filter(|l| !l.starts_with("-----")).collect());
    let der = Zeroizing::new(STANDARD.decode(b64.as_bytes()).map_err(|_| "its private_key isn't a PEM key".to_string())?);
    RsaKeyPair::from_pkcs8(&der).map_err(|e| format!("its private_key isn't an RSA PKCS#8 key ({e})"))
}

fn service_account(json: &str) -> Result<(ServiceAccount, Option<String>), String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("GCP_SERVICE_ACCOUNT_KEY isn't JSON (line {}, column {})", e.line(), e.column()))?;
    if v["type"] != "service_account" {
        return Err("GCP_SERVICE_ACCOUNT_KEY must be a service account key (\"type\": \"service_account\")".into());
    }
    let email = v["client_email"].as_str().filter(|e| e.contains('@')).ok_or("GCP_SERVICE_ACCOUNT_KEY has no client_email")?.to_string();
    let key = rsa_key(v["private_key"].as_str().ok_or("GCP_SERVICE_ACCOUNT_KEY has no private_key")?).map_err(|e| format!("GCP_SERVICE_ACCOUNT_KEY: {e}"))?;
    let token_uri = match v["token_uri"].as_str() {
        None | Some("") => TOKEN_URI.to_string(),
        Some(u) => {
            let url = url::Url::parse(u).map_err(|e| format!("GCP_SERVICE_ACCOUNT_KEY token_uri {u:?}: {e}"))?;
            if !crate::tiers::encrypted_or_loopback(&url) {
                return Err("GCP_SERVICE_ACCOUNT_KEY token_uri must use https://".into());
            }
            u.to_string()
        }
    };
    let key_id = v["private_key_id"].as_str().filter(|k| !k.is_empty()).map(String::from);
    Ok((ServiceAccount { email, key_id, key, token_uri }, v["project_id"].as_str().map(String::from)))
}

/// How botd signs in to Google as itself: the method `method_var` names (with `method` its
/// value), with `GCE_METADATA_HOST` or `GCP_SERVICE_ACCOUNT_KEY`, and the key's project.
/// Secret Manager reads `GCP_SECRET_MANAGER_AUTH`; the audit export's Google SecOps sink,
/// `AUDIT_EXPORT_GCP_AUTH` (ADR 0237).
fn sign_in_settings(var: &dyn Fn(&str) -> String, store: &dyn SecretStore, method_var: &str, method: &str) -> Result<(Auth, Option<String>), String> {
    Ok(match method.trim() {
        "" | "metadata" => {
            let host = match var("GCE_METADATA_HOST").trim() {
                "" => METADATA_HOST.to_string(),
                h if h.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b)) => h.to_string(),
                h => return Err(format!("GCE_METADATA_HOST must be a host[:port], not {h:?}")),
            };
            (Auth::Metadata { host }, None)
        }
        "service-account-key" => {
            let key = store.get("GCP_SERVICE_ACCOUNT_KEY").map_err(|e| format!("GCP_SERVICE_ACCOUNT_KEY: {e}"))?;
            let key = key.ok_or(format!("{method_var}=service-account-key needs GCP_SERVICE_ACCOUNT_KEY_FILE (or GCP_SERVICE_ACCOUNT_KEY)"))?;
            let (sa, project) = service_account(key.expose())?;
            (Auth::Key(Box::new(sa)), project)
        }
        other => return Err(format!("{method_var} must be metadata or service-account-key, not {other:?}")),
    })
}

fn method_of(auth: &Auth) -> &'static str {
    match auth {
        Auth::Metadata { .. } => "metadata",
        Auth::Key(_) => "service-account-key",
    }
}

/// Who botd signs in as, for startup lines: never a credential.
fn signs_in_as(auth: &Auth) -> String {
    match auth {
        Auth::Metadata { host } if host == METADATA_HOST => "the metadata server's service account".to_string(),
        Auth::Metadata { host } => format!("the metadata server's service account at {host}"),
        Auth::Key(sa) => format!("service account key for {}", sa.email),
    }
}

/// botd's own access token, from the metadata server or by trading a JWT signed with its
/// service account key. `label` names the service in errors.
async fn sign_in(label: &str, http: &reqwest::Client, local: &reqwest::Client, auth: &Auth) -> Result<Bearer, Error> {
    let what = format!("{} sign-in", method_of(auth));
    let failed = |e: &dyn std::fmt::Display| Error::Unavailable(format!("{label}: {what}: {e}"));
    let req = match auth {
        Auth::Metadata { host } => local.get(format!("http://{host}/computeMetadata/v1/instance/service-accounts/default/token")).header("Metadata-Flavor", "Google"),
        Auth::Key(sa) => {
            let assertion = jwt(sa).map_err(|e| failed(&e))?;
            http.post(&sa.token_uri).form(&[("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", assertion.as_str())])
        }
    };
    let res = req.send().await.map_err(|e| failed(&e))?;
    let status = res.status();
    let body = Zeroizing::new(res.bytes().await.map_err(|e| failed(&e))?.to_vec());
    if !status.is_success() {
        return Err(Error::Unavailable(format!("{label}: {what} answered {status}{}", http::error_code(&body))));
    }
    let v: Value = serde_json::from_slice(&body).map_err(|e| failed(&e))?;
    let token = v["access_token"].as_str().filter(|t| !t.is_empty()).ok_or_else(|| Error::Unavailable(format!("{label}: {what} gave no token")))?;
    Ok(Bearer::new(token, http::seconds(&v["expires_in"])))
}

/// botd signed in to Google as itself for a service other than Secret Manager, the token
/// kept while it lasts: the audit export's Google SecOps sink (ADR 0237). It reads the same
/// `GCE_METADATA_HOST` and `GCP_SERVICE_ACCOUNT_KEY` as Secret Manager, so it is the same
/// identity.
pub struct Google {
    label: &'static str,
    auth: Auth,
    http: reqwest::Client,
    local: reqwest::Client,
    token: Mutex<Option<Bearer>>,
}

impl Google {
    pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore, method_var: &str, method: &str, label: &'static str) -> Result<Google, String> {
        let (auth, _) = sign_in_settings(var, store, method_var, method)?;
        let http = http::client(label, None, false)?;
        let local = http::client(label, None, true)?;
        Ok(Google { label, auth, http, local, token: Mutex::new(None) })
    }

    pub fn method(&self) -> &'static str {
        method_of(&self.auth)
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
        let t = sign_in(self.label, &self.http, &self.local, &self.auth).await.map_err(|e| e.to_string())?;
        // Masked wherever an error might quote it, while this or another holder uses it:
        // the metadata server hands out the same token until it is near its end.
        super::redact::hold(&t.value);
        let value = t.value.clone();
        if let Some(old) = self.token.lock().unwrap_or_else(|e| e.into_inner()).replace(t) {
            super::redact::release(&old.value);
        }
        Ok(value)
    }

    /// The client to call Google's APIs with.
    pub fn client(&self) -> &reqwest::Client {
        &self.http
    }

    /// The email of the service account botd signs in as: the key's, or the metadata
    /// server's default account's.
    pub async fn email(&self) -> Result<String, String> {
        let host = match &self.auth {
            Auth::Key(sa) => return Ok(sa.email.clone()),
            Auth::Metadata { host } => host,
        };
        let what = format!("{}: the metadata server's service account", self.label);
        let res = self.local.get(format!("http://{host}/computeMetadata/v1/instance/service-accounts/default/email")).header("Metadata-Flavor", "Google").send().await.map_err(|e| format!("{what}: {e}"))?;
        let status = res.status();
        let text = res.text().await.map_err(|e| format!("{what}: {e}"))?;
        let email = text.trim();
        if !status.is_success() {
            return Err(format!("{what} answered {status}"));
        }
        if email.is_empty() || email.len() > 254 || !email.contains('@') || !email.bytes().all(|b| b.is_ascii_alphanumeric() || b"@.-_".contains(&b)) {
            return Err(format!("{what} isn't an email"));
        }
        Ok(email.to_string())
    }

    /// Signs in at `base` instead: a stand-in for the metadata server.
    #[cfg(test)]
    pub fn point_at(&mut self, base: &str) {
        if let Auth::Metadata { host } = &mut self.auth {
            *host = base.trim_start_matches("http://").to_string();
        }
    }
}

impl Drop for Google {
    fn drop(&mut self) {
        if let Some(t) = self.token.get_mut().unwrap_or_else(|e| e.into_inner()).take() {
            super::redact::release(&t.value);
        }
    }
}

struct Endpoints {
    location: Option<String>,
    endpoint: String,
    iam_endpoint: String,
    sts_endpoint: String,
}

fn endpoints(var: &dyn Fn(&str) -> String) -> Result<Endpoints, String> {
    let location = match var("GCP_SECRET_MANAGER_LOCATION").trim() {
        "" => None,
        l => Some(name_setting("GCP_SECRET_MANAGER_LOCATION", l, "europe-west2")?),
    };
    let endpoint = match (var("GCP_SECRET_MANAGER_ENDPOINT").trim(), &location) {
        ("", None) => "https://secretmanager.googleapis.com".to_string(),
        ("", Some(l)) => format!("https://secretmanager.{l}.rep.googleapis.com"),
        (e, _) => http::base_url("GCP_SECRET_MANAGER_ENDPOINT", e, "https://secretmanager.googleapis.com")?,
    };
    let iam_endpoint = match var("GCP_IAM_CREDENTIALS_ENDPOINT").trim() {
        "" => IAM_CREDENTIALS.to_string(),
        e => http::base_url("GCP_IAM_CREDENTIALS_ENDPOINT", e, IAM_CREDENTIALS)?,
    };
    let sts_endpoint = match var("GCP_STS_ENDPOINT").trim() {
        "" => STS.to_string(),
        e => http::base_url("GCP_STS_ENDPOINT", e, STS)?,
    };
    Ok(Endpoints { location, endpoint, iam_endpoint, sts_endpoint })
}

/// Where signing in to Google as `method_var` says reaches, as `(setting, URL, what)`, for
/// `botd offline check` (ADR 0257). A service account key's own `token_uri` is read from
/// `GCP_SERVICE_ACCOUNT_KEY_FILE` when it can be; a key kept elsewhere is taken to use Google's.
pub fn sign_in_reaches(var: &dyn Fn(&str) -> String, method_var: &str, method: &str) -> Result<Vec<(&'static str, String, &'static str)>, String> {
    match method.trim() {
        "" | "metadata" => {
            let host = match var("GCE_METADATA_HOST").trim() {
                "" => METADATA_HOST.to_string(),
                h => h.to_string(),
            };
            Ok(vec![("GCE_METADATA_HOST", format!("http://{host}"), "Google's metadata server")])
        }
        "service-account-key" => {
            let file = var("GCP_SERVICE_ACCOUNT_KEY_FILE");
            let from_key = std::fs::read_to_string(file.trim()).ok().and_then(|j| serde_json::from_str::<Value>(&j).ok()).and_then(|v| v["token_uri"].as_str().map(String::from));
            Ok(vec![("GCP_SERVICE_ACCOUNT_KEY", from_key.unwrap_or_else(|| TOKEN_URI.to_string()), "the service account key's token URI")])
        }
        other => Err(format!("{method_var} must be metadata or service-account-key, not {other:?}")),
    }
}

/// What Secret Manager reaches with these settings, as `(setting, URL, what)`, for `botd
/// offline check` (ADR 0257): its endpoint, sign-in, and IAM Credentials and STS for runs.
pub fn reaches(var: &dyn Fn(&str) -> String) -> Result<Vec<(&'static str, String, &'static str)>, String> {
    let e = endpoints(var)?;
    let mut out = vec![("GCP_SECRET_MANAGER_ENDPOINT", e.endpoint, "Google Secret Manager")];
    out.extend(sign_in_reaches(var, "GCP_SECRET_MANAGER_AUTH", &var("GCP_SECRET_MANAGER_AUTH"))?);
    let runs = var("GCP_RUN_CREDENTIALS");
    if !runs.trim().is_empty() {
        out.push(("GCP_IAM_CREDENTIALS_ENDPOINT", e.iam_endpoint, "IAM Credentials, for runs' credentials"));
        if runs.contains("boundary=") {
            out.push(("GCP_STS_ENDPOINT", e.sts_endpoint, "Google STS, for runs' narrowed credentials"));
        }
    }
    Ok(out)
}

impl Config {
    /// `GCP_*` settings; the key comes from `store` (the environment), so `_FILE` works.
    pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Config, String> {
        let (auth, key_project) = sign_in_settings(var, store, "GCP_SECRET_MANAGER_AUTH", &var("GCP_SECRET_MANAGER_AUTH"))?;
        let project = match (var("GCP_SECRET_MANAGER_PROJECT").trim(), key_project) {
            ("", Some(p)) => p,
            ("", None) => return Err("SECRETS_BACKEND=gcp-secret-manager needs GCP_SECRET_MANAGER_PROJECT, the project id the secrets are in".into()),
            (p, _) => p.to_string(),
        };
        let project = name_setting("GCP_SECRET_MANAGER_PROJECT", &project, "my-project-123")?;
        let Endpoints { location, endpoint, iam_endpoint, sts_endpoint } = endpoints(var)?;
        let parent = match &location {
            None => format!("projects/{project}"),
            Some(l) => format!("projects/{project}/locations/{l}"),
        };
        Ok(Config { endpoint, parent, prefix: prefix_setting(&var("GCP_SECRET_MANAGER_PREFIX"))?, auth, iam_endpoint, sts_endpoint })
    }
}

/// CRC32C (Castagnoli), which Secret Manager sends with each payload.
fn crc32c(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
        }
    }
    !c
}

struct Inner {
    cfg: Config,
    http: reqwest::Client,
    /// For the metadata server: link-local, so never through a proxy.
    local: reqwest::Client,
    token: Mutex<Option<Bearer>>,
}

#[derive(Clone)]
pub struct SecretManager {
    inner: Arc<Inner>,
    worker: Arc<Worker>,
}

fn unavailable(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Unavailable(format!("GCP Secret Manager: {what}: {e}"))
}

impl SecretManager {
    pub fn new(cfg: Config) -> Result<SecretManager, String> {
        let http = http::client("GCP Secret Manager", None, false)?;
        let local = http::client("GCP Secret Manager", None, true)?;
        Ok(SecretManager { inner: Arc::new(Inner { cfg, http, local, token: Mutex::new(None) }), worker: Arc::new(Worker::new("GCP Secret Manager", "gcp-secrets")?) })
    }
}

impl Inner {
    fn secret_id(&self, scope: &Scope, name: &str) -> Option<String> {
        let id = format!("{}-{}-{name}", self.cfg.prefix, scope.folder('-'));
        (id.len() <= MAX_ID).then_some(id)
    }

    fn name_in(&self, scope: &Scope, id: &str) -> Option<String> {
        id.strip_prefix(&format!("{}-{}-", self.cfg.prefix, scope.folder('-'))).filter(|n| !n.is_empty()).map(String::from)
    }

    fn method(&self) -> &'static str {
        method_of(&self.cfg.auth)
    }

    async fn token(&self, fresh: bool) -> Result<Zeroizing<String>, Error> {
        if !fresh && let Some(t) = self.token.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|t| t.fresh()) {
            return Ok(t.value.clone());
        }
        let result = sign_in("GCP Secret Manager", &self.http, &self.local, &self.cfg.auth).await;
        http::audit_login("gcp-secret-manager", self.method(), &result);
        let t = result?;
        let value = t.value.clone();
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = Some(t);
        Ok(value)
    }

    /// GETs `path` under the endpoint; when Secret Manager refuses the token, gets a new
    /// one and asks once more. None for 404.
    async fn get(&self, path: &str, query: &[(&str, &str)], what: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let url = http::with_query(&format!("{}/v1/{path}", self.cfg.endpoint), query)?;
        for fresh in [false, true] {
            let token = self.token(fresh).await?;
            let res = self.http.get(url.clone()).bearer_auth(token.as_str()).send().await.map_err(|e| unavailable(what, e))?;
            let status = res.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && !fresh {
                continue;
            }
            let body = Zeroizing::new(res.bytes().await.map_err(|e| unavailable(what, e))?.to_vec());
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(Error::Unavailable(format!("GCP Secret Manager answered {status}{} for {what}", http::error_code(&body))));
            }
            return Ok(Some(body));
        }
        unreachable!("the second pass returns")
    }

    async fn read(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let Some(id) = self.secret_id(&scope, name) else { return Ok(None) };
        let path = format!("{}/secrets/{id}/versions/latest:access", self.cfg.parent);
        // A disabled or destroyed latest version answers 400 (FAILED_PRECONDITION), which
        // fails closed like any other refusal; only a secret with no versions is "not there".
        let Some(body) = self.get(&path, &[], &id).await? else { return Ok(None) };
        let v: Value = serde_json::from_slice(&body).map_err(|e| unavailable(&id, e))?;
        let data = v["payload"]["data"].as_str().ok_or_else(|| Error::Unavailable(format!("GCP Secret Manager: {id} gave an answer with no payload")))?;
        let bytes = Zeroizing::new(STANDARD.decode(data).map_err(|e| unavailable(&id, e))?);
        // Secret Manager stores a checksum with every version and sends it on each access.
        let want = http::seconds(&v["payload"]["dataCrc32c"]).ok_or_else(|| Error::Unavailable(format!("GCP Secret Manager: {id} gave an answer with no valid CRC32C")))?;
        if u64::from(crc32c(&bytes)) != want {
            return Err(Error::Unavailable(format!("GCP Secret Manager: {id} arrived corrupted (CRC32C mismatch)")));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Error::Unavailable(format!("GCP Secret Manager: {id} isn't UTF-8 text")))?;
        Ok((!text.is_empty()).then(|| Zeroizing::new(text.to_string())))
    }

    async fn list(&self, scope: Scope) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        let mut page_token = String::new();
        let path = format!("{}/secrets", self.cfg.parent);
        for _ in 0..1000 {
            let mut q = vec![("pageSize", "250")];
            if !page_token.is_empty() {
                q.push(("pageToken", page_token.as_str()));
            }
            let body = self.get(&path, &q, "listing secrets").await?.ok_or_else(|| Error::Unavailable("GCP Secret Manager: listing secrets answered 404; check GCP_SECRET_MANAGER_PROJECT".into()))?;
            let v: Value = serde_json::from_slice(&body).map_err(|e| unavailable("listing secrets", e))?;
            // An empty project answers `{}`; anything else odd fails closed, rather than
            // passing as a list without the names botd needs.
            let odd = || Error::Unavailable("GCP Secret Manager: listing secrets gave an answer that isn't a list of secrets".into());
            if !v.is_object() {
                return Err(odd());
            }
            let secrets = match &v["secrets"] {
                Value::Null => &Vec::new(),
                Value::Array(a) => a,
                _ => return Err(odd()),
            };
            for s in secrets {
                let name = s["name"].as_str().and_then(|n| n.rsplit_once("/secrets/")).ok_or_else(odd)?.1;
                if let Some(name) = self.name_in(&scope, name) {
                    out.push(name);
                }
            }
            match &v["nextPageToken"] {
                Value::Null => return Ok(out),
                Value::String(t) if t.is_empty() => return Ok(out),
                Value::String(t) => page_token = t.clone(),
                _ => return Err(odd()),
            }
        }
        Err(Error::Unavailable("GCP Secret Manager: listing secrets ran past 1000 pages".into()))
    }

    /// A new access token of `email` for one run of `bot_id` (ADR 0203), lasting `run_for`
    /// (at least Google's 5 minutes), asked for with botd's own token, and downscoped to
    /// `boundary` if given (ADR 0240). When Google refuses botd's token, gets a new one and
    /// asks once more.
    async fn impersonate(&self, email: &str, fields: &[String], run_for: Duration, bot_id: &str, boundary: Option<&str>) -> Result<Lease, Error> {
        let secs = run_for.as_secs().max(MIN_LIFETIME);
        if secs > MAX_LIFETIME {
            return Err(Error::Unavailable(format!("GCP IAM: a run may last {secs} s (RUN_TIMEOUT_MINUTES), longer than Google's longest access token ({MAX_LIFETIME} s), so GCP_RUN_CREDENTIALS can't cover it")));
        }
        if email.split_once('@').is_none_or(|(account, _)| account.len() > MAX_ACCOUNT_ID) {
            return Err(Error::Unavailable(format!("GCP IAM: {email} can't be a service account: its id, before the @, is at most {MAX_ACCOUNT_ID} characters")));
        }
        let what = format!("generateAccessToken for {email}");
        let url = format!("{}/v1/projects/-/serviceAccounts/{email}:generateAccessToken", self.cfg.iam_endpoint);
        let body = json!({ "scope": [SCOPE], "lifetime": format!("{secs}s") });
        for fresh in [false, true] {
            let token = self.token(fresh).await?;
            let res = self.http.post(&url).bearer_auth(token.as_str()).json(&body).send().await.map_err(|e| iam_unavailable(&what, e))?;
            let status = res.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && !fresh {
                continue;
            }
            let reply = Zeroizing::new(res.bytes().await.map_err(|e| iam_unavailable(&what, e))?.to_vec());
            if status.is_success() {
                let (token, expires) = access_token(&reply, secs, &what)?;
                let (token, expires) = match boundary {
                    Some(b) => self.downscope(&token, b, expires, secs, email).await?,
                    None => (token, expires),
                };
                return Ok(token_lease(token, secs_until(expires), email, fields, bot_id));
            }
            let hint = match status.as_u16() {
                403 => "; botd's service account needs roles/iam.serviceAccountTokenCreator on it, and the IAM Service Account Credentials API must be on in botd's project".to_string(),
                404 => "; is there a service account by that email?".to_string(),
                400 if secs > DEFAULT_LIFETIME => format!("; a token of more than {DEFAULT_LIFETIME} s needs the organization policy constraints/iam.allowServiceAccountCredentialLifetimeExtension to list the service account, or keep RUN_TIMEOUT_MINUTES at 60 or less"),
                _ => String::new(),
            };
            return Err(Error::Unavailable(format!("GCP IAM answered {status}{} for {what}{hint}", http::error_code(&reply))));
        }
        unreachable!("the second pass returns")
    }

    /// `token`, of `email`, traded at Google's Security Token Service for one that can do
    /// only what `boundary` (a Credential Access Boundary, as JSON) allows. It ends when
    /// `token` does (`expires`), or sooner if STS says so; one that ends more than a minute
    /// before the run could (`run_for`) is refused. The exchange needs no other credential:
    /// `token` is its own proof.
    async fn downscope(&self, token: &str, boundary: &str, expires: chrono::DateTime<chrono::Utc>, run_for: u64, email: &str) -> Result<(Zeroizing<String>, chrono::DateTime<chrono::Utc>), Error> {
        let what = format!("downscoping the token of {email}");
        let url = format!("{}/v1/token", self.cfg.sts_endpoint);
        let form = [("grant_type", TOKEN_EXCHANGE), ("subject_token_type", ACCESS_TOKEN_TYPE), ("requested_token_type", ACCESS_TOKEN_TYPE), ("subject_token", token), ("options", boundary)];
        let unavailable = |e: &dyn std::fmt::Display| Error::Unavailable(format!("GCP STS: {what}: {e}"));
        let res = self.http.post(&url).form(&form).send().await.map_err(|e| unavailable(&e))?;
        let status = res.status();
        let reply = Zeroizing::new(res.bytes().await.map_err(|e| unavailable(&e))?.to_vec());
        if !status.is_success() {
            let hint = match status.as_u16() {
                400 => "; check the entry's boundary= file: Google takes only roles it knows after inRole: and conditions in CEL",
                403 => "; the Security Token Service API (sts.googleapis.com) must be on in botd's project",
                _ => "",
            };
            return Err(Error::Unavailable(format!("GCP STS answered {status}{} for {what}{hint}", http::error_code(&reply))));
        }
        let bad = |why: &str| Error::Unavailable(format!("GCP STS: {what} {why}"));
        let v: Value = serde_json::from_slice(&reply).map_err(|_| bad("answered with something that isn't JSON"))?;
        let down = v["access_token"].as_str().filter(|t| !t.is_empty() && t.len() <= MAX_DOWNSCOPED && t.bytes().all(|b| b.is_ascii_graphic())).ok_or_else(|| bad("gave no access token"))?;
        if down == token {
            return Err(bad("gave back the token it was sent, not a downscoped one"));
        }
        // Counted from the source token's own expiry, not its TTL before the exchange, so the
        // time the exchange took isn't added back.
        let stated = http::seconds(&v["expires_in"]).and_then(|s| i64::try_from(s).ok()).map(|s| chrono::Utc::now() + chrono::Duration::seconds(s));
        let expires = stated.map_or(expires, |at| at.min(expires));
        let ttl = secs_until(expires);
        if ttl + 60 < run_for {
            return Err(bad(&format!("gave a token that ends in {ttl} s, but a run may last {run_for} s (RUN_TIMEOUT_MINUTES)")));
        }
        Ok((Zeroizing::new(down.to_string()), expires))
    }
}

fn iam_unavailable(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Unavailable(format!("GCP IAM: {what}: {e}"))
}

/// The token in `generateAccessToken`'s answer, and when it expires. A token that ends
/// before the run could is refused.
fn access_token(body: &[u8], run_for: u64, what: &str) -> Result<(Zeroizing<String>, chrono::DateTime<chrono::Utc>), Error> {
    let bad = |why: &str| Error::Unavailable(format!("GCP IAM: {what} {why}"));
    let v: Value = serde_json::from_slice(body).map_err(|_| bad("answered with something that isn't JSON"))?;
    let token = v["accessToken"].as_str().filter(|t| !t.is_empty() && t.len() <= 8192 && t.bytes().all(|b| b.is_ascii_graphic())).ok_or_else(|| bad("gave no access token"))?;
    let expires = v["expireTime"].as_str().and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok()).ok_or_else(|| bad("gave a token with no expiry"))?;
    let expires = expires.with_timezone(&chrono::Utc);
    let ttl = secs_until(expires);
    // A minute's slack for clocks; Google makes what was asked for or refuses.
    if ttl + 60 < run_for {
        return Err(bad(&format!("gave a token that ends in {ttl} s, but a run may last {run_for} s (RUN_TIMEOUT_MINUTES)")));
    }
    Ok((Zeroizing::new(token.to_string()), expires))
}

/// Whole seconds from now until `at`; 0 if it has passed.
fn secs_until(at: chrono::DateTime<chrono::Utc>) -> u64 {
    u64::try_from(at.timestamp() - chrono::Utc::now().timestamp()).unwrap_or(0)
}

/// A run's lease of `token`: under each field asked for, lasting `ttl`. Google gives a
/// token no id, so the lease's is the account and `superbot-<bot id>-<random>`, for
/// SuperBot's own audit log.
fn token_lease(token: Zeroizing<String>, ttl: u64, email: &str, fields: &[String], bot_id: &str) -> Lease {
    let fields = fields.iter().map(|f| if f == "accessToken" { Field::Value(token.clone()) } else { Field::Missing }).collect();
    Lease { id: format!("{email}/{}", super::aws::session_name(bot_id)), ttl, renewable: false, fields }
}

/// A signed JWT that trades for an access token (RFC 7523), good for an hour.
fn jwt(sa: &ServiceAccount) -> Result<Zeroizing<String>, String> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let mut header = json!({ "alg": "RS256", "typ": "JWT" });
    if let Some(kid) = &sa.key_id {
        header["kid"] = json!(kid);
    }
    let claims = json!({ "iss": sa.email, "scope": SCOPE, "aud": sa.token_uri, "iat": now, "exp": now + 3600 });
    let signing_input = format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
    let mut sig = vec![0u8; sa.key.public_modulus_len()];
    sa.key.sign(&RSA_PKCS1_SHA256, &aws_lc_rs::rand::SystemRandom::new(), signing_input.as_bytes(), &mut sig).map_err(|_| "couldn't sign the service account's JWT".to_string())?;
    Ok(Zeroizing::new(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))))
}

impl Provider for SecretManager {
    fn kind(&self) -> &'static str {
        "gcp-secret-manager"
    }

    fn describe(&self) -> String {
        let c = &self.inner.cfg;
        let auth = signs_in_as(&c.auth);
        format!("GCP Secret Manager at {}, {}/secrets/{}-{{bots,server}}-<NAME>, {auth}", c.endpoint, c.parent, c.prefix)
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

impl Issuer for SecretManager {
    fn kind(&self) -> &'static str {
        "gcp-secret-manager"
    }

    fn issue(&self, email: &str, fields: &[String], run_for: Duration, bot_id: &str) -> Result<Lease, Error> {
        self.issue_narrowed(email, fields, run_for, bot_id, &Narrowed::default())
    }

    fn issue_narrowed(&self, email: &str, fields: &[String], run_for: Duration, bot_id: &str, narrowed: &Narrowed) -> Result<Lease, Error> {
        if narrowed.narrows_session() || narrowed.tenant.is_some() {
            return Err(Error::Unavailable("GCP IAM: a token can't be narrowed with a session policy or tags, or asked of an Entra tenant, only an access boundary".into()));
        }
        let (inner, email, fields, bot_id, boundary) = (Arc::clone(&self.inner), email.to_string(), fields.to_vec(), bot_id.to_string(), narrowed.boundary.clone());
        self.worker.run(async move { inner.impersonate(&email, &fields, run_for, &bot_id, boundary.as_deref()).await })
    }

    fn revoke(&self, _lease_id: &str) -> Result<(), Error> {
        Err(Error::Unavailable("GCP IAM: an impersonated access token can't be revoked; it lasts until it expires".into()))
    }

    fn revocable(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::super::env::EnvStore;
    use super::super::external::{tests::audited, ExternalStore, Shared};
    use super::super::http::tests::{serve, settings};
    use super::super::{redact, sealed, Secrets};
    use super::*;
    use crate::audit::Outcome;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::signature::KeyPair;
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::{Form, Json};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    /// A stand-in for Secret Manager, Google's token endpoint and the metadata server:
    /// no real Google Cloud, account or network.
    #[derive(Default)]
    struct Fake {
        /// `<parent>/secrets/<id>` → latest version's bytes.
        secrets: Mutex<HashMap<String, Vec<u8>>>,
        tokens: Mutex<Vec<String>>,
        sign_ins: AtomicUsize,
        reads: AtomicUsize,
        down: AtomicBool,
        corrupt: AtomicBool,
        /// 1: no checksum, 2: a checksum that isn't a number.
        checksum: AtomicUsize,
        /// 1: `secrets` isn't a list, 2: `nextPageToken` isn't a string.
        odd_list: AtomicUsize,
        expires_in: AtomicUsize,
        /// The service account's public key, to check the JWTs it signs.
        public_key: Mutex<Vec<u8>>,
        audiences: Mutex<Vec<String>>,
        /// Each `generateAccessToken`: the caller's `Authorization`, the account, the body.
        impersonated: Mutex<Vec<(String, String, Value)>>,
        /// The access tokens made for runs.
        run_tokens: Mutex<Vec<String>>,
        /// Each token exchange at STS: the subject token, the options as sent, the token made.
        downscoped: Mutex<Vec<(String, String, String)>>,
    }

    type F = Arc<Fake>;

    fn issue(f: &Fake) -> Json<Value> {
        let n = f.sign_ins.fetch_add(1, Ordering::SeqCst);
        let token = format!("ya29.gcp-{n}");
        f.tokens.lock().unwrap().push(token.clone());
        Json(json!({ "access_token": token, "expires_in": f.expires_in.load(Ordering::SeqCst), "token_type": "Bearer" }))
    }

    async fn metadata_token(State(f): State<F>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if h.get("metadata-flavor").and_then(|v| v.to_str().ok()) != Some("Google") {
            return (StatusCode::FORBIDDEN, Json(json!({})));
        }
        (StatusCode::OK, issue(&f))
    }

    async fn oauth_token(State(f): State<F>, Form(form): Form<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
        let bad = || (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant", "error_description": "Invalid JWT Signature." })));
        if form.get("grant_type").map(String::as_str) != Some("urn:ietf:params:oauth:grant-type:jwt-bearer") {
            return bad();
        }
        let jwt = form.get("assertion").cloned().unwrap_or_default();
        let Some((input, sig)) = jwt.rsplit_once('.') else { return bad() };
        let sig = URL_SAFE_NO_PAD.decode(sig).unwrap_or_default();
        let key = f.public_key.lock().unwrap().clone();
        let pk = aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256, key);
        if pk.verify(input.as_bytes(), &sig).is_err() {
            return bad();
        }
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(input.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!((claims["iss"].as_str(), claims["scope"].as_str()), (Some("botd@proj-1.iam.gserviceaccount.com"), Some(SCOPE)));
        f.audiences.lock().unwrap().push(claims["aud"].as_str().unwrap_or_default().to_string());
        (StatusCode::OK, issue(&f))
    }

    fn authorized(f: &Fake, h: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
        if f.down.load(Ordering::SeqCst) {
            return Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": { "code": 503, "status": "UNAVAILABLE", "message": "x" } }))));
        }
        let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default();
        if !f.tokens.lock().unwrap().iter().any(|t| auth == format!("Bearer {t}")) {
            return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": { "code": 401, "status": "UNAUTHENTICATED", "message": "x" } }))));
        }
        Ok(())
    }

    /// `/v1/projects/...`: an access (`.../versions/latest:access`) or a list (`.../secrets`).
    async fn api(State(f): State<F>, Path(rest): Path<String>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if let Err(e) = authorized(&f, &h) {
            return e;
        }
        if let Some(secret) = rest.strip_suffix("/versions/latest:access") {
            f.reads.fetch_add(1, Ordering::SeqCst);
            if secret.ends_with("-DISABLED_TOKEN") {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": { "code": 400, "status": "FAILED_PRECONDITION", "message": "is in DISABLED state" } })));
            }
            let found = f.secrets.lock().unwrap().get(secret).cloned();
            return match found {
                Some(bytes) => {
                    let crc = crc32c(&bytes) ^ u32::from(f.corrupt.load(Ordering::SeqCst));
                    let crc = match f.checksum.load(Ordering::SeqCst) {
                        1 => Value::Null,
                        2 => json!("invalid"),
                        _ => json!(crc.to_string()),
                    };
                    (StatusCode::OK, Json(json!({ "name": format!("{secret}/versions/3"), "payload": { "data": STANDARD.encode(&bytes), "dataCrc32c": crc } })))
                }
                None => (StatusCode::NOT_FOUND, Json(json!({ "error": { "code": 404, "status": "NOT_FOUND", "message": "x" } }))),
            };
        }
        match f.odd_list.load(Ordering::SeqCst) {
            1 => return (StatusCode::OK, Json(json!({ "secrets": "invalid" }))),
            2 => return (StatusCode::OK, Json(json!({ "secrets": [], "nextPageToken": 7 }))),
            _ => {}
        }
        let parent = rest.strip_suffix("/secrets").unwrap_or(&rest);
        let mut ids: Vec<String> = f.secrets.lock().unwrap().keys().filter_map(|k| k.strip_prefix(&format!("{parent}/secrets/")).map(String::from)).collect();
        ids.sort();
        let start: usize = q.get("pageToken").and_then(|t| t.parse().ok()).unwrap_or(0);
        // The API names secrets by project number, not id.
        let page: Vec<Value> = ids.iter().skip(start).take(2).map(|id| json!({ "name": format!("projects/123456789/secrets/{id}") })).collect();
        let next = (start + 2 < ids.len()).then(|| (start + 2).to_string());
        if page.is_empty() {
            return (StatusCode::OK, Json(json!({})));
        }
        (StatusCode::OK, Json(json!({ "secrets": page, "nextPageToken": next, "totalSize": ids.len() })))
    }

    /// IAM Credentials' `projects/-/serviceAccounts/<email>:generateAccessToken`. Accounts
    /// named `denied`, `missing` and `odd` are refused or answered oddly, `short` gets a
    /// token of ten minutes, and lifetimes over an hour are refused, as without the
    /// organization policy that allows them.
    async fn iam(State(f): State<F>, Path(rest): Path<String>, h: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
        if let Err(e) = authorized(&f, &h) {
            return e;
        }
        let Some(email) = rest.strip_prefix("projects/-/serviceAccounts/").and_then(|r| r.strip_suffix(":generateAccessToken")) else {
            return (StatusCode::NOT_FOUND, Json(json!({})));
        };
        let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        f.impersonated.lock().unwrap().push((auth, email.to_string(), body.clone()));
        let refuse = |code: StatusCode, status: &str| (code, Json(json!({ "error": { "code": code.as_u16(), "status": status, "message": "quoting-the-request" } })));
        let lifetime: i64 = body["lifetime"].as_str().and_then(|l| l.strip_suffix('s')).and_then(|l| l.parse().ok()).unwrap_or(3600);
        match email.split('@').next().unwrap_or_default() {
            "denied" => return refuse(StatusCode::FORBIDDEN, "PERMISSION_DENIED"),
            "missing" => return refuse(StatusCode::NOT_FOUND, "NOT_FOUND"),
            "odd" => return (StatusCode::OK, Json(json!({ "expireTime": "2030-01-01T00:00:00Z" }))),
            _ if lifetime > 3600 => return refuse(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT"),
            _ => {}
        }
        let lifetime = if email.starts_with("short@") { 600 } else { lifetime };
        let token = format!("ya29.run-{}", crate::random_hex(8));
        f.run_tokens.lock().unwrap().push(token.clone());
        let at = (chrono::Utc::now() + chrono::Duration::seconds(lifetime)).to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        (StatusCode::OK, Json(json!({ "accessToken": token, "expireTime": at })))
    }

    /// STS's `v1/token`: trades a run token IAM Credentials made, and nothing else, for a
    /// downscoped one, as Google does for a service account's token (no `expires_in`). The
    /// first rule's bucket picks an odd answer: `refused`, `forbidden`, `short`, `echo`, `odd`,
    /// or `slow` (two seconds late).
    async fn sts(State(f): State<F>, Form(form): Form<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
        let refuse = |code: StatusCode, error: &str| (code, Json(json!({ "error": error, "error_description": "quoting-the-request" })));
        if f.down.load(Ordering::SeqCst) {
            return refuse(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
        let get = |k: &str| form.get(k).cloned().unwrap_or_default();
        if get("grant_type") != TOKEN_EXCHANGE || get("subject_token_type") != ACCESS_TOKEN_TYPE || get("requested_token_type") != ACCESS_TOKEN_TYPE {
            return refuse(StatusCode::BAD_REQUEST, "invalid_request");
        }
        let subject = get("subject_token");
        if !f.run_tokens.lock().unwrap().contains(&subject) {
            return refuse(StatusCode::BAD_REQUEST, "invalid_grant");
        }
        let Ok(options) = serde_json::from_str::<Value>(&get("options")) else { return refuse(StatusCode::BAD_REQUEST, "invalid_request") };
        let bucket = options["accessBoundary"]["accessBoundaryRules"][0]["availableResource"].as_str().and_then(|r| r.rsplit('/').next()).unwrap_or_default().to_string();
        let token = match bucket.as_str() {
            "echo" => subject.clone(),
            "short" => "ya29.down-short".to_string(),
            _ => format!("ya29.down-{}", crate::random_hex(8)),
        };
        f.downscoped.lock().unwrap().push((subject, get("options"), token.clone()));
        if bucket == "slow" {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        match bucket.as_str() {
            "refused" => refuse(StatusCode::BAD_REQUEST, "invalid_request"),
            "forbidden" => refuse(StatusCode::FORBIDDEN, "access_denied"),
            "odd" => (StatusCode::OK, Json(json!({ "token_type": "Bearer" }))),
            "short" => (StatusCode::OK, Json(json!({ "access_token": token, "expires_in": 60, "token_type": "Bearer" }))),
            _ => (StatusCode::OK, Json(json!({ "access_token": token, "issued_token_type": ACCESS_TOKEN_TYPE, "token_type": "Bearer" }))),
        }
    }

    fn stand_in() -> (String, F) {
        let f = F::default();
        f.expires_in.store(3599, Ordering::SeqCst);
        let app = axum::Router::new()
            .route("/computeMetadata/v1/instance/service-accounts/default/token", axum::routing::get(metadata_token))
            .route("/token", axum::routing::post(oauth_token))
            .route("/v1/token", axum::routing::post(sts))
            .route("/v1/{*rest}", axum::routing::get(api).post(iam))
            .with_state(Arc::clone(&f));
        (serve(app), f)
    }

    fn put(f: &Fake, path: &str, value: &str) {
        f.secrets.lock().unwrap().insert(format!("projects/proj-1/{path}"), value.as_bytes().to_vec());
    }

    fn store(url: &str, extra: &[(&str, &str)], ttl: Duration) -> Arc<ExternalStore> {
        let host = url.trim_start_matches("http://");
        let mut pairs = vec![("SECRETS_BACKEND", "gcp-secret-manager"), ("GCP_SECRET_MANAGER_ENDPOINT", url), ("GCE_METADATA_HOST", host)];
        pairs.extend_from_slice(extra);
        if !extra.iter().any(|(k, _)| *k == "GCP_SERVICE_ACCOUNT_KEY") && !extra.iter().any(|(k, _)| *k == "GCP_SECRET_MANAGER_PROJECT") {
            pairs.push(("GCP_SECRET_MANAGER_PROJECT", "proj-1"));
        }
        let cfg = Config::from_env(&settings(&pairs), &EnvStore::fixed(extra)).unwrap();
        Arc::new(ExternalStore::new(Box::new(SecretManager::new(cfg).unwrap()), ttl))
    }

    /// A new RSA key, as a service account key file holds it.
    fn key_file(f: &Fake, token_uri: &str) -> String {
        let kp = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        *f.public_key.lock().unwrap() = kp.public_key().as_ref().to_vec();
        let der = kp.as_der().unwrap();
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", STANDARD.encode(der.as_ref()));
        json!({ "type": "service_account", "project_id": "proj-1", "private_key_id": "kid-1", "private_key": pem, "client_email": "botd@proj-1.iam.gserviceaccount.com", "token_uri": token_uri }).to_string()
    }

    #[test]
    fn reads_bot_and_server_secrets_from_the_metadata_server() {
        let (url, f) = stand_in();
        let bot_value = format!("sk-gcp-{}", crate::random_hex(10));
        put(&f, "secrets/superbot-bots-OPENAI_API_KEY", &bot_value);
        put(&f, "secrets/superbot-bots-LINODE_TOKEN", "never-from-the-bots-folder");
        put(&f, "secrets/superbot-server-LINODE_TOKEN", "linode-from-gcp-1");
        put(&f, "secrets/other-app-SECRET", "not-ours");
        let s = store(&url, &[], Duration::from_secs(60));
        assert_eq!(s.check().unwrap(), 2, "OPENAI_API_KEY and LINODE_TOKEN, each from its own folder, across pages");
        assert_eq!(s.get("OPENAI_API_KEY").unwrap().unwrap().expose(), bot_value);
        assert_eq!(s.get("LINODE_TOKEN").unwrap().unwrap().expose(), "linode-from-gcp-1");
        assert!(s.get("NOT_THERE_TOKEN").unwrap().is_none());
        let reads = f.reads.load(Ordering::SeqCst);
        s.get("OPENAI_API_KEY").unwrap();
        assert_eq!(f.reads.load(Ordering::SeqCst), reads, "cached");
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 1);
        assert_eq!(redact::text(&bot_value), redact::MARK);

        let path = crate::db::temp_path("gcp-facade").join("app.sqlite");
        let sealed = sealed::SealedStore::new(sealed::connect(&path).unwrap(), sealed::cipher());
        let secrets = Secrets::new(vec![Box::new(EnvStore::fixed(&[])), Box::new(Shared(Arc::clone(&s))), Box::new(sealed)]);
        secrets.put("OPENAI_API_KEY", "sealed-but-shadowed-gcp").unwrap();
        let env: Vec<(String, String)> = secrets.try_harness_env().unwrap().into_iter().map(|(k, v)| (k, v.expose().to_string())).collect();
        assert_eq!(env, [("OPENAI_API_KEY".to_string(), bot_value.clone())], "Secret Manager's value wins, and botd's own never reach Bots");
        assert_eq!(secrets.source("LINODE_TOKEN").unwrap(), Some(("gcp-secret-manager", false)));
        assert!(audited("gcp-secret-manager").iter().any(|e| e.action == "secret.backend_login" && e.details["method"] == "metadata"));
        for v in [bot_value.as_str(), "linode-from-gcp-1", "sealed-but-shadowed-gcp"] {
            redact::forget(v);
        }
    }

    #[test]
    fn reads_each_users_own_folder() {
        let (url, f) = stand_in();
        let value = format!("ua1-gcp-{}", crate::random_hex(10));
        put(&f, "secrets/superbot-users-ua1-OPENAI_API_KEY", &value);
        put(&f, "secrets/superbot-users-ua1-LINODE_TOKEN", "never-from-a-users-folder");
        put(&f, "secrets/superbot-users-ub1-OPENAI_API_KEY", "ub1-own-openai");
        put(&f, "secrets/superbot-users-ua10-OPENAI_API_KEY", "not-ua1s");
        let x = super::super::external::tests::users_on(store(&url, &[], Duration::from_secs(60)));
        super::super::external::tests::reads_users_folders(&x, &value);
    }

    #[test]
    fn a_service_account_key_signs_in_and_again_when_refused() {
        let (url, f) = stand_in();
        put(&f, "locations/europe-west2/secrets/acme-server-SMTP_PASSWORD", "smtp-from-gcp-1");
        let key = key_file(&f, &format!("{url}/token"));
        let creds = [("GCP_SECRET_MANAGER_AUTH", "service-account-key"), ("GCP_SERVICE_ACCOUNT_KEY", key.as_str()), ("GCP_SECRET_MANAGER_LOCATION", "europe-west2"), ("GCP_SECRET_MANAGER_PREFIX", "acme")];
        let s = store(&url, &creds, Duration::ZERO);
        assert_eq!(s.check().unwrap(), 1, "the project comes from the key, the region from the setting");
        assert_eq!(s.get("SMTP_PASSWORD").unwrap().unwrap().expose(), "smtp-from-gcp-1");
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 1);
        assert_eq!(f.audiences.lock().unwrap()[0], format!("{url}/token"));
        f.tokens.lock().unwrap().clear();
        assert!(s.get("SMTP_PASSWORD").unwrap().is_some(), "refused: signs in once more and retries");
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 2);

        // A key the token endpoint doesn't know: refused, audited, no description logged.
        let other = key_file(&Fake::default(), &format!("{url}/token"));
        let bad = store(&url, &[("GCP_SECRET_MANAGER_AUTH", "service-account-key"), ("GCP_SERVICE_ACCOUNT_KEY", other.as_str())], Duration::ZERO);
        let e = bad.check().unwrap_err().to_string();
        assert!(e.contains("400") && e.contains("invalid_grant") && !e.contains("Signature"), "{e}");
        let logins = audited("gcp-secret-manager");
        assert!(logins.iter().any(|e| e.outcome == Outcome::Failure && e.details["method"] == "service-account-key"));
        assert!(!format!("{logins:?}").contains("PRIVATE KEY"));
        redact::forget("smtp-from-gcp-1");
    }

    #[tokio::test]
    async fn another_service_signs_in_as_the_same_identity_and_masks_its_tokens_while_held() {
        let (url, f) = stand_in();
        let key = key_file(&f, &format!("{url}/token"));
        let vars = [("GCP_SERVICE_ACCOUNT_KEY", key.as_str())];
        let g = Google::from_env(&settings(&vars), &EnvStore::fixed(&vars), "AUDIT_EXPORT_GCP_AUTH", "service-account-key", "Google SecOps").unwrap();
        assert_eq!((g.method(), g.describe().as_str()), ("service-account-key", "service account key for botd@proj-1.iam.gserviceaccount.com"));
        let first = g.token(false).await.unwrap();
        assert_eq!(*g.token(false).await.unwrap(), *first, "kept while it lasts");
        assert_eq!(redact::text(&format!("x {} y", first.as_str())), format!("x {} y", redact::MARK));
        let second = g.token(true).await.unwrap();
        assert_ne!(*second, *first, "asked again when refused");
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 2);
        assert_eq!(redact::text(second.as_str()), redact::MARK);

        let other = key_file(&Fake::default(), &format!("{url}/token"));
        let vars = [("GCP_SERVICE_ACCOUNT_KEY", other.as_str())];
        let g = Google::from_env(&settings(&vars), &EnvStore::fixed(&vars), "AUDIT_EXPORT_GCP_AUTH", "service-account-key", "Google SecOps").unwrap();
        let e = g.token(false).await.unwrap_err();
        assert!(e.starts_with("Google SecOps: service-account-key sign-in answered 400") && e.contains("invalid_grant") && !e.contains("Signature"), "{e}");
        let e = Google::from_env(&settings(&[]), &EnvStore::fixed(&[]), "AUDIT_EXPORT_GCP_AUTH", "key", "Google SecOps").err().unwrap();
        assert_eq!(e, "AUDIT_EXPORT_GCP_AUTH must be metadata or service-account-key, not \"key\"");
    }

    #[test]
    fn secret_manager_down_disabled_or_corrupt_fails_closed() {
        let (url, f) = stand_in();
        put(&f, "secrets/superbot-bots-DOWN_API_KEY", "down-gcp-value-1");
        put(&f, "secrets/superbot-bots-DISABLED_TOKEN", "disabled-gcp-1");
        put(&f, "secrets/superbot-bots-CRC_TOKEN", "crc-gcp-1");
        let s = store(&url, &[], Duration::from_millis(200));
        let path = crate::db::temp_path("gcp-down").join("app.sqlite");
        let sealed = sealed::SealedStore::new(sealed::connect(&path).unwrap(), sealed::cipher());
        let secrets = Secrets::new(vec![Box::new(EnvStore::fixed(&[])), Box::new(Shared(Arc::clone(&s))), Box::new(sealed)]);
        for n in ["DOWN_API_KEY", "DISABLED_TOKEN", "CRC_TOKEN"] {
            secrets.put(n, "the-sealed-fallback-gcp").unwrap();
        }
        assert_eq!(secrets.get("DOWN_API_KEY").unwrap().unwrap().expose(), "down-gcp-value-1");
        let e = secrets.get("DISABLED_TOKEN").unwrap_err().to_string();
        assert!(e.contains("FAILED_PRECONDITION"), "a disabled version never uncovers the sealed copy: {e}");
        f.corrupt.store(true, Ordering::SeqCst);
        let e = secrets.get("CRC_TOKEN").unwrap_err().to_string();
        assert!(e.contains("CRC32C"), "{e}");
        f.corrupt.store(false, Ordering::SeqCst);
        for mode in [1, 2] {
            f.checksum.store(mode, Ordering::SeqCst);
            let e = secrets.get("CRC_TOKEN").unwrap_err().to_string();
            assert!(e.contains("no valid CRC32C"), "a missing or malformed checksum fails closed: {e}");
        }
        f.checksum.store(0, Ordering::SeqCst);
        for mode in [1, 2] {
            f.odd_list.store(mode, Ordering::SeqCst);
            let e = s.check().unwrap_err().to_string();
            assert!(e.contains("isn't a list of secrets"), "an odd list fails closed: {e}");
        }
        f.odd_list.store(0, Ordering::SeqCst);
        f.down.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(250));
        assert!(matches!(secrets.get("DOWN_API_KEY"), Err(Error::Unavailable(_))), "never the sealed value under it");
        assert!(matches!(secrets.try_harness_env(), Err(Error::Unavailable(_))));
        assert!(audited("DOWN_API_KEY").iter().any(|e| e.outcome == Outcome::Failure && e.details["store"] == "gcp-secret-manager"));
        redact::forget("down-gcp-value-1");
        redact::forget("the-sealed-fallback-gcp");
    }

    use super::super::leases::tests::RUN;
    use super::super::leases::RunCredentials;

    /// `SECRETS_BACKEND=gcp-secret-manager` on the stand-in, with the metadata server and `GCP_RUN_CREDENTIALS`.
    fn run_credentials(url: &str, accounts: &str) -> Arc<RunCredentials> {
        let host = url.trim_start_matches("http://");
        let pairs = [
            ("SECRETS_BACKEND", "gcp-secret-manager"),
            ("GCP_SECRET_MANAGER_PROJECT", "proj-1"),
            ("GCP_SECRET_MANAGER_ENDPOINT", url),
            ("GCP_IAM_CREDENTIALS_ENDPOINT", url),
            ("GCP_STS_ENDPOINT", url),
            ("GCE_METADATA_HOST", host),
            ("GCP_RUN_CREDENTIALS", accounts),
        ];
        let x = super::super::external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap().unwrap();
        Arc::clone(x.run_credentials().expect("GCP_RUN_CREDENTIALS is read with SECRETS_BACKEND=gcp-secret-manager"))
    }

    fn values(env: &[(String, super::super::Secret)]) -> HashMap<String, String> {
        env.iter().map(|(k, v)| (k.clone(), v.expose().to_string())).collect()
    }

    #[test]
    fn each_run_gets_its_own_token_of_the_service_account_it_impersonates() {
        let (url, f) = stand_in();
        let rc = run_credentials(&url, "superbot-bots@proj-1.iam.gserviceaccount.com; superbot-u-{owner}@proj-1.iam.gserviceaccount.com OWN_GCP_TOKEN=accessToken");
        assert!(rc.describe().contains("superbot-bots@proj-1.iam.gserviceaccount.com, superbot-u-{owner}@proj-1.iam.gserviceaccount.com"));
        let (e1, l1) = rc.issue("ugcp7", "bgcp7", true, RUN).unwrap();
        let (e2, l2) = rc.issue("ugcp7", "bgcp7", false, Duration::from_secs(60)).unwrap();
        let (v1, v2) = (values(&e1), values(&e2));
        let mut names: Vec<&str> = v1.keys().map(String::as_str).collect();
        names.sort();
        assert_eq!(names, ["CLOUDSDK_AUTH_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN", "OWN_GCP_TOKEN"]);
        assert_eq!(v1["CLOUDSDK_AUTH_ACCESS_TOKEN"], v1["GOOGLE_OAUTH_ACCESS_TOKEN"], "one token for gcloud and Terraform");
        assert_ne!(v1["CLOUDSDK_AUTH_ACCESS_TOKEN"], v1["OWN_GCP_TOKEN"]);
        assert_eq!(v2.len(), 2, "a run for someone else gets no owner's account");
        assert_ne!(v1["GOOGLE_OAUTH_ACCESS_TOKEN"], v2["GOOGLE_OAUTH_ACCESS_TOKEN"], "each run its own token");
        assert!(f.run_tokens.lock().unwrap().contains(&v1["OWN_GCP_TOKEN"]), "the token Google made");
        assert_eq!(redact::text(&format!("leaked {}", v1["OWN_GCP_TOKEN"])), format!("leaked {}", redact::MARK));

        let calls = f.impersonated.lock().unwrap().clone();
        assert_eq!(calls.iter().map(|(_, sa, _)| sa.as_str()).collect::<Vec<_>>(), ["superbot-bots@proj-1.iam.gserviceaccount.com", "superbot-u-ugcp7@proj-1.iam.gserviceaccount.com", "superbot-bots@proj-1.iam.gserviceaccount.com"]);
        let botd = f.tokens.lock().unwrap().clone();
        assert!(calls.iter().all(|(auth, ..)| botd.iter().any(|t| *auth == format!("Bearer {t}"))), "asked with botd's own token from the metadata server, checked by the stand-in");
        assert_eq!(calls[0].2, json!({ "scope": [SCOPE], "lifetime": "3600s" }), "as long as the longest run");
        assert_eq!(calls[2].2["lifetime"], "300s", "at least Google's 5 minutes");

        let ev: Vec<_> = audited("superbot-bots@proj-1.iam.gserviceaccount.com").into_iter().filter(|e| e.bot_id.as_deref() == Some("bgcp7")).collect();
        let issued = ev.iter().find(|e| e.action == "secret.lease_issued").unwrap();
        let id = issued.details["leaseId"].as_str().unwrap();
        assert!(id.starts_with("superbot-bots@proj-1.iam.gserviceaccount.com/superbot-bgcp7-"), "{id}");
        assert_eq!((issued.details["store"].as_str(), issued.details["renewable"].as_bool()), (Some("gcp-secret-manager"), Some(false)));
        assert_eq!(issued.details["names"], json!(["CLOUDSDK_AUTH_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN"]));
        assert!((3590..=3600).contains(&issued.details["ttl"].as_u64().unwrap()));
        assert!(!format!("{ev:?}").contains(&v1["GOOGLE_OAUTH_ACCESS_TOKEN"]), "never a value");

        drop(l1);
        drop(l2);
        let released: Vec<_> = audited("superbot-u-ugcp7@proj-1.iam.gserviceaccount.com").into_iter().filter(|e| e.action == "secret.lease_released").collect();
        assert_eq!((released.len(), released[0].details["revocable"].as_bool()), (1, Some(false)));
        assert_eq!(released[0].details["userId"], "ugcp7");
        assert!(released[0].details["expiresAt"].as_str().is_some());
        assert_eq!(redact::text(&v1["OWN_GCP_TOKEN"]), redact::MARK, "it works until it expires, so it stays redacted");
    }

    #[test]
    fn google_refusing_or_odd_refuses_the_run() {
        let (url, f) = stand_in();
        let sa = |name: &str| format!("{name}@proj-1.iam.gserviceaccount.com");
        for (name, run_for, err) in [
            ("denied", RUN, "403 Forbidden (PERMISSION_DENIED) for generateAccessToken for denied@proj-1.iam.gserviceaccount.com; botd's service account needs roles/iam.serviceAccountTokenCreator"),
            ("missing", RUN, "404 Not Found (NOT_FOUND) for generateAccessToken for missing@proj-1.iam.gserviceaccount.com; is there a service account"),
            ("hour", Duration::from_secs(7200), "(INVALID_ARGUMENT) for generateAccessToken for hour@proj-1.iam.gserviceaccount.com; a token of more than 3600 s needs the organization policy constraints/iam.allowServiceAccountCredentialLifetimeExtension"),
            ("short", RUN, "but a run may last 3600 s"),
            ("odd", RUN, "gave no access token"),
            ("long", Duration::from_secs(43_201), "longer than Google's longest access token"),
            ("abcdefghijklmnopqrstuvwxyz-{owner}", RUN, "at most 30 characters"),
        ] {
            let rc = run_credentials(&url, &sa(name));
            let e = rc.issue("ugcp8", "bgcp8", true, run_for).err().unwrap().to_string();
            assert!(e.contains(err) && !e.contains("quoting"), "{name}: {e}");
            let path = sa(&name.replace("{owner}", "ugcp8"));
            assert!(audited(&path).iter().any(|e| e.action == "secret.lease_issued" && e.outcome == Outcome::Failure), "{name}");
        }
        assert!(!f.impersonated.lock().unwrap().iter().any(|(_, sa, _)| sa.starts_with("long@") || sa.starts_with("abcdef")), "never asked for what Google can't make");

        // Google refuses botd's token: it signs in again and asks once more.
        let rc = run_credentials(&url, &sa("superbot-bots"));
        rc.issue("ugcp8", "bgcp8", true, RUN).unwrap();
        f.tokens.lock().unwrap().clear();
        let before = f.sign_ins.load(Ordering::SeqCst);
        rc.issue("ugcp8", "bgcp8", true, RUN).unwrap();
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), before + 1);
        let (auth, ..) = f.impersonated.lock().unwrap().last().unwrap().clone();
        assert_eq!(auth, format!("Bearer {}", f.tokens.lock().unwrap()[0]), "with the new token");

        f.down.store(true, Ordering::SeqCst);
        assert!(matches!(rc.issue("ugcp8", "bgcp8", true, RUN), Err(Error::Unavailable(_))), "Google down: refused, never a run without its token");
    }

    use super::super::leases::tests::{policy_file, BOUNDARY};

    #[test]
    fn a_boundary_downscopes_each_runs_token_at_googles_sts() {
        let (url, f) = stand_in();
        let file = policy_file("gcp-boundary", BOUNDARY);
        let rc = run_credentials(&url, &format!("superbot-bots@proj-1.iam.gserviceaccount.com boundary={file}; superbot-plain@proj-1.iam.gserviceaccount.com PLAIN_GCP_TOKEN=accessToken"));
        let (e, l) = rc.issue("ugcp9", "bgcp9", true, RUN).unwrap();
        let v = values(&e);
        let downs = f.downscoped.lock().unwrap().clone();
        let [(subject, options, token)] = &downs[..] else { panic!("{downs:?}") };
        assert_eq!((&v["GOOGLE_OAUTH_ACCESS_TOKEN"], &v["CLOUDSDK_AUTH_ACCESS_TOKEN"]), (token, token), "the run gets the downscoped token");
        assert!(f.run_tokens.lock().unwrap().contains(subject), "traded the token IAM Credentials made, checked by the stand-in");
        assert!(!v.values().any(|t| t == subject), "never the token it was traded for");
        assert!(f.run_tokens.lock().unwrap().contains(&v["PLAIN_GCP_TOKEN"]), "an entry with no boundary isn't downscoped");
        let sent: Value = serde_json::from_str(options).unwrap();
        assert_eq!(sent["accessBoundary"]["accessBoundaryRules"][0]["availabilityCondition"]["expression"], "resource.name.startsWith('projects/_/buckets/acme-bots/objects/bgcp9/')");
        assert_eq!(redact::text(&format!("leaked {token}")), format!("leaked {}", redact::MARK));

        let ev: Vec<_> = audited("superbot-bots@proj-1.iam.gserviceaccount.com").into_iter().filter(|e| e.bot_id.as_deref() == Some("bgcp9")).collect();
        let issued = ev.iter().find(|e| e.action == "secret.lease_issued").unwrap();
        assert_eq!(issued.details["boundarySha256"], crate::sigv4::sha256_hex(options.as_bytes()), "the boundary exactly as sent");
        assert!((3590..=3600).contains(&issued.details["ttl"].as_u64().unwrap()), "as long as the token it came from: {:?}", issued.details);
        assert!(!format!("{ev:?}").contains(token.as_str()) && !format!("{ev:?}").contains(subject.as_str()), "never a token");
        drop(l);
        let released = audited("superbot-bots@proj-1.iam.gserviceaccount.com").into_iter().filter(|e| e.action == "secret.lease_released" && e.bot_id.as_deref() == Some("bgcp9")).count();
        assert_eq!(released, 1);
        assert_eq!(redact::text(token), redact::MARK, "it works until it expires, so it stays redacted");

        // A session policy or tags can't narrow a Google token: refused, not ignored.
        let sm = SecretManager::new(Config::from_env(&settings(&[("GCP_SECRET_MANAGER_PROJECT", "proj-1")]), &EnvStore::fixed(&[])).unwrap()).unwrap();
        let tagged = Narrowed { tags: vec![("superbot-bot", "b1".into())], ..Narrowed::default() };
        let e = sm.issue_narrowed("superbot-bots@proj-1.iam.gserviceaccount.com", &["accessToken".into()], RUN, "b1", &tagged).err().unwrap().to_string();
        assert!(e.contains("can't be narrowed with a session policy or tags"), "{e}");
    }

    #[test]
    fn a_slow_exchange_isnt_added_to_the_tokens_life() {
        let (url, _f) = stand_in();
        let file = policy_file("gcp-sts-slow", &BOUNDARY.replace("acme-bots", "slow"));
        let rc = run_credentials(&url, &format!("superbot-bots@proj-1.iam.gserviceaccount.com boundary={file}"));
        let _l = rc.issue("ugcp11", "bsts-slow", true, RUN).unwrap().1;
        let ev = audited("superbot-bots@proj-1.iam.gserviceaccount.com");
        let issued = ev.iter().find(|e| e.action == "secret.lease_issued" && e.bot_id.as_deref() == Some("bsts-slow")).unwrap();
        let ttl = issued.details["ttl"].as_u64().unwrap();
        assert!((3590..=3598).contains(&ttl), "ends when the source token does, not its TTL after the exchange: {ttl}");
    }

    #[test]
    fn sts_refusing_or_odd_refuses_the_run() {
        let (url, f) = stand_in();
        for (bucket, err) in [
            ("refused", "GCP STS answered 400 Bad Request (invalid_request) for downscoping the token of superbot-bots@proj-1.iam.gserviceaccount.com; check the entry's boundary= file"),
            ("forbidden", "403 Forbidden (access_denied) for downscoping the token of superbot-bots@proj-1.iam.gserviceaccount.com; the Security Token Service API (sts.googleapis.com) must be on"),
            ("short", "gave a token that ends in 60 s, but a run may last 3600 s"),
            ("echo", "gave back the token it was sent"),
            ("odd", "gave no access token"),
        ] {
            let file = policy_file(&format!("gcp-sts-{bucket}"), &BOUNDARY.replace("acme-bots", bucket));
            let rc = run_credentials(&url, &format!("superbot-bots@proj-1.iam.gserviceaccount.com boundary={file}"));
            let e = rc.issue("ugcp10", &format!("bsts-{bucket}"), true, RUN).err().unwrap().to_string();
            assert!(e.contains(err) && !e.contains("quoting"), "{bucket}: {e}");
            let ev = audited("superbot-bots@proj-1.iam.gserviceaccount.com");
            assert!(ev.iter().any(|e| e.action == "secret.lease_issued" && e.outcome == Outcome::Failure && e.bot_id.as_deref() == Some(&format!("bsts-{bucket}"))), "{bucket}");
        }
        assert!(!redact::text("ya29.down-short").contains(redact::MARK), "a refused token is never held");

        // STS down: refused, never the wider token instead.
        let file = policy_file("gcp-sts-down", BOUNDARY);
        let rc = run_credentials(&url, &format!("superbot-bots@proj-1.iam.gserviceaccount.com boundary={file}"));
        let before = f.downscoped.lock().unwrap().len();
        f.down.store(true, Ordering::SeqCst);
        assert!(matches!(rc.issue("ugcp10", "bsts-down", true, RUN), Err(Error::Unavailable(_))));
        assert_eq!(f.downscoped.lock().unwrap().len(), before);
    }

    #[test]
    fn run_credentials_settings_are_checked() {
        let base = [("SECRETS_BACKEND", "gcp-secret-manager"), ("GCP_SECRET_MANAGER_PROJECT", "proj-1")];
        let with = |extra: &[(&str, &str)]| {
            let pairs = [&base[..], extra].concat();
            super::super::external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs))
        };
        let x = with(&[("GCP_RUN_CREDENTIALS", "superbot-bots@proj-1.iam.gserviceaccount.com")]).unwrap().unwrap();
        assert_eq!(x.run_credentials().unwrap().names(), ["CLOUDSDK_AUTH_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN"]);
        assert!(with(&[]).unwrap().unwrap().run_credentials().is_none(), "off unless set");
        let e = with(&[("GCP_RUN_CREDENTIALS", "arn:aws:iam::123456789012:role/r")]).err().unwrap();
        assert!(e.contains("GCP_RUN_CREDENTIALS") && e.contains("service account's email"));
        let e = with(&[("GCP_IAM_CREDENTIALS_ENDPOINT", "http://iamcredentials.example.com")]).err().unwrap();
        assert!(e.contains("GCP_IAM_CREDENTIALS_ENDPOINT") && e.contains("must use https"));
        let e = with(&[("GCP_STS_ENDPOINT", "http://sts.example.com")]).err().unwrap();
        assert!(e.contains("GCP_STS_ENDPOINT") && e.contains("must use https"));
        let var = settings(&[("GCP_RUN_CREDENTIALS", "superbot-bots@proj-1.iam.gserviceaccount.com")]);
        assert_eq!(super::super::external::unused_settings(&var, "aws"), ["GCP_RUN_CREDENTIALS"], "only SECRETS_BACKEND=gcp-secret-manager reads it");
        assert!(super::super::external::unused_settings(&var, "gcp-secret-manager").is_empty());
    }

    #[test]
    fn crc32c_is_castagnoli() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn settings_are_checked() {
        let ok = |pairs: &[(&str, &str)]| Config::from_env(&settings(pairs), &EnvStore::fixed(pairs));
        let c = ok(&[("GCP_SECRET_MANAGER_PROJECT", "proj-1")]).unwrap();
        assert_eq!((c.endpoint.as_str(), c.parent.as_str(), c.prefix.as_str()), ("https://secretmanager.googleapis.com", "projects/proj-1", "superbot"));
        assert!(matches!(&c.auth, Auth::Metadata { host } if host == METADATA_HOST));
        assert_eq!((c.iam_endpoint.as_str(), c.sts_endpoint.as_str()), ("https://iamcredentials.googleapis.com", "https://sts.googleapis.com"));
        let c = ok(&[("GCP_SECRET_MANAGER_PROJECT", "proj-1"), ("GCP_SECRET_MANAGER_LOCATION", "europe-west2")]).unwrap();
        assert_eq!((c.endpoint.as_str(), c.parent.as_str()), ("https://secretmanager.europe-west2.rep.googleapis.com", "projects/proj-1/locations/europe-west2"));
        let p = ("GCP_SECRET_MANAGER_PROJECT", "proj-1");
        for (pairs, err) in [
            (vec![], "needs GCP_SECRET_MANAGER_PROJECT"),
            (vec![("GCP_SECRET_MANAGER_PROJECT", "Proj 1")], "GCP_SECRET_MANAGER_PROJECT must be"),
            (vec![p, ("GCP_SECRET_MANAGER_LOCATION", "eu/west")], "GCP_SECRET_MANAGER_LOCATION"),
            (vec![p, ("GCP_SECRET_MANAGER_ENDPOINT", "http://secretmanager.googleapis.com")], "must use https"),
            (vec![p, ("GCP_SECRET_MANAGER_PREFIX", "a/b")], "GCP_SECRET_MANAGER_PREFIX"),
            (vec![p, ("GCP_SECRET_MANAGER_AUTH", "password")], "metadata or service-account-key"),
            (vec![p, ("GCP_SECRET_MANAGER_AUTH", "service-account-key")], "GCP_SERVICE_ACCOUNT_KEY_FILE"),
            (vec![p, ("GCP_SECRET_MANAGER_AUTH", "service-account-key"), ("GCP_SERVICE_ACCOUNT_KEY", "{not json")], "isn't JSON"),
            (vec![p, ("GCP_SECRET_MANAGER_AUTH", "service-account-key"), ("GCP_SERVICE_ACCOUNT_KEY", r#"{"type":"authorized_user"}"#)], "service account key"),
            (vec![p, ("GCP_SECRET_MANAGER_AUTH", "service-account-key"), ("GCP_SERVICE_ACCOUNT_KEY", r#"{"type":"service_account","client_email":"a@b","private_key":"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}"#)], "RSA PKCS#8"),
            (vec![p, ("GCE_METADATA_HOST", "evil.example/path")], "GCE_METADATA_HOST"),
        ] {
            let e = ok(&pairs).err().unwrap_or_default();
            assert!(e.contains(err), "expected an error containing {err:?}");
        }
        let key = key_file(&Fake::default(), "http://token.example/token");
        let e = ok(&[("GCP_SECRET_MANAGER_AUTH", "service-account-key"), ("GCP_SERVICE_ACCOUNT_KEY", &key)]).err().unwrap();
        assert!(e.contains("token_uri must use https"));
    }
}
