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
//! revoke one, so it is let go at its expiry.

use super::external::{Provider, Scope};
use super::http::{self, Bearer, Worker};
use super::leases::{Field, Issuer, Lease};
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
const IAM_CREDENTIALS: &str = "https://iamcredentials.googleapis.com";
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

impl Config {
    /// `GCP_*` settings; the key comes from `store` (the environment), so `_FILE` works.
    pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Config, String> {
        let (auth, key_project) = match var("GCP_SECRET_MANAGER_AUTH").trim() {
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
                let key = key.ok_or("GCP_SECRET_MANAGER_AUTH=service-account-key needs GCP_SERVICE_ACCOUNT_KEY_FILE (or GCP_SERVICE_ACCOUNT_KEY)")?;
                let (sa, project) = service_account(key.expose())?;
                (Auth::Key(Box::new(sa)), project)
            }
            other => return Err(format!("GCP_SECRET_MANAGER_AUTH must be metadata or service-account-key, not {other:?}")),
        };
        let project = match (var("GCP_SECRET_MANAGER_PROJECT").trim(), key_project) {
            ("", Some(p)) => p,
            ("", None) => return Err("SECRETS_BACKEND=gcp-secret-manager needs GCP_SECRET_MANAGER_PROJECT, the project id the secrets are in".into()),
            (p, _) => p.to_string(),
        };
        let project = name_setting("GCP_SECRET_MANAGER_PROJECT", &project, "my-project-123")?;
        let location = match var("GCP_SECRET_MANAGER_LOCATION").trim() {
            "" => None,
            l => Some(name_setting("GCP_SECRET_MANAGER_LOCATION", l, "europe-west2")?),
        };
        let endpoint = match (var("GCP_SECRET_MANAGER_ENDPOINT").trim(), &location) {
            ("", None) => "https://secretmanager.googleapis.com".to_string(),
            ("", Some(l)) => format!("https://secretmanager.{l}.rep.googleapis.com"),
            (e, _) => http::base_url("GCP_SECRET_MANAGER_ENDPOINT", e, "https://secretmanager.googleapis.com")?,
        };
        let parent = match &location {
            None => format!("projects/{project}"),
            Some(l) => format!("projects/{project}/locations/{l}"),
        };
        let iam_endpoint = match var("GCP_IAM_CREDENTIALS_ENDPOINT").trim() {
            "" => IAM_CREDENTIALS.to_string(),
            e => http::base_url("GCP_IAM_CREDENTIALS_ENDPOINT", e, IAM_CREDENTIALS)?,
        };
        Ok(Config { endpoint, parent, prefix: prefix_setting(&var("GCP_SECRET_MANAGER_PREFIX"))?, auth, iam_endpoint })
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
        match self.cfg.auth {
            Auth::Metadata { .. } => "metadata",
            Auth::Key(_) => "service-account-key",
        }
    }

    async fn token(&self, fresh: bool) -> Result<Zeroizing<String>, Error> {
        if !fresh && let Some(t) = self.token.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|t| t.fresh()) {
            return Ok(t.value.clone());
        }
        let result = self.sign_in().await;
        http::audit_login("gcp-secret-manager", self.method(), &result);
        let t = result?;
        let value = t.value.clone();
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = Some(t);
        Ok(value)
    }

    async fn sign_in(&self) -> Result<Bearer, Error> {
        let what = format!("{} sign-in", self.method());
        let req = match &self.cfg.auth {
            Auth::Metadata { host } => self.local.get(format!("http://{host}/computeMetadata/v1/instance/service-accounts/default/token")).header("Metadata-Flavor", "Google"),
            Auth::Key(sa) => {
                let assertion = jwt(sa).map_err(|e| unavailable(&what, e))?;
                self.http.post(&sa.token_uri).form(&[("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", assertion.as_str())])
            }
        };
        let res = req.send().await.map_err(|e| unavailable(&what, e))?;
        let status = res.status();
        let body = Zeroizing::new(res.bytes().await.map_err(|e| unavailable(&what, e))?.to_vec());
        if !status.is_success() {
            return Err(Error::Unavailable(format!("GCP Secret Manager: {what} answered {status}{}", http::error_code(&body))));
        }
        let v: Value = serde_json::from_slice(&body).map_err(|e| unavailable(&what, e))?;
        let token = v["access_token"].as_str().filter(|t| !t.is_empty()).ok_or_else(|| Error::Unavailable(format!("GCP Secret Manager: {what} gave no token")))?;
        Ok(Bearer::new(token, http::seconds(&v["expires_in"])))
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
    /// (at least Google's 5 minutes), asked for with botd's own token. When Google refuses
    /// that token, gets a new one and asks once more.
    async fn impersonate(&self, email: &str, fields: &[String], run_for: Duration, bot_id: &str) -> Result<Lease, Error> {
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
                return token_lease(&reply, email, fields, secs, bot_id, &what);
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
}

fn iam_unavailable(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Unavailable(format!("GCP IAM: {what}: {e}"))
}

/// A run's lease from `generateAccessToken`'s answer: the token under each field asked
/// for, and how long it lasts. A token that ends before the run could is refused. Google
/// gives a token no id, so the lease's is the account and `superbot-<bot id>-<random>`,
/// for SuperBot's own audit log.
fn token_lease(body: &[u8], email: &str, fields: &[String], run_for: u64, bot_id: &str, what: &str) -> Result<Lease, Error> {
    let bad = |why: &str| Error::Unavailable(format!("GCP IAM: {what} {why}"));
    let v: Value = serde_json::from_slice(body).map_err(|_| bad("answered with something that isn't JSON"))?;
    let token = v["accessToken"].as_str().filter(|t| !t.is_empty() && t.len() <= 8192 && t.bytes().all(|b| b.is_ascii_graphic())).ok_or_else(|| bad("gave no access token"))?;
    let expires = v["expireTime"].as_str().and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok()).ok_or_else(|| bad("gave a token with no expiry"))?;
    let ttl = u64::try_from(expires.timestamp() - chrono::Utc::now().timestamp()).unwrap_or(0);
    // A minute's slack for clocks; Google makes what was asked for or refuses.
    if ttl + 60 < run_for {
        return Err(bad(&format!("gave a token that ends in {ttl} s, but a run may last {run_for} s (RUN_TIMEOUT_MINUTES)")));
    }
    let fields = fields.iter().map(|f| if f == "accessToken" { Field::Value(Zeroizing::new(token.to_string())) } else { Field::Missing }).collect();
    Ok(Lease { id: format!("{email}/{}", super::aws::session_name(bot_id)), ttl, renewable: false, fields })
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
        let auth = match &c.auth {
            Auth::Metadata { host } if host == METADATA_HOST => "the metadata server's service account".to_string(),
            Auth::Metadata { host } => format!("the metadata server's service account at {host}"),
            Auth::Key(sa) => format!("service account key for {}", sa.email),
        };
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
        let (inner, email, fields, bot_id) = (Arc::clone(&self.inner), email.to_string(), fields.to_vec(), bot_id.to_string());
        self.worker.run(async move { inner.impersonate(&email, &fields, run_for, &bot_id).await })
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

    fn stand_in() -> (String, F) {
        let f = F::default();
        f.expires_in.store(3599, Ordering::SeqCst);
        let app = axum::Router::new()
            .route("/computeMetadata/v1/instance/service-accounts/default/token", axum::routing::get(metadata_token))
            .route("/token", axum::routing::post(oauth_token))
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
        assert!(e.contains("GCP_RUN_CREDENTIALS") && e.contains("service account's email"), "{e}");
        let e = with(&[("GCP_IAM_CREDENTIALS_ENDPOINT", "http://iamcredentials.example.com")]).err().unwrap();
        assert!(e.contains("GCP_IAM_CREDENTIALS_ENDPOINT") && e.contains("must use https"), "{e}");
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
        assert_eq!(c.iam_endpoint, "https://iamcredentials.googleapis.com");
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
