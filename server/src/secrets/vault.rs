//! HashiCorp Vault (and OpenBao) as an external secrets `Provider` (ADR 0125).
//!
//! Each secret is one KV v2 secret, `<VAULT_KV_MOUNT>/<VAULT_KV_PREFIX>/<bots|server>/<NAME>`,
//! whose field `VAULT_KV_FIELD` (`value`) holds the value. botd signs in with a token
//! (`VAULT_TOKEN`, or `VAULT_TOKEN_FILE`, read again whenever Vault refuses the one it
//! has, so Vault Agent can rotate it), AppRole (`VAULT_ROLE_ID`, `VAULT_SECRET_ID`,
//! each also `_FILE`), or a JWT the platform keeps in a file: Kubernetes service account
//! tokens (`VAULT_AUTH=kubernetes`) or any OIDC/JWT issuer (`VAULT_AUTH=jwt`, ADR 0159),
//! read again at each login. botd logs in again before the token's lease runs out and
//! once more when Vault refuses it, in `VAULT_AUTH_NAMESPACE` if the auth method is
//! mounted somewhere other than the secrets. Requests run on a runtime of their own
//! (`http::Worker`).

use super::external::{self, Provider, Scope};
use super::http::Worker;
use super::{Error, SecretStore};
use crate::audit::{Event, Outcome};
use base64::Engine;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Where Kubernetes mounts a pod's service account token.
pub const KUBERNETES_TOKEN_FILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// Vault auth methods that take a JWT and a role (`auth/<mount>/login` with `role`, `jwt`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwtMethod {
    /// Vault's `kubernetes` method: a service account token, checked by Vault with the TokenReview API.
    Kubernetes,
    /// Vault's `jwt` method: any issuer Vault trusts (Kubernetes OIDC, GitHub Actions, SPIFFE, ...).
    Jwt,
}

impl JwtMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            JwtMethod::Kubernetes => "kubernetes",
            JwtMethod::Jwt => "jwt",
        }
    }

    /// The setting naming the file the JWT is read from.
    fn file_setting(self) -> &'static str {
        match self {
            JwtMethod::Kubernetes => "VAULT_KUBERNETES_TOKEN_FILE",
            JwtMethod::Jwt => "VAULT_JWT_FILE",
        }
    }
}

pub enum Auth {
    /// The token itself, or the file that holds it (read again when Vault refuses it).
    Token { value: Option<Zeroizing<String>>, file: Option<PathBuf> },
    AppRole { mount: String, role_id: Zeroizing<String>, secret_id: Zeroizing<String> },
    /// A JWT read from `file` at each login, so the platform can rotate it. `role` is None
    /// only for `jwt`, whose mount then uses its `default_role`.
    Jwt { method: JwtMethod, mount: String, role: Option<String>, file: PathBuf },
}

/// A role name: letters, digits, `.`, `_`, `-` and `@`, up to 128.
fn role_setting(key: &str, raw: &str) -> Result<String, String> {
    let v = raw.trim();
    if v.is_empty() || v.len() > 128 || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b)) {
        return Err(format!("{key} must be a Vault role name like \"superbot\" (letters, digits, . _ - @), not {v:?}"));
    }
    Ok(v.to_string())
}

/// A namespace for logins only: `root` for none, else a Vault path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthNamespace {
    /// The same as the secrets (`VAULT_NAMESPACE`).
    Same,
    Root,
    Path(String),
}

pub struct Config {
    /// `scheme://host[:port]`, no trailing slash.
    pub addr: String,
    pub namespace: Option<String>,
    /// Where the auth method is mounted, when that isn't `namespace` (Vault Enterprise, HCP).
    pub auth_namespace: AuthNamespace,
    pub mount: String,
    pub prefix: String,
    pub field: String,
    pub auth: Auth,
    /// PEM of the CA that signed Vault's certificate, when it isn't a public one.
    pub ca: Option<String>,
}

/// A mount, prefix or namespace: `/`-separated parts of letters, digits, `.`, `_` and `-`.
fn path_setting(key: &str, raw: &str, default: &str) -> Result<String, String> {
    let raw = raw.trim().trim_matches('/');
    let v = if raw.is_empty() { default } else { raw };
    let ok = v.split('/').all(|p| !p.is_empty() && p != "." && p != ".." && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)));
    if v.is_empty() || !ok {
        return Err(format!("{key} must be a Vault path like {default:?} (letters, digits, . _ - and /), not {raw:?}"));
    }
    Ok(v.to_string())
}

impl Config {
    /// `VAULT_*` settings; secrets come from `store` (the environment), so `_FILE` works.
    pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Config, String> {
        let secret = |k: &str| store.get(k).map_err(|e| format!("{k}: {e}")).map(|v| v.map(|v| Zeroizing::new(v.expose().to_string())));
        let raw = var("VAULT_ADDR");
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("SECRETS_BACKEND=vault needs VAULT_ADDR, e.g. https://vault.example.com:8200".into());
        }
        let url = url::Url::parse(raw).map_err(|e| format!("VAULT_ADDR {raw:?}: {e}"))?;
        if !crate::tiers::encrypted_or_loopback(&url) {
            return Err("VAULT_ADDR must use https://: plain http:// would send Vault tokens and secrets unencrypted, so it is allowed only to this computer (localhost, 127.0.0.0/8, ::1)".into());
        }
        if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
            return Err(format!("VAULT_ADDR must be just the scheme, host and port, not {raw:?}"));
        }
        let addr = url.as_str().trim_end_matches('/').to_string();
        let namespace = match var("VAULT_NAMESPACE").trim() {
            "" => None,
            ns => Some(path_setting("VAULT_NAMESPACE", ns, "admin")?),
        };
        let auth_namespace = match var("VAULT_AUTH_NAMESPACE").trim() {
            "" => AuthNamespace::Same,
            "root" | "/" => AuthNamespace::Root,
            ns => AuthNamespace::Path(path_setting("VAULT_AUTH_NAMESPACE", ns, "admin")?),
        };
        let jwt = |method: JwtMethod, mount_key: &str, role_key: &str, file: String| -> Result<Auth, String> {
            let role = match var(role_key).trim() {
                "" if method == JwtMethod::Jwt => None,
                "" => return Err(format!("VAULT_AUTH={} needs {role_key}, the Vault role botd logs in as", method.as_str())),
                r => Some(role_setting(role_key, r)?),
            };
            let file = file.trim();
            if file.is_empty() {
                return Err(format!("VAULT_AUTH={} needs {}, the file the platform keeps the JWT in", method.as_str(), method.file_setting()));
            }
            Ok(Auth::Jwt { method, mount: path_setting(mount_key, &var(mount_key), method.as_str())?, role, file: PathBuf::from(file) })
        };
        let auth = match var("VAULT_AUTH").trim() {
            "" | "token" => {
                let file = var("VAULT_TOKEN_FILE");
                let value = secret("VAULT_TOKEN")?.ok_or("VAULT_AUTH=token needs VAULT_TOKEN or VAULT_TOKEN_FILE")?;
                let file = (!file.trim().is_empty()).then(|| PathBuf::from(file.trim()));
                Auth::Token { value: if file.is_some() { None } else { Some(value) }, file }
            }
            "approle" => Auth::AppRole {
                mount: path_setting("VAULT_APPROLE_MOUNT", &var("VAULT_APPROLE_MOUNT"), "approle")?,
                role_id: secret("VAULT_ROLE_ID")?.ok_or("VAULT_AUTH=approle needs VAULT_ROLE_ID (or VAULT_ROLE_ID_FILE)")?,
                secret_id: secret("VAULT_SECRET_ID")?.ok_or("VAULT_AUTH=approle needs VAULT_SECRET_ID (or VAULT_SECRET_ID_FILE)")?,
            },
            "kubernetes" => {
                let file = var("VAULT_KUBERNETES_TOKEN_FILE");
                let file = if file.trim().is_empty() { KUBERNETES_TOKEN_FILE.to_string() } else { file };
                jwt(JwtMethod::Kubernetes, "VAULT_KUBERNETES_MOUNT", "VAULT_KUBERNETES_ROLE", file)?
            }
            "jwt" => jwt(JwtMethod::Jwt, "VAULT_JWT_MOUNT", "VAULT_JWT_ROLE", var("VAULT_JWT_FILE"))?,
            other => return Err(format!("VAULT_AUTH must be token, approle, kubernetes or jwt, not {other:?}")),
        };
        if auth_namespace != AuthNamespace::Same && matches!(auth, Auth::Token { .. }) {
            return Err("VAULT_AUTH_NAMESPACE is where botd logs in, so it needs VAULT_AUTH=approle, kubernetes or jwt; a token needs no login".into());
        }
        let field = var("VAULT_KV_FIELD");
        let field = match field.trim() {
            "" => "value".to_string(),
            f if f.len() <= 128 && f.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) => f.to_string(),
            f => return Err(format!("VAULT_KV_FIELD must be a field name like \"value\", not {f:?}")),
        };
        let ca = match var("VAULT_CACERT").trim() {
            "" => None,
            path => Some(std::fs::read_to_string(path).map_err(|e| format!("VAULT_CACERT ({path}): {e}"))?),
        };
        Ok(Config {
            addr,
            namespace,
            auth_namespace,
            mount: path_setting("VAULT_KV_MOUNT", &var("VAULT_KV_MOUNT"), "secret")?,
            prefix: path_setting("VAULT_KV_PREFIX", &var("VAULT_KV_PREFIX"), "superbot")?,
            field,
            auth,
            ca,
        })
    }
}

struct Token {
    value: Zeroizing<String>,
    /// When to log in again (AppRole, Kubernetes, JWT), before the lease runs out.
    renew_at: Option<Instant>,
}

struct Inner {
    cfg: Config,
    http: reqwest::Client,
    token: Mutex<Option<Token>>,
}

pub struct Vault {
    inner: Arc<Inner>,
    worker: Worker,
}

fn unavailable(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Unavailable(format!("Vault: {what}: {e}"))
}

/// The JWT in `file`, read at each login because the platform rotates it. Checked to be
/// a compact JWT that hasn't expired, so a wrong path or a file nobody renews any more is
/// named in the error rather than sent. Errors never quote the file.
fn read_jwt(method: JwtMethod, file: &std::path::Path) -> Result<Zeroizing<String>, Error> {
    let setting = method.file_setting();
    let text = Zeroizing::new(std::fs::read_to_string(file).map_err(|e| unavailable(&format!("{setting} ({})", file.display()), e))?);
    let jwt = text.trim();
    if jwt.is_empty() {
        return Err(Error::Unavailable(format!("Vault: {setting} ({}) is empty", file.display())));
    }
    let not_jwt = || Error::Unavailable(format!("Vault: {setting} ({}) doesn't hold a JWT", file.display()));
    let parts: Vec<&str> = jwt.split('.').collect();
    let base64url = |p: &&str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if parts.len() != 3 || !parts.iter().all(base64url) {
        return Err(not_jwt());
    }
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).filter(Value::is_object).ok_or_else(not_jwt)?;
    // NumericDate may have a fraction (RFC 7519).
    if let Some(exp) = claims["exp"].as_f64() {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
        if exp <= now {
            return Err(Error::Unavailable(format!("Vault: the JWT in {setting} ({}) expired {} s ago; is the platform still renewing it?", file.display(), (now - exp) as u64)));
        }
    }
    Ok(Zeroizing::new(jwt.to_string()))
}

impl Vault {
    pub fn new(cfg: Config) -> Result<Vault, String> {
        let http = super::http::client("Vault", cfg.ca.as_deref().map(|pem| ("VAULT_CACERT", pem)), false)?;
        Ok(Vault { inner: Arc::new(Inner { cfg, http, token: Mutex::new(None) }), worker: Worker::new("Vault", "vault")? })
    }

    /// Runs `f` on Vault's runtime and waits for it (`http::Worker::run`).
    fn run<T, F, Fut>(&self, f: F) -> Result<T, Error>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Inner>) -> Fut,
        Fut: std::future::Future<Output = Result<T, Error>> + Send + 'static,
    {
        self.worker.run(f(Arc::clone(&self.inner)))
    }
}

impl Inner {
    fn url(&self, path: &str) -> String {
        format!("{}/v1/{path}", self.cfg.addr)
    }

    fn secret_path(&self, kind: &str, scope: Scope, name: &str) -> String {
        format!("{}/{kind}/{}/{}/{name}", self.cfg.mount, self.cfg.prefix, scope.as_str())
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.request_in(self.cfg.namespace.as_deref(), method, path)
    }

    fn request_in(&self, namespace: Option<&str>, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut r = self.http.request(method, self.url(path));
        if let Some(ns) = namespace {
            r = r.header("X-Vault-Namespace", ns);
        }
        r
    }

    /// The namespace logins are sent to.
    fn auth_namespace(&self) -> Option<&str> {
        match &self.cfg.auth_namespace {
            AuthNamespace::Same => self.cfg.namespace.as_deref(),
            AuthNamespace::Root => None,
            AuthNamespace::Path(ns) => Some(ns),
        }
    }

    /// The token to send; a new one if `fresh` (Vault refused the last) or it is due.
    async fn token(&self, fresh: bool) -> Result<Zeroizing<String>, Error> {
        if !fresh
            && let Some(t) = self.token.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|t| t.renew_at.is_none_or(|at| Instant::now() < at))
        {
            return Ok(t.value.clone());
        }
        let t = match &self.cfg.auth {
            Auth::Token { value: Some(v), .. } => Token { value: v.clone(), renew_at: None },
            Auth::Token { file: Some(path), .. } => {
                let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| unavailable("VAULT_TOKEN_FILE", e))?);
                let v = text.trim();
                if v.is_empty() {
                    return Err(Error::Unavailable("Vault: VAULT_TOKEN_FILE is empty".into()));
                }
                Token { value: Zeroizing::new(v.to_string()), renew_at: None }
            }
            Auth::Token { .. } => return Err(Error::Unavailable("Vault: no token".into())),
            Auth::AppRole { mount, role_id, secret_id } => {
                let body = Zeroizing::new(json!({ "role_id": role_id.as_str(), "secret_id": secret_id.as_str() }).to_string());
                self.login("approle", mount, None, async { Ok::<_, Error>(body) }).await?
            }
            Auth::Jwt { method, mount, role, file } => {
                let body = async {
                    let jwt = read_jwt(*method, file)?;
                    // A JWT is base64url and dots, so it needs no escaping; roles are checked at startup.
                    let role = role.as_deref().map(|r| format!(",\"role\":\"{r}\"")).unwrap_or_default();
                    Ok(Zeroizing::new(format!("{{\"jwt\":\"{}\"{role}}}", jwt.as_str())))
                };
                self.login(method.as_str(), mount, role.as_deref(), body).await?
            }
        };
        let value = t.value.clone();
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = Some(t);
        Ok(value)
    }

    /// Logs in at `auth/<mount>/login` with the JSON `body`, in the auth namespace, and
    /// audits it as `secret.vault_login` with the method and role, never a credential.
    async fn login(&self, method: &'static str, mount: &str, role: Option<&str>, body: impl std::future::Future<Output = Result<Zeroizing<String>, Error>>) -> Result<Token, Error> {
        let what = match method {
            "approle" => "AppRole login",
            "kubernetes" => "Kubernetes login",
            _ => "JWT login",
        };
        let namespace = self.auth_namespace();
        let result = async {
            let body = body.await?;
            let res = self
                .request_in(namespace, reqwest::Method::POST, &format!("auth/{mount}/login"))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.as_str().to_owned())
                .send()
                .await
                .map_err(|e| unavailable(what, e))?;
            let status = res.status();
            if !status.is_success() {
                return Err(Error::Unavailable(format!("Vault: {what} at auth/{mount} answered {status}")));
            }
            let v: Value = res.json().await.map_err(|e| unavailable(what, e))?;
            let value = v["auth"]["client_token"].as_str().filter(|t| !t.is_empty()).ok_or_else(|| Error::Unavailable(format!("Vault: {what} gave no token")))?;
            // Log in again two thirds of the way through the lease, so a token never lapses mid-run.
            let lease = v["auth"]["lease_duration"].as_u64().unwrap_or(0);
            let renew_at = (lease > 0).then(|| Instant::now() + Duration::from_secs(lease) * 2 / 3);
            Ok(Token { value: Zeroizing::new(value.to_string()), renew_at })
        }
        .await;
        let mut details = json!({ "method": method });
        if let Some(role) = role {
            details["role"] = json!(role);
        }
        if let Some(ns) = namespace {
            details["namespace"] = json!(ns);
        }
        let e = Event::new(external::actor(), "secret.vault_login").target("vault_auth", mount);
        external::audit(match &result {
            Ok(_) => e.details(details),
            Err(err) => {
                details["error"] = json!(err.kind());
                e.outcome(Outcome::Failure).details(details)
            }
        });
        result
    }

    /// GETs `path`; when Vault refuses the token, gets a new one and asks once more.
    async fn get(&self, path: &str) -> Result<(reqwest::StatusCode, Option<Value>), Error> {
        for fresh in [false, true] {
            let token = self.token(fresh).await?;
            let res = self.request(reqwest::Method::GET, path).header("X-Vault-Token", token.as_str()).send().await.map_err(|e| unavailable(path, e))?;
            let status = res.status();
            if status == reqwest::StatusCode::FORBIDDEN && !fresh {
                continue;
            }
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok((status, None));
            }
            if !status.is_success() {
                return Err(Error::Unavailable(format!("Vault answered {status} for {path}")));
            }
            let body = Zeroizing::new(res.bytes().await.map_err(|e| unavailable(path, e))?.to_vec());
            let v: Value = serde_json::from_slice(&body).map_err(|e| unavailable(path, e))?;
            return Ok((status, Some(v)));
        }
        unreachable!("the second pass returns")
    }

    async fn read(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let path = self.secret_path("data", scope, name);
        let (_, body) = self.get(&path).await?;
        let Some(body) = body else { return Ok(None) };
        let data = &body["data"]["data"];
        if data.is_null() && body["data"]["metadata"].is_object() {
            // A deleted version: no value until a new one is written.
            return Ok(None);
        }
        if !data.is_object() {
            // Anything else isn't KV v2's answer; fail closed rather than read it as "not there".
            return Err(Error::Unavailable(format!("Vault: {path} gave an answer that isn't a KV v2 secret")));
        }
        match data[self.cfg.field.as_str()].as_str() {
            Some(v) if !v.is_empty() => Ok(Some(Zeroizing::new(v.to_string()))),
            Some(_) => Ok(None),
            None => Err(Error::Unavailable(format!("Vault: {path} has no string field {:?}", self.cfg.field))),
        }
    }

    async fn list(&self, scope: Scope) -> Result<Vec<String>, Error> {
        let path = format!("{}/metadata/{}/{}/", self.cfg.mount, self.cfg.prefix, scope.as_str());
        let (_, body) = self.get(&format!("{path}?list=true")).await?;
        let Some(body) = body else { return Ok(Vec::new()) };
        let keys = body["data"]["keys"].as_array().ok_or_else(|| Error::Unavailable(format!("Vault: listing {path} gave no keys")))?;
        Ok(keys.iter().filter_map(Value::as_str).filter(|k| !k.ends_with('/')).map(String::from).collect())
    }
}

impl Provider for Vault {
    fn kind(&self) -> &'static str {
        "vault"
    }

    fn describe(&self) -> String {
        let c = &self.inner.cfg;
        let auth = match &c.auth {
            Auth::Token { file: Some(_), .. } => "token from VAULT_TOKEN_FILE".to_string(),
            Auth::Token { .. } => "token".to_string(),
            Auth::AppRole { mount, .. } => format!("AppRole at auth/{mount}"),
            Auth::Jwt { method, mount, role, file } => {
                let role = role.as_deref().map_or_else(|| "its default role".to_string(), |r| format!("role {r}"));
                let kind = if *method == JwtMethod::Kubernetes { "Kubernetes" } else { "JWT" };
                format!("{kind} login as {role} at auth/{mount} with the token in {}", file.display())
            }
        };
        let auth_ns = match &c.auth_namespace {
            AuthNamespace::Same => String::new(),
            AuthNamespace::Root => " in the root namespace".to_string(),
            AuthNamespace::Path(n) => format!(" in namespace {n}"),
        };
        let ns = c.namespace.as_deref().map(|n| format!(", namespace {n}")).unwrap_or_default();
        format!("HashiCorp Vault at {}{ns}, KV v2 {}/{}/{{bots,server}}/<NAME> field {:?}, {auth}{auth_ns}", c.addr, c.mount, c.prefix, c.field)
    }

    fn read(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let name = name.to_string();
        self.run(move |i| async move { i.read(scope, &name).await })
    }

    fn list(&self, scope: Scope) -> Result<Vec<String>, Error> {
        self.run(move |i| async move { i.list(scope).await })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::env::EnvStore;
    use super::super::external::{tests::audited, ExternalStore};
    use super::super::{redact, sealed, Secrets};
    use super::super::http::tests::settings;
    use super::*;
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::Json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use super::super::http::MAX_REQUESTS;

    /// A stand-in for Vault's KV v2, AppRole, Kubernetes and JWT APIs: no real Vault,
    /// cluster, account or network.
    #[derive(Default)]
    pub(crate) struct Fake {
        /// `<mount>/<path>` → fields.
        kv: Mutex<HashMap<String, Value>>,
        pub tokens: Mutex<Vec<String>>,
        /// JWTs a `kubernetes` or `jwt` mount accepts: (mount, role, JWT).
        pub jwts: Mutex<Vec<(String, Option<String>, String)>>,
        pub logins: AtomicUsize,
        reads: AtomicUsize,
        down: AtomicBool,
        namespaces: Mutex<Vec<String>>,
        /// The namespace each login was sent to ("" for none).
        pub login_namespaces: Mutex<Vec<String>>,
        lease: AtomicUsize,
        delay_ms: AtomicUsize,
    }

    pub(crate) type F = Arc<Fake>;

    /// A compact JWT for `sub` that expires `exp_in` seconds from now. Unsigned: the
    /// stand-in, like Vault's role, only compares it.
    pub(crate) fn jwt(sub: &str, exp_in: i64) -> String {
        let b64 = |v: Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        format!("{}.{}.{}", b64(json!({ "alg": "RS256", "kid": "k1" })), b64(json!({ "iss": "https://kubernetes.default.svc", "sub": sub, "exp": now + exp_in })), crate::random_hex(16))
    }

    fn check(f: &Fake, h: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
        if f.down.load(Ordering::SeqCst) {
            return Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "errors": ["Vault is sealed"] }))));
        }
        f.namespaces.lock().unwrap().push(h.get("x-vault-namespace").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string());
        let token = h.get("x-vault-token").and_then(|v| v.to_str().ok()).unwrap_or_default();
        if !f.tokens.lock().unwrap().iter().any(|t| t == token) {
            return Err((StatusCode::FORBIDDEN, Json(json!({ "errors": ["permission denied"] }))));
        }
        Ok(())
    }

    async fn data(State(f): State<F>, Path(rest): Path<String>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if let Err(e) = check(&f, &h) {
            return e;
        }
        f.reads.fetch_add(1, Ordering::SeqCst);
        let delay = f.delay_ms.load(Ordering::SeqCst) as u64;
        tokio::time::sleep(Duration::from_millis(delay)).await;
        if rest.ends_with("/MALFORMED_TOKEN") {
            return (StatusCode::OK, Json(json!({})));
        }
        if rest.ends_with("/DELETED_TOKEN") {
            return (StatusCode::OK, Json(json!({ "data": { "data": null, "metadata": { "deletion_time": "2026-11-22T00:00:00Z", "version": 2 } } })));
        }
        let found = f.kv.lock().unwrap().get(&rest).cloned();
        match found {
            Some(fields) => (StatusCode::OK, Json(json!({ "data": { "data": fields, "metadata": { "version": 1 } } }))),
            None => (StatusCode::NOT_FOUND, Json(json!({ "errors": [] }))),
        }
    }

    async fn metadata(State(f): State<F>, Path(rest): Path<String>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if let Err(e) = check(&f, &h) {
            return e;
        }
        assert_eq!(q.get("list").map(String::as_str), Some("true"));
        let folder = rest.trim_end_matches('/').to_string() + "/";
        let mut keys: Vec<String> = Vec::new();
        for k in f.kv.lock().unwrap().keys() {
            if let Some(child) = k.strip_prefix(&folder) {
                let key = match child.split_once('/') {
                    Some((dir, _)) => format!("{dir}/"),
                    None => child.to_string(),
                };
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        if keys.is_empty() {
            return (StatusCode::NOT_FOUND, Json(json!({ "errors": [] })));
        }
        (StatusCode::OK, Json(json!({ "data": { "keys": keys } })))
    }

    /// `auth/approle/login` takes `role-1` and `secret-id-1`; any other mount takes the JWTs in `jwts`.
    async fn login(State(f): State<F>, Path(mount): Path<String>, h: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
        f.login_namespaces.lock().unwrap().push(h.get("x-vault-namespace").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string());
        let method = if mount == "approle" {
            if body["role_id"] != "role-1" || body["secret_id"] != "secret-id-1" {
                return (StatusCode::BAD_REQUEST, Json(json!({ "errors": ["invalid role or secret ID"] })));
            }
            "approle"
        } else {
            let role = body.get("role").and_then(Value::as_str);
            let ok = f.jwts.lock().unwrap().iter().any(|(m, r, j)| *m == mount && r.as_deref() == role && body["jwt"] == j.as_str());
            if !ok {
                return (StatusCode::FORBIDDEN, Json(json!({ "errors": ["permission denied"] })));
            }
            "jwt"
        };
        let n = f.logins.fetch_add(1, Ordering::SeqCst);
        let token = format!("hvs.{method}-{n}");
        f.tokens.lock().unwrap().push(token.clone());
        (StatusCode::OK, Json(json!({ "auth": { "client_token": token, "lease_duration": f.lease.load(Ordering::SeqCst), "renewable": true } })))
    }

    /// Starts the stand-in on its own thread and runtime; returns its address.
    pub(crate) fn stand_in() -> (String, F) {
        let f = F::default();
        f.lease.store(3600, Ordering::SeqCst);
        let app = axum::Router::new()
            .route("/v1/secret/data/{*rest}", axum::routing::get(data))
            .route("/v1/secret/metadata/{*rest}", axum::routing::get(metadata))
            .route("/v1/auth/{mount}/login", axum::routing::post(login))
            .with_state(Arc::clone(&f));
        (super::super::http::tests::serve(app), f)
    }

    pub(crate) fn put(f: &Fake, path: &str, value: &str) {
        f.kv.lock().unwrap().insert(format!("superbot/{path}"), json!({ "value": value }));
    }

    /// A temporary file holding `text`, for token and JWT files.
    pub(crate) fn token_file(label: &str, text: &str) -> PathBuf {
        let file = crate::db::temp_path(label).join("token");
        std::fs::write(&file, text).unwrap();
        file
    }

    pub(crate) fn vault(url: &str, extra: &[(&str, &str)], ttl: Duration) -> Arc<ExternalStore> {
        let mut pairs = vec![("SECRETS_BACKEND", "vault"), ("VAULT_ADDR", url)];
        pairs.extend_from_slice(extra);
        let var = settings(&pairs);
        let env = EnvStore::fixed(extra);
        let cfg = Config::from_env(&var, &env).unwrap();
        Arc::new(ExternalStore::new(Box::new(Vault::new(cfg).unwrap()), ttl))
    }

    #[test]
    fn reads_bot_and_server_secrets_with_a_token() {
        let (url, f) = stand_in();
        f.tokens.lock().unwrap().push("hvs.static-1".into());
        let bot_value = format!("sk-vault-{}", crate::random_hex(10));
        put(&f, "bots/OPENAI_API_KEY", &bot_value);
        put(&f, "bots/LINODE_TOKEN", "never-from-the-bots-folder");
        put(&f, "server/LINODE_TOKEN", "linode-from-vault-1");
        put(&f, "server/nested/DEEPER", "skipped");
        let s = vault(&url, &[("VAULT_TOKEN", "hvs.static-1"), ("VAULT_NAMESPACE", "admin/team-a")], Duration::from_secs(60));
        assert_eq!(s.check().unwrap(), 2, "OPENAI_API_KEY and LINODE_TOKEN, each in its own folder");
        assert_eq!(s.get("OPENAI_API_KEY").unwrap().unwrap().expose(), bot_value);
        assert_eq!(s.get("LINODE_TOKEN").unwrap().unwrap().expose(), "linode-from-vault-1");
        assert!(s.get("NOT_THERE_TOKEN").unwrap().is_none());
        let reads = f.reads.load(Ordering::SeqCst);
        s.get("OPENAI_API_KEY").unwrap();
        assert_eq!(f.reads.load(Ordering::SeqCst), reads, "cached");
        assert!(f.namespaces.lock().unwrap().iter().all(|n| n == "admin/team-a"));
        assert_eq!(redact::text(&bot_value), redact::MARK);

        // Through `Secrets`: env, then Vault, then the sealed store.
        let path = crate::db::temp_path("vault-facade").join("app.sqlite");
        let sealed = sealed::SealedStore::new(sealed::connect(&path).unwrap(), sealed::cipher());
        let secrets = Secrets::new(vec![Box::new(EnvStore::fixed(&[])), Box::new(external::Shared(Arc::clone(&s))), Box::new(sealed)]);
        secrets.put("OPENAI_API_KEY", "sealed-but-shadowed").unwrap();
        let env: Vec<(String, String)> = secrets.try_harness_env().unwrap().into_iter().map(|(k, v)| (k, v.expose().to_string())).collect();
        assert_eq!(env, [("OPENAI_API_KEY".to_string(), bot_value.clone())], "Vault's value wins, and botd's own never reach Bots");
        let listed: Vec<_> = secrets.list().unwrap().into_iter().map(|l| (l.name, l.store, l.shadowed_by, l.for_bots)).collect();
        assert!(listed.contains(&("OPENAI_API_KEY".into(), "vault", None, true)) && listed.contains(&("OPENAI_API_KEY".into(), "sealed", Some("vault"), true)), "{listed:?}");
        assert!(listed.contains(&("LINODE_TOKEN".into(), "vault", None, false)), "{listed:?}");
        assert_eq!(secrets.source("LINODE_TOKEN").unwrap(), Some(("vault", false)));
        redact::forget(&bot_value);
        redact::forget("linode-from-vault-1");
        redact::forget("sealed-but-shadowed");
    }

    #[test]
    fn a_token_file_is_read_again_when_vault_refuses_the_token() {
        let (url, f) = stand_in();
        let file = crate::db::temp_path("vault-token").join("token");
        std::fs::write(&file, "hvs.first\n").unwrap();
        f.tokens.lock().unwrap().push("hvs.first".into());
        put(&f, "bots/FILE_TOKEN", "file-token-value-1");
        let s = vault(&url, &[("VAULT_TOKEN_FILE", file.to_str().unwrap())], Duration::ZERO);
        assert!(s.get("FILE_TOKEN").unwrap().is_some());
        // Vault Agent rotates the token and the old one is revoked.
        std::fs::write(&file, "hvs.second\n").unwrap();
        *f.tokens.lock().unwrap() = vec!["hvs.second".into()];
        assert_eq!(s.get("FILE_TOKEN").unwrap().unwrap().expose(), "file-token-value-1");
        f.tokens.lock().unwrap().clear();
        assert!(matches!(s.get("FILE_TOKEN"), Err(Error::Unavailable(_))), "a refused token fails closed");
        redact::forget("file-token-value-1");
    }

    #[test]
    fn approle_logs_in_and_again_when_the_token_lapses() {
        let (url, f) = stand_in();
        put(&f, "server/SMTP_PASSWORD", "smtp-from-vault-1");
        let creds = [("VAULT_AUTH", "approle"), ("VAULT_ROLE_ID", "role-1"), ("VAULT_SECRET_ID", "secret-id-1")];
        let s = vault(&url, &creds, Duration::ZERO);
        assert_eq!(s.get("SMTP_PASSWORD").unwrap().unwrap().expose(), "smtp-from-vault-1");
        s.get("SMTP_PASSWORD").unwrap();
        assert_eq!(f.logins.load(Ordering::SeqCst), 1, "the token is kept while its lease runs");
        f.tokens.lock().unwrap().clear();
        assert!(s.get("SMTP_PASSWORD").unwrap().is_some(), "refused: logs in once more and retries");
        assert_eq!(f.logins.load(Ordering::SeqCst), 2);
        let logins = audited("approle");
        assert!(logins.iter().all(|e| e.action == "secret.vault_login") && logins.iter().filter(|e| e.outcome == Outcome::Success).count() >= 2, "{logins:?}");
        assert!(!format!("{logins:?}").contains("secret-id-1"));

        // A lease of 3 s is renewed after 2.
        f.lease.store(3, Ordering::SeqCst);
        let s = vault(&url, &creds, Duration::ZERO);
        s.get("SMTP_PASSWORD").unwrap();
        let before = f.logins.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(2100));
        s.get("SMTP_PASSWORD").unwrap();
        assert_eq!(f.logins.load(Ordering::SeqCst), before + 1);

        let bad = vault(&url, &[("VAULT_AUTH", "approle"), ("VAULT_ROLE_ID", "role-1"), ("VAULT_SECRET_ID", "wrong")], Duration::ZERO);
        assert!(matches!(bad.check(), Err(Error::Unavailable(_))));
        assert!(audited("approle").iter().any(|e| e.outcome == Outcome::Failure));
        redact::forget("smtp-from-vault-1");
    }

    #[test]
    fn kubernetes_logs_in_with_the_service_account_token_and_rereads_it_when_it_rotates() {
        let (url, f) = stand_in();
        put(&f, "bots/K8S_API_KEY", "k8s-vault-value-1");
        let first = jwt("system:serviceaccount:superbot:botd", 3600);
        f.jwts.lock().unwrap().push(("k8s-rotate".into(), Some("superbot".into()), first.clone()));
        let file = token_file("vault-k8s", &format!("{first}\n"));
        let s = vault(&url, &[("VAULT_AUTH", "kubernetes"), ("VAULT_KUBERNETES_ROLE", "superbot"), ("VAULT_KUBERNETES_MOUNT", "k8s-rotate"), ("VAULT_KUBERNETES_TOKEN_FILE", file.to_str().unwrap())], Duration::ZERO);
        assert!(s.describe().contains("Kubernetes login as role superbot at auth/k8s-rotate with the token in"), "{}", s.describe());
        assert_eq!(s.get("K8S_API_KEY").unwrap().unwrap().expose(), "k8s-vault-value-1");
        s.get("K8S_API_KEY").unwrap();
        assert_eq!(f.logins.load(Ordering::SeqCst), 1, "the Vault token is kept while its lease runs");

        // The kubelet rotates the projected token, and Vault's token is revoked: botd reads the file again.
        let second = jwt("system:serviceaccount:superbot:botd", 3600);
        *f.jwts.lock().unwrap() = vec![("k8s-rotate".into(), Some("superbot".into()), second.clone())];
        std::fs::write(&file, &second).unwrap();
        f.tokens.lock().unwrap().clear();
        assert_eq!(s.get("K8S_API_KEY").unwrap().unwrap().expose(), "k8s-vault-value-1", "refused: logs in with the new token and retries");
        assert_eq!(f.logins.load(Ordering::SeqCst), 2);

        // A token Vault no longer accepts fails closed.
        f.jwts.lock().unwrap().clear();
        f.tokens.lock().unwrap().clear();
        let e = s.get("K8S_API_KEY").err().unwrap().to_string();
        assert!(e.contains("Kubernetes login at auth/k8s-rotate answered 403"), "{e}");
        let ev = audited("k8s-rotate");
        assert!(ev.iter().all(|e| e.action == "secret.vault_login" && e.details["method"] == "kubernetes" && e.details["role"] == "superbot"), "{ev:?}");
        assert_eq!((ev.iter().filter(|e| e.outcome == Outcome::Success).count(), ev.iter().filter(|e| e.outcome == Outcome::Failure).count()), (2, 1), "{ev:?}");
        let logged = format!("{ev:?}{e}");
        assert!(!logged.contains(&first) && !logged.contains(&second) && !logged.contains("hvs."), "no JWT or Vault token in the audit log or errors");
        redact::forget("k8s-vault-value-1");
    }

    #[test]
    fn jwt_logs_in_with_the_default_role_in_the_auth_namespace() {
        let (url, f) = stand_in();
        put(&f, "server/SMTP_PASSWORD", "jwt-smtp-value-1");
        let token = jwt("repo:acme/infra:environment:prod", 600);
        f.jwts.lock().unwrap().push(("oidc-ns".into(), None, token.clone()));
        let file = token_file("vault-jwt", &token);
        let pairs = [("VAULT_AUTH", "jwt"), ("VAULT_JWT_MOUNT", "oidc-ns"), ("VAULT_JWT_FILE", file.to_str().unwrap()), ("VAULT_NAMESPACE", "admin/team-a"), ("VAULT_AUTH_NAMESPACE", "admin")];
        let s = vault(&url, &pairs, Duration::ZERO);
        assert!(s.describe().contains("JWT login as its default role at auth/oidc-ns") && s.describe().contains("in namespace admin"), "{}", s.describe());
        assert_eq!(s.get("SMTP_PASSWORD").unwrap().unwrap().expose(), "jwt-smtp-value-1");
        assert_eq!(*f.login_namespaces.lock().unwrap(), ["admin"], "logged in where the auth method is mounted");
        assert!(f.namespaces.lock().unwrap().iter().all(|n| n == "admin/team-a"), "and read where the secrets are");
        let ev = audited("oidc-ns");
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].details, json!({ "method": "jwt", "namespace": "admin" }));

        // `root`: the login carries no namespace; AppRole follows the same setting.
        f.login_namespaces.lock().unwrap().clear();
        let root = vault(&url, &[pairs[0], pairs[1], pairs[2], pairs[3], ("VAULT_AUTH_NAMESPACE", "root")], Duration::ZERO);
        assert!(root.get("SMTP_PASSWORD").unwrap().is_some());
        let approle = vault(&url, &[("VAULT_AUTH", "approle"), ("VAULT_ROLE_ID", "role-1"), ("VAULT_SECRET_ID", "secret-id-1"), ("VAULT_NAMESPACE", "admin/team-a"), ("VAULT_AUTH_NAMESPACE", "admin/auth")], Duration::ZERO);
        assert!(approle.get("SMTP_PASSWORD").unwrap().is_some());
        assert_eq!(*f.login_namespaces.lock().unwrap(), ["", "admin/auth"]);
        redact::forget("jwt-smtp-value-1");
    }

    #[test]
    fn jwt_files_that_cant_be_used_fail_closed_before_anything_is_sent() {
        let (url, f) = stand_in();
        let expired = jwt("system:serviceaccount:superbot:botd", -120);
        let pem = "-----BEGIN CERTIFICATE-----\nnot-a-jwt-but-private-looking-0123\n-----END CERTIFICATE-----\n";
        let missing = crate::db::temp_path("vault-jwt-missing").join("token");
        let b64 = |v: Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
        let fractional = format!("{}.{}.c2ln", b64(json!({ "alg": "RS256" })), b64(json!({ "sub": "botd", "exp": 1_700_000_000.5 })));
        for (file, err) in [
            (missing, "VAULT_JWT_FILE ("),
            (token_file("vault-jwt-empty", "\n"), "is empty"),
            (token_file("vault-jwt-pem", pem), "doesn't hold a JWT"),
            (token_file("vault-jwt-claims", "a.bm90LWpzb24.c"), "doesn't hold a JWT"),
            (token_file("vault-jwt-expired", &expired), "expired"),
            (token_file("vault-jwt-fractional", &fractional), "expired"),
        ] {
            let s = vault(&url, &[("VAULT_AUTH", "jwt"), ("VAULT_JWT_ROLE", "botd"), ("VAULT_JWT_FILE", file.to_str().unwrap())], Duration::ZERO);
            let e = s.check().err().map(|e| e.to_string()).unwrap_or_default();
            assert!(e.contains(err), "{file:?}: {e}");
            assert!(!e.contains("private-looking") && !e.contains(&expired), "the file is never quoted: {e}");
        }
        assert_eq!(f.logins.load(Ordering::SeqCst), 0, "nothing was sent to Vault");
        assert!(f.login_namespaces.lock().unwrap().is_empty());
        assert!(audited("jwt").iter().any(|e| e.outcome == Outcome::Failure && e.details["error"] == "unavailable" && e.details["role"] == "botd"));
    }

    #[test]
    fn vault_down_fails_closed_and_runs_get_no_secrets() {
        let (url, f) = stand_in();
        f.tokens.lock().unwrap().push("hvs.down".into());
        put(&f, "bots/DOWN_API_KEY", "down-vault-value-1");
        let s = vault(&url, &[("VAULT_TOKEN", "hvs.down")], Duration::from_millis(200));
        let path = crate::db::temp_path("vault-down").join("app.sqlite");
        let sealed = sealed::SealedStore::new(sealed::connect(&path).unwrap(), sealed::cipher());
        let users = sealed::UserSecrets::new(sealed::connect(&path).unwrap(), sealed::cipher());
        let secrets = Secrets::new(vec![Box::new(EnvStore::fixed(&[])), Box::new(external::Shared(Arc::clone(&s))), Box::new(sealed)]).with_users(users);
        secrets.put("DOWN_API_KEY", "the-sealed-fallback-1").unwrap();
        secrets.user_put("ua", "OWN_TOKEN", "own-token-value-1").unwrap();
        assert_eq!(secrets.get("DOWN_API_KEY").unwrap().unwrap().expose(), "down-vault-value-1");
        f.down.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(250));
        assert!(matches!(secrets.get("DOWN_API_KEY"), Err(Error::Unavailable(_))), "never the sealed value under it");
        assert!(matches!(secrets.try_harness_env_for("ua"), Err(Error::Unavailable(_))));
        assert!(secrets.harness_env_for("ua").is_empty() && secrets.harness_env().is_empty() && secrets.inherited_harness_env().is_empty(), "nothing rather than some");
        assert!(matches!(secrets.list(), Err(Error::Unavailable(_))));
        let ev = audited("DOWN_API_KEY");
        assert!(ev.iter().any(|e| e.outcome == Outcome::Failure && e.details["error"] == "unavailable"), "{ev:?}");
        f.down.store(false, Ordering::SeqCst);
        assert!(secrets.try_harness_env_for("ua").unwrap().iter().any(|(k, v)| k == "DOWN_API_KEY" && v.expose() == "down-vault-value-1"));
        for v in ["down-vault-value-1", "the-sealed-fallback-1"] {
            redact::forget(v);
        }
        redact::forget_for("ua", "own-token-value-1");
    }

    #[test]
    fn answers_that_arent_kv_v2_fail_closed() {
        let (url, f) = stand_in();
        f.tokens.lock().unwrap().push("hvs.shape".into());
        let s = vault(&url, &[("VAULT_TOKEN", "hvs.shape")], Duration::from_secs(60));
        let path = crate::db::temp_path("vault-shape").join("app.sqlite");
        let sealed = sealed::SealedStore::new(sealed::connect(&path).unwrap(), sealed::cipher());
        let secrets = Secrets::new(vec![Box::new(EnvStore::fixed(&[])), Box::new(external::Shared(Arc::clone(&s))), Box::new(sealed)]);
        secrets.put("MALFORMED_TOKEN", "sealed-shape-value-1").unwrap();
        assert!(matches!(secrets.get("MALFORMED_TOKEN"), Err(Error::Unavailable(_))), "not read as missing, so the sealed copy stays shadowed");
        assert!(s.get("DELETED_TOKEN").unwrap().is_none(), "a deleted version is no value");
        redact::forget("sealed-shape-value-1");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_slow_vault_doesnt_stall_botds_other_tasks() {
        let (url, f) = stand_in();
        f.tokens.lock().unwrap().push("hvs.slow".into());
        put(&f, "bots/SLOW_TOKEN", "slow-value-1");
        f.delay_ms.store(600, Ordering::SeqCst);
        let s = vault(&url, &[("VAULT_TOKEN", "hvs.slow")], Duration::ZERO);
        let ticks = Arc::new(AtomicUsize::new(0));
        let t = Arc::clone(&ticks);
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                t.fetch_add(1, Ordering::SeqCst);
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let before = ticks.load(Ordering::SeqCst);
        // Called straight from a task on the only worker, as a Bot run does.
        assert_eq!(s.get("SLOW_TOKEN").unwrap().unwrap().expose(), "slow-value-1");
        assert!(ticks.load(Ordering::SeqCst) >= before + 10, "other tasks kept running while Vault was slow");
        ticker.abort();
        redact::forget("slow-value-1");
    }

    #[test]
    fn reads_run_side_by_side() {
        let (url, f) = stand_in();
        f.tokens.lock().unwrap().push("hvs.many".into());
        for i in 0..MAX_REQUESTS {
            put(&f, &format!("bots/MANY_{i}_TOKEN"), &format!("many-value-{i}"));
        }
        f.delay_ms.store(800, Ordering::SeqCst);
        let s = vault(&url, &[("VAULT_TOKEN", "hvs.many")], Duration::ZERO);
        let start = Instant::now();
        std::thread::scope(|sc| {
            for i in 0..MAX_REQUESTS {
                let s = &s;
                sc.spawn(move || assert!(s.get(&format!("MANY_{i}_TOKEN")).unwrap().is_some()));
            }
        });
        assert!(start.elapsed() < Duration::from_millis(800 * 3), "{MAX_REQUESTS} reads of 0.8 s took {:?}", start.elapsed());
        for i in 0..MAX_REQUESTS {
            redact::forget(&format!("many-value-{i}"));
        }
    }

    #[test]
    fn settings_are_checked() {
        let env = EnvStore::fixed(&[("VAULT_TOKEN", "hvs.x")]);
        let ok = |pairs: &[(&str, &str)]| Config::from_env(&settings(pairs), &env);
        let c = ok(&[("VAULT_ADDR", "https://vault.example.com:8200/")]).unwrap();
        assert_eq!((c.addr.as_str(), c.mount.as_str(), c.prefix.as_str(), c.field.as_str()), ("https://vault.example.com:8200", "secret", "superbot", "value"));
        let c = ok(&[("VAULT_ADDR", "http://127.0.0.1:8200"), ("VAULT_KV_MOUNT", "/kv/"), ("VAULT_KV_PREFIX", "teams/acme/superbot"), ("VAULT_KV_FIELD", "secret")]).unwrap();
        assert_eq!((c.mount.as_str(), c.prefix.as_str(), c.field.as_str()), ("kv", "teams/acme/superbot", "secret"));
        for (pairs, err) in [
            (vec![], "needs VAULT_ADDR"),
            (vec![("VAULT_ADDR", "http://vault.example.com:8200")], "must use https"),
            (vec![("VAULT_ADDR", "https://u:p@vault.example.com")], "just the scheme"),
            (vec![("VAULT_ADDR", "https://vault.example.com/ui")], "just the scheme"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_KV_PREFIX", "a/../b")], "VAULT_KV_PREFIX"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_KV_MOUNT", "a b")], "VAULT_KV_MOUNT"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "ldap")], "token, approle, kubernetes or jwt"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "approle")], "VAULT_ROLE_ID"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "kubernetes")], "needs VAULT_KUBERNETES_ROLE"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "kubernetes"), ("VAULT_KUBERNETES_ROLE", "bad role")], "VAULT_KUBERNETES_ROLE must be a Vault role name"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "kubernetes"), ("VAULT_KUBERNETES_ROLE", "r"), ("VAULT_KUBERNETES_MOUNT", "../k8s")], "VAULT_KUBERNETES_MOUNT"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "jwt")], "needs VAULT_JWT_FILE"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "jwt"), ("VAULT_JWT_FILE", "/f"), ("VAULT_JWT_ROLE", "r\"}")], "VAULT_JWT_ROLE must be"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "jwt"), ("VAULT_JWT_FILE", "/f"), ("VAULT_AUTH_NAMESPACE", "a/../b")], "VAULT_AUTH_NAMESPACE"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH_NAMESPACE", "admin")], "needs VAULT_AUTH=approle, kubernetes or jwt"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_CACERT", "/nonexistent/ca.pem")], "VAULT_CACERT"),
        ] {
            let e = ok(&pairs).err().unwrap_or_default();
            assert!(e.contains(err), "{pairs:?}: {e}");
        }
        let none = EnvStore::fixed(&[]);
        assert!(Config::from_env(&settings(&[("VAULT_ADDR", "https://v")]), &none).err().unwrap().contains("VAULT_TOKEN"));
        // Kubernetes and JWT need no secret in the environment: the JWT is in a file.
        let c = Config::from_env(&settings(&[("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "kubernetes"), ("VAULT_KUBERNETES_ROLE", "superbot@prod")]), &none).unwrap();
        assert!(matches!(&c.auth, Auth::Jwt { method: JwtMethod::Kubernetes, mount, role: Some(r), file } if mount == "kubernetes" && r == "superbot@prod" && file.to_str() == Some(KUBERNETES_TOKEN_FILE)));
        assert_eq!(c.auth_namespace, AuthNamespace::Same);
        let c = Config::from_env(&settings(&[("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "jwt"), ("VAULT_JWT_FILE", " /run/oidc/token "), ("VAULT_AUTH_NAMESPACE", "/")]), &none).unwrap();
        assert!(matches!(&c.auth, Auth::Jwt { method: JwtMethod::Jwt, mount, role: None, file } if mount == "jwt" && file.to_str() == Some("/run/oidc/token")));
        assert_eq!(c.auth_namespace, AuthNamespace::Root);
    }

    #[test]
    fn vault_credentials_never_reach_bots() {
        // `VAULT_JWT_FILE` would otherwise be offered to Bots as `VAULT_JWT`, read from the file.
        let file = token_file("vault-jwt-bots", &jwt("system:serviceaccount:superbot:botd", 3600));
        for var in ["VAULT_JWT_FILE", "VAULT_KUBERNETES_TOKEN_FILE"] {
            let s = Secrets::new(vec![Box::new(EnvStore::fixed(&[(var, file.to_str().unwrap())]))]);
            assert!(s.try_harness_env().unwrap().is_empty() && s.try_inherited_harness_env().unwrap().is_empty() && s.list().unwrap().is_empty(), "{var}");
        }
        for name in ["VAULT_TOKEN", "VAULT_SECRET_ID", "VAULT_ROLE_ID", "VAULT_JWT", "VAULT_KUBERNETES_TOKEN"] {
            assert!(super::super::check_name(name).is_err(), "{name} is reserved");
            let s = Secrets::new(vec![Box::new(EnvStore::fixed(&[(name, "hvs.0123456789abcdef")]))]);
            assert!(s.harness_env().is_empty() && s.inherited_harness_env().is_empty() && s.list().unwrap().is_empty(), "{name}");
            let host = crate::adapters::local_host();
            for k in [name.to_string(), format!("{name}_FILE")] {
                assert!(host.remove.contains(&k), "{k} removed from local jobs");
            }
        }
    }
}
