//! HashiCorp Vault (and OpenBao) as an external secrets `Provider` (ADR 0125).
//!
//! Each secret is one KV v2 secret, `<VAULT_KV_MOUNT>/<VAULT_KV_PREFIX>/<bots|server>/<NAME>`,
//! whose field `VAULT_KV_FIELD` (`value`) holds the value. botd signs in with a token
//! (`VAULT_TOKEN`, or `VAULT_TOKEN_FILE`, read again whenever Vault refuses the one it
//! has, so Vault Agent can rotate it) or AppRole (`VAULT_ROLE_ID`, `VAULT_SECRET_ID`,
//! each also `_FILE`), logging in again before the token's lease runs out and once more
//! when Vault refuses it. Requests run on a thread of their own, so a store read from
//! inside botd's async code never blocks on a runtime it is part of.

use super::external::{self, Provider, Scope};
use super::{Error, SecretStore};
use crate::audit::{Event, Outcome};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(10);
/// Longest a caller waits for the request thread: a login and a retried request.
const WAIT: Duration = Duration::from_secs(35);

pub enum Auth {
    /// The token itself, or the file that holds it (read again when Vault refuses it).
    Token { value: Option<Zeroizing<String>>, file: Option<PathBuf> },
    AppRole { mount: String, role_id: Zeroizing<String>, secret_id: Zeroizing<String> },
}

pub struct Config {
    /// `scheme://host[:port]`, no trailing slash.
    pub addr: String,
    pub namespace: Option<String>,
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
            other => return Err(format!("VAULT_AUTH must be token or approle, not {other:?}")),
        };
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
    /// When to log in again (AppRole), before the lease runs out.
    renew_at: Option<Instant>,
}

struct Inner {
    cfg: Config,
    http: reqwest::Client,
    token: Mutex<Option<Token>>,
}

type Job = Box<dyn FnOnce(&tokio::runtime::Runtime) + Send>;

pub struct Vault {
    inner: Arc<Inner>,
    jobs: Mutex<mpsc::Sender<Job>>,
}

fn unavailable(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Unavailable(format!("Vault: {what}: {e}"))
}

impl Vault {
    pub fn new(cfg: Config) -> Result<Vault, String> {
        let mut b = reqwest::Client::builder().connect_timeout(CONNECT_TIMEOUT).timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none());
        if let Some(pem) = &cfg.ca {
            let c = reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|e| format!("VAULT_CACERT: {e}"))?;
            b = b.tls_certs_merge([c]);
        }
        let http = b.build().map_err(|e| format!("Vault client: {e}"))?;
        let (tx, rx) = mpsc::channel::<Job>();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| format!("Vault client: {e}"))?;
        std::thread::Builder::new()
            .name("vault".into())
            .spawn(move || {
                for job in rx {
                    job(&rt);
                }
            })
            .map_err(|e| format!("Vault client: {e}"))?;
        Ok(Vault { inner: Arc::new(Inner { cfg, http, token: Mutex::new(None) }), jobs: Mutex::new(tx) })
    }

    /// Runs `f` on the request thread and waits for it.
    fn run<T, F, Fut>(&self, f: F) -> Result<T, Error>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Inner>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T, Error>>,
    {
        let (tx, rx) = mpsc::channel();
        let inner = Arc::clone(&self.inner);
        let job: Job = Box::new(move |rt| {
            let _ = tx.send(rt.block_on(f(inner)));
        });
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).send(job).map_err(|_| Error::Unavailable("Vault: the request thread stopped".into()))?;
        let wait = || rx.recv_timeout(WAIT);
        // On one of botd's runtime workers, hand its other tasks to another worker while
        // this waits, so a slow Vault never stalls requests, heartbeats or timers.
        let multi = tokio::runtime::Handle::try_current().is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
        let got = if multi { tokio::task::block_in_place(wait) } else { wait() };
        got.map_err(|_| Error::Unavailable("Vault: no answer in time".into()))?
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
        let mut r = self.http.request(method, self.url(path));
        if let Some(ns) = &self.cfg.namespace {
            r = r.header("X-Vault-Namespace", ns);
        }
        r
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
            Auth::AppRole { mount, role_id, secret_id } => self.login(mount, role_id, secret_id).await?,
        };
        let value = t.value.clone();
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = Some(t);
        Ok(value)
    }

    async fn login(&self, mount: &str, role_id: &str, secret_id: &str) -> Result<Token, Error> {
        let result = async {
            let body = json!({ "role_id": role_id, "secret_id": secret_id });
            let res = self.request(reqwest::Method::POST, &format!("auth/{mount}/login")).json(&body).send().await.map_err(|e| unavailable("AppRole login", e))?;
            let status = res.status();
            if !status.is_success() {
                return Err(Error::Unavailable(format!("Vault: AppRole login answered {status}")));
            }
            let v: Value = res.json().await.map_err(|e| unavailable("AppRole login", e))?;
            let value = v["auth"]["client_token"].as_str().filter(|t| !t.is_empty()).ok_or_else(|| Error::Unavailable("Vault: AppRole login gave no token".into()))?;
            // Log in again two thirds of the way through the lease, so a token never lapses mid-run.
            let lease = v["auth"]["lease_duration"].as_u64().unwrap_or(0);
            let renew_at = (lease > 0).then(|| Instant::now() + Duration::from_secs(lease) * 2 / 3);
            Ok(Token { value: Zeroizing::new(value.to_string()), renew_at })
        }
        .await;
        let e = Event::new(external::actor(), "secret.vault_login").target("vault_auth", mount);
        external::audit(match &result {
            Ok(_) => e.details(json!({ "method": "approle" })),
            Err(err) => e.outcome(Outcome::Failure).details(json!({ "method": "approle", "error": err.kind() })),
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
        };
        let ns = c.namespace.as_deref().map(|n| format!(", namespace {n}")).unwrap_or_default();
        format!("HashiCorp Vault at {}{ns}, KV v2 {}/{}/{{bots,server}}/<NAME> field {:?}, {auth}", c.addr, c.mount, c.prefix, c.field)
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
mod tests {
    use super::super::env::EnvStore;
    use super::super::external::{tests::audited, ExternalStore};
    use super::super::{redact, sealed, Secrets};
    use super::*;
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::Json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A stand-in for Vault's KV v2 and AppRole APIs: no real Vault, account or network.
    #[derive(Default)]
    struct Fake {
        /// `<mount>/<path>` → fields.
        kv: Mutex<HashMap<String, Value>>,
        tokens: Mutex<Vec<String>>,
        logins: AtomicUsize,
        reads: AtomicUsize,
        down: AtomicBool,
        namespaces: Mutex<Vec<String>>,
        lease: AtomicUsize,
        delay_ms: AtomicUsize,
    }

    type F = Arc<Fake>;

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

    async fn login(State(f): State<F>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
        if body["role_id"] != "role-1" || body["secret_id"] != "secret-id-1" {
            return (StatusCode::BAD_REQUEST, Json(json!({ "errors": ["invalid role or secret ID"] })));
        }
        let n = f.logins.fetch_add(1, Ordering::SeqCst);
        let token = format!("hvs.approle-{n}");
        f.tokens.lock().unwrap().push(token.clone());
        (StatusCode::OK, Json(json!({ "auth": { "client_token": token, "lease_duration": f.lease.load(Ordering::SeqCst), "renewable": true } })))
    }

    /// Starts the stand-in on its own thread and runtime; returns its address.
    fn stand_in() -> (String, F) {
        let f = F::default();
        f.lease.store(3600, Ordering::SeqCst);
        let app = axum::Router::new()
            .route("/v1/secret/data/{*rest}", axum::routing::get(data))
            .route("/v1/secret/metadata/{*rest}", axum::routing::get(metadata))
            .route("/v1/auth/approle/login", axum::routing::post(login))
            .with_state(Arc::clone(&f));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                tx.send(format!("http://{}", listener.local_addr().unwrap())).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        (rx.recv().unwrap(), f)
    }

    fn put(f: &Fake, path: &str, value: &str) {
        f.kv.lock().unwrap().insert(format!("superbot/{path}"), json!({ "value": value }));
    }

    fn settings(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String + use<> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned().unwrap_or_default()
    }

    fn vault(url: &str, extra: &[(&str, &str)], ttl: Duration) -> Arc<ExternalStore> {
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
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "kubernetes")], "token or approle"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "approle")], "VAULT_ROLE_ID"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_CACERT", "/nonexistent/ca.pem")], "VAULT_CACERT"),
        ] {
            let e = ok(&pairs).err().unwrap_or_default();
            assert!(e.contains(err), "{pairs:?}: {e}");
        }
        let none = EnvStore::fixed(&[]);
        assert!(Config::from_env(&settings(&[("VAULT_ADDR", "https://v")]), &none).err().unwrap().contains("VAULT_TOKEN"));
    }

    #[test]
    fn vault_credentials_never_reach_bots() {
        for name in ["VAULT_TOKEN", "VAULT_SECRET_ID", "VAULT_ROLE_ID"] {
            assert!(super::super::check_name(name).is_err(), "{name} is reserved");
            let s = Secrets::new(vec![Box::new(EnvStore::fixed(&[(name, "hvs.0123456789abcdef")]))]);
            assert!(s.harness_env().is_empty() && s.inherited_harness_env().is_empty() && s.list().unwrap().is_empty(), "{name}");
            let host = crate::adapters::local_host();
            for k in [name.to_string(), format!("{name}_FILE")] {
                assert!(host.remove.iter().any(|r| *r == k), "{k} removed from local jobs");
            }
        }
    }
}
