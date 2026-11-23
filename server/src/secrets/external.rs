//! Secrets kept in an external secrets manager: HashiCorp Vault (`vault`, ADR 0125),
//! Azure Key Vault (`azure-keyvault`), GCP Secret Manager (`gcp-secret-manager`,
//! ADR 0136) and AWS Secrets Manager (`aws`, ADR 0146). Each is a `Provider`; the `ExternalStore` around it is the `SecretStore`
//! botd asks, and does the rest the same way for all of them:
//!
//! - Two folders: `bots` holds the server-wide secrets Bots get, `server` holds botd's
//!   own (`server_secret` names, and Stripe's keys). A name is only ever read from its
//!   own folder, so the backend's own policies can keep the two apart.
//! - Values and name lists are cached for `SECRETS_CACHE_SECONDS` (300 by default).
//! - Fail closed: once a cached answer is older than that, a backend that can't answer
//!   is an error (`Error::Unavailable`), never a stale value and never a fallback to
//!   the next store. A run whose secrets can't be read doesn't start.
//! - Every read that reaches the backend, and every failure, is audited
//!   (`secret.read`, actor `system`/`secrets`), with the name and never the value.
//!   Cache hits aren't, so the log grows with the cache time, not with runs.
//! - Read-only: `botctl secret set` and the API still save into the sealed store,
//!   which a value of the same name here shadows.
//! - With `SECRETS_USER_FOLDERS=1`, a third kind of folder: `users/<user id>` holds one
//!   user's own secrets, which reach only Bots that user owns, over the server-wide ones
//!   and over the ones they saved in botd (ADR 0174). Cached, failing closed and audited
//!   like the others; values are redacted from that user's Bots.

use super::leases::{self, RunCredentials};
use super::{check_name, check_user_name, env_shaped, redact, server_secret, Error, Secret, SecretStore};
use crate::audit::{Actor, Event, Outcome};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Which folder of the backend a name lives in.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Server-wide secrets that reach Bots.
    Bots,
    /// botd's own; no Bot gets them.
    Server,
    /// One user's own, for their Bots only (ADR 0174). Only made by `Scope::user`, so
    /// the id is always safe in a path or a secret name.
    User(String),
}

/// The longest user id that names a folder. botd's own are much shorter (`u` and 8 hex).
const MAX_USER_ID: usize = 64;

impl Scope {
    /// The shared folders, checked at startup. Users' folders are read when their Bots run.
    pub const ALL: [Scope; 2] = [Scope::Bots, Scope::Server];

    /// A user's folder, or None for an id that can't name one: only `a-z` and `0-9`, so
    /// it means the same in every backend, Key Vault's case-blind names included.
    pub fn user(id: &str) -> Option<Scope> {
        let ok = !id.is_empty() && id.len() <= MAX_USER_ID && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        ok.then(|| Scope::User(id.to_string()))
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Bots => "bots",
            Scope::Server => "server",
            Scope::User(_) => "users",
        }
    }

    /// The folder under the prefix, its parts joined with `sep`: `bots`, `server`, or
    /// `users<sep><id>`.
    pub fn folder(&self, sep: char) -> String {
        match self {
            Scope::User(id) => format!("users{sep}{id}"),
            s => s.as_str().to_string(),
        }
    }

    fn user_id(&self) -> Option<&str> {
        match self {
            Scope::User(id) => Some(id),
            _ => None,
        }
    }

    /// Whether `name` may be read from this folder: a name is only read from its own
    /// shared folder, and a user's folder holds only names a user may save.
    fn holds(&self, name: &str) -> bool {
        match self {
            Scope::User(_) => check_user_name(name).is_ok(),
            s => scope_of(name).as_ref() == Some(s),
        }
    }
}

/// botd's own secrets that are reserved names rather than `server_secret` ones, read
/// at startup only (the Stripe keys, ADR 0040 and 0042).
const SERVER_ONLY: [&str; 2] = ["STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"];

/// The folder `name` is read from, or None for a name no external store may answer
/// (`AUTH_PASSWORD`, `SUPERBOT_*`, `PATH`, ...).
pub fn scope_of(name: &str) -> Option<Scope> {
    if !env_shaped(name) {
        None
    } else if server_secret(name) || SERVER_ONLY.contains(&name) {
        Some(Scope::Server)
    } else if check_name(name).is_ok() {
        Some(Scope::Bots)
    } else {
        None
    }
}

/// One secrets manager. Errors are `Error::Unavailable` when the backend couldn't be
/// asked or refused botd, and must carry no value.
pub trait Provider: Send + Sync {
    /// Short name shown to the operator and in the audit log: "vault", ...
    fn kind(&self) -> &'static str;
    /// Where it is and how botd signs in, for the startup line. No secrets.
    fn describe(&self) -> String;
    /// The value of `name` in `scope`, or None if there is none.
    fn read(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error>;
    /// Names in `scope`. Never values.
    fn list(&self, scope: Scope) -> Result<Vec<String>, Error>;
}

/// Audit events from reads, waiting for `start_audit` to write them: a read can happen
/// before the database is open, or while the caller holds it.
static PENDING: Mutex<VecDeque<Event>> = Mutex::new(VecDeque::new());
const MAX_PENDING: usize = 10_000;
static DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn audit(e: Event) {
    let mut q = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    if q.len() >= MAX_PENDING {
        q.pop_front();
        DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    q.push_back(e);
}

/// Takes the events waiting to be written, and how many were dropped because too many waited.
pub fn drain_audit() -> (Vec<Event>, u64) {
    let events = PENDING.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
    (events, DROPPED.swap(0, std::sync::atomic::Ordering::Relaxed))
}

pub(crate) fn actor() -> Actor {
    Actor::system("secrets")
}

/// Writes waiting read events to the audit log every couple of seconds.
pub fn start_audit(app: Arc<crate::runner::App>) {
    tokio::spawn(async move {
        loop {
            flush_audit(&app.db);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

pub fn flush_audit(db: &crate::db::Db) {
    let (events, dropped) = drain_audit();
    write_audit(db, &events, dropped);
}

fn write_audit(db: &crate::db::Db, events: &[Event], dropped: u64) {
    for e in events {
        db.record(e);
    }
    if dropped > 0 {
        crate::obs::log::log_warn!("Secrets: {dropped} read events were dropped before they could be audited.");
        db.record(&Event::new(actor(), "secret.read_events_dropped").outcome(Outcome::Failure).details(json!({ "dropped": dropped })));
    }
}

/// Each name's answer (a value, or "not there") in each folder, and when it was read.
type Answers = HashMap<(Scope, String), (Instant, Option<Zeroizing<String>>)>;

/// A `Provider` with a cache, fail-closed reads and audited reads; see the module docs.
pub struct ExternalStore {
    provider: Box<dyn Provider>,
    ttl: Duration,
    values: Mutex<Answers>,
    names: Mutex<HashMap<Scope, (Instant, Vec<String>)>>,
    /// `SECRETS_USER_FOLDERS`: each user's own folder is read for their Bots (ADR 0174).
    user_folders: bool,
    /// `VAULT_RUN_CREDENTIALS`: short-lived credentials made for each run (ADR 0185).
    run_credentials: Option<Arc<RunCredentials>>,
}

impl ExternalStore {
    pub fn new(provider: Box<dyn Provider>, ttl: Duration) -> ExternalStore {
        ExternalStore { provider, ttl, values: Mutex::default(), names: Mutex::default(), user_folders: false, run_credentials: None }
    }

    pub fn with_user_folders(mut self, on: bool) -> ExternalStore {
        self.user_folders = on;
        self
    }

    pub fn user_folders(&self) -> bool {
        self.user_folders
    }

    pub fn with_run_credentials(mut self, rc: Option<RunCredentials>) -> ExternalStore {
        self.run_credentials = rc.map(Arc::new);
        self
    }

    pub fn run_credentials(&self) -> Option<&Arc<RunCredentials>> {
        self.run_credentials.as_ref()
    }

    pub fn describe(&self) -> String {
        let users = if self.user_folders { ", and users/<id> for each user's own" } else { "" };
        let runs = self.run_credentials.as_ref().map(|rc| format!(", {}", rc.describe())).unwrap_or_default();
        format!("{}{users}, cached for {} s{runs}", self.provider.describe(), self.ttl.as_secs())
    }

    fn fresh(&self, at: Instant) -> bool {
        at.elapsed() < self.ttl
    }

    /// Drops answers past their time as new ones come in, so the cache holds the users
    /// whose Bots ran lately, not everyone who ever had one.
    fn prune<K, V>(&self, cached: &mut HashMap<K, (Instant, V)>) {
        cached.retain(|_, (at, _)| self.fresh(*at));
    }

    /// Drops everything cached from `user_id`'s folder, when the user is deleted.
    pub fn forget_user(&self, user_id: &str) {
        let Some(scope) = Scope::user(user_id) else { return };
        self.values.lock().unwrap_or_else(|e| e.into_inner()).retain(|(s, _), _| *s != scope);
        self.names.lock().unwrap_or_else(|e| e.into_inner()).remove(&scope);
    }

    /// Startup check: lists both folders straight from the backend, so botd refuses to
    /// start on a backend it can't reach or sign in to. Returns how many names it has.
    pub fn check(&self) -> Result<usize, Error> {
        let mut n = 0;
        for scope in Scope::ALL {
            let names = self.list_from_backend(&scope)?;
            n += names.len();
        }
        Ok(n)
    }

    /// The audit details every read of `scope` carries; a user's folder names its user.
    fn details(&self, scope: &Scope, op: &str) -> serde_json::Value {
        let mut d = json!({ "store": self.provider.kind(), "scope": scope.as_str(), "op": op });
        if let Some(id) = scope.user_id() {
            d["userId"] = json!(id);
        }
        d
    }

    fn list_from_backend(&self, scope: &Scope) -> Result<Vec<String>, Error> {
        let target = Event::new(actor(), "secret.read").target("secret_folder", &scope.folder('/'));
        let mut details = self.details(scope, "list");
        match self.provider.list(scope.clone()) {
            Ok(names) => {
                let mut names: Vec<String> = names.into_iter().filter(|n| scope.holds(n)).collect();
                names.sort();
                names.dedup();
                let mut cached = self.names.lock().unwrap_or_else(|e| e.into_inner());
                self.prune(&mut cached);
                cached.insert(scope.clone(), (Instant::now(), names.clone()));
                drop(cached);
                details["names"] = json!(names.len());
                audit(target.details(details));
                Ok(names)
            }
            Err(e) => {
                self.names.lock().unwrap_or_else(|e| e.into_inner()).remove(scope);
                details["error"] = json!(e.kind());
                audit(target.outcome(Outcome::Failure).details(details));
                Err(e)
            }
        }
    }

    fn fetch(&self, scope: &Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let got = self.provider.read(scope.clone(), name);
        let key = (scope.clone(), name.to_string());
        let details = |found: Option<bool>, err: Option<&Error>| {
            let mut d = self.details(scope, "read");
            d["found"] = json!(found);
            d["error"] = json!(err.map(Error::kind));
            d
        };
        match got {
            Ok(v) => {
                if let Some(v) = &v {
                    match scope.user_id() {
                        // Like a value the user saved in botd: redacted from their Bots,
                        // not from everyone's (ADR 0029).
                        Some(id) => redact::register_for(id, v),
                        None => redact::register(v),
                    }
                }
                let mut cached = self.values.lock().unwrap_or_else(|e| e.into_inner());
                self.prune(&mut cached);
                cached.insert(key, (Instant::now(), v.clone()));
                drop(cached);
                audit(Event::new(actor(), "secret.read").target("secret", name).details(details(Some(v.is_some()), None)));
                Ok(v)
            }
            Err(e) => {
                // Fail closed: what was cached is dropped, not served past its time.
                self.values.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
                audit(Event::new(actor(), "secret.read").target("secret", name).outcome(Outcome::Failure).details(details(None, Some(&e))));
                Err(e)
            }
        }
    }

    fn get_in(&self, scope: &Scope, name: &str) -> Result<Option<Secret>, Error> {
        if !scope.holds(name) {
            return Ok(None);
        }
        let key = (scope.clone(), name.to_string());
        let cached = self.values.lock().unwrap_or_else(|e| e.into_inner()).get(&key).filter(|(at, _)| self.fresh(*at)).map(|(_, v)| v.clone());
        let v = match cached {
            Some(v) => v,
            None => self.fetch(scope, name)?,
        };
        Ok(v.map(|v| Secret::new(v.as_str())))
    }

    fn names_in(&self, scope: &Scope) -> Result<Vec<String>, Error> {
        let cached = self.names.lock().unwrap_or_else(|e| e.into_inner()).get(scope).filter(|(at, _)| self.fresh(*at)).map(|(_, n)| n.clone());
        match cached {
            Some(n) => Ok(n),
            None => self.list_from_backend(scope),
        }
    }

    /// The folder of `user_id`'s own secrets, if user folders are on and the id can name one.
    fn user_scope(&self, user_id: &str) -> Option<Scope> {
        if self.user_folders { Scope::user(user_id) } else { None }
    }

    /// Names in `user_id`'s own folder; none while user folders are off. Never values.
    pub fn user_names(&self, user_id: &str) -> Result<Vec<String>, Error> {
        self.user_scope(user_id).map_or(Ok(Vec::new()), |s| self.names_in(&s))
    }

    /// The value of `name` in `user_id`'s own folder.
    pub fn user_get(&self, user_id: &str, name: &str) -> Result<Option<Secret>, Error> {
        self.user_scope(user_id).map_or(Ok(None), |s| self.get_in(&s, name))
    }
}

impl SecretStore for ExternalStore {
    fn kind(&self) -> &'static str {
        self.provider.kind()
    }

    fn get(&self, name: &str) -> Result<Option<Secret>, Error> {
        match scope_of(name) {
            Some(scope) => self.get_in(&scope, name),
            None => Ok(None),
        }
    }

    fn names(&self) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        for scope in Scope::ALL {
            out.extend(self.names_in(&scope)?);
        }
        Ok(out)
    }
}

/// One `ExternalStore` used both at startup and by `Secrets`.
pub struct Shared(pub Arc<ExternalStore>);

impl SecretStore for Shared {
    fn kind(&self) -> &'static str {
        self.0.kind()
    }
    fn get(&self, name: &str) -> Result<Option<Secret>, Error> {
        self.0.get(name)
    }
    fn names(&self) -> Result<Vec<String>, Error> {
        self.0.names()
    }
}

/// Stores asked in order, first answer wins: what startup settings read their secrets
/// through (the environment, then the external store), as `Secrets` does later.
pub struct Layered<'a>(pub Vec<&'a dyn SecretStore>);

impl SecretStore for Layered<'_> {
    fn kind(&self) -> &'static str {
        self.0.first().map_or("none", |s| s.kind())
    }
    fn get(&self, name: &str) -> Result<Option<Secret>, Error> {
        for s in &self.0 {
            if let Some(v) = s.get(name)? {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }
    fn names(&self) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        for s in &self.0 {
            out.extend(s.names()?);
        }
        out.sort();
        out.dedup();
        Ok(out)
    }
}

pub const DEFAULT_CACHE_SECONDS: u64 = 300;
const MAX_CACHE_SECONDS: u64 = 86_400;

/// `SECRETS_CACHE_SECONDS`: how long an answer from the backend is used, 0 to 86400.
pub fn cache_ttl(raw: &str) -> Result<Duration, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Duration::from_secs(DEFAULT_CACHE_SECONDS));
    }
    match raw.parse::<u64>() {
        Ok(n) if n <= MAX_CACHE_SECONDS => Ok(Duration::from_secs(n)),
        _ => Err(format!("SECRETS_CACHE_SECONDS must be a number of seconds from 0 to {MAX_CACHE_SECONDS}, not {raw:?}")),
    }
}

/// `SECRETS_BACKEND`: `local` (the default: the environment and the sealed store only),
/// `vault`, `azure-keyvault`, `gcp-secret-manager` or `aws`. None for local. Settings for a
/// backend that isn't the one chosen are warned about, not used.
pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Option<Arc<ExternalStore>>, String> {
    let ttl = cache_ttl(&var("SECRETS_CACHE_SECONDS"))?;
    let users = user_folders(&var("SECRETS_USER_FOLDERS"))?;
    let chosen = var("SECRETS_BACKEND").trim().to_string();
    let mut run_credentials = None;
    let provider: Box<dyn Provider> = match chosen.as_str() {
        "" | "local" => {
            warn_unused(var, "local");
            if users {
                crate::obs::log::log_warn!("Secrets backend: SECRETS_USER_FOLDERS=1 is set, but SECRETS_BACKEND is local, so users' secrets stay in the sealed store (ADR 0174).");
            }
            return Ok(None);
        }
        "vault" => {
            let v = super::vault::Vault::new(super::vault::Config::from_env(var, store)?)?;
            let wanted = leases::parse(&var("VAULT_RUN_CREDENTIALS"))?;
            if !wanted.is_empty() {
                run_credentials = Some(RunCredentials::new(Arc::new(v.clone()), wanted));
            }
            Box::new(v)
        }
        "azure-keyvault" => Box::new(super::azure::KeyVault::new(super::azure::Config::from_env(var, store)?)?),
        "gcp-secret-manager" => Box::new(super::gcp::SecretManager::new(super::gcp::Config::from_env(var, store)?)?),
        "aws" => {
            let cfg = super::aws::Config::from_env(var, store)?;
            super::keep_from_bots(cfg.source.reserved(), cfg.source.settings());
            let sm = super::aws::SecretsManager::new(cfg)?;
            let wanted = leases::parse_as(&leases::AWS, &var("AWS_RUN_CREDENTIALS"))?;
            if !wanted.is_empty() {
                run_credentials = Some(RunCredentials::new(Arc::new(sm.clone()), wanted));
            }
            Box::new(sm)
        }
        other => return Err(format!("SECRETS_BACKEND must be local, vault, azure-keyvault, gcp-secret-manager or aws, not {other:?}")),
    };
    warn_unused(var, &chosen);
    Ok(Some(Arc::new(ExternalStore::new(provider, ttl).with_user_folders(users).with_run_credentials(run_credentials))))
}

/// `SECRETS_USER_FOLDERS`: `1` reads each user's own folder too (ADR 0174); off by default.
pub fn user_folders(raw: &str) -> Result<bool, String> {
    match raw.trim() {
        "" | "0" => Ok(false),
        "1" => Ok(true),
        other => Err(format!("SECRETS_USER_FOLDERS must be 1 or 0, not {other:?}")),
    }
}

/// The settings of backends other than `chosen` that are set: probably a mistake.
pub fn unused_settings(var: &dyn Fn(&str) -> String, chosen: &str) -> Vec<&'static str> {
    const KEYS: [(&str, &str); 10] = [
        ("vault", "VAULT_ADDR"),
        ("vault", "VAULT_RUN_CREDENTIALS"),
        ("azure-keyvault", "AZURE_KEYVAULT_URL"),
        ("azure-keyvault", "AZURE_KEYVAULT_AUTH"),
        ("gcp-secret-manager", "GCP_SECRET_MANAGER_PROJECT"),
        ("gcp-secret-manager", "GCP_SECRET_MANAGER_AUTH"),
        ("gcp-secret-manager", "GCP_SECRET_MANAGER_LOCATION"),
        ("aws", "AWS_SECRETS_MANAGER_REGION"),
        ("aws", "AWS_SECRETS_MANAGER_AUTH"),
        ("aws", "AWS_RUN_CREDENTIALS"),
    ];
    KEYS.iter().filter(|(b, k)| *b != chosen && !var(k).trim().is_empty()).map(|(_, k)| *k).collect()
}

fn warn_unused(var: &dyn Fn(&str) -> String, chosen: &str) {
    let unused = unused_settings(var, chosen);
    if !unused.is_empty() {
        crate::obs::log::log_warn!("Secrets backend: {} set, but SECRETS_BACKEND is {chosen}, so they are ignored (ADR 0136, ADR 0146).", unused.join(", "));
    }
}

/// The external store botd runs with, for diagnostics (`secrets::init` sets it).
static ACTIVE: std::sync::OnceLock<Arc<ExternalStore>> = std::sync::OnceLock::new();

pub(crate) fn set_active(x: &Arc<ExternalStore>) {
    let _ = ACTIVE.set(Arc::clone(x));
}

/// The secrets backend and whether it answers, for the setup report and `botctl secrets
/// backend`: names, counts and errors, never a value.
pub fn diagnostics() -> serde_json::Value {
    diagnose(ACTIVE.get().map(Arc::as_ref))
}

fn diagnose(x: Option<&ExternalStore>) -> serde_json::Value {
    let Some(x) = x else {
        return json!({
            "backend": "local",
            "description": "the environment and the sealed store",
            "ok": true,
            "detail": "Local: secrets come from the environment and the sealed store. SECRETS_BACKEND=vault, azure-keyvault, gcp-secret-manager or aws adds an external one (ADR 0125, ADR 0136, ADR 0146).",
        });
    };
    // Straight from the backend, not the cache: whether it answers now.
    let (ok, names, detail) = match x.check() {
        Ok(n) => (true, Some(n), format!("{} answers: {n} names in its bots and server folders.", x.kind())),
        Err(e) => (false, None, format!("{} can't be read: {e}. Bot runs are refused until it answers (fail closed).", x.kind())),
    };
    let run_credentials = x.run_credentials.as_ref().map(|rc| rc.paths()).unwrap_or_default();
    json!({ "backend": x.kind(), "description": x.describe(), "cacheSeconds": x.ttl.as_secs(), "userFolders": x.user_folders, "runCredentials": run_credentials, "ok": ok, "names": names, "detail": detail })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A backend held in memory, which can be taken down.
    #[derive(Default)]
    pub(crate) struct Fake {
        pub values: Mutex<HashMap<(Scope, String), String>>,
        pub down: AtomicBool,
        pub reads: AtomicUsize,
        pub lists: AtomicUsize,
    }

    impl Provider for Arc<Fake> {
        fn kind(&self) -> &'static str {
            "fake"
        }
        fn describe(&self) -> String {
            "fake".into()
        }
        fn read(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(Error::Unavailable("fake is down".into()));
            }
            // Empty is "no value", as the real backends answer for a deleted version or empty field.
            Ok(self.values.lock().unwrap().get(&(scope, name.to_string())).filter(|v| !v.is_empty()).map(|v| Zeroizing::new(v.clone())))
        }
        fn list(&self, scope: Scope) -> Result<Vec<String>, Error> {
            self.lists.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(Error::Unavailable("fake is down".into()));
            }
            Ok(self.values.lock().unwrap().keys().filter(|(s, _)| *s == scope).map(|(_, n)| n.clone()).collect())
        }
    }

    pub(crate) fn diagnose_for(x: &ExternalStore) -> serde_json::Value {
        diagnose(Some(x))
    }

    pub(crate) fn user(id: &str) -> Scope {
        Scope::user(id).unwrap()
    }

    /// `x`, with users' folders on, for a provider's own tests.
    pub(crate) fn users_on(x: Arc<ExternalStore>) -> ExternalStore {
        Arc::try_unwrap(x).ok().expect("not shared yet").with_user_folders(true)
    }

    /// What a provider's own tests check about a users' folders: each user reads only
    /// theirs, only names a user may have, and the shared folders don't see them.
    pub(crate) fn reads_users_folders(x: &ExternalStore, value: &str) {
        assert_eq!(x.user_names("ua1").unwrap(), ["OPENAI_API_KEY"], "LINODE_TOKEN is botd's own, never a user's");
        assert_eq!(x.user_get("ua1", "OPENAI_API_KEY").unwrap().unwrap().expose(), value);
        assert!(x.user_get("ua1", "LINODE_TOKEN").unwrap().is_none());
        assert_eq!(x.user_get("ub1", "OPENAI_API_KEY").unwrap().unwrap().expose(), "ub1-own-openai");
        assert!(x.user_names("uc1").unwrap().is_empty() && x.user_get("uc1", "OPENAI_API_KEY").unwrap().is_none(), "no folder: nothing");
        assert!(x.user_names("ua").unwrap().is_empty(), "not a prefix match on another user's id");
        assert_eq!(x.check().unwrap(), 0, "users' folders aren't the shared ones");
        assert!(x.get("OPENAI_API_KEY").unwrap().is_none());
        assert_eq!(redact::text_for(&["ua1"], value), redact::MARK);
        redact::forget_for("ua1", value);
        redact::forget_for("ub1", "ub1-own-openai");
    }

    /// A store over `fake` with users' folders on, and a `Secrets` that reads it as
    /// `secrets::init` does: environment, then it, then the sealed stores.
    fn with_users(values: &[(Scope, &str, &str)], ttl: Duration) -> (Arc<Fake>, Arc<ExternalStore>, super::super::Secrets) {
        use super::super::{env::EnvStore, sealed, Secrets};
        let (f, _) = fake(&[], ttl);
        for (s, n, v) in values {
            f.values.lock().unwrap().insert((s.clone(), n.to_string()), v.to_string());
        }
        let x = Arc::new(ExternalStore::new(Box::new(Arc::clone(&f)), ttl).with_user_folders(true));
        let path = crate::db::temp_path("user-folders").join("app.sqlite");
        let sealed = sealed::SealedStore::new(sealed::connect(&path).unwrap(), sealed::cipher());
        let users = sealed::UserSecrets::new(sealed::connect(&path).unwrap(), sealed::cipher());
        let s = Secrets::new(vec![Box::new(EnvStore::fixed(&[])), Box::new(Shared(Arc::clone(&x))), Box::new(sealed)]).with_users(users).with_user_folders(Arc::clone(&x));
        (f, x, s)
    }

    fn env_of(s: &super::super::Secrets, owner: &str) -> Vec<(String, String)> {
        let mut e: Vec<_> = s.try_harness_env_for(owner).unwrap().into_iter().map(|(k, v)| (k, v.expose().to_string())).collect();
        e.sort();
        e
    }

    #[test]
    fn user_ids_name_folders_only_when_safe_everywhere() {
        assert_eq!(user("u1a2b3c4d").folder('/'), "users/u1a2b3c4d");
        assert_eq!(user("operator").folder('-'), "users-operator");
        assert_eq!(Scope::Bots.folder('/'), "bots");
        for bad in ["", "U1", "u-1", "u_1", "u/1", "../u", "u 1", "ü", &"a".repeat(65)] {
            assert_eq!(Scope::user(bad), None, "{bad:?}");
        }
        assert!(Scope::user(&"a".repeat(64)).is_some());
        assert!(user("ua").holds("OPENAI_API_KEY") && !user("ua").holds("LINODE_TOKEN") && !user("ua").holds("PATH") && !user("ua").holds("SSO_X_CLIENT_SECRET"));
        assert_eq!(user_folders("").unwrap(), false);
        assert_eq!(user_folders(" 1 ").unwrap(), true);
        assert!(user_folders("yes").unwrap_err().contains("must be 1 or 0"));
    }

    #[test]
    fn a_users_folder_reaches_only_their_bots_over_everything_else() {
        let ua = format!("ua-ext-{}", crate::random_hex(10));
        let ub = "ub-ext-value-1";
        let (_, x, s) = with_users(
            &[
                (Scope::Bots, "OPENAI_API_KEY", "team-ext-openai-1"),
                (Scope::Bots, "GH_TOKEN", "team-ext-gh-1"),
                (user("ua"), "OPENAI_API_KEY", &ua),
                (user("ua"), "LINODE_TOKEN", "never-from-a-users-folder"),
                (user("ua"), "PATH", "/never"),
                (user("ua"), "GH_TOKEN", ""),
                (user("ub"), "GH_TOKEN", ub),
            ],
            Duration::from_secs(60),
        );
        s.user_put("ua", "OPENAI_API_KEY", "ua-sealed-but-shadowed").unwrap();
        s.user_put("ua", "NPM_TOKEN", "ua-sealed-npm-1").unwrap();
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(env_of(&s, "ua"), [pair("GH_TOKEN", "team-ext-gh-1"), pair("NPM_TOKEN", "ua-sealed-npm-1"), pair("OPENAI_API_KEY", &ua)], "the folder beats the sealed copy and the team's");
        assert_eq!(env_of(&s, "ub"), [pair("GH_TOKEN", ub), pair("OPENAI_API_KEY", "team-ext-openai-1")], "none of A's");
        assert_eq!(env_of(&s, "uc"), [pair("GH_TOKEN", "team-ext-gh-1"), pair("OPENAI_API_KEY", "team-ext-openai-1")]);
        assert_eq!(env_of(&s, "U-C"), env_of(&s, "uc"), "an id that can't name a folder reads none");
        assert!(s.try_harness_env().unwrap().iter().all(|(_, v)| v.expose() != ua), "never server-wide");
        assert_eq!(redact::text_for(&["ua"], &ua), redact::MARK, "redacted from A's Bots");
        assert_eq!(redact::text(&ua), ua.as_str(), "not from everyone's");

        let listed: Vec<_> = s.user_list("ua").unwrap().into_iter().map(|l| (l.name, l.store, l.saved, l.overrides)).collect();
        assert_eq!(listed, [("NPM_TOKEN".to_string(), "sealed", true, false), ("OPENAI_API_KEY".to_string(), "fake", true, true)], "GH_TOKEN is listed in the folder but has no value, so the team's wins and it isn't shown");
        let b = &s.user_list("ub").unwrap()[0];
        assert_eq!((b.name.as_str(), b.store, b.saved, b.created_at), ("GH_TOKEN", "fake", false, None));
        assert!(serde_json::to_value(b).unwrap().get("createdAt").is_none(), "no dates for a value botd never saved");
        assert_eq!(s.user_forget("ua").unwrap(), 2, "only what botd saved; the folder is the backend's");
        assert!(!x.values.lock().unwrap().keys().any(|(sc, _)| *sc == user("ua")) && !x.names.lock().unwrap().contains_key(&user("ua")), "nor its cache");
        assert_eq!(env_of(&s, "ua"), [pair("GH_TOKEN", "team-ext-gh-1"), pair("OPENAI_API_KEY", &ua)]);
        redact::forget_for("ua", &ua);
        redact::forget_for("ub", ub);
        redact::forget_for("ua", "ua-sealed-npm-1");
        redact::forget_for("ua", "ua-sealed-but-shadowed");
        redact::forget("team-ext-openai-1");
        redact::forget("team-ext-gh-1");
    }

    #[test]
    fn a_users_folder_is_cached_audited_and_fails_closed() {
        let (f, x, s) = with_users(&[(user("uaudit"), "AUDIT_USER_TOKEN", "user-audit-value-1")], Duration::from_millis(300));
        for _ in 0..3 {
            assert_eq!(env_of(&s, "uaudit"), [("AUDIT_USER_TOKEN".to_string(), "user-audit-value-1".to_string())]);
        }
        let ev = audited("AUDIT_USER_TOKEN");
        assert_eq!(ev.len(), 1, "cached: {ev:?}");
        assert_eq!(ev[0].details, json!({ "store": "fake", "scope": "users", "op": "read", "userId": "uaudit", "found": true, "error": null }));
        let listed = audited("users/uaudit");
        assert_eq!((listed.len(), listed[0].details["userId"].as_str(), listed[0].details["names"].as_u64()), (1, Some("uaudit"), Some(1)));
        assert!(!format!("{ev:?}{listed:?}").contains("user-audit-value-1"));

        f.down.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(350));
        assert!(matches!(s.try_harness_env_for("uaudit"), Err(Error::Unavailable(_))), "a run is refused, not started without the user's keys");
        assert!(s.harness_env_for("uaudit").is_empty());
        assert!(matches!(s.user_list("uaudit"), Err(Error::Unavailable(_))));
        assert!(s.user_save("uaudit", "SAVED_WHILE_DOWN_TOKEN", "saved-while-down-1").is_ok(), "saving into botd doesn't need the backend");
        f.down.store(false, Ordering::SeqCst);
        assert_eq!(env_of(&s, "uaudit").len(), 2);

        // Answers past their time are dropped as new ones come in, not kept for every user ever seen.
        std::thread::sleep(Duration::from_millis(350));
        x.user_names("uother").unwrap();
        x.user_get("uother", "OTHER_TOKEN").unwrap();
        assert!(!x.names.lock().unwrap().contains_key(&user("uaudit")) && !x.values.lock().unwrap().keys().any(|(sc, _)| *sc == user("uaudit")));

        // Off: no user folder is ever asked for.
        let lists = f.lists.load(Ordering::SeqCst);
        let off = ExternalStore::new(Box::new(Arc::clone(&f)), Duration::ZERO);
        assert!(off.user_names("uaudit").unwrap().is_empty() && off.user_get("uaudit", "AUDIT_USER_TOKEN").unwrap().is_none());
        assert_eq!(f.lists.load(Ordering::SeqCst), lists);
        assert!(!x.describe().is_empty() && x.describe().contains("users/<id>") && !off.describe().contains("users/<id>"));
        redact::forget_for("uaudit", "user-audit-value-1");
        redact::forget_for("uaudit", "saved-while-down-1");
    }

    #[test]
    fn user_folders_are_a_startup_setting() {
        let env = super::super::env::EnvStore::fixed(&[]);
        let var = super::super::http::tests::settings(&[("SECRETS_BACKEND", "gcp-secret-manager"), ("GCP_SECRET_MANAGER_PROJECT", "proj-1"), ("SECRETS_USER_FOLDERS", "1")]);
        let x = from_env(&var, &env).unwrap().unwrap();
        assert!(x.user_folders() && diagnose(Some(&x))["userFolders"] == true);
        let var = super::super::http::tests::settings(&[("SECRETS_BACKEND", "gcp-secret-manager"), ("GCP_SECRET_MANAGER_PROJECT", "proj-1")]);
        assert!(!from_env(&var, &env).unwrap().unwrap().user_folders(), "off by default");
        let var = super::super::http::tests::settings(&[("SECRETS_BACKEND", "vault"), ("VAULT_ADDR", "https://v"), ("VAULT_TOKEN", "t"), ("SECRETS_USER_FOLDERS", "true")]);
        assert!(from_env(&var, &env).err().unwrap().contains("SECRETS_USER_FOLDERS"));
        let var = super::super::http::tests::settings(&[("SECRETS_USER_FOLDERS", "1")]);
        assert!(from_env(&var, &env).unwrap().is_none(), "local: warned about, nothing to read");
    }

    pub(crate) fn fake(values: &[(Scope, &str, &str)], ttl: Duration) -> (Arc<Fake>, Arc<ExternalStore>) {
        let f = Arc::new(Fake::default());
        for (s, n, v) in values {
            f.values.lock().unwrap().insert((s.clone(), n.to_string()), v.to_string());
        }
        (Arc::clone(&f), Arc::new(ExternalStore::new(Box::new(f), ttl)))
    }

    /// Events waiting for `name`, left in the queue: tests run side by side.
    pub(crate) fn audited(name: &str) -> Vec<Event> {
        PENDING.lock().unwrap().iter().filter(|e| e.target_id.as_deref() == Some(name)).cloned().collect()
    }

    /// Writes the waiting events whose target is one of `targets` to `db`, as `flush_audit`
    /// does, and leaves every other test's in the queue.
    pub(crate) fn flush_audit_for(db: &crate::db::Db, targets: &[&str]) {
        let mine: Vec<Event> = {
            let mut q = PENDING.lock().unwrap();
            let (mine, rest): (Vec<Event>, Vec<Event>) = q.drain(..).partition(|e| e.target_id.as_deref().is_some_and(|t| targets.contains(&t)));
            q.extend(rest);
            mine
        };
        write_audit(db, &mine, 0);
    }

    #[test]
    fn waiting_events_are_written_to_the_audit_log() {
        let db = crate::db::Db::open(&crate::db::temp_path("secrets-audit").join("app.sqlite")).unwrap();
        let e = Event::new(actor(), "secret.read").target("secret", "WRITTEN_TOKEN").details(json!({ "store": "vault", "scope": "bots", "op": "read", "found": true }));
        write_audit(&db, &[e], 3);
        let f = crate::audit::Filter { actions: vec!["secret.*".into()], ..Default::default() };
        let rows = db.audit_events(&f, 10, true);
        let got: Vec<_> = rows.iter().map(|r| (r.action.as_str(), r.target_id.as_deref(), r.actor_id.as_deref())).collect();
        assert_eq!(got, [("secret.read", Some("WRITTEN_TOKEN"), Some("secrets")), ("secret.read_events_dropped", None, Some("secrets"))]);
    }

    #[test]
    fn names_are_read_from_their_own_folder_only() {
        assert_eq!(scope_of("OPENAI_API_KEY"), Some(Scope::Bots));
        assert_eq!(scope_of("LINODE_TOKEN"), Some(Scope::Server));
        assert_eq!(scope_of("SSO_ENTRA_CLIENT_SECRET"), Some(Scope::Server));
        assert_eq!(scope_of("STRIPE_SECRET_KEY"), Some(Scope::Server));
        for none in ["AUTH_PASSWORD", "SUPERBOT_MASTER_KEY", "PATH", "VAULT_TOKEN", "LICENSE_KEY", "lower", "../X"] {
            assert_eq!(scope_of(none), None, "{none}");
        }
        let (_, s) = fake(
            &[(Scope::Bots, "GH_TOKEN", "gh-1"), (Scope::Bots, "LINODE_TOKEN", "in-the-wrong-folder"), (Scope::Server, "OPENAI_API_KEY", "wrong-too"), (Scope::Server, "LINODE_TOKEN", "lin-1")],
            Duration::from_secs(60),
        );
        assert_eq!(s.get("GH_TOKEN").unwrap().unwrap().expose(), "gh-1");
        assert_eq!(s.get("LINODE_TOKEN").unwrap().unwrap().expose(), "lin-1");
        assert!(s.get("OPENAI_API_KEY").unwrap().is_none(), "a Bot secret is never read from the server folder");
        assert!(s.get("AUTH_PASSWORD").unwrap().is_none());
        let mut names = s.names().unwrap();
        names.sort();
        assert_eq!(names, ["GH_TOKEN", "LINODE_TOKEN"]);
        let listed = PENDING.lock().unwrap().iter().filter(|e| e.target_type.as_deref() == Some("secret_folder") && e.details["store"] == "fake" && e.outcome == Outcome::Success).count();
        assert!(listed >= 2, "each folder listed from the backend is audited");
        redact::forget("gh-1");
        redact::forget("lin-1");
    }

    #[test]
    fn answers_are_cached_for_the_ttl_then_asked_again() {
        let value = format!("cached-{}", crate::random_hex(8));
        let (f, s) = fake(&[(Scope::Bots, "CACHE_TOKEN", &value)], Duration::from_millis(300));
        for _ in 0..5 {
            assert_eq!(s.get("CACHE_TOKEN").unwrap().unwrap().expose(), value);
            assert!(s.get("CACHE_MISSING_TOKEN").unwrap().is_none());
            s.names().unwrap();
        }
        assert_eq!((f.reads.load(Ordering::SeqCst), f.lists.load(Ordering::SeqCst)), (2, 2), "one read per name, one list per folder");
        assert_eq!(redact::text(&value), redact::MARK, "a value read is redacted from then on");
        std::thread::sleep(Duration::from_millis(350));
        f.values.lock().unwrap().insert((Scope::Bots, "CACHE_TOKEN".into()), "rotated-value-1".into());
        assert_eq!(s.get("CACHE_TOKEN").unwrap().unwrap().expose(), "rotated-value-1", "a rotation shows once the cache runs out");
        let (_, none) = fake(&[(Scope::Bots, "CACHE_TOKEN", "v")], Duration::ZERO);
        none.get("CACHE_TOKEN").unwrap();
        redact::forget(&value);
        redact::forget("rotated-value-1");
        redact::forget("v");
    }

    #[test]
    fn a_backend_that_cant_answer_fails_closed() {
        let (f, s) = fake(&[(Scope::Bots, "CLOSED_TOKEN", "closed-value-1")], Duration::from_millis(200));
        assert!(s.get("CLOSED_TOKEN").unwrap().is_some());
        f.down.store(true, Ordering::SeqCst);
        assert!(s.get("CLOSED_TOKEN").unwrap().is_some(), "within the cache time the answer stands");
        std::thread::sleep(Duration::from_millis(250));
        assert!(matches!(s.get("CLOSED_TOKEN"), Err(Error::Unavailable(_))), "never a stale value");
        assert!(matches!(s.names(), Err(Error::Unavailable(_))));
        assert!(matches!(s.check(), Err(Error::Unavailable(_))));
        f.down.store(false, Ordering::SeqCst);
        assert_eq!(s.check().unwrap(), 1);
        redact::forget("closed-value-1");
    }

    #[test]
    fn reads_and_failures_are_audited_by_name_never_value() {
        let (f, s) = fake(&[(Scope::Server, "SSO_AUDITED_CLIENT_SECRET", "smtp-audited-value")], Duration::from_secs(60));
        s.get("SSO_AUDITED_CLIENT_SECRET").unwrap();
        s.get("SSO_AUDITED_CLIENT_SECRET").unwrap();
        let ev = audited("SSO_AUDITED_CLIENT_SECRET");
        assert_eq!(ev.len(), 1, "cache hits aren't audited: {ev:?}");
        assert_eq!((ev[0].action.as_str(), ev[0].outcome, ev[0].actor.id.as_deref()), ("secret.read", Outcome::Success, Some("secrets")));
        assert_eq!(ev[0].details, json!({ "store": "fake", "scope": "server", "op": "read", "found": true, "error": null }));
        assert!(!format!("{ev:?}").contains("smtp-audited-value"));
        f.down.store(true, Ordering::SeqCst);
        assert!(s.get("AUDIT_DOWN_TOKEN").is_err());
        let ev = audited("AUDIT_DOWN_TOKEN");
        assert_eq!((ev.len(), ev[0].outcome, ev[0].details["error"].as_str()), (1, Outcome::Failure, Some("unavailable")));
        redact::forget("smtp-audited-value");
    }

    #[test]
    fn cache_seconds_are_checked() {
        assert_eq!(cache_ttl("").unwrap(), Duration::from_secs(300));
        assert_eq!(cache_ttl("0").unwrap(), Duration::ZERO);
        assert_eq!(cache_ttl(" 86400 ").unwrap(), Duration::from_secs(86_400));
        for bad in ["86401", "-1", "5m", "x"] {
            assert!(cache_ttl(bad).is_err(), "{bad}");
        }
        let env = super::super::env::EnvStore::fixed(&[]);
        let var = |k: &str| if k == "SECRETS_BACKEND" { "local".to_string() } else { String::new() };
        assert!(from_env(&var, &env).unwrap().is_none(), "local is the default");
        let var = |k: &str| if k == "SECRETS_BACKEND" { "consul".to_string() } else { String::new() };
        assert!(from_env(&var, &env).err().unwrap().contains("local, vault, azure-keyvault, gcp-secret-manager or aws"));
    }

    #[test]
    fn each_backend_is_chosen_and_checked_at_startup() {
        let env = super::super::env::EnvStore::fixed(&[]);
        for (backend, err) in [("vault", "needs VAULT_ADDR"), ("azure-keyvault", "needs AZURE_KEYVAULT_URL"), ("gcp-secret-manager", "needs GCP_SECRET_MANAGER_PROJECT"), ("aws", "needs AWS_SECRETS_MANAGER_REGION")] {
            let var = super::super::http::tests::settings(&[("SECRETS_BACKEND", backend)]);
            assert!(from_env(&var, &env).err().unwrap().contains(err), "{backend}");
        }
        let var = super::super::http::tests::settings(&[("SECRETS_BACKEND", "azure-keyvault"), ("AZURE_KEYVAULT_URL", "https://kv1.vault.azure.net"), ("SECRETS_CACHE_SECONDS", "60")]);
        let x = from_env(&var, &env).unwrap().unwrap();
        assert_eq!((x.kind(), x.ttl), ("azure-keyvault", Duration::from_secs(60)));
        let var = super::super::http::tests::settings(&[("SECRETS_BACKEND", "gcp-secret-manager"), ("GCP_SECRET_MANAGER_PROJECT", "proj-1")]);
        assert_eq!(from_env(&var, &env).unwrap().unwrap().kind(), "gcp-secret-manager");
        let var = super::super::http::tests::settings(&[("SECRETS_BACKEND", "aws"), ("AWS_REGION", "eu-west-2"), ("SECRETS_CACHE_SECONDS", "0")]);
        let x = from_env(&var, &env).unwrap().unwrap();
        assert_eq!((x.kind(), x.ttl), ("aws", Duration::ZERO));
        let var = super::super::http::tests::settings(&[("VAULT_ADDR", "https://v"), ("GCP_SECRET_MANAGER_PROJECT", "p"), ("AZURE_KEYVAULT_URL", "https://kv"), ("AWS_SECRETS_MANAGER_REGION", "eu-west-2")]);
        assert_eq!(unused_settings(&var, "local"), ["VAULT_ADDR", "AZURE_KEYVAULT_URL", "GCP_SECRET_MANAGER_PROJECT", "AWS_SECRETS_MANAGER_REGION"]);
        assert_eq!(unused_settings(&var, "vault"), ["AZURE_KEYVAULT_URL", "GCP_SECRET_MANAGER_PROJECT", "AWS_SECRETS_MANAGER_REGION"]);
        assert_eq!(unused_settings(&var, "aws"), ["VAULT_ADDR", "AZURE_KEYVAULT_URL", "GCP_SECRET_MANAGER_PROJECT"]);
    }

    #[test]
    fn cloud_credentials_never_reach_bots() {
        for name in ["AZURE_CLIENT_SECRET", "AZURE_FEDERATED_TOKEN", "IDENTITY_HEADER", "GCP_SERVICE_ACCOUNT_KEY"] {
            assert!(super::super::check_name(name).is_err(), "{name} is reserved");
            assert_eq!(scope_of(name), None, "{name} is never read from an external store");
            let s = super::super::Secrets::new(vec![Box::new(super::super::env::EnvStore::fixed(&[(name, "cloud-credential-0123456789")]))]);
            assert!(s.harness_env().is_empty() && s.inherited_harness_env().is_empty() && s.list().unwrap().is_empty(), "{name}");
        }
        // Files too: `NAME_FILE` is offered to Bots as `NAME`, read from the file.
        let file = crate::db::temp_path("cloud-creds").join("token");
        std::fs::write(&file, "federated-assertion-0123456789\n").unwrap();
        for var in ["AZURE_FEDERATED_TOKEN_FILE", "AZURE_CLIENT_SECRET_FILE", "GCP_SERVICE_ACCOUNT_KEY_FILE"] {
            let s = super::super::Secrets::new(vec![Box::new(super::super::env::EnvStore::fixed(&[(var, file.to_str().unwrap())]))]);
            assert!(s.try_harness_env().unwrap().is_empty() && s.try_inherited_harness_env().unwrap().is_empty(), "{var}");
        }
        let host = crate::adapters::local_host();
        for k in ["AZURE_CLIENT_SECRET", "AZURE_CLIENT_SECRET_FILE", "AZURE_FEDERATED_TOKEN_FILE", "IDENTITY_HEADER", "GCP_SERVICE_ACCOUNT_KEY", "GCP_SERVICE_ACCOUNT_KEY_FILE"] {
            assert!(host.remove.iter().any(|r| r == k), "{k} removed from local jobs");
        }
    }

    #[test]
    fn diagnostics_say_whether_the_backend_answers_never_values() {
        assert_eq!(diagnose(None)["backend"], "local");
        let (f, s) = fake(&[(Scope::Bots, "DIAG_TOKEN", "diag-value-1")], Duration::ZERO);
        let (f2, cached) = fake(&[(Scope::Bots, "DIAG_TOKEN", "diag-value-1")], Duration::from_secs(3600));
        cached.names().unwrap();
        f2.down.store(true, Ordering::SeqCst);
        assert_eq!(diagnose(Some(&cached))["ok"], false, "an outage shows even while names are cached");
        let d = diagnose(Some(&s));
        assert_eq!((d["backend"].as_str(), d["ok"].as_bool(), d["names"].as_u64()), (Some("fake"), Some(true), Some(1)));
        f.down.store(true, Ordering::SeqCst);
        let d = diagnose(Some(&s));
        assert_eq!(d["ok"], false);
        assert!(d["detail"].as_str().unwrap().contains("fake is down"), "{d}");
        assert!(!d.to_string().contains("diag-value-1"));
    }
}
