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
//! - `refresh` reads every cached answer again at once, for an admin who rotated a value
//!   and can't wait out the cache, and says which names botd read at startup have
//!   changed since, which only a restart picks up (ADR 0291). A backend that announces
//!   changes (Vault's events, ADR 0306) has each one read again as it comes (`changed`).

use super::leases::{self, RunCredentials};
use super::{check_name, check_user_name, env_shaped, redact, server_secret, Error, Secret, SecretStore};
use crate::audit::{Actor, Event, Outcome};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Which folder of the backend a name lives in.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    pub(crate) fn holds(&self, name: &str) -> bool {
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
    /// Starts telling `store` of changes as the backend announces them (`ExternalStore::changed`),
    /// if it is set to; whether it does. An error when it is set to but can't (ADR 0306).
    fn watch(&self, _store: std::sync::Weak<ExternalStore>) -> Result<bool, Error> {
        Ok(false)
    }
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
    /// What botd's startup settings read through `Startup`, kept as they read it: those
    /// settings hold the value until a restart, whatever the cache does (ADR 0291).
    startup: Mutex<HashMap<(Scope, String), Option<Zeroizing<String>>>>,
    /// Held while a refresh runs, so two can't pile their reads onto the backend.
    refreshing: Mutex<()>,
    /// Bumped as each refresh starts. A read that began before it doesn't cache its
    /// answer, so a key read before a rotation can't land over the refresh's (ADR 0291).
    epoch: AtomicU64,
}

impl ExternalStore {
    pub fn new(provider: Box<dyn Provider>, ttl: Duration) -> ExternalStore {
        ExternalStore {
            provider,
            ttl,
            values: Mutex::default(),
            names: Mutex::default(),
            user_folders: false,
            run_credentials: None,
            startup: Mutex::default(),
            refreshing: Mutex::new(()),
            epoch: AtomicU64::new(0),
        }
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
        let started = self.epoch.load(std::sync::atomic::Ordering::SeqCst);
        match self.provider.list(scope.clone()) {
            Ok(names) => {
                let mut names: Vec<String> = names.into_iter().filter(|n| scope.holds(n)).collect();
                names.sort();
                names.dedup();
                let mut cached = self.names.lock().unwrap_or_else(|e| e.into_inner());
                self.prune(&mut cached);
                if self.epoch.load(std::sync::atomic::Ordering::SeqCst) == started {
                    cached.insert(scope.clone(), (Instant::now(), names.clone()));
                }
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
        let started = self.epoch.load(std::sync::atomic::Ordering::SeqCst);
        let got = self.provider.read(scope.clone(), name);
        self.took(scope, name, started, got)
    }

    /// What a read of `name` that began at `started` got: cached unless a refresh began
    /// since, redacted, and audited.
    fn took(&self, scope: &Scope, name: &str, started: u64, got: Result<Option<Zeroizing<String>>, Error>) -> Result<Option<Zeroizing<String>>, Error> {
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
                if self.epoch.load(std::sync::atomic::Ordering::SeqCst) == started {
                    cached.insert(key, (Instant::now(), v.clone()));
                }
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

    /// Keeps the first answer a startup setting got for `name`.
    fn note_startup(&self, name: &str, value: Option<&Secret>) {
        let Some(scope) = scope_of(name) else { return };
        let mut startup = self.startup.lock().unwrap_or_else(|e| e.into_inner());
        startup.entry((scope, name.to_string())).or_insert_with(|| value.map(|v| Zeroizing::new(v.expose().to_string())));
    }

    /// Reads again, now, every answer in the cache and every name botd's startup settings
    /// read, and lists each folder again (ADR 0291). With `only`, just those names, in
    /// every folder that has one cached, or in their own shared folder when none does.
    ///
    /// Each read goes through `fetch`, so it is audited, its value redacted from then on,
    /// and a backend that can't answer leaves nothing cached for that name: the next use
    /// fails closed as it would once the cache ran out. Values before and after are only
    /// compared here, in memory; the report says what changed, never a value or a digest.
    pub fn refresh(&self, only: Option<&[String]>) -> Result<Refresh, RefreshError> {
        let wanted = match only {
            Some(names) => Some(refresh_names(names)?),
            None => None,
        };
        let _one = self.refreshing.try_lock().map_err(|_| RefreshError::Busy)?;
        // Before anything is read, so reads still in flight from before can't cache over ours.
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let take = |name: &str| wanted.as_ref().is_none_or(|w| w.contains(name));
        let (mut keys, old, startup) = {
            let values = self.values.lock().unwrap_or_else(|e| e.into_inner());
            let startup = self.startup.lock().unwrap_or_else(|e| e.into_inner());
            let keys: BTreeSet<(Scope, String)> = values.keys().chain(startup.keys()).filter(|(_, n)| take(n)).cloned().collect();
            let old: HashMap<_, _> = keys.iter().filter_map(|k| values.get(k).map(|(_, v)| (k.clone(), v.clone()))).collect();
            let startup: HashMap<_, _> = keys.iter().filter_map(|k| startup.get(k).map(|v| (k.clone(), v.clone()))).collect();
            (keys, old, startup)
        };
        for name in wanted.iter().flatten() {
            if !keys.iter().any(|(_, n)| n == name) {
                keys.insert((scope_of(name).expect("checked by refresh_names"), name.clone()));
            }
        }
        let folders: BTreeSet<Scope> = {
            let names = self.names.lock().unwrap_or_else(|e| e.into_inner());
            Scope::ALL.iter().cloned().chain(names.keys().cloned()).collect()
        };
        let listed_before: HashMap<Scope, Vec<String>> = self.names.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(s, (_, n))| (s.clone(), n.clone())).collect();

        let jobs: Vec<Job> = keys.into_iter().map(Job::Read).chain(folders.into_iter().map(Job::List)).collect();
        let done = parallel(&jobs, |job| match job {
            Job::Read((scope, name)) => Done::Read(self.fetch(scope, name)),
            Job::List(scope) => Done::List(self.list_from_backend(scope)),
        });

        let mut entries = Vec::new();
        let mut folders = Vec::new();
        for (job, done) in jobs.into_iter().zip(done) {
            match (job, done) {
                (Job::Read(key), Done::Read(now)) => {
                    let (old, at_startup) = (old.get(&key), startup.get(&key));
                    let (scope, name) = key;
                    entries.push(Refreshed::compared(name, &scope, old, at_startup, &now));
                }
                (Job::List(scope), Done::List(now)) => {
                    let before = listed_before.get(&scope);
                    let (added, removed) = match (before, &now) {
                        (Some(b), Ok(n)) => (n.iter().filter(|x| !b.contains(x)).cloned().collect(), b.iter().filter(|x| !n.contains(x)).cloned().collect()),
                        _ => (Vec::new(), Vec::new()),
                    };
                    folders.push(FolderRefreshed { folder: scope.folder('/'), names: now.as_ref().ok().map(Vec::len), ok: now.is_ok(), added, removed });
                }
                _ => unreachable!("each job is done in its own kind"),
            }
        }
        Ok(Refresh { store: self.provider.kind(), names: wanted.map(|w| w.into_iter().collect()), entries, folders })
    }

    /// Has the backend tell this store of changes as they happen, if it is set to
    /// (`VAULT_EVENTS`, ADR 0306): whether it does. An error stops botd at startup.
    pub fn watch(self: &Arc<Self>) -> Result<bool, Error> {
        self.provider.watch(Arc::downgrade(self))
    }

    /// The backend announced a change to `name` in `scope`, and read it again as `got`
    /// (ADR 0306). The answer replaces what was cached as a read would (audited, redacted,
    /// fail closed when `got` is an error), and the folder's list is dropped so a name that
    /// came or went shows at its next use. A read already in flight can't cache over it.
    /// None when the store doesn't read that name there (another folder's, user folders off).
    pub fn changed(&self, scope: &Scope, name: &str, got: Result<Option<Zeroizing<String>>, Error>) -> Option<Refreshed> {
        if !scope.holds(name) || (scope.user_id().is_some() && !self.user_folders) {
            return None;
        }
        let key = (scope.clone(), name.to_string());
        let started = self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let old = self.values.lock().unwrap_or_else(|e| e.into_inner()).get(&key).map(|(_, v)| v.clone());
        let at_startup = self.startup.lock().unwrap_or_else(|e| e.into_inner()).get(&key).cloned();
        let now = self.took(scope, name, started, got);
        self.names.lock().unwrap_or_else(|e| e.into_inner()).remove(scope);
        Some(Refreshed::compared(name.to_string(), scope, old.as_ref(), at_startup.as_ref(), &now))
    }
}

/// Most names one refresh may ask for.
pub const MAX_REFRESH_NAMES: usize = 100;
/// Reads a refresh runs at once; the clients run up to `http::MAX_REQUESTS` anyway.
const REFRESH_READERS: usize = 8;

/// The names a refresh was asked for, checked: each one an external store may answer.
fn refresh_names(names: &[String]) -> Result<BTreeSet<String>, RefreshError> {
    if names.is_empty() {
        return Err(RefreshError::Invalid("Name at least one secret, or none to refresh them all.".into()));
    }
    if names.len() > MAX_REFRESH_NAMES {
        return Err(RefreshError::Invalid(format!("Refresh at most {MAX_REFRESH_NAMES} names at once, or none to refresh them all.")));
    }
    let mut out = BTreeSet::new();
    for n in names {
        let n = n.trim();
        if scope_of(n).is_none() {
            let shown: String = n.chars().take(128).collect();
            return Err(RefreshError::Invalid(format!("{shown:?} isn't a name an external store answers for botd: use A-Z, 0-9 and _, and not a reserved name.")));
        }
        out.insert(n.to_string());
    }
    Ok(out)
}

enum Job {
    Read((Scope, String)),
    List(Scope),
}

enum Done {
    Read(Result<Option<Zeroizing<String>>, Error>),
    List(Result<Vec<String>, Error>),
}

/// `f` over `jobs` on up to `REFRESH_READERS` threads, answers in the jobs' order. Plain
/// threads, not botd's runtime: each read blocks until the backend answers or times out.
fn parallel<J: Sync, D: Send>(jobs: &[J], f: impl Fn(&J) -> D + Sync) -> Vec<D> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let out: Mutex<Vec<Option<D>>> = Mutex::new((0..jobs.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..REFRESH_READERS.min(jobs.len()) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(job) = jobs.get(i) else { break };
                    let d = f(job);
                    out.lock().unwrap_or_else(|e| e.into_inner())[i] = Some(d);
                }
            });
        }
    });
    out.into_inner().unwrap_or_else(|e| e.into_inner()).into_iter().map(|d| d.expect("every job is done")).collect()
}

/// Why a refresh didn't run.
#[derive(Debug, PartialEq)]
pub enum RefreshError {
    /// Another is running.
    Busy,
    /// A name it can't refresh, or too many.
    Invalid(String),
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RefreshError::Busy => f.write_str("A refresh is already running; try again when it ends."),
            RefreshError::Invalid(m) => f.write_str(m),
        }
    }
}

/// What a refresh found for one name, against the answer cached before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// Another value than the one cached.
    Changed,
    Unchanged,
    /// A value where the cache had "not there".
    Added,
    /// "Not there" where the cache had a value.
    Removed,
    /// A value, with nothing cached before to compare.
    Found,
    NotFound,
    /// The backend couldn't answer; nothing is cached for it now (fail closed).
    Unavailable,
}

/// One name a refresh read again. Never its value.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Refreshed {
    pub name: String,
    pub scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub result: Change,
    /// botd's startup settings read it.
    pub startup: bool,
    /// They read another answer than the backend's now, and hold it until botd restarts.
    pub restart: bool,
}

impl Refreshed {
    /// `name` read again as `now`, against what was cached before (`old`) and what botd's
    /// startup settings read (`at_startup`), when they did.
    fn compared(name: String, scope: &Scope, old: Option<&Option<Zeroizing<String>>>, at_startup: Option<&Option<Zeroizing<String>>>, now: &Result<Option<Zeroizing<String>>, Error>) -> Refreshed {
        let result = match (old, now) {
            (_, Err(_)) => Change::Unavailable,
            (Some(Some(a)), Ok(Some(b))) if a.as_str() == b.as_str() => Change::Unchanged,
            (Some(Some(_)), Ok(Some(_))) => Change::Changed,
            (Some(None), Ok(Some(_))) => Change::Added,
            (Some(Some(_)), Ok(None)) => Change::Removed,
            (None, Ok(Some(_))) => Change::Found,
            (Some(None) | None, Ok(None)) => Change::NotFound,
        };
        let restart = match (at_startup, now) {
            (Some(then), Ok(now)) => then.as_ref().map(|v| v.as_str()) != now.as_ref().map(|v| v.as_str()),
            _ => false,
        };
        Refreshed { name, scope: scope.as_str(), user_id: scope.user_id().map(str::to_string), result, startup: at_startup.is_some(), restart }
    }
}

/// One folder a refresh listed again: how many names it has, and which came or went
/// since the list cached before.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderRefreshed {
    pub folder: String,
    pub ok: bool,
    pub names: Option<usize>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// What `ExternalStore::refresh` did.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Refresh {
    pub store: &'static str,
    /// The names asked for; None for everything.
    pub names: Option<Vec<String>>,
    pub entries: Vec<Refreshed>,
    pub folders: Vec<FolderRefreshed>,
}

/// Most entries an audit event lists by name; the counts cover the rest.
const MAX_AUDITED: usize = 100;

impl Refresh {
    /// Every read and list answered.
    pub fn ok(&self) -> bool {
        self.entries.iter().all(|e| e.result != Change::Unavailable) && self.folders.iter().all(|f| f.ok)
    }

    pub fn count(&self, c: Change) -> usize {
        self.entries.iter().filter(|e| e.result == c).count()
    }

    /// Names botd read at startup whose value is no longer the backend's.
    pub fn restart(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self.entries.iter().filter(|e| e.restart).map(|e| e.name.as_str()).collect();
        out.dedup();
        out
    }

    fn counts(&self) -> serde_json::Value {
        let mut c = serde_json::Map::new();
        for k in [Change::Changed, Change::Unchanged, Change::Added, Change::Removed, Change::Found, Change::NotFound, Change::Unavailable] {
            c.insert(serde_json::to_value(k).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(), json!(self.count(k)));
        }
        serde_json::Value::Object(c)
    }

    /// The API's answer: the report, with counts, whether it all answered, and a line to show.
    pub fn view(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        v["ok"] = json!(self.ok());
        v["counts"] = self.counts();
        v["restart"] = json!(self.restart());
        v["detail"] = json!(self.detail());
        v
    }

    pub fn detail(&self) -> String {
        let moved = self.count(Change::Changed) + self.count(Change::Added) + self.count(Change::Removed);
        let n = self.entries.len();
        let mut out = format!("{} read again: {n} name{}, {moved} changed.", self.store, if n == 1 { "" } else { "s" });
        let down = self.count(Change::Unavailable) + self.folders.iter().filter(|f| !f.ok).count();
        if down > 0 {
            out += &format!(" {down} couldn't be read; nothing is cached for them, so runs that need them are refused until the backend answers (fail closed).");
        }
        let restart = self.restart();
        if !restart.is_empty() {
            out += &format!(" botd read {} at startup and still holds the old value: restart botd for it to take the new one.", restart.join(", "));
        }
        out
    }

    /// For `secret.cache_refreshed`: counts, and the names whose answer moved or failed,
    /// never values or digests of them.
    pub fn audit_details(&self) -> serde_json::Value {
        let moved: Vec<&Refreshed> = self.entries.iter().filter(|e| !matches!(e.result, Change::Unchanged | Change::NotFound | Change::Found) || e.restart).collect();
        let listed: Vec<serde_json::Value> = moved
            .iter()
            .take(MAX_AUDITED)
            .map(|e| {
                let mut d = json!({ "name": e.name, "scope": e.scope, "result": e.result, "restart": e.restart });
                if let Some(id) = &e.user_id {
                    d["userId"] = json!(id);
                }
                d
            })
            .collect();
        json!({
            "store": self.store,
            "names": self.names,
            "counts": self.counts(),
            "entries": listed,
            "entriesOmitted": moved.len().saturating_sub(MAX_AUDITED),
            "restart": self.restart(),
            "folders": { "listed": self.folders.iter().filter(|f| f.ok).count(), "unavailable": self.folders.iter().filter(|f| !f.ok).count() },
        })
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

/// The `ExternalStore` as botd's startup settings read it: each answer is kept, so a
/// refresh can say which of them a rotation left behind (ADR 0291).
pub struct Startup(pub Arc<ExternalStore>);

impl SecretStore for Startup {
    fn kind(&self) -> &'static str {
        self.0.kind()
    }
    fn get(&self, name: &str) -> Result<Option<Secret>, Error> {
        let v = self.0.get(name)?;
        self.0.note_startup(name, v.as_ref());
        Ok(v)
    }
    fn names(&self) -> Result<Vec<String>, Error> {
        self.0.names()
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
        "azure-keyvault" => {
            let cfg = super::azure::Config::from_env(var, store)?;
            let wanted = leases::parse_as(&leases::AZURE, &var("AZURE_RUN_CREDENTIALS"))?;
            if !wanted.is_empty() {
                cfg.run_credentials_ok()?;
            }
            let kv = super::azure::KeyVault::new(cfg)?;
            if !wanted.is_empty() {
                run_credentials = Some(RunCredentials::new(Arc::new(kv.clone()), wanted));
            }
            Box::new(kv)
        }
        "gcp-secret-manager" => {
            let sm = super::gcp::SecretManager::new(super::gcp::Config::from_env(var, store)?)?;
            let wanted = leases::parse_as(&leases::GCP, &var("GCP_RUN_CREDENTIALS"))?;
            if !wanted.is_empty() {
                run_credentials = Some(RunCredentials::new(Arc::new(sm.clone()), wanted));
            }
            Box::new(sm)
        }
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
    const KEYS: [(&str, &str); 13] = [
        ("vault", "VAULT_ADDR"),
        ("vault", "VAULT_RUN_CREDENTIALS"),
        ("vault", "VAULT_EVENTS"),
        ("azure-keyvault", "AZURE_KEYVAULT_URL"),
        ("azure-keyvault", "AZURE_KEYVAULT_AUTH"),
        ("azure-keyvault", "AZURE_RUN_CREDENTIALS"),
        ("gcp-secret-manager", "GCP_SECRET_MANAGER_PROJECT"),
        ("gcp-secret-manager", "GCP_SECRET_MANAGER_AUTH"),
        ("gcp-secret-manager", "GCP_SECRET_MANAGER_LOCATION"),
        ("gcp-secret-manager", "GCP_RUN_CREDENTIALS"),
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

/// What `active` answers in tests that need a store: `ACTIVE` is set once per process,
/// and other tests expect it unset.
#[cfg(test)]
pub(crate) static TEST_ACTIVE: Mutex<Option<Arc<ExternalStore>>> = Mutex::new(None);

/// The external store botd runs with, if any.
pub fn active() -> Option<Arc<ExternalStore>> {
    #[cfg(test)]
    if let Some(x) = TEST_ACTIVE.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return Some(x);
    }
    ACTIVE.get().cloned()
}

/// The secrets backend and whether it answers, for the setup report and `botctl secrets
/// backend`: names, counts and errors, never a value.
pub fn diagnostics() -> serde_json::Value {
    diagnose(ACTIVE.get().map(Arc::as_ref))
}

/// The backend botd started with, as the evidence bundle keeps it (ADR 0285): its kind
/// and settings, never a path or an address, and without asking it anything.
pub fn configured() -> serde_json::Value {
    configured_view(ACTIVE.get().map(Arc::as_ref))
}

fn configured_view(x: Option<&ExternalStore>) -> serde_json::Value {
    match x {
        None => json!({ "backend": "local", "external": false }),
        Some(x) => json!({
            "backend": x.kind(),
            "external": true,
            "cacheSeconds": x.ttl.as_secs(),
            "userFolders": x.user_folders,
            "runCredentialPaths": x.run_credentials.as_ref().map_or(0, |rc| rc.paths().len()),
        }),
    }
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
        /// The next read or list takes its answer, says so on the first, and waits for the second.
        pub pause: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    }

    impl Fake {
        fn hold(&self) {
            let paused = self.pause.lock().unwrap().take();
            if let Some((started, release)) = paused {
                started.send(()).unwrap();
                release.recv().unwrap();
            }
        }

        /// Pauses the next read or list: returns (it has its answer, let it finish).
        pub(crate) fn pause_next(&self) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            *self.pause.lock().unwrap() = Some((started_tx, release_rx));
            (started_rx, release_tx)
        }
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
            let v = self.values.lock().unwrap().get(&(scope, name.to_string())).filter(|v| !v.is_empty()).map(|v| Zeroizing::new(v.clone()));
            self.hold();
            Ok(v)
        }
        fn list(&self, scope: Scope) -> Result<Vec<String>, Error> {
            self.lists.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(Error::Unavailable("fake is down".into()));
            }
            let names = self.values.lock().unwrap().keys().filter(|(s, _)| *s == scope).map(|(_, n)| n.clone()).collect();
            self.hold();
            Ok(names)
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
        for name in ["AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PASSWORD", "AZURE_FEDERATED_TOKEN", "IDENTITY_HEADER", "GCP_SERVICE_ACCOUNT_KEY"] {
            assert!(super::super::check_name(name).is_err(), "{name} is reserved");
            assert_eq!(scope_of(name), None, "{name} is never read from an external store");
            let s = super::super::Secrets::new(vec![Box::new(super::super::env::EnvStore::fixed(&[(name, "cloud-credential-0123456789")]))]);
            assert!(s.harness_env().is_empty() && s.inherited_harness_env().is_empty() && s.list().unwrap().is_empty(), "{name}");
        }
        // Files too: `NAME_FILE` is offered to Bots as `NAME`, read from the file.
        let file = crate::db::temp_path("cloud-creds").join("token");
        std::fs::write(&file, "federated-assertion-0123456789\n").unwrap();
        for var in ["AZURE_FEDERATED_TOKEN_FILE", "AZURE_CLIENT_SECRET_FILE", "AZURE_CLIENT_CERTIFICATE_PASSWORD_FILE", "GCP_SERVICE_ACCOUNT_KEY_FILE"] {
            let s = super::super::Secrets::new(vec![Box::new(super::super::env::EnvStore::fixed(&[(var, file.to_str().unwrap())]))]);
            assert!(s.try_harness_env().unwrap().is_empty() && s.try_inherited_harness_env().unwrap().is_empty(), "{var}");
        }
        let host = crate::adapters::local_host();
        for k in ["AZURE_CLIENT_SECRET", "AZURE_CLIENT_SECRET_FILE", "AZURE_FEDERATED_TOKEN_FILE", "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_CLIENT_CERTIFICATE_PASSWORD", "AZURE_CLIENT_CERTIFICATE_PASSWORD_FILE", "IDENTITY_HEADER", "GCP_SERVICE_ACCOUNT_KEY", "GCP_SERVICE_ACCOUNT_KEY_FILE"] {
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

    fn entry<'a>(r: &'a Refresh, scope: &str, name: &str) -> &'a Refreshed {
        r.entries.iter().find(|e| e.scope == scope && e.name == name).unwrap_or_else(|| panic!("{scope}/{name} in {r:?}"))
    }

    #[test]
    fn a_refresh_reads_every_cached_answer_again_and_says_what_moved() {
        let (f, x) = fake(
            &[(Scope::Bots, "RF_ROTATED_TOKEN", "rf-old-value-1"), (Scope::Bots, "RF_SAME_TOKEN", "rf-same-value-1"), (Scope::Bots, "RF_GONE_TOKEN", "rf-gone-value-1"), (Scope::Server, "SSO_RF_CLIENT_SECRET", "rf-sso-value-1")],
            Duration::from_secs(3600),
        );
        let x = Arc::new(users_on(x));
        f.values.lock().unwrap().insert((user("urf"), "RF_USER_TOKEN".into()), "rf-user-old-1".into());
        for n in ["RF_ROTATED_TOKEN", "RF_SAME_TOKEN", "RF_GONE_TOKEN", "RF_LATER_TOKEN", "SSO_RF_CLIENT_SECRET"] {
            x.get(n).unwrap();
        }
        x.names().unwrap();
        x.user_get("urf", "RF_USER_TOKEN").unwrap();
        x.user_names("urf").unwrap();

        {
            let mut v = f.values.lock().unwrap();
            v.insert((Scope::Bots, "RF_ROTATED_TOKEN".into()), "rf-new-value-1".into());
            v.remove(&(Scope::Bots, "RF_GONE_TOKEN".into()));
            v.insert((Scope::Bots, "RF_LATER_TOKEN".into()), "rf-later-value-1".into());
            v.insert((user("urf"), "RF_USER_TOKEN".into()), "rf-user-new-1".into());
        }
        assert_eq!(x.get("RF_ROTATED_TOKEN").unwrap().unwrap().expose(), "rf-old-value-1", "cached until a refresh");
        let reads = f.reads.load(Ordering::SeqCst);
        let r = x.refresh(None).unwrap();
        assert_eq!(f.reads.load(Ordering::SeqCst) - reads, 6, "each cached answer once: {r:?}");
        assert_eq!(entry(&r, "bots", "RF_ROTATED_TOKEN").result, Change::Changed);
        assert_eq!(entry(&r, "bots", "RF_SAME_TOKEN").result, Change::Unchanged);
        assert_eq!(entry(&r, "bots", "RF_GONE_TOKEN").result, Change::Removed);
        assert_eq!(entry(&r, "bots", "RF_LATER_TOKEN").result, Change::Added);
        assert_eq!(entry(&r, "server", "SSO_RF_CLIENT_SECRET").result, Change::Unchanged);
        let u = entry(&r, "users", "RF_USER_TOKEN");
        assert_eq!((u.result, u.user_id.as_deref(), u.startup, u.restart), (Change::Changed, Some("urf"), false, false));
        assert!(r.ok() && r.restart().is_empty());
        let bots = r.folders.iter().find(|f| f.folder == "bots").unwrap();
        assert_eq!((bots.ok, bots.names, bots.added.clone(), bots.removed.clone()), (true, Some(3), vec!["RF_LATER_TOKEN".to_string()], vec!["RF_GONE_TOKEN".to_string()]));
        assert!(r.folders.iter().any(|f| f.folder == "users/urf" && f.ok), "cached users' folders are listed again too");

        let reads = f.reads.load(Ordering::SeqCst);
        assert_eq!(x.get("RF_ROTATED_TOKEN").unwrap().unwrap().expose(), "rf-new-value-1", "the new value, from the cache");
        assert!(x.get("RF_GONE_TOKEN").unwrap().is_none());
        assert_eq!(x.user_get("urf", "RF_USER_TOKEN").unwrap().unwrap().expose(), "rf-user-new-1");
        assert_eq!(f.reads.load(Ordering::SeqCst), reads, "no read past the refresh's");
        assert!(x.names().unwrap().contains(&"RF_LATER_TOKEN".to_string()), "a new name reaches Bots at once");
        assert_eq!(redact::text("rf-new-value-1"), redact::MARK, "the new value is redacted");
        assert_eq!(redact::text("rf-old-value-1"), redact::MARK, "and the old one still is, wherever it turns up");

        let v = r.view();
        assert_eq!((v["ok"].as_bool(), v["counts"]["changed"].as_u64(), v["counts"]["removed"].as_u64(), v["counts"]["added"].as_u64()), (Some(true), Some(2), Some(1), Some(1)));
        assert!(v["detail"].as_str().unwrap().starts_with("fake read again: 6 names, 4 changed."), "{v}");
        let a = r.audit_details();
        assert_eq!(a["entries"].as_array().unwrap().len(), 4, "only what moved: {a}");
        assert_eq!(a["names"], serde_json::Value::Null);
        let text = format!("{v}{a}");
        for value in ["rf-old-value-1", "rf-new-value-1", "rf-same-value-1", "rf-user-new-1", "rf-later-value-1"] {
            assert!(!text.contains(value), "{value} in {text}");
        }
        for v in ["rf-old-value-1", "rf-new-value-1", "rf-same-value-1", "rf-gone-value-1", "rf-later-value-1", "rf-sso-value-1"] {
            redact::forget(v);
        }
        redact::forget_for("urf", "rf-user-old-1");
        redact::forget_for("urf", "rf-user-new-1");
    }

    #[test]
    fn a_refresh_of_named_secrets_reads_only_those() {
        let (f, x) = fake(&[(Scope::Bots, "RN_ONE_TOKEN", "rn-one-1"), (Scope::Bots, "RN_TWO_TOKEN", "rn-two-1"), (Scope::Server, "LINODE_TOKEN", "rn-linode-1")], Duration::from_secs(3600));
        x.get("RN_ONE_TOKEN").unwrap();
        x.get("RN_TWO_TOKEN").unwrap();
        f.values.lock().unwrap().insert((Scope::Bots, "RN_TWO_TOKEN".into()), "rn-two-2".into());
        let reads = f.reads.load(Ordering::SeqCst);
        let names = ["RN_ONE_TOKEN", "LINODE_TOKEN", "RN_NEVER_TOKEN", " RN_ONE_TOKEN "].map(String::from);
        let r = x.refresh(Some(&names)).unwrap();
        assert_eq!(f.reads.load(Ordering::SeqCst) - reads, 3, "each named once, nothing else: {r:?}");
        assert_eq!(r.names.as_deref(), Some(&["LINODE_TOKEN".to_string(), "RN_NEVER_TOKEN".into(), "RN_ONE_TOKEN".into()][..]));
        assert_eq!(entry(&r, "bots", "RN_ONE_TOKEN").result, Change::Unchanged);
        assert_eq!(entry(&r, "server", "LINODE_TOKEN").result, Change::Found, "not cached: read in its own folder");
        assert_eq!(entry(&r, "bots", "RN_NEVER_TOKEN").result, Change::NotFound);
        assert!(r.entries.iter().all(|e| e.name != "RN_TWO_TOKEN"));
        assert_eq!(x.get("RN_TWO_TOKEN").unwrap().unwrap().expose(), "rn-two-1", "not named: still the cached answer");
        assert_eq!(r.audit_details()["names"], json!(["LINODE_TOKEN", "RN_NEVER_TOKEN", "RN_ONE_TOKEN"]));

        for bad in [vec![], vec!["PATH".to_string()], vec!["lower_case".into()], vec!["AUTH_PASSWORD".into()], vec!["VAULT_TOKEN".into()], (0..=MAX_REFRESH_NAMES).map(|i| format!("RN_{i}_TOKEN")).collect()] {
            assert!(matches!(x.refresh(Some(&bad)), Err(RefreshError::Invalid(_))), "{bad:?}");
        }
        let long = format!("{}x", "A".repeat(500));
        let RefreshError::Invalid(m) = x.refresh(Some(&[long])).unwrap_err() else { panic!() };
        assert!(m.len() < 300, "a long name isn't echoed whole: {m}");
        let reads = f.reads.load(Ordering::SeqCst);
        let _held = x.refreshing.lock().unwrap();
        assert_eq!(x.refresh(None).unwrap_err(), RefreshError::Busy);
        assert_eq!(f.reads.load(Ordering::SeqCst), reads, "a refresh that can't run asks nothing");
        for v in ["rn-one-1", "rn-two-1", "rn-linode-1"] {
            redact::forget(v);
        }
    }

    #[test]
    fn a_read_from_before_a_refresh_never_caches_over_it() {
        let (f, x) = fake(&[(Scope::Bots, "RO_TOKEN", "ro-old-1")], Duration::from_secs(3600));
        let (started, release) = f.pause_next();
        let slow = {
            let x = Arc::clone(&x);
            std::thread::spawn(move || x.get("RO_TOKEN").unwrap().unwrap().expose().to_string())
        };
        started.recv().unwrap();
        f.values.lock().unwrap().insert((Scope::Bots, "RO_TOKEN".into()), "ro-new-1".into());
        let r = x.refresh(Some(&["RO_TOKEN".to_string()])).unwrap();
        assert_eq!(entry(&r, "bots", "RO_TOKEN").result, Change::Found);
        release.send(()).unwrap();
        assert_eq!(slow.join().unwrap(), "ro-old-1", "the read in flight gets what it read");
        let reads = f.reads.load(Ordering::SeqCst);
        assert_eq!(x.get("RO_TOKEN").unwrap().unwrap().expose(), "ro-new-1", "but it didn't cache it over the refresh's");
        assert_eq!(f.reads.load(Ordering::SeqCst), reads, "the refresh's answer is the cached one");

        // Folder lists the same way: a list from before the refresh can't hide a new name.
        let (f, x) = fake(&[(Scope::Bots, "RO_TOKEN", "ro-new-1")], Duration::from_secs(3600));
        let (started, release) = f.pause_next();
        let slow = {
            let x = Arc::clone(&x);
            std::thread::spawn(move || x.names().unwrap())
        };
        started.recv().unwrap();
        f.values.lock().unwrap().insert((Scope::Bots, "RO_NEW_TOKEN".into()), "ro-added-1".into());
        x.refresh(None).unwrap();
        release.send(()).unwrap();
        assert!(!slow.join().unwrap().contains(&"RO_NEW_TOKEN".to_string()));
        let lists = f.lists.load(Ordering::SeqCst);
        assert!(x.names().unwrap().contains(&"RO_NEW_TOKEN".to_string()), "the refresh's list is the cached one");
        assert_eq!(f.lists.load(Ordering::SeqCst), lists);
        for v in ["ro-old-1", "ro-new-1", "ro-added-1"] {
            redact::forget(v);
        }
    }

    #[test]
    fn a_refresh_while_the_backend_is_down_fails_closed() {
        let (f, x) = fake(&[(Scope::Bots, "RD_TOKEN", "rd-value-1")], Duration::from_secs(3600));
        assert!(x.get("RD_TOKEN").unwrap().is_some());
        x.names().unwrap();
        f.down.store(true, Ordering::SeqCst);
        assert!(x.get("RD_TOKEN").unwrap().is_some(), "within the cache time the answer stands");
        let r = x.refresh(None).unwrap();
        assert_eq!(entry(&r, "bots", "RD_TOKEN").result, Change::Unavailable);
        assert!(!r.ok() && r.folders.iter().all(|f| !f.ok));
        assert!(r.detail().contains("fail closed"), "{}", r.detail());
        assert!(matches!(x.get("RD_TOKEN"), Err(Error::Unavailable(_))), "nothing cached any more: never the old value");
        assert!(matches!(x.names(), Err(Error::Unavailable(_))));
        let ev: Vec<_> = audited("RD_TOKEN").into_iter().filter(|e| e.outcome == Outcome::Failure).collect();
        assert!(!ev.is_empty(), "the failed read is audited like any other");
        f.down.store(false, Ordering::SeqCst);
        let r = x.refresh(None).unwrap();
        assert!(r.ok());
        assert_eq!(x.get("RD_TOKEN").unwrap().unwrap().expose(), "rd-value-1");
        redact::forget("rd-value-1");
    }

    #[test]
    fn a_refresh_names_what_startup_settings_still_hold() {
        let (f, x) = fake(&[(Scope::Server, "INCUS_CLIENT_KEY", "rs-incus-1"), (Scope::Server, "METRICS_TOKEN", "rs-metrics-1"), (Scope::Bots, "RS_BOT_TOKEN", "rs-bot-1")], Duration::ZERO);
        let at_start = Startup(Arc::clone(&x));
        assert_eq!(at_start.get("INCUS_CLIENT_KEY").unwrap().unwrap().expose(), "rs-incus-1");
        at_start.get("METRICS_TOKEN").unwrap();
        assert!(at_start.get("SMTP_PASSWORD").unwrap().is_none());
        assert!(at_start.get("PATH").unwrap().is_none(), "never kept: no external store answers it");
        x.get("RS_BOT_TOKEN").unwrap();
        {
            let mut v = f.values.lock().unwrap();
            v.insert((Scope::Server, "INCUS_CLIENT_KEY".into()), "rs-incus-2".into());
            v.insert((Scope::Server, "SMTP_PASSWORD".into()), "rs-smtp-1".into());
            v.insert((Scope::Bots, "RS_BOT_TOKEN".into()), "rs-bot-2".into());
        }
        // A cache of 0 s keeps nothing, so only startup's own copy can tell what changed.
        let r = x.refresh(None).unwrap();
        let incus = entry(&r, "server", "INCUS_CLIENT_KEY");
        assert_eq!((incus.result, incus.startup, incus.restart), (Change::Found, true, true));
        let metrics = entry(&r, "server", "METRICS_TOKEN");
        assert_eq!((metrics.startup, metrics.restart), (true, false));
        let smtp = entry(&r, "server", "SMTP_PASSWORD");
        assert_eq!((smtp.result, smtp.restart), (Change::Found, true), "a name startup found missing, now set, needs a restart too");
        assert!(r.entries.iter().all(|e| e.name != "PATH"));
        assert_eq!(r.restart(), ["INCUS_CLIENT_KEY", "SMTP_PASSWORD"]);
        assert!(r.ok(), "a restart isn't a failed read");
        assert!(r.detail().contains("INCUS_CLIENT_KEY, SMTP_PASSWORD at startup") && r.detail().contains("restart botd"), "{}", r.detail());
        let a = r.audit_details();
        assert_eq!(a["restart"], json!(["INCUS_CLIENT_KEY", "SMTP_PASSWORD"]));
        assert!(a["entries"].as_array().unwrap().iter().any(|e| e["name"] == "INCUS_CLIENT_KEY" && e["restart"] == true), "{a}");
        assert!(!format!("{a}{}", r.view()).contains("rs-"), "no values");

        let r = x.refresh(Some(&["RS_BOT_TOKEN".to_string()])).unwrap();
        assert!(r.restart().is_empty(), "only what was asked for");
        assert_eq!(r.entries.len(), 1);
        for v in ["rs-incus-1", "rs-incus-2", "rs-metrics-1", "rs-smtp-1", "rs-bot-1", "rs-bot-2"] {
            redact::forget(v);
        }
    }

    #[test]
    fn the_evidence_bundle_sees_the_backend_without_asking_it() {
        assert_eq!(configured_view(None), json!({ "backend": "local", "external": false }));
        let f = Arc::new(Fake::default());
        f.down.store(true, Ordering::SeqCst);
        let s = ExternalStore::new(Box::new(Arc::clone(&f)), Duration::from_secs(60)).with_user_folders(true);
        let v = configured_view(Some(&s));
        assert_eq!(v, json!({ "backend": "fake", "external": true, "cacheSeconds": 60, "userFolders": true, "runCredentialPaths": 0 }));
        assert_eq!((f.reads.load(Ordering::SeqCst), f.lists.load(Ordering::SeqCst)), (0, 0), "a down backend isn't asked");
    }
}
