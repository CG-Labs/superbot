//! Secrets kept in an external secrets manager (ADR 0125): HashiCorp Vault today
//! (`vault`), Azure Key Vault or AWS Secrets Manager later. Each is a `Provider`; the
//! `ExternalStore` around it is the `SecretStore` botd asks, and does the rest the same
//! way for all of them:
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

use super::{check_name, env_shaped, redact, server_secret, Error, Secret, SecretStore};
use crate::audit::{Actor, Event, Outcome};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Which folder of the backend a name lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Server-wide secrets that reach Bots.
    Bots,
    /// botd's own; no Bot gets them.
    Server,
}

impl Scope {
    pub const ALL: [Scope; 2] = [Scope::Bots, Scope::Server];

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Bots => "bots",
            Scope::Server => "server",
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

/// Each name's answer (a value, or "not there") and when it was read.
type Answers = HashMap<String, (Instant, Option<Zeroizing<String>>)>;

/// A `Provider` with a cache, fail-closed reads and audited reads; see the module docs.
pub struct ExternalStore {
    provider: Box<dyn Provider>,
    ttl: Duration,
    values: Mutex<Answers>,
    names: Mutex<HashMap<Scope, (Instant, Vec<String>)>>,
}

impl ExternalStore {
    pub fn new(provider: Box<dyn Provider>, ttl: Duration) -> ExternalStore {
        ExternalStore { provider, ttl, values: Mutex::default(), names: Mutex::default() }
    }

    pub fn describe(&self) -> String {
        format!("{}, cached for {} s", self.provider.describe(), self.ttl.as_secs())
    }

    fn fresh(&self, at: Instant) -> bool {
        at.elapsed() < self.ttl
    }

    /// Startup check: lists both folders straight from the backend, so botd refuses to
    /// start on a backend it can't reach or sign in to. Returns how many names it has.
    pub fn check(&self) -> Result<usize, Error> {
        let mut n = 0;
        for scope in Scope::ALL {
            let names = self.list_from_backend(scope)?;
            n += names.len();
        }
        Ok(n)
    }

    fn list_from_backend(&self, scope: Scope) -> Result<Vec<String>, Error> {
        match self.provider.list(scope) {
            Ok(names) => {
                let mut names: Vec<String> = names.into_iter().filter(|n| scope_of(n) == Some(scope)).collect();
                names.sort();
                names.dedup();
                self.names.lock().unwrap_or_else(|e| e.into_inner()).insert(scope, (Instant::now(), names.clone()));
                audit(
                    Event::new(actor(), "secret.read")
                        .target("secret_folder", scope.as_str())
                        .details(json!({ "store": self.provider.kind(), "scope": scope.as_str(), "op": "list", "names": names.len() })),
                );
                Ok(names)
            }
            Err(e) => {
                self.names.lock().unwrap_or_else(|e| e.into_inner()).remove(&scope);
                audit(
                    Event::new(actor(), "secret.read")
                        .target("secret_folder", scope.as_str())
                        .outcome(Outcome::Failure)
                        .details(json!({ "store": self.provider.kind(), "scope": scope.as_str(), "op": "list", "error": e.kind() })),
                );
                Err(e)
            }
        }
    }

    fn fetch(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let got = self.provider.read(scope, name);
        let details = |found: Option<bool>, err: Option<&Error>| {
            json!({ "store": self.provider.kind(), "scope": scope.as_str(), "op": "read", "found": found, "error": err.map(Error::kind) })
        };
        match got {
            Ok(v) => {
                if let Some(v) = &v {
                    redact::register(v);
                }
                self.values.lock().unwrap_or_else(|e| e.into_inner()).insert(name.to_string(), (Instant::now(), v.clone()));
                audit(Event::new(actor(), "secret.read").target("secret", name).details(details(Some(v.is_some()), None)));
                Ok(v)
            }
            Err(e) => {
                // Fail closed: what was cached is dropped, not served past its time.
                self.values.lock().unwrap_or_else(|e| e.into_inner()).remove(name);
                audit(Event::new(actor(), "secret.read").target("secret", name).outcome(Outcome::Failure).details(details(None, Some(&e))));
                Err(e)
            }
        }
    }
}

impl SecretStore for ExternalStore {
    fn kind(&self) -> &'static str {
        self.provider.kind()
    }

    fn get(&self, name: &str) -> Result<Option<Secret>, Error> {
        let Some(scope) = scope_of(name) else { return Ok(None) };
        let cached = self.values.lock().unwrap_or_else(|e| e.into_inner()).get(name).filter(|(at, _)| self.fresh(*at)).map(|(_, v)| v.clone());
        let v = match cached {
            Some(v) => v,
            None => self.fetch(scope, name)?,
        };
        Ok(v.map(|v| Secret::new(v.as_str())))
    }

    fn names(&self) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        for scope in Scope::ALL {
            let cached = self.names.lock().unwrap_or_else(|e| e.into_inner()).get(&scope).filter(|(at, _)| self.fresh(*at)).map(|(_, n)| n.clone());
            out.extend(match cached {
                Some(n) => n,
                None => self.list_from_backend(scope)?,
            });
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

/// `SECRETS_BACKEND`: `local` (the default: the environment and the sealed store only)
/// or `vault`. None for local.
pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Option<Arc<ExternalStore>>, String> {
    let ttl = cache_ttl(&var("SECRETS_CACHE_SECONDS"))?;
    let provider: Box<dyn Provider> = match var("SECRETS_BACKEND").trim() {
        "" | "local" => return Ok(None),
        "vault" => Box::new(super::vault::Vault::new(super::vault::Config::from_env(var, store)?)?),
        other => return Err(format!("SECRETS_BACKEND must be local or vault, not {other:?}")),
    };
    Ok(Some(Arc::new(ExternalStore::new(provider, ttl))))
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
            Ok(self.values.lock().unwrap().get(&(scope, name.to_string())).map(|v| Zeroizing::new(v.clone())))
        }
        fn list(&self, scope: Scope) -> Result<Vec<String>, Error> {
            self.lists.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(Error::Unavailable("fake is down".into()));
            }
            Ok(self.values.lock().unwrap().keys().filter(|(s, _)| *s == scope).map(|(_, n)| n.clone()).collect())
        }
    }

    pub(crate) fn fake(values: &[(Scope, &str, &str)], ttl: Duration) -> (Arc<Fake>, Arc<ExternalStore>) {
        let f = Arc::new(Fake::default());
        for (s, n, v) in values {
            f.values.lock().unwrap().insert((*s, n.to_string()), v.to_string());
        }
        (Arc::clone(&f), Arc::new(ExternalStore::new(Box::new(f), ttl)))
    }

    /// Events waiting for `name`, left in the queue: tests run side by side.
    pub(crate) fn audited(name: &str) -> Vec<Event> {
        PENDING.lock().unwrap().iter().filter(|e| e.target_id.as_deref() == Some(name)).cloned().collect()
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
        assert!(from_env(&var, &env).err().unwrap().contains("local or vault"));
    }
}
