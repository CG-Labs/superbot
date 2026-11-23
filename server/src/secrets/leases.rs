//! Short-lived credentials made for each run (ADR 0185): with `VAULT_RUN_CREDENTIALS`,
//! botd asks Vault for a new lease from each listed path (`aws/creds/<role>`,
//! `database/creds/<role>`, ...) as a run starts, gives the run the fields it names as
//! environment variables, and revokes the leases when the run ends, however it ends.
//!
//! - A path with `{owner}` is read with the Bot owner's id in its place, and only for
//!   runs that get the owner's own secrets; one without is the same role for every run.
//! - Fail closed: a lease that can't be made, or lacks a field it should have, refuses
//!   the run (`secrets_unavailable`), and the leases already made for it are revoked.
//! - Each lease made, refused and revoked is audited (`secret.lease_issued`,
//!   `secret.lease_revoked`) with its path and lease id, never a value.
//! - A name whose field is empty (AWS's `security_token` for an IAM user) is taken out
//!   of the run, so it never pairs a stale value with the fresh ones; the listed names
//!   are kept from what botd starts at all (`adapters::withhold`), so none is inherited.
//! - Values are redacted from everyone's text while a lease that has them lives, and
//!   forgotten once Vault has revoked the last one, unless botd knew them already, so the
//!   redactor doesn't grow with every run.
//! - A lease botd couldn't revoke (it stopped, Vault was down) ends at its TTL: the
//!   Vault role's `default_ttl` is the longest a credential outlives its run.
//! - Each lease is asked for with the longest the run may last (`RUN_TIMEOUT_MINUTES`),
//!   so a backend whose leases end with something else (Vault's with botd's token) can
//!   make sure that lives as long, or refuse the run.

use super::external::{self, Scope};
use super::{check_name, redact, Error, Secret};
use crate::audit::{Event, Outcome};
use serde_json::json;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use zeroize::Zeroizing;

/// The most paths one run asks for.
pub const MAX_PATHS: usize = 16;
/// Stands for the Bot owner's id in a path.
pub const OWNER: &str = "{owner}";

/// One field of a lease, as the backend answered.
#[derive(Debug)]
pub enum Field {
    Value(Zeroizing<String>),
    /// Present but null or empty (AWS's `security_token` for an IAM user): not given.
    Empty,
    /// Not in the answer at all: a wrong field name, so the run is refused.
    Missing,
}

/// A lease the backend made: its id, how long it lasts, and the fields asked for, in order.
#[derive(Debug)]
pub struct Lease {
    pub id: String,
    pub ttl: u64,
    pub renewable: bool,
    pub fields: Vec<Field>,
}

/// A backend that makes and revokes leases. Errors carry no value.
pub trait Issuer: Send + Sync {
    fn kind(&self) -> &'static str;
    /// A new lease from `path`, with the value of each of `fields`, that nothing but its
    /// own TTL or a revoke ends within `run_for`.
    fn issue(&self, path: &str, fields: &[String], run_for: Duration) -> Result<Lease, Error>;
    fn revoke(&self, lease_id: &str) -> Result<(), Error>;
}

/// One path and the environment variables its fields become.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wanted {
    pub path: String,
    /// (variable, field)
    pub names: Vec<(String, String)>,
}

impl Wanted {
    fn per_owner(&self) -> bool {
        self.path.contains(OWNER)
    }
}

fn field_ok(f: &str) -> bool {
    !f.is_empty() && f.len() <= 128 && f.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// A Vault path, `/`-separated parts of letters, digits, `.`, `_` and `-`, where
/// `{owner}` may stand in any part.
fn path_ok(p: &str) -> bool {
    let plain = p.replace(OWNER, "x");
    !plain.is_empty() && plain.split('/').all(|part| !part.is_empty() && part != "." && part != ".." && part.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
}

/// `VAULT_RUN_CREDENTIALS`: entries separated by `;` or new lines, each a path and the
/// variables it gives, `NAME=field`, separated by spaces:
/// `aws/creds/bots AWS_ACCESS_KEY_ID=access_key AWS_SECRET_ACCESS_KEY=secret_key`.
pub fn parse(raw: &str) -> Result<Vec<Wanted>, String> {
    const KEY: &str = "VAULT_RUN_CREDENTIALS";
    let mut out: Vec<Wanted> = Vec::new();
    for entry in raw.split([';', '\n']).map(str::trim).filter(|e| !e.is_empty()) {
        let mut parts = entry.split_whitespace();
        let path = parts.next().unwrap_or_default().trim_matches('/');
        if !path_ok(path) {
            return Err(format!("{KEY}: {path:?} must be a Vault path like \"aws/creds/bots\" (letters, digits, . _ - and /, with {OWNER} for the Bot owner's id)"));
        }
        let mut names = Vec::new();
        for pair in parts {
            let Some((name, field)) = pair.split_once('=') else {
                return Err(format!("{KEY}: {pair:?} after {path} must be NAME=field, like AWS_ACCESS_KEY_ID=access_key"));
            };
            check_name(name).map_err(|e| format!("{KEY}: {name}: {e}"))?;
            if !field_ok(field) {
                return Err(format!("{KEY}: {field:?} must be a field name like \"access_key\""));
            }
            if out.iter().flat_map(|w| &w.names).chain(&names).any(|(n, _): &(String, String)| n == name) {
                return Err(format!("{KEY}: {name} is given twice"));
            }
            names.push((name.to_string(), field.to_string()));
        }
        if names.is_empty() {
            return Err(format!("{KEY}: {path} gives no variables; add NAME=field after it"));
        }
        out.push(Wanted { path: path.to_string(), names });
    }
    if out.len() > MAX_PATHS {
        return Err(format!("{KEY}: at most {MAX_PATHS} paths, not {}", out.len()));
    }
    Ok(out)
}

/// The leases of one run, revoked when this is dropped.
pub struct Leases {
    issuer: Option<Arc<dyn Issuer>>,
    held: Vec<Held>,
    /// Names whose field was empty: the run must not have them at all.
    cleared: Vec<String>,
}

struct Held {
    id: String,
    path: String,
    bot_id: String,
    owner: Option<String>,
    values: Vec<Zeroizing<String>>,
}

impl Leases {
    pub fn none() -> Leases {
        Leases { issuer: None, held: Vec::new(), cleared: Vec::new() }
    }

    /// Names to take out of the run's environment: their lease gave no value, and an
    /// older one of the same name would pair with the fresh ones.
    pub fn cleared(&self) -> &[String] {
        &self.cleared
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

impl Drop for Leases {
    fn drop(&mut self) {
        let (Some(issuer), held) = (self.issuer.take(), std::mem::take(&mut self.held)) else { return };
        if held.is_empty() {
            return;
        }
        // Off the run's task: revoking waits on Vault, and the run has already ended.
        std::thread::spawn(move || {
            for h in held {
                revoke(issuer.as_ref(), h);
            }
        });
    }
}

/// Each lease value the redactor knows because of leases: how many live leases have it,
/// and whether a lease taught it (so revoking may forget it) or botd knew it already.
static LEASED: Mutex<Vec<(String, usize, bool)>> = Mutex::new(Vec::new());

fn hold_value(v: &str) {
    let mut leased = LEASED.lock().unwrap_or_else(|e| e.into_inner());
    match leased.iter_mut().find(|(k, ..)| k == v) {
        Some((_, n, _)) => *n += 1,
        None => {
            let ours = !redact::known().iter().any(|k| k == v.trim());
            redact::register(v);
            leased.push((v.to_string(), 1, ours));
        }
    }
}

fn release_value(v: &str) {
    let mut leased = LEASED.lock().unwrap_or_else(|e| e.into_inner());
    let Some(i) = leased.iter().position(|(k, ..)| k == v) else { return };
    leased[i].1 -= 1;
    if leased[i].1 == 0 {
        let (_, _, ours) = leased.swap_remove(i);
        if ours {
            redact::forget(v);
        }
    }
}

fn event(action: &str, store: &str, path: &str, bot_id: &str, owner: Option<&str>) -> (Event, serde_json::Value) {
    let mut d = json!({ "store": store, "path": path });
    if let Some(o) = owner {
        d["userId"] = json!(o);
    }
    (Event::new(external::actor(), action).target("secret_lease", path).bot(bot_id), d)
}

fn revoke(issuer: &dyn Issuer, h: Held) {
    let (e, mut d) = event("secret.lease_revoked", issuer.kind(), &h.path, &h.bot_id, h.owner.as_deref());
    d["leaseId"] = json!(h.id);
    match issuer.revoke(&h.id) {
        Ok(()) => {
            for v in &h.values {
                release_value(v);
            }
            external::audit(e.details(d));
        }
        Err(err) => {
            crate::obs::log::log_warn!("Secrets: a run's lease from {} couldn't be revoked, so it lasts until its TTL: {err}", h.path);
            d["error"] = json!(err.kind());
            external::audit(e.outcome(Outcome::Failure).details(d));
        }
    }
}

/// What `VAULT_RUN_CREDENTIALS` asks for, and the backend that makes it.
pub struct RunCredentials {
    issuer: Arc<dyn Issuer>,
    wanted: Vec<Wanted>,
}

impl RunCredentials {
    pub fn new(issuer: Arc<dyn Issuer>, wanted: Vec<Wanted>) -> RunCredentials {
        RunCredentials { issuer, wanted }
    }

    /// Every variable a run may get from a lease.
    pub fn names(&self) -> Vec<String> {
        self.wanted.iter().flat_map(|w| w.names.iter().map(|(n, _)| n.clone())).collect()
    }

    /// The variables `issue` sets or clears for a run with the same `owner` and `owner_keys`.
    pub fn names_for(&self, owner: &str, owner_keys: bool) -> Vec<String> {
        let owner_ok = owner_keys && Scope::user(owner).is_some();
        self.wanted.iter().filter(|w| owner_ok || !w.per_owner()).flat_map(|w| w.names.iter().map(|(n, _)| n.clone())).collect()
    }

    pub fn paths(&self) -> Vec<&str> {
        self.wanted.iter().map(|w| w.path.as_str()).collect()
    }

    /// For the startup line: paths only.
    pub fn describe(&self) -> String {
        format!("short-lived credentials for each run from {}", self.paths().join(", "))
    }

    /// New leases for one run of `bot_id`, owned by `owner`, and the variables they give.
    /// Paths with `{owner}` only when `owner_keys` and the id can name one (as for users'
    /// folders, ADR 0174). `run_for` is the longest the run may last. On an error the
    /// leases already made are revoked.
    pub fn issue(&self, owner: &str, bot_id: &str, owner_keys: bool, run_for: Duration) -> Result<(Vec<(String, Secret)>, Leases), Error> {
        let mut leases = Leases { issuer: Some(Arc::clone(&self.issuer)), held: Vec::new(), cleared: Vec::new() };
        let mut env = Vec::new();
        let owner_ok = owner_keys && Scope::user(owner).is_some();
        for w in &self.wanted {
            let per_owner = w.per_owner();
            if per_owner && !owner_ok {
                continue;
            }
            let path = w.path.replace(OWNER, owner);
            let owner_id = per_owner.then_some(owner);
            let (e, mut d) = event("secret.lease_issued", self.issuer.kind(), &path, bot_id, owner_id);
            d["names"] = json!(w.names.iter().map(|(n, _)| n).collect::<Vec<_>>());
            let fields: Vec<String> = w.names.iter().map(|(_, f)| f.clone()).collect();
            let lease = match self.issuer.issue(&path, &fields, run_for) {
                Ok(l) => l,
                Err(err) => {
                    d["error"] = json!(err.kind());
                    external::audit(e.outcome(Outcome::Failure).details(d));
                    return Err(err);
                }
            };
            d["leaseId"] = json!(lease.id);
            d["ttl"] = json!(lease.ttl);
            d["renewable"] = json!(lease.renewable);
            let mut held = Held { id: lease.id, path: path.clone(), bot_id: bot_id.to_string(), owner: owner_id.map(String::from), values: Vec::new() };
            let mut missing = Vec::new();
            for ((name, field), got) in w.names.iter().zip(lease.fields) {
                match got {
                    Field::Value(v) => {
                        hold_value(&v);
                        env.push((name.clone(), Secret::new(v.as_str())));
                        held.values.push(v);
                    }
                    Field::Empty => leases.cleared.push(name.clone()),
                    Field::Missing => missing.push(field.as_str()),
                }
            }
            leases.held.push(held);
            if !missing.is_empty() {
                d["error"] = json!("missing_fields");
                d["missing"] = json!(missing);
                external::audit(e.outcome(Outcome::Failure).details(d));
                return Err(Error::Unavailable(format!("{}: the lease from {path} has no field {}", self.issuer.kind(), missing.join(", "))));
            }
            external::audit(e.details(d));
        }
        Ok((env, leases))
    }
}

static ACTIVE: OnceLock<Arc<RunCredentials>> = OnceLock::new();

pub(crate) fn set_active(rc: &Arc<RunCredentials>) {
    keep_from_inheritance(rc);
    let _ = ACTIVE.set(Arc::clone(rc));
}

/// A name a lease gives reaches a run only from that lease: never inherited from
/// botd's own environment, where an older value could pair with the fresh ones.
fn keep_from_inheritance(rc: &RunCredentials) {
    crate::adapters::withhold(rc.names());
}

/// The short-lived credentials for one run, from the backend botd runs with; none if
/// `VAULT_RUN_CREDENTIALS` isn't set. Hold the `Leases` until the run ends.
pub fn for_run(owner: &str, bot_id: &str, owner_keys: bool, run_for: Duration) -> Result<(Vec<(String, Secret)>, Leases), Error> {
    match active(owner) {
        Some(rc) => rc.issue(owner, bot_id, owner_keys, run_for),
        None => Ok((Vec::new(), Leases::none())),
    }
}

/// The variables `for_run` will set or clear for such a run, before any lease is made.
pub fn names_for_run(owner: &str, owner_keys: bool) -> Vec<String> {
    active(owner).map(|rc| rc.names_for(owner, owner_keys)).unwrap_or_default()
}

fn active(#[allow(unused_variables)] owner: &str) -> Option<Arc<RunCredentials>> {
    #[cfg(test)]
    if let Some(rc) = tests::for_owner(owner) {
        return Some(rc);
    }
    ACTIVE.get().cloned()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Instant;

    /// A backend that makes leases in memory and records what it revoked.
    #[derive(Default)]
    pub(crate) struct Fake {
        /// path → fields its leases have (None: present but null).
        pub roles: Mutex<HashMap<String, Vec<(String, Option<String>)>>>,
        pub revoked: Mutex<Vec<String>>,
        pub issued: AtomicUsize,
        pub down: AtomicBool,
        pub revoke_down: AtomicBool,
        /// Every lease from a path has the same values, as a role that hands out one user would.
        pub same: AtomicBool,
        /// The `run_for` of each lease asked for.
        pub run_for: Mutex<Vec<Duration>>,
    }

    /// The longest a test's run may last.
    pub(crate) const RUN: Duration = Duration::from_secs(3600);

    impl Issuer for Fake {
        fn kind(&self) -> &'static str {
            "fake"
        }
        fn issue(&self, path: &str, fields: &[String], run_for: Duration) -> Result<Lease, Error> {
            self.run_for.lock().unwrap().push(run_for);
            if self.down.load(Ordering::SeqCst) {
                return Err(Error::Unavailable("fake is down".into()));
            }
            let roles = self.roles.lock().unwrap();
            let have = roles.get(path).ok_or_else(|| Error::Unavailable(format!("fake: nothing at {path}")))?;
            let n = self.issued.fetch_add(1, Ordering::SeqCst);
            let fields = fields
                .iter()
                .map(|f| match have.iter().find(|(k, _)| k == f) {
                    Some((_, Some(v))) if self.same.load(Ordering::SeqCst) => Field::Value(Zeroizing::new(v.clone())),
                    Some((_, Some(v))) => Field::Value(Zeroizing::new(format!("{v}-{n}"))),
                    Some((_, None)) => Field::Empty,
                    None => Field::Missing,
                })
                .collect();
            Ok(Lease { id: format!("{path}/lease{n}"), ttl: 900, renewable: true, fields })
        }
        fn revoke(&self, lease_id: &str) -> Result<(), Error> {
            if self.revoke_down.load(Ordering::SeqCst) {
                return Err(Error::Unavailable("fake can't revoke".into()));
            }
            self.revoked.lock().unwrap().push(lease_id.to_string());
            Ok(())
        }
    }

    /// Run credentials for one owner's runs only, so tests that run Bots side by side
    /// don't get each other's.
    static FOR_OWNER: Mutex<Vec<(String, Arc<RunCredentials>)>> = Mutex::new(Vec::new());

    pub(crate) fn set_for_owner(owner: &str, rc: RunCredentials) {
        FOR_OWNER.lock().unwrap().push((owner.to_string(), Arc::new(rc)));
    }

    pub(super) fn for_owner(owner: &str) -> Option<Arc<RunCredentials>> {
        FOR_OWNER.lock().unwrap().iter().find(|(o, _)| o == owner).map(|(_, rc)| Arc::clone(rc))
    }

    pub(crate) fn fake(roles: &[(&str, &[(&str, Option<&str>)])]) -> Arc<Fake> {
        let f = Arc::new(Fake::default());
        for (path, fields) in roles {
            f.roles.lock().unwrap().insert(path.to_string(), fields.iter().map(|(k, v)| (k.to_string(), v.map(String::from))).collect());
        }
        f
    }

    /// Waits for the revocations a dropped `Leases` started on its own thread.
    pub(crate) fn wait_for(what: impl Fn() -> bool) {
        let until = Instant::now() + Duration::from_secs(10);
        while !what() {
            assert!(Instant::now() < until, "timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn env(e: &[(String, Secret)]) -> Vec<(String, String)> {
        let mut v: Vec<_> = e.iter().map(|(k, v)| (k.clone(), v.expose().to_string())).collect();
        v.sort();
        v
    }

    fn pair(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    #[test]
    fn settings_are_checked() {
        let w = parse(" aws/creds/bots CLOUD_KEY_ID=access_key CLOUD_SECRET_KEY=secret_key CLOUD_SESSION_TOKEN=security_token ;\n/database/creds/u-{owner}/ PGUSER=username PGPASSWORD=password\n").unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].names[2], pair("CLOUD_SESSION_TOKEN", "security_token"));
        assert_eq!((w[1].path.as_str(), w[1].per_owner(), w[0].per_owner()), ("database/creds/u-{owner}", true, false));
        assert!(parse("").unwrap().is_empty() && parse(" ; \n").unwrap().is_empty());
        let many = (0..=MAX_PATHS).map(|i| format!("p/{i} N{i}_TOKEN=f")).collect::<Vec<_>>().join(";");
        for (raw, err) in [
            ("aws/creds/bots", "gives no variables"),
            ("aws/../sys CLOUD_X=f", "must be a Vault path"),
            ("aws/creds/{user} CLOUD_X=f", "must be a Vault path"),
            ("aws/creds/bots CLOUD_X", "must be NAME=field"),
            ("aws/creds/bots PATH=f", "PATH"),
            ("aws/creds/bots VAULT_TOKEN=f", "reserved"),
            ("aws/creds/bots lower=f", "environment variable name"),
            ("aws/creds/bots CLOUD_X=a\"b", "field name"),
            ("a/b X_TOKEN=f; c/d X_TOKEN=g", "given twice"),
            (many.as_str(), "at most 16 paths"),
        ] {
            let e = parse(raw).unwrap_err();
            assert!(e.contains(err), "{raw}: {e}");
        }
    }

    #[test]
    fn each_run_gets_new_leases_that_are_revoked_when_it_ends() {
        let f = fake(&[
            ("aws/creds/bots", &[("access_key", Some("AKIAleases")), ("secret_key", Some("aws-run-secret-0a1b")), ("security_token", None)]),
            ("database/creds/u-ulease1", &[("username", Some("v-ulease1-user")), ("password", Some("db-run-pass-9f8e"))]),
        ]);
        let wanted = parse("aws/creds/bots CLOUD_KEY_ID=access_key CLOUD_SECRET_KEY=secret_key CLOUD_SESSION_TOKEN=security_token; database/creds/u-{owner} PGUSER=username PGPASSWORD=password").unwrap();
        let rc = RunCredentials::new(f.clone(), wanted);
        assert!(rc.describe().contains("aws/creds/bots, database/creds/u-{owner}"));

        let (e1, l1) = rc.issue("ulease1", "blease1", true, RUN).unwrap();
        let (e2, l2) = rc.issue("ulease1", "blease1", true, RUN).unwrap();
        assert_eq!(
            env(&e1),
            [pair("CLOUD_KEY_ID", "AKIAleases-0"), pair("CLOUD_SECRET_KEY", "aws-run-secret-0a1b-0"), pair("PGPASSWORD", "db-run-pass-9f8e-1"), pair("PGUSER", "v-ulease1-user-1")],
            "a null field isn't given"
        );
        assert_ne!(env(&e1), env(&e2), "each run its own");
        assert_eq!((l1.len(), l2.len()), (2, 2));
        assert_eq!(l1.cleared(), ["CLOUD_SESSION_TOKEN"], "an empty field is taken out of the run, not left to an older value");
        assert_eq!(redact::text("key aws-run-secret-0a1b-0 here"), "key [redacted] here", "redacted while the lease lives");

        let ev: Vec<_> = external::tests::audited("aws/creds/bots").into_iter().filter(|e| e.details["leaseId"] == "aws/creds/bots/lease0").collect();
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!((ev[0].action.as_str(), ev[0].bot_id.as_deref()), ("secret.lease_issued", Some("blease1")));
        assert_eq!(ev[0].details, json!({ "store": "fake", "path": "aws/creds/bots", "names": ["CLOUD_KEY_ID", "CLOUD_SECRET_KEY", "CLOUD_SESSION_TOKEN"], "leaseId": "aws/creds/bots/lease0", "ttl": 900, "renewable": true }));
        let db = external::tests::audited("database/creds/u-ulease1");
        assert!(db.iter().all(|e| e.details["userId"] == "ulease1"), "{db:?}");
        assert!(!format!("{ev:?}{db:?}").contains("run-secret") && !format!("{db:?}").contains("run-pass"), "never a value");

        drop(l1);
        wait_for(|| f.revoked.lock().unwrap().len() == 2);
        assert_eq!(*f.revoked.lock().unwrap(), ["aws/creds/bots/lease0", "database/creds/u-ulease1/lease1"], "only the ended run's");
        wait_for(|| redact::text("aws-run-secret-0a1b-0") == "aws-run-secret-0a1b-0");
        assert_eq!(redact::text("aws-run-secret-0a1b-2"), redact::MARK, "the other run's still is");
        let revoked = external::tests::audited("aws/creds/bots").into_iter().filter(|e| e.action == "secret.lease_revoked" && e.details["leaseId"] == "aws/creds/bots/lease0").count();
        assert_eq!(revoked, 1);
        drop(l2);
        wait_for(|| f.revoked.lock().unwrap().len() == 4);
    }

    #[test]
    fn owners_paths_only_for_their_own_keys() {
        let f = fake(&[("shared/creds/r", &[("token", Some("shared-run-token-77"))]), ("db/creds/uown2", &[("password", Some("own-run-pass-77"))])]);
        let rc = RunCredentials::new(f.clone(), parse("shared/creds/r SHARED_TOKEN=token; db/creds/{owner} OWN_PASSWORD=password").unwrap());
        let (e, l) = rc.issue("uown2", "bown2", false, RUN).unwrap();
        assert_eq!(env(&e).into_iter().map(|(k, _)| k).collect::<Vec<_>>(), ["SHARED_TOKEN"], "a run for someone else gets no owner's lease");
        assert_eq!(l.len(), 1);
        let (e, _) = rc.issue("U-OWN2", "bown2", true, RUN).unwrap();
        assert_eq!(e.len(), 1, "an id that can't be part of a path gets none of its own");
        let (e, _) = rc.issue("uown2", "bown2", true, RUN).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(rc.names_for("uown2", false), ["SHARED_TOKEN"], "known before any lease, for the plan's key check");
        assert_eq!(rc.names_for("U-OWN2", true), ["SHARED_TOKEN"]);
        assert_eq!(rc.names_for("uown2", true), ["SHARED_TOKEN", "OWN_PASSWORD"]);
        assert!(names_for_run("uown2", true).is_empty());
        let (e, l) = for_run("uown2", "bown2", true, RUN).unwrap();
        assert!(e.is_empty() && l.is_empty(), "nothing set: nothing asked for");
    }

    #[test]
    fn a_lease_that_cant_be_made_refuses_the_run_and_revokes_the_rest() {
        let f = fake(&[("first/creds/r", &[("token", Some("first-run-token-55"))]), ("second/creds/r", &[("username", Some("second-user-55"))])]);
        let rc = RunCredentials::new(f.clone(), parse("first/creds/r FIRST_TOKEN=token; second/creds/r SECOND_USER=username SECOND_PASSWORD=password").unwrap());
        let err = rc.issue("ufail3", "bfail3", true, RUN).err().unwrap();
        assert!(matches!(&err, Error::Unavailable(m) if m.contains("has no field password")), "{err:?}");
        wait_for(|| f.revoked.lock().unwrap().len() == 2);
        assert!(f.revoked.lock().unwrap().iter().any(|l| l.starts_with("first/")) && f.revoked.lock().unwrap().iter().any(|l| l.starts_with("second/")), "both, the one with the missing field too");
        let ev = external::tests::audited("second/creds/r");
        assert!(ev.iter().any(|e| e.outcome == Outcome::Failure && e.details["missing"] == json!(["password"])), "{ev:?}");

        f.down.store(true, Ordering::SeqCst);
        let before = f.revoked.lock().unwrap().len();
        assert!(matches!(rc.issue("ufail3", "bfail3", true, RUN), Err(Error::Unavailable(_))));
        assert!(external::tests::audited("first/creds/r").iter().any(|e| e.outcome == Outcome::Failure && e.details["error"] == "unavailable"));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(f.revoked.lock().unwrap().len(), before, "nothing was made, nothing to revoke");
    }

    #[test]
    fn a_value_stays_redacted_while_any_lease_or_botd_still_knows_it() {
        let f = fake(&[("shared/creds/same", &[("token", Some("same-lease-value-8a7b"))]), ("shared/creds/known", &[("token", Some("known-before-8a7b"))])]);
        f.same.store(true, Ordering::SeqCst);
        let rc = RunCredentials::new(f.clone(), parse("shared/creds/same SAME_TOKEN=token").unwrap());
        let (_, l1) = rc.issue("usame5", "bsame5", true, RUN).unwrap();
        let (_, l2) = rc.issue("usame5", "bsame5", true, RUN).unwrap();
        drop(l1);
        wait_for(|| f.revoked.lock().unwrap().len() == 1);
        assert_eq!(redact::text("same-lease-value-8a7b"), redact::MARK, "the other run's lease still has it");
        drop(l2);
        wait_for(|| f.revoked.lock().unwrap().len() == 2);
        wait_for(|| redact::text("same-lease-value-8a7b") == "same-lease-value-8a7b");

        redact::register("known-before-8a7b");
        let rc = RunCredentials::new(f.clone(), parse("shared/creds/known KNOWN_TOKEN=token").unwrap());
        drop(rc.issue("usame5", "bsame5", true, RUN).unwrap().1);
        wait_for(|| f.revoked.lock().unwrap().len() == 3);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(redact::text("known-before-8a7b"), redact::MARK, "botd knew it before the lease: revoking doesn't forget it");
        redact::forget("known-before-8a7b");
    }

    #[test]
    fn leased_names_are_never_inherited_from_botd() {
        let rc = RunCredentials::new(fake(&[]), parse("x/creds/r INHERIT_LEASED_ONE=a INHERIT_LEASED_TWO=b").unwrap());
        assert!(!crate::adapters::withheld("INHERIT_LEASED_ONE"));
        keep_from_inheritance(&rc);
        let host = crate::adapters::local_host();
        assert!(["INHERIT_LEASED_ONE", "INHERIT_LEASED_TWO"].iter().all(|n| host.remove.iter().any(|r| r == n)), "removed from what botd starts");
    }

    #[test]
    fn a_lease_that_cant_be_revoked_is_audited_and_stays_redacted() {
        let f = fake(&[("stuck/creds/r", &[("token", Some("stuck-run-token-31"))])]);
        let rc = RunCredentials::new(f.clone(), parse("stuck/creds/r STUCK_TOKEN=token").unwrap());
        f.revoke_down.store(true, Ordering::SeqCst);
        let (_, l) = rc.issue("ustuck4", "bstuck4", true, RUN).unwrap();
        drop(l);
        wait_for(|| external::tests::audited("stuck/creds/r").iter().any(|e| e.action == "secret.lease_revoked"));
        let ev: Vec<_> = external::tests::audited("stuck/creds/r").into_iter().filter(|e| e.action == "secret.lease_revoked").collect();
        assert_eq!((ev[0].outcome, ev[0].details["error"].as_str()), (Outcome::Failure, Some("unavailable")));
        assert_eq!(redact::text("stuck-run-token-31-0"), redact::MARK, "it lives until its TTL, so it stays redacted");
        redact::forget("stuck-run-token-31-0");
    }
}
