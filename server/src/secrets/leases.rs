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
//! - With `AWS_RUN_CREDENTIALS` (ADR 0194) the leases are STS `AssumeRole` sessions,
//!   which nothing can revoke: at run end they are audited as `secret.lease_released`
//!   with when they expire, and their values stay redacted until then.
//! - With `GCP_RUN_CREDENTIALS` (ADR 0203) they are access tokens of Google service
//!   accounts botd impersonates (`generateAccessToken`), which can't be revoked either.

use super::external::{self, Scope};
use super::{check_name, redact, Error, Secret};
use crate::audit::{Event, Outcome};
use serde_json::json;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// The most paths one run asks for.
pub const MAX_PATHS: usize = 16;
/// Stands for the Bot owner's id in a path.
pub const OWNER: &str = "{owner}";
/// A lease's TTL as kept here, at most a year, so arithmetic on it can't overflow.
const MAX_TTL: u64 = 86_400 * 366;

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
    /// A new lease from `path` for a run of `bot_id`, with the value of each of `fields`,
    /// that nothing but its own TTL or a revoke ends within `run_for`.
    fn issue(&self, path: &str, fields: &[String], run_for: Duration, bot_id: &str) -> Result<Lease, Error>;
    fn revoke(&self, lease_id: &str) -> Result<(), Error>;
    /// False when leases can't be ended early (STS sessions): they last their TTL.
    fn revocable(&self) -> bool {
        true
    }
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

/// An IAM role's ARN, `arn:<partition>:iam::<account>:role/<path/name>`, where `{owner}`
/// may stand in the role's path or name.
fn role_arn_ok(p: &str) -> bool {
    let plain = p.replace(OWNER, "x");
    let parts: Vec<&str> = plain.splitn(6, ':').collect();
    let ["arn", partition, "iam", "", account, resource] = parts[..] else { return false };
    let role = resource.strip_prefix("role/").unwrap_or_default();
    matches!(partition, "aws" | "aws-cn" | "aws-us-gov")
        && account.len() == 12
        && account.bytes().all(|b| b.is_ascii_digit())
        && !role.is_empty()
        && plain.len() <= 2048
        && role.split('/').all(|part| !part.is_empty())
        && role.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-/".contains(&b))
}

/// A Google service account's email, `<account>@<domain>.gserviceaccount.com`, where
/// `{owner}` may stand in the account, before the `@`.
fn service_account_ok(p: &str) -> bool {
    let Some((account, domain)) = p.split_once('@') else { return false };
    let account = account.replace(OWNER, "x");
    let label_ok = |l: &str| !l.is_empty() && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    p.len() <= 254 && label_ok(&account) && domain.strip_suffix(".gserviceaccount.com").is_some_and(|d| d.split('.').all(label_ok))
}

/// How one backend's run credentials setting is written.
pub struct Syntax {
    pub key: &'static str,
    /// What an entry starts with, for errors.
    what: &'static str,
    path_ok: fn(&str) -> bool,
    /// The fields an entry may name; any field name if empty.
    fields: &'static [&'static str],
    /// What an entry that names no variables gives; none if empty.
    defaults: &'static [(&'static str, &'static str)],
    /// Names botd may sign in with that a lease may still give: the run's own, never botd's.
    own: &'static [&'static str],
    example: &'static str,
}

/// `VAULT_RUN_CREDENTIALS` (ADR 0185).
pub const VAULT: Syntax = Syntax {
    key: "VAULT_RUN_CREDENTIALS",
    what: "a Vault path like \"aws/creds/bots\" (letters, digits, . _ - and /, with {owner} for the Bot owner's id)",
    path_ok,
    fields: &[],
    defaults: &[],
    own: &[],
    example: "AWS_ACCESS_KEY_ID=access_key",
};

/// The variables AWS's SDKs and CLI read, and the fields of an STS session they come from.
const AWS_KEYS: [(&str, &str); 3] = [("AWS_ACCESS_KEY_ID", "AccessKeyId"), ("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"), ("AWS_SESSION_TOKEN", "SessionToken")];

/// `AWS_RUN_CREDENTIALS` (ADR 0194): IAM roles botd assumes with STS for each run.
pub const AWS: Syntax = Syntax {
    key: "AWS_RUN_CREDENTIALS",
    what: "an IAM role's ARN like \"arn:aws:iam::123456789012:role/superbot-bots\" (with {owner} for the Bot owner's id in the role's name)",
    path_ok: role_arn_ok,
    fields: &["AccessKeyId", "SecretAccessKey", "SessionToken"],
    defaults: &AWS_KEYS,
    own: &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
    example: "AWS_ACCESS_KEY_ID=AccessKeyId",
};

/// `GCP_RUN_CREDENTIALS` (ADR 0203): Google service accounts botd impersonates for each
/// run. A bare entry gives the token under the names gcloud and Terraform read.
pub const GCP: Syntax = Syntax {
    key: "GCP_RUN_CREDENTIALS",
    what: "a service account's email like \"superbot-bots@my-project.iam.gserviceaccount.com\" (with {owner} for the Bot owner's id before the @)",
    path_ok: service_account_ok,
    fields: &["accessToken"],
    defaults: &[("CLOUDSDK_AUTH_ACCESS_TOKEN", "accessToken"), ("GOOGLE_OAUTH_ACCESS_TOKEN", "accessToken")],
    own: &[],
    example: "GOOGLE_OAUTH_ACCESS_TOKEN=accessToken",
};

/// `VAULT_RUN_CREDENTIALS`: entries separated by `;` or new lines, each a path and the
/// variables it gives, `NAME=field`, separated by spaces:
/// `aws/creds/bots AWS_ACCESS_KEY_ID=access_key AWS_SECRET_ACCESS_KEY=secret_key`.
pub fn parse(raw: &str) -> Result<Vec<Wanted>, String> {
    parse_as(&VAULT, raw)
}

/// A run credentials setting written as `syntax` says: entries separated by `;` or new
/// lines, each a path (or role) and the variables it gives, `NAME=field`.
pub fn parse_as(syntax: &Syntax, raw: &str) -> Result<Vec<Wanted>, String> {
    let key = syntax.key;
    let mut out: Vec<Wanted> = Vec::new();
    for entry in raw.split([';', '\n']).map(str::trim).filter(|e| !e.is_empty()) {
        let mut parts = entry.split_whitespace();
        let path = parts.next().unwrap_or_default().trim_matches('/');
        if !(syntax.path_ok)(path) {
            return Err(format!("{key}: {path:?} must be {}", syntax.what));
        }
        let mut pairs: Vec<(String, String)> = Vec::new();
        for pair in parts {
            let Some((name, field)) = pair.split_once('=') else {
                return Err(format!("{key}: {pair:?} after {path} must be NAME=field, like {}", syntax.example));
            };
            pairs.push((name.to_string(), field.to_string()));
        }
        if pairs.is_empty() {
            pairs = syntax.defaults.iter().map(|(n, f)| (n.to_string(), f.to_string())).collect();
        }
        let mut names = Vec::new();
        for (name, field) in pairs {
            if !syntax.own.contains(&name.as_str()) {
                check_name(&name).map_err(|e| format!("{key}: {name}: {e}"))?;
            }
            if !field_ok(&field) || (!syntax.fields.is_empty() && !syntax.fields.contains(&field.as_str())) {
                let like = if syntax.fields.is_empty() { "like \"access_key\"".to_string() } else { format!("one of {}", syntax.fields.join(", ")) };
                return Err(format!("{key}: {field:?} must be a field name {like}"));
            }
            if out.iter().flat_map(|w| &w.names).chain(&names).any(|(n, _): &(String, String)| *n == name) {
                return Err(format!("{key}: {name} is given twice"));
            }
            names.push((name, field));
        }
        if names.is_empty() {
            return Err(format!("{key}: {path} gives no variables; add NAME=field after it"));
        }
        out.push(Wanted { path: path.to_string(), names });
    }
    if out.len() > MAX_PATHS {
        return Err(format!("{key}: at most {MAX_PATHS} paths, not {}", out.len()));
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
    /// When the backend ends it by itself: for leases that can't be revoked.
    expires: Instant,
    expires_at: chrono::DateTime<chrono::Utc>,
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

    /// When the first of these leases that can't be revoked expires (STS sessions): the run
    /// must stop by then, or it would go on with keys that no longer work. None for leases
    /// that are revoked at run end.
    pub fn expires_first(&self) -> Option<Instant> {
        if self.issuer.as_ref().is_none_or(|i| i.revocable()) {
            return None;
        }
        self.held.iter().map(|h| h.expires).min()
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
        forget_expired();
        if held.is_empty() {
            return;
        }
        if !issuer.revocable() {
            for h in held {
                release(issuer.kind(), h);
            }
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

/// Values of ended runs' leases that can't be revoked, and when they stop working.
static EXPIRING: Mutex<Vec<(Instant, Vec<Zeroizing<String>>)>> = Mutex::new(Vec::new());

/// Lets the redactor forget values whose lease has expired. Run as leases are made and
/// let go, so a value may stay redacted past its expiry until the next run: harmless.
fn forget_expired() {
    let now = Instant::now();
    let due: Vec<_> = {
        let mut expiring = EXPIRING.lock().unwrap_or_else(|e| e.into_inner());
        let (due, rest) = std::mem::take(&mut *expiring).into_iter().partition(|(at, _)| *at <= now);
        *expiring = rest;
        due
    };
    for v in due.iter().flat_map(|(_, vs)| vs) {
        release_value(v);
    }
}

/// A run's lease that can't be revoked: audited with when it expires, and its values kept
/// redacted until then.
fn release(store: &str, h: Held) {
    let (e, mut d) = event("secret.lease_released", store, &h.path, &h.bot_id, h.owner.as_deref());
    d["leaseId"] = json!(h.id);
    d["revocable"] = json!(false);
    d["expiresAt"] = json!(h.expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    external::audit(e.details(d));
    EXPIRING.lock().unwrap_or_else(|e| e.into_inner()).push((h.expires, h.values));
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
        forget_expired();
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
            let lease = match self.issuer.issue(&path, &fields, run_for, bot_id) {
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
            let ttl = lease.ttl.min(MAX_TTL);
            let mut held = Held {
                id: lease.id,
                path: path.clone(),
                bot_id: bot_id.to_string(),
                owner: owner_id.map(String::from),
                values: Vec::new(),
                expires: Instant::now() + Duration::from_secs(ttl),
                expires_at: chrono::Utc::now() + chrono::Duration::seconds(ttl as i64),
            };
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
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

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
        /// Leases can't be revoked and last `ttl` seconds (900 if 0), as STS sessions.
        pub unrevocable: AtomicBool,
        pub ttl: AtomicU64,
    }

    /// The longest a test's run may last.
    pub(crate) const RUN: Duration = Duration::from_secs(3600);

    impl Issuer for Fake {
        fn kind(&self) -> &'static str {
            "fake"
        }
        fn revocable(&self) -> bool {
            !self.unrevocable.load(Ordering::SeqCst)
        }
        fn issue(&self, path: &str, fields: &[String], run_for: Duration, _bot_id: &str) -> Result<Lease, Error> {
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
            let ttl = match self.ttl.load(Ordering::SeqCst) {
                0 => 900,
                t => t,
            };
            Ok(Lease { id: format!("{path}/lease{n}"), ttl, renewable: true, fields })
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
        assert!(l1.expires_first().is_none() && Leases::none().expires_first().is_none(), "revoked at run end: no deadline of their own");
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

    #[test]
    fn aws_roles_are_checked_and_default_to_the_sdks_names() {
        let w = parse_as(&AWS, "arn:aws:iam::123456789012:role/superbot-bots;\n arn:aws-us-gov:iam::123456789012:role/team/u-{owner} OWN_KEY_ID=AccessKeyId OWN_SECRET=SecretAccessKey OWN_TOKEN=SessionToken").unwrap();
        assert_eq!(w[0].path, "arn:aws:iam::123456789012:role/superbot-bots");
        assert_eq!(w[0].names, [pair("AWS_ACCESS_KEY_ID", "AccessKeyId"), pair("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"), pair("AWS_SESSION_TOKEN", "SessionToken")], "an entry naming no variables gets the ones AWS's SDKs read");
        assert!(w[1].per_owner());
        super::super::keep_from_bots(&["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"], &[]);
        assert!(check_name("AWS_ACCESS_KEY_ID").is_err(), "botd signs in with it, so no store gives it");
        assert!(parse_as(&AWS, "arn:aws:iam::123456789012:role/superbot-bots").is_ok(), "but a run's own session may");
        assert!(parse("aws/creds/bots AWS_ACCESS_KEY_ID=access_key").unwrap_err().contains("reserved"), "Vault's setting has no such exception");
        for (raw, err) in [
            ("aws/creds/bots", "IAM role's ARN"),
            ("arn:aws:iam::12345:role/r", "IAM role's ARN"),
            ("arn:aws:iam::{owner}:role/r", "IAM role's ARN"),
            ("arn:aws:sts::123456789012:role/r", "IAM role's ARN"),
            ("arn:aws:iam::123456789012:user/r", "IAM role's ARN"),
            ("arn:aws:iam::123456789012:role/", "IAM role's ARN"),
            ("arn:aws:iam::123456789012:role/a//b", "IAM role's ARN"),
            ("arn:aws:iam::123456789012:role/a*b", "IAM role's ARN"),
            ("arn:evil:iam::123456789012:role/r", "IAM role's ARN"),
            ("arn:aws:iam::123456789012:role/r X_KEY=Expiration", "one of AccessKeyId, SecretAccessKey, SessionToken"),
            ("arn:aws:iam::123456789012:role/r X_KEY", "like AWS_ACCESS_KEY_ID=AccessKeyId"),
            ("arn:aws:iam::123456789012:role/a; arn:aws:iam::123456789012:role/b", "AWS_ACCESS_KEY_ID is given twice"),
            ("arn:aws:iam::123456789012:role/r PATH=AccessKeyId", "PATH"),
        ] {
            let e = parse_as(&AWS, raw).unwrap_err();
            assert!(e.starts_with("AWS_RUN_CREDENTIALS: ") && e.contains(err), "{raw}: {e}");
        }
    }

    #[test]
    fn gcp_service_accounts_are_checked_and_default_to_gcloud_and_terraforms_names() {
        let w = parse_as(&GCP, "superbot-bots@proj-1.iam.gserviceaccount.com;\n superbot-u-{owner}@proj-1.iam.gserviceaccount.com OWN_GCP_TOKEN=accessToken").unwrap();
        assert_eq!(w[0].path, "superbot-bots@proj-1.iam.gserviceaccount.com");
        assert_eq!(w[0].names, [pair("CLOUDSDK_AUTH_ACCESS_TOKEN", "accessToken"), pair("GOOGLE_OAUTH_ACCESS_TOKEN", "accessToken")], "one token under both names");
        assert!(w[1].per_owner() && !w[0].per_owner());
        assert!(parse_as(&GCP, "123456789-compute@developer.gserviceaccount.com").is_ok(), "the default compute account");
        for (raw, err) in [
            ("aws/creds/bots", "service account's email"),
            ("superbot-bots", "service account's email"),
            ("Superbot@proj-1.iam.gserviceaccount.com", "service account's email"),
            ("superbot@proj-1.iam.example.com", "service account's email"),
            ("superbot@{owner}.iam.gserviceaccount.com", "service account's email"),
            ("superbot@.gserviceaccount.com", "service account's email"),
            ("super bot@proj-1.iam.gserviceaccount.com", "service account's email"),
            ("a@b@proj-1.iam.gserviceaccount.com", "service account's email"),
            ("superbot@proj-1.iam.gserviceaccount.com X_TOKEN=expireTime", "one of accessToken"),
            ("superbot@proj-1.iam.gserviceaccount.com X_TOKEN", "like GOOGLE_OAUTH_ACCESS_TOKEN=accessToken"),
            ("a@p.iam.gserviceaccount.com; b@p.iam.gserviceaccount.com", "CLOUDSDK_AUTH_ACCESS_TOKEN is given twice"),
            ("superbot@proj-1.iam.gserviceaccount.com GCP_SERVICE_ACCOUNT_KEY=accessToken", "reserved"),
        ] {
            let e = parse_as(&GCP, raw).unwrap_err();
            assert!(e.starts_with("GCP_RUN_CREDENTIALS: ") && e.contains(err), "{raw}: {e}");
        }
    }

    #[test]
    fn one_value_under_two_names_is_redacted_until_its_last_lease_lets_go() {
        let f = fake(&[("sa/twice", &[("accessToken", Some("ya29.twice-run-token-2b1a"))])]);
        f.same.store(true, Ordering::SeqCst);
        let rc = RunCredentials::new(f.clone(), parse("sa/twice TWICE_ONE_TOKEN=accessToken TWICE_TWO_TOKEN=accessToken").unwrap());
        let (e, l) = rc.issue("utwice7", "btwice7", true, RUN).unwrap();
        assert_eq!(env(&e), [pair("TWICE_ONE_TOKEN", "ya29.twice-run-token-2b1a"), pair("TWICE_TWO_TOKEN", "ya29.twice-run-token-2b1a")]);
        drop(l);
        wait_for(|| f.revoked.lock().unwrap().len() == 1);
        wait_for(|| redact::text("ya29.twice-run-token-2b1a") == "ya29.twice-run-token-2b1a");
    }

    #[test]
    fn leases_that_cant_be_revoked_stay_redacted_until_they_expire() {
        let f = fake(&[("sts/role/r", &[("SessionToken", Some("sts-run-session-6c5d"))])]);
        f.unrevocable.store(true, Ordering::SeqCst);
        f.ttl.store(1, Ordering::SeqCst);
        f.same.store(true, Ordering::SeqCst);
        let rc = RunCredentials::new(f.clone(), parse("sts/role/r STS_RUN_TOKEN=SessionToken").unwrap());
        let (_, l) = rc.issue("uexp6", "bexp6", true, RUN).unwrap();
        let first = l.expires_first().expect("the run must stop by then");
        assert!(first <= Instant::now() + Duration::from_secs(1));
        drop(l);
        assert!(f.revoked.lock().unwrap().is_empty(), "never asked to revoke");
        let ev: Vec<_> = external::tests::audited("sts/role/r").into_iter().filter(|e| e.action == "secret.lease_released").collect();
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!((ev[0].details["leaseId"].as_str(), ev[0].details["revocable"].as_bool()), (Some("sts/role/r/lease0"), Some(false)));
        let at = chrono::DateTime::parse_from_rfc3339(ev[0].details["expiresAt"].as_str().unwrap()).unwrap();
        assert!((at.timestamp() - chrono::Utc::now().timestamp()).abs() <= 2, "{at}");
        assert!(!external::tests::audited("sts/role/r").iter().any(|e| e.action == "secret.lease_revoked"));
        assert_eq!(redact::text("sts-run-session-6c5d"), redact::MARK, "it still works, so it stays redacted");

        std::thread::sleep(Duration::from_millis(1100));
        f.ttl.store(3600, Ordering::SeqCst);
        let (_, live) = rc.issue("uexp6", "bexp6", true, RUN).unwrap();
        assert_eq!(redact::text("sts-run-session-6c5d"), redact::MARK, "the first expired, but a live lease has the same value");
        drop(live);
        forget_expired();
        assert_eq!(redact::text("sts-run-session-6c5d"), redact::MARK, "the second ended its run but hasn't expired");
        {
            let mut expiring = EXPIRING.lock().unwrap();
            for (at, vs) in expiring.iter_mut() {
                if vs.iter().any(|v| v.as_str() == "sts-run-session-6c5d") {
                    *at = Instant::now();
                }
            }
        }
        forget_expired();
        assert_eq!(redact::text("sts-run-session-6c5d"), "sts-run-session-6c5d", "forgotten once every lease that had it expired");
    }
}
