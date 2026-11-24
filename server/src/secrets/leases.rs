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
//! - With `AZURE_RUN_CREDENTIALS` (ADR 0213) they are Entra access tokens of apps that
//!   trust botd's managed identity or workload identity, which can't be revoked either.
//! - A renewable lease that would end before the run could (ADR 0221) is renewed while
//!   the run lasts, two thirds of the way through each TTL, by the TTL it was made with,
//!   so a role's short `default_ttl` bounds how long a credential outlives botd. Each
//!   renewal is audited (`secret.lease_renewed`). A lease the backend won't renew past a
//!   point (its `max_ttl`), or that ends while renewals fail, stops the run when it ends,
//!   as an STS session does.
//! - An `AWS_RUN_CREDENTIALS` entry may narrow each run's session (ADR 0230): an inline
//!   session policy from a file (`policy=`), managed session policies (`policy-arn=`)
//!   and transitive session tags with the Bot's and owner's ids (`tags=bot,owner`), with
//!   `{owner}` and `{bot}` in the policies filled in for each run. One that names the
//!   owner is only for the owner's runs, as a role with `{owner}` is.
//! - A `GCP_RUN_CREDENTIALS` entry may downscope each run's token (ADR 0240): a Credential
//!   Access Boundary from a file (`boundary=`), with `{owner}` and `{bot}` filled in the
//!   same way, limits it to the Cloud Storage buckets, roles and objects it names.

use super::external::{self, Scope};
use super::{check_name, redact, Error, Secret};
use crate::audit::{Event, Outcome};
use serde_json::{json, Value};
use std::io::Read;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use zeroize::Zeroizing;

/// The most paths one run asks for.
pub const MAX_PATHS: usize = 16;
/// Stands for the Bot owner's id in a path.
pub const OWNER: &str = "{owner}";
/// Stands for the Bot's id in a session policy.
pub const BOT: &str = "{bot}";
/// The entry options that narrow an STS session (ADR 0230).
const SESSION_OPTIONS: &[&str] = &["policy", "policy-arn", "tags"];
/// The entry option that downscopes a Google access token (ADR 0240).
const BOUNDARY_OPTIONS: &[&str] = &["boundary"];
/// STS's most managed session policies, and longest inline one, as plain text.
pub const MAX_POLICY_ARNS: usize = 10;
pub const MAX_POLICY: usize = 2048;
/// The largest session policy or access boundary file read.
const MAX_POLICY_FILE: u64 = 64 * 1024;
/// The most rules a Credential Access Boundary may have, as Google allows.
pub const MAX_BOUNDARY_RULES: usize = 10;
/// What every rule's resource starts with: Credential Access Boundaries cover Cloud
/// Storage buckets only.
const BUCKET_RESOURCE: &str = "//storage.googleapis.com/projects/_/buckets/";
/// A lease's TTL as kept here, at most a year, so arithmetic on it can't overflow.
const MAX_TTL: u64 = 86_400 * 366;
/// How much longer than a run renewals keep its leases alive: the run's end, its
/// harness's exit and the revoke all come after the timeout.
const RENEW_MARGIN: Duration = Duration::from_secs(300);
/// The longest wait before a failed renewal is tried again.
const RETRY_MAX: Duration = Duration::from_secs(30);

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

/// What the backend said to a renewal.
#[derive(Debug, PartialEq, Eq)]
pub enum Renewal {
    /// The lease now lasts `ttl` seconds more; not `renewable` if that was its last.
    Renewed { ttl: u64, renewable: bool },
    /// The backend won't renew it (gone, not renewable, not allowed): it ends when it would have.
    Refused(String),
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
    /// Asks for `lease_id` to last `increment` more. An error may pass (the backend is
    /// down) and is tried again; `Refused` is final.
    fn renew(&self, _lease_id: &str, _increment: Duration) -> Result<Renewal, Error> {
        Ok(Renewal::Refused(format!("{} leases can't be renewed", self.kind())))
    }
    /// `issue`, with the session narrowed as `narrowed` says (ADR 0230, ADR 0240). Only a
    /// setting that takes these options gives a non-empty one; a backend that can't
    /// narrow its leases refuses it rather than make a wider one.
    fn issue_narrowed(&self, path: &str, fields: &[String], run_for: Duration, bot_id: &str, narrowed: &Narrowed) -> Result<Lease, Error> {
        if !narrowed.is_empty() {
            return Err(Error::Unavailable(format!("{}: leases can't be narrowed with a session policy, tags or an access boundary", self.kind())));
        }
        self.issue(path, fields, run_for, bot_id)
    }
}

/// A run's id its STS session is tagged with, so the role's policies can match on
/// `aws:PrincipalTag/<key>` (ADR 0230).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    Bot,
    Owner,
}

impl Tag {
    pub fn key(self) -> &'static str {
        match self {
            Tag::Bot => "superbot-bot",
            Tag::Owner => "superbot-owner",
        }
    }
}

/// How an entry narrows each run's session (ADR 0230) or token (ADR 0240); empty unless
/// its setting takes `policy=`, `policy-arn=` and `tags=`, or `boundary=`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Narrowing {
    /// The inline session policy from `policy=<file>`, read once at startup; `{owner}`
    /// and `{bot}` in its strings are filled in for each run.
    pub policy: Option<Value>,
    /// Managed session policies, `{owner}` allowed in their names.
    pub policy_arns: Vec<String>,
    pub tags: Vec<Tag>,
    /// The Credential Access Boundary from `boundary=<file>`, read once at startup;
    /// `{owner}` and `{bot}` filled in as in a policy.
    pub boundary: Option<Value>,
}

/// One run's narrowing, its ids filled in: the policy as sent (compact JSON), the
/// managed policies' ARNs, the tags (key, value), and the access boundary as sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Narrowed {
    pub policy: Option<String>,
    pub policy_arns: Vec<String>,
    pub tags: Vec<(&'static str, String)>,
    pub boundary: Option<String>,
}

impl Narrowed {
    pub fn is_empty(&self) -> bool {
        self.policy.is_none() && self.policy_arns.is_empty() && self.tags.is_empty() && self.boundary.is_none()
    }

    /// Whether it narrows an STS session: what only AWS can do.
    pub fn narrows_session(&self) -> bool {
        self.policy.is_some() || !self.policy_arns.is_empty() || !self.tags.is_empty()
    }
}

/// Whether `needle` is in any key or string of `v`.
fn mentions(v: &Value, needle: &str) -> bool {
    match v {
        Value::String(s) => s.contains(needle),
        Value::Array(a) => a.iter().any(|v| mentions(v, needle)),
        Value::Object(o) => o.iter().any(|(k, v)| k.contains(needle) || mentions(v, needle)),
        _ => false,
    }
}

/// `v` with `fill` applied to every key and string: values are put in as JSON strings,
/// never as text, so an id can't change the policy's shape.
fn substitute(v: &Value, fill: &dyn Fn(&str) -> String) -> Value {
    match v {
        Value::String(s) => Value::String(fill(s)),
        Value::Array(a) => Value::Array(a.iter().map(|v| substitute(v, fill)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (fill(k), substitute(v, fill))).collect()),
        v => v.clone(),
    }
}

/// A Bot id that may stand in a policy or tag: letters, digits, `_` and `-`, so it can't
/// be a wildcard (`*`, `?`) or a path (`/`) in an ARN.
fn bot_id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl Narrowing {
    fn is_empty(&self) -> bool {
        self.policy.is_none() && self.policy_arns.is_empty() && self.tags.is_empty() && self.boundary.is_none()
    }

    fn per_owner(&self) -> bool {
        self.tags.contains(&Tag::Owner)
            || self.policy_arns.iter().any(|a| a.contains(OWNER))
            || self.policy.as_ref().is_some_and(|p| mentions(p, OWNER))
            || self.boundary.as_ref().is_some_and(|b| mentions(b, OWNER))
    }

    /// What a run of `bot_id` owned by `owner` gets. Refused when the Bot's id can't
    /// stand in a policy, tag or boundary, or the policy grows past STS's limit with the
    /// ids in.
    fn for_run(&self, owner: &str, bot_id: &str) -> Result<Narrowed, String> {
        if self.boundary.as_ref().is_some_and(|b| mentions(b, BOT)) && !bot_id_ok(bot_id) {
            return Err(format!("the Bot's id {bot_id:?} can't stand in an access boundary"));
        }
        let needs_bot = self.tags.contains(&Tag::Bot) || self.policy.as_ref().is_some_and(|p| mentions(p, BOT));
        if needs_bot && !bot_id_ok(bot_id) {
            return Err(format!("the Bot's id {bot_id:?} can't stand in a session policy or tag"));
        }
        let fill = |s: &str| s.replace(OWNER, owner).replace(BOT, bot_id);
        let policy = match &self.policy {
            Some(p) => {
                let text = serde_json::to_string(&substitute(p, &fill)).map_err(|e| format!("the session policy can't be written: {e}"))?;
                let chars = text.chars().count();
                if chars > MAX_POLICY {
                    return Err(format!("the session policy is {chars} characters with this run's ids in it, over STS's {MAX_POLICY}"));
                }
                Some(text)
            }
            None => None,
        };
        let tags = self
            .tags
            .iter()
            .map(|t| {
                let v = match t {
                    Tag::Bot => bot_id,
                    Tag::Owner => owner,
                };
                (t.key(), v.to_string())
            })
            .collect();
        let boundary = match &self.boundary {
            Some(b) => Some(serde_json::to_string(&substitute(b, &fill)).map_err(|e| format!("the access boundary can't be written: {e}"))?),
            None => None,
        };
        Ok(Narrowed { policy, policy_arns: self.policy_arns.iter().map(|a| a.replace(OWNER, owner)).collect(), tags, boundary })
    }
}

/// One path and the environment variables its fields become.
#[derive(Clone, Debug, PartialEq)]
pub struct Wanted {
    pub path: String,
    /// (variable, field)
    pub names: Vec<(String, String)>,
    pub narrowing: Narrowing,
}

impl Wanted {
    /// Only for the owner's own runs: the path, or how its session is narrowed, names them.
    fn per_owner(&self) -> bool {
        self.path.contains(OWNER) || self.narrowing.per_owner()
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

/// An ARN's partition (`aws`, `aws-cn`, `aws-us-gov`).
fn partition(arn: &str) -> &str {
    arn.split(':').nth(1).unwrap_or_default()
}

/// A managed policy's ARN, `arn:<partition>:iam::<account or aws>:policy/<path/name>`,
/// where `{owner}` may stand in the policy's path or name.
fn policy_arn_ok(p: &str) -> bool {
    let plain = p.replace(OWNER, "x");
    let parts: Vec<&str> = plain.splitn(6, ':').collect();
    let ["arn", partition, "iam", "", account, resource] = parts[..] else { return false };
    let policy = resource.strip_prefix("policy/").unwrap_or_default();
    matches!(partition, "aws" | "aws-cn" | "aws-us-gov")
        && (account == "aws" || (account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit())))
        && !policy.is_empty()
        && plain.len() <= 2048
        && policy.split('/').all(|part| !part.is_empty())
        && policy.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-/".contains(&b))
}

/// The session policy in `file`, checked as STS would: a JSON object with a `Statement`,
/// at most `MAX_POLICY` characters once spaces are taken out, and only characters up to
/// U+00FF. Never quoted in errors.
fn read_policy(file: &str) -> Result<Value, String> {
    let bad = |why: String| format!("policy={file}: {why}");
    let v = read_json(file).map_err(bad)?;
    if !v.get("Statement").is_some_and(|s| s.is_array() || s.is_object()) {
        return Err(bad("must be an IAM policy: a JSON object with a Statement".into()));
    }
    let compact = serde_json::to_string(&v).map_err(|e| bad(e.to_string()))?;
    if compact.chars().any(|c| u32::from(c) > 0xFF) {
        return Err(bad("has characters STS won't take in a policy (only up to U+00FF)".into()));
    }
    let chars = compact.chars().count();
    if chars > MAX_POLICY {
        return Err(bad(format!("is {chars} characters with spaces taken out, over STS's {MAX_POLICY}; move statements to a managed policy (policy-arn=)")));
    }
    Ok(v)
}

/// The JSON in `file`, at most `MAX_POLICY_FILE` bytes. Errors never quote it.
fn read_json(file: &str) -> Result<Value, String> {
    let f = std::fs::File::open(file).map_err(|e| format!("can't be read ({e})"))?;
    let mut text = String::new();
    f.take(MAX_POLICY_FILE + 1).read_to_string(&mut text).map_err(|e| format!("can't be read ({e})"))?;
    if text.len() as u64 > MAX_POLICY_FILE {
        return Err(format!("is over {MAX_POLICY_FILE} bytes"));
    }
    serde_json::from_str(&text).map_err(|e| format!("isn't JSON ({e})"))
}

/// The Credential Access Boundary in `file`, checked as Google's client libraries do
/// before they send one. Never quoted in errors.
fn read_boundary(file: &str) -> Result<Value, String> {
    let bad = |why: String| format!("boundary={file}: {why}");
    let v = read_json(file).map_err(bad)?;
    check_boundary(&v).map_err(bad)?;
    Ok(v)
}

/// `{"accessBoundary": {"accessBoundaryRules": [...]}}` with 1 to 10 rules, each a Cloud
/// Storage bucket, `inRole:` permissions and an optional condition; nothing else, so a
/// misspelt key fails at startup rather than being dropped by Google.
fn check_boundary(v: &Value) -> Result<(), String> {
    let shape = || "must be a Credential Access Boundary: {\"accessBoundary\": {\"accessBoundaryRules\": [...]}} and nothing else".to_string();
    let only = |o: &serde_json::Map<String, Value>, keys: &[&str]| o.keys().all(|k| keys.contains(&k.as_str()));
    let top = v.as_object().filter(|o| only(o, &["accessBoundary"])).ok_or_else(shape)?;
    let boundary = top.get("accessBoundary").and_then(Value::as_object).filter(|o| only(o, &["accessBoundaryRules"])).ok_or_else(shape)?;
    let rules = boundary.get("accessBoundaryRules").and_then(Value::as_array).ok_or_else(shape)?;
    if rules.is_empty() || rules.len() > MAX_BOUNDARY_RULES {
        return Err(format!("has {} rules; Google takes 1 to {MAX_BOUNDARY_RULES}", rules.len()));
    }
    let word = |s: &str| !s.is_empty() && !s.chars().any(char::is_whitespace);
    for (i, rule) in rules.iter().enumerate() {
        let n = i + 1;
        let rule = rule
            .as_object()
            .filter(|o| only(o, &["availableResource", "availablePermissions", "availabilityCondition"]))
            .ok_or_else(|| format!("rule {n} must be an object with availableResource, availablePermissions and, optionally, availabilityCondition"))?;
        let bucket = rule.get("availableResource").and_then(Value::as_str).and_then(|r| r.strip_prefix(BUCKET_RESOURCE));
        if !bucket.is_some_and(|b| word(b) && !b.contains('/')) {
            return Err(format!("rule {n}'s availableResource must be a Cloud Storage bucket, {BUCKET_RESOURCE}<bucket>: access boundaries cover nothing else"));
        }
        let roles = rule.get("availablePermissions").and_then(Value::as_array);
        if !roles.is_some_and(|r| !r.is_empty() && r.iter().all(|p| p.as_str().and_then(|p| p.strip_prefix("inRole:")).is_some_and(word))) {
            return Err(format!("rule {n}'s availablePermissions must be a list of roles, like [\"inRole:roles/storage.objectViewer\"]"));
        }
        if let Some(c) = rule.get("availabilityCondition") {
            let ok = c.as_object().is_some_and(|c| {
                only(c, &["expression", "title", "description"]) && c.values().all(Value::is_string) && c.get("expression").and_then(Value::as_str).is_some_and(|e| !e.trim().is_empty())
            });
            if !ok {
                return Err(format!("rule {n}'s availabilityCondition must have an expression, and may have a title and description, all strings"));
            }
        }
    }
    Ok(())
}

/// One of `SESSION_OPTIONS` or `BOUNDARY_OPTIONS`, `name=value`, after `role` in an entry.
fn session_option(n: &mut Narrowing, role: &str, name: &str, value: &str) -> Result<(), String> {
    match name {
        "boundary" => {
            if n.boundary.is_some() {
                return Err("boundary= is given twice; put every rule in one file".into());
            }
            n.boundary = Some(read_boundary(value)?);
        }
        "policy" => {
            if n.policy.is_some() {
                return Err("policy= is given twice; put every statement in one file".into());
            }
            n.policy = Some(read_policy(value)?);
        }
        "policy-arn" => {
            if !policy_arn_ok(value) || partition(value) != partition(role) {
                return Err(format!("policy-arn={value:?} must be a managed policy's ARN in the role's partition, like \"arn:aws:iam::aws:policy/ReadOnlyAccess\""));
            }
            if n.policy_arns.iter().any(|a| a == value) {
                return Err(format!("policy-arn={value} is given twice"));
            }
            if n.policy_arns.len() == MAX_POLICY_ARNS {
                return Err(format!("at most {MAX_POLICY_ARNS} policy-arn= for one role, as STS allows"));
            }
            n.policy_arns.push(value.to_string());
        }
        _ => {
            if !n.tags.is_empty() {
                return Err("tags= is given twice".into());
            }
            for t in value.split(',') {
                let tag = match t {
                    "bot" => Tag::Bot,
                    "owner" => Tag::Owner,
                    _ => return Err(format!("tags= takes bot, owner or both (tags=bot,owner), not {value:?}")),
                };
                if n.tags.contains(&tag) {
                    return Err(format!("tags= names {t} twice"));
                }
                n.tags.push(tag);
            }
        }
    }
    Ok(())
}

/// A Google service account's email, `<account>@<domain>.gserviceaccount.com`, where
/// `{owner}` may stand in the account, before the `@`.
fn service_account_ok(p: &str) -> bool {
    let Some((account, domain)) = p.split_once('@') else { return false };
    let account = account.replace(OWNER, "x");
    let label_ok = |l: &str| !l.is_empty() && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    p.len() <= 254 && label_ok(&account) && domain.strip_suffix(".gserviceaccount.com").is_some_and(|d| d.split('.').all(label_ok))
}

/// An Entra app's client id (a GUID), optionally `@` the host of the resource its tokens
/// are for (`storage.azure.com`). No `{owner}`: app ids are GUIDs Entra chooses.
fn entra_app_ok(p: &str) -> bool {
    let (app, resource) = p.split_once('@').map_or((p, None), |(a, r)| (a, Some(r)));
    let groups: Vec<&str> = app.split('-').collect();
    let guid = groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12]) && groups.iter().all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()));
    let label_ok = |l: &str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    guid && resource.is_none_or(|r| r.len() <= 253 && r.contains('.') && r.split('.').all(label_ok))
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
    /// The options its entries may take to narrow what they make: `SESSION_OPTIONS` or
    /// `BOUNDARY_OPTIONS`, or none.
    options: &'static [&'static str],
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
    options: &[],
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
    options: SESSION_OPTIONS,
    example: "AWS_ACCESS_KEY_ID=AccessKeyId",
};

/// `GCP_RUN_CREDENTIALS` (ADR 0203): Google service accounts botd impersonates for each
/// run. A bare entry gives the token under the names gcloud and Terraform read; one with
/// `boundary=` gives it downscoped (ADR 0240).
pub const GCP: Syntax = Syntax {
    key: "GCP_RUN_CREDENTIALS",
    what: "a service account's email like \"superbot-bots@my-project.iam.gserviceaccount.com\" (with {owner} for the Bot owner's id before the @)",
    path_ok: service_account_ok,
    fields: &["accessToken"],
    defaults: &[("CLOUDSDK_AUTH_ACCESS_TOKEN", "accessToken"), ("GOOGLE_OAUTH_ACCESS_TOKEN", "accessToken")],
    own: &[],
    options: BOUNDARY_OPTIONS,
    example: "GOOGLE_OAUTH_ACCESS_TOKEN=accessToken",
};

/// `AZURE_RUN_CREDENTIALS` (ADR 0213): Entra apps that trust botd's identity as a
/// federated credential, a token of one made for each run. No Azure tool reads a token
/// from the environment, so a bare entry gives it under one plain name.
pub const AZURE: Syntax = Syntax {
    key: "AZURE_RUN_CREDENTIALS",
    what: "an Entra app's client id like \"00000000-0000-0000-0000-000000000000\", optionally @ the resource's host like \"@storage.azure.com\"",
    path_ok: entra_app_ok,
    fields: &["accessToken"],
    defaults: &[("AZURE_ACCESS_TOKEN", "accessToken")],
    own: &[],
    options: &[],
    example: "AZURE_ACCESS_TOKEN=accessToken",
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
        let mut narrowing = Narrowing::default();
        for pair in parts {
            let Some((name, field)) = pair.split_once('=') else {
                return Err(format!("{key}: {pair:?} after {path} must be NAME=field, like {}", syntax.example));
            };
            if SESSION_OPTIONS.contains(&name) || BOUNDARY_OPTIONS.contains(&name) {
                if !syntax.options.contains(&name) {
                    return Err(if SESSION_OPTIONS.contains(&name) {
                        format!("{key}: {name}= narrows AWS STS sessions, so only AWS_RUN_CREDENTIALS takes it")
                    } else {
                        format!("{key}: {name}= downscopes Google access tokens, so only GCP_RUN_CREDENTIALS takes it")
                    });
                }
                session_option(&mut narrowing, path, name, field).map_err(|e| format!("{key}: {path}: {e}"))?;
                continue;
            }
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
        out.push(Wanted { path: path.to_string(), names, narrowing });
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
    /// When the first of these leases ends for good, once that is known: it can't be
    /// revoked, can't be renewed (any more), or ran out while renewals failed.
    ends: Arc<watch::Sender<Option<Instant>>>,
    /// Keeps renewable leases alive while the run lasts; stopped before they are revoked.
    renewer: Option<Renewer>,
}

struct Renewer {
    /// Dropped to stop the thread.
    stop: mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl Renewer {
    fn stop(self) {
        drop(self.stop);
        let _ = self.thread.join();
    }
}

/// A run's lease that is renewed while the run lasts.
struct Renewing {
    id: String,
    path: String,
    bot_id: String,
    owner: Option<String>,
    /// The TTL it was made with, asked for again at each renewal, so a lease botd stops
    /// renewing ends no later than that.
    increment: Duration,
    expires: Instant,
    due: Instant,
}

/// Moves `ends` to `at` if that is sooner.
fn end_by(ends: &watch::Sender<Option<Instant>>, at: Instant) {
    ends.send_if_modified(|e| {
        let sooner = e.is_none_or(|e| at < e);
        if sooner {
            *e = Some(at);
        }
        sooner
    });
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
        Leases { issuer: None, held: Vec::new(), cleared: Vec::new(), ends: Arc::new(watch::channel(None).0), renewer: None }
    }

    /// Names to take out of the run's environment: their lease gave no value, and an
    /// older one of the same name would pair with the fresh ones.
    pub fn cleared(&self) -> &[String] {
        &self.cleared
    }

    /// When the first of these leases ends as things stand: the run must stop by then, or
    /// it would go on with credentials that no longer work. A renewed lease's end moves
    /// later only once a renewal succeeds, so a hung or failing renewal never outlasts it.
    /// None when no lease ends by itself (those revoked at run end with no TTL).
    #[cfg(test)]
    pub fn expires_first(&self) -> Option<Instant> {
        *self.ends.borrow()
    }

    /// `expires_first`, as it changes while the run lasts.
    pub fn ends(&self) -> watch::Receiver<Option<Instant>> {
        self.ends.subscribe()
    }

    /// Starts renewing `due` leases until `deadline`, or the run ends; `fixed` is when the
    /// first of the run's other leases ends. If no thread can be started they can't be
    /// renewed, and the run stops when the first ends, as `ends` already says.
    fn renew(&mut self, issuer: Arc<dyn Issuer>, due: Vec<Renewing>, fixed: Option<Instant>, deadline: Instant) {
        if due.is_empty() {
            return;
        }
        let (stop, stopped) = mpsc::channel();
        let ends = Arc::clone(&self.ends);
        match std::thread::Builder::new().name("lease-renewer".into()).spawn(move || renew_until(issuer.as_ref(), due, fixed, deadline, &ends, &stopped)) {
            Ok(thread) => self.renewer = Some(Renewer { stop, thread }),
            Err(e) => crate::obs::log::log_warn!("Secrets: a run's leases can't be renewed ({e}), so it stops when the first ends"),
        }
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
        let renewer = self.renewer.take();
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
        // Off the run's task: revoking waits on Vault, and the run has already ended. The
        // renewer stops first, so it never renews a lease being revoked.
        std::thread::spawn(move || {
            if let Some(r) = renewer {
                r.stop();
            }
            for h in held {
                revoke(issuer.as_ref(), h);
            }
        });
    }
}

/// Renews each of `leases` when due, until it lasts past `deadline`, can't be renewed any
/// more, or `stop` says the run has ended. After each, `ends` is when the first of the
/// run's leases ends now: `fixed` for those not renewed, and each renewed one's current
/// expiry, which only a renewal Vault answered moves.
fn renew_until(issuer: &dyn Issuer, mut leases: Vec<Renewing>, mut fixed: Option<Instant>, deadline: Instant, ends: &watch::Sender<Option<Instant>>, stop: &mpsc::Receiver<()>) {
    let ended = || !matches!(stop.try_recv(), Err(mpsc::TryRecvError::Empty));
    loop {
        let Some(next) = leases.iter().map(|l| l.due).min() else { return };
        if !matches!(stop.recv_timeout(next.saturating_duration_since(Instant::now())), Err(mpsc::RecvTimeoutError::Timeout)) {
            return;
        }
        let mut i = 0;
        while i < leases.len() {
            if ended() {
                return;
            }
            if leases[i].due > Instant::now() || renew_one(issuer, &mut leases[i], deadline) {
                i += 1;
            } else {
                let done = leases.swap_remove(i);
                fixed = Some(fixed.map_or(done.expires, |f| f.min(done.expires)));
            }
            let first = leases.iter().map(|l| l.expires).chain(fixed).min();
            ends.send_if_modified(|e| std::mem::replace(e, first) != first);
        }
    }
}

fn rfc3339_in(d: Duration) -> String {
    (chrono::Utc::now() + chrono::Duration::from_std(d).unwrap_or_default()).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Renews one lease that is due. False once it needs no more renewals: it lasts past
/// `deadline`, or it can't be renewed past its `expires`.
fn renew_one(issuer: &dyn Issuer, l: &mut Renewing, deadline: Instant) -> bool {
    let (e, mut d) = event("secret.lease_renewed", issuer.kind(), &l.path, &l.bot_id, l.owner.as_deref());
    d["leaseId"] = json!(l.id);
    let now = Instant::now();
    if now >= l.expires {
        crate::obs::log::log_warn!("Secrets: a run's lease from {} ran out before it could be renewed, so the run stops", l.path);
        d["error"] = json!("expired");
        external::audit(e.outcome(Outcome::Failure).details(d));
        return false;
    }
    // Never past the deadline, so the last renewal ends with it rather than an increment later.
    let ask = l.increment.min(deadline.saturating_duration_since(now)).as_secs_f64().ceil().max(1.0) as u64;
    d["increment"] = json!(ask);
    match issuer.renew(&l.id, Duration::from_secs(ask)) {
        Ok(Renewal::Renewed { ttl, renewable }) => {
            let ttl = ttl.min(MAX_TTL);
            l.expires = now + Duration::from_secs(ttl);
            d["ttl"] = json!(ttl);
            d["expiresAt"] = json!(rfc3339_in(Duration::from_secs(ttl)));
            if l.expires >= deadline {
                external::audit(e.details(d));
                return false;
            }
            // Short of what was asked: the role's max TTL (or the token's) is reached.
            if ttl < ask || !renewable {
                crate::obs::log::log_warn!(
                    "Secrets: a run's lease from {} can't be renewed past {ttl} s more, so the run stops then; raise the role's max_ttl over RUN_TIMEOUT_MINUTES",
                    l.path
                );
                d["final"] = json!(true);
                external::audit(e.details(d));
                return false;
            }
            external::audit(e.details(d));
            l.due = now + (Duration::from_secs(ttl) * 2 / 3).max(Duration::from_millis(500));
            true
        }
        Ok(Renewal::Refused(why)) => {
            crate::obs::log::log_warn!("Secrets: a run's lease from {} wasn't renewed, so the run stops when it ends: {why}", l.path);
            d["error"] = json!("refused");
            external::audit(e.outcome(Outcome::Failure).details(d));
            false
        }
        Err(err) => {
            crate::obs::log::log_warn!("Secrets: a run's lease from {} couldn't be renewed yet, trying again: {err}", l.path);
            d["error"] = json!(err.kind());
            external::audit(e.outcome(Outcome::Failure).details(d));
            let left = l.expires.saturating_duration_since(Instant::now());
            l.due = Instant::now() + (left / 3).clamp(Duration::from_secs(1), RETRY_MAX);
            true
        }
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
    /// How long past the longest run renewals keep leases alive.
    margin: Duration,
}

impl RunCredentials {
    pub fn new(issuer: Arc<dyn Issuer>, wanted: Vec<Wanted>) -> RunCredentials {
        RunCredentials { issuer, wanted, margin: RENEW_MARGIN }
    }

    #[cfg(test)]
    pub(crate) fn with_margin(mut self, margin: Duration) -> RunCredentials {
        self.margin = margin;
        self
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

    /// For the startup line: paths, and which sessions are narrowed.
    pub fn describe(&self) -> String {
        let paths: Vec<String> = self.wanted.iter().map(|w| if w.narrowing.is_empty() { w.path.clone() } else { format!("{} (narrowed)", w.path) }).collect();
        format!("short-lived credentials for each run from {}", paths.join(", "))
    }

    /// New leases for one run of `bot_id`, owned by `owner`, and the variables they give.
    /// Paths with `{owner}` only when `owner_keys` and the id can name one (as for users'
    /// folders, ADR 0174). `run_for` is the longest the run may last. On an error the
    /// leases already made are revoked.
    pub fn issue(&self, owner: &str, bot_id: &str, owner_keys: bool, run_for: Duration) -> Result<(Vec<(String, Secret)>, Leases), Error> {
        forget_expired();
        let deadline = Instant::now() + run_for + self.margin;
        let mut leases = Leases::none();
        leases.issuer = Some(Arc::clone(&self.issuer));
        let mut due = Vec::new();
        // When the first lease that isn't renewed ends.
        let mut fixed: Option<Instant> = None;
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
            let narrowed = match w.narrowing.for_run(owner, bot_id) {
                Ok(n) => n,
                Err(why) => {
                    d["error"] = json!("narrowing");
                    external::audit(e.outcome(Outcome::Failure).details(d));
                    return Err(Error::Unavailable(format!("{}: {path}: {why}", self.issuer.kind())));
                }
            };
            if let Some(p) = &narrowed.policy {
                d["policySha256"] = json!(crate::sigv4::sha256_hex(p.as_bytes()));
            }
            if !narrowed.policy_arns.is_empty() {
                d["policyArns"] = json!(narrowed.policy_arns);
            }
            if !narrowed.tags.is_empty() {
                d["tags"] = Value::Object(narrowed.tags.iter().map(|(k, v)| (k.to_string(), json!(v))).collect());
            }
            if let Some(b) = &narrowed.boundary {
                d["boundarySha256"] = json!(crate::sigv4::sha256_hex(b.as_bytes()));
            }
            let fields: Vec<String> = w.names.iter().map(|(_, f)| f.clone()).collect();
            let lease = match self.issuer.issue_narrowed(&path, &fields, run_for, bot_id, &narrowed) {
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
            // A revocable lease with no TTL (0) is ended by the revoke alone.
            if !(self.issuer.revocable() && ttl == 0) {
                end_by(&leases.ends, held.expires);
                if self.issuer.revocable() && lease.renewable && held.expires < deadline {
                    due.push(Renewing {
                        id: held.id.clone(),
                        path: path.clone(),
                        bot_id: bot_id.to_string(),
                        owner: held.owner.clone(),
                        increment: Duration::from_secs(ttl),
                        expires: held.expires,
                        due: Instant::now() + Duration::from_secs(ttl) * 2 / 3,
                    });
                } else {
                    fixed = Some(fixed.map_or(held.expires, |f: Instant| f.min(held.expires)));
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
        leases.renew(Arc::clone(&self.issuer), due, fixed, deadline);
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
        /// Leases are made not renewable.
        pub not_renewable: AtomicBool,
        /// (lease id, increment asked for) of each renewal.
        pub renewals: Mutex<Vec<(String, u64)>>,
        /// The most a renewal gives (0: what was asked), as a role's max TTL.
        pub renew_cap: AtomicU64,
        pub renew_refused: AtomicBool,
        pub renew_down: AtomicBool,
        /// How long each renewal takes to answer.
        pub renew_delay_ms: AtomicU64,
        /// (path, what its session was narrowed to) of each lease asked for.
        pub narrowed: Mutex<Vec<(String, Narrowed)>>,
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
            Ok(Lease { id: format!("{path}/lease{n}"), ttl, renewable: !self.not_renewable.load(Ordering::SeqCst), fields })
        }
        fn issue_narrowed(&self, path: &str, fields: &[String], run_for: Duration, bot_id: &str, narrowed: &Narrowed) -> Result<Lease, Error> {
            self.narrowed.lock().unwrap().push((path.to_string(), narrowed.clone()));
            self.issue(path, fields, run_for, bot_id)
        }
        fn revoke(&self, lease_id: &str) -> Result<(), Error> {
            if self.revoke_down.load(Ordering::SeqCst) {
                return Err(Error::Unavailable("fake can't revoke".into()));
            }
            self.revoked.lock().unwrap().push(lease_id.to_string());
            Ok(())
        }
        fn renew(&self, lease_id: &str, increment: Duration) -> Result<Renewal, Error> {
            if self.renew_down.load(Ordering::SeqCst) {
                return Err(Error::Unavailable("fake can't renew".into()));
            }
            let asked = increment.as_secs();
            self.renewals.lock().unwrap().push((lease_id.to_string(), asked));
            std::thread::sleep(Duration::from_millis(self.renew_delay_ms.load(Ordering::SeqCst)));
            if self.renew_refused.load(Ordering::SeqCst) || self.revoked.lock().unwrap().iter().any(|r| r == lease_id) {
                return Ok(Renewal::Refused("fake won't renew it".into()));
            }
            let ttl = match self.renew_cap.load(Ordering::SeqCst) {
                0 => asked,
                cap => asked.min(cap),
            };
            Ok(Renewal::Renewed { ttl, renewable: true })
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
        assert!(l1.expires_first().is_some_and(|at| at <= Instant::now() + Duration::from_secs(900)) && Leases::none().expires_first().is_none(), "when the first ends as things stand");
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
    fn azure_apps_are_checked_and_default_to_one_plain_name() {
        let w = parse_as(&AZURE, "11111111-2222-3333-4444-555555555555;\n 66666666-7777-8888-9999-AAAAAAAAAAAA@storage.azure.com BLOB_TOKEN=accessToken").unwrap();
        assert_eq!(w[0].path, "11111111-2222-3333-4444-555555555555");
        assert_eq!(w[0].names, [pair("AZURE_ACCESS_TOKEN", "accessToken")]);
        assert_eq!((w[1].path.as_str(), w[1].names[0].0.as_str()), ("66666666-7777-8888-9999-AAAAAAAAAAAA@storage.azure.com", "BLOB_TOKEN"));
        assert!(!w[0].per_owner() && !w[1].per_owner());
        assert!(parse_as(&AZURE, "11111111-2222-3333-4444-555555555555@management.usgovcloudapi.net").is_ok());
        for (raw, err) in [
            ("superbot-bots@proj-1.iam.gserviceaccount.com", "Entra app's client id"),
            ("11111111-2222-3333-4444-55555555555", "Entra app's client id"),
            ("11111111-2222-3333-4444-55555555555g", "Entra app's client id"),
            ("111111112222-3333-4444-555555555555", "Entra app's client id"),
            ("{owner}-2222-3333-4444-555555555555", "Entra app's client id"),
            ("11111111-2222-3333-4444-555555555555@", "Entra app's client id"),
            ("11111111-2222-3333-4444-555555555555@localhost", "Entra app's client id"),
            ("11111111-2222-3333-4444-555555555555@Storage.azure.com", "Entra app's client id"),
            ("11111111-2222-3333-4444-555555555555@storage.azure.com/x", "Entra app's client id"),
            ("11111111-2222-3333-4444-555555555555@-x.azure.com", "Entra app's client id"),
            ("11111111-2222-3333-4444-555555555555@a@b.com", "Entra app's client id"),
            ("11111111-2222-3333-4444-555555555555 X_TOKEN=expiresOn", "one of accessToken"),
            ("11111111-2222-3333-4444-555555555555 X_TOKEN", "like AZURE_ACCESS_TOKEN=accessToken"),
            ("11111111-2222-3333-4444-555555555555; 66666666-7777-8888-9999-aaaaaaaaaaaa", "AZURE_ACCESS_TOKEN is given twice"),
            ("11111111-2222-3333-4444-555555555555 AZURE_CLIENT_SECRET=accessToken", "reserved"),
        ] {
            let e = parse_as(&AZURE, raw).unwrap_err();
            assert!(e.starts_with("AZURE_RUN_CREDENTIALS: ") && e.contains(err), "{raw}: {e}");
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

    fn renewed(path: &str) -> Vec<crate::audit::Event> {
        external::tests::audited(path).into_iter().filter(|e| e.action == "secret.lease_renewed").collect()
    }

    #[test]
    fn renewable_leases_are_renewed_while_the_run_lasts_and_not_after() {
        let f = fake(&[("renew/creds/r", &[("token", Some("renew-run-token-1a2b"))])]);
        f.ttl.store(2, Ordering::SeqCst);
        let rc = RunCredentials::new(f.clone(), parse("renew/creds/r RENEW_TOKEN=token").unwrap());
        let (_, l) = rc.issue("urenew1", "brenew1", true, RUN).unwrap();
        let first = l.expires_first().expect("its TTL, until a renewal moves it");
        assert!(first <= Instant::now() + Duration::from_secs(2));
        wait_for(|| f.renewals.lock().unwrap().len() >= 2);
        assert!(f.renewals.lock().unwrap().iter().all(|(id, n)| id == "renew/creds/r/lease0" && *n == 2), "by the TTL it was made with, never more: {:?}", f.renewals.lock().unwrap());
        wait_for(|| l.expires_first().is_some_and(|at| at > first + Duration::from_secs(2)));
        assert_eq!(redact::text("renew-run-token-1a2b-0"), redact::MARK, "still live, still redacted");
        let ev = renewed("renew/creds/r");
        assert!(ev.len() >= 2 && ev.iter().all(|e| e.outcome == Outcome::Success && e.bot_id.as_deref() == Some("brenew1")), "{ev:?}");
        assert_eq!((ev[0].details["leaseId"].as_str(), ev[0].details["increment"].as_u64(), ev[0].details["ttl"].as_u64()), (Some("renew/creds/r/lease0"), Some(2), Some(2)));
        let at = chrono::DateTime::parse_from_rfc3339(ev[0].details["expiresAt"].as_str().unwrap()).unwrap();
        assert!((at.timestamp() - chrono::Utc::now().timestamp()).abs() <= 3, "{at}");
        assert!(ev[0].details.get("final").is_none() && !format!("{ev:?}").contains("renew-run-token"), "never a value");

        drop(l);
        wait_for(|| f.revoked.lock().unwrap().len() == 1);
        let n = f.renewals.lock().unwrap().len();
        std::thread::sleep(Duration::from_millis(1600));
        assert_eq!(f.renewals.lock().unwrap().len(), n, "the renewer stopped before the revoke, and nothing renews it after");
    }

    #[test]
    fn renewals_stop_once_a_lease_outlasts_the_run() {
        let f = fake(&[("renew/creds/edge", &[("token", Some("edge-run-token-3c4d"))])]);
        f.ttl.store(3, Ordering::SeqCst);
        let rc = RunCredentials::new(f.clone(), parse("renew/creds/edge EDGE_TOKEN=token").unwrap()).with_margin(Duration::ZERO);
        let started = Instant::now();
        let (_, l) = rc.issue("uedge2", "bedge2", true, Duration::from_secs(4)).unwrap();
        wait_for(|| !f.renewals.lock().unwrap().is_empty());
        std::thread::sleep(Duration::from_millis(2500));
        assert_eq!(*f.renewals.lock().unwrap(), [("renew/creds/edge/lease0".to_string(), 2)], "the last renewal asks only up to the run's end, then none");
        assert!(l.expires_first().is_some_and(|at| at >= started + Duration::from_secs(4)), "it lasts the run");

        // A lease that already outlasts the run, or has no TTL, needs none.
        f.ttl.store(900, Ordering::SeqCst);
        let (_, l) = rc.issue("uedge2", "bedge2", true, Duration::from_secs(60)).unwrap();
        assert!(l.renewer.is_none() && l.expires_first().is_some_and(|at| at > Instant::now() + Duration::from_secs(800)));
    }

    #[test]
    fn a_lease_that_cant_be_renewed_far_enough_ends_the_run_with_it() {
        let f = fake(&[("renew/creds/capped", &[("token", Some("capped-run-token-5e6f"))])]);
        f.ttl.store(2, Ordering::SeqCst);
        f.renew_cap.store(1, Ordering::SeqCst);
        let rc = RunCredentials::new(f.clone(), parse("renew/creds/capped CAPPED_TOKEN=token").unwrap());
        let started = Instant::now();
        let (_, l) = rc.issue("ucap3", "bcap3", true, RUN).unwrap();
        let mut ends = l.ends();
        assert!(ends.borrow_and_update().is_some_and(|at| at <= Instant::now() + Duration::from_secs(2)));
        wait_for(|| ends.has_changed().unwrap());
        let at = l.expires_first().unwrap();
        assert!(at > started + Duration::from_millis(2200) && at < started + Duration::from_secs(4), "when the short renewal ends: {:?}", at - started);
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(f.renewals.lock().unwrap().len(), 1, "no point asking again");
        let ev = renewed("renew/creds/capped");
        assert_eq!((ev.len(), ev[0].outcome, ev[0].details["ttl"].as_u64(), ev[0].details["final"].as_bool()), (1, Outcome::Success, Some(1), Some(true)), "{ev:?}");

        // Leases made not renewable end the run when they do, with no renewal tried.
        let f = fake(&[("renew/creds/fixed", &[("token", Some("fixed-run-token-5e6f"))])]);
        f.ttl.store(30, Ordering::SeqCst);
        f.not_renewable.store(true, Ordering::SeqCst);
        let rc = RunCredentials::new(f.clone(), parse("renew/creds/fixed FIXED_TOKEN=token").unwrap());
        let (_, l) = rc.issue("ucap3", "bcap3", true, RUN).unwrap();
        assert!(l.expires_first().is_some_and(|at| at <= Instant::now() + Duration::from_secs(30)));
        assert!(l.renewer.is_none() && f.renewals.lock().unwrap().is_empty());
    }

    #[test]
    fn a_refused_renewal_ends_the_run_when_the_lease_does() {
        let f = fake(&[("renew/creds/refused", &[("token", Some("refused-run-token-7a8b"))])]);
        f.ttl.store(2, Ordering::SeqCst);
        f.renew_refused.store(true, Ordering::SeqCst);
        let rc = RunCredentials::new(f.clone(), parse("renew/creds/refused REFUSED_TOKEN=token").unwrap());
        let started = Instant::now();
        let (_, l) = rc.issue("uref4", "bref4", true, RUN).unwrap();
        wait_for(|| !renewed("renew/creds/refused").is_empty());
        assert!(l.expires_first().unwrap() <= started + Duration::from_secs(3), "when it would have ended anyway");
        let ev = renewed("renew/creds/refused");
        assert_eq!((ev.len(), ev[0].outcome, ev[0].details["error"].as_str()), (1, Outcome::Failure, Some("refused")), "{ev:?}");
    }

    #[test]
    fn failed_renewals_are_tried_again_until_the_lease_runs_out() {
        let f = fake(&[("renew/creds/flaky", &[("token", Some("flaky-run-token-9c0d"))]), ("renew/creds/gone", &[("token", Some("gone-run-token-9c0d"))])]);
        f.ttl.store(6, Ordering::SeqCst);
        f.renew_down.store(true, Ordering::SeqCst);
        let rc = RunCredentials::new(f.clone(), parse("renew/creds/flaky FLAKY_TOKEN=token").unwrap());
        let (_, l) = rc.issue("uflaky5", "bflaky5", true, RUN).unwrap();
        let first = l.expires_first().unwrap();
        wait_for(|| !renewed("renew/creds/flaky").is_empty());
        assert_eq!(l.expires_first(), Some(first), "a failed renewal doesn't move it");
        f.renew_down.store(false, Ordering::SeqCst);
        wait_for(|| renewed("renew/creds/flaky").iter().any(|e| e.outcome == Outcome::Success));
        let ev = renewed("renew/creds/flaky");
        assert_eq!((ev[0].outcome, ev[0].details["error"].as_str()), (Outcome::Failure, Some("unavailable")), "{ev:?}");
        wait_for(|| l.expires_first().is_some_and(|at| at > first));
        drop(l);

        // Down until the lease runs out: the run stops then.
        f.ttl.store(3, Ordering::SeqCst);
        f.renew_down.store(true, Ordering::SeqCst);
        let rc = RunCredentials::new(f.clone(), parse("renew/creds/gone GONE_TOKEN=token").unwrap());
        let (_, l) = rc.issue("uflaky5", "bflaky5", true, RUN).unwrap();
        wait_for(|| renewed("renew/creds/gone").last().is_some_and(|e| e.details["error"] == "expired"));
        assert!(l.expires_first().unwrap() <= Instant::now());
        let ev = renewed("renew/creds/gone");
        assert!(ev.iter().any(|e| e.details["error"] == "unavailable") && ev.last().unwrap().details["error"] == "expired", "{ev:?}");
    }

    #[test]
    fn a_renewal_that_hangs_never_holds_the_runs_end_past_the_lease() {
        let f = fake(&[("renew/creds/hung", &[("token", Some("hung-run-token-1e2f"))])]);
        f.ttl.store(2, Ordering::SeqCst);
        f.renew_delay_ms.store(4000, Ordering::SeqCst);
        let rc = RunCredentials::new(f.clone(), parse("renew/creds/hung HUNG_TOKEN=token").unwrap());
        let (_, l) = rc.issue("uhung6", "bhung6", true, RUN).unwrap();
        let issued = Instant::now();
        wait_for(|| !f.renewals.lock().unwrap().is_empty());
        std::thread::sleep(Duration::from_millis(1000));
        assert!(renewed("renew/creds/hung").is_empty(), "the renewal is still waiting on the backend");
        let at = l.expires_first().unwrap();
        assert!(at <= issued + Duration::from_secs(2) && at <= Instant::now(), "the run's end is the lease's, past now, though the renewal hasn't answered");
    }

    /// A policy file in its own folder, its path.
    pub(crate) fn policy_file(label: &str, text: &str) -> String {
        let file = crate::db::temp_path(label).join("policy.json");
        std::fs::write(&file, text).unwrap();
        file.to_string_lossy().into_owned()
    }

    const BOTS_POLICY: &str = r#"{
        "Version": "2012-10-17",
        "Statement": [{ "Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::acme-bots/{bot}/*" }]
    }"#;
    const OWNER_POLICY: &str = r#"{ "Version": "2012-10-17", "Statement": { "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-users/{owner}/*" } }"#;

    #[test]
    fn aws_entries_narrow_their_sessions_and_are_checked() {
        let bots = policy_file("narrow-bots", BOTS_POLICY);
        let owners = policy_file("narrow-owners", OWNER_POLICY);
        let raw = format!(
            "arn:aws:iam::123456789012:role/bots policy={bots} policy-arn=arn:aws:iam::aws:policy/ReadOnlyAccess tags=bot;\
             arn:aws:iam::123456789012:role/users tags=bot,owner policy-arn=arn:aws:iam::123456789012:policy/u-{{owner}} USER_KEY_ID=AccessKeyId USER_SECRET=SecretAccessKey USER_TOKEN=SessionToken;\
             arn:aws:iam::123456789012:role/shared SHARED_KEY_ID=AccessKeyId SHARED_SECRET=SecretAccessKey SHARED_TOKEN=SessionToken policy={owners}"
        );
        let w = parse_as(&AWS, &raw).unwrap();
        assert_eq!(w[0].names, [pair("AWS_ACCESS_KEY_ID", "AccessKeyId"), pair("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"), pair("AWS_SESSION_TOKEN", "SessionToken")], "options aren't variables: the SDKs' names still");
        assert_eq!(w[0].narrowing.policy.as_ref().unwrap()["Statement"][0]["Resource"], "arn:aws:s3:::acme-bots/{bot}/*", "read once, at startup");
        assert_eq!((w[0].narrowing.policy_arns.as_slice(), w[0].narrowing.tags.as_slice()), (&["arn:aws:iam::aws:policy/ReadOnlyAccess".to_string()][..], &[Tag::Bot][..]));
        assert!(!w[0].per_owner(), "{{bot}} is every run's");
        assert_eq!(w[1].narrowing.tags, [Tag::Bot, Tag::Owner]);
        assert!(w[1].per_owner() && w[2].per_owner(), "tagged with the owner, or a policy naming them: the owner's runs only");
        assert!(parse_as(&AWS, "arn:aws:iam::123456789012:role/r policy-arn=arn:aws:iam::123456789012:policy/team/{owner}-read").unwrap()[0].per_owner());

        let big = policy_file("narrow-big", &format!(r#"{{"Statement":[{{"Effect":"Allow","Action":"s3:GetObject","Resource":"{}"}}]}}"#, "x".repeat(MAX_POLICY)));
        let latin = policy_file("narrow-latin", r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::caf\u00e9"}]}"#);
        let wide = policy_file("narrow-wide", r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::\u0100"}]}"#);
        let nostatement = policy_file("narrow-nostatement", r#"{"Version":"2012-10-17"}"#);
        let notjson = policy_file("narrow-notjson", "Statement: allow everything, secret-in-a-bad-file-1f2e");
        let huge = policy_file("narrow-huge", &" ".repeat(MAX_POLICY_FILE as usize + 1));
        assert!(parse_as(&AWS, &format!("arn:aws:iam::123456789012:role/r policy={latin}")).is_ok(), "Latin-1 is what STS takes");
        let accents = policy_file("narrow-accents", &format!(r#"{{"Statement":[{{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::{}"}}]}}"#, "é".repeat(1900)));
        let w = parse_as(&AWS, &format!("arn:aws:iam::123456789012:role/r policy={accents}")).unwrap();
        let sent = w[0].narrowing.for_run("u1", "b1").unwrap().policy.unwrap();
        assert!(sent.len() > MAX_POLICY && sent.chars().count() <= MAX_POLICY, "STS's limit is in characters, not UTF-8 bytes");
        let role = "arn:aws:iam::123456789012:role/r";
        let arn = |n: usize| format!("arn:aws:iam::123456789012:policy/p{n}");
        let eleven: Vec<String> = (0..=MAX_POLICY_ARNS).map(|n| format!("policy-arn={}", arn(n))).collect();
        for (raw, err) in [
            (format!("{role} policy=/nonexistent/superbot/policy.json"), "policy=/nonexistent/superbot/policy.json: can't be read"),
            (format!("{role} policy={notjson}"), "isn't JSON"),
            (format!("{role} policy={nostatement}"), "a JSON object with a Statement"),
            (format!("{role} policy={big}"), "over STS's 2048; move statements to a managed policy"),
            (format!("{role} policy={wide}"), "only up to U+00FF"),
            (format!("{role} policy={huge}"), "is over 65536 bytes"),
            (format!("{role} policy={bots} policy={owners}"), "policy= is given twice"),
            (format!("{role} policy-arn=arn:aws:iam::123456789012:role/r"), "must be a managed policy's ARN"),
            (format!("{role} policy-arn=arn:aws:iam::aws:policy/*"), "must be a managed policy's ARN"),
            (format!("{role} policy-arn=arn:aws:iam::aws:policy/"), "must be a managed policy's ARN"),
            ("arn:aws-us-gov:iam::123456789012:role/r policy-arn=arn:aws:iam::aws:policy/ReadOnlyAccess".to_string(), "in the role's partition"),
            (format!("{role} policy-arn={} policy-arn={}", arn(1), arn(1)), "is given twice"),
            (format!("{role} {}", eleven.join(" ")), "at most 10 policy-arn="),
            (format!("{role} tags=everyone"), "tags= takes bot, owner or both"),
            (format!("{role} tags="), "tags= takes bot, owner or both"),
            (format!("{role} tags=bot,bot"), "names bot twice"),
            (format!("{role} tags=bot tags=owner"), "tags= is given twice"),
        ] {
            let e = parse_as(&AWS, &raw).unwrap_err();
            assert!(e.starts_with("AWS_RUN_CREDENTIALS: arn:aws") && e.contains(err), "{raw}: {e}");
            assert!(!e.contains("secret-in-a-bad-file"), "a policy file is never quoted: {e}");
        }
        for (syntax, raw) in [(&VAULT, "aws/sts/bots X_KEY=access_key tags=bot"), (&GCP, "a@p.iam.gserviceaccount.com policy-arn=x"), (&AZURE, "11111111-2222-3333-4444-555555555555 policy=/x")] {
            let e = parse_as(syntax, raw).unwrap_err();
            assert!(e.contains("narrows AWS STS sessions, so only AWS_RUN_CREDENTIALS takes it"), "{raw}: {e}");
        }
    }

    fn sts_fake(roles: &[&str]) -> Arc<Fake> {
        let fields: &[(&str, Option<&str>)] = &[("AccessKeyId", Some("ASIANARROW")), ("SecretAccessKey", Some("narrow-secret-4d3c")), ("SessionToken", Some("narrow-token-4d3c"))];
        let f = fake(&roles.iter().map(|r| (*r, fields)).collect::<Vec<_>>());
        f.unrevocable.store(true, Ordering::SeqCst);
        f.ttl.store(3600, Ordering::SeqCst);
        f
    }

    #[test]
    fn narrowed_sessions_get_the_runs_ids_and_are_audited() {
        let bots = policy_file("narrowed-bots", BOTS_POLICY);
        let owners = policy_file("narrowed-owners", OWNER_POLICY);
        let f = sts_fake(&["arn:aws:iam::123456789012:role/nbots", "arn:aws:iam::123456789012:role/nusers", "arn:aws:iam::123456789012:role/nshared"]);
        let raw = format!(
            "arn:aws:iam::123456789012:role/nbots policy={bots} policy-arn=arn:aws:iam::aws:policy/ReadOnlyAccess tags=bot;\
             arn:aws:iam::123456789012:role/nusers tags=bot,owner policy-arn=arn:aws:iam::123456789012:policy/u-{{owner}} USER_KEY_ID=AccessKeyId;\
             arn:aws:iam::123456789012:role/nshared policy={owners} SHARED_KEY_ID=AccessKeyId"
        );
        let rc = RunCredentials::new(f.clone(), parse_as(&AWS, &raw).unwrap());
        assert!(rc.describe().contains("role/nbots (narrowed), arn:aws:iam::123456789012:role/nusers (narrowed)"), "{}", rc.describe());

        let (e, _l) = rc.issue("unar1", "bnar1", true, RUN).unwrap();
        assert_eq!(env(&e).len(), 5);
        let narrowed = f.narrowed.lock().unwrap().clone();
        let [(p0, n0), (p1, n1), (p2, n2)] = &narrowed[..] else { panic!("{narrowed:?}") };
        assert_eq!((p0.as_str(), p1.as_str(), p2.as_str()), ("arn:aws:iam::123456789012:role/nbots", "arn:aws:iam::123456789012:role/nusers", "arn:aws:iam::123456789012:role/nshared"));
        let sent: Value = serde_json::from_str(n0.policy.as_deref().unwrap()).unwrap();
        assert_eq!(sent["Statement"][0]["Resource"], "arn:aws:s3:::acme-bots/bnar1/*", "the run's Bot in place");
        assert!(!n0.policy.as_deref().unwrap().contains(['\n', ' ']), "sent with no spaces, as STS counts it");
        assert_eq!((n0.policy_arns.as_slice(), n0.tags.as_slice()), (&["arn:aws:iam::aws:policy/ReadOnlyAccess".to_string()][..], &[("superbot-bot", "bnar1".to_string())][..]));
        assert_eq!(n1.tags, [("superbot-bot", "bnar1".to_string()), ("superbot-owner", "unar1".to_string())]);
        assert_eq!((n1.policy.as_deref(), n1.policy_arns.as_slice()), (None, &["arn:aws:iam::123456789012:policy/u-unar1".to_string()][..]));
        assert!(n2.policy.as_deref().unwrap().contains("acme-users/unar1/*") && n2.tags.is_empty());

        let ev = external::tests::audited("arn:aws:iam::123456789012:role/nbots");
        let issued = ev.iter().find(|e| e.action == "secret.lease_issued" && e.bot_id.as_deref() == Some("bnar1")).unwrap();
        assert_eq!(issued.details["policySha256"], crate::sigv4::sha256_hex(n0.policy.as_deref().unwrap().as_bytes()), "which policy, never the file's path");
        assert_eq!((issued.details["policyArns"].clone(), issued.details["tags"].clone()), (json!(["arn:aws:iam::aws:policy/ReadOnlyAccess"]), json!({ "superbot-bot": "bnar1" })));
        let users = external::tests::audited("arn:aws:iam::123456789012:role/nusers");
        let issued = users.iter().find(|e| e.action == "secret.lease_issued").unwrap();
        assert_eq!((issued.details["tags"].clone(), issued.details["userId"].as_str()), (json!({ "superbot-bot": "bnar1", "superbot-owner": "unar1" }), Some("unar1")));
        assert!(issued.details.get("policySha256").is_none());

        // A run for someone else: none of the entries naming the owner.
        f.narrowed.lock().unwrap().clear();
        let (e, _l) = rc.issue("unar1", "bnar1", false, RUN).unwrap();
        assert_eq!(env(&e).into_iter().map(|(k, _)| k).collect::<Vec<_>>(), ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]);
        assert_eq!(f.narrowed.lock().unwrap().len(), 1);
        assert_eq!(rc.names_for("unar1", false), ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]);
    }

    #[test]
    fn a_session_that_cant_be_narrowed_refuses_the_run() {
        let bots = policy_file("unnarrowable-bots", BOTS_POLICY);
        let f = sts_fake(&["arn:aws:iam::123456789012:role/plain", "arn:aws:iam::123456789012:role/tagged"]);
        let rc = RunCredentials::new(f.clone(), parse_as(&AWS, "arn:aws:iam::123456789012:role/plain; arn:aws:iam::123456789012:role/tagged tags=bot X_KEY_ID=AccessKeyId").unwrap());
        for bad in ["b*", "b/../x", "", &"b".repeat(65)] {
            let e = rc.issue("ubad2", bad, true, RUN).err().unwrap().to_string();
            assert!(e.contains("role/tagged") && e.contains("can't stand in a session policy or tag"), "{bad:?}: {e}");
        }
        let ev = external::tests::audited("arn:aws:iam::123456789012:role/tagged");
        assert!(ev.iter().any(|e| e.action == "secret.lease_issued" && e.outcome == Outcome::Failure && e.details["error"] == "narrowing"), "{ev:?}");
        assert!(f.narrowed.lock().unwrap().iter().all(|(p, _)| p.ends_with("/plain")), "never asked for a session it couldn't narrow");
        let rc = RunCredentials::new(f.clone(), parse_as(&AWS, &format!("arn:aws:iam::123456789012:role/plain policy={bots}")).unwrap());
        assert!(rc.issue("ubad2", "b-x_1", true, RUN).is_ok(), "letters, digits, - and _");

        // Grown past STS's limit once the owner's id is in.
        let resources = vec!["arn:aws:s3:::b/{owner}"; 70];
        let long = policy_file("unnarrowable-long", &json!({ "Statement": [{ "Effect": "Allow", "Action": "s3:GetObject", "Resource": resources }] }).to_string());
        let f = sts_fake(&["arn:aws:iam::123456789012:role/long"]);
        let rc = RunCredentials::new(f.clone(), parse_as(&AWS, &format!("arn:aws:iam::123456789012:role/long policy={long}")).unwrap());
        assert!(rc.issue("u1", "blong3", true, RUN).is_ok());
        let e = rc.issue(&"u".repeat(64), "blong3", true, RUN).err().unwrap().to_string();
        assert!(e.contains("with this run's ids in it, over STS's 2048"), "{e}");

        // A backend that can't narrow its leases refuses rather than make a wider one.
        struct Plain;
        impl Issuer for Plain {
            fn kind(&self) -> &'static str {
                "plain"
            }
            fn issue(&self, path: &str, _: &[String], _: Duration, _: &str) -> Result<Lease, Error> {
                Ok(Lease { id: path.into(), ttl: 60, renewable: false, fields: Vec::new() })
            }
            fn revoke(&self, _: &str) -> Result<(), Error> {
                Ok(())
            }
        }
        let tagged = Narrowed { tags: vec![("superbot-bot", "b1".into())], ..Narrowed::default() };
        let e = Plain.issue_narrowed("p", &[], RUN, "b1", &tagged).err().unwrap().to_string();
        assert!(e.contains("plain: leases can't be narrowed"), "{e}");
        let bounded = Narrowed { boundary: Some("{}".into()), ..Narrowed::default() };
        assert!(Plain.issue_narrowed("p", &[], RUN, "b1", &bounded).is_err(), "nor downscoped");
        assert!(!bounded.narrows_session() && tagged.narrows_session());
        assert!(Plain.issue_narrowed("p", &[], RUN, "b1", &Narrowed::default()).is_ok());
    }

    pub(crate) const BOUNDARY: &str = r#"{
        "accessBoundary": { "accessBoundaryRules": [{
            "availableResource": "//storage.googleapis.com/projects/_/buckets/acme-bots",
            "availablePermissions": ["inRole:roles/storage.objectViewer", "inRole:roles/storage.objectCreator"],
            "availabilityCondition": { "title": "this Bot's own", "expression": "resource.name.startsWith('projects/_/buckets/acme-bots/objects/{bot}/')" }
        }] }
    }"#;
    const OWNER_BOUNDARY: &str = r#"{ "accessBoundary": { "accessBoundaryRules": [{ "availableResource": "//storage.googleapis.com/projects/_/buckets/acme-u-{owner}", "availablePermissions": ["inRole:roles/storage.objectAdmin"] }] } }"#;

    /// A boundary with `rules` (JSON), in a file of its own.
    fn rules_file(label: &str, rules: &str) -> String {
        policy_file(label, &format!(r#"{{"accessBoundary":{{"accessBoundaryRules":{rules}}}}}"#))
    }

    #[test]
    fn gcp_entries_downscope_their_tokens_and_are_checked() {
        let bots = policy_file("boundary-bots", BOUNDARY);
        let owners = policy_file("boundary-owners", OWNER_BOUNDARY);
        let w = parse_as(&GCP, &format!("superbot-bots@p.iam.gserviceaccount.com boundary={bots}; superbot-users@p.iam.gserviceaccount.com USER_GCP_TOKEN=accessToken boundary={owners}")).unwrap();
        assert_eq!(w[0].names, [pair("CLOUDSDK_AUTH_ACCESS_TOKEN", "accessToken"), pair("GOOGLE_OAUTH_ACCESS_TOKEN", "accessToken")], "an option isn't a variable");
        assert_eq!(w[0].narrowing.boundary.as_ref().unwrap()["accessBoundary"]["accessBoundaryRules"][0]["availableResource"], "//storage.googleapis.com/projects/_/buckets/acme-bots", "read once, at startup");
        assert!(!w[0].per_owner() && w[1].per_owner(), "a boundary naming the owner: the owner's runs only");

        let n = w[0].narrowing.for_run("u1", "bdown-1").unwrap();
        assert!(!n.is_empty() && !n.narrows_session() && n.policy.is_none() && n.tags.is_empty());
        let sent = n.boundary.unwrap();
        assert!(!sent.contains('\n'), "sent compact");
        let back: Value = serde_json::from_str(&sent).unwrap();
        assert_eq!(back["accessBoundary"]["accessBoundaryRules"][0]["availabilityCondition"]["expression"], "resource.name.startsWith('projects/_/buckets/acme-bots/objects/bdown-1/')", "the run's Bot in place, as a JSON string");
        assert!(w[1].narrowing.for_run("uown9", "b*").unwrap().boundary.unwrap().contains("acme-u-uown9"), "a Bot id not in the boundary needn't stand in one");
        for bad in ["b*", "b'||true||'", ""] {
            let e = w[0].narrowing.for_run("u1", bad).unwrap_err();
            assert!(e.contains("can't stand in an access boundary"), "{bad:?}: {e}");
        }

        let rule = r#""availableResource":"//storage.googleapis.com/projects/_/buckets/b","availablePermissions":["inRole:roles/storage.objectViewer"]"#;
        let eleven = format!("[{}]", vec![format!("{{{rule}}}"); MAX_BOUNDARY_RULES + 1].join(","));
        let notjson = policy_file("boundary-notjson", "accessBoundary: secret-in-a-bad-file-7a6b");
        let sa = "superbot@p.iam.gserviceaccount.com";
        for (file, err) in [
            ("/nonexistent/superbot/boundary.json".to_string(), "boundary=/nonexistent/superbot/boundary.json: can't be read"),
            (notjson, "isn't JSON"),
            (policy_file("boundary-policy", BOTS_POLICY), "must be a Credential Access Boundary"),
            (policy_file("boundary-extra", r#"{"accessBoundary":{"accessBoundaryRules":[]},"x":"secret-in-a-bad-file-7a6b"}"#), "must be a Credential Access Boundary"),
            (policy_file("boundary-inner", r#"{"accessBoundary":{"rules":[]}}"#), "must be a Credential Access Boundary"),
            (rules_file("boundary-zero", "[]"), "has 0 rules; Google takes 1 to 10"),
            (rules_file("boundary-eleven", &eleven), "has 11 rules"),
            (rules_file("boundary-typo", r#"[{"availableResource":"//storage.googleapis.com/projects/_/buckets/b","availablePermission":["inRole:roles/storage.objectViewer"]}]"#), "rule 1 must be an object with availableResource"),
            (rules_file("boundary-project", r#"[{"availableResource":"//cloudresourcemanager.googleapis.com/projects/p","availablePermissions":["inRole:roles/viewer"]}]"#), "rule 1's availableResource must be a Cloud Storage bucket"),
            (rules_file("boundary-object", r#"[{"availableResource":"//storage.googleapis.com/projects/_/buckets/b/objects/x","availablePermissions":["inRole:roles/storage.objectViewer"]}]"#), "must be a Cloud Storage bucket"),
            (rules_file("boundary-nobucket", r#"[{"availableResource":"//storage.googleapis.com/projects/_/buckets/","availablePermissions":["inRole:roles/storage.objectViewer"]}]"#), "must be a Cloud Storage bucket"),
            (rules_file("boundary-noroles", r#"[{"availableResource":"//storage.googleapis.com/projects/_/buckets/b","availablePermissions":[]}]"#), "availablePermissions must be a list of roles"),
            (rules_file("boundary-permission", r#"[{"availableResource":"//storage.googleapis.com/projects/_/buckets/b","availablePermissions":["storage.objects.get"]}]"#), "availablePermissions must be a list of roles"),
            (rules_file("boundary-emptyrole", r#"[{"availableResource":"//storage.googleapis.com/projects/_/buckets/b","availablePermissions":["inRole:"]}]"#), "availablePermissions must be a list of roles"),
            (rules_file("boundary-noexpr", &format!(r#"[{{{rule}}},{{{rule},"availabilityCondition":{{"title":"x"}}}}]"#)), "rule 2's availabilityCondition must have an expression"),
            (rules_file("boundary-condkey", &format!(r#"[{{{rule},"availabilityCondition":{{"expression":"true","location":"x"}}}}]"#)), "availabilityCondition must have an expression"),
            (rules_file("boundary-condtype", &format!(r#"[{{{rule},"availabilityCondition":{{"expression":"true","title":7}}}}]"#)), "availabilityCondition must have an expression"),
        ] {
            let e = parse_as(&GCP, &format!("{sa} boundary={file}")).unwrap_err();
            assert!(e.starts_with("GCP_RUN_CREDENTIALS: superbot@p.iam.gserviceaccount.com: boundary=") && e.contains(err), "{file}: {e}");
            assert!(!e.contains("secret-in-a-bad-file"), "a boundary file is never quoted: {e}");
        }
        let e = parse_as(&GCP, &format!("{sa} boundary={bots} boundary={owners}")).unwrap_err();
        assert!(e.contains("boundary= is given twice"), "{e}");
        assert!(parse_as(&GCP, &format!("{sa} policy={bots}")).unwrap_err().contains("only AWS_RUN_CREDENTIALS takes it"));
        for (syntax, raw) in [(&AWS, "arn:aws:iam::123456789012:role/r"), (&VAULT, "gcp/token/bots X_TOKEN=token"), (&AZURE, "11111111-2222-3333-4444-555555555555")] {
            let e = parse_as(syntax, &format!("{raw} boundary={bots}")).unwrap_err();
            assert!(e.contains("boundary= downscopes Google access tokens, so only GCP_RUN_CREDENTIALS takes it"), "{raw}: {e}");
        }
    }

    #[test]
    fn downscoped_tokens_get_the_runs_ids_and_are_audited() {
        let bots = policy_file("downscoped-bots", BOUNDARY);
        let owners = policy_file("downscoped-owners", OWNER_BOUNDARY);
        let token: &[(&str, Option<&str>)] = &[("accessToken", Some("ya29.downscoped-4e5f"))];
        let f = fake(&[("dsbots@pdown.iam.gserviceaccount.com", token), ("dsusers@pdown.iam.gserviceaccount.com", token)]);
        f.unrevocable.store(true, Ordering::SeqCst);
        f.ttl.store(3600, Ordering::SeqCst);
        let raw = format!("dsbots@pdown.iam.gserviceaccount.com boundary={bots}; dsusers@pdown.iam.gserviceaccount.com USER_GCP_TOKEN=accessToken boundary={owners}");
        let rc = RunCredentials::new(f.clone(), parse_as(&GCP, &raw).unwrap());
        assert!(rc.describe().contains("dsbots@pdown.iam.gserviceaccount.com (narrowed), dsusers@pdown.iam.gserviceaccount.com (narrowed)"), "{}", rc.describe());

        let (e, _l) = rc.issue("udown2", "bdown2", true, RUN).unwrap();
        assert_eq!(env(&e).len(), 3);
        let narrowed = f.narrowed.lock().unwrap().clone();
        let [(p0, n0), (p1, n1)] = &narrowed[..] else { panic!("{narrowed:?}") };
        assert_eq!((p0.as_str(), p1.as_str()), ("dsbots@pdown.iam.gserviceaccount.com", "dsusers@pdown.iam.gserviceaccount.com"));
        assert!(n0.boundary.as_deref().unwrap().contains("acme-bots/objects/bdown2/") && !n0.narrows_session());
        assert!(n1.boundary.as_deref().unwrap().contains("buckets/acme-u-udown2"));

        let ev = external::tests::audited("dsbots@pdown.iam.gserviceaccount.com");
        let issued = ev.iter().find(|e| e.action == "secret.lease_issued").unwrap();
        assert_eq!(issued.details["boundarySha256"], crate::sigv4::sha256_hex(n0.boundary.as_deref().unwrap().as_bytes()), "which boundary, never the file's path");
        assert!(issued.details.get("policySha256").is_none() && issued.details.get("tags").is_none() && !format!("{ev:?}").contains("downscoped-bots"));
        let users = external::tests::audited("dsusers@pdown.iam.gserviceaccount.com");
        assert_eq!(users.iter().find(|e| e.action == "secret.lease_issued").unwrap().details["userId"], "udown2");

        // A run for someone else: no token the owner's boundary would scope.
        f.narrowed.lock().unwrap().clear();
        let (e, _l) = rc.issue("udown2", "bdown2", false, RUN).unwrap();
        assert_eq!(env(&e).into_iter().map(|(k, _)| k).collect::<Vec<_>>(), ["CLOUDSDK_AUTH_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN"]);
        assert_eq!(f.narrowed.lock().unwrap().len(), 1);
    }
}
