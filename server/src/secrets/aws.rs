//! AWS Secrets Manager as an external secrets `Provider` (ADR 0146), over its JSON API,
//! each request signed with SigV4 (`crate::sigv4`).
//!
//! Secret names allow `/`, so `<NAME>` in folder `<bots|server>` is the secret
//! `<AWS_SECRETS_MANAGER_PREFIX>/<bots|server>/<NAME>` (`superbot/bots/OPENAI_API_KEY`),
//! and IAM can grant each folder on its own. botd reads the `AWSCURRENT` version. Its
//! credentials come from one source of AWS's standard chain, chosen once at startup:
//! access keys in the environment, a web identity token (EKS IRSA), the container
//! endpoint (ECS, EKS Pod Identity) or the instance profile (IMDSv2 only). Temporary
//! keys are renewed two thirds of the way through their life, and once more whenever
//! Secrets Manager says they have expired. That chain (`Credentials`) also signs Vault's
//! `aws` logins (ADR 0260).
//!
//! It is also the `leases::Issuer` of `AWS_RUN_CREDENTIALS` (ADR 0194): an STS
//! `AssumeRole` session for each run, signed with the same keys, named after the Bot so
//! CloudTrail shows whose run did what, and lasting as long as the longest run. An entry
//! may narrow it with a session policy and transitive tags with the run's ids (ADR 0230).

use super::external::{Provider, Scope};
use super::http::{self, Worker};
use super::leases::{Field, Issuer, Lease, Narrowed};
use super::{redact, Error, SecretStore};
use crate::sigv4;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Secrets Manager's longest secret name.
const MAX_NAME: usize = 512;
const IMDS: &str = "http://169.254.169.254";
/// ECS's credential endpoint, for `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.
const ECS: &str = "http://169.254.170.2";
const JSON: &str = "application/x-amz-json-1.1";
const NOT_FOUND: &str = "ResourceNotFoundException";
/// What Secrets Manager answers for keys that lapsed or were replaced: sign in again.
const EXPIRED: [&str; 3] = ["ExpiredTokenException", "UnrecognizedClientException", "InvalidClientTokenId"];
/// What STS answers for them.
const STS_EXPIRED: [&str; 2] = ["ExpiredToken", "InvalidClientTokenId"];
const FORM: &str = "application/x-www-form-urlencoded; charset=utf-8";
/// The shortest and longest `AssumeRole` session STS makes.
const MIN_SESSION: u64 = 900;
const MAX_SESSION: u64 = 43_200;

/// An access key, with the session token temporary ones come with. Never `Debug`.
#[derive(Clone)]
pub struct Keys {
    pub id: String,
    pub secret: Zeroizing<String>,
    pub token: Option<Zeroizing<String>>,
}

impl Keys {
    /// What must never show up in logs or saved text.
    fn secrets(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.secret.as_str()).chain(self.token.as_ref().map(|t| t.as_str()))
    }
}

/// What the container endpoint wants in `Authorization`.
pub enum ContainerToken {
    None,
    /// `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, read again for each sign-in: EKS Pod
    /// Identity rotates it.
    File(PathBuf),
    Value(Zeroizing<String>),
}

pub enum Source {
    /// `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, read at startup.
    Env(Keys),
    /// STS `AssumeRoleWithWebIdentity` with the token in `AWS_WEB_IDENTITY_TOKEN_FILE`,
    /// read again for each sign-in.
    WebIdentity { role_arn: String, session_name: String, token_file: PathBuf, sts: String },
    /// ECS task roles and EKS Pod Identity.
    Container { url: String, token: ContainerToken },
    /// The instance profile, through IMDSv2 at `AWS_EC2_METADATA_SERVICE_ENDPOINT`.
    InstanceProfile { endpoint: String },
}

impl Source {
    pub fn method(&self) -> &'static str {
        match self {
            Source::Env(_) => "env",
            Source::WebIdentity { .. } => "web-identity",
            Source::Container { .. } => "container",
            Source::InstanceProfile { .. } => "instance-profile",
        }
    }

    /// Names whose values are the credentials botd signs in with: reserved, so no Bot
    /// gets them from any store, while it does.
    pub fn reserved(&self) -> &'static [&'static str] {
        match self {
            Source::Env(_) => &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
            Source::WebIdentity { .. } => &["AWS_WEB_IDENTITY_TOKEN"],
            Source::Container { .. } => &["AWS_CONTAINER_AUTHORIZATION_TOKEN"],
            Source::InstanceProfile { .. } => &[],
        }
    }

    /// Settings that lead to those credentials, removed from everything botd starts.
    pub fn settings(&self) -> &'static [&'static str] {
        match self {
            Source::WebIdentity { .. } => &["AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME"],
            Source::Container { .. } => &["AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"],
            Source::Env(_) | Source::InstanceProfile { .. } => &[],
        }
    }
}

pub struct Config {
    pub region: String,
    /// `https://secretsmanager.<region>.amazonaws.com`, or `AWS_ENDPOINT_URL_SECRETS_MANAGER`; no trailing slash.
    pub endpoint: String,
    pub prefix: String,
    pub source: Source,
    /// `https://sts.<region>.amazonaws.com`, or `AWS_ENDPOINT_URL_STS`: for web identity
    /// sign-in and runs' sessions.
    pub sts: String,
}

/// `eu-west-2`, `us-gov-west-1`, `cn-north-1`: from the first of these that is set.
fn region_setting(var: &dyn Fn(&str) -> String) -> Result<String, String> {
    let found = ["AWS_SECRETS_MANAGER_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"].into_iter().map(|k| (k, var(k).trim().to_string())).find(|(_, v)| !v.is_empty());
    let (key, v) = found.ok_or("SECRETS_BACKEND=aws needs AWS_SECRETS_MANAGER_REGION (or AWS_REGION), the region the secrets are in, e.g. eu-west-2")?;
    let parts: Vec<&str> = v.split('-').collect();
    let ok = v.len() <= 32
        && parts.len() >= 3
        && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
        && parts.last().is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()));
    if !ok {
        return Err(format!("{key} must be a region like eu-west-2, not {v:?}"));
    }
    Ok(v)
}

fn dns_suffix(region: &str) -> &'static str {
    if region.starts_with("cn-") { "amazonaws.com.cn" } else { "amazonaws.com" }
}

/// `superbot`, or a path of them (`acme/prod`): what secret names allow, no empty parts.
fn prefix_setting(raw: &str) -> Result<String, String> {
    let v = match raw.trim() {
        "" => "superbot",
        v => v,
    };
    let ok = v.len() <= 256 && !v.starts_with('/') && !v.ends_with('/') && !v.contains("//") && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_+=.@-".contains(&b));
    if !ok {
        return Err(format!("AWS_SECRETS_MANAGER_PREFIX must be letters, digits and /_+=.@- (like \"superbot\" or \"acme/prod\"), not {v:?}"));
    }
    Ok(v.to_string())
}

/// The metadata service's address: `http://169.254.169.254` unless set, scheme and host only.
fn metadata_setting(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(IMDS.into());
    }
    let bad = || format!("AWS_EC2_METADATA_SERVICE_ENDPOINT must be like {IMDS}, not {raw:?}");
    let u = url::Url::parse(raw).map_err(|_| bad())?;
    if !matches!(u.scheme(), "http" | "https") || u.host().is_none() || !u.username().is_empty() || u.password().is_some() || u.query().is_some() || !matches!(u.path(), "" | "/") {
        return Err(bad());
    }
    Ok(u.as_str().trim_end_matches('/').to_string())
}

/// The container endpoint, as AWS's SDKs allow it: `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
/// on ECS's address, or a `_FULL_URI` that is https, or http to this computer or to
/// ECS's or EKS Pod Identity's link-local address.
fn container_url(var: &dyn Fn(&str) -> String) -> Result<Option<String>, String> {
    let relative = var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
    match relative.trim() {
        "" => {}
        r if r.starts_with('/') && !r.contains(['\r', '\n', ' ']) => return Ok(Some(format!("{ECS}{r}"))),
        r => return Err(format!("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must be a path, not {r:?}")),
    }
    let full = var("AWS_CONTAINER_CREDENTIALS_FULL_URI");
    let full = full.trim();
    if full.is_empty() {
        return Ok(None);
    }
    let bad = || format!("AWS_CONTAINER_CREDENTIALS_FULL_URI must be https://, or http:// to this computer, 169.254.170.2 or 169.254.170.23, not {full:?}");
    let u = url::Url::parse(full).map_err(|_| bad())?;
    let allowed = match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback() || [[169, 254, 170, 2], [169, 254, 170, 23]].contains(&ip.octets()),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback() || ip == std::net::Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x23),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    };
    if !(u.scheme() == "https" || (u.scheme() == "http" && allowed)) || !u.username().is_empty() || u.password().is_some() {
        return Err(bad());
    }
    Ok(Some(u.to_string()))
}

/// No spaces or control characters: it goes in a header or a signature.
fn plain(v: &str) -> bool {
    !v.is_empty() && !v.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// The region, and Secrets Manager's and STS's endpoints in it.
fn endpoints(var: &dyn Fn(&str) -> String) -> Result<(String, String, String), String> {
    let region = region_setting(var)?;
    let dns = dns_suffix(&region);
    let endpoint = match var("AWS_ENDPOINT_URL_SECRETS_MANAGER").trim() {
        "" => format!("https://secretsmanager.{region}.{dns}"),
        e => http::base_url("AWS_ENDPOINT_URL_SECRETS_MANAGER", e, "https://secretsmanager.eu-west-2.amazonaws.com")?,
    };
    let sts = match var("AWS_ENDPOINT_URL_STS").trim() {
        "" => format!("https://sts.{region}.{dns}"),
        e => http::base_url("AWS_ENDPOINT_URL_STS", e, "https://sts.eu-west-2.amazonaws.com")?,
    };
    Ok((region, endpoint, sts))
}

/// What Secrets Manager reaches with these settings, as `(setting, URL, what)`, for `botd
/// offline check` (ADR 0257): its endpoint; STS for web identity and runs' sessions; and a
/// container or metadata endpoint someone named. Keys aren't read.
pub fn reaches(var: &dyn Fn(&str) -> String) -> Result<Vec<(&'static str, String, &'static str)>, String> {
    let (_, endpoint, sts) = endpoints(var)?;
    let mut out = vec![("AWS_ENDPOINT_URL_SECRETS_MANAGER", endpoint, "AWS Secrets Manager")];
    if !var("AWS_WEB_IDENTITY_TOKEN_FILE").trim().is_empty() || !var("AWS_RUN_CREDENTIALS").trim().is_empty() {
        out.push(("AWS_ENDPOINT_URL_STS", sts, "AWS STS, for web identity and runs' sessions"));
    }
    out.extend(credentials_reach(var, "AWS_SECRETS_MANAGER_AUTH")?);
    Ok(out)
}

/// The source `source_from_env` takes botd's keys from, judged from the settings alone:
/// the one `method_var` names, or for `chain` the first that is set, as it picks them.
pub fn chosen_source(var: &dyn Fn(&str) -> String, method_var: &str) -> Result<&'static str, String> {
    let set = |k: &str| !var(k).trim().is_empty();
    // As the environment store reads it: an empty key file is no key, so the chain goes on;
    // one that can't be read stops botd at startup, so the chain ends there.
    let key_set = || match var("AWS_ACCESS_KEY_ID").trim() {
        "" => match var("AWS_ACCESS_KEY_ID_FILE").trim() {
            "" => false,
            f => std::fs::read_to_string(f).map(|v| !v.trim().is_empty()).unwrap_or(true),
        },
        _ => true,
    };
    Ok(match var(method_var).trim() {
        "" | "chain" if key_set() => "env",
        "" | "chain" if set("AWS_WEB_IDENTITY_TOKEN_FILE") => "web-identity",
        "" | "chain" if set("AWS_CONTAINER_CREDENTIALS_FULL_URI") || set("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") => "container",
        "" | "chain" | "instance-profile" => "instance-profile",
        "env" => "env",
        "web-identity" => "web-identity",
        "container" => "container",
        other => return Err(format!("{method_var} must be chain, env, web-identity, container or instance-profile, not {other:?}")),
    })
}

/// Where botd's keys come from beyond STS for web identity, for the source `method_var`
/// chooses only: the container's endpoint, or the instance metadata service when it is set
/// (its default is link-local).
pub fn credentials_reach(var: &dyn Fn(&str) -> String, method_var: &str) -> Result<Vec<(&'static str, String, &'static str)>, String> {
    let mut out = Vec::new();
    match chosen_source(var, method_var)? {
        "container" => {
            if let Some(url) = container_url(var)? {
                out.push(("AWS_CONTAINER_CREDENTIALS_FULL_URI", url, "the container's credentials endpoint"));
            }
        }
        "instance-profile" if !var("AWS_EC2_METADATA_SERVICE_ENDPOINT").trim().is_empty() => {
            out.push(("AWS_EC2_METADATA_SERVICE_ENDPOINT", metadata_setting(&var("AWS_EC2_METADATA_SERVICE_ENDPOINT"))?, "the instance metadata service"));
        }
        _ => {}
    }
    Ok(out)
}

impl Config {
    /// `AWS_*` settings; credentials come from `store` (the environment), so `_FILE` works.
    pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Config, String> {
        let (region, endpoint, sts) = endpoints(var)?;
        let source = source_from_env(var, store, "AWS_SECRETS_MANAGER_AUTH", "SECRETS_BACKEND=aws", &sts)?;
        Ok(Config { region, endpoint, prefix: prefix_setting(&var("AWS_SECRETS_MANAGER_PREFIX"))?, source, sts })
    }
}

/// Where botd's own AWS keys come from: the source `method_var` names (`chain`, the
/// default, takes the first of AWS's standard chain that has credentials), from the
/// standard `AWS_*` settings. `needed_by` names what wants them in errors; `sts` is where
/// a web identity token is traded. Secrets Manager reads `AWS_SECRETS_MANAGER_AUTH`;
/// Vault's `aws` sign-in, `VAULT_AWS_CREDENTIALS` (ADR 0260).
pub fn source_from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore, method_var: &str, needed_by: &str, sts: &str) -> Result<Source, String> {
    let secret = |k: &str| -> Result<Option<Zeroizing<String>>, String> {
        let v = store.get(k).map_err(|e| format!("{k}: {e}"))?;
        Ok(v.map(|v| Zeroizing::new(v.expose().trim().to_string())).filter(|v| !v.is_empty()))
    };
    let env_keys = || -> Result<Option<Keys>, String> {
        match (secret("AWS_ACCESS_KEY_ID")?, secret("AWS_SECRET_ACCESS_KEY")?) {
            (None, None) => Ok(None),
            (Some(id), Some(key)) => {
                if id.len() > 128 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return Err("AWS_ACCESS_KEY_ID must be an access key id like AKIAIOSFODNN7EXAMPLE".into());
                }
                let token = secret("AWS_SESSION_TOKEN")?;
                if !plain(&key) || token.as_ref().is_some_and(|t| !plain(t)) {
                    return Err("AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN can't have spaces in them".into());
                }
                redact::register(&key);
                if let Some(t) = &token {
                    redact::register(t);
                }
                Ok(Some(Keys { id: id.to_string(), secret: key, token }))
            }
            _ => Err("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together".into()),
        }
    };
    let web_identity = || -> Result<Option<Source>, String> {
        let file = var("AWS_WEB_IDENTITY_TOKEN_FILE");
        if file.trim().is_empty() {
            return Ok(None);
        }
        let role_arn = var("AWS_ROLE_ARN").trim().to_string();
        if !(role_arn.starts_with("arn:aws") && role_arn.contains(":role/") && role_arn.len() <= 2048 && plain(&role_arn)) {
            return Err("AWS_WEB_IDENTITY_TOKEN_FILE needs AWS_ROLE_ARN, the role to assume, like arn:aws:iam::123456789012:role/botd".into());
        }
        let session_name = match var("AWS_ROLE_SESSION_NAME").trim() {
            "" => "superbot-botd".to_string(),
            s if (2..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b)) => s.to_string(),
            s => return Err(format!("AWS_ROLE_SESSION_NAME must be 2 to 64 letters, digits and +=,.@_-, not {s:?}")),
        };
        Ok(Some(Source::WebIdentity { role_arn, session_name, token_file: PathBuf::from(file.trim()), sts: sts.to_string() }))
    };
    let container = || -> Result<Option<Source>, String> {
        let Some(url) = container_url(var)? else { return Ok(None) };
        let file = var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
        let token = match file.trim() {
            "" => match secret("AWS_CONTAINER_AUTHORIZATION_TOKEN")? {
                Some(t) if !plain(&t) => return Err("AWS_CONTAINER_AUTHORIZATION_TOKEN can't have spaces in it".into()),
                Some(t) => ContainerToken::Value(t),
                None => ContainerToken::None,
            },
            _ if !var("AWS_CONTAINER_AUTHORIZATION_TOKEN").trim().is_empty() => {
                return Err("Set AWS_CONTAINER_AUTHORIZATION_TOKEN or AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE, not both.".into());
            }
            f => ContainerToken::File(PathBuf::from(f)),
        };
        Ok(Some(Source::Container { url, token }))
    };
    let metadata_off = var("AWS_EC2_METADATA_DISABLED").trim().eq_ignore_ascii_case("true");
    let instance_profile = || -> Result<Source, String> {
        if metadata_off {
            return Err("AWS_EC2_METADATA_DISABLED is true, so botd can't use the instance profile".into());
        }
        Ok(Source::InstanceProfile { endpoint: metadata_setting(&var("AWS_EC2_METADATA_SERVICE_ENDPOINT"))? })
    };
    Ok(match var(method_var).trim() {
        // In order, and only as far as the first that has credentials: settings for a
        // later source botd won't use can't stop it.
        "" | "chain" => {
            if let Some(k) = env_keys()? {
                Source::Env(k)
            } else if let Some(w) = web_identity()? {
                w
            } else if let Some(c) = container()? {
                c
            } else if metadata_off {
                return Err(format!("{needed_by} found no AWS credentials: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN, or the container's credential settings, or unset AWS_EC2_METADATA_DISABLED for the instance profile"));
            } else {
                instance_profile()?
            }
        }
        "env" => Source::Env(env_keys()?.ok_or(format!("{method_var}=env needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (or their _FILE)"))?),
        "web-identity" => web_identity()?.ok_or(format!("{method_var}=web-identity needs AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN (EKS sets them)"))?,
        "container" => container()?.ok_or(format!("{method_var}=container needs AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or AWS_CONTAINER_CREDENTIALS_FULL_URI (ECS and EKS set them)"))?,
        "instance-profile" => instance_profile()?,
        other => return Err(format!("{method_var} must be chain, env, web-identity, container or instance-profile, not {other:?}")),
    })
}

/// What Secrets Manager answered: the body, or a refusal with its error type
/// (`ResourceNotFoundException`, ...), empty if it named none that is safe to log.
enum Reply {
    Ok(Zeroizing<Vec<u8>>),
    Refused(reqwest::StatusCode, String),
}

/// The error type from `x-amzn-ErrorType` or the body's `__type`, without the
/// namespace before `#` or the URL after `:`. Never the message, which can quote what was sent.
fn error_type(header: Option<&str>, body: &[u8]) -> String {
    let v: Value = serde_json::from_slice(body).unwrap_or_default();
    let raw = header.or(v["__type"].as_str()).unwrap_or_default();
    let raw = raw.split(':').next().unwrap_or_default();
    let raw = raw.rsplit('#').next().unwrap_or_default();
    if http::code_suffix(raw).is_empty() { String::new() } else { raw.to_string() }
}

fn unavailable(what: &str, e: impl std::fmt::Display) -> Error {
    Error::Unavailable(format!("AWS Secrets Manager: {what}: {e}"))
}

fn refused(status: reqwest::StatusCode, code: &str, what: &str) -> Error {
    Error::Unavailable(format!("AWS Secrets Manager answered {status}{} for {what}", http::code_suffix(code)))
}

fn failed(label: &str, what: &str, e: impl std::fmt::Display) -> Error {
    Error::Unavailable(format!("{label}: {what}: {e}"))
}

/// Keys from IMDS or the container endpoint, and when to renew them.
fn keys_from_json(label: &str, body: &str, what: &str) -> Result<(Keys, Instant), Error> {
    let v: Value = serde_json::from_str(body).map_err(|e| failed(label, what, e))?;
    if let Some(code) = v["Code"].as_str().filter(|c| *c != "Success") {
        return Err(Error::Unavailable(format!("{label}: {what} answered{}", http::code_suffix(code))));
    }
    keys(label, v["AccessKeyId"].as_str(), v["SecretAccessKey"].as_str(), v["Token"].as_str(), v["Expiration"].as_str(), what)
}

/// Keys from STS's `AssumeRoleWithWebIdentityResponse`.
fn keys_from_xml(label: &str, body: &str, what: &str) -> Result<(Keys, Instant), Error> {
    let doc = roxmltree::Document::parse(body).map_err(|e| failed(label, what, e))?;
    let creds = doc.descendants().find(|n| n.tag_name().name() == "Credentials");
    let field = |name: &str| creds.and_then(|c| c.children().find(|n| n.tag_name().name() == name)).and_then(|n| n.text()).map(str::trim);
    keys(label, field("AccessKeyId"), field("SecretAccessKey"), field("SessionToken"), field("Expiration"), what)
}

/// The short error code in STS's `ErrorResponse`, safe to log, as ` (Code)`.
fn xml_code(body: &str) -> String {
    http::code_suffix(&xml_error(body))
}

/// The error code in STS's `ErrorResponse`, or empty if there is none safe to log.
fn xml_error(body: &str) -> String {
    let doc = roxmltree::Document::parse(body).ok();
    let code = doc.as_ref().and_then(|d| d.descendants().find(|n| n.tag_name().name() == "Code")).and_then(|n| n.text()).map(str::trim).unwrap_or_default();
    if http::code_suffix(code).is_empty() { String::new() } else { code.to_string() }
}

/// `superbot-<bot id>-<random>`: STS's session name, at most 64 of `\w+=,.@-`, which
/// CloudTrail shows on everything the session does.
pub(crate) fn session_name(bot_id: &str) -> String {
    let bot: String = bot_id.chars().filter(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(*c)).take(46).collect();
    let bot = if bot.is_empty() { "run".to_string() } else { bot };
    format!("superbot-{bot}-{}", crate::random_hex(4))
}

/// A run's session from STS's `AssumeRoleResponse`: the fields asked for, the assumed
/// role's ARN as its id, and how long it lasts. A session that ends before the run could
/// is refused.
fn session_from_xml(body: &str, fields: &[String], run_for: u64, what: &str) -> Result<Lease, Error> {
    let bad = |why: &str| Error::Unavailable(format!("AWS STS: {what} {why}"));
    let doc = roxmltree::Document::parse(body).map_err(|_| bad("answered with something that isn't STS's XML"))?;
    let node = |parent: &str, name: &str| {
        let p = doc.descendants().find(|n| n.tag_name().name() == parent)?;
        p.children().find(|n| n.tag_name().name() == name).and_then(|n| n.text()).map(str::trim).filter(|v| plain(v))
    };
    let (Some(id), Some(secret), Some(token), Some(expiration)) = (node("Credentials", "AccessKeyId"), node("Credentials", "SecretAccessKey"), node("Credentials", "SessionToken"), node("Credentials", "Expiration")) else {
        return Err(bad("gave no session"));
    };
    let arn = node("AssumedRoleUser", "Arn").filter(|a| a.starts_with("arn:") && a.len() <= 2048).ok_or_else(|| bad("gave no assumed role"))?;
    let expires = chrono::DateTime::parse_from_rfc3339(expiration).map_err(|_| bad("gave a session with no expiry"))?;
    let ttl = u64::try_from(expires.timestamp() - chrono::Utc::now().timestamp()).unwrap_or(0);
    // A minute's slack for clocks; STS makes what was asked for or refuses.
    if ttl + 60 < run_for {
        return Err(bad(&format!("gave a session that ends in {ttl} s, but a run may last {run_for} s (RUN_TIMEOUT_MINUTES)")));
    }
    let fields = fields
        .iter()
        .map(|f| match f.as_str() {
            "AccessKeyId" => Field::Value(Zeroizing::new(id.to_string())),
            "SecretAccessKey" => Field::Value(Zeroizing::new(secret.to_string())),
            "SessionToken" => Field::Value(Zeroizing::new(token.to_string())),
            _ => Field::Missing,
        })
        .collect();
    Ok(Lease { id: arn.to_string(), ttl, renewable: false, fields })
}

fn keys(label: &str, id: Option<&str>, secret: Option<&str>, token: Option<&str>, expiration: Option<&str>, what: &str) -> Result<(Keys, Instant), Error> {
    let (Some(id), Some(secret)) = (id.filter(|i| plain(i)), secret.filter(|s| plain(s))) else {
        return Err(Error::Unavailable(format!("{label}: {what} gave no access key")));
    };
    let token = token.filter(|t| !t.is_empty());
    if token.is_some_and(|t| !plain(t)) {
        return Err(Error::Unavailable(format!("{label}: {what} gave a session token that can't be sent")));
    }
    let now = chrono::Utc::now().timestamp();
    let lifetime = expiration.and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok()).map(|e| e.timestamp() - now).and_then(|s| u64::try_from(s).ok());
    let keys = Keys { id: id.to_string(), secret: Zeroizing::new(secret.to_string()), token: token.map(|t| Zeroizing::new(t.to_string())) };
    Ok((keys, http::renew_at(lifetime)))
}

/// Sends `req`; its status and text.
async fn fetch(label: &str, req: reqwest::RequestBuilder, what: &str) -> Result<(reqwest::StatusCode, Zeroizing<String>), Error> {
    let res = req.send().await.map_err(|e| failed(label, what, e))?;
    let status = res.status();
    let body = Zeroizing::new(res.bytes().await.map_err(|e| failed(label, what, e))?.to_vec());
    let text = std::str::from_utf8(&body).map_err(|_| failed(label, what, "the answer isn't text"))?;
    Ok((status, Zeroizing::new(text.to_string())))
}

/// `fetch`, failing on anything but success.
async fn fetch_ok(label: &str, req: reqwest::RequestBuilder, what: &str) -> Result<Zeroizing<String>, Error> {
    let (status, text) = fetch(label, req, what).await?;
    if !status.is_success() {
        return Err(Error::Unavailable(format!("{label}: {what} answered {status}{}", http::error_code(text.as_bytes()))));
    }
    Ok(text)
}

/// botd's own AWS keys from one `Source`, kept while they last: Secrets Manager's, and
/// those Vault's `aws` sign-in signs with (ADR 0260). `label` names the service in errors,
/// and `store` the backend in the `secret.backend_login` audit.
pub struct Credentials {
    label: &'static str,
    store: &'static str,
    source: Source,
    http: reqwest::Client,
    /// For IMDS and the container endpoint, never through a proxy, as in AWS's SDKs: both
    /// are on this host or its network, where a proxy may not reach.
    local: reqwest::Client,
    keys: Mutex<Option<(Keys, Instant)>>,
}

impl Credentials {
    pub fn new(label: &'static str, store: &'static str, source: Source) -> Result<Credentials, String> {
        Ok(Credentials { label, store, source, http: http::client(label, None, false)?, local: http::client(label, None, true)?, keys: Mutex::new(None) })
    }

    /// Whether keys can be fetched again: not for those fixed in the environment.
    pub fn renews(&self) -> bool {
        !matches!(self.source, Source::Env(_))
    }

    /// The keys to sign with; new ones if `fresh` (the last were refused) or they are due.
    pub async fn keys(&self, fresh: bool) -> Result<Keys, Error> {
        if let Source::Env(k) = &self.source {
            return Ok(k.clone());
        }
        if !fresh && let Some((k, _)) = self.keys.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|(_, at)| Instant::now() < *at) {
            return Ok(k.clone());
        }
        let result = self.sign_in().await;
        http::audit_login(self.store, self.source.method(), &result);
        let (k, at) = result?;
        // Held rather than registered: Secrets Manager and Vault's sign-in may hold the
        // same instance profile keys, and one replacing them mustn't unmask the other's.
        // Under the lock, so overlapping sign-ins can't release the keys that end up kept.
        let mut kept = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        for v in k.secrets() {
            redact::hold(v);
        }
        if let Some((old, _)) = kept.replace((k.clone(), at)) {
            for v in old.secrets() {
                redact::release(v);
            }
        }
        Ok(k)
    }

    async fn sign_in(&self) -> Result<(Keys, Instant), Error> {
        let label = self.label;
        let what = format!("{} sign-in", self.source.method());
        match &self.source {
            Source::Env(k) => Ok((k.clone(), Instant::now())),
            Source::InstanceProfile { endpoint } => {
                // IMDSv2 only: a session token first, which a forwarded request can't get.
                let token = fetch_ok(label, self.local.put(format!("{endpoint}/latest/api/token")).header("x-aws-ec2-metadata-token-ttl-seconds", "21600"), &what).await?;
                let base = format!("{endpoint}/latest/meta-data/iam/security-credentials/");
                let roles = fetch_ok(label, self.local.get(&base).header("x-aws-ec2-metadata-token", token.as_str()), &what).await?;
                let role = roles.lines().map(str::trim).find(|l| !l.is_empty());
                let role = role.filter(|r| r.len() <= 128 && r.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b)));
                let role = role.ok_or_else(|| Error::Unavailable(format!("{label}: {what}: this instance has no instance profile")))?;
                let body = fetch_ok(label, self.local.get(format!("{base}{role}")).header("x-aws-ec2-metadata-token", token.as_str()), &what).await?;
                keys_from_json(label, &body, &what)
            }
            Source::Container { url, token } => {
                let mut req = self.local.get(url);
                match token {
                    ContainerToken::None => {}
                    ContainerToken::Value(t) => req = req.header("authorization", t.as_str()),
                    ContainerToken::File(path) => {
                        let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| failed(label, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", e))?);
                        if !plain(text.trim()) {
                            return Err(Error::Unavailable(format!("{label}: AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE is empty or has spaces in it")));
                        }
                        req = req.header("authorization", text.trim());
                    }
                }
                let body = fetch_ok(label, req, &what).await?;
                keys_from_json(label, &body, &what)
            }
            Source::WebIdentity { role_arn, session_name, token_file, sts } => {
                let text = Zeroizing::new(std::fs::read_to_string(token_file).map_err(|e| failed(label, "AWS_WEB_IDENTITY_TOKEN_FILE", e))?);
                let jwt = text.trim();
                if jwt.is_empty() {
                    return Err(Error::Unavailable(format!("{label}: AWS_WEB_IDENTITY_TOKEN_FILE is empty")));
                }
                let form = [
                    ("Action", "AssumeRoleWithWebIdentity"),
                    ("Version", "2011-06-15"),
                    ("RoleArn", role_arn.as_str()),
                    ("RoleSessionName", session_name.as_str()),
                    ("WebIdentityToken", jwt),
                ];
                let (status, body) = fetch(label, self.http.post(format!("{sts}/")).form(&form), &what).await?;
                if !status.is_success() {
                    return Err(Error::Unavailable(format!("{label}: {what} answered {status}{}", xml_code(&body))));
                }
                keys_from_xml(label, &body, &what)
            }
        }
    }

    /// Who botd signs in as, for startup lines: never a credential.
    pub fn describe(&self) -> String {
        match &self.source {
            Source::Env(k) if k.token.is_some() => "temporary access keys from the environment".to_string(),
            Source::Env(_) => "access keys from the environment".to_string(),
            Source::WebIdentity { role_arn, .. } => format!("web identity as {role_arn}"),
            Source::Container { .. } => "the container's credentials".to_string(),
            Source::InstanceProfile { .. } => "the instance profile (IMDSv2)".to_string(),
        }
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        if let Some((k, _)) = self.keys.get_mut().unwrap_or_else(|e| e.into_inner()).take() {
            for v in k.secrets() {
                redact::release(v);
            }
        }
    }
}

/// The largest identity document botd sends on: AWS's are about 2 KB.
const MAX_PKCS7: usize = 16 * 1024;

/// The instance's identity document, signed by AWS, from IMDSv2 at
/// `AWS_EC2_METADATA_SERVICE_ENDPOINT`: what Vault's `aws` method takes for its `ec2` type
/// (ADR 0298). Not a credential: any process on the instance can fetch it.
pub struct InstanceIdentity {
    endpoint: String,
    /// Link-local, so never through a proxy.
    local: reqwest::Client,
}

impl InstanceIdentity {
    /// `needed_by` names what wants it in errors.
    pub fn from_env(var: &dyn Fn(&str) -> String, needed_by: &str) -> Result<InstanceIdentity, String> {
        if var("AWS_EC2_METADATA_DISABLED").trim().eq_ignore_ascii_case("true") {
            return Err(format!("{needed_by} reads the instance's identity document from the instance metadata service, but AWS_EC2_METADATA_DISABLED is true"));
        }
        Ok(InstanceIdentity { endpoint: metadata_setting(&var("AWS_EC2_METADATA_SERVICE_ENDPOINT"))?, local: http::client("AWS instance identity", None, true)? })
    }

    /// The PKCS#7 signature of the identity document, base64 with its line breaks taken
    /// out, as Vault wants it. IMDSv2 only: a session token first.
    pub async fn pkcs7(&self) -> Result<String, Error> {
        const LABEL: &str = "AWS (for Vault)";
        let what = "the instance identity document";
        let token = fetch_ok(LABEL, self.local.put(format!("{}/latest/api/token", self.endpoint)).header("x-aws-ec2-metadata-token-ttl-seconds", "60"), what).await?;
        let text = fetch_ok(LABEL, self.local.get(format!("{}/latest/dynamic/instance-identity/pkcs7", self.endpoint)).header("x-aws-ec2-metadata-token", token.as_str()), what).await?;
        let pkcs7: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        if pkcs7.is_empty() || pkcs7.len() > MAX_PKCS7 || !pkcs7.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)) {
            return Err(Error::Unavailable(format!("{LABEL}: {what} isn't a PKCS#7 signature")));
        }
        Ok(pkcs7)
    }

    /// Where it comes from, for startup lines.
    pub fn describe(&self) -> String {
        if self.endpoint == IMDS { "IMDSv2".to_string() } else { format!("IMDSv2 at {}", self.endpoint) }
    }
}

/// What reading the instance's identity document reaches, for `botd offline check`: the
/// instance metadata service when it is set (its default is link-local).
pub fn instance_identity_reach(var: &dyn Fn(&str) -> String) -> Result<Vec<(&'static str, String, &'static str)>, String> {
    Ok(match var("AWS_EC2_METADATA_SERVICE_ENDPOINT").trim() {
        "" => Vec::new(),
        raw => vec![("AWS_EC2_METADATA_SERVICE_ENDPOINT", metadata_setting(raw)?, "the instance metadata service")],
    })
}

struct Inner {
    region: String,
    endpoint: String,
    prefix: String,
    url: url::Url,
    /// What the `Host` header carries, and so what is signed.
    host: String,
    sts_url: url::Url,
    sts_host: String,
    http: reqwest::Client,
    creds: Credentials,
}

#[derive(Clone)]
pub struct SecretsManager {
    inner: Arc<Inner>,
    worker: Arc<Worker>,
}

/// `endpoint/` and what its `Host` header carries.
fn url_and_host(key: &str, endpoint: &str) -> Result<(url::Url, String), String> {
    let url = url::Url::parse(&format!("{endpoint}/")).map_err(|e| format!("{key}: {e}"))?;
    let host = match (url.host_str(), url.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        _ => return Err(format!("{key}: {endpoint} has no host")),
    };
    Ok((url, host))
}

impl SecretsManager {
    pub fn new(cfg: Config) -> Result<SecretsManager, String> {
        let Config { region, endpoint, prefix, source, sts } = cfg;
        let (url, host) = url_and_host("AWS_ENDPOINT_URL_SECRETS_MANAGER", &endpoint)?;
        let (sts_url, sts_host) = url_and_host("AWS_ENDPOINT_URL_STS", &sts)?;
        let http = http::client("AWS Secrets Manager", None, false)?;
        let creds = Credentials::new("AWS Secrets Manager", "aws", source)?;
        let inner = Inner { region, endpoint, prefix, url, host, sts_url, sts_host, http, creds };
        Ok(SecretsManager { inner: Arc::new(inner), worker: Arc::new(Worker::new("AWS Secrets Manager", "aws-secrets")?) })
    }
}

impl Inner {
    /// The secret's name, or None if it would be too long to exist.
    fn secret_id(&self, scope: &Scope, name: &str) -> Option<String> {
        let id = format!("{}/{}/{name}", self.prefix, scope.folder('/'));
        (id.len() <= MAX_NAME).then_some(id)
    }

    async fn keys(&self, fresh: bool) -> Result<Keys, Error> {
        self.creds.keys(fresh).await
    }

    /// Calls `target` (`GetSecretValue`, ...) with `body`, signed. When Secrets Manager
    /// says the keys have lapsed, gets new ones and asks once more.
    async fn call(&self, target: &str, body: &Value, what: &str) -> Result<Reply, Error> {
        let body = serde_json::to_vec(body).map_err(|e| unavailable(what, e))?;
        let target = format!("secretsmanager.{target}");
        let payload = sigv4::sha256_hex(&body);
        for fresh in [false, true] {
            let keys = self.keys(fresh).await?;
            let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
            let scope = sigv4::Scope { amz_date: &amz_date, region: &self.region, service: "secretsmanager" };
            let mut headers = vec![("content-type", JSON), ("host", self.host.as_str()), ("x-amz-date", amz_date.as_str()), ("x-amz-target", target.as_str())];
            if let Some(t) = &keys.token {
                headers.push(("x-amz-security-token", t.as_str()));
            }
            let (signed, sig) = sigv4::signature(&keys.secret, &scope, "POST", "/", "", &headers, &payload);
            let mut req = self.http.post(self.url.clone()).header("authorization", scope.authorization(&keys.id, &signed, &sig)).body(body.clone());
            for (k, v) in headers.iter().filter(|(k, _)| *k != "host") {
                req = req.header(*k, *v);
            }
            let res = req.send().await.map_err(|e| unavailable(what, e))?;
            let status = res.status();
            let header = res.headers().get("x-amzn-errortype").and_then(|v| v.to_str().ok()).map(String::from);
            let reply = Zeroizing::new(res.bytes().await.map_err(|e| unavailable(what, e))?.to_vec());
            if status.is_success() {
                return Ok(Reply::Ok(reply));
            }
            let code = error_type(header.as_deref(), &reply);
            if !fresh && self.creds.renews() && EXPIRED.contains(&code.as_str()) {
                continue;
            }
            return Ok(Reply::Refused(status, code));
        }
        unreachable!("the second pass returns")
    }

    /// A new STS session as `role_arn` for one run of `bot_id` (ADR 0194), lasting
    /// `run_for` (at least STS's 15 minutes), signed with botd's own keys, and narrowed
    /// by a session policy and tags if the entry says so (ADR 0230). When STS says
    /// those keys have lapsed, gets new ones and asks once more.
    async fn assume_role(&self, role_arn: &str, fields: &[String], run_for: Duration, bot_id: &str, narrowed: &Narrowed) -> Result<Lease, Error> {
        let secs = run_for.as_secs().max(MIN_SESSION);
        if secs > MAX_SESSION {
            return Err(Error::Unavailable(format!("AWS STS: a run may last {secs} s (RUN_TIMEOUT_MINUTES), longer than STS's longest session ({MAX_SESSION} s), so AWS_RUN_CREDENTIALS can't cover it")));
        }
        let what = format!("AssumeRole {role_arn}");
        let body = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("Action", "AssumeRole")
                .append_pair("Version", "2011-06-15")
                .append_pair("RoleArn", role_arn)
                .append_pair("RoleSessionName", &session_name(bot_id))
                .append_pair("DurationSeconds", &secs.to_string());
            if let Some(p) = &narrowed.policy {
                form.append_pair("Policy", p);
            }
            for (i, arn) in narrowed.policy_arns.iter().enumerate() {
                form.append_pair(&format!("PolicyArns.member.{}.arn", i + 1), arn);
            }
            // Transitive, so a session the run chains from this one keeps them and can't
            // set its own under the same keys.
            for (i, (k, v)) in narrowed.tags.iter().enumerate() {
                form.append_pair(&format!("Tags.member.{}.Key", i + 1), k).append_pair(&format!("Tags.member.{}.Value", i + 1), v).append_pair(&format!("TransitiveTagKeys.member.{}", i + 1), k);
            }
            form.finish()
        };
        let payload = sigv4::sha256_hex(body.as_bytes());
        for fresh in [false, true] {
            let keys = self.keys(fresh).await?;
            let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
            let scope = sigv4::Scope { amz_date: &amz_date, region: &self.region, service: "sts" };
            let mut headers = vec![("content-type", FORM), ("host", self.sts_host.as_str()), ("x-amz-date", amz_date.as_str())];
            if let Some(t) = &keys.token {
                headers.push(("x-amz-security-token", t.as_str()));
            }
            let (signed, sig) = sigv4::signature(&keys.secret, &scope, "POST", "/", "", &headers, &payload);
            let mut req = self.http.post(self.sts_url.clone()).header("authorization", scope.authorization(&keys.id, &signed, &sig)).body(body.clone());
            for (k, v) in headers.iter().filter(|(k, _)| *k != "host") {
                req = req.header(*k, *v);
            }
            let (status, text) = fetch("AWS Secrets Manager", req, &what).await?;
            if status.is_success() {
                return session_from_xml(&text, fields, secs, &what);
            }
            let code = xml_error(&text);
            if !fresh && self.creds.renews() && STS_EXPIRED.contains(&code.as_str()) {
                continue;
            }
            let hint = match code.as_str() {
                "AccessDenied" if !narrowed.tags.is_empty() => "; botd's identity needs sts:AssumeRole and sts:TagSession on the role, and the role's trust policy must allow both",
                "AccessDenied" => "; botd's identity needs sts:AssumeRole on the role, and the role's trust policy must allow it",
                "ValidationError" => "; is a run (RUN_TIMEOUT_MINUTES) longer than the role's maximum session duration, or than an hour when botd's own identity is a role?",
                "MalformedPolicyDocument" => "; IAM won't take the session policy (policy=) or a managed one (policy-arn=)",
                "PackedPolicyTooLarge" => "; the session policy and tags are too large once STS packs them: shorten the policy, or move statements to a managed policy (policy-arn=)",
                _ => "",
            };
            return Err(Error::Unavailable(format!("AWS STS answered {status}{} for {what}{hint}", http::code_suffix(&code))));
        }
        unreachable!("the second pass returns")
    }

    async fn read(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let Some(id) = self.secret_id(&scope, name) else { return Ok(None) };
        match self.call("GetSecretValue", &json!({ "SecretId": id }), &id).await? {
            Reply::Ok(body) => value(&id, &body),
            Reply::Refused(_, code) if code == NOT_FOUND => Ok(None),
            Reply::Refused(status, code) => {
                // Deleting a secret schedules it for deletion, and reads answer
                // InvalidRequestException until it goes. Deleted on purpose counts as not
                // there; any other refusal fails closed.
                if code == "InvalidRequestException" && self.deleted(&id).await? {
                    return Ok(None);
                }
                Err(refused(status, &code, &id))
            }
        }
    }

    /// Whether `id` is scheduled for deletion (or already gone), from `DescribeSecret`.
    async fn deleted(&self, id: &str) -> Result<bool, Error> {
        let what = format!("{id} (DescribeSecret)");
        match self.call("DescribeSecret", &json!({ "SecretId": id }), &what).await? {
            Reply::Ok(body) => {
                let v: Value = serde_json::from_slice(&body).map_err(|e| unavailable(&what, e))?;
                Ok(!v["DeletedDate"].is_null())
            }
            Reply::Refused(_, code) if code == NOT_FOUND => Ok(true),
            Reply::Refused(status, code) => Err(refused(status, &code, &what)),
        }
    }

    async fn list(&self, scope: Scope) -> Result<Vec<String>, Error> {
        let head = format!("{}/{}/", self.prefix, scope.folder('/'));
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        for _ in 0..1000 {
            let mut req = json!({ "MaxResults": 100, "Filters": [{ "Key": "name", "Values": [head] }] });
            if let Some(t) = &next {
                req["NextToken"] = json!(t);
            }
            let body = match self.call("ListSecrets", &req, "listing secrets").await? {
                Reply::Ok(body) => body,
                Reply::Refused(status, code) => return Err(refused(status, &code, "listing secrets")),
            };
            let v: Value = serde_json::from_slice(&body).map_err(|e| unavailable("listing secrets", e))?;
            // A short list would hide keys kept only here and uncover sealed copies, so
            // anything odd fails closed.
            let odd = || Error::Unavailable("AWS Secrets Manager: listing secrets gave an answer that isn't a list of secrets".into());
            if !v.is_object() {
                return Err(odd());
            }
            let secrets = match &v["SecretList"] {
                Value::Null => &Vec::new(),
                Value::Array(a) => a,
                _ => return Err(odd()),
            };
            for s in secrets {
                let name = s["Name"].as_str().ok_or_else(odd)?;
                if let Some(n) = name.strip_prefix(&head).filter(|n| !n.is_empty()) {
                    out.push(n.to_string());
                }
            }
            match &v["NextToken"] {
                Value::Null => return Ok(out),
                Value::String(t) if t.is_empty() => return Ok(out),
                Value::String(t) => next = Some(t.clone()),
                _ => return Err(odd()),
            }
        }
        Err(Error::Unavailable("AWS Secrets Manager: listing secrets ran past 1000 pages".into()))
    }
}

/// The value in a `GetSecretValue` answer: `SecretString`, or `SecretBinary` holding UTF-8 text.
fn value(id: &str, body: &[u8]) -> Result<Option<Zeroizing<String>>, Error> {
    let v: Value = serde_json::from_slice(body).map_err(|e| unavailable(id, e))?;
    if v["Name"].as_str().is_some_and(|n| n != id) {
        return Err(Error::Unavailable(format!("AWS Secrets Manager: {id} was answered with another secret")));
    }
    let text = match (&v["SecretString"], &v["SecretBinary"]) {
        (Value::String(s), _) => Zeroizing::new(s.clone()),
        (_, Value::String(b)) => {
            let bytes = Zeroizing::new(STANDARD.decode(b).map_err(|e| unavailable(id, e))?);
            let text = std::str::from_utf8(&bytes).map_err(|_| Error::Unavailable(format!("AWS Secrets Manager: {id} isn't UTF-8 text")))?;
            Zeroizing::new(text.to_string())
        }
        _ => return Err(Error::Unavailable(format!("AWS Secrets Manager: {id} gave an answer with no value"))),
    };
    Ok((!text.is_empty()).then_some(text))
}

impl Provider for SecretsManager {
    fn kind(&self) -> &'static str {
        "aws"
    }

    fn describe(&self) -> String {
        let c = &self.inner;
        format!("AWS Secrets Manager in {} at {}, secrets {}/{{bots,server}}/<NAME>, {}", c.region, c.endpoint, c.prefix, c.creds.describe())
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

impl Issuer for SecretsManager {
    fn kind(&self) -> &'static str {
        "aws"
    }

    fn issue(&self, role_arn: &str, fields: &[String], run_for: Duration, bot_id: &str) -> Result<Lease, Error> {
        self.issue_narrowed(role_arn, fields, run_for, bot_id, &Narrowed::default())
    }

    fn issue_narrowed(&self, role_arn: &str, fields: &[String], run_for: Duration, bot_id: &str, narrowed: &Narrowed) -> Result<Lease, Error> {
        if narrowed.boundary.is_some() || narrowed.tenant.is_some() {
            return Err(Error::Unavailable("AWS STS: a session can't be narrowed with a Google access boundary or asked of an Entra tenant".into()));
        }
        let (inner, role_arn, fields, bot_id, narrowed) = (Arc::clone(&self.inner), role_arn.to_string(), fields.to_vec(), bot_id.to_string(), narrowed.clone());
        self.worker.run(async move { inner.assume_role(&role_arn, &fields, run_for, &bot_id, &narrowed).await })
    }

    fn revoke(&self, _lease_id: &str) -> Result<(), Error> {
        Err(Error::Unavailable("AWS STS: a session can't be revoked; it lasts until it expires".into()))
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
    use super::super::{sealed, Secrets};
    use super::*;
    use crate::audit::Outcome;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::Json;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    /// A stand-in for Secrets Manager, IMDSv2, the container endpoint and STS: no real
    /// AWS, account or network. It checks every request's SigV4 signature against what
    /// arrived, headers and body as sent.
    #[derive(Default)]
    struct Fake {
        /// Secret name → its `GetSecretValue` fields (`SecretString` or `SecretBinary`).
        secrets: Mutex<HashMap<String, Value>>,
        /// Names scheduled for deletion.
        deleted: Mutex<HashSet<String>>,
        /// Access key id → its secret and session token.
        keys: Mutex<HashMap<String, (String, Option<String>)>>,
        /// Key ids Secrets Manager calls expired.
        expired: Mutex<HashSet<String>>,
        sign_ins: AtomicUsize,
        reads: AtomicUsize,
        down: AtomicBool,
        /// 1: `SecretList` isn't a list, 2: `NextToken` isn't text, 3: an entry has no name.
        odd_list: AtomicUsize,
        /// Web identity tokens STS was given.
        web_tokens: Mutex<Vec<String>>,
        /// What the container endpoint wants in `Authorization`.
        container_auth: Mutex<String>,
        /// The regions requests were signed for.
        regions: Mutex<Vec<String>>,
        /// Each `AssumeRole`: the key it was signed with, and its form.
        assumed: Mutex<Vec<(String, HashMap<String, String>)>>,
    }

    type F = Arc<Fake>;

    fn issue(f: &Fake) -> (String, String, String) {
        let n = f.sign_ins.fetch_add(1, Ordering::SeqCst);
        let (id, secret, token) = (format!("ASIAFAKE{n:08}"), format!("aws-secret-{n}-{}", crate::random_hex(6)), format!("aws-session-{n}-{}", crate::random_hex(6)));
        f.keys.lock().unwrap().insert(id.clone(), (secret.clone(), Some(token.clone())));
        (id, secret, token)
    }

    fn error(status: StatusCode, kind: &str) -> Response {
        (status, Json(json!({ "__type": kind, "message": "the stand-in's message, quoting what was sent" }))).into_response()
    }

    /// The signature on a request, checked as Secrets Manager does.
    #[allow(clippy::result_large_err)]
    fn verify(f: &Fake, h: &HeaderMap, body: &[u8]) -> Result<(), Response> {
        signed_by(f, h, body, "secretsmanager").map(|_| ()).map_err(|(status, code)| error(status, code))
    }

    /// The access key a request was signed with, checked as `service` does; else the
    /// status and error type it would answer.
    fn signed_by(f: &Fake, h: &HeaderMap, body: &[u8], want_service: &str) -> Result<String, (StatusCode, &'static str)> {
        let header = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        let auth = header("authorization");
        let field = |name: &str| auth.split([' ', ',']).find_map(|p| p.strip_prefix(&format!("{name}="))).unwrap_or_default().to_string();
        let credential = field("Credential");
        let c: Vec<&str> = credential.split('/').collect();
        let [id, date, region, service, "aws4_request"] = c[..] else { return Err((StatusCode::BAD_REQUEST, "IncompleteSignature")) };
        let Some((secret, token)) = f.keys.lock().unwrap().get(id).cloned() else { return Err((StatusCode::BAD_REQUEST, "UnrecognizedClientException")) };
        if f.expired.lock().unwrap().contains(id) {
            return Err((StatusCode::BAD_REQUEST, "ExpiredTokenException"));
        }
        if token.as_deref().unwrap_or_default() != header("x-amz-security-token") {
            return Err((StatusCode::FORBIDDEN, "InvalidClientTokenId"));
        }
        let amz_date = header("x-amz-date");
        let names = field("SignedHeaders");
        let (target, content_type) = if want_service == "sts" { ("", FORM) } else { (";x-amz-target", JSON) };
        let want = format!("content-type;host;x-amz-date{}{target}", if token.is_some() { ";x-amz-security-token" } else { "" });
        if service != want_service || !amz_date.starts_with(date) || names != want || header("content-type") != content_type {
            return Err((StatusCode::BAD_REQUEST, "IncompleteSignature"));
        }
        let values: Vec<(String, String)> = names.split(';').map(|n| (n.to_string(), header(n))).collect();
        let pairs: Vec<(&str, &str)> = values.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let scope = sigv4::Scope { amz_date: &amz_date, region, service };
        let (_, sig) = sigv4::signature(&secret, &scope, "POST", "/", "", &pairs, &sigv4::sha256_hex(body));
        if sig != field("Signature") {
            return Err((StatusCode::BAD_REQUEST, "InvalidSignatureException"));
        }
        f.regions.lock().unwrap().push(region.to_string());
        Ok(id.to_string())
    }

    async fn api(State(f): State<F>, h: HeaderMap, body: Bytes) -> Response {
        if let Err(e) = verify(&f, &h, &body) {
            return e;
        }
        if f.down.load(Ordering::SeqCst) {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "InternalServiceError");
        }
        let req = Json::<Value>::from_bytes(&body).map(|Json(v)| v).unwrap_or_default();
        let id = req["SecretId"].as_str().unwrap_or_default().to_string();
        let target = h.get("x-amz-target").and_then(|v| v.to_str().ok()).unwrap_or_default();
        match target {
            "secretsmanager.GetSecretValue" => {
                f.reads.fetch_add(1, Ordering::SeqCst);
                if id.ends_with("/DENIED_TOKEN") {
                    // Only the header names the error here, as some AWS front ends send it.
                    let mut r = (StatusCode::BAD_REQUEST, Json(json!({ "message": "User is not authorized" }))).into_response();
                    r.headers_mut().insert("x-amzn-errortype", "AccessDeniedException:http://internal.amazon.com/coral/com.amazon.coral.service/".parse().unwrap());
                    return r;
                }
                if id.ends_with("/KMS_TOKEN") {
                    return error(StatusCode::BAD_REQUEST, "DecryptionFailure");
                }
                if id.ends_with("/BUSY_TOKEN") || f.deleted.lock().unwrap().contains(&id) {
                    return error(StatusCode::BAD_REQUEST, "InvalidRequestException");
                }
                let found = f.secrets.lock().unwrap().get(&id).cloned();
                match found {
                    Some(mut v) => {
                        let name = if id.ends_with("/OTHER_TOKEN") { format!("{id}-AbCdEf") } else { id.clone() };
                        v["Name"] = json!(name);
                        v["ARN"] = json!(format!("arn:aws:secretsmanager:eu-west-2:123456789012:secret:{id}-AbCdEf"));
                        v["VersionStages"] = json!(["AWSCURRENT"]);
                        (StatusCode::OK, Json(v)).into_response()
                    }
                    None => error(StatusCode::BAD_REQUEST, "com.amazonaws.secretsmanager#ResourceNotFoundException"),
                }
            }
            "secretsmanager.DescribeSecret" => {
                if f.deleted.lock().unwrap().contains(&id) {
                    (StatusCode::OK, Json(json!({ "Name": id, "DeletedDate": 1_795_000_000.5 }))).into_response()
                } else if f.secrets.lock().unwrap().contains_key(&id) || id.ends_with("/BUSY_TOKEN") {
                    (StatusCode::OK, Json(json!({ "Name": id }))).into_response()
                } else {
                    error(StatusCode::BAD_REQUEST, NOT_FOUND)
                }
            }
            "secretsmanager.ListSecrets" => {
                match f.odd_list.load(Ordering::SeqCst) {
                    1 => return (StatusCode::OK, Json(json!({ "SecretList": "invalid" }))).into_response(),
                    2 => return (StatusCode::OK, Json(json!({ "SecretList": [], "NextToken": 7 }))).into_response(),
                    3 => return (StatusCode::OK, Json(json!({ "SecretList": [{ "ARN": "arn:aws:secretsmanager:x" }] }))).into_response(),
                    _ => {}
                }
                assert_eq!((req["Filters"][0]["Key"].as_str(), req["MaxResults"].as_u64()), (Some("name"), Some(100)));
                let prefix = req["Filters"][0]["Values"][0].as_str().unwrap_or_default().to_string();
                let deleted = f.deleted.lock().unwrap().clone();
                let mut names: Vec<String> = f.secrets.lock().unwrap().keys().filter(|k| k.starts_with(&prefix) && !deleted.contains(*k)).cloned().collect();
                names.sort();
                let start: usize = req["NextToken"].as_str().and_then(|t| t.parse().ok()).unwrap_or(0);
                let page: Vec<Value> = names.iter().skip(start).take(2).map(|n| json!({ "Name": n, "ARN": format!("arn:aws:secretsmanager:eu-west-2:123456789012:secret:{n}-AbCdEf") })).collect();
                let mut v = json!({ "SecretList": page });
                if start + 2 < names.len() {
                    v["NextToken"] = json!((start + 2).to_string());
                }
                (StatusCode::OK, Json(v)).into_response()
            }
            _ => error(StatusCode::BAD_REQUEST, "InvalidAction"),
        }
    }

    fn json_keys(f: &Fake) -> Value {
        let (id, secret, token) = issue(f);
        let expires = (chrono::Utc::now() + chrono::Duration::hours(6)).to_rfc3339();
        json!({ "Code": "Success", "Type": "AWS-HMAC", "AccessKeyId": id, "SecretAccessKey": secret, "Token": token, "Expiration": expires })
    }

    async fn imds_token(h: HeaderMap) -> (StatusCode, String) {
        match h.get("x-aws-ec2-metadata-token-ttl-seconds") {
            Some(_) => (StatusCode::OK, "imds-session-1".into()),
            None => (StatusCode::BAD_REQUEST, String::new()),
        }
    }

    fn imds_session(h: &HeaderMap) -> bool {
        h.get("x-aws-ec2-metadata-token").and_then(|v| v.to_str().ok()) == Some("imds-session-1")
    }

    async fn imds_roles(h: HeaderMap) -> (StatusCode, String) {
        if !imds_session(&h) {
            return (StatusCode::UNAUTHORIZED, String::new());
        }
        (StatusCode::OK, "botd-role\n".into())
    }

    async fn imds_role(State(f): State<F>, axum::extract::Path(role): axum::extract::Path<String>, h: HeaderMap) -> Response {
        if !imds_session(&h) || role != "botd-role" {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        Json(json_keys(&f)).into_response()
    }

    async fn container(State(f): State<F>, h: HeaderMap) -> Response {
        let want = f.container_auth.lock().unwrap().clone();
        if h.get("authorization").and_then(|v| v.to_str().ok()) != Some(want.as_str()) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let mut v = json_keys(&f);
        v.as_object_mut().unwrap().remove("Code");
        Json(v).into_response()
    }

    fn sts_error(status: StatusCode, code: &str) -> Response {
        let xml = format!(r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>{code}</Code><Message>The stand-in's message, quoting what was sent</Message></Error></ErrorResponse>"#);
        (status, xml).into_response()
    }

    /// `AssumeRole` for a run, signed: role `.../denied` is refused, `.../one-hour` allows
    /// at most an hour, `.../short` gives ten minutes whatever was asked, `.../odd` no session.
    fn assume_role(f: &Fake, h: &HeaderMap, body: &[u8], form: HashMap<String, String>) -> Response {
        let signer = match signed_by(f, h, body, "sts") {
            Ok(id) => id,
            Err((status, "ExpiredTokenException")) => return sts_error(status, "ExpiredToken"),
            Err((status, "UnrecognizedClientException")) => return sts_error(status, "InvalidClientTokenId"),
            Err((status, code)) => return sts_error(status, code),
        };
        f.assumed.lock().unwrap().push((signer, form.clone()));
        let get = |k: &str| form.get(k).cloned().unwrap_or_default();
        let (arn, session) = (get("RoleArn"), get("RoleSessionName"));
        let secs: i64 = get("DurationSeconds").parse().unwrap_or(3600);
        let tagged = form.contains_key("Tags.member.1.Key");
        if arn.ends_with("/denied") || (arn.ends_with("/no-tag-session") && tagged) {
            return sts_error(StatusCode::FORBIDDEN, "AccessDenied");
        }
        if arn.ends_with("/malformed") && form.contains_key("Policy") {
            return sts_error(StatusCode::BAD_REQUEST, "MalformedPolicyDocument");
        }
        if arn.ends_with("/packed") && tagged {
            return sts_error(StatusCode::BAD_REQUEST, "PackedPolicyTooLarge");
        }
        if arn.ends_with("/one-hour") && secs > 3600 {
            return sts_error(StatusCode::BAD_REQUEST, "ValidationError");
        }
        if arn.ends_with("/odd") {
            return (StatusCode::OK, "<AssumeRoleResponse><AssumeRoleResult></AssumeRoleResult></AssumeRoleResponse>").into_response();
        }
        let secs = if arn.ends_with("/short") { 600 } else { secs };
        let (id, secret, token) = issue(f);
        let expires = (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let role = arn.rsplit('/').next().unwrap_or_default();
        let xml = format!(
            r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><AssumedRoleUser><AssumedRoleId>AROAFAKE:{session}</AssumedRoleId><Arn>arn:aws:sts::123456789012:assumed-role/{role}/{session}</Arn></AssumedRoleUser><Credentials><AccessKeyId>{id}</AccessKeyId><SecretAccessKey>{secret}</SecretAccessKey><SessionToken>{token}</SessionToken><Expiration>{expires}</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"#
        );
        (StatusCode::OK, xml).into_response()
    }

    async fn sts(State(f): State<F>, h: HeaderMap, body: Bytes) -> Response {
        let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
        if form.get("Action").map(String::as_str) == Some("AssumeRole") {
            return assume_role(&f, &h, &body, form);
        }
        web_identity(&f, &form).into_response()
    }

    fn web_identity(f: &Fake, form: &HashMap<String, String>) -> (StatusCode, String) {
        let get = |k: &str| form.get(k).cloned().unwrap_or_default();
        assert_eq!((get("Action").as_str(), get("Version").as_str(), get("RoleArn").as_str()), ("AssumeRoleWithWebIdentity", "2011-06-15", "arn:aws:iam::123456789012:role/botd"));
        let jwt = get("WebIdentityToken");
        f.web_tokens.lock().unwrap().push(jwt.clone());
        if jwt == "not-a-valid-jwt" {
            let xml = format!(r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>Couldn't verify {jwt}</Message></Error></ErrorResponse>"#);
            return (StatusCode::BAD_REQUEST, xml);
        }
        let (id, secret, token) = issue(f);
        let expires = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let xml = format!(
            r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><SessionToken>{token}</SessionToken><SecretAccessKey>{secret}</SecretAccessKey><Expiration>{expires}</Expiration><AccessKeyId>{id}</AccessKeyId></Credentials><SubjectFromWebIdentityToken>system:serviceaccount:superbot:botd</SubjectFromWebIdentityToken></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"#
        );
        (StatusCode::OK, xml)
    }

    /// Secrets Manager, IMDS and the container endpoint on one address, STS on another.
    fn stand_in() -> (String, String, F) {
        let f = F::default();
        let app = axum::Router::new()
            .route("/", axum::routing::post(api))
            .route("/latest/api/token", axum::routing::put(imds_token))
            .route("/latest/meta-data/iam/security-credentials/", axum::routing::get(imds_roles))
            .route("/latest/meta-data/iam/security-credentials/{role}", axum::routing::get(imds_role))
            .route("/v1/credentials", axum::routing::get(container))
            .with_state(Arc::clone(&f));
        let sts_app = axum::Router::new().route("/", axum::routing::post(sts)).with_state(Arc::clone(&f));
        (serve(app), serve(sts_app), f)
    }

    fn put(f: &Fake, name: &str, value: &str) {
        f.secrets.lock().unwrap().insert(name.to_string(), json!({ "SecretString": value }));
    }

    fn config(url: &str, extra: &[(&str, &str)]) -> Config {
        let mut pairs = vec![("AWS_REGION", "eu-west-2"), ("AWS_ENDPOINT_URL_SECRETS_MANAGER", url), ("AWS_EC2_METADATA_SERVICE_ENDPOINT", url)];
        pairs.extend_from_slice(extra);
        Config::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap()
    }

    fn store(url: &str, extra: &[(&str, &str)], ttl: Duration) -> Arc<ExternalStore> {
        Arc::new(ExternalStore::new(Box::new(SecretsManager::new(config(url, extra)).unwrap()), ttl))
    }

    fn sealed_under(s: &Arc<ExternalStore>, label: &str) -> Secrets {
        let path = crate::db::temp_path(label).join("app.sqlite");
        let sealed = sealed::SealedStore::new(sealed::connect(&path).unwrap(), sealed::cipher());
        Secrets::new(vec![Box::new(EnvStore::fixed(&[])), Box::new(Shared(Arc::clone(s))), Box::new(sealed)])
    }

    #[test]
    fn reads_bot_and_server_secrets_with_the_instance_profile() {
        let (url, _, f) = stand_in();
        let bot_value = format!("sk-aws-{}", crate::random_hex(10));
        put(&f, "superbot/bots/OPENAI_API_KEY", &bot_value);
        put(&f, "superbot/bots/LINODE_TOKEN", "never-from-the-bots-folder");
        put(&f, "superbot/bots/nested/GH_TOKEN", "not-a-name-botd-reads");
        put(&f, "superbot/bots/ANTHROPIC_API_KEY", "ant-from-aws-1");
        put(&f, "superbot/server/LINODE_TOKEN", "linode-from-aws-1");
        put(&f, "other-app/bots/OPENAI_API_KEY", "not-ours");
        let s = store(&url, &[], Duration::from_secs(60));
        assert_eq!(s.check().unwrap(), 3, "ANTHROPIC_API_KEY, OPENAI_API_KEY and LINODE_TOKEN, each from its own folder, across pages");
        assert_eq!(s.get("OPENAI_API_KEY").unwrap().unwrap().expose(), bot_value);
        assert_eq!(s.get("LINODE_TOKEN").unwrap().unwrap().expose(), "linode-from-aws-1");
        assert!(s.get("NOT_THERE_TOKEN").unwrap().is_none());
        let reads = f.reads.load(Ordering::SeqCst);
        s.get("OPENAI_API_KEY").unwrap();
        assert_eq!(f.reads.load(Ordering::SeqCst), reads, "cached");
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 1, "IMDS asked once, its keys kept");
        assert!(f.regions.lock().unwrap().iter().all(|r| r == "eu-west-2"));
        assert_eq!(redact::text(&bot_value), redact::MARK);

        let secrets = sealed_under(&s, "aws-facade");
        secrets.put("OPENAI_API_KEY", "sealed-but-shadowed-aws").unwrap();
        let env: Vec<(String, String)> = secrets.try_harness_env().unwrap().into_iter().map(|(k, v)| (k, v.expose().to_string())).collect();
        assert_eq!(env, [("ANTHROPIC_API_KEY".to_string(), "ant-from-aws-1".to_string()), ("OPENAI_API_KEY".to_string(), bot_value.clone())], "Secrets Manager's value wins, and botd's own never reach Bots");
        assert_eq!(secrets.source("LINODE_TOKEN").unwrap(), Some(("aws", false)));
        assert!(audited("aws").iter().any(|e| e.action == "secret.backend_login" && e.details["method"] == "instance-profile"));
        for v in [bot_value.as_str(), "ant-from-aws-1", "linode-from-aws-1", "sealed-but-shadowed-aws"] {
            redact::forget(v);
        }
    }

    #[test]
    fn reads_each_users_own_folder() {
        let (url, _, f) = stand_in();
        let value = format!("ua1-aws-{}", crate::random_hex(10));
        put(&f, "superbot/users/ua1/OPENAI_API_KEY", &value);
        put(&f, "superbot/users/ua1/LINODE_TOKEN", "never-from-a-users-folder");
        put(&f, "superbot/users/ub1/OPENAI_API_KEY", "ub1-own-openai");
        put(&f, "superbot/users/ua10/OPENAI_API_KEY", "not-ua1s");
        let x = super::super::external::tests::users_on(store(&url, &[], Duration::from_secs(60)));
        super::super::external::tests::reads_users_folders(&x, &value);
    }

    #[test]
    fn access_keys_from_the_environment_sign_every_request() {
        let (url, _, f) = stand_in();
        let secret = format!("env-secret-{}", crate::random_hex(8));
        f.keys.lock().unwrap().insert("AKIAENVEXAMPLE01".into(), (secret.clone(), Some("env-session-1".into())));
        put(&f, "acme/prod/server/SMTP_PASSWORD", "smtp-from-aws-1");
        put(&f, "superbot/server/SMTP_PASSWORD", "another-prefix");
        let creds = [
            ("AWS_ACCESS_KEY_ID", "AKIAENVEXAMPLE01"),
            ("AWS_SECRET_ACCESS_KEY", secret.as_str()),
            ("AWS_SESSION_TOKEN", "env-session-1"),
            ("AWS_SECRETS_MANAGER_PREFIX", "acme/prod"),
            ("AWS_SECRETS_MANAGER_REGION", "us-east-1"),
        ];
        let s = store(&url, &creds, Duration::ZERO);
        assert_eq!(s.check().unwrap(), 1);
        assert_eq!(s.get("SMTP_PASSWORD").unwrap().unwrap().expose(), "smtp-from-aws-1");
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 0, "no sign-in: the keys are used as they are");
        assert!(f.regions.lock().unwrap().iter().all(|r| r == "us-east-1"), "AWS_SECRETS_MANAGER_REGION wins over AWS_REGION");
        assert_eq!(redact::text(&secret), redact::MARK, "the secret key is redacted wherever it shows");

        // A wrong secret key: refused, with no retry and nothing of the key in the error.
        let wrong = [("AWS_ACCESS_KEY_ID", "AKIAENVEXAMPLE01"), ("AWS_SECRET_ACCESS_KEY", "not-the-secret-key"), ("AWS_SESSION_TOKEN", "env-session-1")];
        let e = store(&url, &wrong, Duration::ZERO).check().unwrap_err().to_string();
        assert!(e.contains("400") && e.contains("InvalidSignatureException") && !e.contains("not-the-secret-key") && !e.contains("quoting"), "{e}");
        redact::forget(&secret);
        redact::forget("env-session-1");
        redact::forget("not-the-secret-key");
        redact::forget("smtp-from-aws-1");
    }

    #[test]
    fn web_identity_signs_in_and_again_when_the_keys_expire() {
        let (url, sts_url, f) = stand_in();
        put(&f, "superbot/bots/GITHUB_TOKEN", "gh-from-aws-1");
        let file = crate::db::temp_path("aws-web-identity").join("token");
        std::fs::write(&file, "eyJ.web-identity.1\n").unwrap();
        let web = [("AWS_WEB_IDENTITY_TOKEN_FILE", file.to_str().unwrap()), ("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/botd"), ("AWS_ENDPOINT_URL_STS", sts_url.as_str())];
        let s = store(&url, &web, Duration::ZERO);
        assert_eq!(s.check().unwrap(), 1, "the chain picks the web identity");
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 1);
        assert_eq!(f.web_tokens.lock().unwrap().as_slice(), ["eyJ.web-identity.1"]);

        let (first_id, (first_secret, first_token)) = f.keys.lock().unwrap().iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let first_token = first_token.unwrap();
        let said = format!("signed with {first_secret} and {first_token}");
        assert_eq!(redact::text(&said), format!("signed with {} and {}", redact::MARK, redact::MARK), "STS's keys are redacted wherever they show");

        std::fs::write(&file, "eyJ.web-identity.2\n").unwrap();
        f.expired.lock().unwrap().insert(first_id.clone());
        assert_eq!(s.get("GITHUB_TOKEN").unwrap().unwrap().expose(), "gh-from-aws-1", "expired: signs in once more and retries");
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 2);
        let (second_secret, second_token) = f.keys.lock().unwrap().iter().find(|(k, _)| **k != first_id).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(redact::text(&second_secret), redact::MARK, "renewed keys are redacted too");
        assert_eq!(redact::text(&second_token.unwrap()), redact::MARK);
        assert_eq!(redact::text(&said), said, "and the lapsed ones forgotten, so the list doesn't grow");
        assert_eq!(f.web_tokens.lock().unwrap().last().map(String::as_str), Some("eyJ.web-identity.2"), "the token file is read again");
        assert!(audited("aws").iter().any(|e| e.action == "secret.backend_login" && e.details["method"] == "web-identity" && e.outcome == Outcome::Success));

        // A token STS won't take: refused, audited, its message never repeated.
        std::fs::write(&file, "not-a-valid-jwt").unwrap();
        let e = store(&url, &web, Duration::ZERO).check().unwrap_err().to_string();
        assert!(e.contains("400") && e.contains("InvalidIdentityToken") && !e.contains("not-a-valid-jwt"), "{e}");
        assert!(audited("aws").iter().any(|e| e.outcome == Outcome::Failure && e.details["method"] == "web-identity"));
        redact::forget("gh-from-aws-1");
    }

    #[test]
    fn container_credentials_with_a_rotating_token() {
        let (url, _, f) = stand_in();
        put(&f, "superbot/bots/NPM_TOKEN", "npm-from-aws-1");
        *f.container_auth.lock().unwrap() = "pod-identity-1".into();
        let file = crate::db::temp_path("aws-container").join("token");
        std::fs::write(&file, "pod-identity-1\n").unwrap();
        let full = format!("{url}/v1/credentials");
        let c = [("AWS_CONTAINER_CREDENTIALS_FULL_URI", full.as_str()), ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", file.to_str().unwrap())];
        let s = store(&url, &c, Duration::ZERO);
        assert_eq!(s.check().unwrap(), 1);
        assert_eq!(s.get("NPM_TOKEN").unwrap().unwrap().expose(), "npm-from-aws-1");
        assert_eq!(f.sign_ins.load(Ordering::SeqCst), 1);
        *f.container_auth.lock().unwrap() = "pod-identity-2".into();
        let e = store(&url, &c, Duration::ZERO).check().unwrap_err().to_string();
        assert!(e.contains("container sign-in answered 401"), "{e}");
        std::fs::write(&file, "pod-identity-2\n").unwrap();
        assert_eq!(store(&url, &c, Duration::ZERO).check().unwrap(), 1, "the token file is read for each sign-in");
        redact::forget("npm-from-aws-1");
    }

    #[test]
    fn secrets_manager_refusing_or_odd_fails_closed() {
        let (url, _, f) = stand_in();
        for n in ["DOWN_API_KEY", "DENIED_TOKEN", "KMS_TOKEN", "OTHER_TOKEN", "RETIRED_TOKEN"] {
            put(&f, &format!("superbot/bots/{n}"), &format!("aws-{n}-value"));
        }
        f.secrets.lock().unwrap().insert("superbot/bots/BINARY_TOKEN".into(), json!({ "SecretBinary": STANDARD.encode("bin-from-aws-1") }));
        f.secrets.lock().unwrap().insert("superbot/bots/BADBIN_TOKEN".into(), json!({ "SecretBinary": STANDARD.encode([0xff, 0xfe]) }));
        f.secrets.lock().unwrap().insert("superbot/bots/NOVALUE_TOKEN".into(), json!({}));
        put(&f, "superbot/bots/EMPTY_TOKEN", "");
        f.deleted.lock().unwrap().insert("superbot/bots/RETIRED_TOKEN".into());
        let s = store(&url, &[], Duration::from_millis(200));
        let secrets = sealed_under(&s, "aws-closed");
        for n in ["DOWN_API_KEY", "DENIED_TOKEN", "KMS_TOKEN", "BUSY_TOKEN", "OTHER_TOKEN", "RETIRED_TOKEN", "BADBIN_TOKEN", "NOVALUE_TOKEN", "EMPTY_TOKEN"] {
            secrets.put(n, "the-sealed-fallback-aws").unwrap();
        }
        assert_eq!(secrets.get("DOWN_API_KEY").unwrap().unwrap().expose(), "aws-DOWN_API_KEY-value");
        assert_eq!(secrets.get("BINARY_TOKEN").unwrap().unwrap().expose(), "bin-from-aws-1", "SecretBinary holding text");
        for (n, err) in [
            ("DENIED_TOKEN", "AccessDeniedException"),
            ("KMS_TOKEN", "DecryptionFailure"),
            ("BUSY_TOKEN", "InvalidRequestException"),
            ("OTHER_TOKEN", "another secret"),
            ("BADBIN_TOKEN", "isn't UTF-8"),
            ("NOVALUE_TOKEN", "no value"),
        ] {
            let e = secrets.get(n).unwrap_err().to_string();
            assert!(e.contains(err) && !e.contains("quoting"), "{n} never uncovers the sealed copy: {e}");
        }
        assert_eq!(secrets.get("RETIRED_TOKEN").unwrap().unwrap().expose(), "the-sealed-fallback-aws", "scheduled for deletion counts as deleted");
        assert_eq!(secrets.get("EMPTY_TOKEN").unwrap().unwrap().expose(), "the-sealed-fallback-aws", "an empty value counts as not there");
        for mode in [1, 2, 3] {
            f.odd_list.store(mode, Ordering::SeqCst);
            let e = s.check().unwrap_err().to_string();
            assert!(e.contains("isn't a list of secrets"), "an odd list fails closed: {e}");
        }
        f.odd_list.store(0, Ordering::SeqCst);
        f.down.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(250));
        let e = secrets.get("DOWN_API_KEY").unwrap_err();
        assert!(matches!(&e, Error::Unavailable(m) if m.contains("500") && m.contains("InternalServiceError")), "never the sealed value under it: {e}");
        assert!(matches!(secrets.try_harness_env(), Err(Error::Unavailable(_))));
        assert!(audited("DOWN_API_KEY").iter().any(|e| e.outcome == Outcome::Failure && e.details["store"] == "aws"));
        for v in ["aws-DOWN_API_KEY-value", "bin-from-aws-1", "the-sealed-fallback-aws"] {
            redact::forget(v);
        }
    }

    #[test]
    fn error_types_lose_namespaces_and_messages() {
        assert_eq!(error_type(None, br#"{"__type":"com.amazonaws.secretsmanager#ResourceNotFoundException","message":"x"}"#), NOT_FOUND);
        assert_eq!(error_type(Some("AccessDeniedException:http://internal.amazon.com/coral/"), b"{}"), "AccessDeniedException");
        assert_eq!(error_type(None, br#"{"__type":"has spaces in it"}"#), "");
        assert_eq!(error_type(None, b"<html>"), "");
        assert_eq!(xml_code("<ErrorResponse><Error><Code>InvalidIdentityToken</Code><Message>quoted</Message></Error></ErrorResponse>"), " (InvalidIdentityToken)");
    }

    #[test]
    fn settings_are_checked() {
        let ok = |pairs: &[(&str, &str)]| Config::from_env(&settings(pairs), &EnvStore::fixed(pairs));
        let r = ("AWS_REGION", "eu-west-2");
        let c = ok(&[r]).unwrap();
        assert_eq!((c.region.as_str(), c.endpoint.as_str(), c.prefix.as_str()), ("eu-west-2", "https://secretsmanager.eu-west-2.amazonaws.com", "superbot"));
        assert!(matches!(&c.source, Source::InstanceProfile { endpoint } if endpoint == IMDS), "the chain ends at the instance profile");
        let c = ok(&[("AWS_DEFAULT_REGION", "cn-north-1")]).unwrap();
        assert_eq!(c.endpoint, "https://secretsmanager.cn-north-1.amazonaws.com.cn");
        let keys = [r, ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"), ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")];
        let both = [&keys[..], &[("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/token"), ("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/botd")]].concat();
        assert!(matches!(ok(&both).unwrap().source, Source::Env(_)), "the environment's keys come first, as in AWS's chain");
        let unused = [
            &keys[..],
            &[("AWS_WEB_IDENTITY_TOKEN_FILE", "/t"), ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://evil.example/creds"), ("AWS_EC2_METADATA_SERVICE_ENDPOINT", "nonsense")],
        ]
        .concat();
        assert!(matches!(ok(&unused).unwrap().source, Source::Env(_)), "settings for sources after the one used are never checked");
        let w = [r, ("AWS_WEB_IDENTITY_TOKEN_FILE", "/t"), ("AWS_ROLE_ARN", "arn:aws:iam::1:role/b"), ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "t"), ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/t")];
        assert!(matches!(ok(&w).unwrap().source, Source::WebIdentity { .. }));
        let c = ok(&[r, ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/abc"), ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://127.0.0.1/x")]).unwrap();
        assert!(matches!(&c.source, Source::Container { url, .. } if url == "http://169.254.170.2/v2/credentials/abc"));
        let c = ok(&[r, ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.23/v1/credentials")]).unwrap();
        assert!(matches!(c.source, Source::Container { .. }));
        let c = ok(&[r, ("AWS_SECRETS_MANAGER_AUTH", "web-identity"), ("AWS_WEB_IDENTITY_TOKEN_FILE", "/t"), ("AWS_ROLE_ARN", "arn:aws-us-gov:iam::1:role/b")]).unwrap();
        assert!(matches!(&c.source, Source::WebIdentity { sts, session_name, .. } if sts == "https://sts.eu-west-2.amazonaws.com" && session_name == "superbot-botd"));
        for (pairs, err) in [
            (vec![], "needs AWS_SECRETS_MANAGER_REGION"),
            (vec![("AWS_REGION", "Europe")], "AWS_REGION must be a region"),
            (vec![("AWS_SECRETS_MANAGER_REGION", "eu-west")], "AWS_SECRETS_MANAGER_REGION must be a region"),
            (vec![r, ("AWS_ENDPOINT_URL_SECRETS_MANAGER", "http://secretsmanager.example.com")], "must use https"),
            (vec![r, ("AWS_SECRETS_MANAGER_PREFIX", "/superbot")], "AWS_SECRETS_MANAGER_PREFIX"),
            (vec![r, ("AWS_SECRETS_MANAGER_PREFIX", "a b")], "AWS_SECRETS_MANAGER_PREFIX"),
            (vec![r, ("AWS_SECRETS_MANAGER_AUTH", "profile")], "chain, env, web-identity, container or instance-profile"),
            (vec![r, ("AWS_SECRETS_MANAGER_AUTH", "env")], "needs AWS_ACCESS_KEY_ID"),
            (vec![r, ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")], "set together"),
            (vec![r, ("AWS_ACCESS_KEY_ID", "AKIA EXAMPLE"), ("AWS_SECRET_ACCESS_KEY", "s")], "access key id"),
            (vec![r, ("AWS_WEB_IDENTITY_TOKEN_FILE", "/t")], "needs AWS_ROLE_ARN"),
            (vec![r, ("AWS_WEB_IDENTITY_TOKEN_FILE", "/t"), ("AWS_ROLE_ARN", "arn:aws:iam::1:role/b"), ("AWS_ROLE_SESSION_NAME", "a b")], "AWS_ROLE_SESSION_NAME"),
            (vec![r, ("AWS_SECRETS_MANAGER_AUTH", "container")], "needs AWS_CONTAINER_CREDENTIALS"),
            (vec![r, ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://evil.example/creds")], "AWS_CONTAINER_CREDENTIALS_FULL_URI must be"),
            (vec![r, ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.23/v1"), ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "t"), ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/t")], "not both"),
            (vec![r, ("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://169.254.169.254/latest")], "AWS_EC2_METADATA_SERVICE_ENDPOINT"),
            (vec![r, ("AWS_EC2_METADATA_DISABLED", "true")], "found no AWS credentials"),
            (vec![r, ("AWS_SECRETS_MANAGER_AUTH", "instance-profile"), ("AWS_EC2_METADATA_DISABLED", "TRUE")], "AWS_EC2_METADATA_DISABLED"),
        ] {
            let e = ok(&pairs).err().unwrap_or_default();
            assert!(e.contains(err), "expected an error containing {err:?}, got {e:?}");
        }
    }

    #[test]
    fn botds_aws_credentials_never_reach_bots() {
        let instance = Source::InstanceProfile { endpoint: IMDS.into() };
        assert!(instance.reserved().is_empty() && instance.settings().is_empty(), "nothing in the environment to keep back; the guide covers IMDS");
        let file = crate::db::temp_path("aws-creds").join("secret");
        std::fs::write(&file, "aws-secret-from-file-0123456789\n").unwrap();
        let env = EnvStore::fixed(&[]);
        let pairs = [
            ("SECRETS_BACKEND", "aws"),
            ("AWS_REGION", "eu-west-2"),
            ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY_FILE", file.to_str().unwrap()),
            ("AWS_SESSION_TOKEN", "botd-session-0123456789"),
        ];
        let x = super::super::external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap().unwrap();
        assert_eq!(x.kind(), "aws");
        let web = [("SECRETS_BACKEND", "aws"), ("AWS_REGION", "eu-west-2"), ("AWS_SECRETS_MANAGER_AUTH", "web-identity"), ("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/token"), ("AWS_ROLE_ARN", "arn:aws:iam::1:role/b")];
        super::super::external::from_env(&settings(&web), &env).unwrap();
        let ecs = [("SECRETS_BACKEND", "aws"), ("AWS_REGION", "eu-west-2"), ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/creds"), ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "ecs-auth-0123456789")];
        super::super::external::from_env(&settings(&ecs), &EnvStore::fixed(&ecs)).unwrap();
        for name in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_WEB_IDENTITY_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN"] {
            assert!(super::super::check_name(name).is_err(), "{name} is reserved while botd signs in with it");
            assert_eq!(super::super::external::scope_of(name), None, "{name} is never read from an external store");
        }
        let bots = Secrets::new(vec![Box::new(EnvStore::fixed(&[("AWS_SECRET_ACCESS_KEY_FILE", file.to_str().unwrap()), ("AWS_SESSION_TOKEN", "botd-session-0123456789"), ("AWS_WEB_IDENTITY_TOKEN_FILE", file.to_str().unwrap())]))]);
        assert!(bots.try_harness_env().unwrap().is_empty() && bots.try_inherited_harness_env().unwrap().is_empty() && bots.list().unwrap().is_empty());
        let host = crate::adapters::local_host();
        for k in [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SECRET_ACCESS_KEY_FILE",
            "AWS_SESSION_TOKEN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_ROLE_ARN",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        ] {
            assert!(host.remove.iter().any(|r| r == k), "{k} removed from local jobs");
        }
        redact::forget("aws-secret-from-file-0123456789");
        redact::forget("botd-session-0123456789");
    }

    use super::super::leases::tests::RUN;
    use super::super::leases::RunCredentials;

    /// `SECRETS_BACKEND=aws` on the stand-ins, with the instance profile and `AWS_RUN_CREDENTIALS`.
    fn run_credentials(url: &str, sts_url: &str, roles: &str) -> Arc<RunCredentials> {
        let pairs = [
            ("SECRETS_BACKEND", "aws"),
            ("AWS_REGION", "eu-west-2"),
            ("AWS_ENDPOINT_URL_SECRETS_MANAGER", url),
            ("AWS_EC2_METADATA_SERVICE_ENDPOINT", url),
            ("AWS_ENDPOINT_URL_STS", sts_url),
            ("AWS_SECRETS_MANAGER_AUTH", "instance-profile"),
            ("AWS_RUN_CREDENTIALS", roles),
        ];
        let x = super::super::external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap().unwrap();
        Arc::clone(x.run_credentials().expect("AWS_RUN_CREDENTIALS is read with SECRETS_BACKEND=aws"))
    }

    fn values(env: &[(String, super::super::Secret)]) -> HashMap<String, String> {
        env.iter().map(|(k, v)| (k.clone(), v.expose().to_string())).collect()
    }

    #[test]
    fn each_run_gets_its_own_sts_session_named_after_the_bot() {
        let (url, sts_url, f) = stand_in();
        let rc = run_credentials(&url, &sts_url, "arn:aws:iam::123456789012:role/superbot-bots; arn:aws:iam::123456789012:role/u-{owner} OWN_KEY_ID=AccessKeyId OWN_SECRET_KEY=SecretAccessKey");
        assert!(rc.describe().contains("arn:aws:iam::123456789012:role/superbot-bots, arn:aws:iam::123456789012:role/u-{owner}"));
        let (e1, l1) = rc.issue("uaws7", "baws7", true, RUN).unwrap();
        let (e2, l2) = rc.issue("uaws7", "baws7", false, Duration::from_secs(300)).unwrap();
        let (v1, v2) = (values(&e1), values(&e2));
        let mut names: Vec<&str> = v1.keys().map(String::as_str).collect();
        names.sort();
        assert_eq!(names, ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "OWN_KEY_ID", "OWN_SECRET_KEY"]);
        assert_eq!(v2.len(), 3, "a run for someone else gets no owner's role");
        assert_ne!(v1["AWS_ACCESS_KEY_ID"], v2["AWS_ACCESS_KEY_ID"], "each run its own session");
        let keys = f.keys.lock().unwrap().clone();
        assert_eq!(keys[&v1["AWS_ACCESS_KEY_ID"]], (v1["AWS_SECRET_ACCESS_KEY"].clone(), Some(v1["AWS_SESSION_TOKEN"].clone())), "the keys STS made");
        assert_eq!(redact::text(&format!("leaked {}", v1["AWS_SECRET_ACCESS_KEY"])), format!("leaked {}", redact::MARK));

        let assumed = f.assumed.lock().unwrap().clone();
        assert_eq!(assumed.len(), 3);
        let botd = keys.keys().find(|k| !v1.values().chain(v2.values()).any(|v| v == *k)).unwrap().clone();
        assert!(assumed.iter().all(|(signer, _)| *signer == botd), "signed with botd's own keys from the instance profile, checked by the stand-in");
        let form = |i: usize, k: &str| assumed[i].1.get(k).cloned().unwrap_or_default();
        assert_eq!((form(0, "RoleArn").as_str(), form(0, "Version").as_str()), ("arn:aws:iam::123456789012:role/superbot-bots", "2011-06-15"));
        assert_eq!(form(1, "RoleArn"), "arn:aws:iam::123456789012:role/u-uaws7");
        assert_eq!((form(0, "DurationSeconds").as_str(), form(2, "DurationSeconds").as_str()), ("3600", "900"), "as long as the longest run, at least STS's 15 minutes");
        let session = form(0, "RoleSessionName");
        assert!(session.starts_with("superbot-baws7-") && session.len() <= 64 && session != form(1, "RoleSessionName"), "{session}");

        let ev: Vec<_> = audited("arn:aws:iam::123456789012:role/superbot-bots").into_iter().filter(|e| e.bot_id.as_deref() == Some("baws7")).collect();
        let issued = ev.iter().find(|e| e.action == "secret.lease_issued").unwrap();
        assert_eq!(issued.details["leaseId"], format!("arn:aws:sts::123456789012:assumed-role/superbot-bots/{session}"), "CloudTrail's ARN for the session");
        assert_eq!((issued.details["store"].as_str(), issued.details["renewable"].as_bool()), (Some("aws"), Some(false)));
        assert!((3590..=3600).contains(&issued.details["ttl"].as_u64().unwrap()));
        assert!(!format!("{ev:?}").contains(&v1["AWS_SECRET_ACCESS_KEY"]) && !format!("{ev:?}").contains(&v1["AWS_SESSION_TOKEN"]), "never a value");

        drop(l1);
        drop(l2);
        let released: Vec<_> = audited("arn:aws:iam::123456789012:role/u-uaws7").into_iter().filter(|e| e.action == "secret.lease_released").collect();
        assert_eq!((released.len(), released[0].details["revocable"].as_bool()), (1, Some(false)));
        assert!(released[0].details["expiresAt"].as_str().is_some());
        assert_eq!(redact::text(&v1["AWS_SESSION_TOKEN"]), redact::MARK, "it works until it expires, so it stays redacted");
    }

    #[test]
    fn sts_refusing_or_odd_refuses_the_run() {
        let (url, sts_url, f) = stand_in();
        let role = |name: &str| format!("arn:aws:iam::123456789012:role/{name}");
        for (name, run_for, err) in [
            ("denied", RUN, "403 Forbidden (AccessDenied) for AssumeRole arn:aws:iam::123456789012:role/denied; botd's identity needs sts:AssumeRole"),
            ("one-hour", Duration::from_secs(7200), "(ValidationError)"),
            ("short", RUN, "ends in 600 s, but a run may last 3600 s"),
            ("odd", RUN, "gave no session"),
            ("long", Duration::from_secs(43_201), "longer than STS's longest session"),
        ] {
            let rc = run_credentials(&url, &sts_url, &role(name));
            let e = rc.issue("uaws8", "baws8", true, run_for).err().unwrap().to_string();
            assert!(e.contains(err) && !e.contains("quoting"), "{name}: {e}");
            assert!(audited(&role(name)).iter().any(|e| e.action == "secret.lease_issued" && e.outcome == Outcome::Failure), "{name}");
        }
        assert!(!f.assumed.lock().unwrap().iter().any(|(_, form)| form["RoleArn"].ends_with("/long")), "never asked for what STS can't make");

        // botd's keys lapse: it signs in again and asks once more.
        let rc = run_credentials(&url, &sts_url, &role("superbot-bots"));
        rc.issue("uaws8", "baws8", true, RUN).unwrap();
        let signer = f.assumed.lock().unwrap().last().unwrap().0.clone();
        f.expired.lock().unwrap().insert(signer.clone());
        let before = f.sign_ins.load(Ordering::SeqCst);
        rc.issue("uaws8", "baws8", true, RUN).unwrap();
        assert!(f.sign_ins.load(Ordering::SeqCst) > before);
        assert_ne!(f.assumed.lock().unwrap().last().unwrap().0, signer);
    }

    #[test]
    fn sessions_are_narrowed_by_a_session_policy_and_transitive_tags() {
        let (url, sts_url, f) = stand_in();
        let policy = super::super::leases::tests::policy_file(
            "aws-session-policy",
            r#"{ "Version": "2012-10-17", "Statement": [{ "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::acme-data/users/{owner}/bots/{bot}/*" }] }"#,
        );
        let roles = format!(
            "arn:aws:iam::123456789012:role/superbot-users policy={policy} policy-arn=arn:aws:iam::aws:policy/ReadOnlyAccess policy-arn=arn:aws:iam::123456789012:policy/u-{{owner}} tags=bot,owner;\
             arn:aws:iam::123456789012:role/superbot-plain PLAIN_KEY_ID=AccessKeyId PLAIN_SECRET=SecretAccessKey PLAIN_TOKEN=SessionToken"
        );
        let rc = run_credentials(&url, &sts_url, &roles);
        let (e, _l) = rc.issue("uaws9", "baws9", true, RUN).unwrap();
        assert_eq!(values(&e).len(), 6);
        let assumed = f.assumed.lock().unwrap().clone();
        let form = |i: usize, k: &str| assumed[i].1.get(k).cloned();
        let sent: Value = serde_json::from_str(&form(0, "Policy").unwrap()).unwrap();
        assert_eq!(sent["Statement"][0]["Resource"], "arn:aws:s3:::acme-data/users/uaws9/bots/baws9/*", "signed and checked by the stand-in, with this run's ids");
        assert_eq!(sent["Statement"][0]["Action"], json!(["s3:GetObject", "s3:PutObject"]));
        assert_eq!(form(0, "PolicyArns.member.1.arn").as_deref(), Some("arn:aws:iam::aws:policy/ReadOnlyAccess"));
        assert_eq!(form(0, "PolicyArns.member.2.arn").as_deref(), Some("arn:aws:iam::123456789012:policy/u-uaws9"));
        assert_eq!((form(0, "Tags.member.1.Key").as_deref(), form(0, "Tags.member.1.Value").as_deref()), (Some("superbot-bot"), Some("baws9")));
        assert_eq!((form(0, "Tags.member.2.Key").as_deref(), form(0, "Tags.member.2.Value").as_deref()), (Some("superbot-owner"), Some("uaws9")));
        assert_eq!((form(0, "TransitiveTagKeys.member.1").as_deref(), form(0, "TransitiveTagKeys.member.2").as_deref()), (Some("superbot-bot"), Some("superbot-owner")), "so a chained session keeps them");
        assert!(assumed[1].1.keys().all(|k| !k.starts_with("Policy") && !k.starts_with("Tags") && !k.starts_with("TransitiveTagKeys")), "an entry with no options is as before: {:?}", assumed[1].1);

        // A run for someone else gets no session the owner's tags or policy would scope.
        let before = f.assumed.lock().unwrap().len();
        let (e, _l) = rc.issue("uaws9", "baws9", false, RUN).unwrap();
        assert_eq!(values(&e).len(), 3);
        assert_eq!(f.assumed.lock().unwrap().len(), before + 1);
        assert!(f.assumed.lock().unwrap().last().unwrap().1["RoleArn"].ends_with("/superbot-plain"));

        let role = |name: &str, opts: &str| format!("arn:aws:iam::123456789012:role/{name} {opts}");
        for (raw, err) in [
            (role("no-tag-session", "tags=bot"), "(AccessDenied) for AssumeRole arn:aws:iam::123456789012:role/no-tag-session; botd's identity needs sts:AssumeRole and sts:TagSession on the role"),
            (role("malformed", &format!("policy={policy}")), "(MalformedPolicyDocument) for AssumeRole arn:aws:iam::123456789012:role/malformed; IAM won't take the session policy"),
            (role("packed", "tags=bot,owner"), "(PackedPolicyTooLarge) for AssumeRole arn:aws:iam::123456789012:role/packed; the session policy and tags are too large"),
        ] {
            let e = run_credentials(&url, &sts_url, &raw).issue("uaws9", "baws9", true, RUN).err().unwrap().to_string();
            assert!(e.contains(err) && !e.contains("quoting") && !e.contains("acme-data"), "{raw}: {e}");
        }
        assert!(run_credentials(&url, &sts_url, &role("no-tag-session", "")).issue("uaws9", "baws9", true, RUN).is_ok(), "the same role, untagged");
    }

    #[test]
    fn run_credentials_settings_are_checked() {
        let (url, sts_url, _) = stand_in();
        let base = [("SECRETS_BACKEND", "aws"), ("AWS_REGION", "eu-west-2"), ("AWS_ENDPOINT_URL_SECRETS_MANAGER", url.as_str()), ("AWS_ENDPOINT_URL_STS", sts_url.as_str())];
        let keys = [("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"), ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")];
        let with = |extra: &[(&str, &str)]| {
            let pairs = [&base[..], &keys[..], extra].concat();
            super::super::external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs))
        };
        let x = with(&[("AWS_RUN_CREDENTIALS", "arn:aws:iam::123456789012:role/superbot-bots")]).unwrap().unwrap();
        assert_eq!(x.run_credentials().unwrap().names(), ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"], "the run's own keys under the SDKs' names, though botd signs in with its own under them");
        assert!(super::super::check_name("AWS_ACCESS_KEY_ID").is_err(), "still never from a store");
        assert!(with(&[]).unwrap().unwrap().run_credentials().is_none(), "off unless set");
        let e = with(&[("AWS_RUN_CREDENTIALS", "aws/creds/bots")]).err().unwrap();
        assert!(e.contains("AWS_RUN_CREDENTIALS") && e.contains("IAM role's ARN"));
        let e = with(&[("AWS_ENDPOINT_URL_STS", "http://sts.example.com")]).err().unwrap();
        assert!(e.contains("AWS_ENDPOINT_URL_STS"));
        let var = settings(&[("AWS_RUN_CREDENTIALS", "arn:aws:iam::123456789012:role/r")]);
        assert_eq!(super::super::external::unused_settings(&var, "vault"), ["AWS_RUN_CREDENTIALS"], "only SECRETS_BACKEND=aws reads it");
        assert!(super::super::external::unused_settings(&var, "aws").is_empty());
        let name = session_name("b/../x y");
        assert!(name.starts_with("superbot-b..xy-") && name.len() == "superbot-b..xy-".len() + 8, "{name}");
        let name = session_name(&"b".repeat(100));
        assert_eq!(name.len(), 64, "{name}");
        assert!(session_name("///").starts_with("superbot-run-"));
    }
}
