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
//! Secrets Manager says they have expired.

use super::external::{Provider, Scope};
use super::http::{self, Worker};
use super::{redact, Error, SecretStore};
use crate::sigv4;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
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

impl Config {
    /// `AWS_*` settings; credentials come from `store` (the environment), so `_FILE` works.
    pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Config, String> {
        let region = region_setting(var)?;
        let dns = dns_suffix(&region);
        let endpoint = match var("AWS_ENDPOINT_URL_SECRETS_MANAGER").trim() {
            "" => format!("https://secretsmanager.{region}.{dns}"),
            e => http::base_url("AWS_ENDPOINT_URL_SECRETS_MANAGER", e, "https://secretsmanager.eu-west-2.amazonaws.com")?,
        };
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
            let sts = match var("AWS_ENDPOINT_URL_STS").trim() {
                "" => format!("https://sts.{region}.{dns}"),
                e => http::base_url("AWS_ENDPOINT_URL_STS", e, "https://sts.eu-west-2.amazonaws.com")?,
            };
            Ok(Some(Source::WebIdentity { role_arn, session_name, token_file: PathBuf::from(file.trim()), sts }))
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
        let source = match var("AWS_SECRETS_MANAGER_AUTH").trim() {
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
                    return Err("SECRETS_BACKEND=aws found no AWS credentials: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN, or the container's credential settings, or unset AWS_EC2_METADATA_DISABLED for the instance profile".into());
                } else {
                    instance_profile()?
                }
            }
            "env" => Source::Env(env_keys()?.ok_or("AWS_SECRETS_MANAGER_AUTH=env needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (or their _FILE)")?),
            "web-identity" => web_identity()?.ok_or("AWS_SECRETS_MANAGER_AUTH=web-identity needs AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN (EKS sets them)")?,
            "container" => container()?.ok_or("AWS_SECRETS_MANAGER_AUTH=container needs AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or AWS_CONTAINER_CREDENTIALS_FULL_URI (ECS and EKS set them)")?,
            "instance-profile" => instance_profile()?,
            other => return Err(format!("AWS_SECRETS_MANAGER_AUTH must be chain, env, web-identity, container or instance-profile, not {other:?}")),
        };
        Ok(Config { region, endpoint, prefix: prefix_setting(&var("AWS_SECRETS_MANAGER_PREFIX"))?, source })
    }
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

/// Keys from IMDS or the container endpoint, and when to renew them.
fn keys_from_json(body: &str, what: &str) -> Result<(Keys, Instant), Error> {
    let v: Value = serde_json::from_str(body).map_err(|e| unavailable(what, e))?;
    if let Some(code) = v["Code"].as_str().filter(|c| *c != "Success") {
        return Err(Error::Unavailable(format!("AWS Secrets Manager: {what} answered{}", http::code_suffix(code))));
    }
    keys(v["AccessKeyId"].as_str(), v["SecretAccessKey"].as_str(), v["Token"].as_str(), v["Expiration"].as_str(), what)
}

/// Keys from STS's `AssumeRoleWithWebIdentityResponse`.
fn keys_from_xml(body: &str, what: &str) -> Result<(Keys, Instant), Error> {
    let doc = roxmltree::Document::parse(body).map_err(|e| unavailable(what, e))?;
    let creds = doc.descendants().find(|n| n.tag_name().name() == "Credentials");
    let field = |name: &str| creds.and_then(|c| c.children().find(|n| n.tag_name().name() == name)).and_then(|n| n.text()).map(str::trim);
    keys(field("AccessKeyId"), field("SecretAccessKey"), field("SessionToken"), field("Expiration"), what)
}

/// The short error code in STS's `ErrorResponse`, safe to log.
fn xml_code(body: &str) -> String {
    let doc = roxmltree::Document::parse(body).ok();
    let code = doc.as_ref().and_then(|d| d.descendants().find(|n| n.tag_name().name() == "Code")).and_then(|n| n.text());
    code.map(|c| http::code_suffix(c.trim())).unwrap_or_default()
}

fn keys(id: Option<&str>, secret: Option<&str>, token: Option<&str>, expiration: Option<&str>, what: &str) -> Result<(Keys, Instant), Error> {
    let (Some(id), Some(secret)) = (id.filter(|i| plain(i)), secret.filter(|s| plain(s))) else {
        return Err(Error::Unavailable(format!("AWS Secrets Manager: {what} gave no access key")));
    };
    let token = token.filter(|t| !t.is_empty());
    if token.is_some_and(|t| !plain(t)) {
        return Err(Error::Unavailable(format!("AWS Secrets Manager: {what} gave a session token that can't be sent")));
    }
    let now = chrono::Utc::now().timestamp();
    let lifetime = expiration.and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok()).map(|e| e.timestamp() - now).and_then(|s| u64::try_from(s).ok());
    let keys = Keys { id: id.to_string(), secret: Zeroizing::new(secret.to_string()), token: token.map(|t| Zeroizing::new(t.to_string())) };
    Ok((keys, http::renew_at(lifetime)))
}

struct Inner {
    cfg: Config,
    url: url::Url,
    /// What the `Host` header carries, and so what is signed.
    host: String,
    http: reqwest::Client,
    /// For IMDS and the container endpoint: link-local, so never through a proxy.
    local: reqwest::Client,
    keys: Mutex<Option<(Keys, Instant)>>,
}

pub struct SecretsManager {
    inner: Arc<Inner>,
    worker: Worker,
}

impl SecretsManager {
    pub fn new(cfg: Config) -> Result<SecretsManager, String> {
        let url = url::Url::parse(&format!("{}/", cfg.endpoint)).map_err(|e| format!("AWS_ENDPOINT_URL_SECRETS_MANAGER: {e}"))?;
        let host = match (url.host_str(), url.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_string(),
            _ => return Err(format!("AWS Secrets Manager endpoint {} has no host", cfg.endpoint)),
        };
        let http = http::client("AWS Secrets Manager", None, false)?;
        let local = http::client("AWS Secrets Manager", None, true)?;
        let inner = Inner { cfg, url, host, http, local, keys: Mutex::new(None) };
        Ok(SecretsManager { inner: Arc::new(inner), worker: Worker::new("AWS Secrets Manager", "aws-secrets")? })
    }
}

impl Inner {
    /// The secret's name, or None if it would be too long to exist.
    fn secret_id(&self, scope: Scope, name: &str) -> Option<String> {
        let id = format!("{}/{}/{name}", self.cfg.prefix, scope.as_str());
        (id.len() <= MAX_NAME).then_some(id)
    }

    /// The keys to sign with; new ones if `fresh` (the last were refused) or they are due.
    async fn keys(&self, fresh: bool) -> Result<Keys, Error> {
        if let Source::Env(k) = &self.cfg.source {
            return Ok(k.clone());
        }
        if !fresh && let Some((k, _)) = self.keys.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|(_, at)| Instant::now() < *at) {
            return Ok(k.clone());
        }
        let result = self.sign_in().await;
        http::audit_login("aws", self.cfg.source.method(), &result);
        let (k, at) = result?;
        for v in k.secrets() {
            redact::register(v);
        }
        let old = self.keys.lock().unwrap_or_else(|e| e.into_inner()).replace((k.clone(), at));
        if let Some((old, _)) = &old {
            for v in old.secrets().filter(|v| !k.secrets().any(|n| n == *v)) {
                redact::forget(v);
            }
        }
        Ok(k)
    }

    /// Sends `req`; its status and text.
    async fn fetch(&self, req: reqwest::RequestBuilder, what: &str) -> Result<(reqwest::StatusCode, Zeroizing<String>), Error> {
        let res = req.send().await.map_err(|e| unavailable(what, e))?;
        let status = res.status();
        let body = Zeroizing::new(res.bytes().await.map_err(|e| unavailable(what, e))?.to_vec());
        let text = std::str::from_utf8(&body).map_err(|_| unavailable(what, "the answer isn't text"))?;
        Ok((status, Zeroizing::new(text.to_string())))
    }

    /// `fetch`, failing on anything but success.
    async fn fetch_ok(&self, req: reqwest::RequestBuilder, what: &str) -> Result<Zeroizing<String>, Error> {
        let (status, text) = self.fetch(req, what).await?;
        if !status.is_success() {
            return Err(Error::Unavailable(format!("AWS Secrets Manager: {what} answered {status}{}", http::error_code(text.as_bytes()))));
        }
        Ok(text)
    }

    async fn sign_in(&self) -> Result<(Keys, Instant), Error> {
        let what = format!("{} sign-in", self.cfg.source.method());
        match &self.cfg.source {
            Source::Env(k) => Ok((k.clone(), Instant::now())),
            Source::InstanceProfile { endpoint } => {
                // IMDSv2 only: a session token first, which a forwarded request can't get.
                let token = self.fetch_ok(self.local.put(format!("{endpoint}/latest/api/token")).header("x-aws-ec2-metadata-token-ttl-seconds", "21600"), &what).await?;
                let base = format!("{endpoint}/latest/meta-data/iam/security-credentials/");
                let roles = self.fetch_ok(self.local.get(&base).header("x-aws-ec2-metadata-token", token.as_str()), &what).await?;
                let role = roles.lines().map(str::trim).find(|l| !l.is_empty());
                let role = role.filter(|r| r.len() <= 128 && r.bytes().all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b)));
                let role = role.ok_or_else(|| Error::Unavailable(format!("AWS Secrets Manager: {what}: this instance has no instance profile")))?;
                let body = self.fetch_ok(self.local.get(format!("{base}{role}")).header("x-aws-ec2-metadata-token", token.as_str()), &what).await?;
                keys_from_json(&body, &what)
            }
            Source::Container { url, token } => {
                let client = if url.starts_with("https://") { &self.http } else { &self.local };
                let mut req = client.get(url);
                match token {
                    ContainerToken::None => {}
                    ContainerToken::Value(t) => req = req.header("authorization", t.as_str()),
                    ContainerToken::File(path) => {
                        let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| unavailable("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", e))?);
                        if !plain(text.trim()) {
                            return Err(Error::Unavailable("AWS Secrets Manager: AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE is empty or has spaces in it".into()));
                        }
                        req = req.header("authorization", text.trim());
                    }
                }
                let body = self.fetch_ok(req, &what).await?;
                keys_from_json(&body, &what)
            }
            Source::WebIdentity { role_arn, session_name, token_file, sts } => {
                let text = Zeroizing::new(std::fs::read_to_string(token_file).map_err(|e| unavailable("AWS_WEB_IDENTITY_TOKEN_FILE", e))?);
                let jwt = text.trim();
                if jwt.is_empty() {
                    return Err(Error::Unavailable("AWS Secrets Manager: AWS_WEB_IDENTITY_TOKEN_FILE is empty".into()));
                }
                let form = [
                    ("Action", "AssumeRoleWithWebIdentity"),
                    ("Version", "2011-06-15"),
                    ("RoleArn", role_arn.as_str()),
                    ("RoleSessionName", session_name.as_str()),
                    ("WebIdentityToken", jwt),
                ];
                let (status, body) = self.fetch(self.http.post(format!("{sts}/")).form(&form), &what).await?;
                if !status.is_success() {
                    return Err(Error::Unavailable(format!("AWS Secrets Manager: {what} answered {status}{}", xml_code(&body))));
                }
                keys_from_xml(&body, &what)
            }
        }
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
            let scope = sigv4::Scope { amz_date: &amz_date, region: &self.cfg.region, service: "secretsmanager" };
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
            if !fresh && !matches!(self.cfg.source, Source::Env(_)) && EXPIRED.contains(&code.as_str()) {
                continue;
            }
            return Ok(Reply::Refused(status, code));
        }
        unreachable!("the second pass returns")
    }

    async fn read(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let Some(id) = self.secret_id(scope, name) else { return Ok(None) };
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
        let head = format!("{}/{}/", self.cfg.prefix, scope.as_str());
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
        let c = &self.inner.cfg;
        let auth = match &c.source {
            Source::Env(k) if k.token.is_some() => "temporary access keys from the environment".to_string(),
            Source::Env(_) => "access keys from the environment".to_string(),
            Source::WebIdentity { role_arn, .. } => format!("web identity as {role_arn}"),
            Source::Container { .. } => "the container's credentials".to_string(),
            Source::InstanceProfile { .. } => "the instance profile (IMDSv2)".to_string(),
        };
        format!("AWS Secrets Manager in {} at {}, secrets {}/{{bots,server}}/<NAME>, {auth}", c.region, c.endpoint, c.prefix)
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
    use axum::{Form, Json};
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
        let header = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        let auth = header("authorization");
        let field = |name: &str| auth.split([' ', ',']).find_map(|p| p.strip_prefix(&format!("{name}="))).unwrap_or_default().to_string();
        let credential = field("Credential");
        let c: Vec<&str> = credential.split('/').collect();
        let [id, date, region, service, "aws4_request"] = c[..] else { return Err(error(StatusCode::BAD_REQUEST, "IncompleteSignature")) };
        let Some((secret, token)) = f.keys.lock().unwrap().get(id).cloned() else { return Err(error(StatusCode::BAD_REQUEST, "UnrecognizedClientException")) };
        if f.expired.lock().unwrap().contains(id) {
            return Err(error(StatusCode::BAD_REQUEST, "ExpiredTokenException"));
        }
        if token.as_deref().unwrap_or_default() != header("x-amz-security-token") {
            return Err(error(StatusCode::FORBIDDEN, "InvalidClientTokenId"));
        }
        let amz_date = header("x-amz-date");
        let names = field("SignedHeaders");
        let want = if token.is_some() { "content-type;host;x-amz-date;x-amz-security-token;x-amz-target" } else { "content-type;host;x-amz-date;x-amz-target" };
        if service != "secretsmanager" || !amz_date.starts_with(date) || names != want || header("content-type") != JSON {
            return Err(error(StatusCode::BAD_REQUEST, "IncompleteSignature"));
        }
        let values: Vec<(String, String)> = names.split(';').map(|n| (n.to_string(), header(n))).collect();
        let pairs: Vec<(&str, &str)> = values.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let scope = sigv4::Scope { amz_date: &amz_date, region, service };
        let (_, sig) = sigv4::signature(&secret, &scope, "POST", "/", "", &pairs, &sigv4::sha256_hex(body));
        if sig != field("Signature") {
            return Err(error(StatusCode::BAD_REQUEST, "InvalidSignatureException"));
        }
        f.regions.lock().unwrap().push(region.to_string());
        Ok(())
    }

    async fn api(State(f): State<F>, h: HeaderMap, body: Bytes) -> Response {
        if let Err(e) = verify(&f, &h, &body) {
            return e;
        }
        if f.down.load(Ordering::SeqCst) {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "InternalServiceError");
        }
        let req: Value = serde_json::from_slice(&body).unwrap_or_default();
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

    async fn sts(State(f): State<F>, Form(form): Form<HashMap<String, String>>) -> (StatusCode, String) {
        let get = |k: &str| form.get(k).cloned().unwrap_or_default();
        assert_eq!((get("Action").as_str(), get("Version").as_str(), get("RoleArn").as_str()), ("AssumeRoleWithWebIdentity", "2011-06-15", "arn:aws:iam::123456789012:role/botd"));
        let jwt = get("WebIdentityToken");
        f.web_tokens.lock().unwrap().push(jwt.clone());
        if jwt == "not-a-valid-jwt" {
            let xml = format!(r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>Couldn't verify {jwt}</Message></Error></ErrorResponse>"#);
            return (StatusCode::BAD_REQUEST, xml);
        }
        let (id, secret, token) = issue(&f);
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
}
