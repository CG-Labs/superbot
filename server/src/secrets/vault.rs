//! HashiCorp Vault (and OpenBao) as an external secrets `Provider` (ADR 0125).
//!
//! Each secret is one KV v2 secret, `<VAULT_KV_MOUNT>/<VAULT_KV_PREFIX>/<bots|server>/<NAME>`,
//! whose field `VAULT_KV_FIELD` (`value`) holds the value. botd signs in with a token
//! (`VAULT_TOKEN`, or `VAULT_TOKEN_FILE`, read again whenever Vault refuses the one it
//! has, so Vault Agent can rotate it), AppRole (`VAULT_ROLE_ID`, `VAULT_SECRET_ID`,
//! each also `_FILE`), or a JWT the platform keeps in a file: Kubernetes service account
//! tokens (`VAULT_AUTH=kubernetes`) or any OIDC/JWT issuer (`VAULT_AUTH=jwt`, ADR 0159),
//! read again at each login, or botd's cloud identity (ADR 0260): `VAULT_AUTH=aws`, an STS
//! request signed with botd's own AWS keys; `gcp`, a JWT Google signs as its service
//! account; `azure`, its managed identity's token; or the instance's own identity, signed
//! by its cloud (ADR 0298): `gcp` with `VAULT_GCP_TYPE=gce`, the VM's identity token from the
//! metadata server; `aws` with `VAULT_AWS_TYPE=ec2`, the instance's PKCS#7 identity document
//! and a nonce. botd logs in again before the token's lease runs out and
//! once more when Vault refuses it, in `VAULT_AUTH_NAMESPACE` if the auth method is
//! mounted somewhere other than the secrets. Requests run on a runtime of their own
//! (`http::Worker`). It is also the `leases::Issuer` of `VAULT_RUN_CREDENTIALS`: a new
//! lease from a dynamic secrets engine for each run, renewed while the run lasts (ADR 0221)
//! and revoked when it ends (ADR 0185). With `VAULT_EVENTS=1` it follows Vault's change
//! events and reads a name again as it changes (`events`, ADR 0306).

use super::external::{self, Provider, Scope};
use super::http::Worker;
use super::leases::{Field, Issuer, Lease, Renewal};
use super::{aws, azure, gcp, Error, SecretStore};
use crate::audit::{Event, Outcome};
use base64::Engine;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub(crate) mod events;

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
    /// Vault's `aws` method (`iam` type, ADR 0260): an STS `GetCallerIdentity` request
    /// signed with botd's own AWS keys for `sts_url`, which Vault sends on. `role` None:
    /// the role named after botd's IAM principal.
    Aws { mount: String, role: Option<String>, region: String, sts_url: url::Url, server_id: Option<String>, creds: Box<aws::Credentials> },
    /// Vault's `gcp` method (`iam` type): a short JWT for `vault/<role>`, signed by IAM
    /// Credentials' `signJwt` as `account` (botd's own service account unless set).
    Gcp { mount: String, role: String, signer: Option<String>, iam: String, google: Box<gcp::Google> },
    /// Vault's `azure` method: botd's Entra ID token for the mount's `resource`, with the
    /// VM's subscription, resource group and name from instance metadata if `instance`.
    Azure { mount: String, role: String, instance: bool, entra: Box<azure::Entra> },
    /// Vault's `gcp` method, `gce` type (ADR 0298): the VM's identity token for
    /// `http://vault/<role>`, with the instance's details, from the metadata server.
    Gce { mount: String, role: String, google: Box<gcp::Google> },
    /// Vault's `aws` method, `ec2` type (ADR 0298): the instance's PKCS#7 identity document
    /// and the nonce every login after Vault's first must repeat. `role` None: the role
    /// named after the instance's AMI.
    Ec2 { mount: String, role: Option<String>, nonce: Zeroizing<String>, identity: aws::InstanceIdentity },
}

impl Auth {
    /// The method in audit details and errors' names for it, for those that log in.
    fn method(&self) -> &'static str {
        match self {
            Auth::Token { .. } => "token",
            Auth::AppRole { .. } => "approle",
            Auth::Jwt { method, .. } => method.as_str(),
            Auth::Aws { .. } | Auth::Ec2 { .. } => "aws",
            Auth::Gcp { .. } | Auth::Gce { .. } => "gcp",
            Auth::Azure { .. } => "azure",
        }
    }

    /// The method's login type in audit details, for the instance identity types only, so
    /// the `iam` type's events stay as ADR 0260 made them.
    fn login_type(&self) -> Option<&'static str> {
        match self {
            Auth::Gce { .. } => Some("gce"),
            Auth::Ec2 { .. } => Some("ec2"),
            _ => None,
        }
    }
}

/// How long the JWT botd has Google sign for a `gcp` login lasts: within the 15 minutes
/// Vault's roles allow by default (`max_jwt_exp`), with room for clocks.
const GCP_JWT_SECONDS: u64 = 600;
/// What Vault's `aws` mount checks the login's STS request against unless told otherwise.
const AWS_STS_REGION: &str = "us-east-1";
/// What Vault's `azure` mount takes tokens for unless its `resource` says otherwise.
const AZURE_RESOURCE: &str = "https://management.azure.com/";
/// The header Vault's `aws` mount checks against its `iam_server_id_header_value`.
const AWS_SERVER_ID_HEADER: &str = "x-vault-aws-iam-server-id";

/// A role name: letters, digits, `.`, `_`, `-` and `@`, up to 128.
fn role_setting(key: &str, raw: &str) -> Result<String, String> {
    let v = raw.trim();
    if v.is_empty() || v.len() > 128 || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b)) {
        return Err(format!("{key} must be a Vault role name like \"superbot\" (letters, digits, . _ - @), not {v:?}"));
    }
    Ok(v.to_string())
}

fn required_role(var: &dyn Fn(&str) -> String, method: &str, key: &str) -> Result<String, String> {
    match var(key).trim() {
        "" => Err(format!("VAULT_AUTH={method} needs {key}, the Vault role botd logs in as")),
        r => role_setting(key, r),
    }
}

/// A service account's email, as `signJwt` names it.
fn signer_setting(raw: &str) -> Result<String, String> {
    let ok = raw.len() <= 254 && raw.split_once('@').is_some_and(|(n, d)| !n.is_empty() && d.contains('.')) && raw.bytes().all(|b| b.is_ascii_alphanumeric() || b"@.-_".contains(&b));
    if !ok {
        return Err(format!("VAULT_GCP_SERVICE_ACCOUNT must be a service account's email like botd@my-project.iam.gserviceaccount.com, not {raw:?}"));
    }
    Ok(raw.to_string())
}

/// The region Vault's `aws` mount checks STS requests for (`VAULT_AWS_REGION`), the STS
/// URL botd signs for it, and where botd trades a web identity token for its own keys.
fn aws_sts(var: &dyn Fn(&str) -> String) -> Result<(String, url::Url, String), String> {
    let raw = var("VAULT_AWS_REGION");
    let region = match raw.trim() {
        "" => AWS_STS_REGION,
        r => r,
    };
    let parts: Vec<&str> = region.split('-').collect();
    let ok = region.len() <= 32
        && parts.len() >= 3
        && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
        && parts.last().is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()));
    if !ok {
        return Err(format!("VAULT_AWS_REGION must be the region of the aws mount's sts_endpoint, like {AWS_STS_REGION} (its default), not {region:?}"));
    }
    // As AWS's SDKs and Vault's own CLI sign it: STS's global endpoint for us-east-1.
    let host = match region {
        AWS_STS_REGION => "sts.amazonaws.com".to_string(),
        r if r.starts_with("cn-") => format!("sts.{r}.amazonaws.com.cn"),
        r => format!("sts.{r}.amazonaws.com"),
    };
    let sts_url = url::Url::parse(&format!("https://{host}/")).map_err(|e| format!("VAULT_AWS_REGION: {e}"))?;
    let web_identity_sts = match var("AWS_ENDPOINT_URL_STS").trim() {
        "" => sts_url.as_str().trim_end_matches('/').to_string(),
        e => super::http::base_url("AWS_ENDPOINT_URL_STS", e, "https://sts.amazonaws.com")?,
    };
    Ok((region.to_string(), sts_url, web_identity_sts))
}

/// What botd reaches to log in to Vault with these settings, as `(setting, URL, what)`, for
/// `botd offline check`: cloud sign-in's own endpoints (ADR 0260). Vault itself sends the
/// `aws` method's STS request, so STS is on Vault's side, not botd's.
pub fn sign_in_reaches(var: &dyn Fn(&str) -> String) -> Result<Vec<(&'static str, String, &'static str)>, String> {
    let mut out = Vec::new();
    match var("VAULT_AUTH").trim() {
        "aws" if var("VAULT_AWS_TYPE").trim() == "ec2" => out.extend(aws::instance_identity_reach(var)?),
        "gcp" if var("VAULT_GCP_TYPE").trim() == "gce" => out.extend(gcp::sign_in_reaches(var, "VAULT_GCP_CREDENTIALS", "metadata")?),
        "aws" => {
            let (_, _, sts) = aws_sts(var)?;
            if aws::chosen_source(var, "VAULT_AWS_CREDENTIALS")? == "web-identity" {
                out.push(("AWS_ENDPOINT_URL_STS", sts, "AWS STS, for botd's web identity"));
            }
            out.extend(aws::credentials_reach(var, "VAULT_AWS_CREDENTIALS")?);
        }
        "gcp" => {
            out.extend(gcp::sign_in_reaches(var, "VAULT_GCP_CREDENTIALS", &var("VAULT_GCP_CREDENTIALS"))?);
            let iam = match var("GCP_IAM_CREDENTIALS_ENDPOINT").trim() {
                "" => gcp::IAM_CREDENTIALS.to_string(),
                e => e.to_string(),
            };
            out.push(("GCP_IAM_CREDENTIALS_ENDPOINT", iam, "IAM Credentials, which signs botd's JWT for Vault"));
        }
        "azure" => out.extend(azure::sign_in_reaches(var, "VAULT_AZURE_CREDENTIALS", &var("VAULT_AZURE_CREDENTIALS"), false)?),
        _ => {}
    }
    Ok(out)
}

/// `VAULT_AUTH=aws`: the mount's settings, and botd's own AWS keys from AWS's standard
/// chain (`VAULT_AWS_CREDENTIALS`), kept from Bots while botd uses them.
fn aws_auth(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Auth, String> {
    let (region, sts_url, web_identity_sts) = aws_sts(var)?;
    let server_id = match var("VAULT_AWS_HEADER_VALUE").trim() {
        "" => None,
        v if v.len() <= 256 && v.bytes().all(|b| b.is_ascii_graphic()) => Some(v.to_string()),
        _ => return Err("VAULT_AWS_HEADER_VALUE must be the aws mount's iam_server_id_header_value, printable with no spaces, like vault.example.com".into()),
    };
    let role = match var("VAULT_AWS_ROLE").trim() {
        "" => None,
        r => Some(role_setting("VAULT_AWS_ROLE", r)?),
    };
    let source = aws::source_from_env(var, store, "VAULT_AWS_CREDENTIALS", "VAULT_AUTH=aws", &web_identity_sts)?;
    super::keep_from_bots(source.reserved(), source.settings());
    let creds = aws::Credentials::new("AWS (for Vault)", "vault", source)?;
    Ok(Auth::Aws { mount: path_setting("VAULT_AWS_MOUNT", &var("VAULT_AWS_MOUNT"), "aws")?, role, region, sts_url, server_id, creds: Box::new(creds) })
}

/// The shortest and longest `VAULT_AWS_NONCE`: long enough not to guess, short enough to be
/// a setting.
const NONCE_LEN: std::ops::RangeInclusive<usize> = 16..=128;

/// `VAULT_AUTH=aws` with `VAULT_AWS_TYPE=ec2` (ADR 0298): the instance's identity document
/// and botd's nonce, which Vault ties to the instance at its first login. The `iam` type's
/// settings would be ignored, so they are refused.
fn ec2_auth(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Auth, String> {
    for k in ["VAULT_AWS_REGION", "VAULT_AWS_HEADER_VALUE", "VAULT_AWS_CREDENTIALS"] {
        if !var(k).trim().is_empty() {
            return Err(format!("{k} is for VAULT_AWS_TYPE=iam; the ec2 type sends the instance's identity document and signs nothing, so leave {k} out"));
        }
    }
    let nonce = store.get("VAULT_AWS_NONCE").map_err(|e| format!("VAULT_AWS_NONCE: {e}"))?;
    let nonce = nonce.map(|v| Zeroizing::new(v.expose().trim().to_string())).filter(|v| !v.is_empty());
    let nonce = nonce.ok_or("VAULT_AWS_TYPE=ec2 needs VAULT_AWS_NONCE (or VAULT_AWS_NONCE_FILE), a random value botd sends with every login, such as the output of openssl rand -hex 32; Vault refuses a later login without the first one's")?;
    if !NONCE_LEN.contains(&nonce.len()) || !nonce.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\') {
        return Err(format!("VAULT_AWS_NONCE must be {} to {} printable characters with no spaces or quotes, such as the output of openssl rand -hex 32", NONCE_LEN.start(), NONCE_LEN.end()));
    }
    super::redact::register(&nonce);
    let role = match var("VAULT_AWS_ROLE").trim() {
        "" => None,
        r => Some(role_setting("VAULT_AWS_ROLE", r)?),
    };
    let identity = aws::InstanceIdentity::from_env(var, "VAULT_AWS_TYPE=ec2")?;
    Ok(Auth::Ec2 { mount: path_setting("VAULT_AWS_MOUNT", &var("VAULT_AWS_MOUNT"), "aws")?, role, nonce, identity })
}

/// `VAULT_AUTH=gcp` with `VAULT_GCP_TYPE=gce` (ADR 0298): the VM's identity token, which only
/// the metadata server makes, for the VM's own service account.
fn gce_auth(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Auth, String> {
    match var("VAULT_GCP_CREDENTIALS").trim() {
        "" | "metadata" => {}
        other => return Err(format!("VAULT_GCP_TYPE=gce logs in with the VM's identity token from the metadata server, so VAULT_GCP_CREDENTIALS must be metadata (or unset), not {other:?}")),
    }
    if !var("VAULT_GCP_SERVICE_ACCOUNT").trim().is_empty() {
        return Err("VAULT_GCP_SERVICE_ACCOUNT is for VAULT_GCP_TYPE=iam; the gce type's token is for the VM's own service account, so leave it out".into());
    }
    Ok(Auth::Gce {
        mount: path_setting("VAULT_GCP_MOUNT", &var("VAULT_GCP_MOUNT"), "gcp")?,
        role: required_role(var, "gcp", "VAULT_GCP_ROLE")?,
        google: Box::new(gcp::Google::from_env(var, store, "VAULT_GCP_CREDENTIALS", "metadata", "Google (for Vault)")?),
    })
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
    /// `VAULT_EVENTS=1`: follow Vault's change events and read a name again as it changes (ADR 0306).
    pub events: bool,
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
            "aws" => match var("VAULT_AWS_TYPE").trim() {
                "" | "iam" => aws_auth(var, store)?,
                "ec2" => ec2_auth(var, store)?,
                other => return Err(format!("VAULT_AWS_TYPE must be iam (the default) or ec2, not {other:?}")),
            },
            "gcp" => match var("VAULT_GCP_TYPE").trim() {
                "" | "iam" => Auth::Gcp {
                    mount: path_setting("VAULT_GCP_MOUNT", &var("VAULT_GCP_MOUNT"), "gcp")?,
                    role: required_role(var, "gcp", "VAULT_GCP_ROLE")?,
                    signer: match var("VAULT_GCP_SERVICE_ACCOUNT").trim() {
                        "" => None,
                        a => Some(signer_setting(a)?),
                    },
                    iam: match var("GCP_IAM_CREDENTIALS_ENDPOINT").trim() {
                        "" => gcp::IAM_CREDENTIALS.to_string(),
                        e => super::http::base_url("GCP_IAM_CREDENTIALS_ENDPOINT", e, gcp::IAM_CREDENTIALS)?,
                    },
                    google: Box::new(gcp::Google::from_env(var, store, "VAULT_GCP_CREDENTIALS", &var("VAULT_GCP_CREDENTIALS"), "Google (for Vault)")?),
                },
                "gce" => gce_auth(var, store)?,
                other => return Err(format!("VAULT_GCP_TYPE must be iam (the default) or gce, not {other:?}")),
            },
            "azure" => {
                let resource = match var("VAULT_AZURE_RESOURCE").trim() {
                    "" => AZURE_RESOURCE.to_string(),
                    r if r.len() <= 256 && !r.contains(|c: char| c.is_whitespace() || c.is_control()) => r.to_string(),
                    r => return Err(format!("VAULT_AZURE_RESOURCE must be the resource the azure mount takes tokens for, like {AZURE_RESOURCE}, not {r:?}")),
                };
                let entra = azure::Entra::from_env(var, store, "VAULT_AZURE_CREDENTIALS", &var("VAULT_AZURE_CREDENTIALS"), "Entra ID (for Vault)", &resource)?;
                let instance = match var("VAULT_AZURE_INSTANCE").trim() {
                    "" | "0" => false,
                    "1" if entra.on_vm() => true,
                    "1" => return Err("VAULT_AZURE_INSTANCE=1 reads the VM's details from its instance metadata service, so it needs VAULT_AZURE_CREDENTIALS=managed-identity on a VM or scale set (no IDENTITY_ENDPOINT)".into()),
                    other => return Err(format!("VAULT_AZURE_INSTANCE must be 1 or 0, not {other:?}")),
                };
                Auth::Azure { mount: path_setting("VAULT_AZURE_MOUNT", &var("VAULT_AZURE_MOUNT"), "azure")?, role: required_role(var, "azure", "VAULT_AZURE_ROLE")?, instance, entra: Box::new(entra) }
            }
            other => return Err(format!("VAULT_AUTH must be token, approle, kubernetes, jwt, aws, gcp or azure, not {other:?}")),
        };
        if auth_namespace != AuthNamespace::Same && matches!(auth, Auth::Token { .. }) {
            return Err("VAULT_AUTH_NAMESPACE is where botd logs in, so it needs a VAULT_AUTH that logs in (approle, kubernetes, jwt, aws, gcp or azure); a token needs no login".into());
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
        let events = match var("VAULT_EVENTS").trim() {
            "" | "0" => false,
            "1" => true,
            other => return Err(format!("VAULT_EVENTS must be 1 (follow Vault's change events, Vault Enterprise) or 0, not {other:?}")),
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
            events,
        })
    }
}

/// How much longer than a run the token that makes its leases must live: the run's
/// end, its harness's exit and the revoke all come after the timeout.
const TOKEN_MARGIN: Duration = Duration::from_secs(300);

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

/// Clones share one client, token and runtime: the store and the run credentials' issuer.
#[derive(Clone)]
pub struct Vault {
    inner: Arc<Inner>,
    worker: Arc<Worker>,
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

/// `{"jwt", "role"}` for the methods that take a JWT. A JWT is base64url and dots, so it
/// needs no escaping; roles are checked at startup.
fn jwt_body(jwt: &str, role: Option<&str>) -> Zeroizing<String> {
    let role = role.map(|r| format!(",\"role\":\"{r}\"")).unwrap_or_default();
    Zeroizing::new(format!("{{\"jwt\":\"{jwt}\"{role}}}"))
}

/// The login body of Vault's `aws` method: an STS `GetCallerIdentity` request signed with
/// `keys` for `sts_url` in `region`, which Vault sends to STS to learn who botd is. The
/// server id header, when the mount wants one, is signed so the request can't be replayed
/// to another Vault. Never sent to STS by botd.
fn aws_body(keys: &aws::Keys, role: Option<&str>, region: &str, sts_url: &url::Url, server_id: Option<&str>) -> Zeroizing<String> {
    const BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15";
    const FORM: &str = "application/x-www-form-urlencoded; charset=utf-8";
    let host = sts_url.host_str().unwrap_or_default();
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let scope = crate::sigv4::Scope { amz_date: &amz_date, region, service: "sts" };
    let mut headers = vec![("content-type", FORM), ("host", host), ("x-amz-date", amz_date.as_str())];
    if let Some(t) = &keys.token {
        headers.push(("x-amz-security-token", t.as_str()));
    }
    if let Some(v) = server_id {
        headers.push((AWS_SERVER_ID_HEADER, v));
    }
    let (signed, sig) = crate::sigv4::signature(&keys.secret, &scope, "POST", "/", "", &headers, &crate::sigv4::sha256_hex(BODY.as_bytes()));
    let authorization = Zeroizing::new(scope.authorization(&keys.id, &signed, &sig));
    let mut sent = serde_json::Map::new();
    sent.insert("Authorization".into(), json!([authorization.as_str()]));
    for (k, v) in &headers {
        let name = match *k {
            "content-type" => "Content-Type",
            "host" => "Host",
            "x-amz-date" => "X-Amz-Date",
            "x-amz-security-token" => "X-Amz-Security-Token",
            _ => "X-Vault-AWS-IAM-Server-ID",
        };
        sent.insert(name.into(), json!([v]));
    }
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let headers = Zeroizing::new(Value::Object(sent).to_string());
    let mut body = json!({
        "iam_http_request_method": "POST",
        "iam_request_url": b64(sts_url.as_str().as_bytes()),
        "iam_request_body": b64(BODY.as_bytes()),
        "iam_request_headers": b64(headers.as_bytes()),
    });
    if let Some(r) = role {
        body["role"] = json!(r);
    }
    Zeroizing::new(body.to_string())
}

impl Vault {
    pub fn new(cfg: Config) -> Result<Vault, String> {
        let http = super::http::client("Vault", cfg.ca.as_deref().map(|pem| ("VAULT_CACERT", pem)), false)?;
        Ok(Vault { inner: Arc::new(Inner { cfg, http, token: Mutex::new(None) }), worker: Arc::new(Worker::new("Vault", "vault")?) })
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

    fn secret_path(&self, kind: &str, scope: &Scope, name: &str) -> String {
        format!("{}/{kind}/{}/{}/{name}", self.cfg.mount, self.cfg.prefix, scope.folder('/'))
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
                self.login(mount, None, async { Ok::<_, Error>(body) }).await?
            }
            Auth::Jwt { method, mount, role, file } => {
                let body = async {
                    let jwt = read_jwt(*method, file)?;
                    Ok(jwt_body(&jwt, role.as_deref()))
                };
                self.login(mount, role.as_deref(), body).await?
            }
            Auth::Aws { mount, role, region, sts_url, server_id, creds } => {
                let body = async {
                    // New keys too when Vault refused its token: they may be what it refused.
                    let keys = creds.keys(fresh).await?;
                    Ok(aws_body(&keys, role.as_deref(), region, sts_url, server_id.as_deref()))
                };
                self.login(mount, role.as_deref(), body).await?
            }
            Auth::Gcp { mount, role, signer, iam, google } => self.login(mount, Some(role), self.gcp_jwt(role, signer.as_deref(), iam, google, fresh)).await?,
            Auth::Azure { mount, role, instance, entra } => {
                let body = async {
                    let token = Zeroizing::new(entra.token(fresh).await.map_err(Error::Unavailable)?.to_string());
                    let mut body = json!({ "role": role, "jwt": token.as_str() });
                    if *instance {
                        let vm = entra.vm().await.map_err(Error::Unavailable)?;
                        body["subscription_id"] = json!(vm.subscription);
                        body["resource_group_name"] = json!(vm.resource_group);
                        // Vault ignores vm_name when vmss_name is given.
                        match vm.scale_set {
                            Some(s) => body["vmss_name"] = json!(s),
                            None => body["vm_name"] = json!(vm.name),
                        }
                    }
                    Ok(Zeroizing::new(body.to_string()))
                };
                self.login(mount, Some(role), body).await?
            }
            Auth::Gce { mount, role, google } => {
                let body = async {
                    // As Vault Agent asks for it; Vault checks that the audience ends in `vault/<role>`.
                    let jwt = google.instance_identity(&format!("http://vault/{role}")).await.map_err(Error::Unavailable)?;
                    Ok(jwt_body(&jwt, Some(role)))
                };
                self.login(mount, Some(role), body).await?
            }
            Auth::Ec2 { mount, role, nonce, identity } => {
                let body = async {
                    let mut body = json!({ "pkcs7": identity.pkcs7().await?, "nonce": nonce.as_str() });
                    if let Some(r) = role {
                        body["role"] = json!(r);
                    }
                    Ok(Zeroizing::new(body.to_string()))
                };
                self.login(mount, role.as_deref(), body).await?
            }
        };
        let value = t.value.clone();
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = Some(t);
        Ok(value)
    }

    /// A JWT for `vault/<role>`, signed by Google's IAM Credentials as `signer` (botd's
    /// own service account unless set) with botd's own token, for Vault's `gcp` method;
    /// the login body. A token IAM Credentials refuses is replaced once.
    async fn gcp_jwt(&self, role: &str, signer: Option<&str>, iam: &str, google: &gcp::Google, fresh: bool) -> Result<Zeroizing<String>, Error> {
        let signer = match signer {
            Some(a) => a.to_string(),
            None => google.principal().await.map_err(Error::Unavailable)?,
        };
        let exp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()) + GCP_JWT_SECONDS;
        let payload = json!({ "aud": format!("vault/{role}"), "sub": signer, "exp": exp }).to_string();
        let url = format!("{iam}/v1/projects/-/serviceAccounts/{signer}:signJwt");
        let what = format!("signJwt as {signer}");
        let mut fresh = fresh;
        loop {
            let token = google.token(fresh).await.map_err(Error::Unavailable)?;
            let res = google.client().post(&url).bearer_auth(token.as_str()).json(&json!({ "payload": payload })).send().await.map_err(|e| unavailable(&what, e))?;
            let status = res.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && !fresh {
                fresh = true;
                continue;
            }
            let body = Zeroizing::new(res.bytes().await.map_err(|e| unavailable(&what, e))?.to_vec());
            if !status.is_success() {
                let hint = if status == reqwest::StatusCode::FORBIDDEN { "; botd's identity needs iam.serviceAccounts.signJwt on the account (Service Account Token Creator), and the IAM Credentials API must be on" } else { "" };
                return Err(Error::Unavailable(format!("Vault: Google's {what} answered {status}{}{hint}", super::http::error_code(&body))));
            }
            let v: Value = serde_json::from_slice(&body).map_err(|e| unavailable(&what, e))?;
            let jwt = v["signedJwt"].as_str().filter(|j| !j.is_empty()).ok_or_else(|| Error::Unavailable(format!("Vault: Google's {what} gave no JWT")))?;
            let jwt = Zeroizing::new(jwt.to_string());
            if jwt.split('.').count() != 3 || !jwt.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')) {
                return Err(Error::Unavailable(format!("Vault: Google's {what} gave something that isn't a JWT")));
            }
            return Ok(jwt_body(&jwt, Some(role)));
        }
    }

    /// Logs in at `auth/<mount>/login` with the JSON `body`, in the auth namespace, and
    /// audits it as `secret.vault_login` with the method and role, never a credential.
    async fn login(&self, mount: &str, role: Option<&str>, body: impl std::future::Future<Output = Result<Zeroizing<String>, Error>>) -> Result<Token, Error> {
        let method = self.cfg.auth.method();
        let what = match method {
            "approle" => "AppRole login",
            "kubernetes" => "Kubernetes login",
            "aws" => "AWS login",
            "gcp" => "GCP login",
            "azure" => "Azure login",
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
                // Vault's text can echo what was sent, so only a hint of ours.
                let hint = match &self.cfg.auth {
                    Auth::Ec2 { .. } if status == reqwest::StatusCode::BAD_REQUEST => {
                        "; Vault's log has the reason, often a nonce other than the one it took at this instance's first login (VAULT_AWS_NONCE changed, or another client logged in first) or a role not bound to this instance"
                    }
                    _ => "",
                };
                return Err(Error::Unavailable(format!("Vault: {what} at auth/{mount} answered {status}{hint}")));
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
        if let Some(t) = self.cfg.auth.login_type() {
            details["type"] = json!(t);
        }
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

    /// GETs `path`; when Vault refuses the token, gets a new one and asks once more. With
    /// `index` (an event's `vault_index`), a node that hasn't caught up with it yet waits or
    /// refuses rather than answering from before the change (ADR 0306).
    async fn get(&self, path: &str, index: Option<&str>) -> Result<Option<Value>, Error> {
        for fresh in [false, true] {
            let token = self.token(fresh).await?;
            if let Some(v) = self.get_with(path, &token, fresh, index).await? {
                return Ok(v);
            }
        }
        unreachable!("the second pass returns")
    }

    /// GETs `path` with `token`: the answer (None for 404), or None if Vault refused the
    /// token and `last` is false.
    async fn get_with(&self, path: &str, token: &str, last: bool, index: Option<&str>) -> Result<Option<Option<Value>>, Error> {
        let mut r = self.request(reqwest::Method::GET, path).header("X-Vault-Token", token);
        if let Some(i) = index {
            r = r.header("X-Vault-Index", i);
        }
        let res = r.send().await.map_err(|e| unavailable(path, e))?;
        let status = res.status();
        if status == reqwest::StatusCode::FORBIDDEN && !last {
            return Ok(None);
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(Some(None));
        }
        if !status.is_success() {
            return Err(Error::Unavailable(format!("Vault answered {status} for {path}")));
        }
        let body = Zeroizing::new(res.bytes().await.map_err(|e| unavailable(path, e))?.to_vec());
        let v: Value = serde_json::from_slice(&body).map_err(|e| unavailable(path, e))?;
        Ok(Some(Some(v)))
    }

    /// A token that lives at least `run_for` and a margin more, so the leases it makes do:
    /// Vault revokes a token's leases with it, whatever their own TTL. A token that ends
    /// sooner is renewed (`renew-self`), else, when botd logs in, replaced by a new login;
    /// failing both, an error, so the run is refused rather than losing its credentials.
    /// A token Vault refuses (rotated by Vault Agent, revoked) is replaced once, as for reads.
    async fn token_for(&self, run_for: Duration, fresh: bool) -> Result<Zeroizing<String>, Error> {
        let want = run_for.as_secs() + TOKEN_MARGIN.as_secs();
        let logs_in = !matches!(self.cfg.auth, Auth::Token { .. });
        let mut fresh = fresh;
        loop {
            let token = self.token(fresh).await?;
            let Some((ttl, renewable)) = self.token_life(&token, "auth/token/lookup-self", reqwest::Method::GET, None, fresh).await? else {
                fresh = true;
                continue;
            };
            // 0: a token that never ends, such as a root token.
            if ttl == 0 || ttl >= want {
                return Ok(token);
            }
            if renewable {
                let renewed = self.token_life(&token, "auth/token/renew-self", reqwest::Method::POST, Some(want), true).await?;
                if renewed.is_some_and(|(t, _)| t >= want) {
                    return Ok(token);
                }
            }
            if fresh || !logs_in {
                return Err(Error::Unavailable(format!(
                    "Vault: botd's token ends in {ttl} s and can't be renewed past that, but a run may last {} s (RUN_TIMEOUT_MINUTES), and Vault would revoke its leases with the token; raise the token's TTL or max TTL",
                    run_for.as_secs()
                )));
            }
            fresh = true;
        }
    }

    /// Looks up or renews `token` itself: its remaining TTL in seconds and whether it is
    /// renewable, or None if Vault refused the token and `last` is false. Sent where the
    /// token was made (the auth namespace).
    async fn token_life(&self, token: &str, path: &str, method: reqwest::Method, increment: Option<u64>, last: bool) -> Result<Option<(u64, bool)>, Error> {
        let mut r = self.request_in(self.auth_namespace(), method, path).header("X-Vault-Token", token);
        if let Some(n) = increment {
            r = r.json(&json!({ "increment": n }));
        }
        let res = r.send().await.map_err(|e| unavailable(path, e))?;
        let status = res.status();
        if status == reqwest::StatusCode::FORBIDDEN && !last {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(Error::Unavailable(format!("Vault answered {status} for {path}; botd's policy needs Vault's default policy, which allows it")));
        }
        let v: Value = res.json().await.map_err(|e| unavailable(path, e))?;
        Ok(Some(match increment {
            None => (v["data"]["ttl"].as_u64().unwrap_or(0), v["data"]["renewable"].as_bool().unwrap_or(false)),
            Some(_) => (v["auth"]["lease_duration"].as_u64().unwrap_or(0), v["auth"]["renewable"].as_bool().unwrap_or(false)),
        }))
    }

    async fn read(&self, scope: Scope, name: &str, index: Option<&str>) -> Result<Option<Zeroizing<String>>, Error> {
        let path = self.secret_path("data", &scope, name);
        let Some(body) = self.get(&path, index).await? else { return Ok(None) };
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

    async fn list(&self, scope: Scope, index: Option<&str>) -> Result<Vec<String>, Error> {
        let path = format!("{}/metadata/{}/{}/", self.cfg.mount, self.cfg.prefix, scope.folder('/'));
        let Some(body) = self.get(&format!("{path}?list=true"), index).await? else { return Ok(Vec::new()) };
        let keys = body["data"]["keys"].as_array().ok_or_else(|| Error::Unavailable(format!("Vault: listing {path} gave no keys")))?;
        Ok(keys.iter().filter_map(Value::as_str).filter(|k| !k.ends_with('/')).map(String::from).collect())
    }

    /// A new lease from a dynamic secrets engine: `GET <path>` (ADR 0185), made with a
    /// token that outlives the run (`token_for`).
    async fn issue(&self, path: &str, fields: &[String], run_for: Duration) -> Result<Lease, Error> {
        let mut body = None;
        for fresh in [false, true] {
            let token = self.token_for(run_for, fresh).await?;
            if let Some(b) = self.get_with(path, &token, fresh, None).await? {
                body = b;
                break;
            }
        }
        let body = body.ok_or_else(|| Error::Unavailable(format!("Vault: nothing at {path}; is the secrets engine mounted there, with that role?")))?;
        let Some(id) = body["lease_id"].as_str().filter(|s| !s.is_empty()) else {
            return Err(Error::Unavailable(format!("Vault: {path} gave no lease; VAULT_RUN_CREDENTIALS is for dynamic secrets, keep static ones in the bots folder")));
        };
        let data = &body["data"];
        let fields = fields
            .iter()
            .map(|f| match data.get(f.as_str()) {
                None => Field::Missing,
                Some(Value::Null) => Field::Empty,
                Some(Value::String(s)) if s.is_empty() => Field::Empty,
                Some(Value::String(s)) => Field::Value(Zeroizing::new(s.clone())),
                Some(Value::Number(n)) => Field::Value(Zeroizing::new(n.to_string())),
                Some(_) => Field::Missing,
            })
            .collect();
        Ok(Lease { id: id.to_string(), ttl: body["lease_duration"].as_u64().unwrap_or(0), renewable: body["renewable"].as_bool().unwrap_or(false), fields })
    }

    /// `PUT sys/leases/revoke/<lease id>`, so botd's policy can allow revoking only the
    /// leases of the paths it reads. When Vault refuses the token, gets a new one and asks once more.
    async fn revoke(&self, lease_id: &str) -> Result<(), Error> {
        let path = format!("sys/leases/revoke/{}", lease_path(lease_id)?);
        for fresh in [false, true] {
            let token = self.token(fresh).await?;
            let res = self.request(reqwest::Method::PUT, &path).header("X-Vault-Token", token.as_str()).send().await.map_err(|e| unavailable("sys/leases/revoke", e))?;
            let status = res.status();
            if status == reqwest::StatusCode::FORBIDDEN && !fresh {
                continue;
            }
            if !status.is_success() {
                return Err(Error::Unavailable(format!("Vault answered {status} for sys/leases/revoke")));
            }
            return Ok(());
        }
        unreachable!("the second pass returns")
    }

    /// `PUT sys/leases/renew/<lease id>` for `increment` seconds more (ADR 0221), so botd's
    /// policy can allow renewing only the leases of the paths it reads. Vault gives less
    /// than asked at the role's max TTL. A 400 or 404 (the lease is gone or not renewable)
    /// or a 403 with a fresh token (the policy doesn't allow it) is final; anything else
    /// may pass and is tried again.
    async fn renew(&self, lease_id: &str, increment: u64) -> Result<Renewal, Error> {
        let path = format!("sys/leases/renew/{}", lease_path(lease_id)?);
        for fresh in [false, true] {
            let token = self.token(fresh).await?;
            let res = self
                .request(reqwest::Method::PUT, &path)
                .header("X-Vault-Token", token.as_str())
                .json(&json!({ "increment": increment }))
                .send()
                .await
                .map_err(|e| unavailable("sys/leases/renew", e))?;
            let status = res.status();
            if status == reqwest::StatusCode::FORBIDDEN && !fresh {
                continue;
            }
            match status {
                reqwest::StatusCode::FORBIDDEN => return Ok(Renewal::Refused(format!("Vault answered {status} for sys/leases/renew; botd's policy needs update on sys/leases/renew/<path>/* for each path"))),
                reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::NOT_FOUND => return Ok(Renewal::Refused(format!("Vault answered {status} for sys/leases/renew: the lease is gone or can't be renewed"))),
                s if !s.is_success() => return Err(Error::Unavailable(format!("Vault answered {status} for sys/leases/renew"))),
                _ => {}
            }
            let v: Value = res.json().await.map_err(|e| unavailable("sys/leases/renew", e))?;
            let ttl = v["lease_duration"].as_u64().ok_or_else(|| Error::Unavailable("Vault: sys/leases/renew gave an answer that isn't a lease".into()))?;
            return Ok(Renewal::Renewed { ttl, renewable: v["renewable"].as_bool().unwrap_or(false) });
        }
        unreachable!("the second pass returns")
    }
}

/// A lease id as part of a URL path: `/`-separated parts of letters, digits, `.`, `_` and `-`.
fn lease_path(lease_id: &str) -> Result<&str, Error> {
    let ok = !lease_id.is_empty() && lease_id.split('/').all(|p| !p.is_empty() && p != "." && p != ".." && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)));
    if !ok {
        return Err(Error::Unavailable("Vault: a lease id that can't be part of a path".into()));
    }
    Ok(lease_id)
}

impl Issuer for Vault {
    fn kind(&self) -> &'static str {
        "vault"
    }

    fn issue(&self, path: &str, fields: &[String], run_for: Duration, _bot_id: &str) -> Result<Lease, Error> {
        let (path, fields) = (path.to_string(), fields.to_vec());
        self.run(move |i| async move { i.issue(&path, &fields, run_for).await })
    }

    fn revoke(&self, lease_id: &str) -> Result<(), Error> {
        let lease_id = lease_id.to_string();
        self.run(move |i| async move { i.revoke(&lease_id).await })
    }

    fn renew(&self, lease_id: &str, increment: Duration) -> Result<Renewal, Error> {
        let lease_id = lease_id.to_string();
        self.run(move |i| async move { i.renew(&lease_id, increment.as_secs()).await })
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
            Auth::Aws { mount, role, region, server_id, creds, .. } => {
                let role = role.as_deref().map_or_else(|| "the role named after its IAM principal".to_string(), |r| format!("role {r}"));
                let header = if server_id.is_some() { ", with the server id header" } else { "" };
                format!("AWS login as {role} at auth/{mount}, an STS request signed for {region}{header} with {}", creds.describe())
            }
            Auth::Gcp { mount, role, signer, google, .. } => {
                let who = signer.as_deref().map_or_else(|| "its own service account".to_string(), |a| format!("service account {a}"));
                format!("GCP login as role {role} at auth/{mount}, a JWT signed as {who} with {}", google.describe())
            }
            Auth::Azure { mount, role, instance, entra } => {
                let vm = if *instance { ", with the VM's details" } else { "" };
                format!("Azure login as role {role} at auth/{mount}, a token for {} from {}{vm}", entra.resource(), entra.describe())
            }
            Auth::Gce { mount, role, google } => format!("GCP login (gce) as role {role} at auth/{mount}, the VM's identity token of {}", google.describe()),
            Auth::Ec2 { mount, role, identity, .. } => {
                let role = role.as_deref().map_or_else(|| "the role named after its AMI".to_string(), |r| format!("role {r}"));
                format!("AWS login (ec2) as {role} at auth/{mount}, the instance's signed identity document from {} with the nonce in VAULT_AWS_NONCE", identity.describe())
            }
        };
        let auth_ns = match &c.auth_namespace {
            AuthNamespace::Same => String::new(),
            AuthNamespace::Root => " in the root namespace".to_string(),
            AuthNamespace::Path(n) => format!(" in namespace {n}"),
        };
        let ns = c.namespace.as_deref().map(|n| format!(", namespace {n}")).unwrap_or_default();
        let events = if c.events { ", following Vault's change events" } else { "" };
        format!("HashiCorp Vault at {}{ns}, KV v2 {}/{}/{{bots,server}}/<NAME> field {:?}, {auth}{auth_ns}{events}", c.addr, c.mount, c.prefix, c.field)
    }

    fn read(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let name = name.to_string();
        self.run(move |i| async move { i.read(scope, &name, None).await })
    }

    fn list(&self, scope: Scope) -> Result<Vec<String>, Error> {
        self.run(move |i| async move { i.list(scope, None).await })
    }

    fn list_at(&self, scope: Scope, index: Option<&str>) -> Result<Vec<String>, Error> {
        let index = index.map(str::to_string);
        self.run(move |i| async move { i.list(scope, index.as_deref()).await })
    }

    fn read_at(&self, scope: Scope, name: &str, index: Option<&str>) -> Result<Option<Zeroizing<String>>, Error> {
        let (name, index) = (name.to_string(), index.map(str::to_string));
        self.run(move |i| async move { i.read(scope, &name, index.as_deref()).await })
    }

    fn watch(&self, store: std::sync::Weak<external::ExternalStore>) -> Result<bool, Error> {
        if !self.inner.cfg.events {
            return Ok(false);
        }
        events::start(self, store)?;
        Ok(true)
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
        pub kv: Mutex<HashMap<String, Value>>,
        pub tokens: Mutex<Vec<String>>,
        /// JWTs a `kubernetes` or `jwt` mount accepts: (mount, role, JWT).
        pub jwts: Mutex<Vec<(String, Option<String>, String)>>,
        pub logins: AtomicUsize,
        pub reads: AtomicUsize,
        down: AtomicBool,
        namespaces: Mutex<Vec<String>>,
        /// The namespace each login was sent to ("" for none).
        pub login_namespaces: Mutex<Vec<String>>,
        pub lease: AtomicUsize,
        delay_ms: AtomicUsize,
        /// `<engine>/creds/<role>` → the fields each lease from it has.
        creds: Mutex<HashMap<String, Value>>,
        issued: AtomicUsize,
        pub revoked: Mutex<Vec<String>>,
        /// token → (TTL left in seconds, renewable); a token not here never ends.
        ttls: Mutex<HashMap<String, (u64, bool)>>,
        /// The most `renew-self` gives (0: no limit), as a token's max TTL.
        max_ttl: AtomicUsize,
        /// (token, TTL asked for) of each `renew-self`.
        renewals: Mutex<Vec<(String, u64)>>,
        /// The TTL of each lease from a dynamic secrets engine (0: 900 s).
        creds_ttl: AtomicUsize,
        /// The most a lease renewal gives (0: no limit), as a role's max TTL.
        lease_max: AtomicUsize,
        /// Leases the engines made.
        made: Mutex<Vec<String>>,
        /// (lease id, increment asked for) of each `sys/leases/renew`.
        lease_renewals: Mutex<Vec<(String, u64)>>,
        /// AWS access key id → its secret and session token, as STS knows them.
        pub aws_keys: Mutex<HashMap<String, (String, Option<String>)>>,
        /// The `aws` mount's `iam_server_id_header_value`.
        pub aws_server_id: Mutex<Option<String>>,
        /// Each `aws` login STS answered: (key id, region, role, the URL it was signed for).
        pub aws_logins: Mutex<Vec<(String, String, String, String)>>,
        /// Keys the stand-in instance metadata service handed out.
        imds_issued: AtomicUsize,
        /// Google access tokens the stand-in metadata server handed out, and which `signJwt` takes.
        google_tokens: Mutex<Vec<String>>,
        /// Each `signJwt`: (account, payload).
        signed: Mutex<Vec<(String, Value)>>,
        /// Answers `signJwt` with this status instead, once.
        sign_status: AtomicUsize,
        /// The resource each managed identity token was asked for.
        azure_resources: Mutex<Vec<String>>,
        /// Each `azure` login's body, its token taken out.
        azure_logins: Mutex<Vec<Value>>,
        /// Each identity token the stand-in metadata server made: (audience, format).
        identities: Mutex<Vec<(String, String)>>,
        /// Answers the next identity token request with this status instead, once.
        identity_status: AtomicUsize,
        /// The nonce the `aws` mount took at the instance's first `ec2` login.
        ec2_nonce: Mutex<Option<String>>,
        /// The role of each `ec2` login Vault let in.
        ec2_logins: Mutex<Vec<String>>,
        /// Change event streams (ADR 0306).
        pub events: events::tests::Hub,
    }

    /// The instance's PKCS#7 identity document as IMDS gives it: base64 in lines of 64.
    pub(crate) fn ec2_pkcs7() -> String {
        let doc = json!({ "accountId": "123456789012", "imageId": EC2_AMI, "instanceId": "i-0abc1234def567890", "region": "eu-west-2", "pendingTime": "2026-11-25T08:00:00Z" });
        let b64 = base64::engine::general_purpose::STANDARD.encode(format!("stand-in signature over {doc}"));
        b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n")
    }

    /// The role an `ec2` login with none is for: the one named after the instance's AMI.
    const EC2_AMI: &str = "ami-0abcdef1234567890";

    pub(crate) type F = Arc<Fake>;

    /// A compact JWT for `sub` that expires `exp_in` seconds from now. Unsigned: the
    /// stand-in, like Vault's role, only compares it.
    pub(crate) fn jwt(sub: &str, exp_in: i64) -> String {
        let b64 = |v: Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        format!("{}.{}.{}", b64(json!({ "alg": "RS256", "kid": "k1" })), b64(json!({ "iss": "https://kubernetes.default.svc", "sub": sub, "exp": now + exp_in })), crate::random_hex(16))
    }

    pub(crate) fn check(f: &Fake, h: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
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
        f.events.saw(&h);
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
        f.events.listed(&h);
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

    /// What Vault's `aws` method checks of a login before sending its request to STS, and
    /// what STS checks of the signature: the role it is for, else why it is refused.
    fn aws_login(f: &Fake, body: &Value) -> Result<String, &'static str> {
        let decode = |k: &str| body[k].as_str().and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok()).and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
        let (url, form) = (decode("iam_request_url"), decode("iam_request_body"));
        if body["iam_http_request_method"] != "POST" || form != "Action=GetCallerIdentity&Version=2011-06-15" {
            return Err("not a GetCallerIdentity request");
        }
        let headers: HashMap<String, Vec<String>> = serde_json::from_str(&decode("iam_request_headers")).map_err(|_| "headers aren't a map of lists")?;
        let header = |k: &str| headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).and_then(|(_, v)| v.first().cloned()).unwrap_or_default();
        let auth = header("authorization");
        let field = |name: &str| auth.split([' ', ',']).find_map(|p| p.strip_prefix(&format!("{name}="))).unwrap_or_default().to_string();
        let credential = field("Credential");
        let [id, date, region, "sts", "aws4_request"] = credential.split('/').collect::<Vec<_>>()[..] else { return Err("IncompleteSignature") };
        let Some((secret, token)) = f.aws_keys.lock().unwrap().get(id).cloned() else { return Err("InvalidClientTokenId") };
        if token.unwrap_or_default() != header("x-amz-security-token") {
            return Err("InvalidClientTokenId");
        }
        let signed = field("SignedHeaders");
        if let Some(want) = f.aws_server_id.lock().unwrap().clone()
            && (header(AWS_SERVER_ID_HEADER) != want || !signed.split(';').any(|h| h == AWS_SERVER_ID_HEADER))
        {
            return Err("missing or unsigned server id header");
        }
        let host = url::Url::parse(&url).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default();
        if header("host") != host || !header("x-amz-date").starts_with(date) {
            return Err("IncompleteSignature");
        }
        let values: Vec<(String, String)> = signed.split(';').map(|n| (n.to_string(), header(n))).collect();
        let pairs: Vec<(&str, &str)> = values.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let amz_date = header("x-amz-date");
        let scope = crate::sigv4::Scope { amz_date: &amz_date, region, service: "sts" };
        let (_, sig) = crate::sigv4::signature(&secret, &scope, "POST", "/", "", &pairs, &crate::sigv4::sha256_hex(form.as_bytes()));
        if sig != field("Signature") {
            return Err("SignatureDoesNotMatch");
        }
        // No role: Vault's role named after the principal, here the instance profile's.
        let role = body["role"].as_str().unwrap_or("botd-role").to_string();
        f.aws_logins.lock().unwrap().push((id.to_string(), region.to_string(), role.clone(), url));
        Ok(role)
    }

    /// `auth/approle/login` takes `role-1` and `secret-id-1`; a body with an STS request
    /// is checked as Vault's `aws` method does; any other mount takes the JWTs in `jwts`.
    async fn login(State(f): State<F>, Path(mount): Path<String>, h: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
        f.login_namespaces.lock().unwrap().push(h.get("x-vault-namespace").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string());
        let method = if body.get("iam_request_headers").is_some() {
            if aws_login(&f, &body).is_err() {
                return (StatusCode::BAD_REQUEST, Json(json!({ "errors": ["error making upstream request: the stand-in's text"] })));
            }
            "aws"
        } else if let Some(pkcs7) = body.get("pkcs7").and_then(Value::as_str) {
            // As Vault's `ec2` type: the document without its line breaks, and the nonce of
            // the instance's first login, which Vault keeps in its access list.
            if pkcs7 != ec2_pkcs7().replace('\n', "") {
                return (StatusCode::BAD_REQUEST, Json(json!({ "errors": ["failed to parse the pkcs7: the stand-in's text"] })));
            }
            let nonce = body["nonce"].as_str().unwrap_or_default().to_string();
            {
                let mut taken = f.ec2_nonce.lock().unwrap();
                match taken.as_deref() {
                    None => *taken = Some(nonce),
                    Some(n) if n == nonce => {}
                    Some(_) => return (StatusCode::BAD_REQUEST, Json(json!({ "errors": ["client nonce mismatch: the stand-in's text"] }))),
                }
            }
            f.ec2_logins.lock().unwrap().push(body["role"].as_str().unwrap_or(EC2_AMI).to_string());
            "ec2"
        } else if mount == "approle" {
            if body["role_id"] != "role-1" || body["secret_id"] != "secret-id-1" {
                return (StatusCode::BAD_REQUEST, Json(json!({ "errors": ["invalid role or secret ID"] })));
            }
            "approle"
        } else {
            let role = body.get("role").and_then(Value::as_str);
            // A JWT for `gcp` or `azure` also passes at the `gcp-...` or `azure-...` mounts tests make.
            let ok = f.jwts.lock().unwrap().iter().any(|(m, r, j)| (*m == mount || mount.starts_with(&format!("{m}-"))) && r.as_deref() == role && body["jwt"] == j.as_str());
            if !ok {
                return (StatusCode::FORBIDDEN, Json(json!({ "errors": ["permission denied"] })));
            }
            if body.get("subscription_id").is_some() || mount.starts_with("azure") {
                let mut seen = body.clone();
                seen["jwt"] = json!("<token>");
                f.azure_logins.lock().unwrap().push(seen);
            }
            "jwt"
        };
        let n = f.logins.fetch_add(1, Ordering::SeqCst);
        let token = format!("hvs.{method}-{n}");
        f.tokens.lock().unwrap().push(token.clone());
        let lease = f.lease.load(Ordering::SeqCst);
        f.ttls.lock().unwrap().insert(token.clone(), (lease as u64, true));
        (StatusCode::OK, Json(json!({ "auth": { "client_token": token, "lease_duration": lease, "renewable": true } })))
    }

    fn token_of(h: &HeaderMap) -> String {
        h.get("x-vault-token").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string()
    }

    async fn lookup_self(State(f): State<F>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if let Err(e) = check(&f, &h) {
            return e;
        }
        let (ttl, renewable) = f.ttls.lock().unwrap().get(&token_of(&h)).copied().unwrap_or((0, false));
        (StatusCode::OK, Json(json!({ "data": { "ttl": ttl, "renewable": renewable } })))
    }

    async fn renew_self(State(f): State<F>, h: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
        if let Err(e) = check(&f, &h) {
            return e;
        }
        let token = token_of(&h);
        let asked = body["increment"].as_u64().unwrap_or(0);
        f.renewals.lock().unwrap().push((token.clone(), asked));
        let mut ttls = f.ttls.lock().unwrap();
        let Some(t) = ttls.get_mut(&token).filter(|t| t.1) else {
            return (StatusCode::BAD_REQUEST, Json(json!({ "errors": ["lease is not renewable"] })));
        };
        let max = f.max_ttl.load(Ordering::SeqCst) as u64;
        t.0 = if max > 0 { asked.min(max) } else { asked };
        (StatusCode::OK, Json(json!({ "auth": { "client_token": token, "lease_duration": t.0, "renewable": true } })))
    }

    /// A dynamic secrets engine: each GET makes a new lease, its values numbered.
    async fn creds(State(f): State<F>, Path((engine, role)): Path<(String, String)>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if let Err(e) = check(&f, &h) {
            return e;
        }
        let path = format!("{engine}/creds/{role}");
        let Some(fields) = f.creds.lock().unwrap().get(&path).cloned() else {
            return (StatusCode::NOT_FOUND, Json(json!({ "errors": [] })));
        };
        let n = f.issued.fetch_add(1, Ordering::SeqCst);
        let data: serde_json::Map<String, Value> = fields.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().map_or(Value::Null, |v| json!(format!("{v}-{n}"))))).collect();
        let lease = format!("{path}/l{n}");
        f.made.lock().unwrap().push(lease.clone());
        let ttl = match f.creds_ttl.load(Ordering::SeqCst) {
            0 => 900,
            t => t,
        };
        (StatusCode::OK, Json(json!({ "lease_id": lease, "lease_duration": ttl, "renewable": true, "data": data })))
    }

    /// `sys/leases/renew/<lease id>`: up to `lease_max`; a lease never made or already revoked is a 400.
    async fn renew(State(f): State<F>, Path(lease): Path<String>, h: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
        if let Err(e) = check(&f, &h) {
            return e;
        }
        assert!(body.get("lease_id").is_none(), "the lease id is in the path, where a policy can limit it");
        let asked = body["increment"].as_u64().unwrap_or(0);
        f.lease_renewals.lock().unwrap().push((lease.clone(), asked));
        if !f.made.lock().unwrap().contains(&lease) || f.revoked.lock().unwrap().contains(&lease) {
            return (StatusCode::BAD_REQUEST, Json(json!({ "errors": ["lease not found"] })));
        }
        let ttl = match f.lease_max.load(Ordering::SeqCst) as u64 {
            0 => asked,
            max => asked.min(max),
        };
        (StatusCode::OK, Json(json!({ "lease_id": lease, "lease_duration": ttl, "renewable": true })))
    }

    async fn revoke(State(f): State<F>, Path(lease): Path<String>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if let Err(e) = check(&f, &h) {
            return e;
        }
        f.revoked.lock().unwrap().push(lease);
        (StatusCode::NO_CONTENT, Json(json!({})))
    }

    /// AWS's instance metadata service (IMDSv2): each fetch of the role's keys gives new ones.
    async fn imds_token(h: HeaderMap) -> (StatusCode, String) {
        match h.get("x-aws-ec2-metadata-token-ttl-seconds") {
            Some(_) => (StatusCode::OK, "imds-session-v".into()),
            None => (StatusCode::BAD_REQUEST, String::new()),
        }
    }

    async fn imds_role(State(f): State<F>, Path(role): Path<String>, h: HeaderMap) -> (StatusCode, String) {
        if h.get("x-aws-ec2-metadata-token").and_then(|v| v.to_str().ok()) != Some("imds-session-v") {
            return (StatusCode::UNAUTHORIZED, String::new());
        }
        if role.is_empty() {
            return (StatusCode::OK, "botd-role\n".into());
        }
        let n = f.imds_issued.fetch_add(1, Ordering::SeqCst);
        let (id, secret, token) = (format!("ASIAVAULT{n:07}"), format!("vault-aws-secret-{n}-{}", crate::random_hex(6)), format!("vault-aws-session-{n}-{}", crate::random_hex(6)));
        f.aws_keys.lock().unwrap().insert(id.clone(), (secret.clone(), Some(token.clone())));
        let expires = (chrono::Utc::now() + chrono::Duration::hours(6)).to_rfc3339();
        (StatusCode::OK, json!({ "Code": "Success", "AccessKeyId": id, "SecretAccessKey": secret, "Token": token, "Expiration": expires }).to_string())
    }

    async fn imds_roles(s: State<F>, h: HeaderMap) -> (StatusCode, String) {
        imds_role(s, Path(String::new()), h).await
    }

    async fn imds_pkcs7(h: HeaderMap) -> (StatusCode, String) {
        if h.get("x-aws-ec2-metadata-token").and_then(|v| v.to_str().ok()) != Some("imds-session-v") {
            return (StatusCode::UNAUTHORIZED, String::new());
        }
        (StatusCode::OK, ec2_pkcs7())
    }

    /// Google's metadata server's identity tokens: the `gcp` mount's `gce` type accepts one for
    /// the role its audience names, and only with the instance's details (`format=full`).
    async fn google_identity(State(f): State<F>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> (StatusCode, String) {
        if h.get("metadata-flavor").and_then(|v| v.to_str().ok()) != Some("Google") {
            return (StatusCode::FORBIDDEN, String::new());
        }
        if let s @ 1.. = f.identity_status.swap(0, Ordering::SeqCst) {
            return (StatusCode::from_u16(s as u16).unwrap(), "the stand-in's text".into());
        }
        let (audience, format) = (q.get("audience").cloned().unwrap_or_default(), q.get("format").cloned().unwrap_or_default());
        f.identities.lock().unwrap().push((audience.clone(), format.clone()));
        let token = jwt("botd@acme-prod.iam.gserviceaccount.com", 3600);
        // Only the `superbot` role is bound to this VM, as Vault's `bound_service_accounts` would do.
        if audience == "http://vault/superbot" && format == "full" {
            f.jwts.lock().unwrap().push(("gcp".into(), Some("superbot".into()), token.clone()));
        }
        (StatusCode::OK, token)
    }

    /// Google's metadata server: botd's token and its account's email.
    async fn google_token(State(f): State<F>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if h.get("metadata-flavor").and_then(|v| v.to_str().ok()) != Some("Google") {
            return (StatusCode::FORBIDDEN, Json(json!({})));
        }
        let token = format!("ya29.vault-{}", crate::random_hex(8));
        f.google_tokens.lock().unwrap().push(token.clone());
        (StatusCode::OK, Json(json!({ "access_token": token, "expires_in": 3599, "token_type": "Bearer" })))
    }

    async fn google_email(h: HeaderMap) -> (StatusCode, String) {
        match h.get("metadata-flavor").and_then(|v| v.to_str().ok()) {
            Some("Google") => (StatusCode::OK, "botd@acme-prod.iam.gserviceaccount.com".into()),
            _ => (StatusCode::FORBIDDEN, String::new()),
        }
    }

    /// IAM Credentials' `signJwt`: takes the metadata server's tokens; signs as any account
    /// but `denied@...`; the JWT it makes is one the `gcp` mount accepts for the payload's role.
    async fn sign_jwt(State(f): State<F>, Path(rest): Path<String>, h: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
        let token = h.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or_default().to_string();
        if !f.google_tokens.lock().unwrap().contains(&token) {
            return (StatusCode::UNAUTHORIZED, Json(json!({ "error": { "status": "UNAUTHENTICATED" } })));
        }
        if let s @ 1.. = f.sign_status.swap(0, Ordering::SeqCst) {
            return (StatusCode::from_u16(s as u16).unwrap(), Json(json!({ "error": { "status": "UNAVAILABLE", "message": "the stand-in's message" } })));
        }
        let Some(account) = rest.strip_suffix(":signJwt") else { return (StatusCode::NOT_FOUND, Json(json!({}))) };
        if account.starts_with("denied@") {
            return (StatusCode::FORBIDDEN, Json(json!({ "error": { "status": "PERMISSION_DENIED", "message": "Permission 'iam.serviceAccounts.signJwt' denied" } })));
        }
        let payload: Value = serde_json::from_str(body["payload"].as_str().unwrap_or_default()).unwrap_or_default();
        f.signed.lock().unwrap().push((account.to_string(), payload.clone()));
        let role = payload["aud"].as_str().and_then(|a| a.strip_prefix("vault/")).unwrap_or_default().to_string();
        let jwt = jwt(account, 600);
        f.jwts.lock().unwrap().push(("gcp".into(), Some(role), jwt.clone()));
        (StatusCode::OK, Json(json!({ "keyId": "k1", "signedJwt": jwt })))
    }

    /// Azure's instance metadata service: a managed identity token, which the `azure`
    /// mount accepts for role `botd`, and the VM's details (a scale set's instance).
    async fn azure_token(State(f): State<F>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> (StatusCode, Json<Value>) {
        if h.get("metadata").and_then(|v| v.to_str().ok()) != Some("true") {
            return (StatusCode::BAD_REQUEST, Json(json!({})));
        }
        let resource = q.get("resource").cloned().unwrap_or_default();
        f.azure_resources.lock().unwrap().push(resource);
        let token = jwt("mi-principal", 3600);
        f.jwts.lock().unwrap().push(("azure".into(), Some("botd".into()), token.clone()));
        (StatusCode::OK, Json(json!({ "access_token": token, "expires_in": "3599", "token_type": "Bearer" })))
    }

    async fn azure_vm(h: HeaderMap) -> (StatusCode, Json<Value>) {
        if h.get("metadata").and_then(|v| v.to_str().ok()) != Some("true") {
            return (StatusCode::BAD_REQUEST, Json(json!({})));
        }
        (StatusCode::OK, Json(json!({ "subscriptionId": "00000000-1111-2222-3333-444444444444", "resourceGroupName": "superbot-prod", "name": "botd-vmss_2", "vmScaleSetName": "botd-vmss", "location": "uksouth" })))
    }

    /// Starts the stand-in on its own thread and runtime; returns its address. The cloud
    /// metadata services and Google's IAM Credentials answer on the same address.
    pub(crate) fn stand_in() -> (String, F) {
        let f = F::default();
        f.lease.store(3600, Ordering::SeqCst);
        let app = axum::Router::new()
            .route("/v1/secret/data/{*rest}", axum::routing::get(data))
            .route("/v1/secret/metadata/{*rest}", axum::routing::get(metadata))
            .route("/v1/auth/{mount}/login", axum::routing::post(login))
            .route("/v1/auth/token/lookup-self", axum::routing::get(lookup_self))
            .route("/v1/auth/token/renew-self", axum::routing::post(renew_self))
            .route("/v1/{engine}/creds/{role}", axum::routing::get(creds))
            .route("/v1/sys/leases/revoke/{*lease}", axum::routing::put(revoke))
            .route("/v1/sys/leases/renew/{*lease}", axum::routing::put(renew))
            .route("/v1/sys/events/subscribe/{*types}", axum::routing::get(events::tests::subscribe))
            .route("/latest/api/token", axum::routing::put(imds_token))
            .route("/latest/meta-data/iam/security-credentials/", axum::routing::get(imds_roles))
            .route("/latest/meta-data/iam/security-credentials/{role}", axum::routing::get(imds_role))
            .route("/latest/dynamic/instance-identity/pkcs7", axum::routing::get(imds_pkcs7))
            .route("/computeMetadata/v1/instance/service-accounts/default/identity", axum::routing::get(google_identity))
            .route("/computeMetadata/v1/instance/service-accounts/default/token", axum::routing::get(google_token))
            .route("/computeMetadata/v1/instance/service-accounts/default/email", axum::routing::get(google_email))
            .route("/v1/projects/-/serviceAccounts/{rest}", axum::routing::post(sign_jwt))
            .route("/metadata/identity/oauth2/token", axum::routing::get(azure_token))
            .route("/metadata/instance/compute", axum::routing::get(azure_vm))
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
    fn reads_each_users_own_folder() {
        let (url, f) = stand_in();
        f.tokens.lock().unwrap().push("hvs.users".into());
        let value = format!("ua1-vault-{}", crate::random_hex(10));
        put(&f, "users/ua1/OPENAI_API_KEY", &value);
        put(&f, "users/ua1/LINODE_TOKEN", "never-from-a-users-folder");
        put(&f, "users/ub1/OPENAI_API_KEY", "ub1-own-openai");
        put(&f, "users/ua10/OPENAI_API_KEY", "not-ua1s");
        let x = external::tests::users_on(vault(&url, &[("VAULT_TOKEN", "hvs.users")], Duration::from_secs(60)));
        external::tests::reads_users_folders(&x, &value);
    }

    #[test]
    fn runs_get_short_lived_credentials_that_are_revoked_when_they_end() {
        let (url, f) = stand_in();
        f.tokens.lock().unwrap().push("hvs.leases".into());
        f.creds.lock().unwrap().insert("aws/creds/bots".into(), json!({ "access_key": "AKIAvault", "secret_key": "vault-aws-secret-4c3d", "security_token": null }));
        f.creds.lock().unwrap().insert("database/creds/u-ulv1".into(), json!({ "username": "v-ulv1", "password": "vault-db-pass-4c3d" }));
        put(&f, "bots/STATIC_TOKEN", "static-kv-value-1");
        let creds = "aws/creds/bots CLOUD_KEY_ID=access_key CLOUD_SECRET_KEY=secret_key CLOUD_SESSION_TOKEN=security_token; database/creds/u-{owner} PGUSER=username PGPASSWORD=password";
        let pairs = [("SECRETS_BACKEND", "vault"), ("VAULT_ADDR", url.as_str()), ("VAULT_TOKEN", "hvs.leases"), ("VAULT_RUN_CREDENTIALS", creds)];
        let x = external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap().unwrap();
        let rc = x.run_credentials().expect("set");
        assert!(x.describe().contains("short-lived credentials for each run from aws/creds/bots, database/creds/u-{owner}"), "{}", x.describe());

        let (env, leases) = rc.issue("ulv1", "blv1", true, super::super::leases::tests::RUN).unwrap();
        let mut env: Vec<_> = env.into_iter().map(|(k, v)| (k, v.expose().to_string())).collect();
        env.sort();
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(env, [pair("CLOUD_KEY_ID", "AKIAvault-0"), pair("CLOUD_SECRET_KEY", "vault-aws-secret-4c3d-0"), pair("PGPASSWORD", "vault-db-pass-4c3d-1"), pair("PGUSER", "v-ulv1-1")]);
        assert_eq!(leases.len(), 2);
        drop(leases);
        super::super::leases::tests::wait_for(|| f.revoked.lock().unwrap().len() == 2);
        assert_eq!(*f.revoked.lock().unwrap(), ["aws/creds/bots/l0", "database/creds/u-ulv1/l1"]);

        // Vault refuses botd's token: the revoke fails and is audited, and the lease ends at its TTL.
        let (_, l) = rc.issue("ulv1", "blv1", false, super::super::leases::tests::RUN).unwrap();
        assert_eq!(l.len(), 1, "a run for someone else: the shared role only");
        f.tokens.lock().unwrap().clear();
        drop(l);
        super::super::leases::tests::wait_for(|| external::tests::audited("aws/creds/bots").iter().any(|e| e.details["leaseId"] == "aws/creds/bots/l2" && e.action == "secret.lease_revoked"));
        assert!(external::tests::audited("aws/creds/bots").iter().any(|e| e.details["leaseId"] == "aws/creds/bots/l2" && e.outcome == Outcome::Failure), "a token Vault won't take: the lease is left to its TTL, and audited");
        f.tokens.lock().unwrap().push("hvs.leases".into());

        // A KV path, or one with no engine, isn't a lease.
        for (path, err) in [("secret/data/superbot/bots/STATIC_TOKEN", "gave no lease"), ("nope/creds/r", "nothing at nope/creds/r")] {
            let pairs = [("SECRETS_BACKEND", "vault"), ("VAULT_ADDR", url.as_str()), ("VAULT_TOKEN", "hvs.leases"), ("VAULT_RUN_CREDENTIALS", &format!("{path} X_TOKEN=value"))];
            let x = external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap().unwrap();
            let e = x.run_credentials().unwrap().issue("ulv1", "blv1", true, super::super::leases::tests::RUN).err().unwrap().to_string();
            assert!(e.contains(err), "{path}: {e}");
        }
        assert!(external::from_env(&settings(&[pairs[0], pairs[1], pairs[2], ("VAULT_RUN_CREDENTIALS", "aws/creds/bots PATH=x")]), &EnvStore::fixed(&pairs)).err().unwrap().contains("VAULT_RUN_CREDENTIALS: PATH"));
        assert!(external::from_env(&settings(&pairs[..3]), &EnvStore::fixed(&pairs)).unwrap().unwrap().run_credentials().is_none(), "off unless set");
        let v = Vault::new(Config::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap()).unwrap();
        for bad in ["", "../sys/x", "a//b", "a b"] {
            assert!(Issuer::revoke(&v, bad).is_err(), "{bad:?} never reaches a URL");
        }
        let d = external::tests::diagnose_for(&x);
        assert_eq!(d["runCredentials"], json!(["aws/creds/bots", "database/creds/u-{owner}"]));
        for v in ["AKIAvault-2", "vault-aws-secret-4c3d-2"] {
            redact::forget(v);
        }
    }

    #[test]
    fn a_runs_leases_are_made_with_a_token_that_outlives_the_run() {
        use super::super::leases::tests::RUN;
        let (url, f) = stand_in();
        f.creds.lock().unwrap().insert("aws/creds/outlive".into(), json!({ "access_key": "AKIAoutlive" }));
        let pairs = [("SECRETS_BACKEND", "vault"), ("VAULT_ADDR", url.as_str()), ("VAULT_AUTH", "approle"), ("VAULT_ROLE_ID", "role-1"), ("VAULT_SECRET_ID", "secret-id-1"), ("VAULT_RUN_CREDENTIALS", "aws/creds/outlive OUTLIVE_KEY_ID=access_key")];
        let x = external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap().unwrap();
        let rc = x.run_credentials().unwrap();
        let want = RUN.as_secs() + TOKEN_MARGIN.as_secs();

        // The login's hour is shorter than the run and the margin: renewed to cover both.
        let (_, l) = rc.issue("uout1", "bout1", false, RUN).unwrap();
        assert_eq!(*f.renewals.lock().unwrap(), [("hvs.approle-0".to_string(), want)]);
        drop(l);
        // A short run needs no renewal.
        drop(rc.issue("uout1", "bout1", false, Duration::from_secs(60)).unwrap().1);
        assert_eq!(f.renewals.lock().unwrap().len(), 1);

        // The token's max TTL is too short: a new login is tried, then the run is refused
        // before any lease is made.
        f.max_ttl.store(1000, Ordering::SeqCst);
        f.ttls.lock().unwrap().insert("hvs.approle-0".into(), (900, true));
        let issued = f.issued.load(Ordering::SeqCst);
        let e = rc.issue("uout1", "bout1", false, RUN).err().unwrap().to_string();
        assert!(e.contains("RUN_TIMEOUT_MINUTES") && e.contains("max TTL"), "{e}");
        assert_eq!(f.logins.load(Ordering::SeqCst), 2, "logged in again for a token with longer to live");
        assert_eq!(f.issued.load(Ordering::SeqCst), issued, "no lease that would end with the token");

        // A static token that ends too soon and can't be renewed: refused, no login.
        f.tokens.lock().unwrap().push("hvs.static-short".into());
        f.ttls.lock().unwrap().insert("hvs.static-short".into(), (600, false));
        let pairs = [pairs[0], pairs[1], ("VAULT_TOKEN", "hvs.static-short"), pairs[5]];
        let x = external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap().unwrap();
        let e = x.run_credentials().unwrap().issue("uout1", "bout1", false, RUN).err().unwrap().to_string();
        assert!(e.contains("ends in 600 s"), "{e}");
        assert_eq!(f.logins.load(Ordering::SeqCst), 2);
        super::super::leases::tests::wait_for(|| f.revoked.lock().unwrap().len() == 2);

        // Vault Agent rotates the token file and revokes the old token: the next run's
        // lookup is refused, the file read again, and the lease made with the new token.
        let file = token_file("vault-outlive", "hvs.file-a\n");
        f.tokens.lock().unwrap().push("hvs.file-a".into());
        let pairs = [pairs[0], pairs[1], ("VAULT_TOKEN_FILE", file.to_str().unwrap()), pairs[3]];
        let x = external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap().unwrap();
        let rc = x.run_credentials().unwrap();
        drop(rc.issue("uout1", "bout1", false, RUN).unwrap().1);
        std::fs::write(&file, "hvs.file-b\n").unwrap();
        *f.tokens.lock().unwrap() = vec!["hvs.file-b".into()];
        let issued = f.issued.load(Ordering::SeqCst);
        drop(rc.issue("uout1", "bout1", false, RUN).unwrap().1);
        assert_eq!(f.issued.load(Ordering::SeqCst), issued + 1);
        super::super::leases::tests::wait_for(|| f.revoked.lock().unwrap().len() == 4);
    }

    #[test]
    fn a_runs_leases_are_renewed_through_vault_while_it_lasts() {
        use super::super::leases::tests::{wait_for, RUN};
        let (url, f) = stand_in();
        f.tokens.lock().unwrap().push("hvs.renew".into());
        f.creds_ttl.store(2, Ordering::SeqCst);
        f.creds.lock().unwrap().insert("database/creds/renew".into(), json!({ "password": "vault-renew-pass-6e7f" }));
        let pairs = [("SECRETS_BACKEND", "vault"), ("VAULT_ADDR", url.as_str()), ("VAULT_TOKEN", "hvs.renew"), ("VAULT_NAMESPACE", "admin/team-a"), ("VAULT_RUN_CREDENTIALS", "database/creds/renew RENEW_PGPASSWORD=password")];
        let x = external::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap().unwrap();
        let rc = x.run_credentials().unwrap();
        let renewed = || audited("database/creds/renew").into_iter().filter(|e| e.action == "secret.lease_renewed").collect::<Vec<_>>();

        let (_, l) = rc.issue("urv1", "brv1", true, RUN).unwrap();
        let first = l.expires_first().unwrap();
        wait_for(|| f.lease_renewals.lock().unwrap().len() >= 2);
        assert!(f.lease_renewals.lock().unwrap().iter().all(|(id, n)| id == "database/creds/renew/l0" && *n == 2), "{:?}", f.lease_renewals.lock().unwrap());
        wait_for(|| l.expires_first().is_some_and(|at| at > first + Duration::from_secs(2)));
        let ev = renewed();
        assert!(ev.iter().all(|e| e.outcome == Outcome::Success && e.details["store"] == "vault" && e.details["ttl"] == 2), "{ev:?}");
        assert!(f.namespaces.lock().unwrap().iter().all(|n| n == "admin/team-a"), "renewed where it was made");

        // The role's max TTL: Vault gives less than asked, and the run must stop then.
        f.lease_max.store(1, Ordering::SeqCst);
        wait_for(|| renewed().iter().any(|e| e.details["final"] == true && e.details["ttl"] == 1));
        let n = f.lease_renewals.lock().unwrap().len();
        drop(l);
        wait_for(|| f.revoked.lock().unwrap().len() == 1);
        assert_eq!(f.lease_renewals.lock().unwrap().len(), n, "not asked again after its last");

        let v = Vault::new(Config::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap()).unwrap();
        let refused = |r: Result<Renewal, Error>| match r {
            Ok(Renewal::Refused(why)) => why,
            other => panic!("{other:?}"),
        };
        assert!(refused(Issuer::renew(&v, "database/creds/renew/l0", Duration::from_secs(2))).contains("400"), "revoked: gone, final");
        let other = [pairs[0], pairs[1], ("VAULT_TOKEN", "hvs.not-allowed"), pairs[4]];
        let denied = Vault::new(Config::from_env(&settings(&other), &EnvStore::fixed(&other)).unwrap()).unwrap();
        assert!(refused(Issuer::renew(&denied, "database/creds/renew/l0", Duration::from_secs(2))).contains("sys/leases/renew/<path>/*"), "a policy without renew is named");
        f.down.store(true, Ordering::SeqCst);
        assert!(matches!(Issuer::renew(&v, "database/creds/renew/l0", Duration::from_secs(2)), Err(Error::Unavailable(_))), "Vault down: tried again");
        f.down.store(false, Ordering::SeqCst);
        for bad in ["", "../sys/x", "a//b", "a b"] {
            assert!(Issuer::renew(&v, bad, Duration::from_secs(2)).is_err(), "{bad:?} never reaches a URL");
        }
        redact::forget("vault-renew-pass-6e7f-0");
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
    fn aws_logs_in_with_an_sts_request_signed_with_botds_own_keys() {
        let (url, f) = stand_in();
        put(&f, "server/SMTP_PASSWORD", "aws-login-smtp-1");
        let (id, secret, token) = ("ASIAENVKEYS0001", format!("vault-env-secret-{}", crate::random_hex(6)), format!("vault-env-session-{}", crate::random_hex(6)));
        f.aws_keys.lock().unwrap().insert(id.into(), (secret.clone(), Some(token.clone())));
        *f.aws_server_id.lock().unwrap() = Some("vault.example.com".into());
        let mount = format!("aws-env-{}", crate::random_hex(4));
        let pairs = [
            ("VAULT_AUTH", "aws"),
            ("VAULT_AWS_MOUNT", mount.as_str()),
            ("VAULT_AWS_ROLE", "superbot"),
            ("VAULT_AWS_REGION", "eu-west-2"),
            ("VAULT_AWS_HEADER_VALUE", "vault.example.com"),
            ("VAULT_AWS_CREDENTIALS", "env"),
            ("AWS_ACCESS_KEY_ID", id),
            ("AWS_SECRET_ACCESS_KEY", secret.as_str()),
            ("AWS_SESSION_TOKEN", token.as_str()),
            ("VAULT_NAMESPACE", "admin/team-a"),
            ("VAULT_AUTH_NAMESPACE", "admin"),
        ];
        let s = vault(&url, &pairs, Duration::ZERO);
        assert!(s.describe().contains("AWS login as role superbot at auth/") && s.describe().contains("signed for eu-west-2, with the server id header with temporary access keys from the environment"), "{}", s.describe());
        assert_eq!(s.get("SMTP_PASSWORD").unwrap().unwrap().expose(), "aws-login-smtp-1");
        assert_eq!(*f.aws_logins.lock().unwrap(), [(id.to_string(), "eu-west-2".to_string(), "superbot".to_string(), "https://sts.eu-west-2.amazonaws.com/".to_string())], "signed for the region's STS, as the mount's sts_endpoint must be");
        assert_eq!(*f.login_namespaces.lock().unwrap(), ["admin"]);
        let ev = audited(&mount);
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].details, json!({ "method": "aws", "role": "superbot", "namespace": "admin" }));
        assert!(!format!("{ev:?}").contains(&secret) && !format!("{ev:?}").contains(&token));
        // botd's keys are kept from Bots while it signs in with them.
        assert!(super::super::check_name("AWS_SECRET_ACCESS_KEY").is_err() && super::super::check_name("AWS_SESSION_TOKEN").is_err());

        // A server id that isn't the mount's: Vault refuses the login, and the read fails closed.
        *f.aws_server_id.lock().unwrap() = Some("vault-prod.example.com".into());
        f.tokens.lock().unwrap().clear();
        let e = s.get("SMTP_PASSWORD").err().unwrap().to_string();
        assert!(e.contains("AWS login at auth/") && e.contains("answered 400") && !e.contains("stand-in's text"), "{e}");
        assert!(audited(&mount).iter().any(|e| e.outcome == Outcome::Failure && e.details["method"] == "aws"));
        let logged = format!("{:?}", audited(&mount));
        assert!(!logged.contains(&secret) && !logged.contains(&token) && !logged.contains("Signature="), "no key or signature in the audit log");

        // us-east-1, the mount's default: STS's global endpoint, and no role (the principal's name).
        *f.aws_server_id.lock().unwrap() = None;
        let s = vault(&url, &[pairs[0], pairs[5], pairs[6], pairs[7], pairs[8]], Duration::ZERO);
        assert!(s.describe().contains("AWS login as the role named after its IAM principal at auth/aws"), "{}", s.describe());
        assert!(s.get("SMTP_PASSWORD").unwrap().is_some());
        let last = f.aws_logins.lock().unwrap().last().cloned().unwrap();
        assert_eq!((last.1.as_str(), last.2.as_str(), last.3.as_str()), ("us-east-1", "botd-role", "https://sts.amazonaws.com/"));
        for v in ["aws-login-smtp-1", secret.as_str(), token.as_str()] {
            redact::forget(v);
        }
    }

    #[test]
    fn aws_login_takes_keys_from_the_instance_profile_and_new_ones_when_vault_refuses() {
        let (url, f) = stand_in();
        put(&f, "bots/AWS_LOGIN_API_KEY", "aws-imds-value-1");
        let mount = format!("aws-imds-{}", crate::random_hex(4));
        let s = vault(&url, &[("VAULT_AUTH", "aws"), ("VAULT_AWS_MOUNT", &mount), ("VAULT_AWS_CREDENTIALS", "instance-profile"), ("AWS_EC2_METADATA_SERVICE_ENDPOINT", &url)], Duration::ZERO);
        assert!(s.describe().contains("with the instance profile (IMDSv2)"), "{}", s.describe());
        assert_eq!(s.get("AWS_LOGIN_API_KEY").unwrap().unwrap().expose(), "aws-imds-value-1");
        s.get("AWS_LOGIN_API_KEY").unwrap();
        assert_eq!((f.imds_issued.load(Ordering::SeqCst), f.logins.load(Ordering::SeqCst)), (1, 1), "the keys and Vault's token are kept while they last");
        let (first, ..) = f.aws_logins.lock().unwrap()[0].clone();
        let first_secret = f.aws_keys.lock().unwrap()[&first].0.clone();
        assert_eq!(redact::text(&first_secret), redact::MARK, "botd's keys are masked while it holds them");

        // Vault revokes botd's token: the next login signs with new keys.
        f.tokens.lock().unwrap().clear();
        assert!(s.get("AWS_LOGIN_API_KEY").unwrap().is_some());
        assert_eq!(f.imds_issued.load(Ordering::SeqCst), 2);
        let ids: Vec<String> = f.aws_logins.lock().unwrap().iter().map(|l| l.0.clone()).collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert_ne!(redact::text(&first_secret), redact::MARK, "the old keys are let go");
        let fetched = audited("vault").into_iter().filter(|e| e.action == "secret.backend_login" && e.details["method"] == "instance-profile").count();
        assert!(fetched >= 2, "each fetch of keys is audited as the vault store's");

        // No instance profile: fails closed, audited as a failed login, nothing sent to Vault.
        let logins = f.logins.load(Ordering::SeqCst);
        let none = vault(&url, &[("VAULT_AUTH", "aws"), ("VAULT_AWS_MOUNT", &mount), ("VAULT_AWS_CREDENTIALS", "instance-profile"), ("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://127.0.0.1:9")], Duration::ZERO);
        let e = none.check().err().unwrap().to_string();
        assert!(e.contains("AWS (for Vault): instance-profile sign-in"), "{e}");
        assert_eq!(f.logins.load(Ordering::SeqCst), logins);
        assert!(audited(&mount).iter().any(|e| e.outcome == Outcome::Failure && e.details["error"] == "unavailable"));
        redact::forget("aws-imds-value-1");
    }

    #[test]
    fn gcp_logs_in_with_a_jwt_google_signs_as_botds_service_account() {
        let (url, f) = stand_in();
        put(&f, "server/SMTP_PASSWORD", "gcp-login-smtp-1");
        let host = url.trim_start_matches("http://").to_string();
        let base = [("VAULT_AUTH", "gcp"), ("VAULT_GCP_ROLE", "superbot"), ("GCE_METADATA_HOST", host.as_str()), ("GCP_IAM_CREDENTIALS_ENDPOINT", url.as_str())];
        let s = vault(&url, &base, Duration::ZERO);
        assert!(s.describe().contains("GCP login as role superbot at auth/gcp, a JWT signed as its own service account with the metadata server's service account at"), "{}", s.describe());
        assert_eq!(s.get("SMTP_PASSWORD").unwrap().unwrap().expose(), "gcp-login-smtp-1");
        let (account, payload) = f.signed.lock().unwrap()[0].clone();
        assert_eq!(account, "botd@acme-prod.iam.gserviceaccount.com", "the metadata server's account");
        assert_eq!((payload["aud"].as_str(), payload["sub"].as_str()), (Some("vault/superbot"), Some(account.as_str())));
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let exp = payload["exp"].as_u64().unwrap();
        assert!(exp > now && exp <= now + GCP_JWT_SECONDS, "within the 15 minutes Vault's roles allow: {exp} vs {now}");
        let ev = audited("gcp");
        assert!(ev.iter().any(|e| e.outcome == Outcome::Success && e.details == json!({ "method": "gcp", "role": "superbot" })), "{ev:?}");

        // Another account, which botd may sign as.
        let s = vault(&url, &[base[0], base[1], base[2], base[3], ("VAULT_GCP_SERVICE_ACCOUNT", "vault-login@acme-prod.iam.gserviceaccount.com")], Duration::ZERO);
        assert!(s.get("SMTP_PASSWORD").unwrap().is_some());
        assert_eq!(f.signed.lock().unwrap().last().unwrap().0, "vault-login@acme-prod.iam.gserviceaccount.com");

        // Google revokes botd's token while Vault's lasts: at the next login, two thirds
        // through Vault's lease, IAM Credentials refuses it, and one new token is fetched.
        f.lease.store(3, Ordering::SeqCst);
        let s = vault(&url, &[base[0], base[1], base[2], base[3], ("VAULT_GCP_SERVICE_ACCOUNT", "vault-login@acme-prod.iam.gserviceaccount.com")], Duration::ZERO);
        assert!(s.get("SMTP_PASSWORD").unwrap().is_some());
        f.google_tokens.lock().unwrap().clear();
        std::thread::sleep(Duration::from_millis(2100));
        assert!(s.get("SMTP_PASSWORD").unwrap().is_some());
        assert_eq!(f.google_tokens.lock().unwrap().len(), 1);
        f.lease.store(3600, Ordering::SeqCst);

        // An account botd may not sign as: the role to grant is named, never Google's text.
        let denied = vault(&url, &[base[0], base[1], base[2], base[3], ("VAULT_GCP_SERVICE_ACCOUNT", "denied@acme-prod.iam.gserviceaccount.com")], Duration::ZERO);
        let e = denied.check().err().unwrap().to_string();
        assert!(e.contains("403") && e.contains("Service Account Token Creator") && !e.contains("stand-in"), "{e}");
        f.sign_status.store(503, Ordering::SeqCst);
        f.tokens.lock().unwrap().clear();
        let e = s.check().err().unwrap().to_string();
        assert!(e.contains("signJwt as vault-login@acme-prod.iam.gserviceaccount.com answered 503") && !e.contains("stand-in's message"), "{e}");
        assert!(audited("gcp").iter().any(|e| e.outcome == Outcome::Failure && e.details["role"] == "superbot"));
        redact::forget("gcp-login-smtp-1");
    }

    fn azure_vault(url: &str, extra: &[(&str, &str)]) -> Arc<ExternalStore> {
        let mut pairs = vec![("SECRETS_BACKEND", "vault"), ("VAULT_ADDR", url), ("VAULT_AUTH", "azure"), ("VAULT_AZURE_ROLE", "botd")];
        pairs.extend_from_slice(extra);
        let mut cfg = Config::from_env(&settings(&pairs), &EnvStore::fixed(&pairs)).unwrap();
        if let Auth::Azure { entra, .. } = &mut cfg.auth {
            entra.point_at(url);
        }
        Arc::new(ExternalStore::new(Box::new(Vault::new(cfg).unwrap()), Duration::ZERO))
    }

    #[test]
    fn azure_logs_in_with_the_managed_identitys_token_and_the_vms_details() {
        let (url, f) = stand_in();
        put(&f, "bots/AZURE_LOGIN_API_KEY", "azure-login-value-1");
        let s = azure_vault(&url, &[]);
        assert!(s.describe().contains("Azure login as role botd at auth/azure, a token for https://management.azure.com/ from managed identity"), "{}", s.describe());
        assert_eq!(s.get("AZURE_LOGIN_API_KEY").unwrap().unwrap().expose(), "azure-login-value-1");
        assert_eq!(*f.azure_resources.lock().unwrap(), ["https://management.azure.com/"], "the azure mount's default resource");
        assert_eq!(f.azure_logins.lock().unwrap()[0], json!({ "role": "botd", "jwt": "<token>" }), "no VM details unless asked: a role bound only to the principal needs none");
        assert!(audited("azure").iter().any(|e| e.outcome == Outcome::Success && e.details == json!({ "method": "azure", "role": "botd" })));

        // A role bound to the scale set: its details from instance metadata, vmss_name over vm_name.
        let s = azure_vault(&url, &[("VAULT_AZURE_INSTANCE", "1"), ("VAULT_AZURE_RESOURCE", "api://vault-prod"), ("AZURE_CLIENT_ID", "11111111-2222-3333-4444-555555555555")]);
        assert!(s.describe().contains("a token for api://vault-prod from user-assigned managed identity 11111111-2222-3333-4444-555555555555, with the VM's details"), "{}", s.describe());
        assert!(s.get("AZURE_LOGIN_API_KEY").unwrap().is_some());
        assert_eq!(f.azure_resources.lock().unwrap().last().unwrap(), "api://vault-prod");
        assert_eq!(
            f.azure_logins.lock().unwrap()[1],
            json!({ "role": "botd", "jwt": "<token>", "subscription_id": "00000000-1111-2222-3333-444444444444", "resource_group_name": "superbot-prod", "vmss_name": "botd-vmss" })
        );

        // A role Vault doesn't know: fails closed.
        let e = azure_vault(&url, &[("VAULT_AZURE_ROLE", "nobody")]).check().err().unwrap().to_string();
        assert!(e.contains("Azure login at auth/azure answered 403"), "{e}");
        redact::forget("azure-login-value-1");
    }

    #[test]
    fn gce_logs_in_with_the_vms_identity_token_and_no_iam_permission() {
        let (url, f) = stand_in();
        put(&f, "server/SMTP_PASSWORD", "gce-login-smtp-1");
        let host = url.trim_start_matches("http://").to_string();
        let mount = format!("gcp-gce-{}", crate::random_hex(4));
        let base = [("VAULT_AUTH", "gcp"), ("VAULT_GCP_TYPE", "gce"), ("VAULT_GCP_ROLE", "superbot"), ("VAULT_GCP_MOUNT", mount.as_str()), ("GCE_METADATA_HOST", host.as_str())];
        let s = vault(&url, &base, Duration::ZERO);
        assert!(s.describe().contains(&format!("GCP login (gce) as role superbot at auth/{mount}, the VM's identity token of the metadata server's service account at {host}")), "{}", s.describe());
        assert_eq!(s.get("SMTP_PASSWORD").unwrap().unwrap().expose(), "gce-login-smtp-1");
        assert_eq!(*f.identities.lock().unwrap(), [("http://vault/superbot".to_string(), "full".to_string())], "for the role, with the instance's details Vault binds roles to");
        assert!(f.signed.lock().unwrap().is_empty() && f.google_tokens.lock().unwrap().is_empty(), "no signJwt and no access token: botd needs no IAM permission");
        let token = f.jwts.lock().unwrap().last().unwrap().2.clone();
        let ev = audited(&mount);
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].details, json!({ "method": "gcp", "type": "gce", "role": "superbot" }));
        assert!(!format!("{ev:?}").contains(&token), "never the token");

        // Two thirds through Vault's lease, botd logs in again with a new identity token.
        f.lease.store(3, Ordering::SeqCst);
        let s = vault(&url, &base, Duration::ZERO);
        assert!(s.get("SMTP_PASSWORD").unwrap().is_some());
        std::thread::sleep(Duration::from_millis(2100));
        assert!(s.get("SMTP_PASSWORD").unwrap().is_some());
        assert_eq!(f.identities.lock().unwrap().len(), 3);
        f.lease.store(3600, Ordering::SeqCst);

        // A VM with no service account: named, never the metadata server's text, and nothing sent to Vault.
        let logins = f.logins.load(Ordering::SeqCst);
        f.identity_status.store(404, Ordering::SeqCst);
        let e = vault(&url, &base, Duration::ZERO).check().err().unwrap().to_string();
        assert!(e.contains("identity token answered 404") && e.contains("service account?") && !e.contains("stand-in"), "{e}");
        assert_eq!(f.logins.load(Ordering::SeqCst), logins);
        assert!(audited(&mount).iter().any(|e| e.outcome == Outcome::Failure && e.details["type"] == "gce" && e.details["error"] == "unavailable"));

        // A role Vault doesn't bind to this VM: refused, and the read fails closed.
        let e = vault(&url, &[base[0], base[1], ("VAULT_GCP_ROLE", "nobody"), base[3], base[4]], Duration::ZERO).check().err().unwrap().to_string();
        assert!(e.contains(&format!("GCP login at auth/{mount} answered 403")), "{e}");
        redact::forget("gce-login-smtp-1");
    }

    #[test]
    fn ec2_logs_in_with_the_instances_identity_document_and_its_nonce() {
        let (url, f) = stand_in();
        put(&f, "bots/EC2_LOGIN_API_KEY", "ec2-login-value-1");
        let mount = format!("aws-ec2-{}", crate::random_hex(4));
        let nonce = format!("ec2-nonce-{}", crate::random_hex(16));
        let base = [("VAULT_AUTH", "aws"), ("VAULT_AWS_TYPE", "ec2"), ("VAULT_AWS_MOUNT", mount.as_str()), ("VAULT_AWS_NONCE", nonce.as_str()), ("AWS_EC2_METADATA_SERVICE_ENDPOINT", url.as_str())];
        let s = vault(&url, &base, Duration::ZERO);
        let described = s.describe();
        assert!(described.contains(&format!("AWS login (ec2) as the role named after its AMI at auth/{mount}, the instance's signed identity document from IMDSv2 at {url} with the nonce in VAULT_AWS_NONCE")), "{described}");
        assert!(!described.contains(&nonce));
        assert_eq!(s.get("EC2_LOGIN_API_KEY").unwrap().unwrap().expose(), "ec2-login-value-1");
        assert_eq!(*f.ec2_logins.lock().unwrap(), [EC2_AMI], "no role: the one named after the AMI");
        assert_eq!(f.ec2_nonce.lock().unwrap().as_deref(), Some(nonce.as_str()), "botd's own nonce, so a restart can log in again");
        let ev = audited(&mount);
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].details, json!({ "method": "aws", "type": "ec2" }));
        assert_eq!(redact::text(&nonce), redact::MARK, "the nonce is masked wherever it turns up");

        // Vault revokes botd's token: the next login repeats the nonce, which Vault takes.
        f.tokens.lock().unwrap().clear();
        assert!(s.get("EC2_LOGIN_API_KEY").unwrap().is_some());
        // As does another botd started with the same settings, here for a named role.
        let s = vault(&url, &[base[0], base[1], base[2], base[3], base[4], ("VAULT_AWS_ROLE", "superbot")], Duration::ZERO);
        assert!(s.get("EC2_LOGIN_API_KEY").unwrap().is_some());
        assert_eq!(*f.ec2_logins.lock().unwrap(), [EC2_AMI, EC2_AMI, "superbot"]);

        // Another nonce: Vault refuses it, and the error says what to look at, never either nonce.
        let other = format!("ec2-other-{}", crate::random_hex(16));
        let e = vault(&url, &[base[0], base[1], base[2], ("VAULT_AWS_NONCE", other.as_str()), base[4]], Duration::ZERO).check().err().unwrap().to_string();
        assert!(e.contains(&format!("AWS login at auth/{mount} answered 400")) && e.contains("VAULT_AWS_NONCE changed"), "{e}");
        assert!(!e.contains(&other) && !e.contains(&nonce) && !e.contains("stand-in"), "{e}");
        let logged = format!("{:?}", audited(&mount));
        assert!(audited(&mount).iter().any(|e| e.outcome == Outcome::Failure && e.details["type"] == "ec2"), "{logged}");
        assert!(!logged.contains(&nonce) && !logged.contains(&other) && !logged.contains(&ec2_pkcs7()[..64]), "no nonce or document in the audit log");

        // No metadata service: fails closed before Vault is asked.
        let logins = f.logins.load(Ordering::SeqCst);
        let e = vault(&url, &[base[0], base[1], base[2], base[3], ("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://127.0.0.1:9")], Duration::ZERO).check().err().unwrap().to_string();
        assert!(e.contains("AWS (for Vault): the instance identity document"), "{e}");
        assert_eq!(f.logins.load(Ordering::SeqCst), logins);
        for v in ["ec2-login-value-1", nonce.as_str(), other.as_str()] {
            redact::forget(v);
        }
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
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "ldap")], "token, approle, kubernetes, jwt, aws, gcp or azure"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("VAULT_AWS_REGION", "eu-west")], "VAULT_AWS_REGION must be"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("VAULT_AWS_ROLE", "a b")], "VAULT_AWS_ROLE must be"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("VAULT_AWS_HEADER_VALUE", "has space")], "VAULT_AWS_HEADER_VALUE must be"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("VAULT_AWS_CREDENTIALS", "env")], "VAULT_AWS_CREDENTIALS=env needs AWS_ACCESS_KEY_ID"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("VAULT_AWS_CREDENTIALS", "keys")], "VAULT_AWS_CREDENTIALS must be chain"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("AWS_EC2_METADATA_DISABLED", "true")], "VAULT_AUTH=aws found no AWS credentials"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("VAULT_AWS_MOUNT", "../aws")], "VAULT_AWS_MOUNT"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "gcp")], "needs VAULT_GCP_ROLE"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "gcp"), ("VAULT_GCP_ROLE", "r"), ("VAULT_GCP_SERVICE_ACCOUNT", "not-an-email")], "VAULT_GCP_SERVICE_ACCOUNT must be"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "gcp"), ("VAULT_GCP_ROLE", "r"), ("VAULT_GCP_CREDENTIALS", "service-account-key")], "VAULT_GCP_CREDENTIALS=service-account-key needs GCP_SERVICE_ACCOUNT_KEY_FILE"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "gcp"), ("VAULT_GCP_ROLE", "r"), ("GCP_IAM_CREDENTIALS_ENDPOINT", "http://iam.example.com")], "GCP_IAM_CREDENTIALS_ENDPOINT"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "gcp"), ("VAULT_GCP_ROLE", "r"), ("VAULT_GCP_TYPE", "gke")], "VAULT_GCP_TYPE must be iam (the default) or gce"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "gcp"), ("VAULT_GCP_TYPE", "gce")], "needs VAULT_GCP_ROLE"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "gcp"), ("VAULT_GCP_TYPE", "gce"), ("VAULT_GCP_ROLE", "r"), ("VAULT_GCP_CREDENTIALS", "service-account-key")], "VAULT_GCP_CREDENTIALS must be metadata"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "gcp"), ("VAULT_GCP_TYPE", "gce"), ("VAULT_GCP_ROLE", "r"), ("VAULT_GCP_SERVICE_ACCOUNT", "a@p.iam.gserviceaccount.com")], "VAULT_GCP_SERVICE_ACCOUNT is for VAULT_GCP_TYPE=iam"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "gcp"), ("VAULT_GCP_TYPE", "gce"), ("VAULT_GCP_ROLE", "r"), ("GCE_METADATA_HOST", "a/b")], "GCE_METADATA_HOST must be"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("VAULT_AWS_TYPE", "pkcs7")], "VAULT_AWS_TYPE must be iam (the default) or ec2"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("VAULT_AWS_TYPE", "ec2")], "VAULT_AWS_TYPE=ec2 needs VAULT_AWS_NONCE"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "azure")], "needs VAULT_AZURE_ROLE"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "azure"), ("VAULT_AZURE_ROLE", "r"), ("VAULT_AZURE_CREDENTIALS", "msi")], "VAULT_AZURE_CREDENTIALS must be managed-identity"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "azure"), ("VAULT_AZURE_ROLE", "r"), ("VAULT_AZURE_RESOURCE", "a b")], "VAULT_AZURE_RESOURCE must be"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "azure"), ("VAULT_AZURE_ROLE", "r"), ("VAULT_AZURE_INSTANCE", "yes")], "VAULT_AZURE_INSTANCE must be 1 or 0"),
            (
                vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "azure"), ("VAULT_AZURE_ROLE", "r"), ("VAULT_AZURE_INSTANCE", "1"), ("IDENTITY_ENDPOINT", "http://127.0.0.1:41000/msi/token"), ("IDENTITY_HEADER", "h-1")],
                "VAULT_AZURE_INSTANCE=1 reads the VM's details",
            ),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "approle")], "VAULT_ROLE_ID"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "kubernetes")], "needs VAULT_KUBERNETES_ROLE"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "kubernetes"), ("VAULT_KUBERNETES_ROLE", "bad role")], "VAULT_KUBERNETES_ROLE must be a Vault role name"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "kubernetes"), ("VAULT_KUBERNETES_ROLE", "r"), ("VAULT_KUBERNETES_MOUNT", "../k8s")], "VAULT_KUBERNETES_MOUNT"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "jwt")], "needs VAULT_JWT_FILE"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "jwt"), ("VAULT_JWT_FILE", "/f"), ("VAULT_JWT_ROLE", "r\"}")], "VAULT_JWT_ROLE must be"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "jwt"), ("VAULT_JWT_FILE", "/f"), ("VAULT_AUTH_NAMESPACE", "a/../b")], "VAULT_AUTH_NAMESPACE"),
            (vec![("VAULT_ADDR", "https://v"), ("VAULT_AUTH_NAMESPACE", "admin")], "needs a VAULT_AUTH that logs in"),
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
        // Cloud sign-in needs no secret either: the instance profile, metadata server or managed identity.
        let c = Config::from_env(&settings(&[("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws")]), &none).unwrap();
        assert!(matches!(&c.auth, Auth::Aws { mount, role: None, region, sts_url, server_id: None, creds } if mount == "aws" && region == "us-east-1" && sts_url.as_str() == "https://sts.amazonaws.com/" && creds.describe() == "the instance profile (IMDSv2)"));
        let c = Config::from_env(&settings(&[("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("VAULT_AWS_REGION", "cn-north-1")]), &none).unwrap();
        assert!(matches!(&c.auth, Auth::Aws { sts_url, .. } if sts_url.as_str() == "https://sts.cn-north-1.amazonaws.com.cn/"));
        let c = Config::from_env(&settings(&[("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "gcp"), ("VAULT_GCP_ROLE", "superbot")]), &none).unwrap();
        assert!(matches!(&c.auth, Auth::Gcp { mount, signer: None, iam, .. } if mount == "gcp" && iam == gcp::IAM_CREDENTIALS));
        let c = Config::from_env(&settings(&[("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "azure"), ("VAULT_AZURE_ROLE", "superbot"), ("VAULT_AUTH_NAMESPACE", "admin")]), &none).unwrap();
        assert!(matches!(&c.auth, Auth::Azure { mount, instance: false, entra, .. } if mount == "azure" && entra.resource() == AZURE_RESOURCE));
        // Nor does the gce type: the metadata server makes its token.
        let c = Config::from_env(&settings(&[("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "gcp"), ("VAULT_GCP_TYPE", "gce"), ("VAULT_GCP_ROLE", "superbot"), ("VAULT_GCP_CREDENTIALS", "metadata")]), &none).unwrap();
        assert!(matches!(&c.auth, Auth::Gce { mount, role, google } if mount == "gcp" && role == "superbot" && google.method() == "metadata"));

        // The ec2 type needs its nonce, from the environment or a file, and none of the iam type's settings.
        let ec2 = [("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("VAULT_AWS_TYPE", "ec2")];
        for bad in ["short-nonce", "has a space in it, so no", "quote\"d-0123456789abcdef"] {
            let e = Config::from_env(&settings(&ec2), &EnvStore::fixed(&[("VAULT_AWS_NONCE", bad)])).err().unwrap();
            assert!(e.contains("VAULT_AWS_NONCE must be 16 to 128 printable characters") && !e.contains(bad), "{bad}: {e}");
        }
        let nonce = "0123456789abcdef-settings";
        let good = EnvStore::fixed(&[("VAULT_AWS_NONCE", nonce)]);
        for (extra, err) in [
            (("VAULT_AWS_REGION", "eu-west-2"), "VAULT_AWS_REGION is for VAULT_AWS_TYPE=iam"),
            (("VAULT_AWS_HEADER_VALUE", "vault.example.com"), "VAULT_AWS_HEADER_VALUE is for VAULT_AWS_TYPE=iam"),
            (("VAULT_AWS_CREDENTIALS", "instance-profile"), "VAULT_AWS_CREDENTIALS is for VAULT_AWS_TYPE=iam"),
            (("VAULT_AWS_ROLE", "a b"), "VAULT_AWS_ROLE must be"),
            (("AWS_EC2_METADATA_DISABLED", "true"), "AWS_EC2_METADATA_DISABLED is true"),
            (("AWS_EC2_METADATA_SERVICE_ENDPOINT", "http://169.254.169.254/latest"), "AWS_EC2_METADATA_SERVICE_ENDPOINT"),
        ] {
            let e = Config::from_env(&settings(&[ec2[0], ec2[1], ec2[2], extra]), &good).err().unwrap();
            assert!(e.contains(err), "{extra:?}: {e}");
        }
        let c = Config::from_env(&settings(&ec2), &good).unwrap();
        assert!(matches!(&c.auth, Auth::Ec2 { mount, role: None, nonce: n, .. } if mount == "aws" && n.as_str() == nonce));
        let file = token_file("vault-ec2-nonce", &format!("{nonce}\n"));
        let from_file = EnvStore::fixed(&[("VAULT_AWS_NONCE_FILE", file.to_str().unwrap())]);
        let c = Config::from_env(&settings(&ec2), &from_file).unwrap();
        assert!(matches!(&c.auth, Auth::Ec2 { nonce: n, .. } if n.as_str() == nonce), "read from VAULT_AWS_NONCE_FILE, its line break trimmed");
        redact::forget(nonce);
    }

    #[test]
    fn vault_credentials_never_reach_bots() {
        // `VAULT_JWT_FILE` would otherwise be offered to Bots as `VAULT_JWT`, read from the file.
        let file = token_file("vault-jwt-bots", &jwt("system:serviceaccount:superbot:botd", 3600));
        for var in ["VAULT_JWT_FILE", "VAULT_KUBERNETES_TOKEN_FILE"] {
            let s = Secrets::new(vec![Box::new(EnvStore::fixed(&[(var, file.to_str().unwrap())]))]);
            assert!(s.try_harness_env().unwrap().is_empty() && s.try_inherited_harness_env().unwrap().is_empty() && s.list().unwrap().is_empty(), "{var}");
        }
        // Cloud sign-in: AWS keys botd signs Vault's logins with are kept from Bots once chosen;
        // Google's key and Entra's client secret always are.
        let aws = [("VAULT_ADDR", "https://v"), ("VAULT_AUTH", "aws"), ("VAULT_AWS_CREDENTIALS", "env")];
        let keys = EnvStore::fixed(&[("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"), ("AWS_SECRET_ACCESS_KEY", "vault-bots-aws-secret")]);
        Config::from_env(&settings(&aws), &keys).unwrap();
        redact::forget("vault-bots-aws-secret");
        for name in ["VAULT_TOKEN", "VAULT_SECRET_ID", "VAULT_ROLE_ID", "VAULT_JWT", "VAULT_KUBERNETES_TOKEN", "VAULT_AWS_NONCE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GCP_SERVICE_ACCOUNT_KEY", "AZURE_CLIENT_SECRET"] {
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
