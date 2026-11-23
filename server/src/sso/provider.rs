//! One configured IdP: where it lives, its cached discovery document and keys, the code
//! exchange, and whose tokens it accepts.

use super::github::{self, GitHub};
use super::jwt::{self, Invalid, Jwks, Token};
use super::saml_sp::{self, Attributes, Encryption, IdpMetadata, KeyUse, MetadataRefused, MetadataTrust, SpKey};
use super::{apple, saml};
use crate::rbac::Role;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const META_TTL: Duration = Duration::from_secs(24 * 3600);
const JWKS_TTL: Duration = Duration::from_secs(3600);
/// Discovery documents and key sets are small; this bounds what a broken IdP can send.
const MAX_BODY: usize = 1024 * 1024;

pub const ENTRA_AUTHORITY: &str = "https://login.microsoftonline.com";
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

pub enum Kind {
    /// Microsoft Entra ID. Tokens come from one tenant's issuer, `{authority}/{tid}/v2.0`.
    /// `tenant` is a tenant id, or `organizations`/`common` with an `allowed` list.
    Entra { authority: String, tenant: String, allowed: Vec<String> },
    /// Google accounts, consumer and Workspace. `sub` is the subject, the email must be
    /// verified, and with `hosted_domains` only those Workspace domains (`hd`) get in.
    Google { issuer: String, hosted_domains: Vec<String> },
    /// Any OpenID Connect provider with one issuer. With `allowed_domains`, only people
    /// whose verified email is in one of them get in.
    Oidc { issuer: String, map: ClaimMap, allowed_domains: Vec<String> },
    /// Sign in with Apple: `sub` is the subject (stable per Apple developer team), the
    /// client secret is an ES256 JWT signed with the team's key, and with
    /// `allowed_domains` only verified, non-relay emails there get in.
    Apple { issuer: String, team_id: String, key_id: String, allowed_domains: Vec<String> },
    /// GitHub or GitHub Enterprise Server: OAuth 2 without an ID token. `web` has the
    /// authorize and token endpoints, `api` the REST API that says who signed in. With
    /// `allowed_orgs`, only active members of one of them get in.
    GitHub { web: String, api: String, allowed_orgs: Vec<String> },
    /// A SAML 2.0 IdP behind an OIDC broker (`issuer`, a Keycloak realm), see `saml`. The
    /// token must say the broker used the IdP `alias`; identities are stored under the
    /// IdP's `entity_id`, with its name for the person as the subject.
    Saml { issuer: String, entity_id: String, alias: String, map: ClaimMap, allowed_domains: Vec<String> },
    /// A SAML 2.0 IdP botd is the service provider for itself (ADR 0127), see `saml_sp`.
    /// Identities are stored like the bridge's: under `entity_id`, the NameID lowercased.
    /// `sign_requests` signs AuthnRequests with the SP key (ADR 0137), which is
    /// `SSO_<ID>_PRIVATE_KEY` with `sp_cert` (base64 DER) when that is set, else generated.
    /// `encryption` takes encrypted assertions (ADR 0150) with a key of their own, likewise
    /// `SSO_<ID>_ENCRYPTION_PRIVATE_KEY` with `enc_cert`, else generated. With `metadata_trust`,
    /// the IdP metadata's signature is checked against its certificates (ADR 0151).
    SamlSp {
        entity_id: String,
        sp_entity_id: String,
        source: IdpSource,
        attributes: Attributes,
        allowed_domains: Vec<String>,
        sign_requests: bool,
        sp_cert: Option<String>,
        encryption: Encryption,
        enc_cert: Option<String>,
        metadata_trust: Option<MetadataTrust>,
    },
}

/// Where a native SAML provider's IdP metadata comes from.
#[derive(Clone, Debug, PartialEq)]
pub enum IdpSource {
    /// `SSO_<ID>_IDP_METADATA_URL`: fetched when needed, again daily.
    Url(String),
    /// `SSO_<ID>_IDP_METADATA_FILE`: read at startup.
    File(String),
    /// Neither: imported with `botctl sso saml <id> import`, kept in the database.
    Saved,
}

impl IdpSource {
    pub fn name(&self) -> &'static str {
        match self {
            IdpSource::Url(_) => "url",
            IdpSource::File(_) => "file",
            IdpSource::Saved => "botctl",
        }
    }
}

#[cfg(test)]
impl Kind {
    pub fn oidc(issuer: &str) -> Kind {
        Kind::Oidc { issuer: issuer.into(), map: ClaimMap::default(), allowed_domains: Vec::new() }
    }
}

/// Which ID token claims hold the subject, email, and name (generic OIDC).
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimMap {
    pub subject: String,
    pub email: String,
    pub name: String,
}

impl Default for ClaimMap {
    fn default() -> ClaimMap {
        ClaimMap { subject: "sub".into(), email: "email".into(), name: "name".into() }
    }
}

pub struct Provider {
    pub id: String,
    pub label: String,
    pub kind: Kind,
    pub client_id: String,
    pub scopes: String,
    /// Just-in-time sign-up: who an unknown but valid identity becomes. None: refused.
    pub jit_role: Option<Role>,
    cache: tokio::sync::Mutex<Cache>,
    /// Native SAML: the IdP's metadata, and when it was loaded.
    idp: Mutex<Option<(Arc<IdpMetadata>, Instant)>>,
    /// Native SAML: our signing key, once loaded or made (ADR 0137).
    pub(super) sp_key: Mutex<Option<Arc<SpKey>>>,
    /// Native SAML: our encryption key, likewise (ADR 0150).
    pub(super) enc_key: Mutex<Option<Arc<SpKey>>>,
    /// Native SAML: metadata from the URL refused for its signature or validity, not yet audited.
    metadata_refused: Mutex<Option<MetadataRefused>>,
}

#[derive(Default)]
struct Cache {
    meta: Option<(Arc<Metadata>, Instant)>,
    jwks: Option<(Arc<Jwks>, Instant)>,
    /// The last failed fetch, so a down IdP costs one timeout per gap, not one per sign-in.
    meta_failed: Option<(Instant, Invalid)>,
    jwks_failed: Option<(Instant, Invalid)>,
    idp_failed: Option<(Instant, Invalid)>,
}

pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    jwks_uri: String,
    /// The IdP takes the client secret only as HTTP Basic, not in the form.
    basic_auth: bool,
}

/// What a verified ID token says about the person.
#[derive(Clone, Debug)]
pub struct Claims {
    pub issuer: String,
    /// The stable id: Entra `oid`, else `sub`. Never the email, which people can change.
    pub subject: String,
    pub tenant: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    /// A handle people know the account by (GitHub's login), for admins reading the audit
    /// log. Never the subject: it can change hands.
    pub username: Option<String>,
}

impl Claims {
    /// `issuer|subject`, as sessions and audit actors record it.
    pub fn key(&self) -> String {
        format!("{}|{}", self.issuer, self.subject)
    }
}

/// An Entra tenant or object id, lowercase.
pub fn guid(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    let groups: Vec<&str> = s.split('-').collect();
    let shape = groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12]);
    (shape && groups.iter().all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()))).then_some(s)
}

/// A DNS domain as people write it after the `@`, lowercase.
pub fn domain(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    let label_ok = |l: &str| (1..=63).contains(&l.len()) && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    (s.len() <= 253 && s.contains('.') && s.split('.').all(label_ok)).then_some(s)
}

/// The email's domain is one of `allowed`, exactly (subdomains are listed on their own).
fn email_in(email: &str, allowed: &[String]) -> bool {
    email.rsplit_once('@').and_then(|(local, d)| (!local.is_empty()).then(|| domain(d)).flatten()).is_some_and(|d| allowed.contains(&d))
}

/// The configured issuer and the discovery document's name the same IdP. A trailing slash
/// is a common typo (Auth0's issuer has one), not a different IdP.
fn same_issuer(configured: &str, discovered: &str) -> bool {
    configured.trim_end_matches('/') == discovered.trim_end_matches('/')
}

/// The email in `claim`, only when the IdP says it checked it. Some IdPs send the flag as a string.
fn verified_email(t: &Token, claim: &str) -> Option<String> {
    let verified = match t.claims.get("email_verified") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    };
    t.str(claim).filter(|_| verified).map(|e| e.trim().to_string()).filter(|e| !e.is_empty() && e.len() <= 254)
}

/// The verified email in `claim`. With `allowed` domains it is required, and must be in one.
fn email_within(t: &Token, claim: &str, allowed: &[String]) -> Result<Option<String>, Invalid> {
    let email = verified_email(t, claim);
    if !allowed.is_empty() {
        let e = email.as_deref().ok_or(Invalid("email_unverified"))?;
        if !email_in(e, allowed) {
            return Err(Invalid("wrong_domain"));
        }
    }
    Ok(email)
}

fn subject_of(t: &Token, claim: &str) -> Result<String, Invalid> {
    // Refused rather than trimmed: linking trims what admins type, so a padded or empty
    // subject could never be linked, and empty ones would all be one person.
    t.str(claim).filter(|s| !s.is_empty() && s.len() <= 255 && s.trim() == *s).map(String::from).ok_or(Invalid("missing_subject"))
}

/// https, or http to this machine (a local IdP in development and tests).
pub fn secure_url(u: &str) -> bool {
    match reqwest::Url::parse(u) {
        Ok(u) if u.scheme() == "https" => u.host_str().is_some(),
        Ok(u) if u.scheme() == "http" => matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
        _ => false,
    }
}

pub(super) async fn read_json(res: reqwest::Response) -> Result<(u16, Value), Invalid> {
    let status = res.status().as_u16();
    let mut res = res;
    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|_| Invalid("idp_unreachable"))? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_BODY {
            return Err(Invalid("idp_bad_response"));
        }
    }
    Ok((status, serde_json::from_slice(&body).map_err(|_| Invalid("idp_bad_response"))?))
}

async fn get_json(http: &reqwest::Client, url: &str) -> Result<Value, Invalid> {
    let res = http.get(url).header("accept", "application/json").send().await.map_err(|_| Invalid("idp_unreachable"))?;
    match read_json(res).await? {
        (200, v) => Ok(v),
        _ => Err(Invalid("idp_bad_response")),
    }
}

/// An IdP's SAML metadata document, at most `MAX_METADATA` bytes.
async fn get_text(http: &reqwest::Client, url: &str) -> Result<String, Invalid> {
    let mut res = http.get(url).header("accept", "application/samlmetadata+xml, application/xml, text/xml").send().await.map_err(|_| Invalid("idp_unreachable"))?;
    if res.status().as_u16() != 200 {
        return Err(Invalid("idp_bad_response"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|_| Invalid("idp_unreachable"))? {
        body.extend_from_slice(&chunk);
        if body.len() > saml_sp::MAX_METADATA {
            return Err(Invalid("idp_bad_response"));
        }
    }
    String::from_utf8(body).map_err(|_| Invalid("idp_bad_response"))
}

impl Provider {
    pub fn new(id: &str, label: &str, kind: Kind, client_id: &str, scopes: &str, jit_role: Option<Role>) -> Provider {
        Provider { id: id.into(), label: label.into(), kind, client_id: client_id.into(), scopes: scopes.into(), jit_role, cache: Default::default(), idp: Mutex::default(), sp_key: Mutex::default(), enc_key: Mutex::default(), metadata_refused: Mutex::default() }
    }

    pub fn type_name(&self) -> &'static str {
        match self.kind {
            Kind::Entra { .. } => "entra",
            Kind::Google { .. } => "google",
            Kind::Oidc { .. } => "oidc",
            Kind::Apple { .. } => "apple",
            Kind::GitHub { .. } => "github",
            Kind::Saml { .. } | Kind::SamlSp { .. } => "saml",
        }
    }

    /// botd is the SAML service provider itself, rather than signing in over OIDC.
    pub fn saml_sp(&self) -> bool {
        matches!(self.kind, Kind::SamlSp { .. })
    }

    /// Native SAML has no client secret: it checks signatures with the IdP's certificates.
    pub fn needs_secret(&self) -> bool {
        !self.saml_sp()
    }

    /// Whether a person with this email could sign in here, as far as the email shows:
    /// Some(true) when the provider only takes listed domains and this is one,
    /// Some(false) when it isn't, None when the provider doesn't go by email domain.
    pub fn takes_email(&self, email: &str) -> Option<bool> {
        match &self.kind {
            Kind::Google { hosted_domains: d, .. } | Kind::Oidc { allowed_domains: d, .. } | Kind::Apple { allowed_domains: d, .. } | Kind::Saml { allowed_domains: d, .. } | Kind::SamlSp { allowed_domains: d, .. } if !d.is_empty() => {
                Some(email_in(email, d))
            }
            _ => None,
        }
    }

    /// OpenID Connect, with an ID token and a nonce. GitHub is plain OAuth 2.
    pub fn oidc(&self) -> bool {
        !matches!(self.kind, Kind::GitHub { .. } | Kind::SamlSp { .. })
    }

    /// Native SAML's domain list (the IdP's email attribute, from its signed assertion): with
    /// one, the email is required and must be in it, as `email_within` does for OIDC.
    pub fn check_email(&self, email: Option<&str>) -> Result<(), Invalid> {
        match self.takes_email(email.unwrap_or("")) {
            Some(_) if email.is_none() => Err(Invalid("email_unverified")),
            Some(false) => Err(Invalid("wrong_domain")),
            _ => Ok(()),
        }
    }

    /// How the IdP returns the code: Apple must POST it when scopes are asked for.
    pub fn response_mode(&self) -> &'static str {
        if self.form_post() { "form_post" } else { "query" }
    }

    pub fn form_post(&self) -> bool {
        matches!(self.kind, Kind::Apple { .. })
    }

    /// Who may sign in, for the startup log.
    pub fn audience(&self) -> String {
        match &self.kind {
            Kind::Entra { tenant, allowed, .. } if allowed.is_empty() => format!("tenant {tenant}"),
            Kind::Entra { allowed, .. } => format!("tenants {}", allowed.join(", ")),
            Kind::Google { hosted_domains, .. } if hosted_domains.is_empty() => "any Google account".into(),
            Kind::Google { hosted_domains, .. } => format!("Workspace domains {}", hosted_domains.join(", ")),
            Kind::Oidc { allowed_domains, .. } if allowed_domains.is_empty() => "anyone the IdP signs in".into(),
            Kind::Oidc { allowed_domains, .. } => format!("verified emails at {}", allowed_domains.join(", ")),
            Kind::Apple { allowed_domains, .. } if allowed_domains.is_empty() => "any Apple Account".into(),
            Kind::Apple { allowed_domains, .. } => format!("verified emails at {}", allowed_domains.join(", ")),
            Kind::GitHub { web, allowed_orgs, .. } if allowed_orgs.is_empty() => format!("any account on {web}"),
            Kind::GitHub { web, allowed_orgs, .. } => format!("members of {} on {web}", allowed_orgs.join(", ")),
            Kind::Saml { entity_id, alias, allowed_domains, .. } if allowed_domains.is_empty() => format!("anyone SAML IdP {entity_id} signs in (broker alias {alias})"),
            Kind::Saml { entity_id, alias, allowed_domains, .. } => format!("verified emails at {} from SAML IdP {entity_id} (broker alias {alias})", allowed_domains.join(", ")),
            Kind::SamlSp { entity_id, allowed_domains, .. } if allowed_domains.is_empty() => {
                format!("anyone SAML IdP {entity_id} signs in (native)")
            }
            Kind::SamlSp { entity_id, allowed_domains, .. } => format!("emails at {} from SAML IdP {entity_id} (native)", allowed_domains.join(", ")),
        }
    }

    /// Extra authorization request parameters: always show the account picker for the
    /// big consumer IdPs, and give Google its Workspace domain hint. The hint only
    /// narrows the picker; `claims` checks `hd` itself.
    pub fn auth_params(&self) -> Vec<(&'static str, String)> {
        match &self.kind {
            Kind::Entra { .. } => vec![("prompt", "select_account".into())],
            Kind::Google { hosted_domains, .. } => {
                let mut p = vec![("prompt", "select_account".into())];
                match hosted_domains.as_slice() {
                    [] => {}
                    [one] => p.push(("hd", one.clone())),
                    _ => p.push(("hd", "*".into())),
                }
                p
            }
            Kind::Oidc { .. } | Kind::Apple { .. } => vec![],
            // Nobody makes a GitHub account halfway through signing in to SuperBot.
            Kind::GitHub { .. } => vec![("prompt", "select_account".into()), ("allow_signup", "false".into())],
            // Straight to the SAML IdP, past the broker's own login page. Only a shortcut:
            // `claims` checks the IdP the broker actually used.
            Kind::Saml { alias, .. } => vec![(saml::HINT_PARAM, alias.clone())],
            Kind::SamlSp { .. } => vec![],
        }
    }

    /// Where the provider's secret is set: env, `_FILE`, or the secrets store. Apple's is
    /// the private key that signs each client secret; native SAML's, the SP signing key
    /// when `SP_CERT_FILE` is set; the others', the client secret.
    pub fn env_var(&self) -> String {
        let what = if matches!(self.kind, Kind::Apple { .. } | Kind::SamlSp { .. }) { "PRIVATE_KEY" } else { "CLIENT_SECRET" };
        format!("SSO_{}_{what}", self.id.to_ascii_uppercase())
    }

    /// Read when used, so `botctl secret set` takes effect without a restart.
    fn stored_secret(&self) -> Option<crate::secrets::Secret> {
        Self::stored(&self.env_var())
    }

    fn stored(name: &str) -> Option<crate::secrets::Secret> {
        let s = crate::secrets::global().get(name).ok().flatten()?;
        crate::secrets::redact::register(s.expose());
        Some(s)
    }

    /// Native SAML: where the configured key for `u` is set. The signing key is the
    /// provider's secret (`env_var`); the encryption key has a name of its own.
    pub fn sp_key_var(&self, u: KeyUse) -> String {
        match u {
            KeyUse::Signing => self.env_var(),
            KeyUse::Encryption => format!("SSO_{}_ENCRYPTION_PRIVATE_KEY", self.id.to_ascii_uppercase()),
        }
    }

    /// Native SAML: the certificate configured for `u` (`SP_CERT_FILE`, `SP_ENCRYPTION_CERT_FILE`),
    /// or None when botd makes that key itself.
    pub fn sp_cert_for(&self, u: KeyUse) -> Option<&str> {
        match (&self.kind, u) {
            (Kind::SamlSp { sp_cert, .. }, KeyUse::Signing) => sp_cert.as_deref(),
            (Kind::SamlSp { enc_cert, .. }, KeyUse::Encryption) => enc_cert.as_deref(),
            _ => None,
        }
    }

    /// Where the key for `u` is kept once loaded or made.
    pub(super) fn sp_key_slot(&self, u: KeyUse) -> &Mutex<Option<Arc<SpKey>>> {
        match u {
            KeyUse::Signing => &self.sp_key,
            KeyUse::Encryption => &self.enc_key,
        }
    }

    /// Native SAML with `SP_CERT_FILE` (or `SP_ENCRYPTION_CERT_FILE`): the configured key, once
    /// it is set and matches the certificate. Kept once it does; until then each call reads the
    /// secret again, so `botctl secret set` takes effect without a restart. Err says what is missing.
    pub(super) fn configured_sp_key(&self, u: KeyUse) -> Result<Arc<SpKey>, String> {
        let (file, cert) = match u {
            KeyUse::Signing => ("SP_CERT_FILE", self.sp_cert_for(u)),
            KeyUse::Encryption => ("SP_ENCRYPTION_CERT_FILE", self.sp_cert_for(u)),
        };
        let Some(cert) = cert else { return Err(format!("no {file}")) };
        let mut held = self.sp_key_slot(u).lock().unwrap_or_else(|e| e.into_inner());
        if let Some(k) = held.as_ref() {
            return Ok(k.clone());
        }
        let var = self.sp_key_var(u);
        let pem = Self::stored(&var).ok_or_else(|| format!("not offered until {var} is set for {file} (env, _FILE, or `botctl secret set`)"))?;
        let key = Arc::new(SpKey::from_pem(pem.expose(), cert).map_err(|e| format!("not offered: {var}: {e}"))?);
        if u == KeyUse::Encryption && key.decrypting().is_none() {
            return Err(format!("not offered: {var} must be an RSA key: IdPs encrypt to it with RSA-OAEP"));
        }
        *held = Some(key.clone());
        Ok(key)
    }

    /// The client secret for one code exchange.
    fn client_secret(&self) -> Result<crate::secrets::Secret, Invalid> {
        let stored = self.stored_secret().ok_or(Invalid("not_configured"))?;
        match &self.kind {
            Kind::Apple { issuer, team_id, key_id, .. } => {
                let key = apple::signing_key(stored.expose())?;
                Ok(crate::secrets::Secret::new(apple::client_secret(&key, team_id, key_id, &self.client_id, issuer, crate::db::now() / 1000)?))
            }
            _ => Ok(stored),
        }
    }

    /// Offered on the sign-in page: it has its client secret (Apple: a key that parses).
    pub fn ready(&self) -> bool {
        self.not_ready().is_none()
    }

    /// Why the provider isn't offered, for the startup log.
    pub fn not_ready(&self) -> Option<String> {
        if let Kind::SamlSp { source, sp_cert, encryption, enc_cert, .. } = &self.kind {
            let loaded = self.idp.lock().unwrap_or_else(|e| e.into_inner()).is_some();
            if matches!(source, IdpSource::Saved) && !loaded {
                return Some(format!("not offered until its IdP metadata is imported: botctl sso saml {} import < metadata.xml", self.id));
            }
            let signing = sp_cert.as_ref().and_then(|_| self.configured_sp_key(KeyUse::Signing).err());
            let encrypting = enc_cert.as_ref().filter(|_| *encryption != Encryption::Off).and_then(|_| self.configured_sp_key(KeyUse::Encryption).err());
            return signing.or(encrypting);
        }
        let var = self.env_var();
        match (&self.kind, self.stored_secret()) {
            (_, None) => Some(format!("not offered until {var} is set (env, _FILE, or `botctl secret set`)")),
            (Kind::Apple { .. }, Some(key)) if apple::signing_key(key.expose()).is_err() => Some(format!("not offered: {var} isn't a Sign in with Apple key (the .p8 file)")),
            _ => None,
        }
    }

    /// None for GitHub, which has no discovery document.
    fn discovery_url(&self) -> Option<String> {
        match &self.kind {
            Kind::Entra { authority, tenant, .. } => Some(format!("{authority}/{tenant}/v2.0/.well-known/openid-configuration")),
            Kind::Google { issuer, .. } | Kind::Oidc { issuer, .. } | Kind::Apple { issuer, .. } | Kind::Saml { issuer, .. } => Some(format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'))),
            Kind::GitHub { .. } | Kind::SamlSp { .. } => None,
        }
    }

    /// Where `start` sends the browser. GitHub's is fixed; OIDC providers' comes from discovery.
    pub async fn authorization_endpoint(&self, http: &reqwest::Client, gap: Duration) -> Result<String, Invalid> {
        match &self.kind {
            Kind::GitHub { web, .. } => Ok(format!("{web}/login/oauth/authorize")),
            Kind::SamlSp { .. } => Ok(self.idp_metadata(http, gap).await?.sso_url.clone()),
            _ => Ok(self.metadata(http, gap).await?.authorization_endpoint.clone()),
        }
    }

    /// The issuer of a tenant's tokens (Entra), or the provider's one issuer.
    pub fn issuer_for(&self, tenant: Option<&str>) -> Result<(String, Option<String>), String> {
        match &self.kind {
            Kind::Entra { authority, tenant: own, allowed } => {
                let tid = match tenant {
                    Some(t) => guid(t).ok_or("tenant must be a tenant id (a GUID)")?,
                    None => guid(own).ok_or("This provider allows several tenants: say which with --tenant")?,
                };
                if !(guid(own).as_deref() == Some(tid.as_str()) || allowed.contains(&tid)) {
                    return Err(format!("Tenant {tid} is not allowed by SSO_{}_TENANT or SSO_{}_ALLOWED_TENANTS", self.id.to_ascii_uppercase(), self.id.to_ascii_uppercase()));
                }
                Ok((format!("{authority}/{tid}/v2.0"), Some(tid)))
            }
            Kind::Google { issuer, .. } | Kind::Oidc { issuer, .. } | Kind::Apple { issuer, .. } | Kind::GitHub { web: issuer, .. } | Kind::Saml { entity_id: issuer, .. } | Kind::SamlSp { entity_id: issuer, .. } if tenant.is_none() => {
                Ok((issuer.clone(), None))
            }
            _ => Err("tenant is only for Entra providers".into()),
        }
    }

    /// The subject as tokens carry it: Entra object ids are lowercase GUIDs, GitHub's are numbers.
    pub fn subject(&self, s: &str) -> Result<String, String> {
        let s = s.trim();
        match self.kind {
            Kind::Entra { .. } => guid(s).ok_or_else(|| "subject must be the user's Entra object id (a GUID)".into()),
            Kind::GitHub { .. } => github::user_id(s).ok_or_else(|| "subject must be the GitHub user's numeric id (gh api users/<login> --jq .id), not the login".into()),
            Kind::Saml { .. } | Kind::SamlSp { .. } if !s.is_empty() && s.len() <= 255 => Ok(saml::subject(s)),
            _ if !s.is_empty() && s.len() <= 255 => Ok(s.into()),
            _ => Err("subject must be 1 to 255 characters".into()),
        }
    }

    /// Native SAML: the IdP metadata loaded now, from any source.
    pub fn idp_loaded(&self) -> Option<Arc<IdpMetadata>> {
        self.idp.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|(m, _)| m.clone())
    }

    /// When the IdP metadata was loaded, for `botctl sso saml`.
    pub fn idp_age(&self) -> Option<Duration> {
        self.idp.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|(_, at)| at.elapsed())
    }

    /// Makes the loaded IdP metadata look `by` older, so tests can reach a refresh.
    #[cfg(test)]
    pub fn age_idp(&self, by: Duration) {
        if let Some((_, at)) = self.idp.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            *at = at.checked_sub(by).unwrap_or(*at);
        }
    }

    pub fn set_idp(&self, m: IdpMetadata) {
        *self.idp.lock().unwrap_or_else(|e| e.into_inner()) = Some((Arc::new(m), Instant::now()));
    }

    /// Native SAML: metadata from the URL refused since the last call, for the audit log.
    pub fn take_metadata_refusal(&self) -> Option<MetadataRefused> {
        self.metadata_refused.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    /// Native SAML: the IdP metadata. From a URL it's fetched again after a day, and after a
    /// failure at most once per `gap`, keeping what we had meanwhile, as for OIDC discovery.
    pub async fn idp_metadata(&self, http: &reqwest::Client, gap: Duration) -> Result<Arc<IdpMetadata>, Invalid> {
        let Kind::SamlSp { source, entity_id, sign_requests, metadata_trust, .. } = &self.kind else {
            return Err(Invalid("not_configured"));
        };
        let (stale, fresh) = match self.idp.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some((m, at)) => (Some(m.clone()), at.elapsed() < META_TTL),
            None => (None, false),
        };
        let IdpSource::Url(url) = source else {
            return stale.ok_or(Invalid("not_configured"));
        };
        if let (Some(m), true) = (&stale, fresh) {
            return Ok(m.clone());
        }
        let mut c = self.cache.lock().await;
        // Whoever held the lock may just have fetched it.
        if let Some((m, at)) = self.idp.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
            && at.elapsed() < META_TTL
        {
            return Ok(m.clone());
        }
        if let Some((at, e)) = c.idp_failed
            && at.elapsed() < gap
        {
            return stale.ok_or(e);
        }
        let got = get_text(http, url).await.and_then(|xml| {
            saml_sp::load_idp_metadata(&xml, entity_id, *sign_requests, metadata_trust.as_ref(), crate::db::now()).map_err(|e| {
                crate::obs::log::log_warn!("SSO {}: IdP metadata from {url}: {e}", self.id);
                if e.untrusted() {
                    *self.metadata_refused.lock().unwrap_or_else(|e| e.into_inner()) = Some(e);
                }
                Invalid("idp_bad_response")
            })
        });
        match got {
            Ok(m) => {
                c.idp_failed = None;
                self.set_idp(m);
                self.idp_loaded().ok_or(Invalid("idp_bad_response"))
            }
            Err(e) => {
                c.idp_failed = Some((Instant::now(), e));
                stale.ok_or(e)
            }
        }
    }

    /// The discovery document, retried at most once per `gap` after a failure.
    pub async fn metadata(&self, http: &reqwest::Client, gap: Duration) -> Result<Arc<Metadata>, Invalid> {
        let mut c = self.cache.lock().await;
        let stale = c.meta.as_ref().map(|(m, _)| m.clone());
        if let Some((m, at)) = &c.meta
            && at.elapsed() < META_TTL
        {
            return Ok(m.clone());
        }
        if let Some((at, e)) = c.meta_failed
            && at.elapsed() < gap
        {
            return stale.ok_or(e);
        }
        match self.fetch_metadata(http).await {
            Ok(m) => {
                let m = Arc::new(m);
                c.meta = Some((m.clone(), Instant::now()));
                c.meta_failed = None;
                Ok(m)
            }
            // An IdP outage shouldn't sign everyone out of SSO: keep using what we had.
            Err(e) => {
                c.meta_failed = Some((Instant::now(), e));
                stale.ok_or(e)
            }
        }
    }

    async fn fetch_metadata(&self, http: &reqwest::Client) -> Result<Metadata, Invalid> {
        let v = get_json(http, &self.discovery_url().ok_or(Invalid("not_configured"))?).await?;
        let url = |k: &str| v[k].as_str().filter(|u| secure_url(u)).map(String::from).ok_or(Invalid("idp_bad_response"));
        let methods: Vec<&str> = v["token_endpoint_auth_methods_supported"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        Ok(Metadata {
            issuer: v["issuer"].as_str().unwrap_or_default().to_string(),
            authorization_endpoint: url("authorization_endpoint")?,
            token_endpoint: url("token_endpoint")?,
            jwks_uri: url("jwks_uri")?,
            basic_auth: !methods.is_empty() && !methods.contains(&"client_secret_post"),
        })
    }

    /// The signing keys, fetched again when a token names a key we don't have (the IdP
    /// rotated), at most once per `gap`, and retried at most once per `gap` after a failure.
    async fn keys(&self, http: &reqwest::Client, meta: &Metadata, kid: Option<&str>, gap: Duration) -> Result<Arc<Jwks>, Invalid> {
        let mut c = self.cache.lock().await;
        let stale = c.jwks.as_ref().map(|(k, _)| k.clone());
        if let Some((k, at)) = &c.jwks {
            let fresh = at.elapsed() < JWKS_TTL && k.has(kid);
            if fresh || at.elapsed() < gap {
                return Ok(k.clone());
            }
        }
        if let Some((at, e)) = c.jwks_failed
            && at.elapsed() < gap
        {
            return stale.ok_or(e);
        }
        match get_json(http, &meta.jwks_uri).await.and_then(|v| Jwks::parse(&v)) {
            Ok(k) => {
                let k = Arc::new(k);
                c.jwks = Some((k.clone(), Instant::now()));
                c.jwks_failed = None;
                Ok(k)
            }
            Err(e) => {
                c.jwks_failed = Some((Instant::now(), e));
                stale.ok_or(e)
            }
        }
    }

    /// Trades the authorization code for an ID token (with our PKCE verifier) and checks it.
    /// GitHub has no ID token: its API says who the access token belongs to.
    pub async fn sign_in(&self, http: &reqwest::Client, code: &str, redirect_uri: &str, verifier: &str, nonce: &str, gap: Duration) -> Result<Claims, Invalid> {
        if let Kind::GitHub { web, api, allowed_orgs } = &self.kind {
            let secret = self.client_secret()?;
            let gh = GitHub { web, api, client_id: &self.client_id, allowed_orgs };
            return gh.sign_in(http, code, redirect_uri, verifier, secret.expose()).await;
        }
        let meta = self.metadata(http, gap).await?;
        let secret = self.client_secret()?;
        let mut form = vec![("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect_uri), ("code_verifier", verifier), ("client_id", &self.client_id)];
        let mut req = http.post(&meta.token_endpoint).header("accept", "application/json");
        if meta.basic_auth {
            // RFC 6749 2.3.1: form-encode both before joining.
            let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
            req = req.basic_auth(enc(&self.client_id), Some(enc(secret.expose())));
        } else {
            form.push(("client_secret", secret.expose()));
        }
        let res = req.form(&form).send().await.map_err(|_| Invalid("idp_unreachable"))?;
        let id_token = match read_json(res).await? {
            (200, v) => v["id_token"].as_str().map(String::from).ok_or(Invalid("idp_bad_response"))?,
            _ => return Err(Invalid("code_exchange_failed")),
        };
        let token = jwt::decode(&id_token)?;
        let keys = self.keys(http, &meta, token.kid.as_deref(), gap).await?;
        token.verify(&keys)?;
        token.check(&self.client_id, nonce, crate::db::now() / 1000)?;
        self.claims(&token, &meta)
    }

    /// Whose token this is, if it's from an issuer we accept.
    pub fn claims(&self, t: &Token, meta: &Metadata) -> Result<Claims, Invalid> {
        let iss = t.str("iss").ok_or(Invalid("wrong_issuer"))?;
        let name_in = |claim: &str| t.str(claim).map(|n| crate::audit::clip(n.trim(), 100)).filter(|n| !n.is_empty());
        let name = name_in("name");
        match &self.kind {
            Kind::Entra { authority, tenant, allowed } => {
                let tid = t.str("tid").and_then(guid).ok_or(Invalid("wrong_tenant"))?;
                let ok = guid(tenant).map_or_else(|| allowed.contains(&tid), |own| own == tid);
                if !ok {
                    return Err(Invalid("wrong_tenant"));
                }
                if iss != format!("{authority}/{tid}/v2.0") {
                    return Err(Invalid("wrong_issuer"));
                }
                let oid = t.str("oid").and_then(guid).ok_or(Invalid("missing_subject"))?;
                // Entra's `email` is whatever the account's tenant typed in (nOAuth), so it is kept only
                // when the optional `xms_edov` claim says that tenant owns the email's domain.
                let edov = match t.claims.get("xms_edov") {
                    Some(Value::Bool(b)) => *b,
                    Some(Value::String(s)) => s == "true" || s == "1",
                    Some(Value::Number(n)) => n.as_u64() == Some(1),
                    _ => false,
                };
                let email = t.str("email").filter(|_| edov).map(|e| e.trim().to_string()).filter(|e| !e.is_empty() && e.len() <= 254);
                Ok(Claims { issuer: iss.into(), subject: oid, tenant: Some(tid), email, name, username: None })
            }
            // Identities are stored under the configured issuer, so a link made with
            // `botctl user link` and a sign-in name the same one.
            Kind::Google { issuer, hosted_domains } => {
                // Google's tokens and discovery may name the issuer without its scheme (legacy).
                let ours = |x: &str| {
                    let (x, c) = (x.trim_end_matches('/'), issuer.trim_end_matches('/'));
                    x == c || Some(x) == c.strip_prefix("https://")
                };
                if !ours(&meta.issuer) || !ours(iss) {
                    return Err(Invalid("wrong_issuer"));
                }
                let subject = subject_of(t, "sub")?;
                let email = verified_email(t, "email").ok_or(Invalid("email_unverified"))?;
                // `hd` is set by Google for Workspace accounts only; an email's domain is not
                // proof of membership (anyone can make a Google account for any address).
                if !hosted_domains.is_empty() && !t.str("hd").and_then(domain).is_some_and(|d| hosted_domains.contains(&d)) {
                    return Err(Invalid("wrong_domain"));
                }
                Ok(Claims { issuer: issuer.clone(), subject, tenant: None, email: Some(email), name, username: None })
            }
            Kind::Oidc { issuer, map, allowed_domains } => {
                if !same_issuer(issuer, &meta.issuer) || iss != meta.issuer {
                    return Err(Invalid("wrong_issuer"));
                }
                let subject = subject_of(t, &map.subject)?;
                let email = email_within(t, &map.email, allowed_domains)?;
                Ok(Claims { issuer: issuer.clone(), subject, tenant: None, email, name: name_in(&map.name), username: None })
            }
            // The broker checked the SAML assertion; its signed token says which IdP it used.
            Kind::Saml { issuer, entity_id, alias, map, allowed_domains } => {
                if !same_issuer(issuer, &meta.issuer) || iss != meta.issuer {
                    return Err(Invalid("wrong_issuer"));
                }
                if t.str(saml::IDP_CLAIM) != Some(alias.as_str()) {
                    return Err(Invalid("not_brokered"));
                }
                let subject = saml::subject(&subject_of(t, &map.subject)?);
                let email = email_within(t, &map.email, allowed_domains)?;
                Ok(Claims { issuer: entity_id.clone(), subject, tenant: None, email, name: name_in(&map.name), username: None })
            }
            // Apple's token never has the name: it is posted once, beside it (`apple::posted_name`).
            Kind::Apple { issuer, allowed_domains, .. } => {
                if !same_issuer(issuer, &meta.issuer) || !same_issuer(issuer, iss) {
                    return Err(Invalid("wrong_issuer"));
                }
                let subject = subject_of(t, "sub")?;
                let email = verified_email(t, "email");
                if !allowed_domains.is_empty() {
                    let e = email.as_deref().ok_or(Invalid("email_unverified"))?;
                    // A Hide My Email address never matches: its domain is Apple's (startup refuses listing it).
                    if !email_in(e, allowed_domains) {
                        return Err(Invalid("wrong_domain"));
                    }
                }
                Ok(Claims { issuer: issuer.clone(), subject, tenant: None, email, name: None, username: None })
            }
            Kind::GitHub { .. } | Kind::SamlSp { .. } => Err(Invalid("not_configured")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sso::jwt::test_keys::keys;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use serde_json::json;

    const T1: &str = "11111111-1111-1111-1111-111111111111";
    const T2: &str = "22222222-2222-2222-2222-222222222222";
    const OID: &str = "aaaaaaaa-0000-0000-0000-000000000001";

    fn entra(tenant: &str, allowed: &[&str]) -> Provider {
        let kind = Kind::Entra { authority: ENTRA_AUTHORITY.into(), tenant: tenant.into(), allowed: allowed.iter().map(|s| s.to_string()).collect() };
        Provider::new("entra", "Microsoft", kind, "client-1", "openid", None)
    }

    fn meta(issuer: &str) -> Metadata {
        Metadata { issuer: issuer.into(), authorization_endpoint: String::new(), token_endpoint: String::new(), jwks_uri: String::new(), basic_auth: false }
    }

    fn token(tid: &str, iss: &str, oid: Option<&str>) -> Token {
        let mut c = json!({ "iss": iss, "tid": tid, "sub": "pairwise-sub", "email": "a@example.com", "name": "A" });
        if let Some(o) = oid {
            c["oid"] = json!(o);
        }
        jwt::decode(&keys()[0].sign(&c)).unwrap()
    }

    fn iss(tid: &str) -> String {
        format!("{ENTRA_AUTHORITY}/{tid}/v2.0")
    }

    #[test]
    fn entra_takes_its_tenants_issuer_and_the_object_id() {
        let p = entra(T1, &[]);
        let m = meta(&iss(T1));
        let c = p.claims(&token(T1, &iss(T1), Some(&OID.to_uppercase())), &m).unwrap();
        assert_eq!((c.subject.as_str(), c.tenant.as_deref(), c.key()), (OID, Some(T1), format!("{}|{OID}", iss(T1))));
        assert_eq!(p.claims(&token(T2, &iss(T2), Some(OID)), &m).err(), Some(Invalid("wrong_tenant")));
        assert_eq!(p.claims(&token(T1, &iss(T2), Some(OID)), &m).err(), Some(Invalid("wrong_issuer")), "iss must match tid");
        assert_eq!(p.claims(&token(T1, "https://evil.example/t/v2.0", Some(OID)), &m).err(), Some(Invalid("wrong_issuer")));
        assert_eq!(p.claims(&token(T1, &iss(T1), None), &m).err(), Some(Invalid("missing_subject")), "sub alone is not enough");
    }

    #[test]
    fn entra_email_counts_only_when_its_domain_is_verified() {
        let p = entra(T1, &[]);
        let m = meta(&iss(T1));
        let with = |edov: Value| {
            let mut c = json!({ "iss": iss(T1), "tid": T1, "oid": OID, "email": "ceo@example.com" });
            if !edov.is_null() {
                c["xms_edov"] = edov;
            }
            p.claims(&jwt::decode(&keys()[0].sign(&c)).unwrap(), &m).unwrap().email
        };
        for ok in [json!(true), json!("true"), json!("1"), json!(1)] {
            assert_eq!(with(ok.clone()).as_deref(), Some("ceo@example.com"), "{ok}");
        }
        for no in [Value::Null, json!(false), json!("false"), json!(0), json!("yes")] {
            assert_eq!(with(no.clone()), None, "{no}: any tenant can type in any email");
        }
    }

    #[test]
    fn multi_tenant_entra_takes_only_allowed_tenants() {
        let p = entra("organizations", &[T2]);
        let m = meta(&format!("{ENTRA_AUTHORITY}/{{tenantid}}/v2.0"));
        assert!(p.claims(&token(T2, &iss(T2), Some(OID)), &m).is_ok());
        assert_eq!(p.claims(&token(T1, &iss(T1), Some(OID)), &m).err(), Some(Invalid("wrong_tenant")));
        assert_eq!(p.issuer_for(Some(T2)).unwrap(), (iss(T2), Some(T2.to_string())));
        assert!(p.issuer_for(Some(T1)).is_err());
        assert!(p.issuer_for(None).is_err(), "which tenant?");
        assert_eq!(entra(T1, &[]).issuer_for(None).unwrap().0, iss(T1));
    }

    #[test]
    fn oidc_takes_one_issuer_and_only_verified_email() {
        let p = Provider::new("acme", "Acme", Kind::oidc("https://idp.example"), "client-1", "openid", None);
        let m = meta("https://idp.example");
        let t = |c: Value| jwt::decode(&keys()[0].sign(&c)).unwrap();
        let c = p.claims(&t(json!({ "iss": "https://idp.example", "sub": "s1", "email": "a@example.com" })), &m).unwrap();
        assert_eq!((c.subject.as_str(), c.email), ("s1", None));
        let c = p.claims(&t(json!({ "iss": "https://idp.example", "sub": "s1", "email": "a@example.com", "email_verified": true })), &m).unwrap();
        assert_eq!(c.email.as_deref(), Some("a@example.com"));
        assert_eq!(p.claims(&t(json!({ "iss": "https://other.example", "sub": "s1" })), &m).err(), Some(Invalid("wrong_issuer")));
        assert_eq!(p.claims(&t(json!({ "iss": "https://idp.example" })), &m).err(), Some(Invalid("missing_subject")));
        for padded in ["", " s1", "s1 "] {
            assert_eq!(p.claims(&t(json!({ "iss": "https://idp.example", "sub": padded })), &m).err(), Some(Invalid("missing_subject")), "{padded:?}: empty ones would all be one person");
        }
    }

    fn signed(c: Value) -> Token {
        jwt::decode(&keys()[0].sign(&c)).unwrap()
    }

    fn google(domains: &[&str]) -> Provider {
        let kind = Kind::Google { issuer: GOOGLE_ISSUER.into(), hosted_domains: domains.iter().map(|s| s.to_string()).collect() };
        Provider::new("google", "Google", kind, "client-1", "openid email profile", None)
    }

    fn g(extra: Value) -> Value {
        let mut c = json!({ "iss": GOOGLE_ISSUER, "sub": "1077", "email": "ada@example.com", "email_verified": true, "hd": "example.com", "name": "Ada" });
        c.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        c
    }

    #[test]
    fn google_takes_sub_and_a_verified_email_under_either_issuer_form() {
        let (p, m) = (google(&[]), meta(GOOGLE_ISSUER));
        let c = p.claims(&signed(g(json!({}))), &m).unwrap();
        assert_eq!((c.issuer.as_str(), c.subject.as_str(), c.email.as_deref(), c.tenant.as_deref()), (GOOGLE_ISSUER, "1077", Some("ada@example.com"), None));
        let bare = p.claims(&signed(g(json!({ "iss": "accounts.google.com" }))), &m).unwrap();
        assert_eq!(bare.key(), c.key(), "stored under one issuer, so links match both forms");
        assert!(p.claims(&signed(g(json!({ "hd": null }))), &m).is_ok(), "consumer accounts are fine without a domain list");
        for (claims, why) in [(json!({ "email_verified": false }), "unverified"), (json!({ "email_verified": null }), "no flag"), (json!({ "email": null }), "no email")] {
            assert_eq!(p.claims(&signed(g(claims)), &m).err(), Some(Invalid("email_unverified")), "{why}");
        }
        for iss in ["https://accounts.google.com.evil.example", "http://accounts.google.com", "https://idp.example"] {
            assert_eq!(p.claims(&signed(g(json!({ "iss": iss }))), &m).err(), Some(Invalid("wrong_issuer")), "{iss}");
        }
        assert_eq!(p.claims(&signed(g(json!({}))), &meta("https://evil.example")).err(), Some(Invalid("wrong_issuer")), "discovery from elsewhere");
        assert!(p.claims(&signed(g(json!({}))), &meta("accounts.google.com")).is_ok(), "legacy discovery issuer");
        assert_eq!(p.claims(&signed(g(json!({ "sub": null }))), &m).err(), Some(Invalid("missing_subject")));
    }

    #[test]
    fn google_workspace_domains_are_checked_on_hd_not_the_email() {
        let (p, m) = (google(&["example.com", "example.org"]), meta(GOOGLE_ISSUER));
        assert!(p.claims(&signed(g(json!({}))), &m).is_ok());
        assert!(p.claims(&signed(g(json!({ "hd": "EXAMPLE.org" }))), &m).is_ok());
        assert_eq!(p.claims(&signed(g(json!({ "hd": null }))), &m).err(), Some(Invalid("wrong_domain")), "a consumer account with a company email");
        assert_eq!(p.claims(&signed(g(json!({ "hd": "evil.example" }))), &m).err(), Some(Invalid("wrong_domain")));
        assert_eq!(p.claims(&signed(g(json!({ "hd": "sub.example.com" }))), &m).err(), Some(Invalid("wrong_domain")), "subdomains are listed on their own");
        assert_eq!(p.claims(&signed(g(json!({ "hd": "evil.example", "email": "ada@example.com" }))), &m).err(), Some(Invalid("wrong_domain")));
        assert_eq!(p.auth_params(), [("prompt", "select_account".to_string()), ("hd", "*".to_string())]);
        assert_eq!(google(&["example.com"]).auth_params()[1], ("hd", "example.com".to_string()));
        assert_eq!(google(&[]).auth_params().len(), 1);
    }

    #[test]
    fn google_tokens_pass_the_shared_checks_too() {
        let p = google(&["example.com"]);
        let now = 1_800_000_000;
        let (nonce, other) = (crate::random_hex(16), crate::random_hex(16));
        let base = |extra: Value| {
            let mut c = g(json!({ "aud": "client-1", "nonce": nonce, "iat": now, "exp": now + 3600 }));
            c.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            c
        };
        let run = |c: Value| {
            let t = signed(c);
            t.check("client-1", &nonce, now)?;
            p.claims(&t, &meta(GOOGLE_ISSUER))
        };
        assert!(run(base(json!({}))).is_ok());
        assert_eq!(run(base(json!({ "aud": "someone-else" }))).err(), Some(Invalid("wrong_audience")));
        assert_eq!(run(base(json!({ "exp": now - 3600 }))).err(), Some(Invalid("expired")));
        assert_eq!(run(base(json!({ "nonce": other }))).err(), Some(Invalid("nonce_mismatch")));
        assert_eq!(run(base(json!({ "hd": "evil.example" }))).err(), Some(Invalid("wrong_domain")));
    }

    #[test]
    fn oidc_maps_claims_and_restricts_to_verified_email_domains() {
        let map = ClaimMap { subject: "uid".into(), email: "mail".into(), name: "display".into() };
        let kind = Kind::Oidc { issuer: "https://tenant.auth0.example/".into(), map, allowed_domains: vec!["example.com".into()] };
        let p = Provider::new("acme", "Acme", kind, "client-1", "openid", None);
        let m = meta("https://tenant.auth0.example/");
        let t = |extra: Value| {
            let mut c = json!({ "iss": "https://tenant.auth0.example/", "sub": "pairwise", "uid": "u-1", "mail": "ada@Example.com", "email_verified": "true", "display": "Ada" });
            c.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            signed(c)
        };
        let c = p.claims(&t(json!({})), &m).unwrap();
        assert_eq!((c.subject.as_str(), c.email.as_deref(), c.name.as_deref(), c.issuer.as_str()), ("u-1", Some("ada@Example.com"), Some("Ada"), "https://tenant.auth0.example/"));
        assert_eq!(p.claims(&t(json!({ "uid": null })), &m).err(), Some(Invalid("missing_subject")), "sub is not the subject here");
        assert_eq!(p.claims(&t(json!({ "email_verified": false })), &m).err(), Some(Invalid("email_unverified")));
        assert_eq!(p.claims(&t(json!({ "mail": null })), &m).err(), Some(Invalid("email_unverified")));
        for mail in ["ada@evil.example", "ada@example.com.evil.example", "ada@sub.example.com", "example.com", "@example.com", "ada@example.com@evil.example"] {
            assert_eq!(p.claims(&t(json!({ "mail": mail })), &m).err(), Some(Invalid("wrong_domain")), "{mail}");
        }
        assert_eq!(p.claims(&t(json!({ "iss": "https://tenant.auth0.example" })), &m).err(), Some(Invalid("wrong_issuer")), "the token must match discovery exactly");
        let typo = meta("https://tenant.auth0.example");
        assert_eq!(p.claims(&t(json!({ "iss": "https://tenant.auth0.example" })), &typo).unwrap().issuer, "https://tenant.auth0.example/", "a trailing slash in config is not a different IdP");
        assert!(p.auth_params().is_empty());
    }

    fn apple(domains: &[&str]) -> Provider {
        let kind = Kind::Apple { issuer: apple::ISSUER.into(), team_id: "TEAM123456".into(), key_id: "KEY1234567".into(), allowed_domains: domains.iter().map(|s| s.to_string()).collect() };
        Provider::new("apple", "Apple", kind, "com.example.superbot", "name email", None)
    }

    fn a(extra: Value) -> Token {
        let mut c = json!({ "iss": apple::ISSUER, "sub": "001234.abc", "email": "ada@example.com", "email_verified": "true", "is_private_email": "false" });
        c.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        c.as_object_mut().unwrap().retain(|_, v| !v.is_null());
        signed(c)
    }

    #[test]
    fn apple_takes_sub_and_a_verified_email_and_has_no_name_in_the_token() {
        let (p, m) = (apple(&[]), meta(apple::ISSUER));
        let c = p.claims(&a(json!({ "name": "Not From Apple" })), &m).unwrap();
        assert_eq!((c.issuer.as_str(), c.subject.as_str(), c.email.as_deref(), c.name), (apple::ISSUER, "001234.abc", Some("ada@example.com"), None));
        let relay = p.claims(&a(json!({ "email": "x7@privaterelay.appleid.com", "is_private_email": true, "email_verified": true })), &m).unwrap();
        assert_eq!(relay.email.as_deref(), Some("x7@privaterelay.appleid.com"), "Hide My Email is fine once linked");
        assert_eq!(p.claims(&a(json!({ "email_verified": "false" })), &m).unwrap().email, None);
        assert!(p.claims(&a(json!({ "email": null })), &m).is_ok(), "a linked identity needs no email");
        assert_eq!(p.claims(&a(json!({ "sub": null })), &m).err(), Some(Invalid("missing_subject")));
        for iss in ["https://appleid.apple.com.evil.example", "appleid.apple.com", "https://accounts.google.com"] {
            assert_eq!(p.claims(&a(json!({ "iss": iss })), &m).err(), Some(Invalid("wrong_issuer")), "{iss}");
        }
        assert_eq!(p.claims(&a(json!({})), &meta("https://evil.example")).err(), Some(Invalid("wrong_issuer")), "discovery from elsewhere");
    }

    #[test]
    fn apple_email_domains_refuse_hide_my_email_and_unverified_addresses() {
        let (p, m) = (apple(&["example.com"]), meta(apple::ISSUER));
        assert!(p.claims(&a(json!({})), &m).is_ok());
        for (extra, why) in [
            (json!({ "email": "x7@privaterelay.appleid.com", "is_private_email": "true" }), "Hide My Email"),
            (json!({ "email": "ada@evil.example" }), "another domain"),
            (json!({ "email": "ada@sub.example.com" }), "a subdomain"),
        ] {
            assert_eq!(p.claims(&a(extra), &m).err(), Some(Invalid("wrong_domain")), "{why}");
        }
        assert_eq!(p.claims(&a(json!({ "email_verified": false })), &m).err(), Some(Invalid("email_unverified")));
        assert_eq!(p.claims(&a(json!({ "email": null })), &m).err(), Some(Invalid("email_unverified")));
    }

    const BROKER: &str = "https://sso.example.com/realms/superbot";
    const ADFS: &str = "http://adfs.example.com/adfs/services/trust";

    fn saml_bridge(domains: &[&str]) -> Provider {
        let map = ClaimMap { subject: saml::SUBJECT_CLAIM.into(), ..ClaimMap::default() };
        let kind = Kind::Saml { issuer: BROKER.into(), entity_id: ADFS.into(), alias: "adfs".into(), map, allowed_domains: domains.iter().map(|s| s.to_string()).collect() };
        Provider::new("adfs", "Contoso", kind, "client-1", "openid profile email", None)
    }

    /// What Keycloak's ID token says after a login brokered through the SAML IdP `adfs`.
    fn brokered(extra: Value) -> Value {
        let mut c = json!({
            "iss": BROKER, "sub": "kc-user-uuid", "preferred_username": "ada",
            "identity_provider": "adfs", "identity_provider_identity": "_a1b2c3-persistent",
            "email": "ada@example.com", "email_verified": true, "name": "Ada Lovelace",
        });
        c.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        c.as_object_mut().unwrap().retain(|_, v| !v.is_null());
        c
    }

    #[test]
    fn saml_bridge_takes_the_idps_name_id_under_its_entity_id_only_when_that_idp_signed_in() {
        let (p, m) = (saml_bridge(&[]), meta(BROKER));
        let c = p.claims(&signed(brokered(json!({}))), &m).unwrap();
        assert_eq!((c.issuer.as_str(), c.subject.as_str(), c.email.as_deref(), c.name.as_deref()), (ADFS, "_a1b2c3-persistent", Some("ada@example.com"), Some("Ada Lovelace")));
        assert_eq!(c.key(), format!("{ADFS}|_a1b2c3-persistent"), "not the broker's issuer or its own user id");
        let upper = p.claims(&signed(brokered(json!({ "identity_provider_identity": "G-94F0-AbC" }))), &m).unwrap();
        assert_eq!((upper.subject.as_str(), p.subject(" G-94F0-AbC ").unwrap()), ("g-94f0-abc", "g-94f0-abc".to_string()), "compared without case, at sign-in and when linking");
        for (extra, why) in [
            (json!({ "identity_provider": null, "identity_provider_identity": null }), "a password login at the broker"),
            (json!({ "identity_provider": null }), "no claim naming the IdP"),
            (json!({ "identity_provider": "github" }), "another IdP the broker knows"),
            (json!({ "identity_provider": "ADFS" }), "aliases are compared exactly"),
            (json!({ "identity_provider": ["adfs"] }), "not a string"),
            (json!({ "identity_provider": "" }), "empty"),
        ] {
            assert_eq!(p.claims(&signed(brokered(extra)), &m).err(), Some(Invalid("not_brokered")), "{why}");
        }
        assert_eq!(p.claims(&signed(brokered(json!({ "identity_provider_identity": null }))), &m).err(), Some(Invalid("missing_subject")), "the broker's sub is not the person at the IdP");
        assert_eq!(p.claims(&signed(brokered(json!({ "identity_provider_identity": "x".repeat(256) }))), &m).err(), Some(Invalid("missing_subject")));
        for padded in ["", " ", " g-1", "g-1 ", "\tg-1"] {
            assert_eq!(p.claims(&signed(brokered(json!({ "identity_provider_identity": padded }))), &m).err(), Some(Invalid("missing_subject")), "{padded:?} could never be linked");
        }
        for iss in ["https://sso.example.com/realms/other", "https://sso.example.com/realms/superbot/", ADFS] {
            assert_eq!(p.claims(&signed(brokered(json!({ "iss": iss }))), &m).err(), Some(Invalid("wrong_issuer")), "{iss}");
        }
        assert_eq!(p.claims(&signed(brokered(json!({}))), &meta("https://evil.example")).err(), Some(Invalid("wrong_issuer")), "discovery from elsewhere");
        assert_eq!(p.claims(&signed(brokered(json!({ "email_verified": false }))), &m).unwrap().email, None, "an unverified email is dropped");
    }

    #[test]
    fn saml_bridge_email_domains_need_a_verified_email() {
        let (p, m) = (saml_bridge(&["example.com"]), meta(BROKER));
        assert!(p.claims(&signed(brokered(json!({}))), &m).is_ok());
        assert_eq!(p.claims(&signed(brokered(json!({ "email": "ada@evil.example" }))), &m).err(), Some(Invalid("wrong_domain")));
        assert_eq!(p.claims(&signed(brokered(json!({ "email_verified": false }))), &m).err(), Some(Invalid("email_unverified")));
        assert_eq!(p.claims(&signed(brokered(json!({ "identity_provider": "github" }))), &m).err(), Some(Invalid("not_brokered")), "checked before the email");
    }

    /// The whole check of the broker's answer, as `sign_in` runs it. The SAML assertion's
    /// own checks (XML signature, audience, recipient, NotOnOrAfter, InResponseTo, replay)
    /// are the broker's; these are the same properties on the hop botd verifies.
    #[test]
    fn saml_bridge_tokens_pass_the_shared_checks_too() {
        use crate::sso::jwt::Jwks;
        let p = saml_bridge(&[]);
        let [k1, k2] = keys();
        let set = Jwks::parse(&crate::sso::jwt::test_keys::jwks(&[k1])).unwrap();
        let now = 1_800_000_000;
        let (nonce, other) = (crate::random_hex(16), crate::random_hex(16));
        let claims = |extra: Value| {
            let mut c = json!({ "aud": "client-1", "azp": "client-1", "nonce": nonce, "iat": now, "exp": now + 300 });
            c.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            brokered(c)
        };
        let run = |token: String| {
            let t = jwt::decode(&token)?;
            t.verify(&set)?;
            t.check("client-1", &nonce, now)?;
            p.claims(&t, &meta(BROKER))
        };
        assert!(run(k1.sign(&claims(json!({})))).is_ok());

        let forged = k2.sign_with(&json!({ "alg": "RS256", "kid": "k1" }), &claims(json!({})));
        assert_eq!(run(forged).err(), Some(Invalid("bad_signature")), "signed by someone else");
        let good = k1.sign(&claims(json!({})));
        let (head, rest) = good.split_once('.').unwrap();
        let sig = rest.split_once('.').unwrap().1;
        let swapped = format!("{head}.{}.{sig}", B64.encode(claims(json!({ "identity_provider_identity": "_someone-else" })).to_string()));
        assert_eq!(run(swapped).err(), Some(Invalid("bad_signature")), "the person swapped under a good signature");
        assert_eq!(run(k2.sign(&claims(json!({})))).err(), Some(Invalid("unknown_key")));
        assert_eq!(run(k1.sign(&claims(json!({ "aud": "another-app", "azp": "another-app" })))).err(), Some(Invalid("wrong_audience")));
        assert_eq!(run(k1.sign(&claims(json!({ "aud": ["client-1", "another-app"], "azp": "another-app" })))).err(), Some(Invalid("wrong_audience")));
        assert_eq!(run(k1.sign(&claims(json!({ "iat": now - 3600, "exp": now - 600 })))).err(), Some(Invalid("expired")));
        assert_eq!(run(k1.sign(&claims(json!({ "iat": now + 3600, "exp": now + 7200 })))).err(), Some(Invalid("not_yet_valid")));
        assert_eq!(run(k1.sign(&claims(json!({ "nonce": other })))).err(), Some(Invalid("nonce_mismatch")), "an answer to another sign-in (SAML's InResponseTo)");
        assert_eq!(run(k1.sign(&claims(json!({ "nonce": null })))).err(), Some(Invalid("nonce_mismatch")), "unsolicited (IdP-initiated)");
        assert_eq!(run(k1.sign_with(&json!({ "alg": "none" }), &claims(json!({})))).err(), Some(Invalid("bad_algorithm")));
    }

    #[tokio::test]
    async fn a_down_idp_is_retried_once_per_gap_not_once_per_sign_in() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let app = axum::Router::new().fallback(move || {
            h.fetch_add(1, Ordering::SeqCst);
            async { axum::http::StatusCode::SERVICE_UNAVAILABLE }
        });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let p = Provider::new("acme", "Acme", Kind::oidc(&base), "client-1", "openid", None);
        let http = reqwest::Client::new();
        let gap = Duration::from_secs(60);
        for _ in 0..3 {
            assert_eq!(p.metadata(&http, gap).await.err(), Some(Invalid("idp_bad_response")));
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let m = Metadata { jwks_uri: format!("{base}/keys"), ..meta(&base) };
        for _ in 0..3 {
            assert_eq!(p.keys(&http, &m, Some("k1"), gap).await.err(), Some(Invalid("idp_bad_response")));
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(p.metadata(&http, Duration::ZERO).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 3, "retried once the gap has passed");
    }

    #[test]
    fn urls_and_ids() {
        assert!(secure_url("https://login.example/x") && secure_url("http://127.0.0.1:9/x"));
        assert!(!secure_url("http://idp.example/x") && !secure_url("file:///etc/passwd") && !secure_url("nope"));
        assert_eq!(guid(&T1.to_uppercase()).as_deref(), Some(T1));
        assert!(guid("contoso.onmicrosoft.com").is_none() && guid("1111111-1111-1111-1111-1111111111111").is_none());
        assert_eq!(domain(" Example.COM. ").as_deref(), Some("example.com"));
        for bad in ["localhost", "a@example.com", "-x.example", "exa mple.com", "*.example.com", "", "example..com"] {
            assert!(domain(bad).is_none(), "{bad}");
        }
    }
}
