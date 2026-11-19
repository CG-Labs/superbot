//! One configured IdP: where it lives, its cached discovery document and keys, the code
//! exchange, and whose tokens it accepts.

use super::jwt::{self, Invalid, Jwks, Token};
use crate::rbac::Role;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};

const META_TTL: Duration = Duration::from_secs(24 * 3600);
const JWKS_TTL: Duration = Duration::from_secs(3600);
/// Discovery documents and key sets are small; this bounds what a broken IdP can send.
const MAX_BODY: usize = 1024 * 1024;

pub const ENTRA_AUTHORITY: &str = "https://login.microsoftonline.com";

pub enum Kind {
    /// Microsoft Entra ID. Tokens come from one tenant's issuer, `{authority}/{tid}/v2.0`.
    /// `tenant` is a tenant id, or `organizations`/`common` with an `allowed` list.
    Entra { authority: String, tenant: String, allowed: Vec<String> },
    /// Any OpenID Connect provider with one issuer.
    Oidc { issuer: String },
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
}

#[derive(Default)]
struct Cache {
    meta: Option<(Arc<Metadata>, Instant)>,
    jwks: Option<(Arc<Jwks>, Instant)>,
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

/// https, or http to this machine (a local IdP in development and tests).
pub fn secure_url(u: &str) -> bool {
    match reqwest::Url::parse(u) {
        Ok(u) if u.scheme() == "https" => u.host_str().is_some(),
        Ok(u) if u.scheme() == "http" => matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
        _ => false,
    }
}

async fn read_json(res: reqwest::Response) -> Result<(u16, Value), Invalid> {
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

impl Provider {
    pub fn new(id: &str, label: &str, kind: Kind, client_id: &str, scopes: &str, jit_role: Option<Role>) -> Provider {
        Provider { id: id.into(), label: label.into(), kind, client_id: client_id.into(), scopes: scopes.into(), jit_role, cache: Default::default() }
    }

    pub fn type_name(&self) -> &'static str {
        match self.kind {
            Kind::Entra { .. } => "entra",
            Kind::Oidc { .. } => "oidc",
        }
    }

    pub fn secret_name(&self) -> String {
        format!("SSO_{}_CLIENT_SECRET", self.id.to_ascii_uppercase())
    }

    /// Read when used, so `botctl secret set` takes effect without a restart.
    fn client_secret(&self) -> Option<crate::secrets::Secret> {
        let s = crate::secrets::global().get(&self.secret_name()).ok().flatten()?;
        crate::secrets::redact::register(s.expose());
        Some(s)
    }

    /// Offered on the sign-in page: it has its client secret.
    pub fn ready(&self) -> bool {
        self.client_secret().is_some()
    }

    fn discovery_url(&self) -> String {
        match &self.kind {
            Kind::Entra { authority, tenant, .. } => format!("{authority}/{tenant}/v2.0/.well-known/openid-configuration"),
            Kind::Oidc { issuer } => format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/')),
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
            Kind::Oidc { issuer } if tenant.is_none() => Ok((issuer.clone(), None)),
            Kind::Oidc { .. } => Err("tenant is only for Entra providers".into()),
        }
    }

    /// The subject as tokens carry it: Entra object ids are lowercase GUIDs.
    pub fn subject(&self, s: &str) -> Result<String, String> {
        let s = s.trim();
        match self.kind {
            Kind::Entra { .. } => guid(s).ok_or_else(|| "subject must be the user's Entra object id (a GUID)".into()),
            Kind::Oidc { .. } if !s.is_empty() && s.len() <= 255 => Ok(s.into()),
            Kind::Oidc { .. } => Err("subject must be 1 to 255 characters".into()),
        }
    }

    pub async fn metadata(&self, http: &reqwest::Client) -> Result<Arc<Metadata>, Invalid> {
        let mut c = self.cache.lock().await;
        if let Some((m, at)) = &c.meta
            && at.elapsed() < META_TTL
        {
            return Ok(m.clone());
        }
        match self.fetch_metadata(http).await {
            Ok(m) => {
                let m = Arc::new(m);
                c.meta = Some((m.clone(), Instant::now()));
                Ok(m)
            }
            // An IdP outage shouldn't sign everyone out of SSO: keep using what we had.
            Err(e) => c.meta.as_ref().map(|(m, _)| m.clone()).ok_or(e),
        }
    }

    async fn fetch_metadata(&self, http: &reqwest::Client) -> Result<Metadata, Invalid> {
        let v = get_json(http, &self.discovery_url()).await?;
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
    /// rotated), at most once per `gap`.
    async fn keys(&self, http: &reqwest::Client, meta: &Metadata, kid: Option<&str>, gap: Duration) -> Result<Arc<Jwks>, Invalid> {
        let mut c = self.cache.lock().await;
        if let Some((k, at)) = &c.jwks {
            let fresh = at.elapsed() < JWKS_TTL && k.has(kid);
            if fresh || at.elapsed() < gap {
                return Ok(k.clone());
            }
        }
        match get_json(http, &meta.jwks_uri).await.and_then(|v| Jwks::parse(&v)) {
            Ok(k) => {
                let k = Arc::new(k);
                c.jwks = Some((k.clone(), Instant::now()));
                Ok(k)
            }
            Err(e) => c.jwks.as_ref().map(|(k, _)| k.clone()).ok_or(e),
        }
    }

    /// Trades the authorization code for an ID token (with our PKCE verifier) and checks it.
    pub async fn sign_in(&self, http: &reqwest::Client, code: &str, redirect_uri: &str, verifier: &str, nonce: &str, gap: Duration) -> Result<Claims, Invalid> {
        let meta = self.metadata(http).await?;
        let secret = self.client_secret().ok_or(Invalid("not_configured"))?;
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
        let name = t.str("name").map(|n| crate::audit::clip(n.trim(), 100)).filter(|n| !n.is_empty());
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
                // Entra's `email` is informational only (it isn't verified), so we never look anyone up by it.
                Ok(Claims { issuer: iss.into(), subject: oid, tenant: Some(tid), email: t.str("email").map(String::from), name })
            }
            Kind::Oidc { issuer } => {
                if iss != issuer || iss != meta.issuer {
                    return Err(Invalid("wrong_issuer"));
                }
                let sub = t.str("sub").filter(|s| s.len() <= 255).ok_or(Invalid("missing_subject"))?;
                let verified = t.claims.get("email_verified").and_then(Value::as_bool) == Some(true);
                Ok(Claims { issuer: iss.into(), subject: sub.into(), tenant: None, email: t.str("email").filter(|_| verified).map(String::from), name })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sso::jwt::test_keys::keys;
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
        let p = Provider::new("acme", "Acme", Kind::Oidc { issuer: "https://idp.example".into() }, "client-1", "openid", None);
        let m = meta("https://idp.example");
        let t = |c: Value| jwt::decode(&keys()[0].sign(&c)).unwrap();
        let c = p.claims(&t(json!({ "iss": "https://idp.example", "sub": "s1", "email": "a@example.com" })), &m).unwrap();
        assert_eq!((c.subject.as_str(), c.email), ("s1", None));
        let c = p.claims(&t(json!({ "iss": "https://idp.example", "sub": "s1", "email": "a@example.com", "email_verified": true })), &m).unwrap();
        assert_eq!(c.email.as_deref(), Some("a@example.com"));
        assert_eq!(p.claims(&t(json!({ "iss": "https://other.example", "sub": "s1" })), &m).err(), Some(Invalid("wrong_issuer")));
        assert_eq!(p.claims(&t(json!({ "iss": "https://idp.example" })), &m).err(), Some(Invalid("missing_subject")));
    }

    #[test]
    fn urls_and_ids() {
        assert!(secure_url("https://login.example/x") && secure_url("http://127.0.0.1:9/x"));
        assert!(!secure_url("http://idp.example/x") && !secure_url("file:///etc/passwd") && !secure_url("nope"));
        assert_eq!(guid(&T1.to_uppercase()).as_deref(), Some(T1));
        assert!(guid("contoso.onmicrosoft.com").is_none() && guid("1111111-1111-1111-1111-1111111111111").is_none());
    }
}
