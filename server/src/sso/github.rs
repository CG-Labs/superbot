//! GitHub sign-in (ADR 0018). GitHub is OAuth 2, not OpenID Connect: there is no ID
//! token to verify. botd trades the code (with its PKCE verifier and client secret) for
//! an access token, asks GitHub's API who that is over TLS, then revokes the token.

use super::jwt::Invalid;
use super::provider::{Claims, read_json};
use serde_json::{Value, json};

pub const URL: &str = "https://github.com";
pub const API: &str = "https://api.github.com";
/// The scopes the checks below need: the profile, the email list, and org membership.
pub const SCOPE_EMAIL: &str = "user:email";
pub const SCOPE_ORGS: &str = "read:org";
const EMAILS_PER_PAGE: usize = 100;
/// GitHub caps an account's addresses well below this.
const EMAIL_PAGES: usize = 10;

/// The API next to a GitHub address: github.com's own, or GitHub Enterprise Server's `/api/v3`.
pub fn api_for(web: &str) -> String {
    if web == URL { API.into() } else { format!("{web}/api/v3") }
}

/// An organization's login as GitHub allows it, lowercase (GitHub compares them that way).
pub fn org(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    let ok = (1..=39).contains(&s.len()) && !s.starts_with('-') && !s.ends_with('-') && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    ok.then_some(s)
}

/// A GitHub user id: digits. The login is not the subject: people can rename themselves,
/// and someone else can then take the old login.
pub fn user_id(s: &str) -> Option<String> {
    let s = s.trim();
    ((1..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) && !s.starts_with('0')).then(|| s.to_string())
}

pub struct GitHub<'a> {
    pub web: &'a str,
    pub api: &'a str,
    pub client_id: &'a str,
    pub allowed_orgs: &'a [String],
}

impl GitHub<'_> {
    pub async fn sign_in(&self, http: &reqwest::Client, code: &str, redirect_uri: &str, verifier: &str, secret: &str) -> Result<Claims, Invalid> {
        let form = [("client_id", self.client_id), ("client_secret", secret), ("code", code), ("redirect_uri", redirect_uri), ("code_verifier", verifier)];
        let res = http.post(format!("{}/login/oauth/access_token", self.web)).header("accept", "application/json").form(&form).send().await.map_err(|_| Invalid("idp_unreachable"))?;
        // Errors come back as 200 with an `error` field.
        let token = match read_json(res).await? {
            (200, v) if v["token_type"].as_str().is_some_and(|t| t.eq_ignore_ascii_case("bearer")) => v["access_token"].as_str().filter(|t| !t.is_empty() && t.len() <= 4096).map(String::from),
            _ => None,
        };
        let token = token.ok_or(Invalid("code_exchange_failed"))?;
        let claims = self.who(http, &token).await;
        self.revoke(http, token, secret);
        claims
    }

    async fn get(&self, http: &reqwest::Client, token: &str, path: &str) -> Result<(u16, Value), Invalid> {
        let res = http
            .get(format!("{}{path}", self.api))
            .bearer_auth(token)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .send()
            .await
            .map_err(|_| Invalid("idp_unreachable"))?;
        read_json(res).await
    }

    async fn who(&self, http: &reqwest::Client, token: &str) -> Result<Claims, Invalid> {
        let user = match self.get(http, token, "/user").await? {
            (200, v) => v,
            _ => return Err(Invalid("idp_bad_response")),
        };
        let subject = user["id"].as_u64().filter(|id| *id > 0).ok_or(Invalid("missing_subject"))?.to_string();
        let login = user["login"].as_str().map(|l| crate::audit::clip(l, 39));
        let email = self.primary_email(http, token).await?.ok_or(Invalid("email_unverified"))?;
        if !self.allowed_orgs.is_empty() && !self.in_allowed_org(http, token).await? {
            return Err(Invalid("wrong_org"));
        }
        let name = user["name"].as_str().map(|n| crate::audit::clip(n.trim(), 100)).filter(|n| !n.is_empty()).or_else(|| login.clone());
        Ok(Claims { issuer: self.web.to_string(), subject, tenant: None, email: Some(email), name, username: login, authn_context: None, encryption: None, response_binding: None, subject_from: None, assurance: vec![] })
    }

    /// The primary address, only if verified: GitHub lets people add any address
    /// unverified. The list is paged, and the primary needn't be on the first page.
    async fn primary_email(&self, http: &reqwest::Client, token: &str) -> Result<Option<String>, Invalid> {
        for page in 1..=EMAIL_PAGES {
            let list = match self.get(http, token, &format!("/user/emails?per_page={EMAILS_PER_PAGE}&page={page}")).await? {
                (200, Value::Array(list)) => list,
                // No user:email scope (or a GitHub App without the email permission).
                (403 | 404, _) => return Ok(None),
                _ => return Err(Invalid("idp_bad_response")),
            };
            if let Some(e) = list.iter().find(|e| e["primary"] == json!(true)) {
                let verified = e["verified"] == json!(true);
                return Ok(e["email"].as_str().map(|e| e.trim().to_string()).filter(|e| verified && crate::users::valid_email(e)));
            }
            if list.len() < EMAILS_PER_PAGE {
                break;
            }
        }
        Ok(None)
    }

    /// An active member of one of the allowed organizations. Pending invitations don't
    /// count. GitHub answers 404 (or 403 when the organization restricts OAuth apps it
    /// hasn't approved) for anyone it won't vouch for.
    async fn in_allowed_org(&self, http: &reqwest::Client, token: &str) -> Result<bool, Invalid> {
        for org in self.allowed_orgs {
            match self.get(http, token, &format!("/user/memberships/orgs/{org}")).await? {
                (200, v) if v["state"] == "active" && v["organization"]["login"].as_str().is_some_and(|l| l.eq_ignore_ascii_case(org)) => return Ok(true),
                (200 | 403 | 404, _) => {}
                _ => return Err(Invalid("idp_bad_response")),
            }
        }
        Ok(false)
    }

    /// botd needs the token for one sign-in only, so it doesn't leave it valid. Best
    /// effort, in the background: sign-in doesn't wait for it.
    fn revoke(&self, http: &reqwest::Client, token: String, secret: &str) {
        let (http, url, id, secret) = (http.clone(), format!("{}/applications/{}/token", self.api, self.client_id), self.client_id.to_string(), crate::secrets::Secret::new(secret));
        tokio::spawn(async move {
            let req = http.delete(url).basic_auth(id, Some(secret.expose())).header("accept", "application/vnd.github+json").json(&json!({ "access_token": token }));
            let _ = req.send().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_orgs_and_enterprise_addresses() {
        assert_eq!(user_id(" 583231 ").as_deref(), Some("583231"));
        for bad in ["", "octocat", "-1", "0", "012", "1".repeat(21).as_str()] {
            assert!(user_id(bad).is_none(), "{bad}");
        }
        assert_eq!(org(" CG-Labs ").as_deref(), Some("cg-labs"));
        for bad in ["", "-acme", "acme-", "ac me", "acme/x", &"a".repeat(40)] {
            assert!(org(bad).is_none(), "{bad}");
        }
        assert_eq!(api_for(URL), API);
        assert_eq!(api_for("https://github.example.com"), "https://github.example.com/api/v3");
    }
}
