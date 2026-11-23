//! The GitHub REST API, read only: GET requests with the operator's token, pages followed
//! by their `Link` headers (only on the API's own host, so the token never goes anywhere
//! else), rate limits waited out up to a limit, and server errors retried.

use reqwest::header::{ACCEPT, HeaderMap, LINK, USER_AGENT};
use serde_json::Value;
use std::time::Duration;

pub const DEFAULT_API: &str = "https://api.github.com";
const RETRIES: u32 = 3;
/// The longest a rate limit is waited out before giving up: GitHub's hourly window.
const MAX_WAIT: Duration = Duration::from_secs(65 * 60);

pub struct Reply {
    pub body: Value,
    pub next: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct Failure {
    /// The HTTP status, or 0 when there was no answer.
    pub status: u16,
    pub message: String,
}

impl Failure {
    pub fn new(status: u16, message: impl Into<String>) -> Failure {
        Failure { status, message: message.into() }
    }
}

/// What the exporter needs from GitHub; the tests answer it from fixtures.
pub trait Api {
    /// GETs `path` (`/repos/...`, relative to the API) or a `next` link it returned.
    fn get(&mut self, path: &str) -> Result<Reply, Failure>;
}

/// `GITHUB_API_URL`: `https://host[/path]` (GitHub Enterprise Server's is `/api/v3`), plain
/// `http://` only to this computer. No query, fragment or credentials; no trailing slash.
pub fn base_url(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let raw = if raw.is_empty() { DEFAULT_API } else { raw };
    let u = url::Url::parse(raw).map_err(|e| format!("GITHUB_API_URL {raw}: {e}"))?;
    let loopback = matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if !(u.scheme() == "https" || (u.scheme() == "http" && loopback)) {
        return Err(format!("GITHUB_API_URL must be https (plain http only to this computer), not {raw}"));
    }
    if !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() {
        return Err("GITHUB_API_URL takes no credentials, query or fragment: the token goes in GITHUB_TOKEN.".into());
    }
    Ok(u.as_str().trim_end_matches('/').to_string())
}

/// The `rel="next"` URL of a `Link` header.
pub fn next_link(link: &str) -> Option<String> {
    link.split(',').find(|part| part.split(';').skip(1).any(|p| p.trim() == "rel=\"next\"")).and_then(|part| {
        let part = part.trim();
        Some(part.strip_prefix('<')?.split_once('>')?.0.to_string())
    })
}

/// How long to wait before trying again after `status`, if it is a rate limit:
/// `Retry-After`, else until `X-RateLimit-Reset` once `X-RateLimit-Remaining` is 0.
pub fn rate_wait(status: u16, headers: &HeaderMap, now_secs: u64) -> Option<Duration> {
    if status != 403 && status != 429 {
        return None;
    }
    let header = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).map(str::trim);
    if let Some(s) = header("retry-after").and_then(|v| v.parse::<u64>().ok()) {
        return Some(Duration::from_secs(s));
    }
    if header("x-ratelimit-remaining") == Some("0") {
        let reset = header("x-ratelimit-reset").and_then(|v| v.parse::<u64>().ok()).unwrap_or(now_secs + 60);
        return Some(Duration::from_secs(reset.saturating_sub(now_secs).max(1)));
    }
    None
}

pub struct GitHub {
    base: String,
    token: String,
    http: reqwest::Client,
    rt: tokio::runtime::Runtime,
    pub requests: u64,
    /// A classic token's scopes (`X-OAuth-Scopes`); GitHub sends none for Actions' token.
    pub scopes: Option<String>,
}

impl GitHub {
    pub fn new(base: &str, token: &str) -> Result<GitHub, String> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
        let _in = rt.enter();
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(90))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("HTTP client: {e}"))?;
        drop(_in);
        Ok(GitHub { base: base_url(base)?, token: token.to_string(), http, rt, requests: 0, scopes: None })
    }

    pub fn host(&self) -> String {
        url::Url::parse(&self.base).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default()
    }

    fn resolve(&self, path: &str) -> Result<String, Failure> {
        if path.starts_with('/') {
            Ok(format!("{}{path}", self.base))
        } else if path.starts_with(&format!("{}/", self.base)) {
            Ok(path.to_string())
        } else {
            Err(Failure::new(0, format!("refusing to follow a link off {}: {path}", self.base)))
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

impl Api for GitHub {
    fn get(&mut self, path: &str) -> Result<Reply, Failure> {
        let url = self.resolve(path)?;
        let shown = url.strip_prefix(&self.base).unwrap_or(&url).to_string();
        let _in = self.rt.enter();
        let mut attempt = 0;
        loop {
            let req = self
                .http
                .get(&url)
                .bearer_auth(&self.token)
                .header(ACCEPT, "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header(USER_AGENT, concat!("superbot-evidence/", env!("CARGO_PKG_VERSION")));
            self.requests += 1;
            let res = match self.rt.block_on(req.send()) {
                Ok(r) => r,
                Err(e) if attempt < RETRIES => {
                    eprintln!("GitHub didn't answer {shown} ({e}); trying again.");
                    attempt += 1;
                    std::thread::sleep(Duration::from_secs(2u64.pow(attempt)));
                    continue;
                }
                Err(e) => return Err(Failure::new(0, format!("GitHub didn't answer {shown}: {e}"))),
            };
            let status = res.status().as_u16();
            let headers = res.headers().clone();
            if self.scopes.is_none() {
                self.scopes = headers.get("x-oauth-scopes").and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string());
            }
            let text = self.rt.block_on(res.text()).unwrap_or_default();
            if (200..300).contains(&status) {
                let body = serde_json::from_str(&text).map_err(|e| Failure::new(status, format!("GitHub's answer to {shown} isn't JSON: {e}")))?;
                let next = headers.get(LINK).and_then(|v| v.to_str().ok()).and_then(next_link);
                return Ok(Reply { body, next });
            }
            if attempt < RETRIES {
                if let Some(wait) = rate_wait(status, &headers, now_secs()) {
                    if wait > MAX_WAIT {
                        return Err(Failure::new(status, format!("GitHub's rate limit for {shown} lifts in {} minutes; try again later", wait.as_secs() / 60)));
                    }
                    eprintln!("GitHub's rate limit: waiting {}s before {shown}.", wait.as_secs());
                    std::thread::sleep(wait);
                    attempt += 1;
                    continue;
                }
                if status >= 500 {
                    attempt += 1;
                    std::thread::sleep(Duration::from_secs(2u64.pow(attempt)));
                    continue;
                }
            }
            let msg = serde_json::from_str::<Value>(&text).ok().and_then(|v| v["message"].as_str().map(String::from)).unwrap_or_else(|| text.chars().take(200).collect());
            return Err(Failure::new(status, format!("GitHub answered {status} for {shown}: {msg}")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn the_api_is_https_or_this_computer() {
        assert_eq!(base_url("").unwrap(), "https://api.github.com");
        assert_eq!(base_url("https://ghe.example.com/api/v3/").unwrap(), "https://ghe.example.com/api/v3");
        assert_eq!(base_url("http://127.0.0.1:8080").unwrap(), "http://127.0.0.1:8080");
        for bad in ["http://api.github.com", "ftp://x", "https://user:pw@api.github.com", "https://api.github.com/?token=x", "not a url"] {
            assert!(base_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn links_follow_only_the_api_host() {
        let gh = GitHub::new("https://ghe.example.com/api/v3", "t").unwrap();
        assert_eq!(gh.resolve("/repos/a/b").unwrap(), "https://ghe.example.com/api/v3/repos/a/b");
        assert_eq!(gh.resolve("https://ghe.example.com/api/v3/repos/a/b?page=2").unwrap(), "https://ghe.example.com/api/v3/repos/a/b?page=2");
        for off in ["https://evil.example.com/api/v3/repos", "https://ghe.example.com/api/v3x/repos", "https://ghe.example.com.evil.example/x"] {
            assert_eq!(gh.resolve(off).unwrap_err().status, 0, "{off}");
        }
        assert_eq!(gh.host(), "ghe.example.com");
    }

    #[test]
    fn next_links_and_rate_limits() {
        let link = r#"<https://api.github.com/x?page=1>; rel="prev", <https://api.github.com/x?page=3>; rel="next", <https://api.github.com/x?page=9>; rel="last""#;
        assert_eq!(next_link(link).as_deref(), Some("https://api.github.com/x?page=3"));
        assert_eq!(next_link(r#"<https://api.github.com/x?page=1>; rel="prev""#), None);
        let mut h = HeaderMap::new();
        assert_eq!(rate_wait(403, &h, 100), None, "a plain 403 is a refusal, not a rate limit");
        h.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        h.insert("x-ratelimit-reset", HeaderValue::from_static("160"));
        assert_eq!(rate_wait(403, &h, 100), Some(Duration::from_secs(60)));
        assert_eq!(rate_wait(403, &h, 500), Some(Duration::from_secs(1)), "a reset already past waits a second");
        assert_eq!(rate_wait(404, &h, 100), None);
        h.insert("retry-after", HeaderValue::from_static("7"));
        assert_eq!(rate_wait(429, &h, 100), Some(Duration::from_secs(7)));
    }
}
