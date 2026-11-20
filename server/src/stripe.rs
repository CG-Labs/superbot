//! The Stripe API calls botd makes (ADR 0041): opening, reading, and expiring a Checkout
//! Session, and opening a Billing Portal session, with the secret key, an idempotency key
//! on every POST, and a timeout. Nothing here spends money: Stripe charges only when the
//! person completes the page it returns.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const API: &str = "https://api.stripe.com";
/// Pinned so the fields botd reads don't move under it when the account's default changes.
pub const VERSION: &str = "2025-09-30.clover";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(20);
/// Calls with the same user, parameters, and minute share an idempotency key, so a double
/// click gets the same session back instead of a second one.
const IDEMPOTENCY_WINDOW_MS: i64 = 60_000;

pub struct Stripe {
    key: String,
    base: String,
    http: reqwest::Client,
}

/// What went wrong, without anything Stripe sent back but its error type and code.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// No answer, or one that wasn't JSON.
    Unreachable,
    Refused { status: u16, kind: Option<String>, code: Option<String> },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unreachable => write!(f, "no answer from Stripe"),
            Error::Refused { status, kind, code } => {
                write!(f, "HTTP {status}")?;
                for v in [kind, code].into_iter().flatten() {
                    write!(f, " {v}")?;
                }
                Ok(())
            }
        }
    }
}

impl Stripe {
    /// `base` is Stripe's API; tests point it at a fake on loopback, the only place the
    /// key may go without TLS.
    pub fn new(key: &str, base: &str) -> Stripe {
        let loopback = url::Url::parse(base).ok().is_some_and(|u| matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")));
        let http = reqwest::Client::builder().https_only(!loopback).connect_timeout(CONNECT_TIMEOUT).timeout(TIMEOUT).build().expect("HTTP client");
        Stripe { key: key.into(), base: base.trim_end_matches('/').into(), http }
    }

    /// POSTs `form` to `path` (`/v1/...`). Retried once, with the same idempotency key, when
    /// Stripe doesn't answer or answers 429 or 5xx, as Stripe's own libraries do.
    pub async fn post(&self, path: &str, form: &[(String, String)], idempotency_key: &str) -> Result<Value, Error> {
        self.send(path, Some((form, idempotency_key))).await
    }

    /// GETs `path`, retried like `post`.
    pub async fn get(&self, path: &str) -> Result<Value, Error> {
        self.send(path, None).await
    }

    async fn send(&self, path: &str, post: Option<(&[(String, String)], &str)>) -> Result<Value, Error> {
        let mut last = Error::Unreachable;
        for attempt in 0..2 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let url = format!("{}{path}", self.base);
            let req = match post {
                Some((form, key)) => self.http.post(url).header("Idempotency-Key", key).form(form),
                None => self.http.get(url),
            };
            let sent = req.bearer_auth(&self.key).header("Stripe-Version", VERSION).send().await;
            let Ok(res) = sent else {
                last = Error::Unreachable;
                continue;
            };
            let status = res.status().as_u16();
            let Ok(body) = res.json::<Value>().await else {
                last = Error::Unreachable;
                continue;
            };
            if (200..300).contains(&status) {
                return Ok(body);
            }
            let e = &body["error"];
            last = Error::Refused { status, kind: e["type"].as_str().map(String::from), code: e["code"].as_str().map(String::from) };
            if status != 429 && status < 500 {
                break;
            }
        }
        Err(last)
    }
}

/// An idempotency key for one action by one user with these parameters at `now_ms`:
/// the same within a minute, so a retried or double-clicked request makes one session,
/// and never the same for different parameters, which Stripe would refuse.
pub fn idempotency_key(action: &str, user: &str, form: &[(String, String)], now_ms: i64) -> String {
    let mut h = Sha256::new();
    for part in [action, user, &(now_ms / IDEMPOTENCY_WINDOW_MS).to_string()] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    for (k, v) in form {
        h.update(k.as_bytes());
        h.update([0]);
        h.update(v.as_bytes());
        h.update([0]);
    }
    let hex: String = h.finalize().iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!("superbot-{action}-{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn idempotency_keys_repeat_only_for_the_same_request_in_the_same_minute() {
        let f = form(&[("customer", "cus_1")]);
        let t = 1_800_000_000_000;
        let k = idempotency_key("portal", "u1", &f, t);
        assert!(k.starts_with("superbot-portal-") && k.len() == "superbot-portal-".len() + 32, "{k}");
        assert_eq!(k, idempotency_key("portal", "u1", &f, t + 59_999 - t % 60_000));
        assert_ne!(k, idempotency_key("portal", "u1", &f, t + 60_000));
        assert_ne!(k, idempotency_key("portal", "u2", &f, t));
        assert_ne!(k, idempotency_key("checkout", "u1", &f, t));
        assert_ne!(k, idempotency_key("portal", "u1", &form(&[("customer", "cus_2")]), t));
        // Field boundaries count: ("ab", "c") isn't ("a", "bc").
        assert_ne!(idempotency_key("x", "u", &form(&[("ab", "c")]), t), idempotency_key("x", "u", &form(&[("a", "bc")]), t));
    }

    #[tokio::test]
    async fn the_key_goes_over_plain_http_only_to_loopback() {
        // Nothing listens on 192.0.2.1 (TEST-NET-1): refused before connecting, so this
        // doesn't wait for a connect timeout.
        let s = Stripe::new("sk_test_x", "http://192.0.2.1");
        let started = std::time::Instant::now();
        assert_eq!(s.get("/v1/checkout/sessions/cs_1").await, Err(Error::Unreachable));
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    }

    #[test]
    fn errors_say_only_the_status_type_and_code() {
        let e = Error::Refused { status: 400, kind: Some("invalid_request_error".into()), code: Some("resource_missing".into()) };
        assert_eq!(e.to_string(), "HTTP 400 invalid_request_error resource_missing");
        assert_eq!(Error::Refused { status: 503, kind: None, code: None }.to_string(), "HTTP 503");
    }
}
