//! What the external secrets clients share (ADR 0125, ADR 0136): a small runtime of
//! their own that requests run on, so a store read from inside botd's async code never
//! blocks on a runtime it is part of; an HTTP client that never follows redirects, so a
//! token is never sent anywhere else; bearer tokens renewed before they lapse; and
//! sign-in events for the audit log.

use super::external;
use super::Error;
use crate::audit::{Event, Outcome};
use serde_json::{json, Value};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);
/// Longest a caller waits for its turn, then for its answer: a sign-in and a retried request.
const WAIT: Duration = Duration::from_secs(35);
/// Requests to the backend at once; more wait for a permit.
pub(crate) const MAX_REQUESTS: usize = 8;

/// Runs a client's requests on a runtime of its own, up to `MAX_REQUESTS` at once.
pub(crate) struct Worker {
    label: &'static str,
    /// Botd's own runtime can't be blocked on from inside, so requests run on this one.
    rt: Option<tokio::runtime::Runtime>,
    permits: Arc<tokio::sync::Semaphore>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Dropping a runtime blocks, which panics inside another runtime's tasks.
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

impl Worker {
    /// `label` names the backend in errors and the threads' names: "Vault", ...
    pub fn new(label: &'static str, thread: &'static str) -> Result<Worker, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name(thread)
            .enable_all()
            .build()
            .map_err(|e| format!("{label} client: {e}"))?;
        Ok(Worker { label, rt: Some(rt), permits: Arc::new(tokio::sync::Semaphore::new(MAX_REQUESTS)) })
    }

    /// Runs `job` and waits for it. A caller that gives up drops its receiver, and a job
    /// not yet started is skipped.
    pub fn run<T, Fut>(&self, job: Fut) -> Result<T, Error>
    where
        T: Send + 'static,
        Fut: std::future::Future<Output = Result<T, Error>> + Send + 'static,
    {
        // None says the request started; then its answer.
        let (tx, rx) = mpsc::channel::<Option<Result<T, Error>>>();
        let permits = Arc::clone(&self.permits);
        let rt = self.rt.as_ref().ok_or_else(|| Error::Unavailable(format!("{}: the client stopped", self.label)))?;
        rt.spawn(async move {
            let Ok(_permit) = permits.acquire_owned().await else { return };
            // Whoever asked has stopped waiting: don't spend a request on it.
            if tx.send(None).is_err() {
                return;
            }
            let _ = tx.send(Some(job.await));
        });
        let wait = || -> Option<Result<T, Error>> {
            rx.recv_timeout(WAIT).ok()?;
            rx.recv_timeout(WAIT).ok().flatten()
        };
        // On one of botd's runtime workers, hand its other tasks to another worker while
        // this waits, so a slow backend never stalls requests, heartbeats or timers.
        let multi = tokio::runtime::Handle::try_current().is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
        let got = if multi { tokio::task::block_in_place(wait) } else { wait() };
        got.unwrap_or_else(|| Err(Error::Unavailable(format!("{}: no answer in time", self.label))))
    }
}

/// An HTTP client for a backend: rustls, timeouts, no redirects. `ca` is the PEM of a
/// private CA, named by `ca_setting` in errors. Instance metadata endpoints are on the
/// link-local network and must never go through a proxy (`direct`).
pub(crate) fn client(label: &str, ca: Option<(&str, &str)>, direct: bool) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder().connect_timeout(CONNECT_TIMEOUT).timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none());
    if let Some((setting, pem)) = ca {
        let c = reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|e| format!("{setting}: {e}"))?;
        b = b.tls_certs_merge([c]);
    }
    if direct {
        b = b.no_proxy();
    }
    b.build().map_err(|e| format!("{label} client: {e}"))
}

/// A base URL setting: `https://host[:port]` (plain `http://` only to this computer),
/// with no path, query or credentials. No trailing slash.
pub(crate) fn base_url(key: &str, raw: &str, example: &str) -> Result<String, String> {
    let raw = raw.trim();
    let url = url::Url::parse(raw).map_err(|e| format!("{key} {raw:?}: {e}, e.g. {example}"))?;
    if !crate::tiers::encrypted_or_loopback(&url) {
        return Err(format!("{key} must use https://: plain http:// would send tokens and secrets unencrypted, so it is allowed only to this computer (localhost, 127.0.0.0/8, ::1)"));
    }
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
        return Err(format!("{key} must be just the scheme, host and port, like {example}, not {raw:?}"));
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// `base` with `query` encoded onto it.
pub(crate) fn with_query(base: &str, query: &[(&str, &str)]) -> Result<url::Url, Error> {
    url::Url::parse_with_params(base, query).map_err(|e| Error::Unavailable(format!("{base}: {e}")))
}

/// A bearer token and when to get a new one.
pub(crate) struct Bearer {
    pub value: Zeroizing<String>,
    pub renew_at: Option<Instant>,
}

impl Bearer {
    /// A token that lasts `lifetime` seconds is renewed two thirds of the way through,
    /// so it never lapses mid-run. Unknown lifetimes are renewed after five minutes.
    pub fn new(value: &str, lifetime: Option<u64>) -> Bearer {
        let secs = lifetime.filter(|s| *s > 0).unwrap_or(300);
        Bearer { value: Zeroizing::new(value.to_string()), renew_at: Some(Instant::now() + Duration::from_secs(secs) * 2 / 3) }
    }

    pub fn fresh(&self) -> bool {
        self.renew_at.is_none_or(|at| Instant::now() < at)
    }
}

/// A number of seconds sent as a number or a string, as token endpoints do.
pub(crate) fn seconds(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// The short error code in a JSON error reply (`invalid_client`, `SecretNotFound`,
/// `PERMISSION_DENIED`, ...), safe to log: letters, digits, `_`, `.` and `-` only, and
/// never the description, which could quote what was sent.
pub(crate) fn error_code(body: &[u8]) -> String {
    let v: Value = serde_json::from_slice(body).unwrap_or_default();
    let code = [&v["error"]["code"], &v["error"]["status"], &v["error"]]
        .into_iter()
        .find_map(Value::as_str)
        .filter(|c| !c.is_empty() && c.len() <= 64 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)));
    code.map(|c| format!(" ({c})")).unwrap_or_default()
}

/// Audits a sign-in to a backend: `secret.backend_login`, with the method, never a credential.
pub(crate) fn audit_login<T>(store: &str, method: &str, result: &Result<T, Error>) {
    let e = Event::new(external::actor(), "secret.backend_login").target("secrets_backend", store);
    external::audit(match result {
        Ok(_) => e.details(json!({ "store": store, "method": method })),
        Err(err) => e.outcome(Outcome::Failure).details(json!({ "store": store, "method": method, "error": err.kind() })),
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Settings from pairs, as `from_env` reads them.
    pub(crate) fn settings(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String + use<> {
        let map: std::collections::HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| map.get(k).cloned().unwrap_or_default()
    }

    /// Starts `app` on its own thread and runtime; returns its address.
    pub(crate) fn serve(app: axum::Router) -> String {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                tx.send(format!("http://{}", listener.local_addr().unwrap())).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        rx.recv().unwrap()
    }

    #[test]
    fn base_urls_are_checked() {
        assert_eq!(base_url("X", "https://kv.example.com/", "e").unwrap(), "https://kv.example.com");
        assert_eq!(base_url("X", "http://127.0.0.1:8080", "e").unwrap(), "http://127.0.0.1:8080");
        for (bad, err) in [("http://kv.example.com", "must use https"), ("https://u:p@kv.example.com", "just the scheme"), ("https://kv.example.com/x", "just the scheme"), ("kv", "X \"kv\"")] {
            let e = base_url("X", bad, "e").unwrap_err();
            assert!(e.contains(err), "{bad}: {e}");
        }
    }

    #[test]
    fn error_codes_never_carry_descriptions() {
        assert_eq!(error_code(br#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided. s3cr3t"}"#), " (invalid_client)");
        assert_eq!(error_code(br#"{"error":{"code":"Forbidden","message":"Caller is not authorized"}}"#), " (Forbidden)");
        assert_eq!(error_code(br#"{"error":{"code":403,"status":"PERMISSION_DENIED","message":"x"}}"#), " (PERMISSION_DENIED)");
        assert_eq!(error_code(br#"{"error":"has spaces in it"}"#), "");
        assert_eq!(error_code(b"<html>"), "");
    }

    #[test]
    fn tokens_renew_two_thirds_through() {
        assert!(Bearer::new("t", Some(3600)).fresh());
        assert!(!Bearer { value: Zeroizing::new("t".into()), renew_at: Some(Instant::now() - Duration::from_secs(1)) }.fresh());
        assert_eq!((seconds(&json!(60)), seconds(&json!("86399")), seconds(&json!("x"))), (Some(60), Some(86399), None));
    }
}
