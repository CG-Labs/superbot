//! Error reporting (ADR 0113): botd's panics and the 5xx answers it gives, sent to an
//! error tracker that speaks Sentry's envelope protocol (Sentry, self-hosted Sentry,
//! GlitchTip, Bugsink), off unless `ERROR_REPORT_DSN` is set.
//!
//! A report is built field by field from what botd's code defines: the kind, a route
//! template and class, a method, a status, a source location, a panic's kind from a
//! fixed list, botd's version and the request id. A panic's own message never leaves
//! (formatted panics can hold any text, a prompt included); botd's log keeps it. Every
//! string is passed through secret redaction and stripped of emails before it's sent.
//!
//! `superbot_panics_total` counts panics whether or not reports are on, and
//! `superbot_error_reports_total` counts reports sent, failed and dropped.

use super::log::{self, Level};
use super::metrics::{family, sample};
use crate::secrets::{self, SecretStore};
use serde_json::{Map, Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

pub const KINDS: [&str; 2] = ["panic", "http_5xx"];
pub const OUTCOMES: [&str; 3] = ["sent", "failed", "dropped"];
/// Reports sent in any one minute; more are dropped, so a storm of 5xx can't flood the
/// tracker or botd's outbound connections.
pub const PER_MINUTE: u32 = 20;
/// Reports waiting to be sent; more are dropped.
const QUEUE: usize = 64;
const TIMEOUT: Duration = Duration::from_secs(10);
/// The longest string a report carries.
const MAX_TEXT: usize = 200;

static PANICS: AtomicU64 = AtomicU64::new(0);
static REPORTS: [[AtomicU64; 3]; 2] = [const { [const { AtomicU64::new(0) }; 3] }; 2];
static REPORTER: RwLock<Option<Arc<Reporter>>> = RwLock::new(None);
static WINDOW: Mutex<(i64, u32)> = Mutex::new((0, 0));

#[derive(Debug, Default)]
pub struct Settings {
    pub dsn: Option<Dsn>,
    pub environment: String,
}

/// Where reports go. Its key is a secret: it never prints.
pub struct Dsn {
    endpoint: String,
    auth: secrets::Secret,
    host: String,
    loopback: bool,
}

impl std::fmt::Debug for Dsn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Dsn({})", self.host)
    }
}

impl Dsn {
    /// `https://<key>@<host>[:<port>][/<path>]/<project>`, as the tracker shows it. Plain
    /// http only to loopback.
    pub fn parse(raw: &str) -> Result<Dsn, String> {
        let bad = |why: &str| {
            format!("ERROR_REPORT_DSN must look like https://<key>@<host>/<project>: {why}")
        };
        let u = url::Url::parse(raw.trim()).map_err(|_| bad("it isn't a URL"))?;
        let host = u.host_str().ok_or_else(|| bad("no host"))?.to_string();
        let loopback = matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]");
        match u.scheme() {
            "https" => {}
            "http" if loopback => {}
            _ => return Err(bad("use https (plain http only to loopback)")),
        }
        if u.username().is_empty() {
            return Err(bad("no key before the @"));
        }
        if u.query().is_some() || u.fragment().is_some() {
            return Err(bad("no query or fragment"));
        }
        let path = u.path().trim_end_matches('/');
        let (prefix, project) = path.rsplit_once('/').ok_or_else(|| bad("no project id"))?;
        if project.is_empty()
            || !project
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(bad("no project id"));
        }
        let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
        let key = u.username().to_string();
        secrets::redact::register(&key);
        let mut auth = format!(
            "Sentry sentry_version=7, sentry_client=superbot-botd/{}, sentry_key={key}",
            env!("CARGO_PKG_VERSION")
        );
        if let Some(secret) = u.password() {
            secrets::redact::register(secret);
            auth.push_str(&format!(", sentry_secret={secret}"));
        }
        Ok(Dsn {
            endpoint: format!(
                "{}://{host}{port}{prefix}/api/{project}/envelope/",
                u.scheme()
            ),
            auth: secrets::Secret::new(auth),
            host,
            loopback,
        })
    }
}

impl Settings {
    pub fn from_env(
        get: &dyn Fn(&str) -> String,
        store: &dyn SecretStore,
    ) -> Result<Settings, String> {
        let environment = match get("ERROR_REPORT_ENVIRONMENT").trim() {
            "" => "production".to_string(),
            e if e.len() <= 64
                && e.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) =>
            {
                e.to_string()
            }
            e => {
                return Err(format!(
                    "ERROR_REPORT_ENVIRONMENT must be letters, digits, '-', '_' or '.', up to 64, not \"{e}\""
                ));
            }
        };
        let raw = store.get("ERROR_REPORT_DSN").map_err(|e| e.to_string())?;
        let dsn = match raw.as_ref().map(|s| s.expose().trim()) {
            None | Some("" | "off") => None,
            Some(v) => Some(Dsn::parse(v)?),
        };
        Ok(Settings { dsn, environment })
    }

    pub fn describe(&self) -> String {
        match &self.dsn {
            None => "error reports off (ERROR_REPORT_DSN)".into(),
            Some(d) => format!(
                "error reports to {} as {} (ERROR_REPORT_DSN)",
                d.host, self.environment
            ),
        }
    }
}

struct Reporter {
    tx: tokio::sync::mpsc::Sender<(usize, String)>,
    environment: String,
}

/// Starts sending reports, if `s` has somewhere to send them. In a Tokio runtime.
pub fn start(s: &Settings) {
    let Some(dsn) = &s.dsn else {
        *REPORTER.write().unwrap_or_else(|e| e.into_inner()) = None;
        return;
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(usize, String)>(QUEUE);
    let http = reqwest::Client::builder()
        .https_only(!dsn.loopback)
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP client");
    let (endpoint, auth) = (
        dsn.endpoint.clone(),
        secrets::Secret::new(dsn.auth.expose()),
    );
    tokio::spawn(async move {
        while let Some((kind, body)) = rx.recv().await {
            let sent = http
                .post(&endpoint)
                .header("X-Sentry-Auth", auth.expose())
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-sentry-envelope",
                )
                .body(body)
                .send()
                .await;
            match sent {
                Ok(r) if r.status().is_success() => count(kind, 0),
                Ok(r) => {
                    count(kind, 1);
                    log::line(
                        Level::Warn,
                        &format!(
                            "WARNING: the error tracker refused a report: HTTP {}",
                            r.status().as_u16()
                        ),
                    );
                }
                Err(e) => {
                    count(kind, 1);
                    let why = if e.is_timeout() {
                        "timed out"
                    } else if e.is_connect() {
                        "couldn't connect"
                    } else {
                        "failed"
                    };
                    log::line(
                        Level::Warn,
                        &format!("WARNING: sending a report to the error tracker {why}"),
                    );
                }
            }
        }
    });
    *REPORTER.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(Reporter {
        tx,
        environment: s.environment.clone(),
    }));
}

/// Tests run side by side: one that reads reports takes only those of its own requests.
#[cfg(test)]
pub static ONLY_REQUESTS: Mutex<Option<String>> = Mutex::new(None);

#[cfg(test)]
pub fn stop() {
    *REPORTER.write().unwrap_or_else(|e| e.into_inner()) = None;
}

fn count(kind: usize, outcome: usize) {
    REPORTS[kind][outcome].fetch_add(1, Ordering::Relaxed);
}

/// Queues a report, unless reports are off; dropped past `PER_MINUTE` or a full queue.
fn send(kind: usize, event: Value) {
    let reporter = REPORTER.read().unwrap_or_else(|e| e.into_inner()).clone();
    let Some(r) = reporter else { return };
    #[cfg(test)]
    {
        let only = ONLY_REQUESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if only.is_some_and(|p| {
            !event["tags"]["request_id"]
                .as_str()
                .is_some_and(|id| id.starts_with(&p))
        }) {
            return;
        }
    }
    let minute = crate::db::now().div_euclid(60_000);
    let allowed = {
        let mut w = WINDOW.lock().unwrap_or_else(|e| e.into_inner());
        if w.0 != minute {
            *w = (minute, 0);
        }
        w.1 += 1;
        w.1 <= PER_MINUTE
    };
    if !allowed {
        return count(kind, 2);
    }
    let body = envelope(event, &r.environment);
    if r.tx.try_send((kind, body)).is_err() {
        count(kind, 2);
    }
}

/// A 5xx botd answered: what route, never what was asked or answered.
pub fn http_error(method: &str, route: Option<&str>, class: &str, status: u16, request_id: &str) {
    if REPORTER.read().unwrap_or_else(|e| e.into_inner()).is_none() {
        return;
    }
    let route = route.unwrap_or("unmatched");
    send(
        1,
        json!({
            "level": "error",
            "message": { "formatted": format!("HTTP {status} from {method} {route}") },
            "tags": { "kind": "http_5xx", "route_class": class, "route": route, "method": method, "status": status.to_string(), "request_id": request_id },
            "fingerprint": ["http_5xx", method, route, status.to_string()],
        }),
    );
}

/// Counts panics, logs where each one happened, and reports it; then runs the hook
/// that was there before (Rust's own prints the message to stderr, for botd's log).
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        panicked(
            info.payload_as_str().unwrap_or(""),
            info.location().map(|l| (l.file(), l.line())),
        );
        previous(info);
    }));
}

fn panicked(message: &str, at: Option<(&str, u32)>) {
    PANICS.fetch_add(1, Ordering::Relaxed);
    let summary = panic_kind(message);
    let location = at.map(|(file, line)| format!("{}:{line}", short_path(file)));
    let request = super::request_id();
    log::event(
        Level::Warn,
        "server.panic",
        json!({ "panic": summary, "location": location, "requestId": request }),
    );
    let location = location.unwrap_or_else(|| "unknown".into());
    send(
        0,
        json!({
            "level": "fatal",
            "message": { "formatted": format!("panic at {location}: {summary}") },
            "exception": { "values": [{ "type": "panic", "value": summary, "mechanism": { "type": "panic" } }] },
            "tags": { "kind": "panic", "location": location, "request_id": request },
            "fingerprint": ["panic", location],
        }),
    );
}

/// What kind of panic it was, from a fixed list: the message itself may hold any text.
pub fn panic_kind(message: &str) -> &'static str {
    const KNOWN: [(&str, &str); 12] = [
        (
            "called `Option::unwrap()` on a `None` value",
            "called `Option::unwrap()` on a `None` value",
        ),
        (
            "called `Result::unwrap()` on an `Err` value",
            "called `Result::unwrap()` on an `Err` value",
        ),
        (
            "called `Result::unwrap_err()` on an `Ok` value",
            "called `Result::unwrap_err()` on an `Ok` value",
        ),
        ("index out of bounds", "index out of bounds"),
        ("range start index", "slice range out of bounds"),
        ("range end index", "slice range out of bounds"),
        ("slice index starts", "slice range out of bounds"),
        (
            "attempt to add with overflow",
            "attempt to add with overflow",
        ),
        (
            "attempt to subtract with overflow",
            "attempt to subtract with overflow",
        ),
        (
            "attempt to multiply with overflow",
            "attempt to multiply with overflow",
        ),
        ("attempt to divide by zero", "attempt to divide by zero"),
        ("already borrowed", "RefCell already borrowed"),
    ];
    if message.contains("is not a char boundary") {
        return "string sliced inside a character";
    }
    KNOWN
        .iter()
        .find(|(p, _)| message.starts_with(p))
        .map_or("panic (message withheld; see botd's log)", |(_, k)| k)
}

/// A source path without the build machine's directories: `src/runner.rs`, or
/// `tokio-1.47.0/src/runtime/task.rs` for a dependency.
fn short_path(file: &str) -> String {
    if !file.starts_with('/') && !file.contains(":\\") {
        return file.to_string();
    }
    let parts: Vec<&str> = file.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    match parts.iter().rposition(|p| *p == "src") {
        Some(i) if i > 0 => parts[i - 1..].join("/"),
        _ => parts[parts.len().saturating_sub(2)..].join("/"),
    }
}

/// The envelope a tracker takes: a header, an item header and the event, every string
/// in it scrubbed.
fn envelope(event: Value, environment: &str) -> String {
    let mut event = scrub_value(event);
    let id = event_id();
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if let Value::Object(m) = &mut event {
        m.insert("event_id".into(), json!(id));
        m.insert("timestamp".into(), json!(ts));
        m.insert("platform".into(), json!("native"));
        m.insert("logger".into(), json!("botd"));
        m.insert(
            "release".into(),
            json!(format!("superbot@{}", env!("CARGO_PKG_VERSION"))),
        );
        m.insert("environment".into(), json!(environment));
        m.insert(
            "sdk".into(),
            json!({ "name": "superbot.botd", "version": env!("CARGO_PKG_VERSION") }),
        );
        if let Some(Value::Object(tags)) = m.get_mut("tags") {
            tags.retain(|_, v| !v.is_null());
        }
    }
    format!(
        "{}\n{}\n{}\n",
        json!({ "event_id": id, "sent_at": ts }),
        json!({ "type": "event" }),
        event
    )
}

/// 32 hex digits, unique within this process, without I/O: this runs in the panic hook,
/// where a second panic (say, `/dev/urandom` unreadable for want of descriptors) would
/// abort botd.
fn event_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:016x}{:08x}{:08x}", std::process::id(), seq as u32)
}

fn scrub_value(v: Value) -> Value {
    match v {
        Value::String(s) => Value::String(scrub(&s)),
        Value::Array(a) => Value::Array(a.into_iter().map(scrub_value).collect()),
        Value::Object(o) => Value::Object(
            o.into_iter()
                .map(|(k, v)| (k, scrub_value(v)))
                .collect::<Map<_, _>>(),
        ),
        other => other,
    }
}

/// Known secrets redacted, anything like an email replaced, and at most `MAX_TEXT` long.
pub fn scrub(s: &str) -> String {
    let redacted = secrets::redact::text(s);
    let out: Vec<&str> = redacted
        .split(' ')
        .map(|w| if email_like(w) { "[email]" } else { w })
        .collect();
    out.join(" ").chars().take(MAX_TEXT).collect()
}

/// `name@host.tld`, maybe with punctuation around it.
fn email_like(w: &str) -> bool {
    let Some((_, host)) = w.split_once('@') else {
        return false;
    };
    let host = host.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
    host.rsplit_once('.')
        .is_some_and(|(_, tld)| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()))
}

pub fn render(out: &mut String) {
    family(
        out,
        "superbot_panics_total",
        "counter",
        "Panics in botd, caught or not, since it started (ADR 0113).",
    );
    sample(
        out,
        "superbot_panics_total",
        &[],
        PANICS.load(Ordering::Relaxed) as f64,
    );
    family(
        out,
        "superbot_error_reporting_enabled",
        "gauge",
        "1 when botd sends panics and 5xx answers to an error tracker (ERROR_REPORT_DSN).",
    );
    let on = REPORTER.read().unwrap_or_else(|e| e.into_inner()).is_some();
    sample(
        out,
        "superbot_error_reporting_enabled",
        &[],
        on as u8 as f64,
    );
    family(
        out,
        "superbot_error_reports_total",
        "counter",
        "Reports to the error tracker, by kind and outcome: sent, failed (the tracker refused or didn't answer) or dropped (over the rate limit or queue).",
    );
    for (k, kind) in KINDS.iter().enumerate() {
        for (o, outcome) in OUTCOMES.iter().enumerate() {
            sample(
                out,
                "superbot_error_reports_total",
                &[("kind", kind), ("outcome", outcome)],
                REPORTS[k][o].load(Ordering::Relaxed) as f64,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dsn_needs_https_a_key_and_a_project() {
        let d = Dsn::parse("https://abc123publickey@errors.example.org/42").unwrap();
        assert_eq!(d.endpoint, "https://errors.example.org/api/42/envelope/");
        assert!(d.auth.expose().contains("sentry_key=abc123publickey"));
        assert!(!format!("{d:?}").contains("abc123"), "the key never prints");
        let d = Dsn::parse("https://k3y0000000@errors.example.org:8443/sentry/7/").unwrap();
        assert_eq!(
            d.endpoint,
            "https://errors.example.org:8443/sentry/api/7/envelope/"
        );
        assert_eq!(
            Dsn::parse("http://k@127.0.0.1:9000/1").unwrap().endpoint,
            "http://127.0.0.1:9000/api/1/envelope/"
        );
        for bad in [
            "http://k@errors.example.org/1",
            "https://errors.example.org/1",
            "https://k@errors.example.org/",
            "https://k@errors.example.org/1?x=y",
            "nope",
        ] {
            assert!(Dsn::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn panic_messages_never_leave_only_their_kind() {
        assert_eq!(
            panic_kind(
                "called `Result::unwrap()` on an `Err` value: Os { code: 2, message: \"/home/ada/secret\" }"
            ),
            "called `Result::unwrap()` on an `Err` value"
        );
        assert_eq!(
            panic_kind(
                "byte index 3 is not a char boundary; it is inside 'é' (bytes 2..4) of `my prompt text`"
            ),
            "string sliced inside a character"
        );
        assert_eq!(
            panic_kind("index out of bounds: the len is 3 but the index is 5"),
            "index out of bounds"
        );
        assert_eq!(
            panic_kind("Ada asked: summarise the board minutes"),
            "panic (message withheld; see botd's log)"
        );
        assert_eq!(short_path("src/runner.rs"), "src/runner.rs");
        assert_eq!(
            short_path(
                "/home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.0/src/runtime/task.rs"
            ),
            "tokio-1.47.0/src/runtime/task.rs"
        );
        assert_eq!(
            short_path("/rustc/0ef1bc386/library/core/src/str/mod.rs"),
            "core/src/str/mod.rs"
        );
    }

    #[test]
    fn every_string_in_a_report_is_scrubbed() {
        let secret = format!("sk-live-{}", crate::random_hex(12));
        secrets::redact::register(&secret);
        let body = envelope(
            json!({ "message": { "formatted": format!("boom {secret} for ada@example.com") }, "tags": { "a": "x".repeat(500), "b": null } }),
            "staging",
        );
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3, "{body}");
        let e: Value = serde_json::from_str(lines[2]).unwrap();
        let text = e["message"]["formatted"].as_str().unwrap();
        assert!(
            !text.contains(&secret) && !text.contains("example.com"),
            "{text}"
        );
        assert_eq!(e["tags"]["a"].as_str().unwrap().len(), MAX_TEXT);
        assert!(e["tags"].get("b").is_none());
        assert_eq!(e["environment"], "staging");
        assert_eq!(e["event_id"].as_str().unwrap().len(), 32);
        assert_ne!(event_id(), event_id());
        assert_eq!(
            e["release"],
            format!("superbot@{}", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            scrub("mail (ada@example.com), v1@2.0 x@y"),
            "mail [email] v1@2.0 x@y"
        );
        assert!(
            e.get("user").is_none() && e.get("request").is_none() && e.get("server_name").is_none(),
            "{e}"
        );
    }
}
