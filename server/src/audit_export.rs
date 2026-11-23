//! SIEM export of the audit log (ADR 0122): every event, as one JSON line in the shape
//! `GET /api/audit` returns, with its place on the hash chain, sent to a SIEM, an
//! archive, or both at once (`AUDIT_EXPORT=<siem>,s3://...`, ADR 0173):
//!
//! - `https://<host>/<path>`: an HTTPS webhook, `POST`ed in batches as JSON lines
//!   (`application/x-ndjson`), with headers from the secret `AUDIT_EXPORT_HEADERS`.
//! - `syslog+tls://<host>[:6514]`: syslog (RFC 5424) over TLS (RFC 5425), one event a
//!   message, the JSON line as its text.
//! - Plain `http://` and `syslog+tcp://` to loopback, or with `AUDIT_EXPORT_INSECURE=on`.
//! - `s3://<bucket>[/<prefix>]`: batches as JSON-lines objects in an S3-compatible
//!   store, each locked with S3 Object Lock ([`crate::audit_archive`], ADR 0154).
//!
//! Off unless `AUDIT_EXPORT` is set. Delivery is at least once, in id order: a cursor
//! in the database (per sink) moves only when a batch is accepted, a failed batch is
//! tried again with backoff for as long as it takes, and retention never deletes an
//! event before it is delivered. Payloads are the audit log's own rows, already
//! scrubbed of secrets; the sink's credentials never go in them.

use crate::audit::{Actor, Event, Filter, Outcome};
use crate::db::{now, AuditEvent};
use crate::obs::log::{log_info, log_warn};
use crate::obs::metrics;
use crate::runner::App;
use crate::secrets::{self, Secret, SecretStore};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Events a batch takes at most.
const BATCH: i64 = 200;
const IDLE: Duration = Duration::from_millis(if cfg!(test) { 50 } else { 1_000 });
const FIRST_RETRY: Duration = Duration::from_millis(if cfg!(test) { 50 } else { 1_000 });
const LAST_RETRY: Duration = Duration::from_secs(5 * 60);
const TIMEOUT: Duration = Duration::from_secs(30);
/// Failed tries in a row before `audit.export_failing` is recorded.
const FAILING_AFTER: u32 = 3;
pub const SCHEMA: &str = "superbot.audit.v1";
/// RFC 5424 facility 13, "log audit".
const FACILITY: u8 = 13;

enum Kind {
    Webhook { url: String, plain: bool, headers: Vec<(String, secrets::Secret)> },
    Syslog { host: String, port: u16, tls: bool },
    Archive(Box<crate::audit_archive::Archive>),
}

pub struct Sink {
    kind: Kind,
    /// What logs, the API and the audit log show: never a credential.
    pub shown: String,
    /// Names the sink's cursor: a different sink starts again from the start. Never the
    /// sink's name, so naming a sink later keeps its place.
    pub id: String,
    /// `<name>=` in `AUDIT_EXPORT` (ADR 0191): needed once it lists more than one SIEM,
    /// and picks the sink's headers (`AUDIT_EXPORT_HEADERS_<NAME>`).
    pub name: Option<String>,
}

impl std::fmt::Debug for Sink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sink({})", self.shown)
    }
}

impl Sink {
    pub fn kind(&self) -> &'static str {
        match self.kind {
            Kind::Webhook { .. } => "webhook",
            Kind::Syslog { .. } => "syslog",
            Kind::Archive(_) => "s3",
        }
    }

    pub(crate) fn archive(&self) -> Option<&crate::audit_archive::Archive> {
        match &self.kind {
            Kind::Archive(a) => Some(a),
            _ => None,
        }
    }

    /// Events a batch takes at most.
    fn batch(&self) -> i64 {
        if self.archive().is_some() { crate::audit_archive::MAX_EVENTS } else { BATCH }
    }

    fn from_archive(a: crate::audit_archive::Archive) -> Sink {
        Sink { shown: a.shown(), id: a.id(), kind: Kind::Archive(Box::new(a)), name: None }
    }

    fn siem(&self) -> bool {
        self.archive().is_none()
    }

    /// The sink as logs say it: its name first, when it has one.
    pub fn label(&self) -> String {
        match &self.name {
            Some(n) => format!("{n} ({})", self.shown),
            None => self.shown.clone(),
        }
    }

    /// The secret holding this sink's headers: `AUDIT_EXPORT_HEADERS_<NAME>`.
    fn headers_key(&self) -> Option<String> {
        self.name.as_ref().map(|n| format!("AUDIT_EXPORT_HEADERS_{}", n.to_ascii_uppercase()))
    }

    pub fn parse(raw: &str, insecure: bool) -> Result<Sink, String> {
        let bad = |why: &str| format!("AUDIT_EXPORT must be https://<host>/<path>, syslog+tls://<host>[:<port>] or s3://<bucket>[/<prefix>]: {why}");
        let u = url::Url::parse(raw.trim()).map_err(|_| bad("it isn't a URL"))?;
        let host = u.host_str().filter(|h| !h.is_empty()).ok_or_else(|| bad("no host"))?.to_string();
        let loopback = matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]");
        if !u.username().is_empty() || u.password().is_some() {
            return Err(bad("put credentials in AUDIT_EXPORT_HEADERS, not the URL"));
        }
        if u.query().is_some() || u.fragment().is_some() {
            return Err(bad("no query or fragment: put credentials in AUDIT_EXPORT_HEADERS"));
        }
        let plain_ok = loopback || insecure;
        let insecure_hint = "plain only to loopback, or set AUDIT_EXPORT_INSECURE=on for a collector on a private network";
        let (kind, port) = match u.scheme() {
            "https" => (Kind::Webhook { url: u.to_string(), plain: false, headers: Vec::new() }, u.port_or_known_default()),
            "http" if plain_ok => (Kind::Webhook { url: u.to_string(), plain: true, headers: Vec::new() }, u.port_or_known_default()),
            "http" => return Err(bad(&format!("use https ({insecure_hint})"))),
            s @ ("syslog+tls" | "syslog+tcp") => {
                if !matches!(u.path(), "" | "/") {
                    return Err(bad("a syslog sink has no path"));
                }
                let tls = s == "syslog+tls";
                if !tls && !plain_ok {
                    return Err(bad(&format!("use syslog+tls ({insecure_hint})")));
                }
                let port = u.port().unwrap_or(if tls { 6514 } else { 514 });
                let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
                (Kind::Syslog { host, port, tls }, Some(port))
            }
            _ => return Err(bad("use https, syslog+tls, syslog+tcp or s3")),
        };
        let port = port.map(|p| format!(":{p}")).unwrap_or_default();
        let (shown, id) = match &kind {
            Kind::Webhook { .. } => (format!("{}://{host}{port}", u.scheme()), format!("{}://{host}{port}{}", u.scheme(), u.path())),
            Kind::Syslog { .. } => (format!("{}://{host}{port}", u.scheme()), format!("{}://{host}{port}", u.scheme())),
            Kind::Archive(_) => unreachable!("s3:// sinks are read with their settings"),
        };
        Ok(Sink { kind, shown, id, name: None })
    }
}

/// SIEMs (webhooks and syslog) `AUDIT_EXPORT` takes at most, beside one archive.
pub const MAX_SIEMS: usize = 4;
const MAX_NAME: usize = 32;

/// Splits `<name>=<url>` into its name and URL; a `=` after `://` is the URL's own.
fn named(entry: &str) -> Result<(Option<String>, &str), String> {
    let (Some(eq), scheme) = (entry.find('='), entry.find("://")) else { return Ok((None, entry)) };
    if scheme.is_some_and(|s| s < eq) {
        return Ok((None, entry));
    }
    let name = entry[..eq].trim().to_ascii_lowercase();
    let ok = name.len() <= MAX_NAME && name.starts_with(|c: char| c.is_ascii_lowercase()) && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !ok {
        return Err(format!("AUDIT_EXPORT names a sink with <name>=<url>, the name a letter then letters, digits or _, at most {MAX_NAME}: not \"{}\"", crate::audit::clip(&name, 40)));
    }
    if matches!(name.as_str(), "webhook" | "syslog" | "s3") {
        return Err(format!("AUDIT_EXPORT can't name a sink \"{name}\": that is a kind of sink"));
    }
    Ok((Some(name), entry[eq + 1..].trim()))
}

/// Gives each webhook its headers: a named sink's from `AUDIT_EXPORT_HEADERS_<NAME>`,
/// and the one webhook's from `AUDIT_EXPORT_HEADERS` when only one is listed. Headers
/// that could reach the wrong collector stop botd instead.
fn headers(sinks: &mut [Sink], store: &dyn SecretStore) -> Result<(), String> {
    let read = |k: &str| store.get(k).map_err(|e| e.to_string());
    let webhooks = sinks.iter().filter(|s| matches!(s.kind, Kind::Webhook { .. })).count();
    let shared = read("AUDIT_EXPORT_HEADERS")?;
    if shared.is_some() && webhooks > 1 {
        return Err("AUDIT_EXPORT_HEADERS can't say which of the https sinks it is for: set AUDIT_EXPORT_HEADERS_<NAME> for each one instead".into());
    }
    for s in sinks.iter_mut() {
        let own = match s.headers_key() {
            Some(k) => read(&k)?.map(|h| (k, h)),
            None => None,
        };
        let is_webhook = matches!(s.kind, Kind::Webhook { .. });
        let (var, h) = match (own, shared.as_ref().filter(|_| is_webhook)) {
            (Some((k, _)), Some(_)) => return Err(format!("{k} and AUDIT_EXPORT_HEADERS are both set for {}: keep one", s.label())),
            (Some(kh), None) => kh,
            (None, Some(h)) => ("AUDIT_EXPORT_HEADERS".to_string(), Secret::new(h.expose())),
            (None, None) => continue,
        };
        match &mut s.kind {
            Kind::Webhook { headers, .. } => *headers = crate::obs::trace::headers(&var, h.expose())?,
            Kind::Syslog { .. } => return Err(format!("{var} is for an https sink; syslog over TLS has no headers")),
            Kind::Archive(_) => return Err(format!("{var} is for an https sink; the S3 archive signs with AUDIT_EXPORT_S3_ACCESS_KEY_ID and _SECRET_ACCESS_KEY")),
        }
    }
    if shared.is_some() && webhooks == 0 {
        let why = match sinks.iter().any(|s| matches!(s.kind, Kind::Syslog { .. })) {
            true => "syslog over TLS has no headers",
            false => "the S3 archive signs with AUDIT_EXPORT_S3_ACCESS_KEY_ID and _SECRET_ACCESS_KEY",
        };
        return Err(format!("AUDIT_EXPORT_HEADERS is for an https sink; {why}"));
    }
    Ok(())
}

/// Where to start a sink the database has no cursor for: every event kept (`all`, the
/// default) or only those from now on (`new`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Start {
    All,
    New,
}

#[derive(Debug)]
pub struct Settings {
    /// In the order `AUDIT_EXPORT` lists them: at most one SIEM (webhook or syslog) and
    /// one S3 archive (ADR 0173).
    pub sinks: Vec<Sink>,
    pub start: Start,
}

impl Settings {
    pub fn from_env(get: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Settings, String> {
        let insecure = match get("AUDIT_EXPORT_INSECURE").trim().to_ascii_lowercase().as_str() {
            "" | "off" => false,
            "on" => true,
            other => return Err(format!("AUDIT_EXPORT_INSECURE must be on or off, not \"{other}\"")),
        };
        let start = match get("AUDIT_EXPORT_START").trim().to_ascii_lowercase().as_str() {
            "" | "all" => Start::All,
            "new" => Start::New,
            other => return Err(format!("AUDIT_EXPORT_START must be all or new, not \"{other}\"")),
        };
        let raw = get("AUDIT_EXPORT");
        let listed: Vec<&str> = match raw.trim() {
            "" | "off" => Vec::new(),
            v => v.split(',').map(str::trim).collect(),
        };
        if listed.iter().any(|v| v.is_empty()) {
            return Err("AUDIT_EXPORT lists sinks split by single commas, with none empty".into());
        }
        let mut sinks: Vec<Sink> = Vec::new();
        for entry in listed {
            let (name, v) = named(entry)?;
            let mut sink = match v.to_ascii_lowercase().starts_with("s3://") {
                true => Sink::from_archive(crate::audit_archive::Archive::from_env(v, get, store)?),
                false => Sink::parse(v, insecure)?,
            };
            if let Some(n) = &name
                && sinks.iter().any(|s| s.name.as_ref() == Some(n))
            {
                return Err(format!("AUDIT_EXPORT names two sinks \"{n}\": each name once"));
            }
            if sinks.iter().any(|s| s.id == sink.id) {
                return Err(format!("AUDIT_EXPORT lists {} twice: each sink once", sink.shown));
            }
            sink.name = name;
            sinks.push(sink);
        }
        let archives = sinks.iter().filter(|s| !s.siem()).count();
        let siems = sinks.len() - archives;
        if archives > 1 || siems > MAX_SIEMS {
            return Err(format!("AUDIT_EXPORT takes {MAX_SIEMS} SIEMs (https:// or syslog+tls://) and one archive (s3://) at most, split by commas"));
        }
        if siems > 1
            && let Some(s) = sinks.iter().find(|s| s.siem() && s.name.is_none())
        {
            return Err(format!("AUDIT_EXPORT lists {siems} SIEMs, so each needs a name, as <name>=<url>: {} has none", s.shown));
        }
        // Read only when export is on, so a leftover _FILE doesn't stop botd starting.
        if !sinks.is_empty() {
            headers(&mut sinks, store)?;
        }
        Ok(Settings { sinks, start })
    }

    #[cfg(test)]
    fn headers_of(&self, name: &str) -> Vec<(String, String)> {
        let s = self.sinks.iter().find(|s| s.name.as_deref() == Some(name) || s.shown == name).expect("sink");
        match &s.kind {
            Kind::Webhook { headers, .. } => headers.iter().map(|(k, v)| (k.clone(), v.expose().to_string())).collect(),
            _ => Vec::new(),
        }
    }

    pub fn describe(&self) -> String {
        if self.sinks.is_empty() {
            return "off (AUDIT_EXPORT)".into();
        }
        let each: Vec<String> = self
            .sinks
            .iter()
            .map(|s| {
                let how = match &s.kind {
                    Kind::Webhook { headers, plain, .. } => {
                        format!("as JSON lines over {}{}", if *plain { "plain HTTP" } else { "HTTPS" }, if headers.is_empty() { "" } else { ", with headers" })
                    }
                    Kind::Syslog { tls: true, .. } => "as RFC 5424 syslog over TLS".into(),
                    Kind::Syslog { .. } => "as RFC 5424 syslog over plain TCP".into(),
                    Kind::Archive(a) => a.describe(),
                };
                format!("every audit event to {} {how}", s.label())
            })
            .collect();
        let also = if each.len() > 1 { ", each on its own and" } else { "" };
        format!("{}{also}, resuming where it left off", each.join("; and "))
    }
}

#[derive(Default)]
struct State {
    delivered: i64,
    delivered_at: Option<i64>,
    failures: u32,
    failing_since: Option<i64>,
    last_error: Option<String>,
    /// The archive's last object (ADR 0154).
    archived: Option<Value>,
}

/// The running export: its sink and how far it got.
pub struct Exporter {
    pub sink: Sink,
    state: Mutex<State>,
}

impl Exporter {
    fn new(sink: Sink, delivered: i64) -> Exporter {
        Exporter { sink, state: Mutex::new(State { delivered, ..Default::default() }) }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The last event the sink accepted: retention keeps everything after it.
    pub fn delivered(&self) -> i64 {
        self.state().delivered
    }

    /// Returns how many tries failed and since when, if it had been failing.
    fn delivered_to(&self, id: i64) -> Option<(u32, i64)> {
        let mut s = self.state();
        s.delivered = id;
        s.delivered_at = Some(now());
        let was = s.failing_since.take().map(|t| (s.failures, t));
        s.failures = 0;
        s.last_error = None;
        was
    }

    fn archived(&self, object: Value) {
        self.state().archived = Some(object);
    }

    /// True on the try that makes it count as failing.
    fn failed(&self, error: &str) -> bool {
        let mut s = self.state();
        s.failures += 1;
        s.last_error = Some(error.into());
        if s.failures == FAILING_AFTER {
            s.failing_since = Some(now());
            return true;
        }
        false
    }

    /// `GET /api/audit/siem` and `botctl audit siem`.
    pub fn view(&self, head: i64) -> Value {
        let s = self.state();
        let mut v = json!({
            "enabled": true,
            "kind": self.sink.kind(),
            "name": self.sink.name,
            "sink": self.sink.shown,
            "delivered": s.delivered,
            "pending": (head - s.delivered).max(0),
            "deliveredAt": s.delivered_at,
            "failing": s.failing_since.is_some(),
            "failingSince": s.failing_since,
            "failedTries": s.failures,
            "lastError": s.last_error,
        });
        if let Some(a) = self.sink.archive() {
            v["archive"] = a.view(s.archived.as_ref());
        }
        v
    }
}

/// Every running export (ADR 0173): a SIEM, an archive, or both. Each has its own
/// cursor, retries and status, so one sink's outage never holds up the other.
pub struct Exports {
    pub sinks: Vec<Arc<Exporter>>,
}

impl Exports {
    /// The last event every sink accepted: retention keeps everything after it.
    pub fn delivered(&self) -> i64 {
        self.sinks.iter().map(|x| x.delivered()).min().unwrap_or(0)
    }

    /// The S3 archive, when one is set.
    pub fn archive(&self) -> Option<(&Exporter, &crate::audit_archive::Archive)> {
        self.sinks.iter().find_map(|x| x.sink.archive().map(|a| (x.as_ref(), a)))
    }

    /// The sink in the worst state (failing, then furthest behind), so a reader of one
    /// sink's fields never misses another's trouble; and every sink under `sinks`.
    pub fn view(&self, head: i64) -> Value {
        let views: Vec<Value> = self.sinks.iter().map(|x| x.view(head)).collect();
        let worst = views.iter().max_by_key(|v| (v["failing"].as_bool().unwrap_or(false), v["pending"].as_i64().unwrap_or(0))).cloned();
        let mut v = worst.unwrap_or_else(|| json!({ "enabled": false }));
        if !views.is_empty() {
            v["sinks"] = Value::Array(views);
        }
        v
    }
}

/// Starts the export to each sink set. Before retention starts, so its first pass
/// already keeps what isn't delivered.
pub fn start(app: &Arc<App>, settings: Settings) {
    if settings.sinks.is_empty() {
        return;
    }
    let sinks: Vec<Arc<Exporter>> = settings
        .sinks
        .into_iter()
        .map(|sink| {
            let delivered = app.db.audit_export_cursor(&sink.id).unwrap_or_else(|| {
                let from = match settings.start {
                    Start::All => 0,
                    Start::New => app.db.audit_head(),
                };
                if let Err(e) = app.db.set_audit_export_cursor(&sink.id, from) {
                    log_warn!("Audit export: couldn't save where {} starts ({e}); trying again after the first delivery.", sink.label());
                }
                from
            });
            Arc::new(Exporter::new(sink, delivered))
        })
        .collect();
    if app.audit_export.set(Arc::new(Exports { sinks: sinks.clone() })).is_ok() {
        for x in sinks {
            tokio::spawn(run(app.clone(), x));
        }
    }
}

async fn run(app: Arc<App>, x: Arc<Exporter>) {
    let mut out = Out::new(&x.sink);
    let host = hostname();
    let mut wait = FIRST_RETRY;
    // The archive sends a batch as it was first cut, across retries and restarts, so a
    // retry writes the same object. The batch's last id is saved before its first try.
    let batch_key = format!("{}#batch", x.sink.id);
    let start_key = format!("{}#start", x.sink.id);
    let mut retry_to: Option<i64> = x.sink.archive().and_then(|_| app.db.audit_export_cursor(&batch_key)).filter(|&b| b > x.delivered());
    loop {
        if let Some(a) = x.sink.archive()
            && retry_to.is_none()
            && !archive_batch_due(&app, a, x.delivered())
        {
            tokio::time::sleep(IDLE).await;
            continue;
        }
        // A row that can't be read stops the export there, so it's never skipped.
        // Failures carry a reason code for the audit event beside the message.
        let rows = app.db.try_audit_events(&Filter { after: Some(x.delivered()), ..Default::default() }, x.sink.batch(), true).map_err(|e| ("unreadable", format!("couldn't read the audit log: {e}")));
        let sent = match rows {
            Ok(mut rows) => {
                if let Some(to) = retry_to {
                    rows.retain(|e| e.id <= to);
                }
                let Some(last) = rows.last().map(|e| e.id) else {
                    tokio::time::sleep(IDLE).await;
                    continue;
                };
                // Delivered only once the cursor is saved; if it can't be, the batch goes again.
                let extras = crate::audit_checkpoint::export_extras(&app.db, &rows);
                let cut = match x.sink.archive().is_some() && retry_to.is_none() {
                    true => {
                        // Where the archive begins (ADR 0163), saved once with the first batch it ever gets.
                        let first = match app.db.audit_export_cursor(&batch_key) {
                            None => app.db.set_audit_export_cursor(&start_key, rows[0].id).map_err(|e| ("cursor_unsaved", format!("couldn't save where the archive starts: {e}"))),
                            Some(_) => Ok(()),
                        };
                        first.and_then(|()| app.db.set_audit_export_cursor(&batch_key, last).map_err(|e| ("cursor_unsaved", format!("couldn't save the archive's next batch: {e}"))))
                    }
                    false => Ok(()),
                };
                let r = match cut {
                    Ok(()) => out
                        .send(&x.sink, &rows, &extras, &host)
                        .await
                        .and_then(|object| app.db.set_audit_export_cursor(&x.sink.id, last).map(|()| object).map_err(|e| ("cursor_unsaved", format!("couldn't save the export cursor: {e}")))),
                    Err(e) => Err(e),
                };
                if x.sink.archive().is_some() {
                    retry_to = r.is_err().then_some(last);
                }
                r.map(|object| {
                    if let Some(o) = object {
                        x.archived(o);
                    }
                    last
                })
            }
            Err(e) => Err(e),
        };
        match sent {
            Ok(last) => {
                if let Some((tries, since)) = x.delivered_to(last) {
                    log_info!("Audit export: {} is taking events again after {tries} failed tries.", x.sink.label());
                    let e = Event::new(Actor::system("audit_export"), "audit.export_recovered").target("audit", "export");
                    app.db.record(&e.details(json!({ "sink": x.sink.shown, "kind": x.sink.kind(), "name": x.sink.name, "failedTries": tries, "failingSince": since })));
                }
                wait = FIRST_RETRY;
            }
            Err((reason, e)) => {
                let e = secrets::redact::text(&e).into_owned();
                if x.failed(&e) {
                    log_warn!("WARNING: audit export to {} is failing ({e}); events wait in the database and retention keeps them until they are delivered.", x.sink.label());
                    let pending = (app.db.audit_head() - x.delivered()).max(0);
                    let ev = Event::new(Actor::system("audit_export"), "audit.export_failing").target("audit", "export").outcome(Outcome::Failure);
                    app.db.record(&ev.details(json!({ "sink": x.sink.shown, "kind": x.sink.kind(), "name": x.sink.name, "reason": reason, "error": e, "pending": pending })));
                }
                tokio::time::sleep(jitter(wait)).await;
                wait = (wait * 2).min(LAST_RETRY);
            }
        }
    }
}

/// Whether the archive's next batch should go now: it is full, or its oldest event has
/// waited `AUDIT_EXPORT_S3_BATCH_SECONDS`. A row that can't be read is due, so the read
/// that follows fails on it.
pub(crate) fn archive_batch_due(app: &App, a: &crate::audit_archive::Archive, delivered: i64) -> bool {
    let pending = app.db.audit_head() - delivered;
    if pending <= 0 {
        return false;
    }
    if pending >= crate::audit_archive::MAX_EVENTS {
        return true;
    }
    match app.db.try_audit_events(&Filter { after: Some(delivered), ..Default::default() }, 1, true) {
        Ok(rows) => rows.first().is_some_and(|e| now() - e.at >= a.batch_ms),
        Err(_) => true,
    }
}

/// From three quarters to all of `d`, so many servers don't retry in step.
fn jitter(d: Duration) -> Duration {
    let r = crate::random_bytes(1)[0] as u32;
    d.mul_f64(0.75 + 0.25 * r as f64 / 255.0)
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname writes at most that.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let name = if ok { String::from_utf8_lossy(&buf[..buf.iter().position(|&b| b == 0).unwrap_or(buf.len())]).into_owned() } else { String::new() };
    printable(&name, 255)
}

/// RFC 5424's PRINTUSASCII, at most `max` characters; `-` (its nil) when empty.
fn printable(s: &str, max: usize) -> String {
    let s: String = s.chars().map(|c| if c.is_ascii_graphic() { c } else { '-' }).take(max).collect();
    if s.is_empty() { "-".into() } else { s }
}

/// One event as a JSON line: the API's shape, plus the schema and this host.
#[cfg(test)]
pub fn line(e: &AuditEvent, host: &str) -> String {
    line_with(e, host, None)
}

/// [`line`], with a checkpoint event's signed record and token (ADR 0149) as `checkpoint`.
pub fn line_with(e: &AuditEvent, host: &str, checkpoint: Option<&Value>) -> String {
    let mut v = serde_json::to_value(e).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.insert("schema".into(), json!(SCHEMA));
        o.insert("host".into(), json!(host));
        if let Some(c) = checkpoint {
            o.insert("checkpoint".into(), c.clone());
        }
    }
    v.to_string()
}

/// One event as an RFC 5424 message: facility "log audit", severity by outcome, the
/// action as MSGID, and the JSON line as the text.
pub fn syslog(e: &AuditEvent, host: &str, checkpoint: Option<&Value>) -> String {
    let severity = match e.outcome.as_str() {
        "denied" => 4,
        "failure" => 5,
        _ => 6,
    };
    format!("<{}>1 {} {host} superbot {} {} - {}", FACILITY * 8 + severity, e.time, std::process::id(), printable(&e.action, 32), line_with(e, host, checkpoint))
}

/// Checkpoint records to add to their events, by event id.
type Extras = std::collections::BTreeMap<i64, Value>;

trait Stream: tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncWrite + Unpin + Send> Stream for T {}

enum Out {
    Http(reqwest::Client),
    Syslog { conn: Option<Box<dyn Stream>>, tls: Option<Arc<rustls::ClientConfig>> },
    Archive(crate::audit_archive::Client),
}

impl Out {
    fn new(sink: &Sink) -> Out {
        match &sink.kind {
            Kind::Webhook { plain, .. } => {
                Out::Http(reqwest::Client::builder().https_only(!plain).timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none()).build().expect("HTTP client"))
            }
            Kind::Syslog { tls, .. } => Out::Syslog { conn: None, tls: tls.then(platform_tls) },
            Kind::Archive(a) => Out::Archive(crate::audit_archive::Client::new(a)),
        }
    }

    /// Sends one batch: the archive's object when it wrote one. Failures carry a reason
    /// code for `audit.export_failing`.
    async fn send(&mut self, sink: &Sink, rows: &[AuditEvent], extras: &Extras, host: &str) -> Result<Option<Value>, (&'static str, String)> {
        if let (Out::Archive(client), Kind::Archive(a)) = (&mut *self, &sink.kind) {
            let body: String = rows.iter().map(|e| line_with(e, host, extras.get(&e.id)) + "\n").collect();
            return client.send(a, rows, body.into_bytes()).await.map(Some);
        }
        self.send_stream(sink, rows, extras, host).await.map(|()| None).map_err(|e| ("delivery_failed", e))
    }

    async fn send_stream(&mut self, sink: &Sink, rows: &[AuditEvent], extras: &Extras, host: &str) -> Result<(), String> {
        match (self, &sink.kind) {
            (Out::Http(http), Kind::Webhook { url, headers, .. }) => {
                let body: String = rows.iter().map(|e| line_with(e, host, extras.get(&e.id)) + "\n").collect();
                let mut req = http.post(url).header(reqwest::header::CONTENT_TYPE, "application/x-ndjson").body(body);
                for (k, v) in headers {
                    req = req.header(k.as_str(), v.expose());
                }
                let r = req.send().await.map_err(|e| format!("couldn't reach {}: {}", sink.shown, e.without_url()))?;
                if r.status().is_success() { Ok(()) } else { Err(format!("{} answered HTTP {}", sink.shown, r.status().as_u16())) }
            }
            (Out::Syslog { conn, tls }, Kind::Syslog { host: peer, port, .. }) => {
                if conn.is_none() {
                    *conn = Some(connect(peer, *port, tls.clone()).await?);
                }
                let mut frames = Vec::new();
                for e in rows {
                    let m = syslog(e, host, extras.get(&e.id));
                    frames.extend(format!("{} ", m.len()).as_bytes());
                    frames.extend(m.as_bytes());
                }
                let s = conn.as_mut().expect("connected");
                let sent = tokio::time::timeout(TIMEOUT, async {
                    s.write_all(&frames).await?;
                    s.flush().await
                })
                .await;
                match sent {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => {
                        *conn = None;
                        Err(format!("couldn't write to {}: {e}", sink.shown))
                    }
                    Err(_) => {
                        *conn = None;
                        Err(format!("{} stopped taking messages", sink.shown))
                    }
                }
            }
            _ => unreachable!("a sink's output matches its kind"),
        }
    }
}

async fn connect(host: &str, port: u16, tls: Option<Arc<rustls::ClientConfig>>) -> Result<Box<dyn Stream>, String> {
    let tcp = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect((host, port)))
        .await
        .map_err(|_| format!("connecting to {host}:{port} took too long"))?
        .map_err(|e| format!("couldn't connect to {host}:{port}: {e}"))?;
    let Some(config) = tls else { return Ok(Box::new(tcp)) };
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| format!("{host}: {e}"))?;
    let s = tokio::time::timeout(TIMEOUT, tokio_rustls::TlsConnector::from(config).connect(name, tcp))
        .await
        .map_err(|_| format!("TLS with {host} took too long"))?
        .map_err(|e| format!("TLS with {host} failed: {e}"))?;
    Ok(Box::new(s))
}

/// The system's trusted roots, as reqwest uses them.
fn platform_tls() -> Arc<rustls::ClientConfig> {
    use rustls_platform_verifier::BuilderVerifierExt;
    let b = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider())).with_safe_default_protocol_versions().expect("TLS versions");
    Arc::new(b.with_platform_verifier().expect("the system's TLS roots").with_no_client_auth())
}

/// `GET /api/audit/siem`: whether the export is on, where to, and how far it got. Admins only.
pub async fn get(axum::extract::State(app): axum::extract::State<Arc<App>>) -> axum::Json<Value> {
    axum::Json(match app.audit_export.get() {
        Some(x) => x.view(app.db.audit_head()),
        None => json!({ "enabled": false }),
    })
}

/// How far behind each sink is, when the export is on, labelled by its kind and, for a
/// named sink, its name (ADR 0191). An unnamed sink is the only one of its kind.
pub fn render(app: &App, out: &mut String) {
    let Some(xs) = app.audit_export.get() else { return };
    let head = app.db.audit_head();
    let views: Vec<(Vec<(&str, &str)>, Value)> = xs
        .sinks
        .iter()
        .map(|x| {
            let mut labels = vec![("kind", x.sink.kind())];
            if let Some(n) = &x.sink.name {
                labels.push(("name", n.as_str()));
            }
            (labels, x.view(head))
        })
        .collect();
    metrics::family(out, "superbot_audit_export_pending_events", "gauge", "Audit events not yet delivered to the sink (ADR 0122).");
    for (labels, v) in &views {
        metrics::sample(out, "superbot_audit_export_pending_events", labels, v["pending"].as_i64().unwrap_or(0) as f64);
    }
    metrics::family(out, "superbot_audit_export_failing", "gauge", "1 while delivery to the sink keeps failing.");
    for (labels, v) in &views {
        metrics::sample(out, "superbot_audit_export_failing", labels, v["failing"].as_bool().unwrap_or(false) as u8 as f64);
    }
    let delivered: Vec<(&[(&str, &str)], i64)> = views.iter().filter_map(|(l, v)| v["deliveredAt"].as_i64().map(|t| (l.as_slice(), t))).collect();
    if !delivered.is_empty() {
        metrics::family(out, "superbot_audit_export_last_delivery_timestamp_seconds", "gauge", "When the sink last accepted a batch.");
        for (labels, t) in delivered {
            metrics::sample(out, "superbot_audit_export_last_delivery_timestamp_seconds", labels, t as f64 / 1000.0);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::secrets::env::EnvStore;

    fn settings(vars: &[(&str, &str)]) -> Result<Settings, String> {
        let store = EnvStore::fixed(vars);
        let map: std::collections::HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Settings::from_env(&|k| map.get(k).cloned().unwrap_or_default(), &store)
    }

    #[test]
    fn export_is_off_by_default_and_needs_tls_off_loopback() {
        assert!(settings(&[]).unwrap().sinks.is_empty());
        assert!(settings(&[("AUDIT_EXPORT", "off")]).unwrap().sinks.is_empty());
        assert_eq!(settings(&[]).unwrap().describe(), "off (AUDIT_EXPORT)");
        let s = settings(&[("AUDIT_EXPORT", "https://siem.example.net/ingest/superbot")]).unwrap().sinks.remove(0);
        assert_eq!((s.kind(), s.shown.as_str(), s.id.as_str()), ("webhook", "https://siem.example.net:443", "https://siem.example.net:443/ingest/superbot"));
        let s = settings(&[("AUDIT_EXPORT", "syslog+tls://logs.example.net")]).unwrap().sinks.remove(0);
        assert_eq!((s.kind(), s.shown.as_str()), ("syslog", "syslog+tls://logs.example.net:6514"));
        assert_eq!(settings(&[("AUDIT_EXPORT", "syslog+tcp://127.0.0.1:1514")]).unwrap().sinks.remove(0).shown, "syslog+tcp://127.0.0.1:1514");
        assert!(settings(&[("AUDIT_EXPORT", "http://127.0.0.1:8080/x")]).is_ok());
        for plain in ["http://siem.internal/x", "syslog+tcp://logs.internal"] {
            assert!(settings(&[("AUDIT_EXPORT", plain)]).unwrap_err().contains("AUDIT_EXPORT_INSECURE"), "{plain}");
            assert!(settings(&[("AUDIT_EXPORT", plain), ("AUDIT_EXPORT_INSECURE", "on")]).is_ok(), "{plain}");
        }
        for bad in ["nope", "ftp://siem.example.net", "https://u:p@siem.example.net", "https://siem.example.net/?token=x", "https://siem.example.net/#x", "syslog+tls://logs.example.net/path", "syslog+udp://logs.example.net"] {
            assert!(settings(&[("AUDIT_EXPORT", bad)]).is_err(), "{bad}");
        }
        assert!(settings(&[("AUDIT_EXPORT_INSECURE", "yes")]).is_err());
        assert_eq!(settings(&[("AUDIT_EXPORT_START", "new")]).unwrap().start, Start::New);
        assert!(settings(&[("AUDIT_EXPORT_START", "later")]).is_err());
    }

    #[test]
    fn headers_are_secrets_for_webhooks_only() {
        let key = "sbx-audit-export-test-key-0123456789";
        let s = settings(&[("AUDIT_EXPORT", "https://siem.example.net/in"), ("AUDIT_EXPORT_HEADERS", &format!("Authorization=Bearer {key}"))]).unwrap();
        assert!(s.describe().contains("with headers"));
        assert!(!s.describe().contains(key) && !format!("{:?}", s).contains(key));
        assert!(!secrets::redact::text(&format!("x {key} y")).contains(key), "registered, so an error quoting it is masked");
        assert!(settings(&[("AUDIT_EXPORT", "syslog+tls://logs.example.net"), ("AUDIT_EXPORT_HEADERS", "a=b")]).is_err());
        assert!(settings(&[("AUDIT_EXPORT", "https://siem.example.net/in"), ("AUDIT_EXPORT_HEADERS", "no-equals")]).is_err());
        // A leftover headers file doesn't matter while export is off.
        assert!(settings(&[("AUDIT_EXPORT_HEADERS_FILE", "/nonexistent/superbot-headers")]).is_ok());
    }

    fn with_archive(vars: &[(&str, &str)]) -> Result<Settings, String> {
        let mut all = vec![("AUDIT_EXPORT_S3_ENDPOINT", "https://s3.example.net"), ("AUDIT_EXPORT_S3_ACCESS_KEY_ID", "AKID"), ("AUDIT_EXPORT_S3_SECRET_ACCESS_KEY", "archive-secret-0123456789")];
        all.extend_from_slice(vars);
        settings(&all)
    }

    #[test]
    fn a_siem_and_an_archive_together() {
        let s = with_archive(&[("AUDIT_EXPORT", " https://siem.example.net/in , s3://audit-archive/prod "), ("AUDIT_EXPORT_HEADERS", "Authorization=Bearer x")]).unwrap();
        assert_eq!(s.sinks.iter().map(|s| s.kind()).collect::<Vec<_>>(), ["webhook", "s3"]);
        let d = s.describe();
        assert!(d.contains("https://siem.example.net:443 as JSON lines over HTTPS, with headers") && d.contains("; and every audit event to s3://audit-archive/prod") && d.contains("each on its own"), "{d}");
        let s = with_archive(&[("AUDIT_EXPORT", "s3://audit-archive/prod,syslog+tls://logs.example.net")]).unwrap();
        assert_eq!(s.sinks.iter().map(|s| s.kind()).collect::<Vec<_>>(), ["s3", "syslog"], "in the order listed");

        for (export, why) in [
            ("https://a.example.net/in,https://b.example.net/in", "each needs a name"),
            ("a=https://a.example.net/in,syslog+tls://logs.example.net", "syslog+tls://logs.example.net:6514 has none"),
            ("s3://audit-archive/a,s3://audit-archive/b", "one archive"),
            ("https://a.example.net/in,s3://audit-archive/a,syslog+tls://logs.example.net", "each needs a name"),
            ("a=https://a.example.net/in,b=https://a.example.net/in", "twice"),
            ("a=https://a.example.net/in,A=https://b.example.net/in", "two sinks \"a\""),
            ("a=https://1.example.net/in,b=https://2.example.net/in,c=https://3.example.net/in,d=https://4.example.net/in,e=https://5.example.net/in", "4 SIEMs"),
            ("webhook=https://a.example.net/in", "kind of sink"),
            ("1st=https://a.example.net/in", "a letter then"),
            ("my-siem=https://a.example.net/in", "a letter then"),
            ("=https://a.example.net/in", "a letter then"),
            ("https://a.example.net/in,", "none empty"),
            (",s3://audit-archive/a", "none empty"),
            ("https://a.example.net/in,ftp://x.example.net", "use https"),
        ] {
            let e = with_archive(&[("AUDIT_EXPORT", export)]).unwrap_err();
            assert!(e.contains(why), "{export}: {e}");
        }
        // Headers need the webhook, wherever it is listed.
        assert!(with_archive(&[("AUDIT_EXPORT", "s3://audit-archive/a,https://a.example.net/in"), ("AUDIT_EXPORT_HEADERS", "a=b")]).is_ok());
        assert!(with_archive(&[("AUDIT_EXPORT", "s3://audit-archive/a,syslog+tls://logs.example.net"), ("AUDIT_EXPORT_HEADERS", "a=b")]).unwrap_err().contains("syslog"));
        assert!(with_archive(&[("AUDIT_EXPORT", "s3://audit-archive/a"), ("AUDIT_EXPORT_HEADERS", "a=b")]).unwrap_err().contains("S3 archive signs"));
    }

    #[test]
    fn several_siems_by_name_each_with_its_own_headers() {
        let export = "splunk=https://splunk.example.net:8088/services/collector/raw, Sentinel=https://sentinel.example.net/in, soc=syslog+tls://logs.example.net, s3://audit-archive/prod";
        let s = with_archive(&[("AUDIT_EXPORT", export), ("AUDIT_EXPORT_HEADERS_SPLUNK", "Authorization=Splunk splunk-token-0123456789"), ("AUDIT_EXPORT_HEADERS_SENTINEL", "x-api-key=sentinel-key-0123456789")]).unwrap();
        let names: Vec<_> = s.sinks.iter().map(|s| (s.kind(), s.name.as_deref())).collect();
        assert_eq!(names, [("webhook", Some("splunk")), ("webhook", Some("sentinel")), ("syslog", Some("soc")), ("s3", None)]);
        assert_eq!(s.headers_of("splunk"), [("Authorization".to_string(), "Splunk splunk-token-0123456789".to_string())]);
        assert_eq!(s.headers_of("sentinel"), [("x-api-key".to_string(), "sentinel-key-0123456789".to_string())]);
        let d = s.describe();
        assert!(d.contains("splunk (https://splunk.example.net:8088) as JSON lines over HTTPS, with headers") && d.contains("sentinel (https://sentinel.example.net:443)") && !d.contains("token"), "{d}");
        // The cursor follows the URL, not the name: naming a running sink keeps its place.
        let one = settings(&[("AUDIT_EXPORT", "https://splunk.example.net:8088/services/collector/raw")]).unwrap();
        assert_eq!(one.sinks[0].id, s.sinks[0].id);
        // A `=` in the URL is the URL's own.
        let s = settings(&[("AUDIT_EXPORT", "https://siem.example.net/in=1")]).unwrap();
        assert_eq!((s.sinks[0].name.as_deref(), s.sinks[0].id.as_str()), (None, "https://siem.example.net:443/in=1"));
        // One webhook, named or not, may still take AUDIT_EXPORT_HEADERS.
        let s = settings(&[("AUDIT_EXPORT", "splunk=https://a.example.net/in"), ("AUDIT_EXPORT_HEADERS", "a=b")]).unwrap();
        assert_eq!(s.headers_of("splunk"), [("a".to_string(), "b".to_string())]);
        let s = settings(&[("AUDIT_EXPORT", "a=https://a.example.net/in,b=https://b.example.net/in"), ("AUDIT_EXPORT_HEADERS_B", "k=v")]).unwrap();
        assert!(s.headers_of("a").is_empty(), "a sink without its own headers gets none");

        let two = "a=https://a.example.net/in,b=https://b.example.net/in";
        for (vars, why) in [
            (vec![("AUDIT_EXPORT", two), ("AUDIT_EXPORT_HEADERS", "k=v")], "can't say which"),
            (vec![("AUDIT_EXPORT", "a=https://a.example.net/in"), ("AUDIT_EXPORT_HEADERS", "k=v"), ("AUDIT_EXPORT_HEADERS_A", "k=w")], "both set"),
            (vec![("AUDIT_EXPORT", "a=https://a.example.net/in,soc=syslog+tls://logs.example.net"), ("AUDIT_EXPORT_HEADERS_SOC", "k=v")], "AUDIT_EXPORT_HEADERS_SOC is for an https sink"),
            (vec![("AUDIT_EXPORT", "a=https://a.example.net/in,arc=s3://audit-archive/a"), ("AUDIT_EXPORT_HEADERS_ARC", "k=v")], "S3 archive signs"),
            (vec![("AUDIT_EXPORT", two), ("AUDIT_EXPORT_HEADERS_A", "nope")], "AUDIT_EXPORT_HEADERS_A must be name=value"),
        ] {
            let e = with_archive(&vars).unwrap_err();
            assert!(e.contains(why), "{vars:?}: {e}");
        }
        // A leftover named headers file doesn't matter while export is off.
        assert!(settings(&[("AUDIT_EXPORT_HEADERS_A_FILE", "/nonexistent/superbot-headers")]).is_ok());
    }

    #[test]
    fn retention_waits_for_the_slowest_sink_and_the_view_leads_with_the_worst() {
        let siem = Arc::new(Exporter::new(Sink::parse("https://siem.example.net/in", false).unwrap(), 9));
        let other = Arc::new(Exporter::new(Sink::parse("syslog+tls://logs.example.net", false).unwrap(), 4));
        let xs = Exports { sinks: vec![siem.clone(), other.clone()] };
        assert_eq!(xs.delivered(), 4);
        assert!(xs.archive().is_none());
        let v = xs.view(10);
        assert_eq!((v["kind"].as_str(), v["pending"].as_i64(), v["sinks"].as_array().map(Vec::len)), (Some("syslog"), Some(6), Some(2)), "furthest behind: {v}");
        for _ in 0..FAILING_AFTER {
            siem.failed("down");
        }
        let v = xs.view(10);
        assert_eq!((v["kind"].as_str(), v["failing"].as_bool(), v["lastError"].as_str()), (Some("webhook"), Some(true), Some("down")), "failing comes first: {v}");
        assert_eq!(v["sinks"][1]["failing"], false);
        assert_eq!(Exports { sinks: vec![] }.view(1), json!({ "enabled": false }));
    }

    pub(crate) fn event(outcome: &str) -> AuditEvent {
        AuditEvent {
            id: 7,
            at: 0,
            time: "1970-01-01T00:00:00.000Z".into(),
            actor_kind: "user".into(),
            actor_id: Some("u1".into()),
            actor_name: None,
            actor_subject: None,
            action: "auth.login_failed".into(),
            target_type: None,
            target_id: None,
            bot_id: None,
            outcome: outcome.into(),
            ip: Some("192.0.2.1".into()),
            user_agent: None,
            details: json!({ "n": 1 }),
            actor_email: None,
            actor_role: None,
            auth_method: Some("password".into()),
            idp: None,
            idp_provider: None,
            session_id: None,
            on_behalf_of: None,
            chain_prev: Some(crate::audit_chain::GENESIS.into()),
            chain_hash: Some("ab".repeat(32)),
        }
    }

    #[test]
    fn lines_and_syslog_messages() {
        let l: Value = serde_json::from_str(&line(&event("failure"), "host-1")).unwrap();
        assert_eq!((l["schema"].as_str(), l["host"].as_str(), l["id"].as_i64(), l["action"].as_str()), (Some(SCHEMA), Some("host-1"), Some(7), Some("auth.login_failed")));
        assert_eq!((l["chainPrev"].as_str(), l["chainHash"].as_str()), (Some(crate::audit_chain::GENESIS), Some("ab".repeat(32).as_str())));
        let m = syslog(&event("failure"), "host-1", None);
        assert!(m.starts_with(&format!("<109>1 1970-01-01T00:00:00.000Z host-1 superbot {} auth.login_failed - {{", std::process::id())), "{m}");
        assert!(syslog(&event("denied"), "h", None).starts_with("<108>1 "));
        assert!(syslog(&event("success"), "h", None).starts_with("<110>1 "));
        assert!(!m.contains('\n'));
        assert_eq!(printable("a b\u{e9}", 32), "a-b-");
        assert_eq!(printable("", 32), "-");
        assert_eq!(printable(&"x".repeat(40), 32).len(), 32);
    }

    #[test]
    fn failing_is_recorded_once_until_it_recovers() {
        let x = Exporter::new(Sink::parse("https://siem.example.net/in", false).unwrap(), 5);
        assert!(!x.failed("a") && !x.failed("b"));
        assert!(x.failed("c"), "the third failure in a row");
        assert!(!x.failed("d"), "and only that one");
        let v = x.view(9);
        assert_eq!((v["pending"].as_i64(), v["failing"].as_bool(), v["lastError"].as_str()), (Some(4), Some(true), Some("d")));
        assert_eq!(x.delivered_to(9).map(|(n, _)| n), Some(4));
        assert_eq!((x.delivered(), x.delivered_to(10)), (9, None));
        assert!(!x.view(10)["failing"].as_bool().unwrap());
        for _ in 0..100 {
            let j = jitter(Duration::from_secs(8));
            assert!(j >= Duration::from_secs(6) && j <= Duration::from_secs(8), "{j:?}");
        }
    }
}
