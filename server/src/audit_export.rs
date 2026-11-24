//! SIEM export of the audit log (ADR 0122): every event, as one JSON line in the shape
//! `GET /api/audit` returns, with its place on the hash chain, sent to a SIEM, an
//! archive, or both at once (`AUDIT_EXPORT=<siem>,s3://...`, ADR 0173), or to several
//! named SIEMs (`AUDIT_EXPORT=splunk=https://...,soc=syslog+tls://...`, ADR 0191):
//!
//! - `https://<host>/<path>`: an HTTPS webhook, `POST`ed in batches as JSON lines
//!   (`application/x-ndjson`), with headers from the secret `AUDIT_EXPORT_HEADERS`, or
//!   for a named sink `AUDIT_EXPORT_HEADERS_<NAME>`.
//! - `syslog+tls://<host>[:6514]`: syslog (RFC 5424) over TLS (RFC 5425), one event a
//!   message, the JSON line as its text.
//! - Plain `http://` and `syslog+tcp://` to loopback, or with `AUDIT_EXPORT_INSECURE=on`.
//! - `s3://<bucket>[/<prefix>]`: batches as JSON-lines objects in an S3-compatible
//!   store, each locked with S3 Object Lock ([`crate::audit_archive`], ADR 0154).
//! - `azure-monitor://<host>/<dcr>/<stream>`: records in a Log Analytics workspace, for
//!   Microsoft Sentinel, through Azure Monitor's Logs Ingestion API, signed in with
//!   Entra ID ([`crate::audit_azure`], ADR 0217).
//! - `google-secops://<location>/<project>/<instance>/<log type>`: raw logs in a Google
//!   SecOps instance through the Chronicle API's `logs:import`, signed in as botd's
//!   Google identity ([`crate::audit_secops`], ADR 0237).
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
use crate::secrets::{self, SecretStore};
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
pub const SCHEMA: &str = crate::audit_line::SCHEMA;
/// RFC 5424 facility 13, "log audit".
const FACILITY: u8 = 13;
/// SIEMs `AUDIT_EXPORT` takes at most, beside one archive (ADR 0191). Each holds
/// retention back while it is behind.
pub const MAX_SIEMS: usize = 4;
const MAX_NAME: usize = 24;
const MONITOR_SIGNS_IN: &str = "Azure Monitor signs in with Entra ID (AUDIT_EXPORT_AZURE_AUTH)";
const SECOPS_SIGNS_IN: &str = "Google SecOps signs in to Google as botd (AUDIT_EXPORT_GCP_AUTH)";

enum Kind {
    /// `headers_from` names the setting the headers came from, for the startup line.
    Webhook { url: String, plain: bool, headers: Vec<(String, secrets::Secret)>, headers_from: String },
    Syslog { host: String, port: u16, tls: bool },
    Archive(Box<crate::audit_archive::Archive>),
    Monitor(Box<crate::audit_azure::Monitor>),
    SecOps(Box<crate::audit_secops::SecOps>),
}

pub struct Sink {
    kind: Kind,
    /// What logs, the API and the audit log show: never a credential.
    pub shown: String,
    /// Names the sink's cursor: a different sink starts again from the start. A name
    /// isn't part of it, so naming a running sink resumes it.
    pub id: String,
    /// From `<name>=<url>` in `AUDIT_EXPORT` (ADR 0191): picks the sink's own settings
    /// and tells it apart in events, status and metrics. Lowercase letters and digits.
    pub name: Option<String>,
    /// `AUDIT_EXPORT_START_<NAME>`, for a named sink with no cursor yet.
    start: Option<Start>,
    /// Request bodies go gzipped (`AUDIT_EXPORT_COMPRESS`, or `_<NAME>`, ADR 0227): webhook
    /// and Azure Monitor only. The archive's own setting is [`crate::audit_archive::Archive::gzip`].
    gzip: bool,
}

/// Splits `<name>=<url>` into its name and URL. An entry is named when what comes
/// before its first `=` has no `:` or `/`, so a URL with `=` in its path isn't.
fn named(entry: &str) -> Result<(Option<String>, &str), String> {
    let Some((name, url)) = entry.split_once('=').filter(|(n, _)| !n.contains([':', '/'])) else { return Ok((None, entry)) };
    let name = name.trim().to_ascii_lowercase();
    let ok = name.len() <= MAX_NAME && name.starts_with(|c: char| c.is_ascii_lowercase()) && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if !ok {
        return Err(format!("AUDIT_EXPORT: a sink's name (before its =) is 1 to {MAX_NAME} letters and digits, starting with a letter, not \"{name}\""));
    }
    if name == "file" {
        return Err("AUDIT_EXPORT: a sink can't be named \"file\", which AUDIT_EXPORT_HEADERS_FILE already means".into());
    }
    Ok((Some(name), url.trim()))
}

/// The setting `base` for the sink named `name`: `AUDIT_EXPORT_HEADERS_SPLUNK`.
fn own(base: &str, name: &str) -> String {
    format!("{base}_{}", name.to_ascii_uppercase())
}

fn start_from(var: &str, raw: &str) -> Result<Option<Start>, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "all" => Ok(Some(Start::All)),
        "new" => Ok(Some(Start::New)),
        other => Err(format!("{var} must be all or new, not \"{other}\"")),
    }
}

/// `gzip` or `off` (ADR 0227); None when unset.
pub(crate) fn compress_from(var: &str, raw: &str) -> Result<Option<bool>, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "gzip" => Ok(Some(true)),
        "off" => Ok(Some(false)),
        other => Err(format!("{var} must be gzip or off, not \"{}\"", crate::audit::clip(other, 40))),
    }
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
            Kind::Monitor(_) => "azure-monitor",
            Kind::SecOps(_) => "google-secops",
        }
    }

    #[cfg(test)]
    pub(crate) fn monitor_mut(&mut self) -> Option<&mut crate::audit_azure::Monitor> {
        match &mut self.kind {
            Kind::Monitor(m) => Some(m),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn secops_mut(&mut self) -> Option<&mut crate::audit_secops::SecOps> {
        match &mut self.kind {
            Kind::SecOps(g) => Some(g),
            _ => None,
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

    /// The name and where it goes, for logs: `splunk (https://hec.example.net:443)`.
    pub fn label(&self) -> String {
        match &self.name {
            Some(n) => format!("{n} ({})", self.shown),
            None => self.shown.clone(),
        }
    }

    fn siem(&self) -> bool {
        self.archive().is_none()
    }

    /// Whether what goes to it is gzipped: its request bodies, or the archive's objects.
    pub(crate) fn gzipped(&self) -> bool {
        self.gzip || self.archive().is_some_and(|a| a.gzip)
    }

    /// `sink`, `kind` and, for a named sink, `name`: what a SIEM rule matches on.
    fn about(&self) -> Value {
        let mut v = json!({ "sink": self.shown, "kind": self.kind() });
        if let Some(n) = &self.name {
            v["name"] = json!(n);
        }
        v
    }

    fn from_archive(a: crate::audit_archive::Archive) -> Sink {
        Sink { shown: a.shown(), id: a.id(), kind: Kind::Archive(Box::new(a)), name: None, start: None, gzip: false }
    }

    fn from_monitor(m: crate::audit_azure::Monitor) -> Sink {
        Sink { shown: m.shown(), id: m.id(), kind: Kind::Monitor(Box::new(m)), name: None, start: None, gzip: false }
    }

    fn from_secops(g: crate::audit_secops::SecOps) -> Sink {
        Sink { shown: g.shown(), id: g.id(), kind: Kind::SecOps(Box::new(g)), name: None, start: None, gzip: false }
    }

    pub fn parse(raw: &str, insecure: bool) -> Result<Sink, String> {
        let bad = |why: &str| format!("AUDIT_EXPORT must be https://<host>/<path>, syslog+tls://<host>[:<port>], azure-monitor://<host>/<dcr>/<stream>, google-secops://<location>/<project>/<instance>/<log type> or s3://<bucket>[/<prefix>]: {why}");
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
            "https" => (Kind::Webhook { url: u.to_string(), plain: false, headers: Vec::new(), headers_from: String::new() }, u.port_or_known_default()),
            "http" if plain_ok => (Kind::Webhook { url: u.to_string(), plain: true, headers: Vec::new(), headers_from: String::new() }, u.port_or_known_default()),
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
            _ => return Err(bad("use https, syslog+tls, syslog+tcp, azure-monitor, google-secops or s3")),
        };
        let port = port.map(|p| format!(":{p}")).unwrap_or_default();
        let (shown, id) = match &kind {
            Kind::Webhook { .. } => (format!("{}://{host}{port}", u.scheme()), format!("{}://{host}{port}{}", u.scheme(), u.path())),
            Kind::Syslog { .. } => (format!("{}://{host}{port}", u.scheme()), format!("{}://{host}{port}", u.scheme())),
            Kind::Archive(_) | Kind::Monitor(_) | Kind::SecOps(_) => unreachable!("s3://, azure-monitor:// and google-secops:// sinks are read with their settings"),
        };
        Ok(Sink { kind, shown, id, name: None, start: None, gzip: false })
    }
}

/// `AUDIT_EXPORT_COMPRESS` for every webhook and Azure Monitor sink, and
/// `AUDIT_EXPORT_COMPRESS_<NAME>` for a named one, which wins (ADR 0227). Syslog and Google
/// SecOps have no compression and the archive has its own `AUDIT_EXPORT_S3_COMPRESS`, so a
/// setting that would do nothing stops botd rather than look as if it did. The server-wide
/// one leaves a SecOps sink plain (ADR 0237).
fn compression(sinks: &mut [Sink], get: &dyn Fn(&str) -> String) -> Result<(), String> {
    const FOR: &str = "is for https and azure-monitor sinks";
    let all = compress_from("AUDIT_EXPORT_COMPRESS", &get("AUDIT_EXPORT_COMPRESS"))?;
    for s in sinks.iter_mut() {
        let var = s.name.as_deref().map(|n| own("AUDIT_EXPORT_COMPRESS", n));
        let mine = match &var {
            Some(v) => compress_from(v, &get(v))?,
            None => None,
        };
        let var = var.unwrap_or_default();
        match (&s.kind, mine) {
            (Kind::Webhook { .. } | Kind::Monitor(_), mine) => s.gzip = mine.or(all).unwrap_or(false),
            (Kind::Syslog { .. }, Some(true)) => return Err(format!("{var} {FOR}; syslog has no compression")),
            (Kind::SecOps(_), Some(true)) => return Err(format!("{var} {FOR}; the Chronicle API takes no compressed bodies")),
            (Kind::Archive(_), Some(_)) => return Err(format!("{var} {FOR}; the archive's is AUDIT_EXPORT_S3_COMPRESS")),
            _ => {}
        }
    }
    if all == Some(true) && !sinks.iter().any(|s| matches!(s.kind, Kind::Webhook { .. } | Kind::Monitor(_))) {
        return Err(format!("AUDIT_EXPORT_COMPRESS {FOR}, and AUDIT_EXPORT has none: syslog and Google SecOps have no compression, and the archive's is AUDIT_EXPORT_S3_COMPRESS"));
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
    /// In the order `AUDIT_EXPORT` lists them: up to [`MAX_SIEMS`] SIEMs (webhook or
    /// syslog), named when there is more than one (ADR 0191), and one S3 archive (ADR 0173).
    pub sinks: Vec<Sink>,
    /// `AUDIT_EXPORT_START`: for every sink with no cursor and no start of its own.
    pub start: Start,
}

impl Settings {
    pub fn from_env(get: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Settings, String> {
        let insecure = match get("AUDIT_EXPORT_INSECURE").trim().to_ascii_lowercase().as_str() {
            "" | "off" => false,
            "on" => true,
            other => return Err(format!("AUDIT_EXPORT_INSECURE must be on or off, not \"{other}\"")),
        };
        let start = start_from("AUDIT_EXPORT_START", &get("AUDIT_EXPORT_START"))?.unwrap_or(Start::All);
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
            let lower = v.to_ascii_lowercase();
            let mut sink = if lower.starts_with("s3://") {
                Sink::from_archive(crate::audit_archive::Archive::from_env(v, get, store)?)
            } else if lower.starts_with("azure-monitor://") {
                Sink::from_monitor(crate::audit_azure::Monitor::from_env(v, get, store)?)
            } else if lower.starts_with("google-secops://") {
                Sink::from_secops(crate::audit_secops::SecOps::from_env(v, get, store)?)
            } else {
                Sink::parse(v, insecure)?
            };
            if let Some(n) = &name {
                if sinks.iter().any(|s| s.name.as_ref() == Some(n)) {
                    return Err(format!("AUDIT_EXPORT names two sinks \"{n}\": give each its own name"));
                }
                let var = own("AUDIT_EXPORT_START", n);
                sink.start = start_from(&var, &get(&var))?;
            }
            // Two entries for one sink would share its cursor and race to move it.
            if sinks.iter().any(|s| s.id == sink.id) {
                return Err(format!("AUDIT_EXPORT lists {} twice", sink.shown));
            }
            sink.name = name;
            sinks.push(sink);
        }
        let archives = sinks.iter().filter(|s| s.archive().is_some()).count();
        let siems = sinks.len() - archives;
        if archives > 1 || siems > MAX_SIEMS {
            return Err(format!("AUDIT_EXPORT takes up to {MAX_SIEMS} SIEMs (https://, syslog+tls://, azure-monitor:// or google-secops://) and one archive (s3://) at most, split by commas"));
        }
        if siems > 1 && let Some(s) = sinks.iter().find(|s| s.siem() && s.name.is_none()) {
            return Err(format!(
                "AUDIT_EXPORT lists more than one SIEM, so name each, as <name>={}..., to tell them apart and give each its own AUDIT_EXPORT_HEADERS_<NAME>",
                s.shown
            ));
        }
        // Read only when export is on, so a leftover _FILE doesn't stop botd starting.
        if sinks.is_empty() {
            return Ok(Settings { sinks, start });
        }
        for s in &mut sinks {
            let Some(n) = s.name.clone() else { continue };
            let var = own("AUDIT_EXPORT_HEADERS", &n);
            let Some(h) = store.get(&var).map_err(|e| e.to_string())? else { continue };
            match &mut s.kind {
                Kind::Webhook { headers, headers_from, .. } => {
                    *headers = crate::obs::trace::headers(&var, h.expose())?;
                    *headers_from = var;
                }
                Kind::Syslog { .. } => return Err(format!("{var} is for an https sink; syslog over TLS has no headers")),
                Kind::Archive(_) => return Err(format!("{var} is for an https sink; the S3 archive signs with AUDIT_EXPORT_S3_ACCESS_KEY_ID and _SECRET_ACCESS_KEY")),
                Kind::Monitor(_) => return Err(format!("{var} is for an https sink; {MONITOR_SIGNS_IN}")),
                Kind::SecOps(_) => return Err(format!("{var} is for an https sink; {SECOPS_SIGNS_IN}")),
            }
        }
        if let Some(h) = store.get("AUDIT_EXPORT_HEADERS").map_err(|e| e.to_string())? {
            if siems > 1 {
                return Err("AUDIT_EXPORT_HEADERS would go to every SIEM: with more than one, give each its own AUDIT_EXPORT_HEADERS_<NAME>".into());
            }
            match sinks.iter_mut().find(|s| s.siem()).map(|s| (s.name.clone(), &mut s.kind)) {
                Some((name, Kind::Webhook { headers, headers_from, .. })) => {
                    if !headers_from.is_empty() {
                        return Err(format!("Set AUDIT_EXPORT_HEADERS or {}, not both", own("AUDIT_EXPORT_HEADERS", name.as_deref().unwrap_or_default())));
                    }
                    *headers = crate::obs::trace::headers("AUDIT_EXPORT_HEADERS", h.expose())?;
                    *headers_from = "AUDIT_EXPORT_HEADERS".into();
                }
                Some((_, Kind::Monitor(_))) => return Err(format!("AUDIT_EXPORT_HEADERS is for an https sink; {MONITOR_SIGNS_IN}")),
                Some((_, Kind::SecOps(_))) => return Err(format!("AUDIT_EXPORT_HEADERS is for an https sink; {SECOPS_SIGNS_IN}")),
                Some(_) => return Err("AUDIT_EXPORT_HEADERS is for an https sink; syslog over TLS has no headers".into()),
                None => return Err("AUDIT_EXPORT_HEADERS is for an https sink; the S3 archive signs with AUDIT_EXPORT_S3_ACCESS_KEY_ID and _SECRET_ACCESS_KEY".into()),
            }
        }
        compression(&mut sinks, get)?;
        Ok(Settings { sinks, start })
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
                    Kind::Webhook { headers, plain, headers_from, .. } => {
                        let with = if headers.is_empty() { String::new() } else { format!(", with headers ({headers_from})") };
                        let gz = if s.gzip { "gzipped " } else { "" };
                        format!("as {gz}JSON lines over {}{with}", if *plain { "plain HTTP" } else { "HTTPS" })
                    }
                    Kind::Syslog { tls: true, .. } => "as RFC 5424 syslog over TLS".into(),
                    Kind::Syslog { .. } => "as RFC 5424 syslog over plain TCP".into(),
                    Kind::Archive(a) => a.describe(),
                    Kind::Monitor(m) if s.gzip => format!("{}, gzipped", m.describe()),
                    Kind::Monitor(m) => m.describe(),
                    Kind::SecOps(g) => g.describe(),
                };
                let from = match (s.start, &s.name) {
                    (Some(Start::All), Some(n)) => format!(", starting with the history kept ({})", own("AUDIT_EXPORT_START", n)),
                    (Some(Start::New), Some(n)) => format!(", starting with new events ({})", own("AUDIT_EXPORT_START", n)),
                    _ => String::new(),
                };
                format!("every audit event to {} {how}{from}", s.label())
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
            "compress": if self.sink.gzipped() { "gzip" } else { "off" },
        });
        match &self.sink.kind {
            Kind::Archive(a) => v["archive"] = a.view(s.archived.as_ref()),
            Kind::Monitor(m) => v["azureMonitor"] = m.view(),
            Kind::SecOps(g) => v["googleSecOps"] = g.view(),
            _ => {}
        }
        v
    }
}

/// Every running export (ADR 0173): a SIEM, an archive, or both. Each has its own
/// cursor, retries and status, so one sink's outage never holds up the other.
pub struct Exports {
    pub sinks: Vec<Arc<Exporter>>,
    /// Events after this one go to every sink with their digest (ADR 0199).
    pub digests_after: i64,
}

/// The cursor, beside the sinks', past which events carry their digest (ADR 0199).
pub const DIGESTS: &str = "#digests";

/// Saved the first time the export starts with digests: past everything any sink, set
/// now or before, has delivered or cut a batch of, so a sink resending what it sent
/// before (an archive turned back on too) sends the same lines, and no sink sends
/// without its digest an event another sent with one. Every event after it has one,
/// which is what a check of the lines holds them to.
fn digests_after(app: &App, sinks: &[Arc<Exporter>]) -> i64 {
    if let Some(after) = app.db.audit_export_cursor(DIGESTS) {
        return after;
    }
    let saved = app.db.audit_export_furthest(DIGESTS);
    let after = saved.map(|s| sinks.iter().map(|x| x.delivered()).fold(s, i64::max));
    match after.and_then(|after| app.db.set_audit_export_cursor(DIGESTS, after).map(|()| after)) {
        Ok(after) => after,
        Err(e) => {
            log_warn!("Audit export: couldn't save where events start carrying their digest ({e}); sending none until botd restarts and saves it.");
            i64::MAX
        }
    }
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
            v["digestsAfter"] = json!(self.digests_after);
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
                let from = match sink.start.unwrap_or(settings.start) {
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
    let after = digests_after(app, &sinks);
    if app.audit_export.set(Arc::new(Exports { sinks: sinks.clone(), digests_after: after })).is_ok() {
        for x in sinks {
            tokio::spawn(run(app.clone(), x, after));
        }
    }
}

async fn run(app: Arc<App>, x: Arc<Exporter>, sealed_after: i64) {
    let mut out = Out::new(&x.sink);
    let host = hostname();
    let mut wait = FIRST_RETRY;
    // The archive sends a batch as it was first cut, across retries and restarts, so a
    // retry writes the same object. The batch's last id is saved before its first try.
    let batch_key = format!("{}#batch", x.sink.id);
    let start_key = format!("{}#start", x.sink.id);
    let mut retry_to: Option<i64> = x.sink.archive().and_then(|_| app.db.audit_export_cursor(&batch_key)).filter(|&b| b > x.delivered());
    'export: loop {
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
            Ok(mut rows) => 'batch: {
                if let Some(to) = retry_to {
                    rows.retain(|e| e.id <= to);
                }
                let Some(last) = rows.last().map(|e| e.id) else {
                    tokio::time::sleep(IDLE).await;
                    continue 'export;
                };
                // Delivered only once the cursor is saved; if it can't be, the batch goes again.
                let extras = match crate::audit_checkpoint::export_extras(&app.db, &rows) {
                    Ok(x) => x,
                    Err(e) => break 'batch Err(("unreadable", format!("couldn't read a checkpoint's record: {e}"))),
                };
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
                        .send(&x.sink, &rows, &extras, &host, sealed_after)
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
                    let mut d = x.sink.about();
                    d["failedTries"] = json!(tries);
                    d["failingSince"] = json!(since);
                    app.db.record(&e.details(d));
                }
                wait = FIRST_RETRY;
            }
            Err((reason, e)) => {
                let e = secrets::redact::text(&e).into_owned();
                if x.failed(&e) {
                    log_warn!("WARNING: audit export to {} is failing ({e}); events wait in the database and retention keeps them until they are delivered.", x.sink.label());
                    let pending = (app.db.audit_head() - x.delivered()).max(0);
                    let ev = Event::new(Actor::system("audit_export"), "audit.export_failing").target("audit", "export").outcome(Outcome::Failure);
                    let mut d = x.sink.about();
                    d["reason"] = json!(reason);
                    d["error"] = json!(e);
                    d["pending"] = json!(pending);
                    app.db.record(&ev.details(d));
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

/// `Retry-After` as seconds or as an HTTP date (RFC 9110); a date already past is no wait.
pub(crate) fn retry_after(v: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let v = v.trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = chrono::DateTime::parse_from_rfc2822(v).ok()?;
    Some((at.with_timezone(&chrono::Utc) - now).to_std().unwrap_or_default())
}

/// How long a throttled answer asks botd to wait, if it says.
pub(crate) fn asked_to_wait(r: &reqwest::Response) -> Option<Duration> {
    r.headers().get(reqwest::header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|v| retry_after(v, chrono::Utc::now()))
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
    line_with(e, host, None, true)
}

/// [`line`], with a checkpoint event's signed record and token (ADR 0149) as `checkpoint`,
/// and, when `sealed` (ADR 0199), the event's `chainDigest`, so the line's own fields give
/// its hash. `chainSalt` goes too only when the line's fields give that digest under it:
/// not once an erasure has cleared the salt, nor when the export redacted a secret
/// recorded in clear before botd knew it, a guess at which the salt would let anyone test.
pub fn line_with(e: &AuditEvent, host: &str, checkpoint: Option<&Value>, sealed: bool) -> String {
    line_value(e, host, checkpoint, sealed).to_string()
}

/// [`line_with`], before it is written out.
pub fn line_value(e: &AuditEvent, host: &str, checkpoint: Option<&Value>, sealed: bool) -> Value {
    let mut v = serde_json::to_value(e).unwrap_or(Value::Null);
    let digest = e.chain_digest.as_deref().filter(|_| sealed);
    let salt = e.chain_salt.as_deref().filter(|s| digest.is_some_and(|d| crate::audit_line::digest(s, &v) == d));
    if let Some(o) = v.as_object_mut() {
        o.insert("schema".into(), json!(SCHEMA));
        o.insert("host".into(), json!(host));
        if let Some(c) = checkpoint {
            o.insert("checkpoint".into(), c.clone());
        }
        if let Some(d) = digest {
            o.insert("chainDigest".into(), json!(d));
        }
        if let Some(s) = salt {
            o.insert("chainSalt".into(), json!(s));
        }
    }
    v
}

/// One event as an RFC 5424 message: facility "log audit", severity by outcome, the
/// action as MSGID, and the JSON line as the text.
pub fn syslog(e: &AuditEvent, host: &str, checkpoint: Option<&Value>, sealed: bool) -> String {
    let severity = match e.outcome.as_str() {
        "denied" => 4,
        "failure" => 5,
        _ => 6,
    };
    format!("<{}>1 {} {host} superbot {} {} - {}", FACILITY * 8 + severity, e.time, std::process::id(), printable(&e.action, 32), line_with(e, host, checkpoint, sealed))
}

/// Checkpoint records to add to their events, by event id.
type Extras = std::collections::BTreeMap<i64, Value>;

trait Stream: tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncWrite + Unpin + Send> Stream for T {}

enum Out {
    Http(reqwest::Client),
    Syslog { conn: Option<Box<dyn Stream>>, tls: Option<Arc<rustls::ClientConfig>> },
    Archive(crate::audit_archive::Client),
    Monitor(crate::audit_azure::Client),
    SecOps(crate::audit_secops::Client),
}

impl Out {
    fn new(sink: &Sink) -> Out {
        match &sink.kind {
            Kind::Webhook { plain, .. } => {
                Out::Http(reqwest::Client::builder().https_only(!plain).timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none()).build().expect("HTTP client"))
            }
            Kind::Syslog { tls, .. } => Out::Syslog { conn: None, tls: tls.then(platform_tls) },
            Kind::Archive(a) => Out::Archive(crate::audit_archive::Client::new(a)),
            Kind::Monitor(m) => Out::Monitor(crate::audit_azure::Client::new(m)),
            Kind::SecOps(g) => Out::SecOps(crate::audit_secops::Client::new(g)),
        }
    }

    /// Sends one batch: the archive's object when it wrote one. Failures carry a reason
    /// code for `audit.export_failing`.
    /// `sealed_after`: events after it carry their digest ([`Exports::digests_after`]).
    async fn send(&mut self, sink: &Sink, rows: &[AuditEvent], extras: &Extras, host: &str, sealed_after: i64) -> Result<Option<Value>, (&'static str, String)> {
        if let (Out::Archive(client), Kind::Archive(a)) = (&mut *self, &sink.kind) {
            let body: String = rows.iter().map(|e| line_with(e, host, extras.get(&e.id), e.id > sealed_after) + "\n").collect();
            return client.send(a, rows, body.into_bytes()).await.map(Some);
        }
        if let (Out::Monitor(client), Kind::Monitor(m)) = (&mut *self, &sink.kind) {
            let records: Vec<Value> = rows
                .iter()
                .flat_map(|e| {
                    let v = line_value(e, host, extras.get(&e.id), e.id > sealed_after);
                    crate::audit_azure::records(&v, &v.to_string())
                })
                .collect();
            return client.send(m, &records, sink.gzip).await.map(|()| None);
        }
        if let (Out::SecOps(client), Kind::SecOps(g)) = (&mut *self, &sink.kind) {
            let at = now();
            let logs: Vec<Value> = rows.iter().map(|e| crate::audit_secops::log(&line_with(e, host, extras.get(&e.id), e.id > sealed_after), &e.time, &crate::audit_secops::collected(e.at, at))).collect();
            return client.send(g, &logs).await.map(|()| None);
        }
        self.send_stream(sink, rows, extras, host, sealed_after).await.map(|()| None).map_err(|e| ("delivery_failed", e))
    }

    async fn send_stream(&mut self, sink: &Sink, rows: &[AuditEvent], extras: &Extras, host: &str, sealed_after: i64) -> Result<(), String> {
        match (self, &sink.kind) {
            (Out::Http(http), Kind::Webhook { url, headers, .. }) => {
                let body: String = rows.iter().map(|e| line_with(e, host, extras.get(&e.id), e.id > sealed_after) + "\n").collect();
                let mut req = http.post(url).header(reqwest::header::CONTENT_TYPE, "application/x-ndjson");
                req = match sink.gzip {
                    true => req.header(reqwest::header::CONTENT_ENCODING, "gzip").body(crate::audit_line::gzip(body.as_bytes())),
                    false => req.body(body),
                };
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
                    let m = syslog(e, host, extras.get(&e.id), e.id > sealed_after);
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
/// named sink, its name (ADR 0191), so several SIEMs of one kind are each a series.
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
            ("https://a.example.net/in,https://b.example.net/in", "name each"),
            ("https://a.example.net/in,syslog+tls://logs.example.net", "name each"),
            ("a=https://a.example.net/in,syslog+tls://logs.example.net", "<name>=syslog+tls://logs.example.net:6514"),
            ("s3://audit-archive/a,s3://audit-archive/b", "one archive"),
            ("https://a.example.net/in,s3://audit-archive/a,syslog+tls://logs.example.net", "name each"),
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

    fn headers_of(s: &Sink) -> Vec<(String, String)> {
        match &s.kind {
            Kind::Webhook { headers, .. } => headers.iter().map(|(k, v)| (k.clone(), v.expose().to_string())).collect(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn sinks_can_be_named_without_moving_their_cursor() {
        let s = settings(&[("AUDIT_EXPORT", " Splunk = https://hec.example.net/services/collector/raw ")]).unwrap().sinks.remove(0);
        assert_eq!((s.name.as_deref(), s.id.as_str()), (Some("splunk"), "https://hec.example.net:443/services/collector/raw"), "the cursor is the URL's, as before");
        assert_eq!(s.label(), "splunk (https://hec.example.net:443)");
        // A URL with = in its path isn't a name.
        let s = settings(&[("AUDIT_EXPORT", "https://siem.example.net/in/a=b")]).unwrap().sinks.remove(0);
        assert_eq!((s.name, s.id.as_str()), (None, "https://siem.example.net:443/in/a=b"));
        let s = with_archive(&[("AUDIT_EXPORT", "vault=s3://audit-archive/prod")]).unwrap().sinks.remove(0);
        assert_eq!((s.kind(), s.name.as_deref(), s.shown.as_str()), ("s3", Some("vault"), "s3://audit-archive/prod"));
        for (export, why) in [
            ("my-siem=https://a.example.net/in", "letters and digits"),
            ("1st=https://a.example.net/in", "starting with a letter"),
            ("=https://a.example.net/in", "letters and digits"),
            (&format!("{}=https://a.example.net/in", "a".repeat(MAX_NAME + 1)), "1 to 24"),
            ("file=https://a.example.net/in", "AUDIT_EXPORT_HEADERS_FILE"),
            ("a=https://a.example.net/in,a=https://b.example.net/in", "two sinks \"a\""),
            ("a=https://a.example.net/in,b=https://a.example.net/in", "lists https://a.example.net:443 twice"),
        ] {
            let e = settings(&[("AUDIT_EXPORT", export)]).unwrap_err();
            assert!(e.contains(why), "{export}: {e}");
        }
    }

    #[test]
    fn several_siems_each_with_their_own_headers() {
        let (splunk, elastic) = ("sbx-splunk-hec-token-0a1b2c3d4e", "sbx-elastic-api-key-5f6a7b8c9d");
        let all = with_archive(&[
            ("AUDIT_EXPORT", "splunk=https://hec.example.net/raw,elastic=https://es.example.net/_bulk,soc=syslog+tls://soc.example.net,s3://audit-archive/prod"),
            ("AUDIT_EXPORT_HEADERS_SPLUNK", &format!("Authorization=Splunk {splunk}")),
            ("AUDIT_EXPORT_HEADERS_ELASTIC_FILE", ""),
            ("AUDIT_EXPORT_HEADERS_ELASTIC", &format!("Authorization=ApiKey {elastic}")),
        ])
        .unwrap();
        assert_eq!(all.sinks.iter().map(|s| (s.kind(), s.name.as_deref())).collect::<Vec<_>>(), [("webhook", Some("splunk")), ("webhook", Some("elastic")), ("syslog", Some("soc")), ("s3", None)]);
        assert_eq!(headers_of(&all.sinks[0]), [("Authorization".to_string(), format!("Splunk {splunk}"))], "each webhook gets its own headers only");
        assert_eq!(headers_of(&all.sinks[1]), [("Authorization".to_string(), format!("ApiKey {elastic}"))]);
        let d = all.describe();
        assert!(d.contains("splunk (https://hec.example.net:443) as JSON lines over HTTPS, with headers (AUDIT_EXPORT_HEADERS_SPLUNK)") && d.contains("with headers (AUDIT_EXPORT_HEADERS_ELASTIC)") && d.contains("soc (syslog+tls://soc.example.net:6514)"), "{d}");
        assert!(!d.contains(splunk) && !d.contains(elastic) && !format!("{all:?}").contains(splunk));
        assert!(!secrets::redact::text(&format!("x {elastic} y")).contains(elastic), "registered, so an error quoting it is masked");
        // A named SIEM without headers of its own sends none.
        let s = settings(&[("AUDIT_EXPORT", "a=https://a.example.net/in,b=https://b.example.net/in"), ("AUDIT_EXPORT_HEADERS_A", "X-Token=1")]).unwrap();
        assert_eq!((headers_of(&s.sinks[0]).len(), headers_of(&s.sinks[1]).len()), (1, 0));

        let five: Vec<String> = (0..=MAX_SIEMS).map(|i| format!("s{i}=https://s{i}.example.net/in")).collect();
        let four = five[..MAX_SIEMS].join(",");
        assert_eq!(settings(&[("AUDIT_EXPORT", &four)]).unwrap().sinks.len(), MAX_SIEMS);
        for (vars, why) in [
            (vec![("AUDIT_EXPORT", five.join(","))], "up to 4 SIEMs"),
            (vec![("AUDIT_EXPORT", "a=https://a.example.net/in,b=https://b.example.net/in".into()), ("AUDIT_EXPORT_HEADERS", "X=1".into())], "would go to every SIEM"),
            (vec![("AUDIT_EXPORT", "a=https://a.example.net/in".into()), ("AUDIT_EXPORT_HEADERS", "X=1".into()), ("AUDIT_EXPORT_HEADERS_A", "X=2".into())], "AUDIT_EXPORT_HEADERS or AUDIT_EXPORT_HEADERS_A, not both"),
            (vec![("AUDIT_EXPORT", "a=https://a.example.net/in,soc=syslog+tls://soc.example.net".into()), ("AUDIT_EXPORT_HEADERS_SOC", "X=1".into())], "AUDIT_EXPORT_HEADERS_SOC is for an https sink; syslog"),
            (vec![("AUDIT_EXPORT", "a=https://a.example.net/in".into()), ("AUDIT_EXPORT_HEADERS_A", "no-equals".into())], "AUDIT_EXPORT_HEADERS_A must be name=value"),
        ] {
            let vars: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let e = settings(&vars).unwrap_err();
            assert!(e.contains(why), "{vars:?}: {e}");
        }
        let e = with_archive(&[("AUDIT_EXPORT", "vault=s3://audit-archive/prod"), ("AUDIT_EXPORT_HEADERS_VAULT", "X=1")]).unwrap_err();
        assert!(e.contains("AUDIT_EXPORT_HEADERS_VAULT is for an https sink; the S3 archive"), "{e}");
        // One SIEM, named or not, still takes AUDIT_EXPORT_HEADERS, beside an archive too.
        let s = with_archive(&[("AUDIT_EXPORT", "splunk=https://hec.example.net/raw,s3://audit-archive/prod"), ("AUDIT_EXPORT_HEADERS", "X-Token=1")]).unwrap();
        assert_eq!(headers_of(&s.sinks[0]).len(), 1);
        assert!(s.describe().contains("with headers (AUDIT_EXPORT_HEADERS)"));
    }

    #[test]
    fn each_named_sink_can_start_on_its_own() {
        let s = with_archive(&[
            ("AUDIT_EXPORT", "splunk=https://hec.example.net/raw,soc=syslog+tls://soc.example.net,s3://audit-archive/prod"),
            ("AUDIT_EXPORT_START", "new"),
            ("AUDIT_EXPORT_START_SPLUNK", "ALL"),
        ])
        .unwrap();
        assert_eq!(s.start, Start::New);
        assert_eq!(s.sinks.iter().map(|s| s.start).collect::<Vec<_>>(), [Some(Start::All), None, None], "the others take AUDIT_EXPORT_START");
        let d = s.describe();
        assert!(d.contains("over HTTPS, starting with the history kept (AUDIT_EXPORT_START_SPLUNK)") && !d.contains("AUDIT_EXPORT_START_SOC"), "{d}");
        let e = settings(&[("AUDIT_EXPORT", "soc=syslog+tls://soc.example.net"), ("AUDIT_EXPORT_START_SOC", "later")]).unwrap_err();
        assert!(e.contains("AUDIT_EXPORT_START_SOC must be all or new"), "{e}");
    }

    #[test]
    fn compression_is_for_webhooks_and_azure_monitor_and_a_named_sinks_own_wins() {
        let gz = |s: &Settings| s.sinks.iter().map(|s| s.gzip).collect::<Vec<_>>();
        let s = settings(&[("AUDIT_EXPORT", "https://siem.example.net/in")]).unwrap();
        assert_eq!(gz(&s), [false], "off unless asked: not every collector takes gzip");
        let s = settings(&[("AUDIT_EXPORT", "https://siem.example.net/in"), ("AUDIT_EXPORT_COMPRESS", "Gzip")]).unwrap();
        assert_eq!(gz(&s), [true]);
        assert!(s.describe().contains("as gzipped JSON lines over HTTPS"), "{}", s.describe());
        assert_eq!(Exporter::new(s.sinks.into_iter().next().unwrap(), 0).view(0)["compress"], "gzip");

        let all = with_archive(&[
            ("AUDIT_EXPORT", "splunk=https://hec.example.net/raw,mdr=https://mdr.example.net/in,soc=syslog+tls://soc.example.net,s3://audit-archive/prod"),
            ("AUDIT_EXPORT_COMPRESS", "gzip"),
            ("AUDIT_EXPORT_COMPRESS_MDR", "off"),
            ("AUDIT_EXPORT_COMPRESS_SOC", "off"),
        ])
        .unwrap();
        assert_eq!(gz(&all), [true, false, false, false], "the archive's objects are AUDIT_EXPORT_S3_COMPRESS's, and syslog has none");
        let s = settings(&[("AUDIT_EXPORT", "a=https://a.example.net/in,b=https://b.example.net/in"), ("AUDIT_EXPORT_COMPRESS_B", "gzip")]).unwrap();
        assert_eq!(gz(&s), [false, true]);
        let d = s.describe();
        assert!(d.contains("a (https://a.example.net:443) as JSON lines") && d.contains("b (https://b.example.net:443) as gzipped JSON lines"), "{d}");
        assert!(settings(&[("AUDIT_EXPORT_COMPRESS", "gzip")]).is_ok(), "a leftover setting doesn't matter while export is off");

        for (vars, why) in [
            (vec![("AUDIT_EXPORT", "https://siem.example.net/in"), ("AUDIT_EXPORT_COMPRESS", "br")], "AUDIT_EXPORT_COMPRESS must be gzip or off, not \"br\""),
            (vec![("AUDIT_EXPORT", "a=https://a.example.net/in"), ("AUDIT_EXPORT_COMPRESS_A", "yes")], "AUDIT_EXPORT_COMPRESS_A must be gzip or off"),
            (vec![("AUDIT_EXPORT", "syslog+tls://logs.example.net"), ("AUDIT_EXPORT_COMPRESS", "gzip")], "AUDIT_EXPORT has none: syslog and Google SecOps have no compression"),
            (vec![("AUDIT_EXPORT", "a=https://a.example.net/in,soc=syslog+tls://soc.example.net"), ("AUDIT_EXPORT_COMPRESS_SOC", "gzip")], "AUDIT_EXPORT_COMPRESS_SOC is for https and azure-monitor sinks; syslog has no compression"),
        ] {
            let e = settings(&vars).unwrap_err();
            assert!(e.contains(why), "{vars:?}: {e}");
        }
        let e = with_archive(&[("AUDIT_EXPORT", "s3://audit-archive/prod"), ("AUDIT_EXPORT_COMPRESS", "gzip")]).unwrap_err();
        assert!(e.contains("the archive's is AUDIT_EXPORT_S3_COMPRESS"), "{e}");
        let e = with_archive(&[("AUDIT_EXPORT", "vault=s3://audit-archive/prod"), ("AUDIT_EXPORT_COMPRESS_VAULT", "gzip")]).unwrap_err();
        assert!(e.contains("AUDIT_EXPORT_COMPRESS_VAULT is for https and azure-monitor sinks; the archive's is AUDIT_EXPORT_S3_COMPRESS"), "{e}");
        let s = with_archive(&[("AUDIT_EXPORT", "s3://audit-archive/prod"), ("AUDIT_EXPORT_S3_COMPRESS", "gzip")]).unwrap();
        assert_eq!(Exporter::new(s.sinks.into_iter().next().unwrap(), 0).view(0)["compress"], "gzip", "the archive's shows the same way");
    }

    #[test]
    fn retry_after_is_seconds_or_an_http_date() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-24T12:30:00Z").unwrap().with_timezone(&chrono::Utc);
        assert_eq!(retry_after(" 45 ", now), Some(Duration::from_secs(45)));
        assert_eq!(retry_after("Tue, 24 Nov 2026 12:32:00 GMT", now), Some(Duration::from_secs(120)), "an HTTP date, as RFC 9110 allows");
        assert_eq!(retry_after("Tue, 24 Nov 2026 12:29:00 GMT", now), Some(Duration::ZERO), "already past");
        assert_eq!(retry_after("soon", now), None);
        assert_eq!(retry_after("-5", now), None);
    }

    #[test]
    fn named_sinks_headers_are_server_secrets() {
        use crate::secrets::external::{scope_of, Scope};
        for name in ["AUDIT_EXPORT_HEADERS_SPLUNK", "AUDIT_EXPORT_HEADERS_S3"] {
            assert!(secrets::server_secret(name), "{name}");
            assert_eq!(scope_of(name), Some(Scope::Server), "{name}: read from botd's own folder, never a Bot's");
        }
        for name in ["AUDIT_EXPORT_HEADERS_", "AUDIT_EXPORT_HEADERS_FILE", "AUDIT_EXPORT_HEADERS_MY_SIEM", "AUDIT_EXPORT_START_SPLUNK"] {
            assert!(!secrets::server_secret(name), "{name}");
        }
    }

    #[test]
    fn retention_waits_for_the_slowest_sink_and_the_view_leads_with_the_worst() {
        let siem = Arc::new(Exporter::new(Sink::parse("https://siem.example.net/in", false).unwrap(), 9));
        let other = Arc::new(Exporter::new(Sink::parse("syslog+tls://logs.example.net", false).unwrap(), 4));
        let xs = Exports { sinks: vec![siem.clone(), other.clone()], digests_after: 0 };
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
        assert_eq!(Exports { sinks: vec![], digests_after: 0 }.view(1), json!({ "enabled": false }));
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
            chain_digest: Some("cd".repeat(32)),
            chain_salt: Some("ef".repeat(16)),
        }
    }

    #[test]
    fn lines_and_syslog_messages() {
        let l: Value = serde_json::from_str(&line(&event("failure"), "host-1")).unwrap();
        assert_eq!((l["schema"].as_str(), l["host"].as_str(), l["id"].as_i64(), l["action"].as_str()), (Some(SCHEMA), Some("host-1"), Some(7), Some("auth.login_failed")));
        assert_eq!((l["chainPrev"].as_str(), l["chainHash"].as_str()), (Some(crate::audit_chain::GENESIS), Some("ab".repeat(32).as_str())));
        let m = syslog(&event("failure"), "host-1", None, true);
        assert!(m.starts_with(&format!("<109>1 1970-01-01T00:00:00.000Z host-1 superbot {} auth.login_failed - {{", std::process::id())), "{m}");
        assert!(syslog(&event("denied"), "h", None, true).starts_with("<108>1 "));
        assert!(syslog(&event("success"), "h", None, true).starts_with("<110>1 "));
        assert!(!m.contains('\n'));
        assert_eq!(printable("a b\u{e9}", 32), "a-b-");
        assert_eq!(printable("", 32), "-");
        assert_eq!(printable(&"x".repeat(40), 32).len(), 32);
    }

    #[test]
    fn a_line_carries_its_digest_and_its_salt_only_when_that_hides_nothing() {
        use crate::audit::{Actor, Event};
        use crate::audit_line::{Bound, check};
        let app = crate::runner::test_app();
        let read = |id: i64| app.db.audit_events(&Default::default(), 1000, false).into_iter().find(|e| e.id == id).unwrap();
        let exported = |id: i64, sealed: bool| -> Value { serde_json::from_str(&line_with(&read(id), "h", None, sealed)).unwrap() };

        let plain = app.db.try_record(&Event::new(Actor::system("test"), "test.plain").details(json!({ "n": 1 }))).unwrap();
        let v = exported(plain, true);
        assert!(v["chainDigest"].is_string() && v["chainSalt"].is_string(), "{v}");
        assert_eq!(check(&v), Ok(Bound::All), "{v}");
        let mut changed = v.clone();
        changed["details"]["n"] = json!(2);
        assert!(check(&changed).unwrap_err().contains("digest"));
        let mut moved = v.clone();
        moved["outcome"] = json!("failure");
        assert!(check(&moved).unwrap_err().contains("chainHash"));
        let before = exported(plain, false);
        assert!(before.get("chainDigest").is_none() && before.get("chainSalt").is_none(), "at or before the marker: {before}");
        assert_eq!(check(&before), Ok(Bound::None));

        // A value that became a known secret after it was written is masked on the way
        // out; its salt would let anyone test guesses at it against the digest.
        let later = "became-secret-later-5d21ab";
        let masked = app.db.try_record(&Event::new(Actor::system("test"), "test.masked").details(json!({ "note": later }))).unwrap();
        crate::secrets::redact::register(later);
        let v = exported(masked, true);
        crate::secrets::redact::forget(later);
        assert!(!v.to_string().contains(later), "{v}");
        assert!(v["chainDigest"].is_string() && v.get("chainSalt").is_none(), "{v}");
        assert_eq!(check(&v), Ok(Bound::Fixed), "{v}");

        // Erased: no salt to send, and its erasable fields are rewritten.
        let erased = app.db.try_record(&Event::new(Actor::system("test"), "test.erased").details(json!({ "name": "Ada" }))).unwrap();
        app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
        app.db.execute_raw(&format!("UPDATE audit_events SET chain_salt = NULL, details = '{{\"name\":\"erased-1\"}}' WHERE id = {erased}")).unwrap();
        let v = exported(erased, true);
        assert!(v["chainDigest"].is_string() && v.get("chainSalt").is_none(), "{v}");
        assert_eq!(check(&v), Ok(Bound::Fixed), "{v}");
    }

    #[test]
    fn digests_start_past_every_sink_ever_set_and_stay_there() {
        let app = crate::runner::test_app();
        // An archive turned off for now, which had cut a batch to 100 and delivered to 80.
        let old = "s3://s3.example.net/audit-archive/prod";
        app.db.set_audit_export_cursor(old, 80).unwrap();
        app.db.set_audit_export_cursor(&format!("{old}#batch"), 100).unwrap();
        app.db.set_audit_export_cursor("https://siem.example.net:443/in", 50).unwrap();
        app.db.set_setting(&format!("audit_export:{old}#checked"), r#"{"head":{"id":900}}"#);
        assert_eq!(digests_after(&app, &[]), 100, "a batch it resends when back is the same as before");
        app.db.set_audit_export_cursor(old, 400).unwrap();
        assert_eq!(digests_after(&app, &[]), 100, "saved once");
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
