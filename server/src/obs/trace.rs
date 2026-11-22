//! Traces (ADR 0118): a span per HTTP request and per Bot run, with child spans for each
//! harness attempt, tool call, approval check and call to a machine's agent, exported
//! over OTLP/HTTP (JSON) to any OpenTelemetry collector or tracing backend. Off unless
//! `TRACES_OTLP_ENDPOINT` is set.
//!
//! Like `/metrics` and error reports, a span is built field by field from what botd's
//! code names: attribute keys are `&'static str`, values are botd's own ids, harness and
//! tool names, route templates, statuses, counts and timings. Never a prompt, a chat, a
//! tool's input, a path as sent, a person's id, name or email, or a secret. Every string
//! is passed through secret redaction and stripped of emails before it's kept.
//!
//! The settings are SuperBot's own (`TRACES_*`), not OpenTelemetry's `OTEL_*`: harnesses
//! inherit botd's environment, and some of them export their own telemetry, prompts
//! included, when they see `OTEL_*`.

use super::log::{self, Level};
use super::metrics::{family, sample};
use crate::secrets::{self, SecretStore};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

pub const OUTCOMES: [&str; 3] = ["sent", "failed", "dropped"];
/// Finished spans waiting to be sent; more are dropped and counted.
pub const QUEUE: usize = 2048;
/// Spans per export request.
pub const BATCH: usize = 256;
/// How often spans waiting are sent, if a batch hasn't filled first.
pub const FLUSH_EVERY: Duration = Duration::from_secs(5);
const TIMEOUT: Duration = Duration::from_secs(10);
/// Attributes and events one span keeps; more are dropped.
const MAX_ATTRS: usize = 32;
const MAX_EVENTS: usize = 64;
/// Runs and queued messages remembered for their trace; the oldest are forgotten.
const MAX_REMEMBERED: usize = 4096;
pub const TRACEPARENT: &str = "traceparent";

#[derive(Debug)]
pub struct Settings {
    pub endpoint: Option<Endpoint>,
    /// The share of new traces kept, 0 to 1.
    pub ratio: f64,
    /// Whether a `traceparent` sent in (by a proxy) is joined.
    pub accept_parent: bool,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { endpoint: None, ratio: 1.0, accept_parent: false }
    }
}

/// Where spans go, and the headers sent with them. The headers are a secret.
pub struct Endpoint {
    url: String,
    host: String,
    plain: bool,
    headers: Vec<(String, secrets::Secret)>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Endpoint({})", self.host)
    }
}

impl Endpoint {
    /// An OTLP/HTTP URL: `https://<host>[:<port>]` (spans go to `/v1/traces`) or the
    /// full traces URL. Plain http only to loopback, unless `insecure`.
    pub fn parse(raw: &str, insecure: bool) -> Result<Endpoint, String> {
        let bad = |why: &str| format!("TRACES_OTLP_ENDPOINT must be an OTLP/HTTP URL such as https://<collector-host>:4318: {why}");
        let u = url::Url::parse(raw.trim()).map_err(|_| bad("it isn't a URL"))?;
        let host = u.host_str().ok_or_else(|| bad("no host"))?.to_string();
        let loopback = matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]");
        let plain = match u.scheme() {
            "https" => false,
            "http" if loopback || insecure => true,
            "http" => return Err(bad("use https (plain http only to loopback, or set TRACES_OTLP_INSECURE=on for a collector on a private network)")),
            _ => return Err(bad("use https")),
        };
        if !u.username().is_empty() || u.password().is_some() {
            return Err(bad("put credentials in TRACES_OTLP_HEADERS, not the URL"));
        }
        if u.query().is_some() || u.fragment().is_some() {
            return Err(bad("no query or fragment"));
        }
        let mut url = u.clone();
        if matches!(u.path(), "" | "/") {
            url.set_path("/v1/traces");
        }
        Ok(Endpoint { url: url.to_string(), host, plain, headers: Vec::new() })
    }

    fn with_headers(mut self, raw: &str) -> Result<Endpoint, String> {
        self.headers = headers("TRACES_OTLP_HEADERS", raw)?;
        Ok(self)
    }
}

/// `name=value` pairs split by commas, as OpenTelemetry's `OTEL_EXPORTER_OTLP_HEADERS`,
/// from the secret `var`. Each value is registered for redaction.
pub fn headers(var: &str, raw: &str) -> Result<Vec<(String, secrets::Secret)>, String> {
    let mut out = Vec::new();
    for pair in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').ok_or(format!("{var} must be name=value pairs split by commas"))?;
        let (k, v) = (k.trim(), v.trim());
        if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(format!("{var}: a header name is letters, digits, '-' and '_'"));
        }
        if v.is_empty() || reqwest::header::HeaderValue::from_str(v).is_err() {
            return Err(format!("{var}: the value of {k} isn't a valid header value"));
        }
        secrets::redact::register(v);
        // `Bearer <token>`: the token may turn up on its own.
        if let Some((_, token)) = v.rsplit_once(' ') {
            secrets::redact::register(token.trim());
        }
        out.push((k.to_string(), secrets::Secret::new(v)));
    }
    Ok(out)
}

impl Settings {
    pub fn from_env(get: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Settings, String> {
        let ratio = match get("TRACES_SAMPLE_RATIO").trim() {
            "" => 1.0,
            r => r.parse::<f64>().ok().filter(|r| (0.0..=1.0).contains(r)).ok_or_else(|| format!("TRACES_SAMPLE_RATIO must be a number from 0 to 1, not \"{r}\""))?,
        };
        let accept_parent = match get("TRACES_PARENT").trim().to_ascii_lowercase().as_str() {
            "" | "ignore" => false,
            "accept" => true,
            other => return Err(format!("TRACES_PARENT must be ignore or accept, not \"{other}\"")),
        };
        let insecure = match get("TRACES_OTLP_INSECURE").trim().to_ascii_lowercase().as_str() {
            "" | "off" => false,
            "on" => true,
            other => return Err(format!("TRACES_OTLP_INSECURE must be on or off, not \"{other}\"")),
        };
        let raw = get("TRACES_OTLP_ENDPOINT");
        let endpoint = match raw.trim() {
            "" | "off" => None,
            v => {
                let e = Endpoint::parse(v, insecure)?;
                // Read only when traces are on, so a leftover _FILE doesn't stop botd starting.
                let headers = store.get("TRACES_OTLP_HEADERS").map_err(|e| e.to_string())?;
                Some(match headers {
                    Some(h) => e.with_headers(h.expose())?,
                    None => e,
                })
            }
        };
        Ok(Settings { endpoint, ratio, accept_parent })
    }

    pub fn describe(&self) -> String {
        match &self.endpoint {
            None => "traces off (TRACES_OTLP_ENDPOINT)".into(),
            Some(e) => format!(
                "traces to {} over OTLP/HTTP{}, keeping {}% of new traces{}",
                e.host,
                if e.headers.is_empty() { "" } else { " with headers (TRACES_OTLP_HEADERS)" },
                (self.ratio * 100.0 * 100.0).round() / 100.0,
                if self.accept_parent { ", joining a traceparent sent in" } else { "" }
            ),
        }
    }
}

/// Where a span sits in its trace, as W3C Trace Context spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ctx {
    pub trace: u128,
    pub span: u64,
    pub sampled: bool,
}

impl Ctx {
    pub fn trace_id(&self) -> String {
        format!("{:032x}", self.trace)
    }

    pub fn span_id(&self) -> String {
        format!("{:016x}", self.span)
    }

    pub fn traceparent(&self) -> String {
        format!("00-{}-{}-{:02x}", self.trace_id(), self.span_id(), self.sampled as u8)
    }

    /// A `traceparent` header: version, trace id, parent id and flags, lowercase hex.
    /// Anything else, an all-zero id, or version `ff`, is None.
    pub fn parse(h: &str) -> Option<Ctx> {
        let parts: Vec<&str> = h.trim().split('-').collect();
        let hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let [version, trace, span, flags, rest @ ..] = &parts[..] else { return None };
        let (version, trace, span, flags) = (*version, *trace, *span, *flags);
        if !hex(version, 2) || version == "ff" || (version == "00" && !rest.is_empty()) || !hex(trace, 32) || !hex(span, 16) || !hex(flags, 2) {
            return None;
        }
        let (trace, span) = (u128::from_str_radix(trace, 16).ok()?, u64::from_str_radix(span, 16).ok()?);
        let flags = u8::from_str_radix(flags, 16).ok()?;
        (trace != 0 && span != 0).then_some(Ctx { trace, span, sampled: flags & 1 == 1 })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Internal,
    Server,
    Client,
}

impl Kind {
    fn otlp(self) -> u8 {
        match self {
            Kind::Internal => 1,
            Kind::Server => 2,
            Kind::Client => 3,
        }
    }
}

/// An attribute's value. Strings are scrubbed when set.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl From<&str> for Val {
    fn from(s: &str) -> Val {
        Val::Str(super::errors::scrub(s))
    }
}
impl From<String> for Val {
    fn from(s: String) -> Val {
        Val::from(s.as_str())
    }
}
impl From<&String> for Val {
    fn from(s: &String) -> Val {
        Val::from(s.as_str())
    }
}
impl From<bool> for Val {
    fn from(b: bool) -> Val {
        Val::Bool(b)
    }
}
impl From<i64> for Val {
    fn from(n: i64) -> Val {
        Val::Int(n)
    }
}
impl From<u64> for Val {
    fn from(n: u64) -> Val {
        Val::Int(n.min(i64::MAX as u64) as i64)
    }
}
impl From<u32> for Val {
    fn from(n: u32) -> Val {
        Val::Int(n as i64)
    }
}
impl From<u16> for Val {
    fn from(n: u16) -> Val {
        Val::Int(n as i64)
    }
}
impl From<usize> for Val {
    fn from(n: usize) -> Val {
        Val::from(n as u64)
    }
}

impl Val {
    fn otlp(&self) -> Value {
        match self {
            Val::Str(s) => json!({ "stringValue": s }),
            Val::Int(n) => json!({ "intValue": n.to_string() }),
            Val::Bool(b) => json!({ "boolValue": b }),
        }
    }
}

/// A tool's name as harnesses give it (`Bash`, `apply_patch`, `mcp__github__search`):
/// letters, digits and `_.:-`, up to 64; anything else is `other`.
pub fn tool_name(name: &str) -> &str {
    let ok = !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'));
    if ok { name } else { "other" }
}

enum Msg {
    Span(Value),
    Flush(tokio::sync::oneshot::Sender<()>),
}

enum Sink {
    Export(tokio::sync::mpsc::Sender<Msg>),
    #[cfg(test)]
    Capture(Mutex<Vec<Value>>),
}

/// One tracer's sampling and where its spans go.
struct Shared {
    ratio: f64,
    accept_parent: bool,
    sink: Sink,
    counts: [AtomicU64; 3],
}

impl Shared {
    fn count(&self, outcome: usize, n: u64) {
        self.counts[outcome].fetch_add(n, Ordering::Relaxed);
    }

    fn keep(&self, trace: u128) -> bool {
        if self.ratio >= 1.0 {
            return true;
        }
        ((trace >> 64) as u64) < (self.ratio * u64::MAX as f64) as u64
    }

    fn finish(&self, span: Value) {
        match &self.sink {
            Sink::Export(tx) => {
                if tx.try_send(Msg::Span(span)).is_err() {
                    self.count(2, 1);
                }
            }
            #[cfg(test)]
            Sink::Capture(spans) => {
                spans.lock().unwrap_or_else(|e| e.into_inner()).push(span);
                self.count(0, 1);
            }
        }
    }
}

/// One per database, like `Metrics`, so each test's app traces on its own. Off until
/// `start` is given an endpoint.
#[derive(Default)]
pub struct Tracer(RwLock<Option<Arc<Shared>>>);

impl Tracer {
    fn shared(&self) -> Option<Arc<Shared>> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn on(&self) -> bool {
        self.0.read().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    pub fn accepts_parent(&self) -> bool {
        self.shared().is_some_and(|s| s.accept_parent)
    }

    /// Starts exporting, if `s` has an endpoint. In a Tokio runtime.
    pub fn start(&self, s: &Settings) {
        let Some(e) = &s.endpoint else {
            *self.0.write().unwrap_or_else(|e| e.into_inner()) = None;
            return;
        };
        let (tx, rx) = tokio::sync::mpsc::channel(QUEUE);
        let shared = Arc::new(Shared { ratio: s.ratio, accept_parent: s.accept_parent, sink: Sink::Export(tx), counts: Default::default() });
        let http = reqwest::Client::builder().https_only(!e.plain).timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none()).build().expect("HTTP client");
        let headers = e.headers.iter().map(|(k, v)| (k.clone(), secrets::Secret::new(v.expose()))).collect();
        tokio::spawn(export(rx, http, e.url.clone(), headers, Arc::downgrade(&shared)));
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Some(shared);
    }

    /// Keeps finished spans in memory instead of sending them, for tests to read.
    #[cfg(test)]
    pub fn capture(&self, ratio: f64, accept_parent: bool) {
        let shared = Shared { ratio, accept_parent, sink: Sink::Capture(Mutex::new(Vec::new())), counts: Default::default() };
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(shared));
    }

    /// The spans `capture` kept, finished ones only, oldest first.
    #[cfg(test)]
    pub fn captured(&self) -> Vec<Value> {
        match self.shared().as_deref().map(|s| &s.sink) {
            Some(Sink::Capture(spans)) => spans.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            _ => Vec::new(),
        }
    }

    /// A new span: a child of `parent` (in its trace, keeping its sampling decision), or
    /// the root of a new trace, kept at the tracer's ratio. Inert when traces are off.
    pub fn span(&self, name: &str, kind: Kind, parent: Option<Ctx>) -> Span {
        let Some(shared) = self.shared() else { return Span::default() };
        Span::new(shared, name, kind, parent)
    }

    /// Sends what's waiting now, for up to `within`. On shutdown.
    pub async fn flush(&self, within: Duration) {
        let Some(shared) = self.shared() else { return };
        #[allow(irrefutable_let_patterns)]
        let Sink::Export(tx) = &shared.sink else { return };
        let (done, wait) = tokio::sync::oneshot::channel();
        // A full queue and a slow collector mustn't hold shutdown past `within`.
        let _ = tokio::time::timeout(within, async {
            if tx.send(Msg::Flush(done)).await.is_ok() {
                let _ = wait.await;
            }
        })
        .await;
    }

    pub fn render(&self, out: &mut String) {
        let shared = self.shared();
        family(out, "superbot_tracing_enabled", "gauge", "1 when botd exports traces over OTLP (TRACES_OTLP_ENDPOINT, ADR 0118).");
        sample(out, "superbot_tracing_enabled", &[], shared.is_some() as u8 as f64);
        family(
            out,
            "superbot_trace_spans_total",
            "counter",
            "Spans exported, by outcome: sent, failed (the collector refused or didn't answer) or dropped (the queue was full).",
        );
        for (i, outcome) in OUTCOMES.iter().enumerate() {
            let n = shared.as_ref().map_or(0, |s| s.counts[i].load(Ordering::Relaxed));
            sample(out, "superbot_trace_spans_total", &[("outcome", outcome)], n as f64);
        }
    }
}

/// Batches spans and posts them to the collector until the tracer is gone.
async fn export(mut rx: tokio::sync::mpsc::Receiver<Msg>, http: reqwest::Client, url: String, headers: Vec<(String, secrets::Secret)>, shared: std::sync::Weak<Shared>) {
    let mut batch: Vec<Value> = Vec::new();
    let mut tick = tokio::time::interval(FLUSH_EVERY);
    let mut failing = false;
    loop {
        let flushed = tokio::select! {
            m = rx.recv() => match m {
                Some(Msg::Span(s)) => {
                    batch.push(s);
                    if batch.len() < BATCH {
                        continue;
                    }
                    None
                }
                Some(Msg::Flush(done)) => Some(done),
                None => return,
            },
            _ = tick.tick() => None,
        };
        if !batch.is_empty() {
            let spans = std::mem::take(&mut batch);
            let n = spans.len() as u64;
            let mut req = http.post(&url).header(reqwest::header::CONTENT_TYPE, "application/json");
            for (k, v) in &headers {
                req = req.header(k, v.expose());
            }
            let outcome = match req.body(envelope(spans).to_string()).send().await {
                Ok(r) if r.status().is_success() => Ok(rejected(r).await.min(n)),
                Ok(r) => Err(format!("refused them: HTTP {}", r.status().as_u16())),
                Err(e) if e.is_timeout() => Err("timed out".into()),
                Err(e) if e.is_connect() => Err("couldn't be reached".into()),
                Err(_) => Err("failed".into()),
            };
            let Some(s) = shared.upgrade() else { return };
            let (failed, why) = match outcome {
                Ok(0) => (0, None),
                // Accepted spans aren't sent again; the rest are lost, as when it's down.
                Ok(k) => (k, Some(format!("rejected {k} of {n}"))),
                Err(why) => (n, Some(why)),
            };
            s.count(0, n - failed);
            s.count(1, failed);
            match why {
                None => failing = false,
                // Once until it works again: a collector that's down would fill the log.
                Some(why) if !std::mem::replace(&mut failing, true) => {
                    log::line(Level::Warn, &format!("WARNING: sending spans to the trace collector: it {why}"));
                }
                Some(_) => {}
            }
        }
        if let Some(done) = flushed {
            let _ = done.send(());
        }
    }
}

/// How many spans an accepted export says it rejected (OTLP's `partialSuccess`), from
/// the first 64 KiB of its reply. An empty or unreadable reply rejected none.
async fn rejected(mut r: reqwest::Response) -> u64 {
    let mut body = Vec::new();
    while body.len() < 64 * 1024 {
        match r.chunk().await {
            Ok(Some(c)) => body.extend_from_slice(&c),
            _ => break,
        }
    }
    let v: Value = serde_json::from_slice(&body).unwrap_or_default();
    // proto3 JSON writes int64 as a string; some collectors write a number.
    let n = &v["partialSuccess"]["rejectedSpans"];
    n.as_u64().or_else(|| n.as_str()?.parse().ok()).unwrap_or(0)
}

/// OTLP's `ExportTraceServiceRequest`, as JSON.
fn envelope(spans: Vec<Value>) -> Value {
    let version = env!("CARGO_PKG_VERSION");
    json!({
        "resourceSpans": [{
            "resource": { "attributes": [
                { "key": "service.name", "value": { "stringValue": "superbot-botd" } },
                { "key": "service.version", "value": { "stringValue": version } },
            ] },
            "scopeSpans": [{ "scope": { "name": "superbot.botd", "version": version }, "spans": spans }],
        }],
    })
}

fn now_ns() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos().min(u64::MAX as u128) as u64)
}

fn new_trace() -> u128 {
    loop {
        let b = crate::random_bytes(16);
        let id = u128::from_be_bytes(b.try_into().unwrap_or([0; 16]));
        if id != 0 {
            return id;
        }
    }
}

fn new_span() -> u64 {
    loop {
        let b = crate::random_bytes(8);
        let id = u64::from_be_bytes(b.try_into().unwrap_or([0; 8]));
        if id != 0 {
            return id;
        }
    }
}

struct State {
    ctx: Ctx,
    parent: Option<u64>,
    name: String,
    attrs: Vec<(&'static str, Val)>,
    events: Vec<Value>,
    error: bool,
    end: Option<u64>,
}

struct Live {
    shared: Arc<Shared>,
    kind: Kind,
    start: u64,
    state: Mutex<State>,
}

impl Live {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        let s = self.state.get_mut().unwrap_or_else(|e| e.into_inner());
        if !s.ctx.sampled {
            return;
        }
        let mut span = json!({
            "traceId": s.ctx.trace_id(),
            "spanId": s.ctx.span_id(),
            "name": s.name,
            "kind": self.kind.otlp(),
            "startTimeUnixNano": self.start.to_string(),
            "endTimeUnixNano": s.end.unwrap_or_else(now_ns).max(self.start).to_string(),
            "attributes": s.attrs.iter().map(|(k, v)| json!({ "key": k, "value": v.otlp() })).collect::<Vec<_>>(),
            "status": if s.error { json!({ "code": 2 }) } else { json!({}) },
        });
        if let Some(p) = s.parent {
            span["parentSpanId"] = json!(format!("{p:016x}"));
        }
        if !s.events.is_empty() {
            span["events"] = json!(std::mem::take(&mut s.events));
        }
        self.shared.finish(span);
    }
}

/// A span, sent when its last clone drops. The default is inert: every method does
/// nothing, so call sites needn't check whether traces are on.
#[derive(Clone, Default)]
pub struct Span(Option<Arc<Live>>);

/// What a child needs of its parent: its place and its tracer, without keeping the
/// parent from finishing.
#[derive(Clone)]
pub struct Handle {
    shared: Arc<Shared>,
    ctx: Ctx,
}

impl Handle {
    pub fn child(&self, name: &str, kind: Kind) -> Span {
        Span::new(self.shared.clone(), name, kind, Some(self.ctx))
    }
}

impl Span {
    fn new(shared: Arc<Shared>, name: &str, kind: Kind, parent: Option<Ctx>) -> Span {
        let ctx = match parent {
            Some(p) => Ctx { trace: p.trace, span: new_span(), sampled: p.sampled },
            None => {
                let trace = new_trace();
                Ctx { trace, span: new_span(), sampled: shared.keep(trace) }
            }
        };
        let state = State { ctx, parent: parent.map(|p| p.span), name: super::errors::scrub(name), attrs: Vec::new(), events: Vec::new(), error: false, end: None };
        Span(Some(Arc::new(Live { shared, kind, start: now_ns(), state: Mutex::new(state) })))
    }

    pub fn ctx(&self) -> Option<Ctx> {
        self.0.as_ref().map(|l| l.state().ctx)
    }

    /// Its place, if it's kept: what logs and audit events name.
    pub fn sampled(&self) -> Option<Ctx> {
        self.ctx().filter(|c| c.sampled)
    }

    pub fn handle(&self) -> Option<Handle> {
        self.0.as_ref().map(|l| Handle { shared: l.shared.clone(), ctx: l.state().ctx })
    }

    pub fn child(&self, name: &str, kind: Kind) -> Span {
        self.handle().map_or_else(Span::default, |h| h.child(name, kind))
    }

    pub fn set(&self, key: &'static str, v: impl Into<Val>) {
        let Some(l) = &self.0 else { return };
        let v = v.into();
        let mut s = l.state();
        if let Some(slot) = s.attrs.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = v;
        } else if s.attrs.len() < MAX_ATTRS {
            s.attrs.push((key, v));
        }
    }

    /// A span's name is a template (`GET /api/bots/{id}/messages`, `run claude`), never a
    /// path as sent.
    pub fn rename(&self, name: impl Into<String>) {
        if let Some(l) = &self.0 {
            l.state().name = super::errors::scrub(&name.into());
        }
    }

    pub fn fail(&self) {
        if let Some(l) = &self.0 {
            l.state().error = true;
        }
    }

    /// Something that happened during the span, with attributes from botd's own words.
    pub fn event(&self, name: &str, attrs: &[(&'static str, Val)]) {
        let Some(l) = &self.0 else { return };
        let mut s = l.state();
        if s.events.len() < MAX_EVENTS {
            let attrs: Vec<Value> = attrs.iter().map(|(k, v)| json!({ "key": k, "value": v.otlp() })).collect();
            s.events.push(json!({ "timeUnixNano": now_ns().to_string(), "name": name, "attributes": attrs }));
        }
    }

    /// Ends it now; it's sent once the last clone drops.
    pub fn end(&self) {
        if let Some(l) = &self.0 {
            let mut s = l.state();
            if s.end.is_none() {
                s.end = Some(now_ns());
            }
        }
    }

    /// Moves this span under `parent`, in its trace, keeping its own id. Only before it
    /// has children: a request that turns out to be a Bot's, during its run.
    fn join(&self, parent: Ctx) {
        if let Some(l) = &self.0 {
            let mut s = l.state();
            s.ctx = Ctx { trace: parent.trace, span: s.ctx.span, sampled: parent.sampled };
            s.parent = Some(parent.span);
        }
    }
}

tokio::task_local! {
    static CURRENT: Span;
}

/// Runs `f` with `span` as the current span, the parent `child` and `note` use.
pub async fn within<F: Future>(span: &Span, f: F) -> F::Output {
    CURRENT.scope(span.clone(), f).await
}

/// The current span's place, if this task is in one.
pub fn current() -> Option<Ctx> {
    CURRENT.try_with(Span::ctx).ok().flatten()
}

/// The current span's place, if it's kept.
pub fn current_sampled() -> Option<Ctx> {
    current().filter(|c| c.sampled)
}

pub fn current_handle() -> Option<Handle> {
    CURRENT.try_with(Span::handle).ok().flatten()
}

/// A child of the current span; inert when there's none, so background work (the
/// reconciler, heartbeats) never starts traces of its own.
pub fn child(name: &str, kind: Kind) -> Span {
    CURRENT.try_with(|s| s.child(name, kind)).unwrap_or_default()
}

/// Sets an attribute on the current span, if there is one.
pub fn note(key: &'static str, v: impl Into<Val>) {
    let _ = CURRENT.try_with(|s| s.set(key, v));
}

/// Marks the current span as failed, if there is one.
pub fn fail() {
    let _ = CURRENT.try_with(Span::fail);
}

/// An audit event recorded in a traced task: an event on its span, so a trace shows what
/// the audit log has for it; `traceId` and `spanId` go in the event's details.
pub fn audited(action: &str, outcome: &str, reason: Option<&str>) {
    let _ = CURRENT.try_with(|s| {
        if s.sampled().is_none() {
            return;
        }
        let mut attrs = vec![("superbot.audit.outcome", Val::from(outcome))];
        if let Some(r) = reason.filter(|r| !r.is_empty() && r.len() <= 40 && r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')) {
            attrs.push(("superbot.audit.reason", Val::from(r)));
        }
        s.event(&audit_name(action), &attrs);
        if action == "bot.run_refused" {
            s.set("superbot.run.result", "refused");
            if let Some((_, r)) = attrs.iter().find(|(k, _)| *k == "superbot.audit.reason") {
                s.set("superbot.run.refused", r.clone());
            }
        }
    });
}

/// Audit actions are botd's own dotted words; anything else is `audit`.
fn audit_name(action: &str) -> String {
    let ok = !action.is_empty() && action.len() <= 64 && action.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_'));
    if ok { action.to_string() } else { "audit".into() }
}

/// Live runs' current attempt spans, by run id, so the Bot's calls to botd during a run
/// (its approval hook, `botctl`) join the run's trace.
static RUNS: Mutex<Option<HashMap<String, Handle>>> = Mutex::new(None);
/// Messages queued by a traced request, so their run continues its trace.
static QUEUED: Mutex<Option<Queued>> = Mutex::new(None);
type Queued = (HashMap<i64, Handle>, VecDeque<i64>);

/// Forgets a run's span when dropped.
pub struct RunTraced(Option<String>);

impl Drop for RunTraced {
    fn drop(&mut self) {
        if let Some(id) = &self.0
            && let Some(m) = RUNS.lock().unwrap_or_else(|e| e.into_inner()).as_mut()
        {
            m.remove(id);
        }
    }
}

/// While the guard lives, requests carrying run `id`'s token are children of `span`.
pub fn run_attempt(id: &str, span: &Span) -> RunTraced {
    let Some(h) = span.handle() else { return RunTraced(None) };
    let mut runs = RUNS.lock().unwrap_or_else(|e| e.into_inner());
    let m = runs.get_or_insert_with(HashMap::new);
    if m.len() >= MAX_REMEMBERED && !m.contains_key(id) {
        return RunTraced(None);
    }
    m.insert(id.to_string(), h);
    RunTraced(Some(id.to_string()))
}

/// The current request is a Bot's during run `id`: it becomes a child of the run's span.
pub fn join_run(id: &str) {
    let parent = RUNS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|m| m.get(id)).map(|h| h.ctx);
    if let Some(p) = parent {
        let _ = CURRENT.try_with(|s| s.join(p));
    }
}

/// Remembers the current span for message `id`, which was just queued.
pub fn queued(id: i64) {
    let Some(h) = current_handle() else { return };
    let mut q = QUEUED.lock().unwrap_or_else(|e| e.into_inner());
    let (m, order) = q.get_or_insert_with(Default::default);
    if m.insert(id, h).is_none() {
        order.push_back(id);
    }
    while order.len() > MAX_REMEMBERED {
        if let Some(old) = order.pop_front() {
            m.remove(&old);
        }
    }
}

/// The span message `id` was queued in, if it was traced.
pub fn take_queued(id: i64) -> Option<Handle> {
    let mut q = QUEUED.lock().unwrap_or_else(|e| e.into_inner());
    let (m, order) = q.as_mut()?;
    let h = m.remove(&id)?;
    order.retain(|x| *x != id);
    Some(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::env::EnvStore;

    fn settings(vars: &[(&str, &str)]) -> Result<Settings, String> {
        let store = EnvStore::fixed(vars);
        let get = |k: &str| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()).unwrap_or_default();
        Settings::from_env(&get, &store)
    }

    fn attr<'a>(span: &'a Value, key: &str) -> Option<&'a Value> {
        span["attributes"].as_array()?.iter().find(|a| a["key"] == key).map(|a| &a["value"])
    }

    #[test]
    fn traces_are_off_by_default_and_need_https_or_loopback() {
        let s = settings(&[]).unwrap();
        assert!(s.endpoint.is_none() && s.ratio == 1.0 && !s.accept_parent, "{s:?}");
        assert!(settings(&[("TRACES_OTLP_ENDPOINT", "off")]).unwrap().endpoint.is_none());
        assert_eq!(s.describe(), "traces off (TRACES_OTLP_ENDPOINT)");

        let e = settings(&[("TRACES_OTLP_ENDPOINT", "https://otel.example.net:4318")]).unwrap().endpoint.unwrap();
        assert_eq!(e.url, "https://otel.example.net:4318/v1/traces");
        let e = settings(&[("TRACES_OTLP_ENDPOINT", "https://api.example.net/otlp/v1/traces")]).unwrap().endpoint.unwrap();
        assert_eq!(e.url, "https://api.example.net/otlp/v1/traces");
        assert_eq!(settings(&[("TRACES_OTLP_ENDPOINT", "http://127.0.0.1:4318/")]).unwrap().endpoint.unwrap().url, "http://127.0.0.1:4318/v1/traces");
        let plain = settings(&[("TRACES_OTLP_ENDPOINT", "http://otel-collector:4318")]).unwrap_err();
        assert!(plain.contains("TRACES_OTLP_INSECURE"), "{plain}");
        let ok = settings(&[("TRACES_OTLP_ENDPOINT", "http://otel-collector:4318"), ("TRACES_OTLP_INSECURE", "on")]).unwrap();
        assert!(ok.endpoint.unwrap().plain);
        for bad in ["nope", "ftp://otel.example.net", "https://user:pw@otel.example.net", "https://otel.example.net/?k=v", "https://otel.example.net/#x"] {
            assert!(settings(&[("TRACES_OTLP_ENDPOINT", bad)]).is_err(), "{bad}");
        }
        assert!(settings(&[("TRACES_SAMPLE_RATIO", "1.5")]).unwrap_err().contains("TRACES_SAMPLE_RATIO"));
        assert!(settings(&[("TRACES_SAMPLE_RATIO", "x")]).is_err());
        assert_eq!(settings(&[("TRACES_SAMPLE_RATIO", "0.25")]).unwrap().ratio, 0.25);
        assert!(settings(&[("TRACES_PARENT", "accept")]).unwrap().accept_parent);
        assert!(settings(&[("TRACES_PARENT", "always")]).is_err());
        assert!(settings(&[("TRACES_OTLP_INSECURE", "yes")]).is_err());
    }

    #[test]
    fn headers_are_a_secret_read_only_when_traces_are_on() {
        let key = format!("hk{}", crate::random_hex(10));
        let s = settings(&[("TRACES_OTLP_ENDPOINT", "https://otel.example.net"), ("TRACES_OTLP_HEADERS", &format!("Authorization=Bearer {key}, x-tenant = ops"))]).unwrap();
        let e = s.endpoint.as_ref().unwrap();
        assert_eq!(e.headers.iter().map(|(k, v)| (k.as_str(), v.expose())).collect::<Vec<_>>(), vec![("Authorization", format!("Bearer {key}").as_str()), ("x-tenant", "ops")]);
        assert!(!format!("{s:?}").contains(&key) && !s.describe().contains(&key), "{s:?} {}", s.describe());
        assert!(s.describe().contains("otel.example.net") && s.describe().contains("100%"), "{}", s.describe());
        assert!(!secrets::redact::text(&format!("x {key} y")).contains(&key), "registered for redaction");
        for bad in ["novalue", "bad name=x", "k=", "k=a\nb"] {
            assert!(settings(&[("TRACES_OTLP_ENDPOINT", "https://otel.example.net"), ("TRACES_OTLP_HEADERS", bad)]).is_err(), "{bad}");
        }
        // Traces off: a leftover headers file is never read.
        let gone = std::env::temp_dir().join(format!("superbot-gone-{}", crate::random_hex(4)));
        assert!(settings(&[("TRACES_OTLP_HEADERS_FILE", gone.to_str().unwrap())]).unwrap().endpoint.is_none());
        assert!(settings(&[("TRACES_OTLP_ENDPOINT", "https://otel.example.net"), ("TRACES_OTLP_HEADERS_FILE", gone.to_str().unwrap())]).is_err());
    }

    #[test]
    fn traceparent_round_trips_and_rejects_anything_odd() {
        let c = Ctx::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap();
        assert_eq!((c.trace_id().as_str(), c.span_id().as_str(), c.sampled), ("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", true));
        assert_eq!(Ctx::parse(&c.traceparent()), Some(c));
        assert!(!Ctx::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00").unwrap().sampled);
        assert!(Ctx::parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-future").is_some(), "later versions may add fields");
        for bad in [
            "",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "00-ada@example.com-00f067aa0ba902b7-01",
        ] {
            assert!(Ctx::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn an_off_tracer_makes_inert_spans() {
        let t = Tracer::default();
        let s = t.span("x", Kind::Internal, None);
        assert!(s.ctx().is_none() && s.handle().is_none() && s.child("y", Kind::Internal).ctx().is_none());
        s.set("k", "v");
        s.end();
        let mut out = String::new();
        t.render(&mut out);
        assert!(out.contains("superbot_tracing_enabled 0") && out.contains(r#"superbot_trace_spans_total{outcome="sent"} 0"#), "{out}");
    }

    #[tokio::test]
    async fn spans_nest_carry_only_scrubbed_attributes_and_end_once() {
        let t = Tracer::default();
        t.capture(1.0, false);
        let secret = format!("sk-live-{}", crate::random_hex(8));
        secrets::redact::register(&secret);
        let root = t.span("GET", Kind::Server, None);
        let rc = root.ctx().unwrap();
        within(&root, async {
            assert_eq!(current(), Some(rc));
            note("superbot.route_class", "bots");
            note("superbot.where", format!("ada@example.com {secret}"));
            let d = child("tool", Kind::Internal);
            d.rename("tool ada@example.com");
            drop(d);
            let c = child(&format!("tool {secret}"), Kind::Internal);
            c.set("n", 3u64);
            c.set("n", 4u64);
            c.fail();
            audited("bot.run_refused", "denied", Some("storage_limit"));
            audited("Weird Action!", "denied", Some("Alex's key"));
        })
        .await;
        root.rename("GET /api/bots/{id}");
        root.end();
        drop(root);
        assert_eq!(current(), None, "outside, no current span");
        let spans = t.captured();
        assert_eq!(spans.len(), 3, "{spans:?}");
        let (child, root) = (&spans[1], &spans[2]);
        assert!(spans[0]["name"].as_str().is_some_and(|n| n.starts_with("tool ") && !n.contains("ada")), "names are scrubbed too: {}", spans[0]);
        assert_eq!(child["traceId"], root["traceId"]);
        assert_eq!(child["parentSpanId"], root["spanId"]);
        assert!(root.get("parentSpanId").is_none() && root["kind"] == 2 && child["kind"] == 1);
        assert_eq!(root["name"], "GET /api/bots/{id}");
        assert_eq!(attr(child, "n").unwrap()["intValue"], "4");
        assert_eq!(child["status"]["code"], 2);
        let text = serde_json::to_string(&spans).unwrap();
        assert!(!text.contains(&secret) && !text.contains("example.com") && !text.contains("Alex"), "{text}");
        let events: Vec<&str> = root["events"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
        assert_eq!(events, ["bot.run_refused", "audit"]);
        assert_eq!(attr(root, "superbot.run.refused").unwrap()["stringValue"], "storage_limit");
        assert!(root["startTimeUnixNano"].as_str().unwrap().parse::<u64>().unwrap() <= root["endTimeUnixNano"].as_str().unwrap().parse::<u64>().unwrap());
    }

    #[tokio::test]
    async fn sampling_follows_the_ratio_and_the_parent() {
        let t = Tracer::default();
        t.capture(0.0, false);
        let dropped = t.span("a", Kind::Internal, None);
        assert!(dropped.ctx().is_some_and(|c| !c.sampled) && dropped.sampled().is_none());
        assert!(dropped.child("b", Kind::Internal).sampled().is_none(), "a child keeps its parent's decision");
        let parent = Ctx { trace: 7, span: 9, sampled: true };
        let kept = t.span("c", Kind::Internal, Some(parent));
        assert_eq!(kept.sampled().map(|c| (c.trace, c.sampled)), Some((7, true)));
        drop((dropped, kept));
        assert_eq!(t.captured().len(), 1);
    }

    #[tokio::test]
    async fn a_bots_request_joins_its_runs_trace_and_queued_messages_keep_theirs() {
        let t = Tracer::default();
        t.capture(1.0, false);
        let run = t.span("run", Kind::Internal, None);
        let id = format!("r{}", crate::random_hex(8));
        let guard = run_attempt(&id, &run);
        let req = t.span("POST", Kind::Server, None);
        within(&req, async { join_run(&id) }).await;
        assert_eq!(req.ctx().map(|c| c.trace), run.ctx().map(|c| c.trace));
        drop(guard);
        let other = t.span("POST", Kind::Server, None);
        within(&other, async { join_run(&id) }).await;
        assert_ne!(other.ctx().map(|c| c.trace), run.ctx().map(|c| c.trace), "not once the run is over");

        let mid = i64::from_str_radix(&crate::random_hex(6), 16).unwrap();
        within(&req, async { queued(mid) }).await;
        let child = take_queued(mid).map(|h| h.child("run", Kind::Internal)).unwrap();
        assert_eq!(child.ctx().map(|c| c.trace), req.ctx().map(|c| c.trace));
        assert!(take_queued(mid).is_none(), "taken once");
    }

    #[tokio::test]
    async fn spans_reach_an_otlp_collector_as_json_with_the_headers() {
        use axum::routing::post;
        let got: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
        let seen = got.clone();
        let collector = axum::Router::new().route(
            "/v1/traces",
            post(move |h: axum::http::HeaderMap, body: String| {
                let seen = seen.clone();
                async move {
                    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                    let partial = body.contains("\"partial\"");
                    seen.lock().unwrap().push((auth, serde_json::from_str(&body).unwrap()));
                    // One rejected, so the counts hold whether "partial" goes alone or batched.
                    if partial { r#"{"partialSuccess":{"rejectedSpans":"1","errorMessage":"too old"}}"# } else { "{}" }
                }
            }),
        );
        let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(l, collector).await });
        let key = crate::random_hex(12);
        let s = settings(&[("TRACES_OTLP_ENDPOINT", &format!("http://127.0.0.1:{port}")), ("TRACES_OTLP_HEADERS", &format!("authorization=Bearer {key}"))]).unwrap();
        let t = Tracer::default();
        t.start(&s);
        let span = t.span("run claude", Kind::Internal, None);
        span.set("superbot.harness", "claude");
        drop(span);
        t.flush(Duration::from_secs(5)).await;
        let got = got.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, format!("Bearer {key}"));
        let rs = &got[0].1["resourceSpans"][0];
        assert_eq!(rs["resource"]["attributes"][0]["value"]["stringValue"], "superbot-botd");
        let span = &rs["scopeSpans"][0]["spans"][0];
        assert_eq!((span["name"].as_str(), span["traceId"].as_str().map(str::len)), (Some("run claude"), Some(32)));
        let mut out = String::new();
        t.render(&mut out);
        assert!(out.contains("superbot_tracing_enabled 1") && out.contains(r#"superbot_trace_spans_total{outcome="sent"} 1"#), "{out}");

        // Accepted, with some rejected: those count as failed, the rest as sent.
        for name in ["partial", "a", "b"] {
            drop(t.span(name, Kind::Internal, None));
        }
        t.flush(Duration::from_secs(5)).await;
        let mut out = String::new();
        t.render(&mut out);
        assert!(out.contains(r#"superbot_trace_spans_total{outcome="sent"} 3"#) && out.contains(r#"superbot_trace_spans_total{outcome="failed"} 1"#), "{out}");

        // A collector that's down: counted as failed, never retried into memory.
        let down = settings(&[("TRACES_OTLP_ENDPOINT", "http://127.0.0.1:9/v1/traces")]).unwrap();
        let t = Tracer::default();
        t.start(&down);
        drop(t.span("x", Kind::Internal, None));
        t.flush(Duration::from_secs(5)).await;
        let mut out = String::new();
        t.render(&mut out);
        assert!(out.contains(r#"superbot_trace_spans_total{outcome="failed"} 1"#), "{out}");
    }

    #[test]
    fn tool_names_stay_plain() {
        assert_eq!(tool_name("Bash"), "Bash");
        assert_eq!(tool_name("mcp__github__search_issues"), "mcp__github__search_issues");
        assert_eq!(tool_name("rm -rf /"), "other");
        assert_eq!(tool_name(&"x".repeat(65)), "other");
    }
}
