//! The audit export's Datadog sink (ADR 0245): every event into Datadog Log Management,
//! where Cloud SIEM reads it, through the Logs API's HTTP intake.
//!
//! `AUDIT_EXPORT=datadog://<site>` names the Datadog site (`datadoghq.com`, `datadoghq.eu`,
//! `us5.datadoghq.com`, ...), which picks its intake, `https://http-intake.logs.<site>`.
//! Each batch is `POST`ed as a JSON array of logs, at most 4 MB and 1,000 logs a request,
//! gzipped if asked, with the API key from `AUDIT_EXPORT_HEADERS` (or the named sink's
//! `AUDIT_EXPORT_HEADERS_<NAME>`) as `DD-API-KEY`. The key goes only to that intake.
//!
//! A log carries the exported line exactly (`line`), so the copy in Datadog checks itself
//! with `botctl audit verify-lines`, and the line's fields as attributes (`superbot.*`,
//! and Datadog's standard `evt`, `usr` and `network.client.ip`) for search and detections.
//! Those come from the line as exported, so they never say more than it does.

use crate::secrets::Secret;
use serde_json::{json, Map, Value};
use std::time::Duration;

/// A request's most before compression: under the intake's 5 MB.
const MAX_BODY: usize = if cfg!(test) { 4_096 } else { 4_000_000 };
/// The intake takes at most 1,000 logs a request.
const MAX_LOGS: usize = if cfg!(test) { 8 } else { 1_000 };
/// The longest `line` sent whole. A log is the line twice (as `line` and as attributes),
/// and Datadog cuts any log over 1 MB.
const MAX_LINE: usize = if cfg!(test) { 1_000 } else { 256_000 };
/// How much of a longer line each part carries: JSON escaping at most doubles it.
const PART: usize = if cfg!(test) { 500 } else { 128_000 };
/// Datadog drops a log dated more than 18 hours ago, so an older event goes undated and
/// Datadog dates it when it takes it; `superbot.time` still says when it happened.
const MAX_AGE_MS: i64 = 17 * 60 * 60 * 1000;
const TIMEOUT: Duration = Duration::from_secs(30);
/// The longest `Retry-After` botd waits for before trying again.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);
/// `ddsource` and `service` of every log.
pub const SOURCE: &str = "superbot";
const EXAMPLE: &str = "datadog://datadoghq.eu";
/// The domains Datadog's sites are on: each site is one, or a region of one (`us5.`).
const DOMAINS: [&str; 3] = ["datadoghq.com", "datadoghq.eu", "ddog-gov.com"];

pub struct Datadog {
    /// The site, lowercase: `datadoghq.com`, `us5.datadoghq.com`, `datadoghq.eu`, ...
    pub site: String,
    /// Where batches go: `https://http-intake.logs.<site>/api/v2/logs`.
    url: String,
    key: Option<Secret>,
    /// The setting the key came from, for the startup line and status.
    key_from: String,
}

/// `datadoghq.com`, `datadoghq.eu`, `ddog-gov.com`, or a region of one: two letters and a
/// number (`us3`, `us5`, `ap1`, `uk1`, `us2`).
fn site_ok(s: &str) -> bool {
    if DOMAINS.contains(&s) {
        return true;
    }
    let Some((region, domain)) = s.split_once('.') else { return false };
    let (letters, digits) = region.split_at(region.len().min(2));
    DOMAINS.contains(&domain) && letters.len() == 2 && letters.bytes().all(|b| b.is_ascii_lowercase()) && (1..=2).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
}

/// The Logs API's intake for `site`, such as `https://http-intake.logs.datadoghq.eu`.
pub(crate) fn intake(site: &str) -> String {
    format!("https://http-intake.logs.{site}")
}

fn intake_url(base: &str) -> String {
    format!("{base}/api/v2/logs")
}

impl Datadog {
    /// `raw` is `datadog://<site>`. The API key is set afterwards, from the sink's headers.
    pub fn from_url(raw: &str) -> Result<Datadog, String> {
        let bad = |why: &str| format!("AUDIT_EXPORT: a Datadog sink is datadog://<site>, such as {EXAMPLE}: {why}");
        let u = url::Url::parse(raw.trim()).map_err(|_| bad("it isn't a URL"))?;
        if !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() {
            return Err(bad("no credentials, query or fragment: the API key goes in AUDIT_EXPORT_HEADERS as DD-API-KEY=<key>"));
        }
        if u.port().is_some() || !matches!(u.path(), "" | "/") {
            return Err(bad("no port or path: the site picks the Logs API's intake"));
        }
        let site = u.host_str().unwrap_or_default().to_ascii_lowercase();
        if !site_ok(&site) {
            return Err(bad(&format!("\"{site}\" isn't a Datadog site (datadoghq.com, us3.datadoghq.com, us5.datadoghq.com, datadoghq.eu, ap1.datadoghq.com, ap2.datadoghq.com, uk1.datadoghq.com, ddog-gov.com, ...: the site in your Datadog URL, without app.)")));
        }
        let url = intake_url(&intake(&site));
        Ok(Datadog { site, url, key: None, key_from: String::new() })
    }

    /// The key from `var`, a header setting: `DD-API-KEY=<API key>` and nothing else.
    pub fn set_key(&mut self, var: &str, raw: &str) -> Result<(), String> {
        let one = format!("{var} for a Datadog sink is one header, DD-API-KEY=<API key>");
        let mut headers = crate::obs::trace::headers(var, raw)?;
        let (Some((name, key)), None) = (headers.pop(), headers.pop()) else { return Err(one) };
        if !name.eq_ignore_ascii_case("DD-API-KEY") {
            return Err(one);
        }
        let v = key.expose();
        if v.len() != 32 || !v.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(format!("{var}: DD-API-KEY is a Datadog API key, 32 letters and digits (Organization Settings > API Keys); an application key isn't one, and isn't needed"));
        }
        self.key = Some(key);
        self.key_from = var.to_string();
        Ok(())
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// What logs, the API and the audit log show.
    pub fn shown(&self) -> String {
        format!("datadog://http-intake.logs.{}", self.site)
    }

    /// The sink's cursor: another site starts again.
    pub fn id(&self) -> String {
        format!("datadog://{}", self.site)
    }

    pub fn describe(&self) -> String {
        format!("into Datadog Log Management through the Logs API (site {}), with the API key in {}", self.site, self.key_from)
    }

    /// For `botctl audit siem`.
    pub fn view(&self) -> Value {
        json!({ "site": self.site, "source": SOURCE, "apiKeyFrom": self.key_from })
    }

    /// Sends to `base` instead: a stand-in for Datadog.
    #[cfg(test)]
    pub fn point_at(&mut self, base: &str) {
        self.url = intake_url(base);
    }
}

/// Datadog's log status, as syslog's severity has it (ADR 0122).
fn status(outcome: &str) -> &'static str {
    match outcome {
        "denied" => "warn",
        "failure" => "notice",
        _ => "info",
    }
}

/// Datadog's standard attributes (`evt`, `usr`, `network.client.ip`) that the line has.
fn standard(line: &Value, log: &mut Map<String, Value>) {
    let field = |f: &str| line.get(f).filter(|v| !v.is_null()).cloned();
    let some = |pairs: Vec<(&str, Option<Value>)>| {
        let m: Map<String, Value> = pairs.into_iter().filter_map(|(k, v)| v.map(|v| (k.to_string(), v))).collect();
        (!m.is_empty()).then_some(Value::Object(m))
    };
    if let Some(evt) = some(vec![("name", field("action")), ("outcome", field("outcome"))]) {
        log.insert("evt".into(), evt);
    }
    if let Some(usr) = some(vec![("id", field("actorId")), ("name", field("actorName")), ("email", field("actorEmail"))]) {
        log.insert("usr".into(), usr);
    }
    if let Some(ip) = field("ip") {
        log.insert("network".into(), json!({ "client": { "ip": ip } }));
    }
}

/// One exported line as Datadog logs: the line's fields as attributes, and the line whole
/// in `line` with `linePart` 0. Dated by the event unless that is older than Datadog
/// takes ([`MAX_AGE_MS`]). A line over [`MAX_LINE`] (an `audit.erased` listing many rows)
/// goes as several logs instead, `linePart` 1 to n, each `line` a
/// [`crate::audit_line::part`] that `botctl audit verify-lines` puts back together. Their
/// `superbot.details` is left out: it is as big as the line.
pub fn logs(line: &Value, text: &str, now_ms: i64) -> Vec<Value> {
    let action = line["action"].as_str().unwrap_or_default();
    let mut log = Map::new();
    log.insert("ddsource".into(), json!(SOURCE));
    log.insert("service".into(), json!(SOURCE));
    if let Some(host) = line["host"].as_str() {
        log.insert("hostname".into(), json!(host));
    }
    log.insert("message".into(), json!(action));
    log.insert("status".into(), json!(status(line["outcome"].as_str().unwrap_or_default())));
    if let Some(at) = line["at"].as_i64().filter(|at| now_ms - at < MAX_AGE_MS) {
        log.insert("timestamp".into(), json!(at));
    }
    standard(line, &mut log);
    if text.len() <= MAX_LINE {
        log.insert("superbot".into(), line.clone());
        log.insert("linePart".into(), json!(0));
        log.insert("line".into(), json!(text));
        return vec![Value::Object(log)];
    }
    let mut short = line.clone();
    if let Some(o) = short.as_object_mut() {
        o.remove("details");
    }
    log.insert("superbot".into(), short);
    let id = line["id"].as_i64().unwrap_or_default();
    let host = line["host"].as_str().unwrap_or_default();
    crate::audit_line::parts(id, host, text, PART)
        .into_iter()
        .enumerate()
        .map(|(i, part)| {
            let mut log = log.clone();
            log.insert("linePart".into(), json!(i + 1));
            log.insert("line".into(), json!(part));
            Value::Object(log)
        })
        .collect()
}

/// The logs as JSON arrays of at most [`MAX_BODY`] bytes and [`MAX_LOGS`] logs each, in
/// order. A log bigger than that on its own goes alone.
pub fn bodies(logs: &[Value]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut body = vec![b'['];
    let mut n = 0;
    for l in logs {
        let l = l.to_string();
        if n > 0 && (n == MAX_LOGS || body.len() + l.len() + 2 > MAX_BODY) {
            body.push(b']');
            out.push(std::mem::replace(&mut body, vec![b'[']));
            n = 0;
        }
        if n > 0 {
            body.push(b',');
        }
        body.extend(l.as_bytes());
        n += 1;
    }
    if n > 0 {
        body.push(b']');
        out.push(body);
    }
    out
}

fn hint(status: u16) -> &'static str {
    match status {
        400 => ": Datadog refused the body; see docs/ops/audit-export.md",
        401 | 403 => ": check DD-API-KEY in the sink's AUDIT_EXPORT_HEADERS: an API key (not an application key) of the organization on this site",
        413 => ": a request was over 5 MB",
        429 => ": throttled; botd waits as Datadog asks",
        _ => "",
    }
}

pub struct Client {
    http: reqwest::Client,
}

impl Client {
    pub fn new(d: &Datadog) -> Client {
        let http = reqwest::Client::builder().https_only(d.url.starts_with("https://")).timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none()).build().expect("HTTP client");
        Client { http }
    }

    /// Sends one batch's logs, a request per body, `gzip`ped if asked (ADR 0227); bodies
    /// are cut by their size before compression, as the intake counts it. Each is
    /// accepted with a 202; a failed one fails the batch, which goes again whole (Datadog
    /// keeps the bodies it took, so a retry can repeat events, as any at-least-once
    /// export can).
    pub async fn send(&self, d: &Datadog, logs: &[Value], gzip: bool) -> Result<(), (&'static str, String)> {
        let shown = d.shown();
        let Some(key) = &d.key else { return Err(("delivery_failed", format!("{shown} has no API key"))) };
        for body in bodies(logs) {
            let body = if gzip { crate::audit_line::gzip(&body) } else { body };
            let mut req = self.http.post(&d.url).header("DD-API-KEY", key.expose()).header(reqwest::header::CONTENT_TYPE, "application/json");
            if gzip {
                req = req.header(reqwest::header::CONTENT_ENCODING, "gzip");
            }
            let r = req.body(body).send().await.map_err(|e| ("delivery_failed", format!("couldn't reach {shown}: {}", e.without_url())))?;
            let status = r.status();
            if status.is_success() {
                continue;
            }
            let wait = (status == reqwest::StatusCode::TOO_MANY_REQUESTS).then(|| crate::audit_export::asked_to_wait(&r)).flatten();
            // Datadog's answer isn't logged: it may quote what was sent.
            let _ = r.bytes().await;
            if let Some(wait) = wait {
                tokio::time::sleep(wait.min(MAX_RETRY_AFTER)).await;
            }
            return Err(("delivery_failed", format!("{shown} answered HTTP {}{}", status.as_u16(), hint(status.as_u16()))));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Actor, Event};
    use crate::audit_chain_http_tests::until;
    use crate::audit_export::Settings;
    use crate::secrets::env::EnvStore;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const KEY: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";

    fn settings(vars: &[(&str, &str)]) -> Result<Settings, String> {
        let store = EnvStore::fixed(vars);
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Settings::from_env(&|k| map.get(k).cloned().unwrap_or_default(), &store)
    }

    fn header() -> String {
        format!("DD-API-KEY={KEY}")
    }

    #[test]
    fn the_sink_names_a_site_and_its_key_goes_only_to_that_intake() {
        let s = settings(&[("AUDIT_EXPORT", "dd=datadog://DatadogHQ.eu"), ("AUDIT_EXPORT_HEADERS_DD", &header())]).unwrap().sinks.remove(0);
        assert_eq!((s.kind(), s.name.as_deref(), s.shown.as_str(), s.id.as_str()), ("datadog", Some("dd"), "datadog://http-intake.logs.datadoghq.eu", "datadog://datadoghq.eu"));
        for (site, url) in [
            ("datadoghq.com", "https://http-intake.logs.datadoghq.com/api/v2/logs"),
            ("us5.datadoghq.com", "https://http-intake.logs.us5.datadoghq.com/api/v2/logs"),
            ("ap1.datadoghq.com", "https://http-intake.logs.ap1.datadoghq.com/api/v2/logs"),
            ("ddog-gov.com", "https://http-intake.logs.ddog-gov.com/api/v2/logs"),
            ("us2.ddog-gov.com", "https://http-intake.logs.us2.ddog-gov.com/api/v2/logs"),
        ] {
            assert_eq!(Datadog::from_url(&format!("datadog://{site}/")).unwrap().url, url);
        }
        let d = settings(&[("AUDIT_EXPORT", "datadog://datadoghq.com"), ("AUDIT_EXPORT_HEADERS", &header())]).unwrap().describe();
        assert!(d.contains("every audit event to datadog://http-intake.logs.datadoghq.com into Datadog Log Management through the Logs API (site datadoghq.com), with the API key in AUDIT_EXPORT_HEADERS"), "{d}");
        assert!(!d.contains(KEY));

        for (raw, why) in [
            ("datadog://evil.example.net", "isn't a Datadog site"),
            ("datadog://app.datadoghq.com", "isn't a Datadog site"),
            ("datadog://datadoghq.com.evil.example", "isn't a Datadog site"),
            ("datadog://us.datadoghq.com", "isn't a Datadog site"),
            ("datadog://us123.datadoghq.com", "isn't a Datadog site"),
            ("datadog://datadoghq.com/api/v2/logs", "no port or path"),
            ("datadog://datadoghq.com:443", "no port or path"),
            ("datadog://datadoghq.com?dd-api-key=x", "no credentials, query or fragment"),
            ("datadog://key@datadoghq.com", "no credentials"),
        ] {
            let e = settings(&[("AUDIT_EXPORT", raw), ("AUDIT_EXPORT_HEADERS", &header())]).unwrap_err();
            assert!(e.contains(why), "{raw}: {e}");
        }
    }

    #[test]
    fn its_api_key_is_one_header_from_the_sinks_own_setting() {
        let e = settings(&[("AUDIT_EXPORT", "datadog://datadoghq.com")]).unwrap_err();
        assert!(e.contains("datadog://http-intake.logs.datadoghq.com needs its API key: AUDIT_EXPORT_HEADERS=DD-API-KEY=<API key>"), "{e}");
        let e = settings(&[("AUDIT_EXPORT", "dd=datadog://datadoghq.com")]).unwrap_err();
        assert!(e.contains("AUDIT_EXPORT_HEADERS_DD=DD-API-KEY=<API key>"), "{e}");
        for (headers, why) in [
            ("Authorization=Bearer x", "AUDIT_EXPORT_HEADERS for a Datadog sink is one header, DD-API-KEY=<API key>"),
            (&format!("DD-API-KEY={KEY},DD-APPLICATION-KEY={KEY}abcdefgh") as &str, "is one header"),
            ("DD-API-KEY=0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d", "an application key isn't one"),
            ("DD-API-KEY=short", "32 letters and digits"),
        ] {
            let e = settings(&[("AUDIT_EXPORT", "datadog://datadoghq.com"), ("AUDIT_EXPORT_HEADERS", headers)]).unwrap_err();
            assert!(e.contains(why), "{headers}: {e}");
            assert!(!e.contains(KEY), "{e}");
        }
        let s = settings(&[("AUDIT_EXPORT", "datadog://datadoghq.com"), ("AUDIT_EXPORT_HEADERS", &format!("dd-api-key={KEY}"))]).unwrap();
        assert!(!format!("{s:?}").contains(KEY));
        assert!(!crate::secrets::redact::text(&format!("x {KEY} y")).contains(KEY), "registered, so an error quoting it is masked");
        let e = settings(&[("AUDIT_EXPORT", "dd=datadog://datadoghq.com"), ("AUDIT_EXPORT_HEADERS", &header()), ("AUDIT_EXPORT_HEADERS_DD", &header())]).unwrap_err();
        assert!(e.contains("Set AUDIT_EXPORT_HEADERS or AUDIT_EXPORT_HEADERS_DD, not both"), "{e}");

        // One of the SIEMs: with another, each is named and has its own key; gzip as asked.
        let e = settings(&[("AUDIT_EXPORT", "dd=datadog://datadoghq.com,splunk=https://siem.example.net/in"), ("AUDIT_EXPORT_HEADERS", &header())]).unwrap_err();
        assert!(e.contains("give each its own AUDIT_EXPORT_HEADERS_<NAME>"), "{e}");
        let s = settings(&[
            ("AUDIT_EXPORT", "dd=datadog://datadoghq.com,eu=datadog://datadoghq.eu,splunk=https://siem.example.net/in"),
            ("AUDIT_EXPORT_HEADERS_DD", &header()),
            ("AUDIT_EXPORT_HEADERS_EU", &header()),
            ("AUDIT_EXPORT_COMPRESS", "gzip"),
            ("AUDIT_EXPORT_COMPRESS_EU", "off"),
        ])
        .unwrap();
        assert_eq!(s.sinks.iter().map(|s| (s.kind(), s.gzipped())).collect::<Vec<_>>(), [("datadog", true), ("datadog", false), ("webhook", true)]);
        assert!(s.describe().contains("with the API key in AUDIT_EXPORT_HEADERS_DD, gzipped"), "{}", s.describe());
        let e = settings(&[("AUDIT_EXPORT", "dd=datadog://datadoghq.com,datadog://datadoghq.com"), ("AUDIT_EXPORT_HEADERS_DD", &header())]).unwrap_err();
        assert!(e.contains("lists datadog://http-intake.logs.datadoghq.com twice"), "{e}");
    }

    fn event_line(details: Value) -> (Value, String, i64) {
        let app = crate::runner::test_app();
        let actor = Actor { kind: crate::audit::ActorKind::User, id: Some("u1".into()), email: Some("ada@example.com".into()), ..Default::default() };
        let mut ev = Event::new(actor, "auth.login_failed").outcome(crate::audit::Outcome::Failure).details(details);
        ev.source.ip = Some("203.0.113.7".into());
        let id = app.db.try_record(&ev).unwrap();
        let e = app.db.audit_events(&Default::default(), 1000, false).into_iter().find(|e| e.id == id).unwrap();
        let v = crate::audit_export::line_value(&e, "host-1", None, true);
        let text = v.to_string();
        (v, text, e.at)
    }

    #[test]
    fn logs_carry_the_line_whole_and_its_fields_as_attributes() {
        let (v, text, at) = event_line(json!({ "reason": "bad_password" }));
        let ls = logs(&v, &text, at + 5_000);
        assert_eq!(ls.len(), 1, "a short line goes whole");
        let l = &ls[0];
        assert_eq!((l["ddsource"].as_str(), l["service"].as_str(), l["hostname"].as_str(), l["message"].as_str()), (Some("superbot"), Some("superbot"), Some("host-1"), Some("auth.login_failed")));
        assert_eq!((l["status"].as_str(), l["timestamp"].as_i64(), l["linePart"].as_i64()), (Some("notice"), Some(at), Some(0)));
        assert_eq!(l["superbot"], v, "every field of the line, under superbot");
        assert_eq!((&l["evt"]["name"], &l["evt"]["outcome"], &l["network"]["client"]["ip"]), (&json!("auth.login_failed"), &json!("failure"), &json!("203.0.113.7")));
        assert_eq!((&l["usr"]["id"], &l["usr"]["email"]), (&v["actorId"], &v["actorEmail"]));
        assert_eq!(l["line"].as_str(), Some(text.as_str()), "the line, byte for byte");
        assert_eq!(crate::audit_line::check(&serde_json::from_str(&text).unwrap()), Ok(crate::audit_line::Bound::All), "so it checks itself in Datadog");

        let old = logs(&v, &text, at + 18 * 60 * 60 * 1000);
        assert!(old[0].get("timestamp").is_none(), "Datadog drops logs dated over 18 hours ago, so an old event goes undated");
        assert_eq!(old[0]["superbot"]["time"], v["time"]);
        assert_eq!(status("denied"), "warn");
        assert_eq!(status("success"), "info");
        let system = json!({ "action": "audit.checkpoint", "outcome": "success", "actorKind": "system" });
        let l = &logs(&system, &system.to_string(), 0)[0];
        assert!(l.get("usr").is_none() && l.get("network").is_none() && l.get("hostname").is_none(), "{l}");

        let many: Vec<Value> = (0..40).map(|i| json!({ "n": i, "line": "x".repeat(300) })).collect();
        let split = bodies(&many);
        assert!(split.len() > 1, "split: {}", split.len());
        let mut back = Vec::new();
        for b in &split {
            let part: Vec<Value> = serde_json::from_slice(b).unwrap();
            assert!(b.len() <= MAX_BODY && part.len() <= MAX_LOGS, "{} bytes, {} logs", b.len(), part.len());
            back.extend(part);
        }
        assert_eq!(back, many, "every log, once, in order");
        let small: Vec<Value> = (0..20).map(|i| json!(i)).collect();
        assert_eq!(bodies(&small).len(), 3, "at most {MAX_LOGS} logs a request");
        assert_eq!(bodies(&[json!({ "line": "y".repeat(MAX_BODY) })]).len(), 1, "alone");
        assert!(bodies(&[]).is_empty());
    }

    #[test]
    fn a_line_too_long_for_one_log_goes_in_pieces_that_check_once_joined() {
        let (v, text, at) = event_line(json!({ "pad": "quoted \"é\" ".repeat(400) }));
        assert!(text.len() > MAX_LINE, "{}", text.len());
        let ls = logs(&v, &text, at);
        assert!(ls.len() > 2, "{}", ls.len());
        for (i, l) in ls.iter().enumerate() {
            assert!(l["line"].as_str().unwrap().len() <= 2 * PART + 200, "piece {}", i + 1);
            assert_eq!((l["linePart"].as_u64(), &l["superbot"]["id"], l["superbot"].get("details")), (Some(i as u64 + 1), &v["id"], None));
        }
        let mut lines = crate::audit_line::Lines::new(None);
        for (n, l) in ls.iter().rev().enumerate() {
            lines.line(l["line"].as_str().unwrap(), &format!("datadog:{}", n + 1));
        }
        let report = lines.finish();
        assert!(report.ok && report.hosts[0].events == 1, "{report:?}");
    }

    /// A stand-in for the Logs API's intake.
    #[derive(Default)]
    struct Intake {
        logs: Mutex<Vec<Value>>,
        requests: AtomicUsize,
        gzipped: AtomicUsize,
        /// Answers this status to every request while set.
        refuse: AtomicUsize,
        /// `Retry-After` on a 429, when set.
        retry_after: Mutex<Option<String>>,
    }

    type I = Arc<Intake>;

    async fn intake(State(i): State<I>, h: HeaderMap, raw: axum::body::Bytes) -> (StatusCode, HeaderMap, axum::Json<Value>) {
        i.requests.fetch_add(1, Ordering::SeqCst);
        let mut answer = HeaderMap::new();
        if h.get("dd-api-key").and_then(|v| v.to_str().ok()) != Some(KEY) {
            return (StatusCode::FORBIDDEN, answer, axum::Json(json!({ "errors": ["Forbidden"] })));
        }
        assert_eq!(h.get("content-type").and_then(|v| v.to_str().ok()), Some("application/json"));
        let plain = match h.get("content-encoding").and_then(|v| v.to_str().ok()) {
            Some("gzip") => {
                i.gzipped.fetch_add(1, Ordering::SeqCst);
                crate::audit_line::gunzip(&raw, MAX_BODY as u64).expect("gzip within the limit, uncompressed too")
            }
            None => raw.to_vec(),
            Some(other) => panic!("Content-Encoding {other}"),
        };
        assert!(plain.len() <= MAX_BODY, "{}", plain.len());
        let body: Vec<Value> = serde_json::from_slice(&plain).expect("a JSON array");
        assert!(body.len() <= MAX_LOGS);
        match i.refuse.load(Ordering::SeqCst) {
            0 => {}
            429 => {
                if let Some(v) = i.retry_after.lock().unwrap().clone() {
                    answer.insert("retry-after", v.parse().unwrap());
                }
                return (StatusCode::TOO_MANY_REQUESTS, answer, axum::Json(json!({})));
            }
            s => return (StatusCode::from_u16(s as u16).unwrap(), answer, axum::Json(json!({ "errors": ["quoting the request"] }))),
        }
        i.logs.lock().unwrap().extend(body);
        (StatusCode::ACCEPTED, answer, axum::Json(json!({})))
    }

    async fn stand_in() -> (String, I) {
        let i = I::default();
        let r = axum::Router::new().route("/api/v2/logs", axum::routing::post(intake)).with_state(i.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
        (format!("http://{addr}"), i)
    }

    fn lines_of(logs: &[Value]) -> crate::audit_line::Report {
        let mut lines = crate::audit_line::Lines::new(None);
        for (n, l) in logs.iter().enumerate() {
            lines.line(l["line"].as_str().unwrap(), &format!("datadog:{}", n + 1));
        }
        lines.finish()
    }

    #[tokio::test]
    async fn every_event_reaches_datadog_in_order_and_checks_itself() {
        let (_, app, _, _) = crate::tests::serve_app().await;
        let (base, dd) = stand_in().await;
        for i in 0..30 {
            app.db.record(&Event::new(Actor::system("test"), "test.datadog").details(json!({ "n": i, "pad": "p".repeat(200) })));
        }
        let scattered: Vec<i64> = (1_000..1_600).step_by(2).collect();
        let erased = app.db.with_conn(|c| crate::audit_chain::insert_erased(c, "p", &scattered)).unwrap();
        let mut s = settings(&[("AUDIT_EXPORT", "dd=datadog://datadoghq.com"), ("AUDIT_EXPORT_HEADERS_DD", &header()), ("AUDIT_EXPORT_COMPRESS_DD", "gzip")]).unwrap();
        s.sinks[0].datadog_mut().unwrap().point_at(&base);
        crate::audit_export::start(&app, s);
        let xs = app.audit_export.get().unwrap().clone();
        until("delivered", || xs.delivered() >= app.db.audit_head()).await;

        let (requests, gzipped) = (dd.requests.load(Ordering::SeqCst), dd.gzipped.load(Ordering::SeqCst));
        assert!(requests > 1 && gzipped == requests, "a batch over the limits goes in several gzipped requests: {gzipped} of {requests}");
        let logs = dd.logs.lock().unwrap().clone();
        let ids: Vec<i64> = logs.iter().filter(|l| l["linePart"].as_i64() <= Some(1)).map(|l| l["superbot"]["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, (1..=*ids.last().unwrap()).collect::<Vec<_>>(), "every event once, in order, history first");
        assert!(logs.iter().filter(|l| l["superbot"]["id"].as_i64() == Some(erased)).count() > 1, "the erasure's line in pieces");
        let report = lines_of(&logs);
        assert!(report.ok && report.hosts[0].events == ids.len() as u64, "botctl audit verify-lines passes on Datadog's copy: {report:?}");
        assert!(!serde_json::to_string(&logs).unwrap().contains(KEY), "no key in what was sent");

        // A key Datadog refuses: it fails with what to do, and waits.
        let failing = || app.db.audit_events(&crate::audit::Filter { actions: vec!["audit.export_failing".into()], ..Default::default() }, 10, false);
        dd.refuse.store(403, Ordering::SeqCst);
        let before = xs.delivered();
        app.db.record(&Event::new(Actor::system("test"), "test.forbidden"));
        until("failing", || !failing().is_empty()).await;
        let f = &failing()[0];
        assert_eq!((f.details["kind"].as_str(), f.details["name"].as_str(), f.details["reason"].as_str()), (Some("datadog"), Some("dd"), Some("delivery_failed")));
        let error = f.details["error"].as_str().unwrap();
        assert!(error.contains("datadog://http-intake.logs.datadoghq.com answered HTTP 403: check DD-API-KEY") && !error.contains("quoting") && !error.contains(KEY), "{error}");
        assert_eq!(xs.delivered(), before, "the cursor stays");
        let v = xs.view(app.db.audit_head());
        assert_eq!((v["kind"].as_str(), v["failing"].as_bool(), v["datadog"]["site"].as_str(), v["datadog"]["apiKeyFrom"].as_str(), v["compress"].as_str()), (Some("datadog"), Some(true), Some("datadoghq.com"), Some("AUDIT_EXPORT_HEADERS_DD"), Some("gzip")), "{v}");
        let mut metrics = String::new();
        crate::audit_export::render(&app, &mut metrics);
        assert!(metrics.contains("superbot_audit_export_failing{kind=\"datadog\",name=\"dd\"} 1"), "{metrics}");

        dd.refuse.store(0, Ordering::SeqCst);
        until("recovered", || xs.delivered() >= app.db.audit_head()).await;
        assert!(lines_of(&dd.logs.lock().unwrap()).ok, "copies from the retries check too");
    }

    #[tokio::test]
    async fn a_429_waits_as_datadog_asks() {
        let (base, dd) = stand_in().await;
        let mut d = Datadog::from_url("datadog://datadoghq.com").unwrap();
        d.set_key("AUDIT_EXPORT_HEADERS", &header()).unwrap();
        d.point_at(&base);
        dd.refuse.store(429, Ordering::SeqCst);
        let at = chrono::Utc::now() + chrono::Duration::seconds(2);
        *dd.retry_after.lock().unwrap() = Some(at.format("%a, %d %b %Y %H:%M:%S GMT").to_string());
        let started = std::time::Instant::now();
        let (reason, error) = Client::new(&d).send(&d, &[json!({ "line": "x" })], false).await.unwrap_err();
        let waited = started.elapsed();
        assert!(waited >= Duration::from_secs(1) && waited < Duration::from_secs(10), "waited {waited:?}");
        assert_eq!(reason, "delivery_failed");
        assert!(error.contains("answered HTTP 429: throttled"), "{error}");
        *dd.retry_after.lock().unwrap() = Some("1".into());
        let started = std::time::Instant::now();
        Client::new(&d).send(&d, &[json!({ "line": "x" })], false).await.unwrap_err();
        assert!(started.elapsed() >= Duration::from_secs(1), "seconds too");
    }
}
