//! The audit export's Google SecOps sink (ADR 0237): every event into a Google Security
//! Operations (Chronicle) instance, through the Chronicle API's `logs:import`.
//!
//! `AUDIT_EXPORT=google-secops://<location>/<project>/<instance>/<log type>` names the
//! instance's location (which picks its regional endpoint,
//! `https://<location>-chronicle.googleapis.com`), its Google Cloud project, its id (the
//! customer id) and the log type the events are filed under. Each batch is `POST`ed as raw
//! logs, at most 2 MB a request, with a bearer token botd gets from Google as itself (the
//! same identity as Secret Manager, `AUDIT_EXPORT_GCP_AUTH`), kept while it lasts and
//! asked again once when Google refuses it. Tokens go only to that endpoint.
//!
//! Each raw log is the exported line exactly, so the copy in SecOps checks itself with
//! `botctl audit verify-lines`.

use crate::secrets::gcp::Google;
use crate::secrets::SecretStore;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use std::time::Duration;

pub const API_VERSION: &str = "v1";
/// A request's most, before base64 and JSON: well under the API's 4 MB, at the 2 MB Google
/// suggests.
const MAX_BODY: usize = if cfg!(test) { 4_096 } else { 2_000_000 };
/// The API's own request timeout.
const TIMEOUT: Duration = Duration::from_secs(60);
/// Google asks for at least 30 seconds after a 429 before trying again.
const MIN_THROTTLE: Duration = if cfg!(test) { Duration::from_millis(20) } else { Duration::from_secs(30) };
/// The longest `Retry-After` botd waits for before trying again.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);
const LABEL: &str = "Google SecOps";
const EXAMPLE: &str = "google-secops://eu/my-project/01234567-89ab-cdef-0123-456789abcdef/SUPERBOT_AUDIT";

pub struct SecOps {
    /// The instance's location, lowercase: `us`, `eu`, `europe-west2`, ...
    pub location: String,
    /// The Google Cloud project the instance is bound to: its id or number.
    pub project: String,
    /// The instance's id, the customer id: a UUID, lowercase.
    pub instance: String,
    /// The log type events are filed under, such as a custom `SUPERBOT_AUDIT`.
    pub log_type: String,
    /// Where batches go: `https://<location>-chronicle.googleapis.com/v1/projects/.../logs:import`.
    url: String,
    google: Google,
}

fn import_url(base: &str, location: &str, project: &str, instance: &str, log_type: &str) -> String {
    format!("{base}/{API_VERSION}/projects/{project}/locations/{location}/instances/{instance}/logTypes/{log_type}/logs:import")
}

pub(crate) fn endpoint(location: &str) -> String {
    format!("https://{location}-chronicle.googleapis.com")
}

/// `us`, `eu`, `europe-west2`: lowercase letters, digits and inner `-`, as Google's regions are.
fn location_ok(l: &str) -> bool {
    (2..=30).contains(&l.len()) && l.starts_with(|c: char| c.is_ascii_lowercase()) && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A project id (`my-project-123`: 6 to 30 lowercase letters, digits and `-`, starting with a
/// letter) or a project number.
fn project_ok(p: &str) -> bool {
    let id = (6..=30).contains(&p.len()) && p.starts_with(|c: char| c.is_ascii_lowercase()) && !p.ends_with('-') && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let number = (1..=20).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit());
    id || number
}

fn uuid_ok(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12]) && groups.iter().all(|g| g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// SecOps's log types are capitals, digits and `_`: `SUPERBOT_AUDIT`, `WORKDAY`.
fn log_type_ok(t: &str) -> bool {
    (1..=64).contains(&t.len()) && t.starts_with(|c: char| c.is_ascii_uppercase()) && t.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

impl SecOps {
    /// `raw` is `google-secops://<location>/<project>/<instance>/<log type>`; botd signs in as
    /// `AUDIT_EXPORT_GCP_AUTH` says, or as `GCP_SECRET_MANAGER_AUTH` when that is set.
    pub fn from_env(raw: &str, get: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<SecOps, String> {
        let bad = |why: &str| format!("AUDIT_EXPORT: a Google SecOps sink is google-secops://<location>/<project>/<instance>/<log type>, such as {EXAMPLE}: {why}");
        let u = url::Url::parse(raw.trim()).map_err(|_| bad("it isn't a URL"))?;
        if !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() {
            return Err(bad("no credentials, query or fragment: botd signs in to Google as itself (AUDIT_EXPORT_GCP_AUTH)"));
        }
        if u.port().is_some() {
            return Err(bad("no port: the location picks the Chronicle API's regional endpoint"));
        }
        let location = u.host_str().unwrap_or_default().to_ascii_lowercase();
        if !location_ok(&location) {
            return Err(bad(&format!("\"{location}\" isn't a SecOps location (us, eu, europe-west2, ...: the region the instance is in, on its SIEM Settings > Profile page)")));
        }
        let parts: Vec<&str> = u.path().trim_start_matches('/').split('/').collect();
        let [project, instance, log_type] = parts.as_slice() else { return Err(bad("the path is the project, the instance's id, then the log type")) };
        if !project_ok(project) {
            return Err(bad(&format!("\"{project}\" isn't a Google Cloud project id or number (the project the instance is bound to)")));
        }
        let instance = instance.to_ascii_lowercase();
        if !uuid_ok(&instance) {
            return Err(bad(&format!("\"{instance}\" isn't a SecOps instance id (the customer id, a UUID, on SIEM Settings > Profile)")));
        }
        if !log_type_ok(log_type) {
            return Err(bad(&format!("\"{log_type}\" isn't a log type (capitals, digits and _, such as SUPERBOT_AUDIT, made as a custom log type)")));
        }
        let (method_var, method) = match (get("AUDIT_EXPORT_GCP_AUTH"), get("GCP_SECRET_MANAGER_AUTH")) {
            (m, _) if !m.trim().is_empty() => ("AUDIT_EXPORT_GCP_AUTH", m),
            (_, sm) if !sm.trim().is_empty() => ("GCP_SECRET_MANAGER_AUTH", sm),
            _ => ("AUDIT_EXPORT_GCP_AUTH", String::new()),
        };
        let google = Google::from_env(get, store, method_var, &method, LABEL)?;
        let url = import_url(&endpoint(&location), &location, project, &instance, log_type);
        Ok(SecOps { url, location, project: project.to_string(), instance, log_type: log_type.to_string(), google })
    }

    /// What logs, the API and the audit log show.
    pub fn shown(&self) -> String {
        format!("google-secops://{}-chronicle.googleapis.com", self.location)
    }

    /// The sink's cursor: another instance or log type starts again.
    pub fn id(&self) -> String {
        format!("google-secops://{}/{}/{}/{}", self.location, self.project, self.instance, self.log_type)
    }

    pub fn describe(&self) -> String {
        format!("into Google SecOps through the Chronicle API (project {}, instance {}, log type {}), signing in to Google as {}", self.project, self.instance, self.log_type, self.google.describe())
    }

    /// For `botctl audit siem`.
    pub fn view(&self) -> Value {
        json!({ "location": self.location, "project": self.project, "instance": self.instance, "logType": self.log_type, "signIn": self.google.method() })
    }

    /// Sends to `base` instead, and signs in there: a stand-in for Google.
    #[cfg(test)]
    pub fn point_at(&mut self, base: &str) {
        self.url = import_url(base, &self.location, &self.project, &self.instance, &self.log_type);
        self.google.point_at(base);
    }
}

/// When SecOps collected an event: now, and never before the event itself, as the API asks.
pub fn collected(at_ms: i64, now_ms: i64) -> String {
    let ms = now_ms.max(at_ms + 1);
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// One exported line as a raw log: the line exactly, base64 as the API takes `data`, at the
/// event's time.
pub fn log(text: &str, time: &str, collected: &str) -> Value {
    json!({ "data": STANDARD.encode(text), "logEntryTime": time, "collectionTime": collected })
}

/// The logs as `logs:import` bodies of at most [`MAX_BODY`] bytes each, in order. A log
/// bigger than that on its own goes alone, still under the API's 4 MB a log.
pub fn bodies(logs: &[Value]) -> Vec<Vec<u8>> {
    const HEAD: &[u8] = br#"{"inlineSource":{"logs":["#;
    const TAIL: &[u8] = b"]}}";
    let mut out = Vec::new();
    let mut body = HEAD.to_vec();
    for l in logs {
        let l = l.to_string();
        if body.len() > HEAD.len() && body.len() + l.len() + 1 + TAIL.len() > MAX_BODY {
            body.extend(TAIL);
            out.push(std::mem::replace(&mut body, HEAD.to_vec()));
        }
        if body.len() > HEAD.len() {
            body.push(b',');
        }
        body.extend(l.as_bytes());
    }
    if body.len() > HEAD.len() {
        body.extend(TAIL);
        out.push(body);
    }
    out
}

/// Google's status name in its answer (`PERMISSION_DENIED`), safe to log: never its
/// message, which may quote what was sent.
fn status_of(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let s = v["error"]["status"].as_str()?;
    (!s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')).then(|| s.to_string())
}

fn hint(status: u16) -> &'static str {
    match status {
        400 => ": is the log type one the instance has (make SUPERBOT_AUDIT a custom log type)? See docs/ops/audit-export.md",
        401 => ": it refused botd's token, a new one too; does botd's identity have the cloud-platform scope?",
        403 => ": give botd's service account chronicle.logs.import on the instance's project (a custom role, or Chronicle API Editor), and turn the Chronicle API on there",
        404 => ": check the location, project, instance id and log type",
        413 => ": a request was over 4 MB",
        429 => ": over the instance's ingestion limit; botd waits at least 30 seconds",
        _ => "",
    }
}

pub struct Client {
    http: reqwest::Client,
}

impl Client {
    pub fn new(s: &SecOps) -> Client {
        let http = reqwest::Client::builder().https_only(s.url.starts_with("https://")).timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none()).build().expect("HTTP client");
        Client { http }
    }

    /// Sends one batch's logs, a request per body. Each is accepted with a 200; a failed one
    /// fails the batch, which goes again whole. SecOps drops a batch whose logs it already
    /// has for the log type, and a body it says it already has (409 `ALREADY_EXISTS`) counts
    /// as taken, so a retry adds no copies.
    pub async fn send(&self, s: &SecOps, logs: &[Value]) -> Result<(), (&'static str, String)> {
        let shown = s.shown();
        for body in bodies(logs) {
            let mut fresh = false;
            loop {
                let token = s.google.token(fresh).await.map_err(|e| ("sign_in_failed", format!("couldn't sign in to Google for {shown}: {e}")))?;
                let req = self.http.post(&s.url).bearer_auth(token.as_str()).header(reqwest::header::CONTENT_TYPE, "application/json").body(body.clone());
                let r = req.send().await.map_err(|e| ("delivery_failed", format!("couldn't reach {shown}: {}", e.without_url())))?;
                let status = r.status();
                if status.is_success() {
                    break;
                }
                // A token past its time, or revoked: one new one, then it counts.
                if status == reqwest::StatusCode::UNAUTHORIZED && !fresh {
                    fresh = true;
                    continue;
                }
                let wait = (status == reqwest::StatusCode::TOO_MANY_REQUESTS).then(|| crate::audit_export::asked_to_wait(&r).unwrap_or_default().clamp(MIN_THROTTLE, MAX_RETRY_AFTER));
                let answer = r.bytes().await.unwrap_or_default();
                let code = status_of(&answer);
                if status == reqwest::StatusCode::CONFLICT && code.as_deref() == Some("ALREADY_EXISTS") {
                    break;
                }
                if let Some(wait) = wait {
                    tokio::time::sleep(wait).await;
                }
                let code = code.map(|c| format!(" ({c})")).unwrap_or_default();
                return Err(("delivery_failed", format!("{shown} answered HTTP {}{code}{}", status.as_u16(), hint(status.as_u16()))));
            }
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
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const INSTANCE: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const PROJECT: &str = "proj-secops-1";

    fn sink_url() -> String {
        format!("google-secops://eu/{PROJECT}/{INSTANCE}/SUPERBOT_AUDIT")
    }

    fn settings(vars: &[(&str, &str)]) -> Result<Settings, String> {
        let store = EnvStore::fixed(vars);
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Settings::from_env(&|k| map.get(k).cloned().unwrap_or_default(), &store)
    }

    fn secops(vars: &[(&str, &str)]) -> Result<SecOps, String> {
        let store = EnvStore::fixed(vars);
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let raw = map.get("AUDIT_EXPORT").cloned().unwrap_or_default();
        SecOps::from_env(&raw, &|k| map.get(k).cloned().unwrap_or_default(), &store)
    }

    #[test]
    fn the_sink_names_an_instance_and_log_type_and_goes_only_to_its_regional_endpoint() {
        let raw = format!("google-secops://EU/{PROJECT}/{}/SUPERBOT_AUDIT", INSTANCE.to_ascii_uppercase());
        let s = settings(&[("AUDIT_EXPORT", &format!("secops={raw}"))]).unwrap().sinks.remove(0);
        assert_eq!((s.kind(), s.name.as_deref(), s.shown.as_str()), ("google-secops", Some("secops"), "google-secops://eu-chronicle.googleapis.com"));
        assert_eq!(s.id, sink_url(), "another instance or log type is another cursor");
        let g = secops(&[("AUDIT_EXPORT", &raw)]).unwrap();
        assert_eq!(g.url, format!("https://eu-chronicle.googleapis.com/v1/projects/{PROJECT}/locations/eu/instances/{INSTANCE}/logTypes/SUPERBOT_AUDIT/logs:import"));
        assert_eq!(g.google.method(), "metadata");
        let g = secops(&[("AUDIT_EXPORT", &format!("google-secops://europe-west2/123456789012/{INSTANCE}/WORKDAY_AUDIT"))]).unwrap();
        assert!(g.url.starts_with("https://europe-west2-chronicle.googleapis.com/v1/projects/123456789012/locations/europe-west2/"), "{}", g.url);
        let d = settings(&[("AUDIT_EXPORT", &sink_url())]).unwrap().describe();
        assert!(d.contains(&format!("into Google SecOps through the Chronicle API (project {PROJECT}, instance {INSTANCE}, log type SUPERBOT_AUDIT), signing in to Google as the metadata server's service account")), "{d}");

        for (raw, why) in [
            (format!("google-secops://eu/{PROJECT}/{INSTANCE}/SUPERBOT_AUDIT?x=1"), "no credentials, query or fragment"),
            (format!("google-secops://u:p@eu/{PROJECT}/{INSTANCE}/SUPERBOT_AUDIT"), "no credentials"),
            (format!("google-secops://eu:443/{PROJECT}/{INSTANCE}/SUPERBOT_AUDIT"), "no port"),
            (format!("google-secops://evil.example.net/{PROJECT}/{INSTANCE}/SUPERBOT_AUDIT"), "isn't a SecOps location"),
            (format!("google-secops://eu-/{PROJECT}/{INSTANCE}/SUPERBOT_AUDIT"), "isn't a SecOps location"),
            (format!("google-secops://eu/{PROJECT}/{INSTANCE}"), "the project, the instance's id, then the log type"),
            (format!("google-secops://eu/projects/{PROJECT}/locations/eu/instances/{INSTANCE}/logTypes/SUPERBOT_AUDIT"), "the project, the instance's id, then the log type"),
            (format!("google-secops://eu/My_Project/{INSTANCE}/SUPERBOT_AUDIT"), "isn't a Google Cloud project"),
            (format!("google-secops://eu/{PROJECT}/not-a-uuid/SUPERBOT_AUDIT"), "isn't a SecOps instance id"),
            (format!("google-secops://eu/{PROJECT}/{INSTANCE}/superbot_audit"), "isn't a log type"),
            (format!("google-secops://eu/{PROJECT}/{INSTANCE}/SUPERBOT%20AUDIT"), "isn't a log type"),
        ] {
            let e = settings(&[("AUDIT_EXPORT", &raw)]).unwrap_err();
            assert!(e.contains(why), "{raw}: {e}");
        }
    }

    #[test]
    fn it_signs_in_as_botds_google_identity_and_takes_no_headers_or_gzip() {
        let url = sink_url();
        let g = secops(&[("AUDIT_EXPORT", &url), ("GCP_SECRET_MANAGER_AUTH", "metadata"), ("GCE_METADATA_HOST", "metadata.internal:8080")]).unwrap();
        assert_eq!(g.google.describe(), "the metadata server's service account at metadata.internal:8080", "the same identity as Secret Manager");
        for (vars, why) in [
            (vec![("AUDIT_EXPORT_GCP_AUTH", "password")], "AUDIT_EXPORT_GCP_AUTH must be metadata or service-account-key"),
            (vec![("AUDIT_EXPORT_GCP_AUTH", "service-account-key")], "AUDIT_EXPORT_GCP_AUTH=service-account-key needs GCP_SERVICE_ACCOUNT_KEY_FILE"),
            (vec![("GCP_SECRET_MANAGER_AUTH", "service-account-key")], "GCP_SECRET_MANAGER_AUTH=service-account-key needs GCP_SERVICE_ACCOUNT_KEY_FILE"),
            (vec![("AUDIT_EXPORT_GCP_AUTH", "service-account-key"), ("GCP_SERVICE_ACCOUNT_KEY", "{}")], "must be a service account key"),
            (vec![("AUDIT_EXPORT_HEADERS", "Authorization=Bearer x")], "AUDIT_EXPORT_HEADERS is for an https sink; Google SecOps signs in"),
            (vec![("AUDIT_EXPORT_COMPRESS", "gzip")], "AUDIT_EXPORT has none"),
        ] {
            let mut all = vec![("AUDIT_EXPORT", url.as_str())];
            all.extend(vars);
            let e = settings(&all).unwrap_err();
            assert!(e.contains(why), "{all:?}: {e}");
        }
        let named = format!("secops={url}");
        let e = settings(&[("AUDIT_EXPORT", &named), ("AUDIT_EXPORT_HEADERS_SECOPS", "X=1")]).unwrap_err();
        assert!(e.contains("AUDIT_EXPORT_HEADERS_SECOPS is for an https sink; Google SecOps signs in to Google as botd"), "{e}");
        let e = settings(&[("AUDIT_EXPORT", &named), ("AUDIT_EXPORT_COMPRESS_SECOPS", "gzip")]).unwrap_err();
        assert!(e.contains("AUDIT_EXPORT_COMPRESS_SECOPS is for https, azure-monitor and datadog sinks; the Chronicle API takes no compressed bodies"), "{e}");
        // It is one of the SIEMs: with another, both need names; a server-wide gzip leaves it plain.
        let e = settings(&[("AUDIT_EXPORT", &format!("{url},https://siem.example.net/in"))]).unwrap_err();
        assert!(e.contains("name each"), "{e}");
        let s = settings(&[("AUDIT_EXPORT", &format!("{named},splunk=https://siem.example.net/in")), ("AUDIT_EXPORT_COMPRESS", "gzip")]).unwrap();
        assert_eq!(s.sinks.iter().map(|s| (s.kind(), s.gzipped())).collect::<Vec<_>>(), [("google-secops", false), ("webhook", true)]);
    }

    #[test]
    fn each_log_is_the_line_exactly_and_bodies_stay_under_the_limit() {
        let app = crate::runner::test_app();
        let id = app.db.try_record(&Event::new(Actor::system("test"), "test.secops").target("bot", "b1").details(json!({ "n": 1 }))).unwrap();
        let e = app.db.audit_events(&Default::default(), 1000, false).into_iter().find(|e| e.id == id).unwrap();
        let text = crate::audit_export::line_value(&e, "host-1", None, true).to_string();
        let l = log(&text, &e.time, &collected(e.at, e.at + 5));
        assert_eq!(l["logEntryTime"].as_str(), Some(e.time.as_str()));
        let back = String::from_utf8(STANDARD.decode(l["data"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(back, text, "the raw log is the line, byte for byte");
        assert_eq!(crate::audit_line::check(&serde_json::from_str(&back).unwrap()), Ok(crate::audit_line::Bound::All), "so it checks itself in SecOps");
        assert_eq!(collected(1_795_000_000_000, 1_795_000_000_250), "2026-11-18T11:06:40.250Z");
        assert_eq!(collected(1_795_000_000_000, 1_000), "2026-11-18T11:06:40.001Z", "never at or before the event, whatever the clock says");

        let logs: Vec<Value> = (0..40).map(|i| json!({ "data": format!("{i}").repeat(150), "logEntryTime": "t", "collectionTime": "c" })).collect();
        let split = bodies(&logs);
        assert!(split.len() > 1, "split: {}", split.len());
        let mut back = Vec::new();
        for b in &split {
            assert!(b.len() <= MAX_BODY, "{}", b.len());
            let v: Value = serde_json::from_slice(b).unwrap();
            back.extend(v["inlineSource"]["logs"].as_array().unwrap().clone());
        }
        assert_eq!(back, logs, "every log, once, in order");
        assert_eq!(bodies(&[json!({ "data": "y".repeat(MAX_BODY) })]).len(), 1, "alone");
        assert!(bodies(&[]).is_empty());
        assert_eq!(status_of(br#"{"error":{"code":403,"message":"Permission denied on quoting-the-request","status":"PERMISSION_DENIED"}}"#).as_deref(), Some("PERMISSION_DENIED"));
        assert_eq!(status_of(br#"{"error":{"status":"has spaces"}}"#), None);
    }

    /// A stand-in for the metadata server and the Chronicle API's `logs:import`.
    #[derive(Default)]
    struct Google {
        tokens: Mutex<Vec<String>>,
        /// Tokens the API no longer takes, as when one is past its time.
        revoked: Mutex<Vec<String>>,
        logs: Mutex<Vec<Value>>,
        requests: AtomicUsize,
        /// Answers this status to every import while set.
        refuse: AtomicUsize,
        /// Takes the next import, then answers it as a duplicate.
        duplicate: AtomicUsize,
    }

    type G = Arc<Google>;

    async fn metadata(State(g): State<G>, h: HeaderMap) -> (StatusCode, axum::Json<Value>) {
        if h.get("metadata-flavor").and_then(|v| v.to_str().ok()) != Some("Google") {
            return (StatusCode::FORBIDDEN, axum::Json(json!({})));
        }
        let token = format!("ya29.secops-{}", crate::random_hex(6));
        g.tokens.lock().unwrap().push(token.clone());
        (StatusCode::OK, axum::Json(json!({ "access_token": token, "expires_in": 3599, "token_type": "Bearer" })))
    }

    async fn import(State(g): State<G>, Path(rest): Path<String>, h: HeaderMap, axum::Json(body): axum::Json<Value>) -> (StatusCode, axum::Json<Value>) {
        g.requests.fetch_add(1, Ordering::SeqCst);
        assert_eq!(rest, format!("{PROJECT}/locations/eu/instances/{INSTANCE}/logTypes/SUPERBOT_AUDIT/logs:import"));
        assert_eq!(h.get("content-type").and_then(|v| v.to_str().ok()), Some("application/json"));
        assert!(h.get("content-encoding").is_none());
        let size: usize = h.get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()).expect("a request's size");
        assert!(size <= MAX_BODY, "{size}");
        let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        let known = g.tokens.lock().unwrap().iter().any(|t| auth == format!("Bearer {t}"));
        if !known || g.revoked.lock().unwrap().iter().any(|t| auth == format!("Bearer {t}")) {
            return (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": { "code": 401, "status": "UNAUTHENTICATED", "message": "quoting the request" } })));
        }
        match g.refuse.load(Ordering::SeqCst) {
            0 => {}
            s => return (StatusCode::from_u16(s as u16).unwrap(), axum::Json(json!({ "error": { "code": s, "status": "PERMISSION_DENIED", "message": "Permission 'chronicle.logs.import' denied on quoting-the-request" } }))),
        }
        for l in body["inlineSource"]["logs"].as_array().expect("logs") {
            let (entry, collection) = (l["logEntryTime"].as_str().unwrap(), l["collectionTime"].as_str().unwrap());
            assert!(chrono::DateTime::parse_from_rfc3339(collection).unwrap() > chrono::DateTime::parse_from_rfc3339(entry).unwrap(), "collected after the event");
        }
        g.logs.lock().unwrap().extend(body["inlineSource"]["logs"].as_array().unwrap().iter().cloned());
        if g.duplicate.swap(0, Ordering::SeqCst) == 1 {
            return (StatusCode::CONFLICT, axum::Json(json!({ "error": { "code": 409, "status": "ALREADY_EXISTS", "message": "x" } })));
        }
        (StatusCode::OK, axum::Json(json!({})))
    }

    async fn stand_in() -> (String, G) {
        let g = G::default();
        let r = axum::Router::new()
            .route("/computeMetadata/v1/instance/service-accounts/default/token", axum::routing::get(metadata))
            .route("/v1/projects/{*rest}", axum::routing::post(import))
            .with_state(g.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
        (format!("http://{addr}"), g)
    }

    fn lines_of(logs: &[Value]) -> crate::audit_line::Report {
        let mut lines = crate::audit_line::Lines::new(None);
        for (n, l) in logs.iter().enumerate() {
            let text = String::from_utf8(STANDARD.decode(l["data"].as_str().unwrap()).unwrap()).unwrap();
            lines.line(&text, &format!("secops:{}", n + 1));
        }
        lines.finish()
    }

    #[tokio::test]
    async fn every_event_reaches_secops_in_order_and_checks_itself() {
        let (_, app, _, _) = crate::tests::serve_app().await;
        let (base, google) = stand_in().await;
        for i in 0..30 {
            app.db.record(&Event::new(Actor::system("test"), "test.secops").details(json!({ "n": i, "pad": "p".repeat(200) })));
        }
        let mut s = settings(&[("AUDIT_EXPORT", &format!("secops={}", sink_url()))]).unwrap();
        s.sinks[0].secops_mut().unwrap().point_at(&base);
        crate::audit_export::start(&app, s);
        let xs = app.audit_export.get().unwrap().clone();
        until("delivered", || xs.delivered() >= app.db.audit_head()).await;

        assert_eq!(google.tokens.lock().unwrap().len(), 1, "one token, kept while it lasts");
        assert!(google.requests.load(Ordering::SeqCst) > 1, "a batch over the limit goes in several requests");
        let logs = google.logs.lock().unwrap().clone();
        let report = lines_of(&logs);
        assert!(report.ok && report.hosts[0].events == logs.len() as u64 && logs.len() >= 30 && report.hosts[0].first == Some(1), "botctl audit verify-lines passes on SecOps's copy, every event once: {report:?}");

        // A token Google no longer takes: one new one, and delivery carries on.
        let first = google.tokens.lock().unwrap()[0].clone();
        google.revoked.lock().unwrap().push(first);
        app.db.record(&Event::new(Actor::system("test"), "test.after_revoke"));
        until("delivered with a new token", || xs.delivered() >= app.db.audit_head()).await;
        assert_eq!(google.tokens.lock().unwrap().len(), 2);
        let failing = || app.db.audit_events(&crate::audit::Filter { actions: vec!["audit.export_failing".into()], ..Default::default() }, 10, false);
        assert!(failing().is_empty(), "a refused token isn't a failure");

        // A body SecOps says it already has is taken.
        google.duplicate.store(1, Ordering::SeqCst);
        app.db.record(&Event::new(Actor::system("test"), "test.duplicate"));
        until("a duplicate counts as delivered", || xs.delivered() >= app.db.audit_head()).await;

        // Without the permission, it fails with what to do, and waits.
        google.refuse.store(403, Ordering::SeqCst);
        let before = xs.delivered();
        app.db.record(&Event::new(Actor::system("test"), "test.forbidden"));
        until("failing", || !failing().is_empty()).await;
        let f = &failing()[0];
        assert_eq!((f.details["kind"].as_str(), f.details["name"].as_str(), f.details["reason"].as_str()), (Some("google-secops"), Some("secops"), Some("delivery_failed")));
        let error = f.details["error"].as_str().unwrap();
        assert!(error.contains("answered HTTP 403 (PERMISSION_DENIED): give botd's service account chronicle.logs.import") && !error.contains("quoting"), "{error}");
        assert_eq!(xs.delivered(), before, "the cursor stays");
        let v = xs.view(app.db.audit_head());
        assert_eq!((v["kind"].as_str(), v["failing"].as_bool(), v["googleSecOps"]["logType"].as_str(), v["compress"].as_str()), (Some("google-secops"), Some(true), Some("SUPERBOT_AUDIT"), Some("off")), "{v}");
        let mut metrics = String::new();
        crate::audit_export::render(&app, &mut metrics);
        assert!(metrics.contains("superbot_audit_export_failing{kind=\"google-secops\",name=\"secops\"} 1"), "{metrics}");
        let sent = serde_json::to_string(&*google.logs.lock().unwrap()).unwrap();
        assert!(google.tokens.lock().unwrap().iter().all(|t| !sent.contains(t.as_str())), "no token in what was sent");

        // Throttled: it waits, then carries on once SecOps takes events again.
        google.refuse.store(429, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        google.refuse.store(0, Ordering::SeqCst);
        until("recovered", || xs.delivered() >= app.db.audit_head()).await;
        let report = lines_of(&google.logs.lock().unwrap());
        assert!(report.ok, "copies from the retries check too: {report:?}");
    }

    #[tokio::test]
    async fn a_sign_in_that_fails_is_its_own_reason() {
        let (_, app, _, _) = crate::tests::serve_app().await;
        let mut s = settings(&[("AUDIT_EXPORT", &sink_url())]).unwrap();
        // Nothing listens there: no metadata server.
        s.sinks[0].secops_mut().unwrap().point_at("http://127.0.0.1:9");
        crate::audit_export::start(&app, s);
        let failing = || app.db.audit_events(&crate::audit::Filter { actions: vec!["audit.export_failing".into()], ..Default::default() }, 10, false);
        until("failing", || !failing().is_empty()).await;
        let f = &failing()[0];
        assert_eq!(f.details["reason"].as_str(), Some("sign_in_failed"), "{:?}", f.details);
        assert!(f.details["error"].as_str().unwrap().contains("couldn't sign in to Google for google-secops://eu-chronicle.googleapis.com"), "{:?}", f.details);
    }
}
