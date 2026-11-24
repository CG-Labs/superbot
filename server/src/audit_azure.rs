//! The audit export's Azure Monitor sink (ADR 0217): every event into a Log Analytics
//! workspace, where Microsoft Sentinel reads it, through the Logs Ingestion API.
//!
//! `AUDIT_EXPORT=azure-monitor://<ingestion host>/<DCR immutable id>/<stream>` names the
//! data collection rule's (or a data collection endpoint's) logs ingestion host, the rule
//! and its input stream. Each batch is `POST`ed as a JSON array of records, at most 1 MB
//! a request, with a bearer token botd gets from Entra ID as itself (the same `AZURE_*`
//! identity as Key Vault, `AUDIT_EXPORT_AZURE_AUTH`), kept while it lasts and asked
//! again once when Azure refuses it. Tokens go only to Azure Monitor's own hosts.
//!
//! A record carries the exported line whole (`Line`), so the copy in the workspace can be
//! checked with `botctl audit verify-lines`, and a few of its fields as typed columns for
//! queries and detections. Those columns come from the line as exported, so they never
//! say more than it does.

use crate::secrets::azure::Entra;
use crate::secrets::SecretStore;
use serde_json::{json, Value};
use std::time::Duration;

pub const API_VERSION: &str = "2023-01-01";
/// The Logs Ingestion API's limit for one request, compressed or not.
const MAX_BODY: usize = if cfg!(test) { 4_096 } else { 1_000_000 };
const TIMEOUT: Duration = Duration::from_secs(30);
/// The longest `Retry-After` botd waits for before trying again.
const MAX_RETRY_AFTER: u64 = 300;
const LABEL: &str = "Azure Monitor";

/// The typed columns, beside `TimeGenerated` and `Line`, and the line field each is from.
pub const COLUMNS: [(&str, &str); 17] = [
    ("EventId", "id"),
    ("Host", "host"),
    ("Action", "action"),
    ("Outcome", "outcome"),
    ("ActorKind", "actorKind"),
    ("ActorId", "actorId"),
    ("ActorName", "actorName"),
    ("ActorEmail", "actorEmail"),
    ("ActorRole", "actorRole"),
    ("AuthMethod", "authMethod"),
    ("TargetType", "targetType"),
    ("TargetId", "targetId"),
    ("BotId", "botId"),
    ("SourceIp", "ip"),
    ("SessionId", "sessionId"),
    ("Details", "details"),
    ("ChainHash", "chainHash"),
];

pub struct Monitor {
    /// The ingestion host, lowercase: `<name>.<region>-1.ingest.monitor.azure.com`.
    pub host: String,
    /// The data collection rule's immutable id: `dcr-` and 32 hex digits.
    pub dcr: String,
    /// The rule's input stream: `Custom-<name>` (or `Microsoft-<table>`).
    pub stream: String,
    /// Where batches go: `https://<host>/dataCollectionRules/<dcr>/streams/<stream>?api-version=...`.
    url: String,
    entra: Entra,
}

/// Azure Monitor's hosts in each cloud, and what tokens for them are for. Tokens for
/// Azure Monitor go nowhere else.
const CLOUDS: [(&str, &str); 3] = [(".monitor.azure.com", "https://monitor.azure.com"), (".monitor.azure.us", "https://monitor.azure.us"), (".monitor.azure.cn", "https://monitor.azure.cn")];

fn upload_url(base: &str, dcr: &str, stream: &str) -> String {
    format!("{base}/dataCollectionRules/{dcr}/streams/{stream}?api-version={API_VERSION}")
}

impl Monitor {
    /// `raw` is `azure-monitor://<host>/<dcr>/<stream>`; botd signs in as
    /// `AUDIT_EXPORT_AZURE_AUTH` says, or as `AZURE_KEYVAULT_AUTH` when that is set.
    pub fn from_env(raw: &str, get: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Monitor, String> {
        let bad = |why: &str| format!("AUDIT_EXPORT: an Azure Monitor sink is azure-monitor://<logs ingestion host>/<DCR immutable id>/<stream>, such as azure-monitor://superbot-a1b2.eastus-1.ingest.monitor.azure.com/dcr-00000000000000000000000000000000/Custom-SuperBotAudit: {why}");
        let u = url::Url::parse(raw.trim()).map_err(|_| bad("it isn't a URL"))?;
        if !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() {
            return Err(bad("no credentials, query or fragment: botd signs in with Entra ID (AUDIT_EXPORT_AZURE_AUTH)"));
        }
        if u.port().is_some_and(|p| p != 443) {
            return Err(bad("the Logs Ingestion API is on port 443"));
        }
        let host = u.host_str().unwrap_or_default().to_ascii_lowercase();
        let Some((_, resource)) = CLOUDS.iter().find(|(suffix, _)| host.len() > suffix.len() && host.ends_with(suffix)) else {
            return Err(bad(&format!("\"{host}\" isn't an Azure Monitor host (ending .monitor.azure.com, .monitor.azure.us or .monitor.azure.cn); take the logs ingestion endpoint from the DCR's JSON view, or the DCE's")));
        };
        let parts: Vec<&str> = u.path().trim_start_matches('/').split('/').collect();
        let [dcr, stream] = parts.as_slice() else { return Err(bad("the path is the DCR's immutable id, then the stream")) };
        let hex = dcr.strip_prefix("dcr-").filter(|h| h.len() == 32 && h.bytes().all(|b| b.is_ascii_hexdigit()));
        if hex.is_none() {
            return Err(bad(&format!("\"{dcr}\" isn't a DCR immutable id (dcr- and 32 hex digits, on the rule's Overview page)")));
        }
        let name = stream.strip_prefix("Custom-").or_else(|| stream.strip_prefix("Microsoft-"));
        if !name.is_some_and(|n| !n.is_empty() && n.len() <= 100 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')) {
            return Err(bad(&format!("\"{stream}\" isn't a stream name (Custom-<name>, as the DCR's streamDeclarations have it)")));
        }
        let (method_var, method) = match (get("AUDIT_EXPORT_AZURE_AUTH"), get("AZURE_KEYVAULT_AUTH")) {
            (m, _) if !m.trim().is_empty() => ("AUDIT_EXPORT_AZURE_AUTH", m),
            (_, kv) if !kv.trim().is_empty() => ("AZURE_KEYVAULT_AUTH", kv),
            _ => ("AUDIT_EXPORT_AZURE_AUTH", String::new()),
        };
        let entra = Entra::from_env(get, store, method_var, &method, LABEL, resource)?;
        let url = upload_url(&format!("https://{host}"), dcr, stream);
        Ok(Monitor { url, host, dcr: dcr.to_string(), stream: stream.to_string(), entra })
    }

    /// What logs, the API and the audit log show.
    pub fn shown(&self) -> String {
        format!("azure-monitor://{}", self.host)
    }

    /// The sink's cursor: another rule or stream starts again.
    pub fn id(&self) -> String {
        format!("azure-monitor://{}/{}/{}", self.host, self.dcr, self.stream)
    }

    pub fn describe(&self) -> String {
        format!("into Log Analytics through the Logs Ingestion API (rule {}, stream {}), signing in to Entra ID as {}", self.dcr, self.stream, self.entra.describe())
    }

    /// For `botctl audit siem`.
    pub fn view(&self) -> Value {
        json!({ "dataCollectionRule": self.dcr, "stream": self.stream, "signIn": self.entra.method(), "resource": self.entra.resource() })
    }

    /// Sends to `base` instead, and signs in there: a stand-in for Azure.
    #[cfg(test)]
    pub fn point_at(&mut self, base: &str) {
        self.url = upload_url(base, &self.dcr, &self.stream);
        self.entra.point_at(base);
    }
}

/// One exported line as a record of the stream: `TimeGenerated` from the event's time,
/// the typed columns from the line's own fields, and the line whole.
pub fn record(line: &Value, text: &str) -> Value {
    let mut r = serde_json::Map::new();
    r.insert("TimeGenerated".into(), line["time"].clone());
    for (column, field) in COLUMNS {
        r.insert(column.into(), line.get(field).cloned().unwrap_or(Value::Null));
    }
    r.insert("Line".into(), json!(text));
    Value::Object(r)
}

/// The records as JSON arrays of at most [`MAX_BODY`] bytes each, in order. A record
/// bigger than that on its own goes alone, and Azure refuses it.
pub fn bodies(records: &[Value]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut body = vec![b'['];
    for r in records {
        let r = r.to_string();
        if body.len() > 1 && body.len() + r.len() + 2 > MAX_BODY {
            body.push(b']');
            out.push(std::mem::replace(&mut body, vec![b'[']));
        }
        if body.len() > 1 {
            body.push(b',');
        }
        body.extend(r.as_bytes());
    }
    if body.len() > 1 {
        body.push(b']');
        out.push(body);
    }
    out
}

/// The error code in Azure's answer, when it is safe to log: never its message, which
/// may quote what was sent.
fn code(body: &[u8]) -> String {
    let v: Value = serde_json::from_slice(body).unwrap_or_default();
    match v["error"]["code"].as_str() {
        Some(c) if !c.is_empty() && c.len() <= 64 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)) => format!(" ({c})"),
        _ => String::new(),
    }
}

fn hint(status: u16) -> &'static str {
    match status {
        401 => ": it refused botd's token, a new one too; is AZURE_AUTHORITY_HOST this cloud's?",
        403 => ": give botd's identity the Monitoring Metrics Publisher role on the data collection rule (it can take 30 minutes to apply)",
        404 => ": check the DCR's immutable id and the stream name, and that the host is the rule's (or its DCE's) logs ingestion endpoint",
        400 => ": does the rule's stream declare the columns botd sends? See docs/ops/audit-export.md",
        413 => ": a request was over 1 MB",
        429 => ": throttled; botd waits as Azure asks",
        _ => "",
    }
}

pub struct Client {
    http: reqwest::Client,
}

impl Client {
    pub fn new(m: &Monitor) -> Client {
        let http = reqwest::Client::builder().https_only(m.url.starts_with("https://")).timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none()).build().expect("HTTP client");
        Client { http }
    }

    /// Sends one batch's records, a request per body. Each is accepted with a 204; a
    /// failed one fails the batch, which goes again whole (Azure keeps the bodies it took,
    /// so a retry can repeat events, as any at-least-once export can).
    pub async fn send(&self, m: &Monitor, records: &[Value]) -> Result<(), (&'static str, String)> {
        let shown = m.shown();
        for body in bodies(records) {
            let mut fresh = false;
            loop {
                let token = m.entra.token(fresh).await.map_err(|e| ("sign_in_failed", format!("couldn't sign in to Entra ID for {shown}: {e}")))?;
                let req = self.http.post(&m.url).bearer_auth(token.as_str()).header(reqwest::header::CONTENT_TYPE, "application/json").body(body.clone());
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
                let wait = (status == reqwest::StatusCode::TOO_MANY_REQUESTS)
                    .then(|| r.headers().get(reqwest::header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok()))
                    .flatten();
                let answer = r.bytes().await.unwrap_or_default();
                if let Some(secs) = wait {
                    tokio::time::sleep(Duration::from_secs(secs.min(MAX_RETRY_AFTER))).await;
                }
                return Err(("delivery_failed", format!("{shown} answered HTTP {}{}{}", status.as_u16(), code(&answer), hint(status.as_u16()))));
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
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const DCR: &str = "dcr-0123456789abcdef0123456789abcdef";
    const HOST: &str = "superbot-a1b2.eastus-1.ingest.monitor.azure.com";

    fn settings(vars: &[(&str, &str)]) -> Result<Settings, String> {
        let store = EnvStore::fixed(vars);
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Settings::from_env(&|k| map.get(k).cloned().unwrap_or_default(), &store)
    }

    fn monitor(vars: &[(&str, &str)]) -> Result<Monitor, String> {
        let store = EnvStore::fixed(vars);
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let raw = map.get("AUDIT_EXPORT").cloned().unwrap_or_default();
        Monitor::from_env(&raw, &|k| map.get(k).cloned().unwrap_or_default(), &store)
    }

    #[test]
    fn the_sink_names_a_rule_and_stream_on_azure_monitors_own_hosts() {
        let url = format!("azure-monitor://{}/{DCR}/Custom-SuperBotAudit", HOST.to_ascii_uppercase());
        let s = settings(&[("AUDIT_EXPORT", &format!("sentinel={url}"))]).unwrap().sinks.remove(0);
        assert_eq!((s.kind(), s.name.as_deref(), s.shown.as_str()), ("azure-monitor", Some("sentinel"), format!("azure-monitor://{HOST}").as_str()));
        assert_eq!(s.id, format!("azure-monitor://{HOST}/{DCR}/Custom-SuperBotAudit"), "another rule or stream is another cursor");
        let m = monitor(&[("AUDIT_EXPORT", &url)]).unwrap();
        assert_eq!(m.url, format!("https://{HOST}/dataCollectionRules/{DCR}/streams/Custom-SuperBotAudit?api-version={API_VERSION}"));
        assert_eq!((m.entra.method(), m.entra.resource()), ("managed-identity", "https://monitor.azure.com"));
        for (host, resource) in [("x.usgovvirginia-1.ingest.monitor.azure.us", "https://monitor.azure.us"), ("x.chinanorth3-1.ingest.monitor.azure.cn", "https://monitor.azure.cn")] {
            let m = monitor(&[("AUDIT_EXPORT", &format!("azure-monitor://{host}/{DCR}/Custom-A"))]).unwrap();
            assert_eq!(m.entra.resource(), resource, "{host}: each cloud's tokens are its own");
        }
        assert!(monitor(&[("AUDIT_EXPORT", &format!("azure-monitor://{HOST}:443/{DCR}/Microsoft-Syslog"))]).is_ok());
        let d = settings(&[("AUDIT_EXPORT", &url), ("AZURE_CLIENT_ID", "user-assigned-1")]).unwrap().describe();
        assert!(d.contains(&format!("into Log Analytics through the Logs Ingestion API (rule {DCR}, stream Custom-SuperBotAudit), signing in to Entra ID as user-assigned managed identity user-assigned-1")), "{d}");

        for (raw, why) in [
            (format!("azure-monitor://evil.example.net/{DCR}/Custom-A"), "isn't an Azure Monitor host"),
            (format!("azure-monitor://monitor.azure.com.evil.example/{DCR}/Custom-A"), "isn't an Azure Monitor host"),
            (format!("azure-monitor://.monitor.azure.com/{DCR}/Custom-A"), "isn't an Azure Monitor host"),
            (format!("azure-monitor://{HOST}:8443/{DCR}/Custom-A"), "port 443"),
            (format!("azure-monitor://{HOST}/{DCR}/Custom-A?api-version=2023-01-01"), "no credentials, query or fragment"),
            (format!("azure-monitor://u:p@{HOST}/{DCR}/Custom-A"), "no credentials"),
            (format!("azure-monitor://{HOST}/{DCR}"), "the DCR's immutable id, then the stream"),
            (format!("azure-monitor://{HOST}/dataCollectionRules/{DCR}/streams/Custom-A"), "the DCR's immutable id, then the stream"),
            (format!("azure-monitor://{HOST}/dcr-123/Custom-A"), "isn't a DCR immutable id"),
            (format!("azure-monitor://{HOST}/{DCR}/SuperBotAudit"), "isn't a stream name"),
            (format!("azure-monitor://{HOST}/{DCR}/Custom-"), "isn't a stream name"),
            (format!("azure-monitor://{HOST}/{DCR}/Custom-a%20b"), "isn't a stream name"),
        ] {
            let e = settings(&[("AUDIT_EXPORT", &raw)]).unwrap_err();
            assert!(e.contains(why), "{raw}: {e}");
        }
    }

    #[test]
    fn it_signs_in_as_botds_azure_identity_and_takes_no_headers() {
        let url = format!("azure-monitor://{HOST}/{DCR}/Custom-SuperBotAudit");
        let secret = "sbx-azure-monitor-sp-secret-7e6d5c";
        let sp = [("AUDIT_EXPORT", url.as_str()), ("AUDIT_EXPORT_AZURE_AUTH", "client-secret"), ("AZURE_TENANT_ID", "tenant-1"), ("AZURE_CLIENT_ID", "client-1"), ("AZURE_CLIENT_SECRET", secret)];
        let s = settings(&sp).unwrap();
        assert!(s.describe().contains("service principal client-1 in tenant tenant-1") && !s.describe().contains(secret) && !format!("{s:?}").contains(secret));
        assert!(!crate::secrets::redact::text(&format!("x {secret} y")).contains(secret), "registered, so an error quoting it is masked");
        // With Key Vault, the same identity unless the export says otherwise.
        let m = monitor(&[("AUDIT_EXPORT", url.as_str()), ("AZURE_KEYVAULT_AUTH", "workload-identity"), ("AZURE_TENANT_ID", "t"), ("AZURE_CLIENT_ID", "c"), ("AZURE_FEDERATED_TOKEN_FILE", "/var/run/token")]).unwrap();
        assert_eq!(m.entra.method(), "workload-identity");
        let m = monitor(&[("AUDIT_EXPORT", url.as_str()), ("AZURE_KEYVAULT_AUTH", "workload-identity"), ("AUDIT_EXPORT_AZURE_AUTH", "managed-identity")]).unwrap();
        assert_eq!(m.entra.method(), "managed-identity");

        for (vars, why) in [
            (vec![("AUDIT_EXPORT_AZURE_AUTH", "password")], "AUDIT_EXPORT_AZURE_AUTH must be managed-identity, client-secret or workload-identity"),
            (vec![("AUDIT_EXPORT_AZURE_AUTH", "client-secret"), ("AZURE_TENANT_ID", "t"), ("AZURE_CLIENT_ID", "c")], "AUDIT_EXPORT_AZURE_AUTH=client-secret needs AZURE_CLIENT_SECRET"),
            (vec![("AUDIT_EXPORT_AZURE_AUTH", "workload-identity"), ("AZURE_TENANT_ID", "t"), ("AZURE_CLIENT_ID", "c")], "AUDIT_EXPORT_AZURE_AUTH=workload-identity needs AZURE_FEDERATED_TOKEN_FILE"),
            (vec![("AZURE_KEYVAULT_AUTH", "client-secret")], "AZURE_KEYVAULT_AUTH=client-secret needs AZURE_CLIENT_SECRET"),
            (vec![("AUDIT_EXPORT_HEADERS", "Authorization=Bearer x")], "AUDIT_EXPORT_HEADERS is for an https sink; Azure Monitor signs in with Entra ID"),
        ] {
            let mut all = vec![("AUDIT_EXPORT", url.as_str())];
            all.extend(vars);
            let e = settings(&all).unwrap_err();
            assert!(e.contains(why), "{all:?}: {e}");
        }
        let e = settings(&[("AUDIT_EXPORT", &format!("sentinel={url}")), ("AUDIT_EXPORT_HEADERS_SENTINEL", "X=1")]).unwrap_err();
        assert!(e.contains("AUDIT_EXPORT_HEADERS_SENTINEL is for an https sink; Azure Monitor signs in with Entra ID"), "{e}");
        // It is one of the SIEMs: with another, both need names.
        let e = settings(&[("AUDIT_EXPORT", &format!("{url},https://siem.example.net/in"))]).unwrap_err();
        assert!(e.contains("name each"), "{e}");
        let s = settings(&[("AUDIT_EXPORT", &format!("sentinel={url},splunk=https://siem.example.net/in"))]).unwrap();
        assert_eq!(s.sinks.iter().map(|s| s.kind()).collect::<Vec<_>>(), ["azure-monitor", "webhook"]);
    }

    #[test]
    fn records_carry_the_line_whole_and_bodies_stay_under_the_limit() {
        let app = crate::runner::test_app();
        let id = app.db.try_record(&Event::new(Actor::system("test"), "test.monitor").target("bot", "b1").details(json!({ "n": 1 }))).unwrap();
        let e = app.db.audit_events(&Default::default(), 1000, false).into_iter().find(|e| e.id == id).unwrap();
        let v = crate::audit_export::line_value(&e, "host-1", None, true);
        let text = v.to_string();
        let r = record(&v, &text);
        assert_eq!((r["TimeGenerated"].as_str(), r["EventId"].as_i64(), r["Host"].as_str(), r["Action"].as_str()), (Some(e.time.as_str()), Some(id), Some("host-1"), Some("test.monitor")));
        assert_eq!((r["TargetType"].as_str(), r["TargetId"].as_str(), &r["Details"], r["ChainHash"].as_str()), (Some("bot"), Some("b1"), &json!({ "n": 1 }), e.chain_hash.as_deref()));
        assert_eq!(r["ActorEmail"], Value::Null);
        assert_eq!(r.as_object().unwrap().len(), COLUMNS.len() + 2);
        let line: Value = serde_json::from_str(r["Line"].as_str().unwrap()).unwrap();
        assert_eq!(crate::audit_line::check(&line), Ok(crate::audit_line::Bound::All), "the line in the workspace checks itself");
        for (column, _) in COLUMNS {
            let ok = column.len() <= 45 && column.starts_with(|c: char| c.is_ascii_alphabetic()) && !["id", "TenantId", "Type", "Title", "UniqueId"].contains(&column);
            assert!(ok, "{column}: a column name Log Analytics takes");
        }

        let records: Vec<Value> = (0..40).map(|i| json!({ "EventId": i, "Line": "x".repeat(300) })).collect();
        let split = bodies(&records);
        assert!(split.len() > 1, "split: {}", split.len());
        let mut back = Vec::new();
        for b in &split {
            assert!(b.len() <= MAX_BODY, "{}", b.len());
            back.extend(serde_json::from_slice::<Vec<Value>>(b).unwrap());
        }
        assert_eq!(back, records, "every record, once, in order");
        let big = vec![json!({ "Line": "y".repeat(MAX_BODY) })];
        assert_eq!(bodies(&big).len(), 1, "alone");
        assert!(bodies(&[]).is_empty());
    }

    /// A stand-in for the instance metadata service, Entra ID and the Logs Ingestion API.
    #[derive(Default)]
    struct Azure {
        tokens: Mutex<Vec<String>>,
        asked: Mutex<Vec<HashMap<String, String>>>,
        /// Tokens Azure Monitor no longer takes, as when one is past its time.
        revoked: Mutex<Vec<String>>,
        records: Mutex<Vec<Value>>,
        requests: AtomicUsize,
        /// Answers this status to every upload while set.
        refuse: AtomicUsize,
    }

    type A = Arc<Azure>;

    async fn imds(State(a): State<A>, Query(q): Query<HashMap<String, String>>, h: HeaderMap) -> (StatusCode, axum::Json<Value>) {
        if h.get("metadata").and_then(|v| v.to_str().ok()) != Some("true") {
            return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": "invalid_request" })));
        }
        let token = format!("eyJ.monitor-{}", crate::random_hex(6));
        a.tokens.lock().unwrap().push(token.clone());
        a.asked.lock().unwrap().push(q);
        (StatusCode::OK, axum::Json(json!({ "access_token": token, "expires_in": "86399", "token_type": "Bearer" })))
    }

    async fn upload(State(a): State<A>, Path((dcr, stream)): Path<(String, String)>, Query(q): Query<HashMap<String, String>>, h: HeaderMap, body: String) -> (StatusCode, axum::Json<Value>) {
        a.requests.fetch_add(1, Ordering::SeqCst);
        assert_eq!((dcr.as_str(), stream.as_str(), q.get("api-version").map(String::as_str)), (DCR, "Custom-SuperBotAudit", Some(API_VERSION)));
        assert_eq!(h.get("content-type").and_then(|v| v.to_str().ok()), Some("application/json"));
        assert!(body.len() <= MAX_BODY, "{}", body.len());
        let auth = h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        let known = a.tokens.lock().unwrap().iter().any(|t| auth == format!("Bearer {t}"));
        if !known || a.revoked.lock().unwrap().iter().any(|t| auth == format!("Bearer {t}")) {
            return (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": { "code": "InvalidToken", "message": "quoting the request" } })));
        }
        match a.refuse.load(Ordering::SeqCst) {
            0 => {}
            s => return (StatusCode::from_u16(s as u16).unwrap(), axum::Json(json!({ "error": { "code": "OperationFailed", "message": "The authentication token provided does not have access to ingest data for the data collection rule" } }))),
        }
        a.records.lock().unwrap().extend(serde_json::from_str::<Vec<Value>>(&body).unwrap());
        (StatusCode::NO_CONTENT, axum::Json(Value::Null))
    }

    async fn stand_in() -> (String, A) {
        let a = A::default();
        let r = axum::Router::new()
            .route("/metadata/identity/oauth2/token", axum::routing::get(imds))
            .route("/dataCollectionRules/{dcr}/streams/{stream}", axum::routing::post(upload))
            .with_state(a.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
        (format!("http://{addr}"), a)
    }

    #[tokio::test]
    async fn every_event_reaches_the_workspace_in_order_and_checks_itself() {
        let (_, app, _, _) = crate::tests::serve_app().await;
        let (base, azure) = stand_in().await;
        for i in 0..30 {
            app.db.record(&Event::new(Actor::system("test"), "test.sentinel").details(json!({ "n": i, "pad": "p".repeat(200) })));
        }
        let url = format!("sentinel=azure-monitor://{HOST}/{DCR}/Custom-SuperBotAudit");
        let mut s = settings(&[("AUDIT_EXPORT", &url), ("AZURE_CLIENT_ID", "user-assigned-1")]).unwrap();
        s.sinks[0].monitor_mut().unwrap().point_at(&base);
        crate::audit_export::start(&app, s);
        let xs = app.audit_export.get().unwrap().clone();
        until("delivered", || xs.delivered() >= app.db.audit_head()).await;

        let asked = azure.asked.lock().unwrap()[0].clone();
        assert_eq!((asked["resource"].as_str(), asked["client_id"].as_str()), ("https://monitor.azure.com", "user-assigned-1"));
        assert_eq!(azure.tokens.lock().unwrap().len(), 1, "one token, kept while it lasts");
        let records = azure.records.lock().unwrap().clone();
        assert!(azure.requests.load(Ordering::SeqCst) > 1, "a batch over 1 MB goes in several requests");
        let ids: Vec<i64> = records.iter().map(|r| r["EventId"].as_i64().unwrap()).collect();
        assert_eq!(ids, (1..=*ids.last().unwrap()).collect::<Vec<_>>(), "every event once, in order, history first");
        let mut lines = crate::audit_line::Lines::new(None);
        for (n, r) in records.iter().enumerate() {
            assert_eq!(r["TimeGenerated"], serde_json::from_str::<Value>(r["Line"].as_str().unwrap()).unwrap()["time"]);
            lines.line(r["Line"].as_str().unwrap(), &format!("workspace:{}", n + 1));
        }
        let report = lines.finish();
        assert!(report.ok, "botctl audit verify-lines passes on the workspace's copy: {report:?}");

        // A token Azure no longer takes: one new one, and delivery carries on.
        let first = azure.tokens.lock().unwrap()[0].clone();
        azure.revoked.lock().unwrap().push(first);
        app.db.record(&Event::new(Actor::system("test"), "test.after_revoke"));
        until("delivered with a new token", || xs.delivered() >= app.db.audit_head()).await;
        assert_eq!(azure.tokens.lock().unwrap().len(), 2);
        assert!(!app.db.audit_events(&Default::default(), 1000, false).iter().any(|e| e.action == "audit.export_failing"), "a refused token isn't a failure");

        // Without the role on the rule, it fails with what to do, and waits.
        azure.refuse.store(403, Ordering::SeqCst);
        let before = xs.delivered();
        app.db.record(&Event::new(Actor::system("test"), "test.forbidden"));
        let failing = || app.db.audit_events(&crate::audit::Filter { actions: vec!["audit.export_failing".into()], ..Default::default() }, 10, false);
        until("failing", || !failing().is_empty()).await;
        let f = &failing()[0];
        assert_eq!((f.details["kind"].as_str(), f.details["name"].as_str(), f.details["reason"].as_str()), (Some("azure-monitor"), Some("sentinel"), Some("delivery_failed")));
        let error = f.details["error"].as_str().unwrap();
        assert!(error.contains("answered HTTP 403 (OperationFailed): give botd's identity the Monitoring Metrics Publisher role") && !error.contains("ingest data"), "{error}");
        assert_eq!(xs.delivered(), before, "the cursor stays");
        let v = xs.view(app.db.audit_head());
        assert_eq!((v["kind"].as_str(), v["failing"].as_bool(), v["azureMonitor"]["stream"].as_str()), (Some("azure-monitor"), Some(true), Some("Custom-SuperBotAudit")), "{v}");
        let mut metrics = String::new();
        crate::audit_export::render(&app, &mut metrics);
        assert!(metrics.contains("superbot_audit_export_failing{kind=\"azure-monitor\",name=\"sentinel\"} 1"), "{metrics}");
        let body = serde_json::to_string(&*azure.records.lock().unwrap()).unwrap();
        assert!(azure.tokens.lock().unwrap().iter().all(|t| !body.contains(t.as_str())), "no token in what was sent");

        azure.refuse.store(0, Ordering::SeqCst);
        until("recovered", || xs.delivered() >= app.db.audit_head()).await;
    }

    #[tokio::test]
    async fn a_sign_in_that_fails_is_its_own_reason() {
        let (_, app, _, _) = crate::tests::serve_app().await;
        let url = format!("azure-monitor://{HOST}/{DCR}/Custom-SuperBotAudit");
        let mut s = settings(&[("AUDIT_EXPORT", &url)]).unwrap();
        // Nothing listens there: no instance metadata service.
        s.sinks[0].monitor_mut().unwrap().point_at("http://127.0.0.1:9");
        crate::audit_export::start(&app, s);
        let failing = || app.db.audit_events(&crate::audit::Filter { actions: vec!["audit.export_failing".into()], ..Default::default() }, 10, false);
        until("failing", || !failing().is_empty()).await;
        let f = &failing()[0];
        assert_eq!(f.details["reason"].as_str(), Some("sign_in_failed"), "{:?}", f.details);
        assert!(f.details["error"].as_str().unwrap().contains("couldn't sign in to Entra ID for azure-monitor://"), "{:?}", f.details);
    }
}
