//! ADR 0288: `superbot-evidence alerts` against a stand-in for Prometheus' query and rules
//! API: botd's scrape and the alerts read a day at a time with the token on every request,
//! a page and a ticket as episodes, a gap in the scrape, Alertmanager's notifications, and
//! the shipped rules loaded. Then the operator's own rule file naming a rule that isn't
//! loaded, which maps no controls. The token, Prometheus' address and the hosts in alert
//! labels are never written. The bundle checks with `tar`, `sha256sum -c` and
//! `superbot-evidence coverage`.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const TOKEN: &str = "test-token-alerts-5e02b7";
const WATCH: &str = r#"up{job="superbot"}"#;
const ALERTS: &str = r#"ALERTS{alertstate="firing"}"#;
/// 2026-10-01T00:00:00Z and 2026-11-01T00:00:00Z.
const START: i64 = 1_790_812_800;
const END: i64 = START + 31 * 86_400;

fn at(d: i64, h: i64, m: i64) -> i64 {
    START + (d - 1) * 86_400 + h * 3600 + m * 60
}

struct Mock {
    requests: Mutex<Vec<(String, Option<String>)>>,
}

/// Every alert the shipped rule files define, with its severity.
fn shipped() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../deploy/prometheus");
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap() {
        let path = e.unwrap().path();
        if !path.to_string_lossy().ends_with(".rules.yml") {
            continue;
        }
        for line in fs::read_to_string(&path).unwrap().lines() {
            let t = line.trim();
            if let Some(name) = t.strip_prefix("- alert:") {
                out.push((name.trim().to_string(), String::new()));
            } else if let (Some(sev), Some(last)) = (t.strip_prefix("severity:"), out.last_mut()) {
                if last.1.is_empty() {
                    last.1 = sev.trim().to_string();
                }
            }
        }
    }
    out
}

fn reply(status: u16, body: Value) -> Response {
    let mut r = (StatusCode::from_u16(status).unwrap(), body.to_string()).into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    r
}

fn ok(data: Value) -> Response {
    reply(200, json!({ "status": "success", "data": data }))
}

/// botd scraped every 30 seconds, but for 8 minutes at noon on 9 October; SuperBotDown
/// firing from 10:00 to 10:12 on 20 October; a disk on an Incus host filling for an hour on
/// 25 October; Alertmanager sending an email and failing a webhook on 20 October.
async fn prometheus(State(m): State<Arc<Mock>>, uri: Uri, headers: HeaderMap) -> Response {
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(String::from);
    let q: HashMap<String, String> = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).into_owned().collect();
    m.requests.lock().unwrap().push((format!("{}?{}", uri.path(), q.get("query").or(q.get("type")).cloned().unwrap_or_default()), auth));
    if uri.path() == "/prom/api/v1/rules" {
        let now = chrono::Utc::now().to_rfc3339();
        let rules: Vec<Value> = shipped().into_iter().map(|(name, severity)| json!({ "type": "alerting", "name": name, "health": "ok", "lastError": "", "labels": { "severity": severity }, "lastEvaluation": now, "duration": 300, "query": "up{instance=\"botd.internal:8080\"} == 0" })).collect();
        return ok(json!({ "groups": [{ "name": "superbot-alerts", "file": "/etc/prometheus/superbot.rules.yml", "rules": rules, "interval": 60 }] }));
    }
    if uri.path() != "/prom/api/v1/query" {
        return reply(404, json!({ "status": "error", "error": "not found" }));
    }
    let time: i64 = q["time"].parse().unwrap();
    let query = q["query"].clone();
    if let Some(rest) = query.strip_prefix("sum by (integration) (increase(") {
        let day20 = time == at(21, 0, 0);
        let result = match (rest.starts_with("alertmanager_notifications_failed_total"), day20) {
            (false, true) => json!([{ "metric": { "integration": "email" }, "value": [time, "1.0000002"] }, { "metric": { "integration": "webhook" }, "value": [time, "1"] }]),
            (true, true) => json!([{ "metric": { "integration": "webhook" }, "value": [time, "1"] }, { "metric": { "integration": "email" }, "value": [time, "0"] }]),
            (false, false) => json!([{ "metric": { "integration": "email" }, "value": [time, "0"] }]),
            (true, false) => json!([]),
        };
        return ok(json!({ "resultType": "vector", "result": result }));
    }
    let Some((selector, range)) = query.rsplit_once('[') else {
        return reply(400, json!({ "status": "error", "errorType": "bad_data", "error": "unexpected query" }));
    };
    let from = time - range.trim_end_matches("s]").parse::<i64>().unwrap();
    let within = |t: &i64| *t > from && *t <= time;
    let result = match selector {
        WATCH => {
            let gap = at(9, 12, 0);
            let values: Vec<Value> = (START - 3600..END + 3600).step_by(30).filter(within).filter(|t| !(gap..gap + 8 * 60).contains(t)).map(|t| json!([t as f64, "1"])).collect();
            json!([{ "metric": { "__name__": "up", "job": "superbot", "instance": "botd.internal:8080" }, "values": values }])
        }
        ALERTS => {
            let series = |labels: Value, a: i64, b: i64| json!({ "metric": labels, "values": (a..=b).step_by(60).filter(within).map(|t| json!([t as f64, "1"])).collect::<Vec<_>>() });
            json!([
                series(json!({ "__name__": "ALERTS", "alertname": "SuperBotDown", "alertstate": "firing", "severity": "page", "job": "superbot", "instance": "botd.internal:8080" }), at(20, 10, 0), at(20, 10, 12)),
                series(json!({ "__name__": "ALERTS", "alertname": "SuperBotHostDiskFilling", "alertstate": "firing", "severity": "ticket", "job": "superbot", "host": "incus-a.internal" }), at(25, 0, 0), at(25, 1, 0)),
            ])
        }
        _ => json!([]),
    };
    ok(json!({ "resultType": "matrix", "result": result }))
}

fn serve() -> (Arc<Mock>, String) {
    let m = Arc::new(Mock { requests: Mutex::new(Vec::new()) });
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}/prom", listener.local_addr().unwrap());
    let app = axum::Router::new().fallback(prometheus).with_state(m.clone());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move { axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app).await.unwrap() });
    });
    (m, base)
}

fn temp() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!("superbot-alert-evidence-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn evidence(dir: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_superbot-evidence"));
    cmd.current_dir(dir).env_remove("PROMETHEUS_TOKEN");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.args(args).output().unwrap()
}

fn text(o: &Output) -> String {
    format!("{}\n{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn json_in(dir: &Path, name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.join(name)).unwrap_or_else(|_| panic!("{name} in the bundle"))).unwrap()
}

fn unpack(dir: &Path, tar: &Path) -> PathBuf {
    let out = dir.join(format!("unpacked-{}", tar.file_stem().unwrap().to_string_lossy()));
    fs::create_dir_all(&out).unwrap();
    assert!(Command::new("tar").arg("-xf").arg(tar).current_dir(&out).status().unwrap().success(), "any tar reads it");
    let folder = fs::read_dir(&out).unwrap().map(|e| e.unwrap().path()).find(|p| p.is_dir() && p.file_name().unwrap().to_string_lossy().starts_with("superbot-alerts-2026-10-01_2026-11-01-")).unwrap();
    let check = Command::new("sha256sum").args(["-c", "SHA256SUMS"]).current_dir(&folder).output().unwrap();
    assert!(check.status.success(), "sha256sum -c: {}", String::from_utf8_lossy(&check.stdout));
    folder
}

const PERIOD: [&str; 4] = ["--from", "2026-10-01", "--to", "2026-11-01"];

#[test]
fn a_month_of_alert_history_as_a_checkable_bundle() {
    let (m, base) = serve();
    let dir = temp();
    let env = [("PROMETHEUS_TOKEN", TOKEN)];
    let o = evidence(&dir, &env, &[&["alerts", "--prometheus", &base, "-o", "alerts.tar"][..], &PERIOD].concat());
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    let rules = shipped().len();
    for want in [
        "2 alert episodes (1 pages), 72 firing minutes".to_string(),
        "Prometheus unwatched 9 minutes".to_string(),
        format!("{rules} of {rules} expected rules loaded"),
        "2 notifications sent, 1 failed".to_string(),
        "Pages, each needing its response on record: SuperBotDown-20261020T1000Z-".to_string(),
        "Notifications failed: 2026-10-20 webhook 1".to_string(),
        "in 125 requests".to_string(),
    ] {
        assert!(out.contains(&want), "{want}\n{out}");
    }
    assert!(!out.contains("maps no controls"), "{out}");

    let requests = m.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 125, "botd's scrape and the alerts a day at a time, two notification counters a day, and the rules once");
    assert!(requests.iter().all(|(_, a)| a.as_deref() == Some(&format!("Bearer {TOKEN}"))), "the token on every request");
    assert_eq!((requests[0].0.as_str(), requests[31].0.as_str(), requests[124].0.as_str()), (&*format!("/prom/api/v1/query?{WATCH}[86460s]"), &*format!("/prom/api/v1/query?{ALERTS}[86460s]"), "/prom/api/v1/rules?alert"));

    let tar = dir.join("alerts.tar");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&tar).unwrap().permissions().mode() & 0o777, 0o600, "private to its owner");
    }
    let raw = fs::read(&tar).unwrap();
    for never in [TOKEN, "internal", "127.0.0.1", "/etc/prometheus", "== 0"] {
        assert!(!raw.windows(never.len()).any(|w| w == never.as_bytes()), "{never:?} is in the bundle");
    }
    let folder = unpack(&dir, &tar);
    let manifest = json_in(&folder, "manifest.json");
    assert_eq!((manifest["kind"].as_str(), manifest["format"].as_u64(), manifest["source"]["requests"].as_u64(), manifest["source"]["watch"].as_str()), (Some("alerting"), Some(1), Some(125), Some(WATCH)));
    assert_eq!((manifest["files"][1]["name"].as_str(), manifest["files"][1]["checklist"].clone()), (Some("alerts.json"), json!(["CC2.1-1", "CC7.2-1", "A1.1-1"])));
    assert_eq!(manifest["source"]["rulesExpected"]["kind"], "shipped");

    let a = json_in(&folder, "alerts.json");
    assert_eq!((a["summary"]["unwatchedMinutes"].as_i64(), a["summary"]["mapsControls"].as_bool()), (Some(9), Some(true)));
    assert_eq!(a["exceptions"]["watchGaps"], json!(["2026-10-09T11:59:30Z/2026-10-09T12:08:00Z"]));
    let ep = a["episodes"].as_array().unwrap();
    assert_eq!(ep.iter().map(|e| (e["alert"].as_str().unwrap(), e["severity"].as_str().unwrap(), e["minutes"].as_i64().unwrap())).collect::<Vec<_>>(), [("SuperBotDown", "page", 12), ("SuperBotHostDiskFilling", "ticket", 60)]);
    assert_eq!(ep[1]["labels"], json!({ "alertname": "SuperBotHostDiskFilling", "severity": "ticket", "job": "superbot" }), "never the host");
    assert_eq!(a["exceptions"]["notificationsNotRecorded"], json!([]));
    assert_eq!(a["byDay"][19]["notifications"], json!({ "sent": { "email": 1, "webhook": 1 }, "failed": { "email": 0, "webhook": 1 } }));
    assert_eq!(a["periodCovered"]["days"], 31);

    // The coverage report reads it as a seventh kind of bundle.
    let store = dir.join("store");
    fs::create_dir_all(store.join("CC7.2/2026-10")).unwrap();
    fs::copy(&tar, store.join("CC7.2/2026-10/alerts.tar")).unwrap();
    let o = evidence(&dir, &[], &[&["coverage", store.to_str().unwrap(), "--json"][..], &PERIOD].concat());
    assert_eq!(o.status.code(), Some(2), "the other kinds are missing: {}", text(&o));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap();
    let kind = r["kinds"].as_array().unwrap().iter().find(|k| k["kind"] == "alerting").unwrap();
    assert_eq!((kind["complete"].as_bool(), r["bundles"][0]["verified"].as_bool()), (Some(true), Some(true)), "{r:#}");
    for id in ["CC2.1-1", "CC7.2-1", "A1.1-1"] {
        assert_eq!(r["rows"].as_array().unwrap().iter().find(|x| x["row"] == id).unwrap()["complete"], true, "{id}");
    }
    assert_eq!((r["bundles"][0]["exceptions"]["alerts.json"]["pages"].as_u64(), r["bundles"][0]["exceptions"]["alerts.json"]["watchGaps"].as_u64()), (Some(1), Some(1)));

    // The operator's own rule file, naming a rule Prometheus hasn't loaded: no controls.
    fs::write(dir.join("mine.rules.yml"), "groups:\n  - name: mine\n    rules:\n      - alert: SuperBotDown\n        expr: up == 0\n        labels:\n          severity: page\n      - alert: SuperBotLicenceExpiring\n        expr: x < 7\n        labels:\n          severity: ticket\n").unwrap();
    let o = evidence(&dir, &env, &[&["alerts", "--prometheus", &base, "--rules", "mine.rules.yml", "-o", "mine.tar"][..], &PERIOD].concat());
    let out = text(&o);
    assert!(o.status.success() && out.contains("1 of 2 expected rules loaded") && out.contains("Expected rules not loaded (the bundle maps no controls): SuperBotLicenceExpiring"), "{out}");
    let folder = unpack(&dir, &dir.join("mine.tar"));
    let manifest = json_in(&folder, "manifest.json");
    assert_eq!((manifest["files"][1]["checklist"].clone(), manifest["source"]["rulesExpected"]["files"][0]["file"].as_str(), manifest["source"]["rulesExpected"]["files"][0]["alerts"].as_u64()), (json!([]), Some("mine.rules.yml"), Some(2)));
    assert_eq!(json_in(&folder, "alerts.json")["otherSuperBotRulesLoaded"].as_array().unwrap().len(), rules - 1, "the shipped ones it didn't expect, by name");

    let o = evidence(&dir, &env, &[&["alerts", "--prometheus", &base, "-o", "alerts.tar"][..], &PERIOD].concat());
    assert!(!o.status.success() && text(&o).contains("alerts.tar"), "never over an existing file");
    let o = evidence(&dir, &env, &[&["alerts", "--prometheus", &base.replace("127.0.0.1", "prometheus.internal"), "-o", "clear.tar"][..], &PERIOD].concat());
    assert!(!o.status.success() && text(&o).contains("PROMETHEUS_TOKEN is set") && !text(&o).contains(TOKEN), "{}", text(&o));
    let o = evidence(&dir, &env, &[&["alerts", "--prometheus", &base, "--watch", r#"up{job="nothing"}"#, "-o", "none.tar"][..], &PERIOD].concat());
    assert!(!o.status.success() && text(&o).contains("no samples of up{job=\"nothing\"}"), "{}", text(&o));
    assert!(!dir.join("none.tar").exists());
    let _ = fs::remove_dir_all(&dir);
}
