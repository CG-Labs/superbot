//! ADR 0251: `superbot-evidence uptime` against a stand-in for Prometheus' query API: the
//! probe's raw samples read a day at a time with the token on every request, an outage
//! that needs a written review, a gap in the probe's record and announced maintenance, the
//! token and the probe's target never written. Then the same from a checks file, with no
//! network. The bundle checks with `tar`, `sha256sum -c` and `superbot-evidence coverage`.

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

const TOKEN: &str = "test-token-uptime-7c41d9";
const QUERY: &str = r#"probe_success{job="superbot-status"}"#;
const TARGET: &str = "https://bots.example.com/status.json";
/// 2026-10-01T00:00:00Z and 2026-11-01T00:00:00Z.
const START: i64 = 1_790_812_800;
const END: i64 = START + 31 * 86_400;

struct Mock {
    requests: Mutex<Vec<(String, i64, Option<String>)>>,
}

/// The probe every 30 seconds from two places: London fails from 10:00 to 10:20 on 20
/// October and Frankfurt from 10:05 to 10:15, so the outage is those 10 minutes; both fail
/// from 01:00 to 01:30 on 14 October, inside announced maintenance.
fn ok(t: i64, location: &str) -> bool {
    let at = |d: i64, h: i64, m: i64| START + (d - 1) * 86_400 + h * 3600 + m * 60;
    let failing = |a: i64, b: i64| t >= a && t < b;
    let outage = if location == "lon" { failing(at(20, 10, 0), at(20, 10, 20)) } else { failing(at(20, 10, 5), at(20, 10, 15)) };
    !(outage || failing(at(14, 1, 0), at(14, 1, 30)))
}

/// Both stop for 8 minutes at noon on 9 October.
fn measured(t: i64) -> bool {
    let day9 = START + 8 * 86_400 + 12 * 3600;
    !(t >= day9 && t < day9 + 8 * 60)
}

fn reply(status: u16, body: Value) -> Response {
    let mut r = (StatusCode::from_u16(status).unwrap(), body.to_string()).into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    r
}

async fn prometheus(State(m): State<Arc<Mock>>, uri: Uri, headers: HeaderMap) -> Response {
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(String::from);
    let q: HashMap<String, String> = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).into_owned().collect();
    if uri.path() != "/prom/api/v1/query" {
        return reply(404, json!({ "status": "error", "error": "not found" }));
    }
    let time: i64 = q["time"].parse().unwrap();
    m.requests.lock().unwrap().push((q["query"].clone(), time, auth));
    let Some(range) = q["query"].strip_prefix(QUERY).and_then(|r| r.strip_prefix('[')).and_then(|r| r.strip_suffix("s]")) else {
        return reply(400, json!({ "status": "error", "errorType": "bad_data", "error": "unexpected query" }));
    };
    let from = time - range.parse::<i64>().unwrap();
    let series = |location: &str| {
        let values: Vec<Value> = (START - 3600..END + 3600).step_by(30).filter(|t| *t > from && *t <= time && measured(*t)).map(|t| json!([t as f64, if ok(t, location) { "1" } else { "0" }])).collect();
        json!({ "metric": { "__name__": "probe_success", "job": "superbot-status", "instance": TARGET, "location": location }, "values": values })
    };
    reply(200, json!({ "status": "success", "data": { "resultType": "matrix", "result": [series("lon"), series("fra")] } }))
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
    let d = std::env::temp_dir().join(format!("superbot-uptime-evidence-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
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
    let folder = fs::read_dir(&out).unwrap().map(|e| e.unwrap().path()).find(|p| p.is_dir() && p.file_name().unwrap().to_string_lossy().starts_with("superbot-uptime-2026-10-01_2026-11-01-")).unwrap();
    let check = Command::new("sha256sum").args(["-c", "SHA256SUMS"]).current_dir(&folder).output().unwrap();
    assert!(check.status.success(), "sha256sum -c: {}", String::from_utf8_lossy(&check.stdout));
    folder
}

const PERIOD: [&str; 4] = ["--from", "2026-10-01", "--to", "2026-11-01"];

#[test]
fn measures_a_month_from_prometheus_as_a_checkable_bundle() {
    let (m, base) = serve();
    let dir = temp();
    let env = [("PROMETHEUS_TOKEN", TOKEN)];
    let o = evidence(&dir, &env, &[&["uptime", "--prometheus", &base, "--maintenance", "2026-10-14T01:00:00Z/2026-10-14T02:00:00Z", "-o", "uptime.tar"][..], &PERIOD].concat());
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    for want in ["available against an objective of 99.9% (10 minutes down", "8 unmeasured, 60 excused for maintenance, 1 outages", "2026-10: 99.9776%, met", "1 gaps of 5 minutes or more"] {
        assert!(out.contains(want), "{want}\n{out}");
    }
    assert!(!out.contains("Outages needing a written review"), "10 minutes is under a quarter of 43.2: {out}");

    let requests = m.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 31, "a day at a time");
    assert!(requests.iter().all(|(q, _, a)| q == &format!("{QUERY}[86460s]") && a.as_deref() == Some(&format!("Bearer {TOKEN}"))), "{requests:?}");
    assert_eq!((requests[0].1, requests[30].1), (START + 86_400, END));

    let tar = dir.join("uptime.tar");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&tar).unwrap().permissions().mode() & 0o777, 0o600, "private to its owner");
    }
    let raw = fs::read(&tar).unwrap();
    for never in [TOKEN, "bots.example.com", "127.0.0.1"] {
        assert!(!raw.windows(never.len()).any(|w| w == never.as_bytes()), "{never:?} is in the bundle");
    }
    let folder = unpack(&dir, &tar);
    let manifest = json_in(&folder, "manifest.json");
    assert_eq!((manifest["kind"].as_str(), manifest["format"].as_u64(), manifest["source"]["requests"].as_u64(), manifest["source"]["probe"]["query"].as_str()), (Some("availability"), Some(1), Some(31), Some(QUERY)));
    assert_eq!((manifest["files"][1]["name"].as_str(), manifest["files"][1]["checklist"].clone()), (Some("uptime.json"), json!(["A1.1-3"])));

    let u = json_in(&folder, "uptime.json");
    let s = &u["summary"];
    assert_eq!((s["downMinutes"].as_u64(), s["unmeasuredMinutes"].as_u64(), s["maintenanceMinutes"].as_u64(), s["downInMaintenanceMinutes"].as_u64()), (Some(10), Some(8), Some(60), Some(30)));
    assert_eq!(s["checks"].as_u64(), Some(2 * (31 * 2880 - 16)), "two locations, less the 8 unmeasured minutes");
    assert_eq!(u["outages"][0]["id"], "outage-20261020T1005Z", "down only while both locations failed");
    assert_eq!(u["series"].as_array().unwrap().iter().map(|x| x["labels"]["location"].as_str().unwrap()).collect::<Vec<_>>(), ["lon", "fra"]);
    assert_eq!(u["exceptions"]["probeGaps"], json!(["2026-10-09T12:00:00Z/2026-10-09T12:08:00Z"]));
    assert_eq!(u["periodCovered"]["days"], 31);

    // The coverage report reads it as a sixth kind of bundle.
    let store = dir.join("store");
    fs::create_dir_all(store.join("A1.1/2026-10")).unwrap();
    fs::copy(&tar, store.join("A1.1/2026-10/uptime.tar")).unwrap();
    let o = evidence(&dir, &[], &[&["coverage", store.to_str().unwrap(), "--json"][..], &PERIOD].concat());
    assert_eq!(o.status.code(), Some(2), "the other kinds are missing: {}", text(&o));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap();
    let kind = r["kinds"].as_array().unwrap().iter().find(|k| k["kind"] == "availability").unwrap();
    assert_eq!((kind["complete"].as_bool(), r["bundles"][0]["verified"].as_bool()), (Some(true), Some(true)), "{r:#}");
    let row = r["rows"].as_array().unwrap().iter().find(|x| x["row"] == "A1.1-3").unwrap();
    assert_eq!(row["complete"], true);
    assert_eq!(r["bundles"][0]["exceptions"]["uptime.json"]["probeGaps"], 1);

    let o = evidence(&dir, &env, &[&["uptime", "--prometheus", &base, "-o", "uptime.tar"][..], &PERIOD].concat());
    assert!(!o.status.success() && text(&o).contains("uptime.tar"), "never over an existing file");
    let o = evidence(&dir, &env, &[&["uptime", "--prometheus", &base.replace("127.0.0.1", "prometheus.internal"), "-o", "clear.tar"][..], &PERIOD].concat());
    assert!(!o.status.success() && text(&o).contains("PROMETHEUS_TOKEN is set") && !text(&o).contains(TOKEN), "{}", text(&o));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn measures_a_month_from_another_probes_export() {
    let dir = temp();
    let mut csv = String::from("time,result\n");
    for t in (START..END).step_by(60) {
        let down = (START + 19 * 86_400 + 36_000..START + 19 * 86_400 + 36_000 + 40 * 60).contains(&t);
        csv += &format!("{t},{}\n", if down { "down" } else { "up" });
    }
    fs::write(dir.join("october.csv"), &csv).unwrap();
    let o = evidence(&dir, &[], &[&["uptime", "--checks", "october.csv", "--objective", "99.95", "-o", "u.tar"][..], &PERIOD].concat());
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    for want in ["objective of 99.95% (40 minutes down", "2026-10: 99.9104%, missed", "Objective missed in: 2026-10", "Outages needing a written review: outage-20261020T1000Z"] {
        assert!(out.contains(want), "{want}\n{out}");
    }
    let folder = unpack(&dir, &dir.join("u.tar"));
    let manifest = json_in(&folder, "manifest.json");
    let digest = String::from_utf8_lossy(&Command::new("sha256sum").arg(dir.join("october.csv")).output().unwrap().stdout).split_whitespace().next().unwrap().to_string();
    assert_eq!((manifest["source"]["probe"]["files"][0]["file"].as_str(), manifest["source"]["probe"]["files"][0]["sha256"].as_str()), (Some("october.csv"), Some(digest.as_str())), "the export kept beside the bundle");
    let u = json_in(&folder, "uptime.json");
    let plans: Vec<bool> = u["summary"]["plans"].as_array().unwrap().iter().map(|p| p["met"].as_bool().unwrap()).collect();
    assert_eq!(plans, [true, true, true, false], "Starter, Pro and Max met; Enterprise missed");

    fs::write(dir.join("empty.csv"), "time,result\n2026-09-30T23:59:00Z,1\n").unwrap();
    let o = evidence(&dir, &[], &[&["uptime", "--checks", "empty.csv", "-o", "e.tar"][..], &PERIOD].concat());
    assert!(!o.status.success() && text(&o).contains("no checks from 2026-10-01 to 2026-11-01"), "{}", text(&o));
    assert!(!dir.join("e.tar").exists());
    let _ = fs::remove_dir_all(&dir);
}
