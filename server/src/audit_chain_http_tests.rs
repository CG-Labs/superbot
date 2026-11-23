//! The tamper-evident audit log and its SIEM export (ADR 0122) on the real router:
//! `GET /api/audit/verify` names the first broken link, erasure and retention keep the
//! chain whole, and the export delivers every event in order, retrying until it's taken.

use crate::audit::{Actor, Event};
use crate::audit_export::Settings;
use crate::db::now;
use crate::secrets::env::EnvStore;
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use std::sync::Mutex as StdMutex;
use tokio::io::AsyncReadExt;

async fn verify(port: u16, admin: &str, query: &str) -> Value {
    let (code, body) = call(port, "GET", &format!("/api/audit/verify{query}"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    parse(&body)
}

async fn events(port: u16, admin: &str, query: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?limit=1000&{query}"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

pub(crate) fn export_to(app: &AppState, vars: &[(&str, &str)]) {
    let store = EnvStore::fixed(vars);
    let map: std::collections::HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let settings = Settings::from_env(&|k| map.get(k).cloned().unwrap_or_default(), &store).unwrap();
    crate::audit_export::start(app, settings);
}

pub(crate) async fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn verify_names_the_first_broken_link_and_holds_pins() {
    let (port, app, admin, key) = serve_app().await;
    for name in ["Scout", "Helper"] {
        assert_eq!(call(port, "POST", "/api/bots", &admin, &json!({ "name": name }).to_string()).await.0, 201);
    }
    let v = verify(port, &admin, "").await;
    assert_eq!(v["ok"], true, "{v}");
    let head = v["head"].clone();
    assert!(v["checked"].as_i64().unwrap() >= 3 && head["hash"].as_str().unwrap().len() == 64, "{v}");
    assert_eq!(v["first"], 1, "a fresh database chains from its first event");
    // The check is on the record, with the head a SIEM can keep.
    let checked = &events(port, &admin, "action=audit.verified").await[0];
    assert_eq!((checked["outcome"].as_str(), &checked["details"]["head"]), (Some("success"), &head));

    // Every event carries its link; a hash kept elsewhere still matches.
    let created = events(port, &admin, "action=bot.created").await;
    let scout = created.iter().find(|e| e["details"]["name"] == "Scout").unwrap().clone();
    let pin = format!("{}:{}", scout["id"], scout["chainHash"].as_str().unwrap());
    let v = verify(port, &admin, &format!("?pin={pin}")).await;
    assert_eq!((v["ok"].as_bool(), v["pins"][0]["result"].as_str()), (Some(true), Some("match")), "{v}");
    // A repeated pin is checked too, not dropped for the last one.
    let wrong = format!("{}:{}", scout["id"], "0".repeat(64));
    let v = verify(port, &admin, &format!("?pin={wrong}&pin={pin}")).await;
    let results: Vec<&str> = v["pins"].as_array().unwrap().iter().map(|p| p["result"].as_str().unwrap()).collect();
    assert_eq!((v["ok"].as_bool(), results), (Some(false), vec!["mismatch", "match"]), "{v}");
    for bad in ["x", "12", "12:nothex", "0:00"] {
        assert_eq!(call(port, "GET", &format!("/api/audit/verify?pin={bad}"), &admin, "").await.0, 400, "{bad}");
    }

    // Storing a value as another type, even with the same hex, breaks the link.
    app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
    let typed = app.db.try_record(&Event::new(Actor::system("test"), "test.typed").target("bot", "deadbeef")).unwrap();
    app.db.execute_raw(&format!("UPDATE audit_events SET target_id = x'deadbeef' WHERE id = {typed}")).unwrap();
    let v = verify(port, &admin, "").await;
    assert_eq!((v["ok"].as_bool(), v["firstBroken"]["id"].as_i64()), (Some(false), Some(typed)), "{v}");
    app.db.execute_raw(&format!("UPDATE audit_events SET target_id = 'deadbeef' WHERE id = {typed}")).unwrap();
    assert_eq!(verify(port, &admin, "").await["ok"], true);

    // Someone with the database file rewrites history: the edited row is named.
    let forged = scout["id"].as_i64().unwrap();
    app.db.execute_raw(&format!("UPDATE audit_events SET details = '{{\"name\":\"Innocent\"}}' WHERE id = {forged}")).unwrap();
    let v = verify(port, &admin, "").await;
    assert_eq!((v["ok"].as_bool(), v["firstBroken"]["id"].as_i64(), v["firstBroken"]["reason"].as_str()), (Some(false), Some(forged), Some("contents")), "{v}");
    let failed = &events(port, &admin, "action=audit.verified&outcome=failure").await[0];
    assert_eq!(failed["details"]["firstBroken"]["id"].as_i64(), Some(forged));
    assert_eq!(failed["details"]["reason"].as_str().map(crate::support::reason_code), Some("contents"), "a code the support bundle shows");
    assert_eq!(checked["details"]["reason"], Value::Null);

    // Re-hashing every row after it hides nothing from a pin kept outside.
    assert!(crate::audit_chain::reseal_from(&app.db, forged) > 0);
    let v = verify(port, &admin, "").await;
    assert_eq!(v["ok"], true, "a rebuilt chain is consistent on its own: {v}");
    let v = verify(port, &admin, &format!("?pin={pin}")).await;
    assert_eq!((v["ok"].as_bool(), v["pins"][0]["result"].as_str(), v["firstBroken"]["reason"].as_str()), (Some(false), Some("mismatch"), Some("pin")), "{v}");

    // Admins only.
    let (_, member) = user_with(port, &admin, "ada@example.com", "member").await;
    let (_, b) = call(port, "POST", "/api/bots", &member, r#"{"name":"Ada's"}"#).await;
    let bot = parse(&b)["id"].as_str().unwrap().to_string();
    for path in ["/api/audit/verify", "/api/audit/siem"] {
        assert_eq!(call(port, "GET", path, &member, "").await.0, 403, "{path}");
        assert_eq!(call(port, "GET", path, &key.auth(&bot), "").await.0, 403, "{path}");
    }
}

#[tokio::test]
async fn erasure_and_retention_keep_the_chain_whole() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    assert_eq!(call(port, "POST", "/api/bots", &ada_auth, r#"{"name":"Ada's"}"#).await.0, 201);
    let (code, body) = call(port, "POST", &format!("/api/users/{ada}/erase"), &admin, "{}").await;
    assert_eq!(code, 200, "{body}");
    let v = verify(port, &admin, "").await;
    assert_eq!(v["ok"], true, "{v}");
    assert!(v["erased"].as_i64().unwrap() > 0, "her events lost their salt: {v}");
    let named = &events(port, &admin, "action=audit.erased").await[0];
    assert!(named["details"]["rows"].as_array().is_some_and(|r| !r.is_empty()), "the erasure names the rows it cleared: {named}");

    // Clearing a salt by hand, to change a row's fields unseen, is caught.
    let id = app.db.try_record(&Event::new(Actor::system("test"), "test.kept").details(json!({ "name": "Kept" }))).unwrap();
    app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
    app.db.execute_raw(&format!("UPDATE audit_events SET chain_salt = NULL, details = '{{\"name\":\"Other\"}}' WHERE id = {id}")).unwrap();
    let v = verify(port, &admin, "").await;
    assert_eq!((v["ok"].as_bool(), v["firstBroken"]["id"].as_i64(), v["firstBroken"]["reason"].as_str()), (Some(false), Some(id), Some("erased")), "{v}");
    // Nor is widening the erasure's own rows to cover it, its salt cleared so they go
    // unchecked: its hash, and so any pin of it, stays the same.
    let erasure = named["id"].as_i64().unwrap();
    let before = app.db.audit_chain_rows(erasure - 1, 1).unwrap().remove(0);
    let pin = before.hash.clone().unwrap();
    app.db.execute_raw(&format!("UPDATE audit_events SET chain_salt = NULL, details = '{{\"rows\":[[1,{id}]]}}' WHERE id = {erasure}")).unwrap();
    let v = verify(port, &admin, &format!("?pin={erasure}:{pin}")).await;
    assert_eq!((v["ok"].as_bool(), v["pins"][0]["result"].as_str(), v["firstBroken"]["reason"].as_str()), (Some(false), Some("match"), Some("erased")), "{v}");
    assert_eq!(v["broken"], v["erased"], "her rows, the erasure and the changed row: none is vouched for now: {v}");
    let rows = &before.erasable[crate::audit_chain::ERASABLE.iter().position(|c| *c == "details").unwrap()];
    let rusqlite::types::Value::Text(rows) = rows else { panic!("{rows:?}") };
    app.db.execute_raw(&format!("UPDATE audit_events SET chain_salt = '{}', details = '{rows}' WHERE id = {erasure}", before.salt.unwrap())).unwrap();
    // A seal SQLite holds as something other than text is no seal, never skipped.
    app.db.execute_raw(&format!("UPDATE audit_events SET chain_salt = 'x', chain_hash = x'00' WHERE id = {id}")).unwrap();
    let v = verify(port, &admin, "").await;
    assert_eq!((v["ok"].as_bool(), v["firstBroken"]["reason"].as_str()), (Some(false), Some("unsealed")), "{v}");
    assert!(v["checked"].as_i64().unwrap() > 1, "and the rows after it are still checked");

    // Retention cuts a run of old events from the start and keeps the last one's hash
    // as the anchor. (A fresh log, so it can start with old events.)
    app.db.execute_raw("DROP TRIGGER audit_events_no_delete").unwrap();
    app.db.execute_raw("DELETE FROM audit_events").unwrap();
    let old = now() - 40 * 86_400_000;
    let record = |action: &str, at: i64| app.db.record_at(&Event::new(Actor::system("test"), action), at).unwrap();
    let (o1, o2) = (record("test.old", old), record("test.old", old));
    let young = record("test.young", now());
    let late = record("test.old", old);
    app.db.set_audit_retention(Some(30));
    crate::audit::prune(&app, 30);
    let v = verify(port, &admin, "").await;
    assert_eq!((v["ok"].as_bool(), v["first"].as_i64(), v["anchor"]["id"].as_i64()), (Some(true), Some(young), Some(o2)), "{v}");
    assert!(o1 < o2 && late > young);
    let left: Vec<i64> = app.db.audit_chain_rows(i64::MIN, 1000).unwrap().iter().map(|r| r.id).collect();
    assert!(left.contains(&late), "an old event after a young one waits for it");
    let pruned = &events(port, &admin, "action=audit.pruned").await[0];
    assert_eq!((pruned["details"]["deleted"].as_i64(), pruned["details"]["anchor"]["id"].as_i64()), (Some(2), Some(o2)));

    // A pinned event newer than the anchor that's gone is a failure, not pruning.
    let v = verify(port, &admin, &format!("?pin={o1}:{}", "a".repeat(64))).await;
    assert_eq!((v["ok"].as_bool(), v["pins"][0]["result"].as_str()), (Some(true), Some("gone")), "{v}");
    let newest = app.db.audit_head();
    let pin = format!("{newest}:{}", app.db.audit_chain_rows(newest - 1, 1).unwrap()[0].hash.clone().unwrap());
    app.db.execute_raw(&format!("DELETE FROM audit_events WHERE id = {newest}")).unwrap();
    let v = verify(port, &admin, &format!("?pin={pin}")).await;
    assert_eq!((v["ok"].as_bool(), v["pins"][0]["result"].as_str(), v["firstBroken"]["reason"].as_str()), (Some(false), Some("missing"), Some("pin")), "{v}");

    // Rows cut without the anchor show as a broken link.
    app.db.execute_raw(&format!("DELETE FROM settings WHERE key = '{}'", crate::audit_chain::ANCHOR)).unwrap();
    let v = verify(port, &admin, "").await;
    assert_eq!((v["ok"].as_bool(), v["firstBroken"]["id"].as_i64(), v["firstBroken"]["reason"].as_str()), (Some(false), Some(young), Some("link")), "{v}");
}

/// What a collector saw: how many requests, the lines it took, and each request's headers.
pub(crate) type Collected = Arc<StdMutex<(usize, Vec<String>, Vec<String>)>>;

/// A webhook collector: answers 500 to the first `fail` requests, then takes the batches.
pub(crate) async fn collector(fail: usize) -> (String, Collected) {
    let got: Collected = Default::default();
    let state = got.clone();
    let r = axum::Router::new().route(
        "/ingest",
        axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
            let state = state.clone();
            async move {
                let mut s = state.lock().unwrap();
                s.0 += 1;
                s.2.push(format!("{:?}", headers));
                if s.0 <= fail {
                    return axum::http::StatusCode::INTERNAL_SERVER_ERROR;
                }
                s.1.extend(body.lines().map(String::from));
                axum::http::StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    (format!("http://{addr}/ingest"), got)
}

#[tokio::test]
async fn the_siem_export_delivers_every_event_in_order_and_retries() {
    let (port, app, admin, _) = serve_app().await;
    let off = parse(&call(port, "GET", "/api/audit/siem", &admin, "").await.1);
    assert_eq!(off, json!({ "enabled": false }), "off by default");

    let secret = "sbx-siem-test-secret-9f8e7d6c5b4a";
    secrets::redact::register(secret);
    app.db.record(&Event::new(Actor::system("test"), "test.secret").details(json!({ "note": format!("token {secret}") })));
    let token = "siem-collector-token-0a1b2c3d4e5f";
    let (url, got) = collector(3).await;
    export_to(&app, &[("AUDIT_EXPORT", &url), ("AUDIT_EXPORT_HEADERS", &format!("Authorization=Bearer {token}"))]);
    until("delivery", || app.audit_export.get().is_some_and(|x| x.delivered() >= app.db.audit_head())).await;

    // Three failures make it a failing export, on the record once; delivery ends it.
    until("recovery event", || app.db.audit_events(&Default::default(), 1000, false).iter().any(|e| e.action == "audit.export_recovered")).await;
    let all = app.db.audit_events(&Default::default(), 1000, true);
    assert_eq!(all.iter().filter(|e| e.action == "audit.export_failing").count(), 1);
    let failing = all.iter().find(|e| e.action == "audit.export_failing").unwrap();
    assert_eq!((failing.outcome.as_str(), failing.details["sink"].as_str()), ("failure", Some(url.trim_end_matches("/ingest"))));
    assert_eq!(failing.details["reason"].as_str().map(crate::support::reason_code), Some("delivery_failed"));
    until("everything delivered", || app.audit_export.get().unwrap().delivered() >= app.db.audit_head()).await;

    let (tries, lines, headers) = got.lock().unwrap().clone();
    assert!(tries > 3);
    assert!(headers.iter().all(|h| h.contains(&format!("Bearer {token}")) && h.contains("application/x-ndjson")), "{headers:?}");
    let sent: Vec<Value> = lines.iter().map(|l| serde_json::from_str(l).unwrap()).collect();
    let ids: Vec<i64> = sent.iter().map(|e| e["id"].as_i64().unwrap()).collect();
    let mut sorted = ids.clone();
    sorted.dedup();
    assert_eq!(ids, sorted, "in id order, each once");
    assert_eq!(ids.first(), Some(&1), "AUDIT_EXPORT_START=all sends the history too");
    assert!(sent.iter().all(|e| e["schema"] == "superbot.audit.v1" && e["chainHash"].as_str().is_some_and(|h| h.len() == 64)));
    // Each line links to the one before it, so the SIEM holds the chain too.
    for w in sent.windows(2) {
        assert_eq!(w[1]["chainPrev"], w[0]["chainHash"]);
    }
    let body = lines.join("\n");
    assert!(!body.contains(secret) && !body.contains(token), "no secrets in what leaves");

    let siem = parse(&call(port, "GET", "/api/audit/siem", &admin, "").await.1);
    assert_eq!((siem["enabled"].as_bool(), siem["kind"].as_str(), siem["failing"].as_bool()), (Some(true), Some("webhook"), Some(false)), "{siem}");
    let mut metrics = String::new();
    crate::audit_export::render(&app, &mut metrics);
    assert!(metrics.contains("superbot_audit_export_failing{kind=\"webhook\"} 0") && metrics.contains("superbot_audit_export_last_delivery_timestamp_seconds"), "{metrics}");
    // The cursor is saved, so a restart resumes after the last delivered event.
    let delivered = app.audit_export.get().unwrap().delivered();
    assert_eq!(app.db.audit_export_cursor(&url), Some(delivered));
}

/// A webhook collector that answers 503 while `down` is set, keeping every request's
/// headers, and the lines of each batch it takes.
async fn switchable_collector(down: Arc<std::sync::atomic::AtomicBool>) -> (String, Collected) {
    let got: Collected = Default::default();
    let state = got.clone();
    let r = axum::Router::new().route(
        "/ingest",
        axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
            let (state, down) = (state.clone(), down.clone());
            async move {
                let mut s = state.lock().unwrap();
                s.0 += 1;
                s.2.push(format!("{:?}", headers));
                if down.load(std::sync::atomic::Ordering::SeqCst) {
                    return axum::http::StatusCode::SERVICE_UNAVAILABLE;
                }
                s.1.extend(body.lines().map(String::from));
                axum::http::StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    (format!("http://{addr}/ingest"), got)
}

#[tokio::test]
async fn several_siems_each_get_their_own_headers_start_and_cursor() {
    let (port, app, admin, _) = serve_app().await;
    let down = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (splunk_url, splunk) = switchable_collector(down.clone()).await;
    let (elastic_url, elastic) = collector(0).await;
    for i in 0..3 {
        app.db.record(&Event::new(Actor::system("test"), "test.several").details(json!({ "n": i })));
    }
    let head_at_start = app.db.audit_head();
    let (splunk_token, elastic_token) = ("sbx-splunk-hec-token-1a2b3c4d5e", "sbx-elastic-api-key-6f7a8b9c0d");
    let export = format!("splunk={splunk_url},elastic={elastic_url}");
    export_to(
        &app,
        &[
            ("AUDIT_EXPORT", &export),
            ("AUDIT_EXPORT_HEADERS_SPLUNK", &format!("Authorization=Splunk {splunk_token}")),
            ("AUDIT_EXPORT_HEADERS_ELASTIC", &format!("Authorization=ApiKey {elastic_token}")),
            ("AUDIT_EXPORT_START_ELASTIC", "new"),
        ],
    );
    let xs = app.audit_export.get().unwrap().clone();
    let (to_splunk, to_elastic) = (xs.sinks[0].clone(), xs.sinks[1].clone());
    assert_eq!((to_splunk.sink.name.as_deref(), to_elastic.sink.name.as_deref()), (Some("splunk"), Some("elastic")));

    // Splunk is down: Elastic carries on, from where it was told to start.
    until("splunk failing", || to_splunk.view(app.db.audit_head())["failing"] == true).await;
    app.db.record(&Event::new(Actor::system("test"), "test.while_down"));
    until("elastic caught up", || to_elastic.delivered() >= app.db.audit_head()).await;
    assert_eq!(xs.delivered(), to_splunk.delivered(), "retention waits for the SIEM that's behind");
    let failing = app.db.audit_events(&crate::audit::Filter { actions: vec!["audit.export_failing".into()], ..Default::default() }, 10, false);
    assert_eq!(failing.len(), 1, "only splunk is failing");
    assert_eq!((failing[0].details["name"].as_str(), failing[0].details["kind"].as_str()), (Some("splunk"), Some("webhook")));

    let v = parse(&call(port, "GET", "/api/audit/siem", &admin, "").await.1);
    assert_eq!((v["name"].as_str(), v["failing"].as_bool()), (Some("splunk"), Some(true)), "the failing sink leads: {v}");
    let names: Vec<&str> = v["sinks"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["splunk", "elastic"], "{v}");
    let mut metrics = String::new();
    crate::audit_export::render(&app, &mut metrics);
    assert!(
        metrics.contains("superbot_audit_export_failing{kind=\"webhook\",name=\"splunk\"} 1") && metrics.contains("superbot_audit_export_failing{kind=\"webhook\",name=\"elastic\"} 0"),
        "a series each: {metrics}"
    );

    // Splunk is back: it catches up from its own cursor, with the whole history.
    down.store(false, std::sync::atomic::Ordering::SeqCst);
    until("splunk caught up", || to_splunk.delivered() >= app.db.audit_head()).await;
    until("recovery event", || app.db.audit_events(&Default::default(), 1000, false).iter().any(|e| e.action == "audit.export_recovered" && e.details["name"] == "splunk")).await;
    until("both caught up", || xs.sinks.iter().all(|x| x.delivered() >= app.db.audit_head())).await;
    let ids = |got: &Collected| got.lock().unwrap().1.iter().map(|l| serde_json::from_str::<Value>(l).unwrap()["id"].as_i64().unwrap()).collect::<Vec<_>>();
    let (s_ids, e_ids) = (ids(&splunk), ids(&elastic));
    assert!(s_ids[0] == 1 && s_ids.windows(2).all(|w| w[1] == w[0] + 1), "splunk gets the history (AUDIT_EXPORT_START=all): {s_ids:?}");
    assert!(e_ids[0] > head_at_start && e_ids.windows(2).all(|w| w[1] == w[0] + 1), "elastic starts after it (AUDIT_EXPORT_START_ELASTIC=new): {e_ids:?}");
    assert!(e_ids.iter().all(|id| s_ids.contains(id)), "the same events, so host and id match across SIEMs");

    // Each SIEM saw only its own token, and no line carries either.
    let (s_headers, e_headers) = (splunk.lock().unwrap().2.clone(), elastic.lock().unwrap().2.clone());
    assert!(s_headers.iter().all(|h| h.contains(&format!("Splunk {splunk_token}")) && !h.contains(elastic_token)), "{s_headers:?}");
    assert!(e_headers.iter().all(|h| h.contains(&format!("ApiKey {elastic_token}")) && !h.contains(splunk_token)), "{e_headers:?}");
    let lines = [splunk.lock().unwrap().1.join("\n"), elastic.lock().unwrap().1.join("\n")].join("\n");
    assert!(!lines.contains(splunk_token) && !lines.contains(elastic_token));
    let head = app.db.audit_head();
    assert_eq!((app.db.audit_export_cursor(&splunk_url), app.db.audit_export_cursor(&elastic_url)), (Some(head), Some(head)), "a cursor each, by URL");
}

#[tokio::test]
async fn syslog_sinks_get_rfc_5424_with_octet_counting() {
    let app = runner::test_app();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    app.db.record(&Event::new(Actor::system("test"), "test.syslog"));
    export_to(&app, &[("AUDIT_EXPORT", &format!("syslog+tcp://{addr}")), ("AUDIT_EXPORT_START", "all")]);
    let (mut conn, _) = listener.accept().await.unwrap();
    let head = app.db.audit_head();
    let mut buf = Vec::new();
    let mut frames: Vec<String> = Vec::new();
    while (frames.len() as i64) < head {
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(10), conn.read(&mut chunk)).await.unwrap().unwrap();
        assert!(n > 0, "closed early");
        buf.extend_from_slice(&chunk[..n]);
        // RFC 5425: "<length> <message>", over and over.
        while let Some(sp) = buf.iter().position(|&b| b == b' ') {
            let len: usize = std::str::from_utf8(&buf[..sp]).unwrap().parse().unwrap();
            if buf.len() < sp + 1 + len {
                break;
            }
            frames.push(String::from_utf8(buf[sp + 1..sp + 1 + len].to_vec()).unwrap());
            buf.drain(..sp + 1 + len);
        }
    }
    let ours = frames.iter().find(|f| f.contains(" test.syslog ")).expect("our event");
    // <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG; facility 13 (log audit), severity 6.
    let parts: Vec<&str> = ours.splitn(8, ' ').collect();
    assert_eq!((parts[0], parts[3], parts[5], parts[6]), ("<110>1", "superbot", "test.syslog", "-"), "{ours}");
    assert!(parts[1].ends_with('Z'));
    let msg: Value = serde_json::from_str(parts[7]).unwrap();
    assert_eq!((msg["action"].as_str(), msg["schema"].as_str()), (Some("test.syslog"), Some("superbot.audit.v1")));
    until("cursor saved", || app.audit_export.get().unwrap().delivered() >= head).await;
}

#[tokio::test]
async fn the_siem_export_stops_at_a_row_it_cannot_read() {
    let app = runner::test_app();
    let record = |action: &str| app.db.try_record(&Event::new(Actor::system("test"), action)).unwrap();
    record("test.before");
    let bad = record("test.unreadable");
    record("test.after");
    app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
    app.db.execute_raw(&format!("UPDATE audit_events SET actor_name = x'00' WHERE id = {bad}")).unwrap();
    let (url, got) = collector(0).await;
    export_to(&app, &[("AUDIT_EXPORT", &url), ("AUDIT_EXPORT_START", "all")]);
    let x = app.audit_export.get().unwrap();
    until("failing", || x.view(app.db.audit_head())["failing"] == true).await;
    assert!(x.delivered() < bad, "the cursor stops before it, never past it");
    let ids = |got: &Collected| got.lock().unwrap().1.iter().map(|l| serde_json::from_str::<Value>(l).unwrap()["id"].as_i64().unwrap()).collect::<Vec<_>>();
    assert!(ids(&got).iter().all(|&id| id < bad), "{:?}", ids(&got));

    // Once it reads again, it goes out in order and the export recovers.
    app.db.execute_raw(&format!("UPDATE audit_events SET actor_name = NULL WHERE id = {bad}")).unwrap();
    until("recovery event", || app.db.audit_events(&Default::default(), 1000, false).iter().any(|e| e.action == "audit.export_recovered")).await;
    until("everything delivered", || x.delivered() >= app.db.audit_head()).await;
    let sent = ids(&got);
    assert!(sent.contains(&bad) && sent.windows(2).all(|w| w[0] < w[1]), "{sent:?}");
}
