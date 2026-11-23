//! Signed, timestamped audit checkpoints (ADR 0149) on the real router, against a fake
//! RFC 3161 TSA over HTTP: they're made, stamped after the TSA's failures, sent to the
//! SIEM with what's needed to check them, shown by `GET /api/audit/chain`, and a token
//! swapped in the database is caught.

use crate::audit::{Actor, Event};
use crate::audit_chain_http_tests::{collector, export_to, until};
use crate::audit_checkpoint::{self, Settings};
use crate::tests::{call, serve_app};
use crate::tsa::fake::FakeTsa;
use crate::users_http_tests::{parse, user_with};
use crate::*;
use base64::Engine;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A TSA on loopback: fails the first `fail` requests with HTTP 500, then answers with
/// `answer` (None: a token for the request). Returns its URL and the request count.
pub(crate) async fn tsa(fake: Arc<FakeTsa>, fail: usize, answer: Option<Vec<u8>>) -> (String, Arc<AtomicUsize>) {
    let tries = Arc::new(AtomicUsize::new(0));
    let count = tries.clone();
    let r = axum::Router::new().route(
        "/tsr",
        axum::routing::post(move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
            let (fake, count, answer) = (fake.clone(), count.clone(), answer.clone());
            async move {
                assert_eq!(headers.get("content-type").and_then(|v| v.to_str().ok()), Some("application/timestamp-query"));
                if count.fetch_add(1, Ordering::SeqCst) < fail {
                    return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Vec::new());
                }
                (axum::http::StatusCode::OK, answer.unwrap_or_else(|| fake.reply(&body, crate::db::now())))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    (format!("http://{addr}/tsr"), tries)
}

pub(crate) fn checkpoints_with(app: &AppState, vars: &[(&str, &str)]) {
    let map: std::collections::HashMap<&str, &str> = vars.iter().copied().collect();
    let s = Settings::from_env(&|k| map.get(k).map(|v| v.to_string()).unwrap_or_default()).unwrap();
    audit_checkpoint::start(app, s);
}

fn actions(app: &AppState, action: &str) -> Vec<crate::db::AuditEvent> {
    app.db.audit_events(&crate::audit::Filter { actions: vec![action.into()], ..Default::default() }, 1000, true)
}

#[tokio::test]
async fn checkpoints_are_signed_timestamped_exported_and_checked() {
    let (port, app, admin, key) = serve_app().await;
    let fake = Arc::new(FakeTsa::new());
    let (url, tries) = tsa(fake.clone(), 3, None).await;
    let ca = crate::db::temp_path("checkpoint-tsa").join("ca.pem");
    std::fs::write(&ca, &fake.ca_pem).unwrap();
    checkpoints_with(&app, &[("AUDIT_CHECKPOINT_MINUTES", "0"), ("AUDIT_TIMESTAMP_URL", &url), ("AUDIT_TIMESTAMP_CA_FILE", ca.to_str().unwrap())]);
    let (sink, got) = collector(0).await;
    export_to(&app, &[("AUDIT_EXPORT", &sink)]);
    assert_eq!(call(port, "POST", "/api/bots", &admin, r#"{"name":"Scout"}"#).await.0, 201);

    let (code, body) = call(port, "POST", "/api/audit/checkpoints", &admin, "").await;
    assert_eq!(code, 201, "{body}");
    let made = parse(&body);
    let id = made["id"].as_i64().unwrap();
    assert_eq!(made["timestamp"]["status"], "pending", "{made}");
    // The TSA fails three times: on the record once, and the audit log goes on meanwhile.
    until("the timestamp", || app.db.with_conn(|c| audit_checkpoint::row(c, id)).unwrap().is_some_and(|c| c.tsa_status == "stamped")).await;
    assert!(tries.load(Ordering::SeqCst) >= 4);
    let failing = actions(&app, audit_checkpoint::FAILING);
    assert_eq!(failing.len(), 1);
    assert_eq!((failing[0].outcome.as_str(), failing[0].details["reason"].as_str()), ("failure", Some("refused")));
    until("recovery", || !actions(&app, audit_checkpoint::RECOVERED).is_empty()).await;
    let stamped = &actions(&app, audit_checkpoint::TIMESTAMPED)[0];
    assert_eq!((stamped.details["checkpoint"].as_i64(), stamped.details["trusted"].as_bool()), (Some(id), Some(true)), "{:?}", stamped.details);

    // Checked end to end: the signature, the head it names, and the token.
    let (code, body) = call(port, "GET", "/api/audit/verify", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let v = parse(&body);
    assert_eq!(
        (v["ok"].as_bool(), v["checkpoints"]["checked"].as_i64(), v["checkpoints"]["timestamped"].as_i64(), v["checkpoints"]["trustedTimestamps"].as_i64()),
        (Some(true), Some(1), Some(1), Some(1)),
        "{v}"
    );

    // What the panel and `botctl audit chain` show.
    let (code, body) = call(port, "GET", "/api/audit/chain", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let chain = parse(&body);
    assert_eq!(chain["checkpoints"]["last"]["id"].as_i64(), Some(id), "{chain}");
    assert_eq!((chain["timestamps"]["enabled"].as_bool(), chain["timestamps"]["last"]["checkpoint"].as_i64(), chain["timestamps"]["pending"].as_i64()), (Some(true), Some(id), Some(0)));
    assert_eq!((chain["export"]["enabled"].as_bool(), chain["verification"]["ok"].as_bool()), (Some(true), Some(true)), "{chain}");
    assert!(chain["head"]["hash"].as_str().is_some_and(|h| h.len() == 64));
    let (_, body) = call(port, "GET", "/api/audit/checkpoints/key", &admin, "").await;
    let k = parse(&body);
    assert_eq!(k["publicKey"], made["publicKey"]);
    let (_, body) = call(port, "GET", "/api/audit/checkpoints?limit=5", &admin, "").await;
    let listed = parse(&body)["checkpoints"][0].clone();
    let token = base64::engine::general_purpose::STANDARD.decode(listed["timestamp"]["token"].as_str().unwrap()).unwrap();

    // The SIEM gets the statement and token, and can check both without botd.
    until("export", || app.audit_export.get().is_some_and(|x| x.delivered() >= app.db.audit_head())).await;
    let sent: Vec<Value> = got.lock().unwrap().1.iter().map(|l| serde_json::from_str(l).unwrap()).collect();
    let line = sent.iter().find(|e| e["action"] == "audit.checkpoint" && e["id"] == id).unwrap();
    let c = &line["checkpoint"];
    let public = audit_checkpoint::parse_public_key(c["publicKey"].as_str().unwrap()).unwrap();
    assert!(crate::audit_line::signed(&public, c["statement"].as_str().unwrap(), c["signature"].as_str().unwrap()), "{line}");
    assert_eq!(c["hash"], line["chainPrev"], "it signs the head it follows");
    let line = sent.iter().find(|e| e["action"] == "audit.checkpoint_timestamped").unwrap();
    let c = &line["checkpoint"];
    let exported = base64::engine::general_purpose::STANDARD.decode(c["timestamp"]["token"].as_str().unwrap()).unwrap();
    assert_eq!(exported, token);
    let imprint = audit_checkpoint::imprint(c["statement"].as_str().unwrap(), c["signature"].as_str().unwrap());
    let trust = crate::tsa::Trust::from_pem(&fake.ca_pem).unwrap();
    assert_eq!(crate::tsa::verify(&exported, &imprint, None, &trust).unwrap().trusted, Some(true));

    let mut metrics = String::new();
    audit_checkpoint::render(&app, &mut metrics);
    assert!(metrics.contains("superbot_audit_timestamp_pending_checkpoints 0") && metrics.contains("superbot_audit_checkpoint_last_timestamp_seconds"), "{metrics}");

    // A token swapped in the database is caught.
    app.db.execute_raw("DROP TRIGGER audit_checkpoints_signed").unwrap();
    let other = base64::engine::general_purpose::STANDARD.encode(fake.token(&[0; 32], None, crate::db::now()));
    app.db.execute_raw(&format!("UPDATE audit_checkpoints SET tsa_token = '{other}' WHERE event_id = {id}")).unwrap();
    let v = parse(&call(port, "GET", "/api/audit/verify", &admin, "").await.1);
    assert_eq!((v["ok"].as_bool(), v["firstBroken"]["reason"].as_str(), v["checkpoints"]["firstBroken"]["reason"].as_str()), (Some(false), Some("timestamp"), Some("record")), "{v}");
    let chain = parse(&call(port, "GET", "/api/audit/chain", &admin, "").await.1);
    assert_eq!(chain["verification"]["reason"], "timestamp", "{chain}");

    // Admins only.
    let (_, member) = user_with(port, &admin, "ada@example.com", "member").await;
    let (_, b) = call(port, "POST", "/api/bots", &member, r#"{"name":"Ada's"}"#).await;
    let bot = parse(&b)["id"].as_str().unwrap().to_string();
    for (method, path) in [("GET", "/api/audit/chain"), ("GET", "/api/audit/checkpoints"), ("POST", "/api/audit/checkpoints"), ("GET", "/api/audit/checkpoints/key")] {
        assert_eq!(call(port, method, path, &member, "").await.0, 403, "{path}");
        assert_eq!(call(port, method, path, &key.auth(&bot), "").await.0, 403, "{path}");
    }
}

#[tokio::test]
async fn a_refusing_tsa_never_holds_up_the_audit_log() {
    let (port, app, admin, _) = serve_app().await;
    let (url, tries) = tsa(Arc::new(FakeTsa::new()), 0, Some(FakeTsa::refusal())).await;
    checkpoints_with(&app, &[("AUDIT_CHECKPOINT_MINUTES", "0"), ("AUDIT_TIMESTAMP_URL", &url)]);
    let (code, body) = call(port, "POST", "/api/audit/checkpoints", &admin, "").await;
    assert_eq!(code, 201, "{body}");
    let id = parse(&body)["id"].as_i64().unwrap();
    until("failing", || !actions(&app, audit_checkpoint::FAILING).is_empty()).await;
    assert!(tries.load(Ordering::SeqCst) >= 3);
    // Events are still written while it fails.
    let later = app.db.try_record(&Event::new(Actor::system("test"), "test.later")).unwrap();
    assert!(later > id);
    let c = app.db.with_conn(|c| audit_checkpoint::row(c, id)).unwrap().unwrap();
    assert_eq!(c.tsa_status, "pending");
    assert!(c.tsa_tries >= 3 && c.tsa_error.as_deref().is_some_and(|e| e.contains("unsupported policy") || e.contains("refused")), "{c:?}");
    let failing = &actions(&app, audit_checkpoint::FAILING)[0];
    assert_eq!(failing.details["reason"], "refused");
    let chain = parse(&call(port, "GET", "/api/audit/chain", &admin, "").await.1);
    assert_eq!((chain["timestamps"]["failing"].as_bool(), chain["timestamps"]["pending"].as_i64()), (Some(true), Some(1)), "{chain}");
    // A checkpoint waiting for its token isn't a broken chain.
    let v = parse(&call(port, "GET", "/api/audit/verify", &admin, "").await.1);
    assert_eq!((v["ok"].as_bool(), v["checkpoints"]["checked"].as_i64(), v["checkpoints"]["timestamped"].as_i64()), (Some(true), Some(1), Some(0)), "{v}");
}

#[tokio::test]
async fn verify_takes_a_range_and_keys() {
    let (port, app, admin, _) = serve_app().await;
    checkpoints_with(&app, &[("AUDIT_CHECKPOINT_MINUTES", "0")]);
    let first = app.db.try_record(&Event::new(Actor::system("test"), "test.one")).unwrap();
    let made = parse(&call(port, "POST", "/api/audit/checkpoints", &admin, "").await.1);
    let id = made["id"].as_i64().unwrap();
    let v = parse(&call(port, "GET", &format!("/api/audit/verify?from={first}&to={id}"), &admin, "").await.1);
    assert_eq!((v["ok"].as_bool(), v["range"]["from"].as_i64(), v["head"]["id"].as_i64()), (Some(true), Some(first), Some(id)), "{v}");
    // Pinning botd's key passes; pinning another names the checkpoint.
    let v = parse(&call(port, "GET", &format!("/api/audit/verify?key={}", made["publicKey"].as_str().unwrap()), &admin, "").await.1);
    assert_eq!(v["ok"], true, "{v}");
    let v = parse(&call(port, "GET", &format!("/api/audit/verify?key={}", "11".repeat(32)), &admin, "").await.1);
    assert_eq!((v["ok"].as_bool(), v["firstBroken"]["id"].as_i64(), v["checkpoints"]["firstBroken"]["reason"].as_str()), (Some(false), Some(id), Some("key")), "{v}");
    for bad in ["from=x", "from=5&to=2", "key=abc", "from=1&from=2"] {
        assert_eq!(call(port, "GET", &format!("/api/audit/verify?{bad}"), &admin, "").await.0, 400, "{bad}");
    }
}
