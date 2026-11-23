//! The audit log's write-once S3 archive (ADR 0153) against the S3 stand-in: it refuses
//! a bucket that isn't write-once, writes every event once, in order, in locked
//! objects, retries a batch as the same object, and catches a store that drops the lock.

use crate::audit::{Actor, Event};
use crate::audit_chain_http_tests::{export_to, until};
use crate::machines::s3_standin::{self, StandIn};
use crate::tests::{call, serve_app};
use crate::users_http_tests::parse;
use crate::*;

const DEFAULT_RETENTION: &str = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>";
const LOCK_ONLY: &str = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";

fn vars<'a>(s: &'a StandIn, more: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut v = vec![
        ("AUDIT_EXPORT", "s3://backups/audit/prod"),
        ("AUDIT_EXPORT_S3_ENDPOINT", s.url.as_str()),
        ("AUDIT_EXPORT_S3_ACCESS_KEY_ID", s3_standin::ACCESS_KEY),
        ("AUDIT_EXPORT_S3_SECRET_ACCESS_KEY", s3_standin::SECRET),
        ("AUDIT_EXPORT_S3_BATCH_SECONDS", "0"),
    ];
    v.extend_from_slice(more);
    v
}

/// Every event in the archive's objects, in key order.
fn archived(s: &StandIn) -> Vec<Value> {
    let w = s.w();
    w.objects.iter().filter(|(k, _)| k.starts_with("audit/prod/")).flat_map(|(_, b)| String::from_utf8_lossy(b).lines().map(|l| serde_json::from_str(l).unwrap()).collect::<Vec<Value>>()).collect()
}

fn failing_reasons(app: &App) -> Vec<String> {
    app.db.audit_events(&Default::default(), 1000, true).iter().filter(|e| e.action == "audit.export_failing").map(|e| e.details["reason"].as_str().unwrap_or_default().to_string()).collect()
}

#[tokio::test]
async fn the_archive_refuses_a_bucket_that_isnt_write_once_then_locks_every_object() {
    let (port, app, admin, _) = serve_app().await;
    let s = StandIn::start().await;
    s.w().versioning = Some("Enabled");
    for i in 0..5 {
        app.db.record(&Event::new(Actor::system("test"), "test.archive").details(json!({ "n": i })));
    }
    export_to(&app, &vars(&s, &[]));
    let x = app.audit_export.get().unwrap();
    until("failing", || x.view(app.db.audit_head())["failing"] == true).await;
    assert!(failing_reasons(&app).iter().any(|r| r.contains("not_write_once")), "{:?}", failing_reasons(&app));
    assert!(x.view(0)["lastError"].as_str().unwrap().contains("doesn't have Object Lock on"), "{}", x.view(0));
    assert!(s.keys().is_empty(), "nothing goes to a bucket that isn't write-once");

    // Object Lock without a default retention isn't enough when the bucket's default locks.
    s.w().object_lock = Some(LOCK_ONLY.into());
    until("still refused", || x.view(0)["lastError"].as_str().is_some_and(|e| e.contains("no default retention"))).await;
    assert!(s.keys().is_empty());

    s.w().object_lock = Some(DEFAULT_RETENTION.into());
    until("recovery event", || app.db.audit_events(&Default::default(), 1000, false).iter().any(|e| e.action == "audit.export_recovered")).await;
    until("everything archived", || x.delivered() >= app.db.audit_head()).await;

    let sent = archived(&s);
    let ids: Vec<i64> = sent.iter().map(|e| e["id"].as_i64().unwrap()).collect();
    assert_eq!(ids, (1..=ids.len() as i64).collect::<Vec<_>>(), "every event once, in order, across objects");
    for w in sent.windows(2) {
        assert_eq!(w[1]["chainPrev"], w[0]["chainHash"], "the chain runs on from object to object");
    }
    {
        let w = s.w();
        for (key, body) in w.objects.iter() {
            let name = key.strip_prefix("audit/prod/").expect("under the prefix");
            assert_eq!(name.len(), "yyyy/mm/dd/".len() + 20 + 1 + 20 + ".jsonl".len(), "{key}");
            let (lines, (meta, _)) = (String::from_utf8_lossy(body).lines().count(), &w.meta[key]);
            let m = |k: &str| meta.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str()).unwrap();
            assert_eq!(m("x-amz-meta-superbot-events"), lines.to_string());
            assert_eq!(m("x-amz-meta-superbot-schema"), "superbot.audit.v1");
            assert_eq!(m("x-amz-meta-superbot-chain-head").len(), 64);
            assert_eq!(w.locks[key].0, "COMPLIANCE", "the bucket's default locked {key}");
        }
    }

    // The status shows the last object and how long it's kept.
    let siem = parse(&call(port, "GET", "/api/audit/siem", &admin, "").await.1);
    assert_eq!((siem["kind"].as_str(), siem["sink"].as_str(), siem["archive"]["lock"].as_str()), (Some("s3"), Some("s3://backups/audit/prod"), Some("bucket")), "{siem}");
    let last = &siem["archive"]["lastObject"];
    assert_eq!(last["lockMode"].as_str(), Some("compliance"), "{siem}");
    assert!(last["retainUntil"].as_i64().unwrap() > db::now() + 29 * 86_400_000, "{siem}");
    assert!(s.keys().contains(&last["key"].as_str().unwrap().to_string()));
    let body = serde_json::to_string(&siem).unwrap();
    assert!(!body.contains(s3_standin::SECRET));

    // A locked object can't be deleted, not even with the archive's own keys.
    let c = machines::s3::S3::new(s.settings()).unwrap();
    let key = last["key"].as_str().unwrap();
    assert!(c.delete_version(key, last["version"].as_str().unwrap()).await.unwrap_err().contains("AccessDenied"));
}

#[tokio::test]
async fn compliance_locks_retry_the_same_object_and_catch_a_store_that_drops_the_lock() {
    let app = runner::test_app();
    let s = StandIn::start().await;
    s.w().versioning = Some("Enabled");
    s.w().object_lock = Some(LOCK_ONLY.into());
    app.db.record(&Event::new(Actor::system("test"), "test.first"));
    s.w().fail = Some(("PUT".into(), 500));
    export_to(&app, &vars(&s, &[("AUDIT_EXPORT_S3_LOCK", "compliance"), ("AUDIT_EXPORT_S3_RETAIN_DAYS", "400"), ("AUDIT_EXPORT_START", "all")]));
    let x = app.audit_export.get().unwrap();
    until("first batch archived", || !s.keys().is_empty()).await;
    let puts: Vec<String> = s.w().calls.iter().filter(|c| c.starts_with("PUT /backups/audit/prod/")).cloned().collect();
    assert!(puts.len() >= 2, "{puts:?}");
    assert_eq!(puts[0], puts[1], "a failed batch goes again as the same object");
    let key = s.keys()[0].clone();
    let (mode, until_date) = s.w().locks[&key].clone();
    assert_eq!(mode, "COMPLIANCE");
    let until_ms = chrono::DateTime::parse_from_rfc3339(&until_date).unwrap().timestamp_millis();
    assert!((until_ms - (db::now() + 400 * 86_400_000)).abs() < 120_000, "{until_date}");

    // A store that takes the headers but keeps no lock is failing, not a quiet gap.
    until("caught up", || x.delivered() >= app.db.audit_head()).await;
    let before = x.delivered();
    s.w().ignore_lock = true;
    for i in 0..3 {
        app.db.record(&Event::new(Actor::system("test"), "test.unlocked").details(json!({ "n": i })));
    }
    until("failing", || x.view(app.db.audit_head())["failing"] == true).await;
    assert!(x.view(0)["lastError"].as_str().unwrap().contains("without a lock"), "{}", x.view(0));
    assert!(failing_reasons(&app).iter().any(|r| r.contains("not_write_once")));
    assert_eq!(x.delivered(), before, "the cursor holds, so retention keeps the events");

    s.w().ignore_lock = false;
    until("everything archived", || x.delivered() >= app.db.audit_head()).await;
    let ids: Vec<i64> = archived(&s).iter().map(|e| e["id"].as_i64().unwrap()).collect();
    assert!(ids.windows(2).all(|w| w[1] == w[0] + 1) && ids[0] == 1, "{ids:?}");
}

#[tokio::test]
async fn a_plain_bucket_with_the_lock_off_and_batches_that_wait() {
    let app = runner::test_app();
    let s = StandIn::start().await;
    app.db.record(&Event::new(Actor::system("test"), "test.plain"));
    export_to(&app, &vars(&s, &[("AUDIT_EXPORT", "s3://backups/audit/prod"), ("AUDIT_EXPORT_S3_LOCK", "off"), ("AUDIT_EXPORT_START", "all")]));
    let x = app.audit_export.get().unwrap();
    until("archived", || x.delivered() >= 1 && !s.keys().is_empty()).await;
    {
        let w = s.w();
        assert!(w.locks.is_empty() && !w.calls.iter().any(|c| c.contains("object-lock") || c.starts_with("HEAD")), "{:?}", w.calls);
    }
    assert!(x.view(0)["archive"]["lastObject"]["retainUntil"].is_null());

    // A batch waits for its oldest event to be AUDIT_EXPORT_S3_BATCH_SECONDS old, or to fill up.
    let a = crate::audit_archive::tests::archive(&[("AUDIT_EXPORT_S3_BATCH_SECONDS", "3600")]).unwrap();
    let head = app.db.audit_head();
    assert!(!crate::audit_export::archive_batch_due(&app, &a, head), "nothing waiting");
    app.db.record(&Event::new(Actor::system("test"), "test.young"));
    assert!(!crate::audit_export::archive_batch_due(&app, &a, head), "one young event waits");
    let now_due = crate::audit_archive::tests::archive(&[("AUDIT_EXPORT_S3_BATCH_SECONDS", "0")]).unwrap();
    assert!(crate::audit_export::archive_batch_due(&app, &now_due, head));
}
