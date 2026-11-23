//! The audit log's write-once S3 archive (ADR 0154) against the S3 stand-in: it refuses
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
    for _ in 0..4 {
        app.db.record(&Event::new(Actor::system("test"), "test.plain"));
    }
    // A batch of events 1 to 2 was cut before a restart, and maybe written: it goes again as it was.
    let sink = format!("s3://{}/backups/audit/prod", s.url.trim_start_matches("http://"));
    app.db.set_audit_export_cursor(&format!("{sink}#batch"), 2).unwrap();
    export_to(&app, &vars(&s, &[("AUDIT_EXPORT", "s3://backups/audit/prod"), ("AUDIT_EXPORT_S3_LOCK", "off"), ("AUDIT_EXPORT_START", "all")]));
    let x = app.audit_export.get().unwrap();
    until("archived", || x.delivered() >= 4).await;
    let keys = s.keys();
    assert!(keys[0].ends_with("/00000000000000000001-00000000000000000002.jsonl"), "{keys:?}");
    assert!(keys[1].contains("/00000000000000000003-"), "the next batch starts after it: {keys:?}");
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

async fn verify_archive(port: u16, admin: &str, query: &str) -> Value {
    let (code, body) = call(port, "GET", &format!("/api/audit/verify?archive=on{query}"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    parse(&body)
}

fn reasons(v: &Value) -> Vec<String> {
    v["archive"]["firstProblems"].as_array().unwrap().iter().map(|p| p["reason"].as_str().unwrap().to_string()).collect()
}

/// Records `n` events and waits until they are archived, so each round is its own object.
async fn archive_round(app: &App, x: &crate::audit_export::Exporter, n: usize) {
    for i in 0..n {
        app.db.record(&Event::new(Actor::system("test"), "test.archive").details(json!({ "n": i })));
    }
    until("archived", || x.delivered() >= app.db.audit_head()).await;
}

#[tokio::test]
async fn checking_the_archive_catches_a_log_rebuilt_after_it_was_archived() {
    let (port, app, admin, _) = serve_app().await;
    let (code, body) = call(port, "GET", "/api/audit/verify?archive=on", &admin, "").await;
    assert_eq!(code, 409, "no archive to check: {body}");
    assert_eq!(call(port, "GET", "/api/audit/verify?archive=maybe", &admin, "").await.0, 400);

    let s = StandIn::start().await;
    s.w().versioning = Some("Enabled");
    s.w().object_lock = Some(DEFAULT_RETENTION.into());
    export_to(&app, &vars(&s, &[]));
    let x = app.audit_export.get().unwrap().clone();
    archive_round(&app, &x, 3).await;
    assert_eq!(call(port, "POST", "/api/audit/checkpoints", &admin, "").await.0, 201);
    archive_round(&app, &x, 2).await;
    archive_round(&app, &x, 2).await;
    // After the last signed checkpoint, which a rebuilt chain would need re-signing to keep.
    let forged = app.db.audit_head();

    let v = verify_archive(port, &admin, "").await;
    let a = &v["archive"];
    assert_eq!((v["ok"].as_bool(), a["ok"].as_bool(), a["problems"].as_u64()), (Some(true), Some(true), Some(0)), "{v}");
    assert!(a["objects"].as_u64().unwrap() >= 3, "{a}");
    assert_eq!(a["events"], a["matched"], "{a}");
    assert_eq!(a["locked"], a["objects"], "{a}");
    assert!(a["checkpoints"].as_u64().unwrap() >= 1, "the signed checkpoint holds from the archive: {a}");
    assert_eq!(a["first"].as_i64(), Some(1), "{a}");
    assert!(a["head"]["id"].as_i64() >= a["delivered"].as_i64(), "{a}");
    assert!(!serde_json::to_string(&v).unwrap().contains(s3_standin::SECRET));
    assert!(s.w().calls.iter().any(|c| c.starts_with("GET /backups?") && c.contains("versions")), "versions are listed");

    // A range reads only the objects it overlaps.
    let v = verify_archive(port, &admin, "&to=1").await;
    assert_eq!((v["archive"]["objects"].as_u64(), v["archive"]["ok"].as_bool()), (Some(1), Some(true)), "{v}");
    assert!(v["archive"]["skipped"].as_u64().unwrap() >= 2);

    // Someone with the database rewrites an archived event and rebuilds the chain after it:
    // the log holds on its own, but not against the archive.
    app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
    app.db.execute_raw(&format!("UPDATE audit_events SET details = '{{\"n\":99}}' WHERE id = {forged}")).unwrap();
    assert!(crate::audit_chain::reseal_from(&app.db, forged) > 0);
    let (_, plain) = call(port, "GET", "/api/audit/verify", &admin, "").await;
    assert_eq!(parse(&plain)["ok"], true, "a rebuilt chain is consistent on its own");
    let v = verify_archive(port, &admin, "").await;
    assert_eq!((v["ok"].as_bool(), v["firstBroken"]["id"].as_i64(), v["firstBroken"]["reason"].as_str()), (Some(false), Some(forged), Some("archive")), "{v}");
    assert_eq!(v["archive"]["firstProblems"][0]["reason"], "mismatch", "{v}");
    assert!(v["archive"]["mismatched"].as_u64().unwrap() >= 1);
    let failed = app.db.audit_events(&crate::audit::Filter { actions: vec!["audit.verified".into()], ..Default::default() }, 1, false);
    assert_eq!((failed[0].outcome.as_str(), failed[0].details["reason"].as_str()), ("failure", Some("archive")));
    assert_eq!(failed[0].details["archive"]["firstProblem"]["reason"], "mismatch", "{:?}", failed[0].details);

    // Admins only, as every check is.
    let (_, member) = crate::users_http_tests::user_with(port, &admin, "member@example.com", "member").await;
    assert_eq!(call(port, "GET", "/api/audit/verify?archive=on", &member, "").await.0, 403);
}

#[tokio::test]
async fn checking_the_archive_catches_a_forged_version_a_gap_and_a_stray_key() {
    let (port, app, admin, _) = serve_app().await;
    let s = StandIn::start().await;
    s.w().versioning = Some("Enabled");
    s.w().object_lock = Some(DEFAULT_RETENTION.into());
    export_to(&app, &vars(&s, &[]));
    let x = app.audit_export.get().unwrap().clone();
    for _ in 0..3 {
        archive_round(&app, &x, 2).await;
    }
    let first = s.keys()[0].clone();

    // Whoever holds the archive's keys writes a new version over a locked object. The
    // locked one is still there, and is what's checked; the new one is named.
    let c = machines::s3::S3::new(s.settings()).unwrap();
    let (meta, _) = s.w().meta[&first].clone();
    let body = String::from_utf8(s.w().objects[&first].clone()).unwrap().replace("test.archive", "test.innocent");
    use base64::Engine;
    let sum = base64::engine::general_purpose::STANDARD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, body.as_bytes()).as_ref());
    let mut h: Vec<(&str, String)> = meta.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    h.push(("x-amz-checksum-sha256", sum));
    c.put_with(&first, body.into_bytes(), &h).await.unwrap();
    // A delete only hides an object behind a marker; it is still checked.
    c.delete(&s.keys()[1]).await.unwrap();
    let v = verify_archive(port, &admin, "").await;
    assert_eq!((v["ok"].as_bool(), reasons(&v)), (Some(false), vec!["overwritten".to_string()]), "{v}");
    assert_eq!((v["firstBroken"].as_null(), v["archive"]["hidden"].as_u64()), (Some(()), Some(1)), "this server's log still matches: {v}");
    assert_eq!(v["archive"]["events"], v["archive"]["matched"]);

    // A plain bucket with the lock off: objects can go, and the gap shows.
    let (port, app, admin, _) = serve_app().await;
    let s = StandIn::start().await;
    export_to(&app, &vars(&s, &[("AUDIT_EXPORT_S3_LOCK", "off")]));
    let x = app.audit_export.get().unwrap().clone();
    for _ in 0..4 {
        archive_round(&app, &x, 2).await;
    }
    assert_eq!(verify_archive(port, &admin, "").await["archive"]["ok"], true);
    let c = machines::s3::S3::new(s.settings()).unwrap();
    let keys = s.keys();
    c.delete(&keys[1]).await.unwrap();
    c.put("audit/prod/README", b"hello".to_vec()).await.unwrap();
    let v = verify_archive(port, &admin, "").await;
    assert_eq!(reasons(&v), ["stray", "link"], "{v}");
    let gap = &v["archive"]["firstProblems"][1];
    assert!(gap["key"].as_str().unwrap() == keys[2] && gap["error"].as_str().unwrap().contains("missing from the archive"), "{gap}");
    // The newest objects gone: the archive ends before what botd delivered to it.
    until("the checks archived", || x.delivered() >= app.db.audit_head()).await;
    let delivered = x.delivered();
    for k in s.keys().iter().filter(|k| k.ends_with(".jsonl")).skip(1) {
        c.delete(k).await.unwrap();
    }
    let v = verify_archive(port, &admin, "").await;
    assert!(reasons(&v).contains(&"behind".to_string()), "{v}");
    assert!(v["archive"]["delivered"].as_i64().unwrap() >= delivered);
}

#[tokio::test]
async fn checking_the_archive_catches_its_first_objects_gone_and_reads_null_versions() {
    let (port, app, admin, _) = serve_app().await;
    let s = StandIn::start().await;
    export_to(&app, &vars(&s, &[("AUDIT_EXPORT_S3_LOCK", "off")]));
    let x = app.audit_export.get().unwrap().clone();
    for _ in 0..3 {
        archive_round(&app, &x, 2).await;
    }
    let v = verify_archive(port, &admin, "").await;
    assert_eq!((v["archive"]["ok"].as_bool(), v["archive"]["start"].as_i64(), v["archive"]["first"].as_i64()), (Some(true), Some(1), Some(1)), "{v}");

    // Written before versioning was on, the first object's version is `null`; a different
    // version over it is caught, not read in its place.
    let first = s.keys()[0].clone();
    {
        let mut w = s.w();
        let v = w.history[&first][0].clone();
        w.history.insert(first.clone(), vec!["null".into()]);
        let b = w.bodies.remove(&(first.clone(), v.clone())).unwrap();
        w.bodies.insert((first.clone(), "null".into()), b);
        let st = w.versions.remove(&(first.clone(), v)).unwrap();
        w.versions.insert((first.clone(), "null".into()), st);
        w.meta.get_mut(&first).unwrap().1 = "null".into();
        w.versioning = Some("Enabled");
    }
    let c = machines::s3::S3::new(s.settings()).unwrap();
    let (meta, _) = s.w().meta[&first].clone();
    let body = String::from_utf8(s.w().objects[&first].clone()).unwrap().replace("test.archive", "test.innocent");
    use base64::Engine;
    let sum = base64::engine::general_purpose::STANDARD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, body.as_bytes()).as_ref());
    let mut h: Vec<(&str, String)> = meta.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    h.push(("x-amz-checksum-sha256", sum));
    c.put_with(&first, body.into_bytes(), &h).await.unwrap();
    let v = verify_archive(port, &admin, "").await;
    assert_eq!(reasons(&v), ["overwritten"], "{v}");
    assert!(s.w().calls.iter().any(|c| c.contains("versionId=null")), "the null version is read by its id");

    // The first objects gone for good: the rest still links up and reaches the end, yet
    // the archive no longer begins where botd started it.
    let fresh = StandIn::start().await;
    let (port, app, admin, _) = serve_app().await;
    export_to(&app, &vars(&fresh, &[("AUDIT_EXPORT_S3_LOCK", "off")]));
    let x = app.audit_export.get().unwrap().clone();
    for _ in 0..3 {
        archive_round(&app, &x, 2).await;
    }
    let c = machines::s3::S3::new(fresh.settings()).unwrap();
    // A batch copied to a new key, its details changed and its hashes kept: what it says
    // no longer matches this server's rows under those hashes.
    let original = fresh.keys()[0].clone();
    let copy = format!("audit/prod/2099/01/01/{}", original.rsplit('/').next().unwrap());
    let (meta, _) = fresh.w().meta[&original].clone();
    let changed = String::from_utf8(fresh.w().objects[&original].clone()).unwrap().replacen("\"details\":{\"n\":0}", "\"details\":{\"n\":7}", 1);
    let sum = base64::engine::general_purpose::STANDARD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, changed.as_bytes()).as_ref());
    let mut h: Vec<(&str, String)> = meta.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    h.push(("x-amz-checksum-sha256", sum));
    c.put_with(&copy, changed.into_bytes(), &h).await.unwrap();
    let v = verify_archive(port, &admin, "").await;
    assert_eq!((reasons(&v), v["archive"]["altered"].as_u64()), (vec!["contents".to_string()], Some(1)), "{v}");
    assert!(v["firstBroken"].is_null(), "this server's log is fine: {v}");
    c.delete(&copy).await.unwrap();
    assert_eq!(verify_archive(port, &admin, "").await["archive"]["ok"], true);
    c.delete(&fresh.keys()[0]).await.unwrap();
    let v = verify_archive(port, &admin, "").await;
    assert_eq!((v["archive"]["ok"].as_bool(), reasons(&v)), (Some(false), vec!["start".to_string()]), "{v}");
    assert_eq!(v["archive"]["firstProblems"][0]["id"].as_i64(), Some(1), "{v}");
}
