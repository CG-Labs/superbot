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
async fn archive_round(app: &App, x: &crate::audit_export::Exports, n: usize) {
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
    // A value archived in the clear that becomes a known secret later is no false alarm.
    let later = "archived-then-secret-7a41c9";
    app.db.record(&Event::new(Actor::system("test"), "test.archive").details(json!({ "note": later })));
    until("archived", || x.delivered() >= app.db.audit_head()).await;
    crate::secrets::redact::register(later);
    let v = verify_archive(port, &admin, "").await;
    crate::secrets::redact::forget(later);
    assert_eq!(v["archive"]["ok"], true, "{v}");
    let c = machines::s3::S3::new(fresh.settings()).unwrap();
    // A batch copied to a new key, its details changed and its hashes kept: the line no
    // longer follows from its own digest, and no longer matches this server's rows.
    let original = fresh.keys()[0].clone();
    let copy = format!("audit/prod/2099/01/01/{}", original.rsplit('/').next().unwrap());
    let (meta, _) = fresh.w().meta[&original].clone();
    let changed = String::from_utf8(fresh.w().objects[&original].clone()).unwrap().replacen("\"details\":{\"n\":0}", "\"details\":{\"n\":7}", 1);
    let sum = base64::engine::general_purpose::STANDARD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, changed.as_bytes()).as_ref());
    let mut h: Vec<(&str, String)> = meta.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    h.push(("x-amz-checksum-sha256", sum));
    c.put_with(&copy, changed.into_bytes(), &h).await.unwrap();
    let v = verify_archive(port, &admin, "").await;
    assert_eq!((reasons(&v), v["archive"]["altered"].as_u64()), (vec!["digest".to_string(), "contents".to_string()], Some(1)), "{v}");
    assert!(v["firstBroken"].is_null(), "this server's log is fine: {v}");
    c.delete(&copy).await.unwrap();
    assert_eq!(verify_archive(port, &admin, "").await["archive"]["ok"], true);
    c.delete(&fresh.keys()[0]).await.unwrap();
    let v = verify_archive(port, &admin, "").await;
    assert_eq!((v["archive"]["ok"].as_bool(), reasons(&v)), (Some(false), vec!["start".to_string()]), "{v}");
    assert_eq!(v["archive"]["firstProblems"][0]["id"].as_i64(), Some(1), "{v}");

    // A middle object gone, and only its events asked for: nothing is read, yet it's caught.
    let middle = fresh.keys()[1].clone();
    let (from, to) = crate::audit_archive_verify::ids("audit/prod", &middle).unwrap();
    c.delete(&middle).await.unwrap();
    let v = verify_archive(port, &admin, &format!("&from={from}&to={to}")).await;
    assert_eq!((v["archive"]["objects"].as_u64(), reasons(&v)), (Some(0), vec!["behind".to_string()]), "{v}");
    assert_eq!(v["archive"]["firstProblems"][0]["id"].as_i64(), Some(from), "{v}");
}

/// The last `audit.verified` event's details and outcome.
fn last_verified(app: &App) -> (String, Value) {
    let e = app.db.audit_events(&crate::audit::Filter { actions: vec!["audit.verified".into()], ..Default::default() }, 1, false).remove(0);
    (e.outcome, e.details)
}

/// The keys botd read a version of, in order.
fn read_keys(s: &StandIn) -> Vec<String> {
    s.w().calls.iter().filter(|c| c.starts_with("GET /backups/audit/prod/") && c.contains("versionId=")).map(|c| c["GET /backups/".len()..].split('?').next().unwrap().to_string()).collect()
}

/// As if every version so far was written two days ago.
fn age_store(s: &StandIn) {
    for at in s.w().written.values_mut() {
        *at -= 2 * 86_400_000;
    }
}

#[tokio::test]
async fn the_daily_check_reads_whats_new_since_its_last_pass() {
    let (port, app, admin, _) = serve_app().await;
    let s = StandIn::start().await;
    s.w().versioning = Some("Enabled");
    s.w().object_lock = Some(DEFAULT_RETENTION.into());
    export_to(&app, &vars(&s, &[]));
    let x = app.audit_export.get().unwrap().clone();
    let sink = x.archive().unwrap().0.sink.id.clone();
    for _ in 0..3 {
        archive_round(&app, &x, 2).await;
    }

    // The first daily check has no pass to carry on from, so it reads the whole archive.
    let before = s.keys();
    crate::audit_chain::daily(&app).await;
    let (outcome, d) = last_verified(&app);
    assert_eq!((outcome.as_str(), d["archive"]["ok"].as_bool(), d["archive"]["after"].as_i64()), ("success", Some(true), None), "{d}");
    let checked = d["archive"]["objects"].as_u64().unwrap();
    assert!(checked >= before.len() as u64, "{d}");
    let pass = crate::audit_archive_verify::last_pass(&app, &sink).expect("a pass saved");
    assert_eq!(Some(pass.head.id), d["archive"]["head"]["id"].as_i64());
    let chain = parse(&call(port, "GET", "/api/audit/chain", &admin, "").await.1);
    assert_eq!(chain["verification"]["archive"]["ok"], true, "the app shows the archive's part: {chain}");

    // A day on: only the objects archived since are read, and the chain picks up from the head.
    age_store(&s);
    archive_round(&app, &x, 2).await;
    archive_round(&app, &x, 2).await;
    s.w().calls.clear();
    crate::audit_chain::daily(&app).await;
    let (outcome, d) = last_verified(&app);
    let a = &d["archive"];
    assert_eq!((outcome.as_str(), a["ok"].as_bool(), a["after"].as_i64()), ("success", Some(true), Some(pass.head.id)), "{d}");
    let read = read_keys(&s);
    assert!(!read.is_empty() && read.iter().all(|k| !before.contains(k)), "only new objects: {read:?}");
    assert_eq!((a["objects"].as_u64(), a["skipped"].as_u64()), (Some(read.len() as u64), Some(checked)), "{a}");
    assert!(a["first"].as_i64() > Some(pass.head.id), "{a}");
    let next = crate::audit_archive_verify::last_pass(&app, &sink).unwrap();
    assert!(next.head.id > pass.head.id && next.at > pass.at);

    // A batch already checked, copied to a new key with its details changed: the store says
    // it was written since, so it's read, and it no longer says what this server's rows do.
    age_store(&s);
    let original = before.iter().find(|k| String::from_utf8_lossy(&s.w().objects[*k]).contains("\"details\":{\"n\":0}")).unwrap().clone();
    let copy = format!("audit/prod/2099/01/01/{}", original.rsplit('/').next().unwrap());
    let (meta, _) = s.w().meta[&original].clone();
    let changed = String::from_utf8(s.w().objects[&original].clone()).unwrap().replacen("\"details\":{\"n\":0}", "\"details\":{\"n\":7}", 1);
    use base64::Engine;
    let sum = base64::engine::general_purpose::STANDARD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, changed.as_bytes()).as_ref());
    let mut h: Vec<(&str, String)> = meta.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    h.push(("x-amz-checksum-sha256", sum));
    let c = machines::s3::S3::new(s.settings()).unwrap();
    c.put_with(&copy, changed.into_bytes(), &h).await.unwrap();
    crate::audit_chain::daily(&app).await;
    let (outcome, d) = last_verified(&app);
    assert_eq!((outcome.as_str(), d["reason"].as_str(), d["archive"]["firstProblem"]["reason"].as_str()), ("failure", Some("archive"), Some("digest")), "{d}");
    assert_eq!(crate::audit_archive_verify::last_pass(&app, &sink), Some(next.clone()), "a failed check doesn't move the last pass");

    // Off: the daily check leaves the archive alone.
    let (_, app2, _, _) = serve_app().await;
    let s2 = StandIn::start().await;
    export_to(&app2, &vars(&s2, &[("AUDIT_EXPORT_S3_LOCK", "off"), ("AUDIT_EXPORT_S3_CHECK", "off")]));
    let x2 = app2.audit_export.get().unwrap().clone();
    archive_round(&app2, &x2, 2).await;
    crate::audit_chain::daily(&app2).await;
    let (outcome, d) = last_verified(&app2);
    assert_eq!((outcome.as_str(), d.get("archive")), ("success", None), "{d}");
    assert!(read_keys(&s2).is_empty());
}

#[tokio::test]
async fn the_daily_check_catches_a_log_rebuilt_where_it_already_checked() {
    let (port, app, admin, _) = serve_app().await;
    let s = StandIn::start().await;
    export_to(&app, &vars(&s, &[("AUDIT_EXPORT_S3_LOCK", "off")]));
    let x = app.audit_export.get().unwrap().clone();
    let sink = x.archive().unwrap().0.sink.id.clone();
    for _ in 0..3 {
        archive_round(&app, &x, 2).await;
    }
    // A whole check by hand that passes is where the daily check picks up, too.
    assert_eq!(verify_archive(port, &admin, "").await["archive"]["ok"], true);
    let pass = crate::audit_archive_verify::last_pass(&app, &sink).expect("a pass saved");
    assert!(verify_archive(port, &admin, "&from=2").await["archive"]["ok"] == true);
    assert_eq!(crate::audit_archive_verify::last_pass(&app, &sink), Some(pass.clone()), "a range doesn't move it");
    age_store(&s);
    s.w().calls.clear();

    // Someone with the database changes an event the last pass covered and rebuilds the
    // chain from it. Those objects aren't read again, but the head they reached moved.
    app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
    app.db.execute_raw("UPDATE audit_events SET details = '{\"n\":99}' WHERE id = 2").unwrap();
    assert!(crate::audit_chain::reseal_from(&app.db, 2) > 0);
    crate::audit_chain::daily(&app).await;
    let (outcome, d) = last_verified(&app);
    assert_eq!((outcome.as_str(), d["reason"].as_str()), ("failure", Some("archive")), "{d}");
    let first = &d["archive"]["firstProblem"];
    assert_eq!((first["reason"].as_str(), first["id"].as_i64()), (Some("mismatch"), Some(pass.head.id)), "{d}");
    assert!(first["error"].as_str().unwrap().contains("the log was rebuilt"), "{d}");
    assert!(read_keys(&s).iter().all(|k| crate::audit_archive_verify::ids("audit/prod", k).unwrap().1 > pass.head.id), "objects already checked aren't read again");
}

/// A webhook collector that answers 503 while `down` is set, then takes every batch.
async fn flaky_collector(down: Arc<std::sync::atomic::AtomicBool>) -> (String, Arc<std::sync::Mutex<Vec<Value>>>) {
    let got: Arc<std::sync::Mutex<Vec<Value>>> = Default::default();
    let state = got.clone();
    let r = axum::Router::new().route(
        "/ingest",
        axum::routing::post(move |body: String| {
            let (state, down) = (state.clone(), down.clone());
            async move {
                if down.load(std::sync::atomic::Ordering::SeqCst) {
                    return axum::http::StatusCode::SERVICE_UNAVAILABLE;
                }
                state.lock().unwrap().extend(body.lines().map(|l| serde_json::from_str::<Value>(l).unwrap()));
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
async fn an_archive_beside_a_siem_gets_every_event_while_the_siem_is_down() {
    let (port, app, admin, _) = serve_app().await;
    let s = StandIn::start().await;
    s.w().versioning = Some("Enabled");
    s.w().object_lock = Some(DEFAULT_RETENTION.into());
    let down = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (url, got) = flaky_collector(down.clone()).await;
    for i in 0..5 {
        app.db.record(&Event::new(Actor::system("test"), "test.both").details(json!({ "n": i })));
    }
    let both = format!("{url},s3://backups/audit/prod");
    export_to(&app, &vars(&s, &[("AUDIT_EXPORT", &both)]));
    let xs = app.audit_export.get().unwrap().clone();
    assert_eq!(xs.sinks.iter().map(|x| x.sink.kind()).collect::<Vec<_>>(), ["webhook", "s3"]);
    let (siem, archive) = (xs.sinks[0].clone(), xs.archive().unwrap().0);

    // The SIEM is down: the archive carries on, and retention waits for the SIEM.
    until("the SIEM failing", || siem.view(app.db.audit_head())["failing"] == true).await;
    until("archived while the SIEM is down", || archive.delivered() >= app.db.audit_head()).await;
    assert_eq!(xs.delivered(), siem.delivered(), "retention keeps what the slowest sink hasn't taken");
    assert!(xs.delivered() < archive.delivered());
    let failing = app.db.audit_events(&crate::audit::Filter { actions: vec!["audit.export_failing".into()], ..Default::default() }, 10, false);
    assert_eq!((failing.len(), failing[0].details["kind"].as_str()), (1, Some("webhook")), "only the SIEM is failing");

    let v = parse(&call(port, "GET", "/api/audit/siem", &admin, "").await.1);
    assert_eq!((v["kind"].as_str(), v["failing"].as_bool()), (Some("webhook"), Some(true)), "the failing sink leads: {v}");
    let sinks = v["sinks"].as_array().unwrap();
    assert_eq!((sinks.len(), sinks[1]["kind"].as_str(), sinks[1]["failing"].as_bool()), (2, Some("s3"), Some(false)), "{v}");
    assert_eq!(sinks[1]["archive"]["bucket"], "backups");
    let chain = parse(&call(port, "GET", "/api/audit/chain", &admin, "").await.1);
    assert_eq!(chain["export"]["sinks"].as_array().map(Vec::len), Some(2), "{chain}");
    let mut metrics = String::new();
    crate::audit_export::render(&app, &mut metrics);
    assert!(metrics.contains("superbot_audit_export_failing{kind=\"webhook\"} 1") && metrics.contains("superbot_audit_export_failing{kind=\"s3\"} 0"), "{metrics}");
    // The archive check finds the archive among the sinks.
    let checked = verify_archive(port, &admin, "").await;
    assert_eq!(checked["archive"]["ok"], true, "{checked}");

    // The SIEM is back: it catches up from its own cursor, and both hold every event once, in order.
    down.store(false, std::sync::atomic::Ordering::SeqCst);
    until("both caught up", || xs.sinks.iter().all(|x| x.delivered() >= app.db.audit_head())).await;
    let ids = |events: &[Value]| events.iter().map(|e| e["id"].as_i64().unwrap()).collect::<Vec<_>>();
    let (to_siem, to_archive) = (ids(&got.lock().unwrap()), ids(&archived(&s)));
    let head = app.db.audit_head();
    assert!(to_siem.windows(2).all(|w| w[1] == w[0] + 1) && to_siem[0] == 1 && *to_siem.last().unwrap() == head, "{to_siem:?}");
    assert_eq!(to_siem, to_archive);
    assert_eq!((app.db.audit_export_cursor(&siem.sink.id), app.db.audit_export_cursor(&archive.sink.id)), (Some(head), Some(head)), "a cursor each");
}

/// Writes `body` to `key` as botd would, its metadata copied from `like`.
async fn put_like(s: &StandIn, like: &str, key: &str, body: String) {
    use base64::Engine;
    let (meta, _) = s.w().meta[like].clone();
    let sum = base64::engine::general_purpose::STANDARD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, body.as_bytes()).as_ref());
    let mut h: Vec<(&str, String)> = meta.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    h.push(("x-amz-checksum-sha256", sum));
    machines::s3::S3::new(s.settings()).unwrap().put_with(key, body.into_bytes(), &h).await.unwrap();
}

/// Every archived line, checked as `botctl audit verify-lines` would, with no botd.
fn offline(s: &StandIn) -> crate::audit_line::Report {
    let mut l = crate::audit_line::Lines::new(None);
    for (key, body) in s.w().objects.iter().filter(|(k, _)| k.starts_with("audit/prod/")) {
        for (n, line) in String::from_utf8_lossy(body).lines().enumerate() {
            l.line(line, &format!("{key}:{}", n + 1));
        }
    }
    l.finish()
}

#[tokio::test]
async fn archived_lines_vouch_for_themselves_once_retention_has_taken_the_rows() {
    let (port, app, admin, _) = serve_app().await;
    let s = StandIn::start().await;
    // A fresh log, so it can start with old events.
    app.db.execute_raw("DROP TRIGGER audit_events_no_delete").unwrap();
    app.db.execute_raw("DELETE FROM audit_events").unwrap();
    let old = db::now() - 40 * 86_400_000;
    let ids: Vec<i64> = (0..6).map(|i| app.db.record_at(&Event::new(Actor::system("test"), "test.old").details(json!({ "n": i })), old).unwrap()).collect();
    // A batch of the first two was cut before the upgrade: it goes again as it was, with
    // no digests, and the events after it carry theirs.
    let marker = ids[1];
    let sink = format!("s3://{}/backups/audit/prod", s.url.trim_start_matches("http://"));
    app.db.set_audit_export_cursor(&format!("{sink}#batch"), marker).unwrap();
    export_to(&app, &vars(&s, &[("AUDIT_EXPORT_S3_LOCK", "off"), ("AUDIT_EXPORT_START", "all")]));
    let x = app.audit_export.get().unwrap().clone();
    until("archived", || x.delivered() >= app.db.audit_head()).await;
    assert_eq!(app.db.audit_export_cursor(crate::audit_export::DIGESTS), Some(marker));
    let siem = parse(&call(port, "GET", "/api/audit/siem", &admin, "").await.1);
    assert_eq!(siem["digestsAfter"].as_i64(), Some(marker), "{siem}");
    let sent = archived(&s);
    assert_eq!(sent[0]["id"].as_i64(), Some(ids[0]), "{sent:?}");
    assert!(sent.iter().all(|e| e["chainDigest"].is_string() == (e["id"].as_i64().unwrap() > marker)), "{sent:?}");
    assert!(sent.iter().filter(|e| e["id"].as_i64().unwrap() > marker).all(|e| e["chainSalt"].is_string()));

    let r = offline(&s);
    assert!(r.ok, "{r:?}");
    assert_eq!((r.hosts.len(), r.hosts[0].first, r.hosts[0].unbound, r.hosts[0].bound as usize), (1, Some(ids[0]), 2, sent.len() - 2), "{r:?}");
    let v = verify_archive(port, &admin, "").await;
    assert_eq!((v["archive"]["ok"].as_bool(), v["archive"]["unbound"].as_u64(), v["archive"]["digestsAfter"].as_i64()), (Some(true), Some(2), Some(marker)), "{v}");

    // Retention takes the old rows. Nothing here can say what they were any more.
    app.db.set_audit_retention(Some(30));
    crate::audit::prune(&app, 30);
    let left = app.db.audit_chain_rows(i64::MIN, 1000).unwrap();
    assert!(left.iter().all(|r| r.id > ids[5]), "{:?}", left.iter().map(|r| r.id).collect::<Vec<_>>());
    assert_eq!(verify_archive(port, &admin, "").await["archive"]["ok"], true);

    // A copy of an archived batch, the third event's details changed and its hashes kept: once
    // the row was gone this went unseen; its own digest gives it away now.
    let original = s.keys().into_iter().find(|k| String::from_utf8_lossy(&s.w().objects[k]).contains("\"details\":{\"n\":2}")).unwrap();
    let body = String::from_utf8(s.w().objects[&original].clone()).unwrap();
    let forged = format!("audit/prod/2099/01/01/{}", original.rsplit('/').next().unwrap());
    put_like(&s, &original, &forged, body.replacen("\"details\":{\"n\":2}", "\"details\":{\"n\":7}", 1)).await;
    let v = verify_archive(port, &admin, "").await;
    assert_eq!((v["ok"].as_bool(), reasons(&v)), (Some(false), vec!["digest".to_string()]), "{v}");
    assert_eq!(v["archive"]["firstProblems"][0]["id"].as_i64(), Some(ids[2]), "{v}");
    assert!(v["firstBroken"].is_null(), "this server's log is fine: {v}");
    let r = offline(&s);
    assert!(!r.ok && r.hosts[0].first_problems.iter().any(|p| p.reason == "digest" && p.id == Some(ids[2])), "{r:?}");
    machines::s3::S3::new(s.settings()).unwrap().delete(&forged).await.unwrap();
    assert_eq!(verify_archive(port, &admin, "").await["archive"]["ok"], true);

    // The same copy with its digest and salt stripped, to pass as written before them.
    let stripped: Vec<String> = body
        .lines()
        .map(|l| {
            let mut e: Value = serde_json::from_str(l).unwrap();
            if e["id"] == ids[2] {
                let o = e.as_object_mut().unwrap();
                o.remove("chainDigest");
                o.remove("chainSalt");
            }
            e.to_string()
        })
        .collect();
    put_like(&s, &original, &forged, stripped.join("\n") + "\n").await;
    let v = verify_archive(port, &admin, "").await;
    assert_eq!((reasons(&v), v["archive"]["unbound"].as_u64()), (vec!["unbound".to_string()], Some(3)), "{v}");
    let r = offline(&s);
    assert!(!r.ok && r.hosts[0].first_problems.iter().any(|p| p.reason == "unbound" && p.id == Some(ids[2])), "{r:?}");
}
