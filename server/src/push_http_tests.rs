//! HTTP tests for push notifications (ADR 0079) on the real router: a phone per
//! session, never shown back and gone with the session; approvals that reach only their
//! deciders' phones and routines only the phones of the person they ran for, with
//! nothing a Bot asked to run in them. The provider is a fake that keeps what it got.

use crate::acl::{Grant, Visibility};
use crate::audit::{Actor, Who};
use crate::notify::{self, push};
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, signed_in, user_with};
use crate::*;

const ADA: &str = "ExponentPushToken[ada-phone-1]";
const BOB: &str = "ExponentPushToken[bob-phone-1]";
const CY: &str = "ExponentPushToken[cy-phone-1]";
const DEE: &str = "ExponentPushToken[dee-phone-1]";
const EVE: &str = "ExponentPushToken[eve-phone-1]";

fn with_push(app: &App, routine_window: Duration) -> push::fake::Recorder {
    let rec = push::fake::Recorder::default();
    let mut p = push::Push::new(Box::new(rec.clone()), users::SessionConfig::default());
    p.routine_window = routine_window;
    let n = notify::Notifier::new(None, Some("https://bots.example.com".into())).with_push(p);
    assert!(app.notifier.set(Arc::new(n)).is_ok());
    rec
}

async fn register(port: u16, auth: &str, token: &str, extra: Value) -> (u16, Value) {
    let mut body = json!({ "token": token, "platform": "ios" });
    body.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    let (code, b) = call(port, "PUT", "/api/me/push", auth, &body.to_string()).await;
    (code, serde_json::from_str(&b).unwrap_or(Value::Null))
}

async fn events(port: u16, admin: &str, q: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?limit=500&{q}"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn session_of(port: u16, auth: &str) -> String {
    let (_, me) = call(port, "GET", "/api/auth/me", auth, "").await;
    parse(&me)["session"]["id"].as_str().unwrap().to_string()
}

async fn until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..500 {
        if let Some(v) = f() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

/// A stand-in `claude` on the Bots' PATH that replies once and exits.
fn fake_claude(app: &App) {
    use std::os::unix::fs::PermissionsExt;
    let path = app.cfg.bin_dir.join("claude");
    let reply = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Done: 3 invoices."}]}}"#;
    std::fs::write(&path, format!("#!/bin/sh\necho '{reply}'\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[tokio::test]
async fn push_is_off_until_an_operator_turns_it_on() {
    let (port, app, admin, key) = serve_app().await;
    let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, false);
    let (_, ada) = user_with(port, &admin, "push-off@example.com", "member").await;
    let (code, body) = call(port, "GET", "/api/me/push", &ada, "").await;
    let v = parse(&body);
    assert_eq!((code, v["available"].as_bool(), v["device"].is_null()), (200, Some(false), true), "{body}");
    let (code, v) = register(port, &ada, ADA, json!({})).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("PUSH_PROVIDER=expo"), "{v}");
    // No session to tie a phone to: the shared password, and Bots.
    assert_eq!(call(port, "GET", "/api/me/push", &admin, "").await.0, 409);
    assert_eq!(call(port, "GET", "/api/me/push", &key.auth(&bot.id), "").await.0, 403);
    assert_eq!(call(port, "GET", "/api/me/push", "", "").await.0, 401);
}

#[tokio::test]
async fn a_phone_is_registered_per_session_and_its_token_never_comes_back() {
    let (port, app, admin, _) = serve_app().await;
    with_push(&app, push::ROUTINE_WINDOW);
    let (ada_id, ada) = user_with(port, &admin, "push-reg@example.com", "readonly").await;

    for (bad, why) in [
        (json!({ "token": "not-a-token", "platform": "ios" }), "token"),
        (json!({ "token": ADA, "platform": "web" }), "platform"),
        (json!({ "token": ADA, "platform": "ios", "routines": "yes" }), "routines"),
    ] {
        let (code, body) = call(port, "PUT", "/api/me/push", &ada, &bad.to_string()).await;
        assert_eq!(code, 400, "{why}: {body}");
    }
    let (code, v) = register(port, &ada, ADA, json!({})).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["available"].as_bool(), v["provider"].as_str()), (Some(true), Some("expo")));
    let d = &v["device"];
    assert_eq!((d["platform"].as_str(), d["approvals"].as_bool(), d["routines"].as_bool()), (Some("ios"), Some(true), Some(true)), "both on unless turned off");
    assert!(!v.to_string().contains("ada-phone"), "{v}");
    let (_, again) = register(port, &ada, ADA, json!({})).await;
    assert_eq!(again["device"]["id"], d["id"], "the same phone, not another");

    let (code, v) = register(port, &ada, ADA, json!({ "approvals": false })).await;
    assert_eq!((code, v["device"]["approvals"].as_bool(), v["device"]["routines"].as_bool()), (200, Some(false), Some(true)), "switches left out stay as they were");
    let (_, got) = call(port, "GET", "/api/me/push", &ada, "").await;
    assert_eq!(parse(&got)["device"]["approvals"], false);

    let (code, body) = call(port, "DELETE", "/api/me/push", &ada, "").await;
    assert_eq!((code, parse(&body)["device"].is_null()), (200, true), "{body}");
    let audit = events(port, &admin, &format!("action=push.*&actor=user:{ada_id}")).await;
    let actions: Vec<&str> = audit.iter().rev().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["push.registered", "push.updated", "push.unregistered"], "an unchanged register isn't an event");
    assert_eq!((audit[2]["details"]["platform"].as_str(), audit[2]["details"]["moved"].as_bool()), (Some("ios"), Some(false)));
    assert!(!serde_json::to_string(&audit).unwrap().contains("ada-phone"));
}

#[tokio::test]
async fn signing_out_revoking_or_disabling_removes_the_phone() {
    let (port, app, admin, _) = serve_app().await;
    with_push(&app, push::ROUTINE_WINDOW);
    let (ada_id, ada) = user_with(port, &admin, "push-out@example.com", "member").await;
    let has = |s: &str| app.db.session_push_device(s).is_some();

    register(port, &ada, ADA, json!({})).await;
    let s = session_of(port, &ada).await;
    assert!(has(&s));
    assert_eq!(call(port, "POST", "/api/auth/logout", &ada, "").await.0, 200);
    assert!(!has(&s), "signing out");

    let ada = signed_in(port, &admin, &ada_id).await.unwrap();
    register(port, &ada, ADA, json!({})).await;
    let s = session_of(port, &ada).await;
    assert_eq!(call(port, "DELETE", &format!("/api/sessions/{s}"), &admin, "").await.0, 200);
    assert!(!has(&s), "an admin revoking the session");

    let ada = signed_in(port, &admin, &ada_id).await.unwrap();
    register(port, &ada, ADA, json!({})).await;
    let s = session_of(port, &ada).await;
    assert_eq!(call(port, "DELETE", &format!("/api/users/{ada_id}/sessions"), &admin, "").await.0, 200);
    assert!(!has(&s), "an admin ending all their sessions");

    let ada = signed_in(port, &admin, &ada_id).await.unwrap();
    register(port, &ada, ADA, json!({})).await;
    let s = session_of(port, &ada).await;
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ada_id}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert!(!has(&s), "disabling them");

    // A session that has gone idle or past its age reaches nothing, though not yet pruned.
    let (bob_id, bob) = user_with(port, &admin, "push-idle@example.com", "member").await;
    register(port, &bob, BOB, json!({})).await;
    let now = db::now();
    assert_eq!(app.db.live_push_devices(&bob_id, db::PushKind::Approvals, now, 60_000, 3_600_000).len(), 1);
    assert!(app.db.live_push_devices(&bob_id, db::PushKind::Approvals, now + 61_000, 60_000, 3_600_000).is_empty(), "idle");
    assert!(app.db.live_push_devices(&bob_id, db::PushKind::Approvals, now + 3_601_000, 7_200_000, 3_600_000).is_empty(), "too old");
    assert!(app.db.live_push_devices(&bob_id, db::PushKind::Routines, now, 60_000, 3_600_000).len() == 1);
}

#[tokio::test]
async fn an_approval_reaches_only_its_deciders_phones_and_says_nothing_it_asked() {
    let (port, app, admin, key) = serve_app().await;
    let rec = with_push(&app, push::ROUTINE_WINDOW);
    let (ada_id, ada) = user_with(port, &admin, "push-ada@example.com", "member").await;
    let (bob_id, bob) = user_with(port, &admin, "push-bob@example.com", "member").await;
    let (cy_id, cy) = user_with(port, &admin, "push-cy@example.com", "member").await;
    let (_, dee) = user_with(port, &admin, "push-dee@example.com", "member").await;
    let (eve_id, eve) = user_with(port, &admin, "push-eve@example.com", "readonly").await;
    let bot = app.db.create_bot_owned("Ada's Ops", "#fff", "waddle", "claude", None, false, &ada_id, Visibility::Private);
    // Bob can answer; Cy can only look; Eve can't approve whatever she's granted; Dee can't see it.
    app.db.set_grant(&bot.id, &bob_id, Grant::Operator, "test");
    app.db.set_grant(&bot.id, &cy_id, Grant::Viewer, "test");
    app.db.set_grant(&bot.id, &eve_id, Grant::Operator, "test");
    for (auth, token) in [(&ada, ADA), (&bob, BOB), (&cy, CY), (&dee, DEE), (&eve, EVE)] {
        assert_eq!(register(port, auth, token, json!({})).await.0, 200);
    }
    call(port, "PUT", "/api/notifications", &admin, r#"{"delaySeconds":0}"#).await;

    let bot_auth = key.auth(&bot.id);
    let check = json!({ "from": bot.id, "harness": "claude", "event": { "tool_name": "Bash", "tool_input": { "command": "git push origin main --force" }, "cwd": "/tmp" } }).to_string();
    let waiting = tokio::spawn(async move { call(port, "POST", "/api/approvals/check", &bot_auth, &check).await });
    let sent = until("the pushes", || {
        let s = rec.sent.lock().unwrap().clone();
        (s.len() >= 2).then_some(s)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rec.sent.lock().unwrap().len(), 2, "one push per decider's phone, nobody else's");
    let mut to: Vec<&str> = sent.iter().map(|m| m.to.as_str()).collect();
    to.sort();
    assert_eq!(to, [ADA, BOB]);
    let id = sent[0].data["approvalId"].as_str().unwrap().to_string();
    for m in &sent {
        assert_eq!((m.title.as_str(), m.body.as_str()), ("Approval needed", "Ada's Ops is waiting for your approval."));
        assert_eq!((m.data["url"].as_str(), m.data["botId"].as_str()), (Some(format!("/home?approval={id}").as_str()), Some(bot.id.as_str())));
        let all = format!("{} {} {}", m.title, m.body, m.data);
        assert!(!all.contains("git push") && !all.contains("Bash") && !all.contains("--force"), "{all}");
    }
    let e = until("the audit event", || {
        let f = audit::Filter::from_query(&HashMap::from([("action".to_string(), "notification.sent".to_string())])).unwrap();
        app.db.audit_events(&f, 50, true).into_iter().find(|e| e.details["channel"] == "push")
    })
    .await;
    assert_eq!((e.target_id.as_deref(), e.details["delivered"].as_u64(), e.details["devices"].as_u64()), (Some(id.as_str()), Some(2), Some(2)));
    let users = e.details["users"].as_array().unwrap();
    assert!(users.contains(&json!(ada_id)) && users.contains(&json!(bob_id)) && users.len() == 2, "{users:?}");

    assert_eq!(call(port, "POST", &format!("/api/approvals/{id}/deny"), &ada, "{}").await.0, 200);
    assert_eq!(waiting.await.unwrap().1.lines().next(), Some("deny"));
}

#[tokio::test]
async fn a_phone_that_changes_hands_stops_reaching_the_last_person() {
    let (port, app, admin, _) = serve_app().await;
    let rec = with_push(&app, push::ROUTINE_WINDOW);
    let (ada_id, ada) = user_with(port, &admin, "push-hand-a@example.com", "member").await;
    let (dee_id, dee) = user_with(port, &admin, "push-hand-d@example.com", "member").await;
    let bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &ada_id, Visibility::Private);
    register(port, &ada, ADA, json!({})).await;
    let n = app.notifier.get().unwrap().clone();
    assert_eq!(n.plan(&app.db, Some(&bot), &notify::load(&app.db)).push.len(), 1);

    let (code, v) = register(port, &dee, ADA, json!({ "platform": "android" })).await;
    assert_eq!((code, v["device"]["platform"].as_str()), (200, Some("android")));
    let (_, mine) = call(port, "GET", "/api/me/push", &ada, "").await;
    assert!(parse(&mine)["device"].is_null(), "Ada's session lost it: {mine}");
    assert!(n.plan(&app.db, Some(&bot), &notify::load(&app.db)).is_empty(), "nothing of Ada's Bot reaches Dee's phone");
    let moved = &events(port, &admin, &format!("action=push.registered&actor=user:{dee_id}")).await[0];
    assert_eq!(moved["details"]["moved"], true);

    // A routine of Ada's doesn't reach it either.
    let m = app.db.add_message(&bot.id, "routine", "Payroll: run it", None, false, Some("queued"));
    notify::routine_done(&app, &bot, &m);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rec.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_finished_routine_reaches_the_phones_of_the_person_it_ran_for() {
    let (port, app, admin, _) = serve_app().await;
    fake_claude(&app);
    let rec = with_push(&app, Duration::from_millis(1500));
    let (ada_id, ada) = user_with(port, &admin, "push-rt-a@example.com", "member").await;
    let (bob_id, bob) = user_with(port, &admin, "push-rt-b@example.com", "member").await;
    let (_, dee) = user_with(port, &admin, "push-rt-d@example.com", "member").await;
    let bot = app.db.create_bot_owned("Ledger", "#fff", "waddle", "claude", None, false, &ada_id, Visibility::Shared);
    for (auth, token) in [(&ada, ADA), (&bob, BOB), (&dee, DEE)] {
        register(port, auth, token, json!({})).await;
    }
    let queue = |text: &str, author: Option<&str>| {
        let mut m = app.db.add_message(&bot.id, "routine", text, None, false, Some("queued"));
        let mut actor = Actor::system("scheduler").on_behalf_of(&ada_id);
        actor.asker = author.map(String::from);
        let by = Who { actor, source: Default::default() };
        app.db.set_requested_by(m.id, &by);
        m.requested_by = Some(by);
        app.enqueue(m);
    };

    queue("Secret payroll: pay everyone", None);
    let first = until("the first push", || rec.to(ADA).first().cloned()).await;
    assert_eq!((first.title.as_str(), first.body.as_str()), ("Routine finished", "Ledger finished a scheduled routine."));
    assert_eq!((first.data["type"].as_str(), first.data["url"].as_str()), (Some("routine"), Some(format!("/home?bot={}", bot.id).as_str())));
    let all = format!("{first:?}");
    assert!(!all.contains("payroll") && !all.contains("invoices"), "no routine name or output: {all}");

    // Two more inside the window go as one at its end.
    queue("Secret payroll: again", None);
    queue("Secret payroll: and again", None);
    let digest = until("the digest", || rec.to(ADA).get(1).cloned()).await;
    assert_eq!(digest.body, "Ledger finished 2 scheduled routines.");

    // A routine Bob wrote runs for him: his phone hears of it, not Ada's.
    queue("Bob's check: look", Some(&bob_id));
    let his = until("Bob's push", || rec.to(BOB).first().cloned()).await;
    assert_eq!(his.body, "Ledger finished a scheduled routine.");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(rec.to(ADA).len(), 2);
    assert!(rec.to(DEE).is_empty(), "Dee can see the shared Bot but the routines aren't hers");

    let e = events(port, &admin, &format!("action=notification.sent&bot={}", bot.id)).await;
    assert!(e.iter().all(|e| e["details"]["channel"] == "push" && e["details"]["kind"] == "routine"), "{e:?}");
    assert_eq!(e.iter().map(|e| e["details"]["routines"].as_u64().unwrap()).sum::<u64>(), 4);
}

#[tokio::test]
async fn a_device_the_provider_says_is_gone_is_forgotten() {
    let (port, app, admin, _) = serve_app().await;
    let rec = with_push(&app, push::ROUTINE_WINDOW);
    let (ada_id, ada) = user_with(port, &admin, "push-gone@example.com", "member").await;
    let bot = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &ada_id, Visibility::Private);
    register(port, &ada, ADA, json!({})).await;
    rec.gone.lock().unwrap().push(ADA.into());
    let m = app.db.add_message(&bot.id, "routine", "R: x", None, false, Some("queued"));
    notify::routine_done(&app, &bot, &m);
    let s = session_of(port, &ada).await;
    until("the device to go", || app.db.session_push_device(&s).is_none().then_some(())).await;
    let e = until("the audit event", || {
        let f = audit::Filter::from_query(&HashMap::from([("action".to_string(), "push.unregistered".to_string())])).unwrap();
        app.db.audit_events(&f, 5, true).into_iter().next()
    })
    .await;
    assert_eq!((e.actor_id.as_deref(), e.details["reason"].as_str(), e.details["userId"].as_str()), (Some("notifications"), Some("provider_gone"), Some(ada_id.as_str())));
}
