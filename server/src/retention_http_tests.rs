//! Chat retention (ADR 0098) on the real router: off unless set, deletes old chat in
//! batches but never a held Bot's or a message whose run is still going, audits each pass
//! with its counts, and lets only admins see it and hold or release a Bot's chat.

use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const DAY: i64 = 86_400_000;

async fn audit(port: u16, admin: &str, action: &str) -> Vec<Value> {
    audit_list(&call(port, "GET", &format!("/api/audit?action={action}"), admin, "").await.1)
}

#[tokio::test]
async fn off_by_default_keeps_everything() {
    let (port, app, admin, _) = serve_app().await;
    let bot = app.db.create_bot("Ada", "#fff", "waddle", "claude", None, false);
    app.db.add_messages_at(&bot.id, 3, db::now() - 3650 * DAY, None);
    retention::start(app.clone(), None);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(app.db.message_count(&bot.id), 3, "nothing is deleted while retention is off");
    let (code, body) = call(port, "GET", "/api/retention", &admin, "").await;
    let v = parse(&body);
    assert_eq!(code, 200, "{body}");
    assert_eq!((v["chat"]["retentionDays"].clone(), v["chat"]["lastPass"].clone(), v["audit"]["retentionDays"].clone()), (Value::Null, Value::Null, Value::Null), "{v}");
    assert!(audit(port, &admin, "chat.*").await.is_empty(), "no change, no pass");
}

#[tokio::test]
async fn turning_it_on_prunes_now_and_records_the_change() {
    let (port, app, admin, _) = serve_app().await;
    let bot = app.db.create_bot("Ada", "#fff", "waddle", "claude", None, false);
    app.db.add_messages_at(&bot.id, 2, db::now() - 40 * DAY, None);
    let recent = app.db.add_message(&bot.id, "user", "this week", None, false, None);
    retention::start(app.clone(), Some(30));
    for _ in 0..50 {
        if app.db.message_count(&bot.id) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(app.db.messages(&bot.id, 10).iter().map(|m| m.id).collect::<Vec<_>>(), [recent.id]);
    let changed = audit(port, &admin, "chat.retention_changed").await;
    assert_eq!((changed.len(), changed[0]["details"]["before"].clone(), changed[0]["details"]["after"].as_u64()), (1, Value::Null, Some(30)), "{changed:?}");
    let pruned = audit(port, &admin, "chat.pruned").await;
    assert_eq!(pruned[0]["details"]["deleted"].as_u64(), Some(2), "{pruned:?}");
    assert_eq!(app.db.chat_retention(), Some(30));

    // Starting again with the same setting is no change; turning it off is.
    retention::start(app.clone(), Some(30));
    retention::start(app.clone(), None);
    let changed = audit(port, &admin, "chat.retention_changed").await;
    assert_eq!((changed.len(), changed[0]["details"]["before"].as_u64(), changed[0]["details"]["after"].clone()), (2, Some(30), Value::Null), "{changed:?}");
    assert_eq!(app.db.chat_retention(), None);
}

#[tokio::test]
async fn a_pass_deletes_old_chat_in_batches_and_spares_held_and_running() {
    let (port, app, admin, _) = serve_app().await;
    let now = db::now();
    let ada = app.db.create_bot("Ada", "#fff", "waddle", "claude", None, false);
    let kept = app.db.create_bot("Kept", "#fff", "waddle", "claude", None, false);
    let old = now - 100 * DAY;
    let n = retention::BATCH as usize * 2 + 7;
    app.db.add_messages_at(&ada.id, n, old, None);
    // A held Bot's chat, and what it said in another Bot's chat, stay.
    app.db.add_messages_at(&kept.id, 4, old, None);
    app.db.add_messages_at(&ada.id, 2, old, Some(&kept.id));
    // A queued or running message stays however old; a finished one goes.
    let queued = app.db.add_message(&ada.id, "user", "still queued", None, false, Some("queued"));
    let running = app.db.add_message(&ada.id, "routine", "still running", None, false, Some("running"));
    let done = app.db.add_message(&ada.id, "user", "done", None, false, Some("done"));
    for m in [&queued, &running, &done] {
        app.db.set_message_time(m.id, old);
    }
    // Inside the window: kept.
    let fresh = app.db.add_message(&ada.id, "bot", "fresh", None, false, None);
    app.db.set_message_time(fresh.id, now - 29 * DAY);

    let (code, body) = call(port, "PUT", &format!("/api/retention/holds/{}", kept.id), &admin, &json!({ "reason": "Legal hold: matter 42" }).to_string()).await;
    assert_eq!(code, 200, "{body}");

    let pass = retention::prune(&app, 30, now).await;
    assert_eq!(pass["deleted"].as_u64(), Some(n as u64 + 1), "{pass}");
    assert_eq!((pass["batches"].as_u64(), pass["heldBots"].as_u64(), pass["error"].clone()), (Some(3), Some(1), Value::Null), "{pass}");
    assert_eq!(pass["olderThan"].as_i64(), Some(now - 30 * DAY));
    let left: Vec<i64> = app.db.messages(&ada.id, 100).iter().map(|m| m.id).collect();
    assert_eq!(left.len(), 2 + 3, "{left:?}");
    assert!([queued.id, running.id, fresh.id].iter().all(|id| left.contains(id)) && !left.contains(&done.id), "{left:?}");
    assert_eq!(app.db.message_count(&kept.id), 4);

    let pruned = audit(port, &admin, "chat.pruned").await;
    assert_eq!(pruned.len(), 1, "{pruned:?}");
    let e = &pruned[0];
    assert_eq!((e["actorKind"].as_str(), e["actorId"].as_str(), e["outcome"].as_str()), (Some("system"), Some("retention"), Some("success")), "{e}");
    assert_eq!((e["details"]["deleted"].as_u64(), e["details"]["retentionDays"].as_u64()), (Some(n as u64 + 1), Some(30)), "{e}");
    // No chat text in the event.
    assert!(!e.to_string().contains("old 1"), "{e}");

    // Admins see the last pass and the hold.
    let (_, body) = call(port, "GET", "/api/retention", &admin, "").await;
    let v = parse(&body);
    assert_eq!(v["chat"]["lastPass"]["deleted"].as_u64(), Some(n as u64 + 1), "{v}");
    let holds = v["chat"]["holds"].as_array().unwrap();
    assert_eq!((holds.len(), holds[0]["botId"].as_str(), holds[0]["botName"].as_str(), holds[0]["reason"].as_str()), (1, Some(kept.id.as_str()), Some("Kept"), Some("Legal hold: matter 42")), "{v}");

    // A pass with nothing to delete is saved but not audited.
    let again = retention::prune(&app, 30, now).await;
    assert_eq!((again["deleted"].as_u64(), again["batches"].as_u64()), (Some(0), Some(0)), "{again}");
    assert_eq!(audit(port, &admin, "chat.pruned").await.len(), 1);
    let (_, body) = call(port, "GET", "/api/retention", &admin, "").await;
    assert_eq!(parse(&body)["chat"]["lastPass"]["deleted"].as_u64(), Some(0));

    // Released, its chat goes at the next pass.
    assert_eq!(call(port, "DELETE", &format!("/api/retention/holds/{}", kept.id), &admin, "").await.0, 200);
    let pass = retention::prune(&app, 30, now).await;
    assert_eq!(pass["deleted"].as_u64(), Some(6), "{pass}");
    assert_eq!(app.db.message_count(&kept.id), 0);
}

#[tokio::test]
async fn holds_are_admin_only_audited_and_stop_the_bot_being_deleted() {
    let (port, app, admin, _) = serve_app().await;
    let (_, member) = user_with(port, &admin, "mia@example.com", "member").await;
    let (code, b) = call(port, "POST", "/api/bots", &member, &json!({ "name": "Mine" }).to_string()).await;
    assert_eq!(code, 201, "{b}");
    let bot = parse(&b)["id"].as_str().unwrap().to_string();
    let hold = format!("/api/retention/holds/{bot}");
    let reason = |r: &str| json!({ "reason": r }).to_string();

    // Members can't see retention, hold their own Bot, or release a hold.
    assert_eq!(call(port, "GET", "/api/retention", &member, "").await.0, 403);
    assert_eq!(call(port, "PUT", &hold, &member, &reason("mine")).await.0, 403);
    assert_eq!(call(port, "DELETE", &hold, &member, "").await.0, 403);

    for (body, want) in [(json!({}).to_string(), 400), (reason("  "), 400), (reason(&"x".repeat(501)), 400)] {
        assert_eq!(call(port, "PUT", &hold, &admin, &body).await.0, want, "{body}");
    }
    assert_eq!(call(port, "PUT", "/api/retention/holds/nope", &admin, &reason("x")).await.0, 404);
    assert_eq!(call(port, "DELETE", &hold, &admin, "").await.0, 404, "no hold yet");

    let (code, body) = call(port, "PUT", &hold, &admin, &reason("Litigation hold")).await;
    let v = parse(&body);
    assert_eq!((code, v["reason"].as_str(), v["owner"]["email"].as_str()), (200, Some("Litigation hold"), Some("mia@example.com")), "{body}");
    let held_at = v["heldAt"].as_i64();
    // The same reason again changes nothing; a new one is recorded, and the first hold's time is kept.
    assert_eq!(call(port, "PUT", &hold, &admin, &reason("Litigation hold")).await.0, 200);
    let (_, body) = call(port, "PUT", &hold, &admin, &reason("Litigation hold, extended")).await;
    assert_eq!(parse(&body)["heldAt"].as_i64(), held_at);
    let placed = audit(port, &admin, "chat.hold_placed").await;
    let changed = audit(port, &admin, "chat.hold_changed").await;
    assert_eq!((placed.len(), placed[0]["botId"].as_str(), placed[0]["details"]["reason"].as_str()), (1, Some(bot.as_str()), Some("Litigation hold")), "{placed:?}");
    assert_eq!((changed.len(), changed[0]["details"]["before"].as_str()), (1, Some("Litigation hold")), "{changed:?}");

    // Held, the Bot can't be deleted, by its owner or an admin.
    for who in [&member, &admin] {
        let (code, body) = call(port, "DELETE", &format!("/api/bots/{bot}"), who, "").await;
        assert_eq!(code, 409, "{body}");
        assert!(body.contains("retention hold"), "{body}");
    }
    assert!(app.db.bot(&bot).is_some());
    // Nor can a Bot the held one wrote to, since its chat goes with it.
    let (_, b) = call(port, "POST", "/api/bots", &member, &json!({ "name": "Peer" }).to_string()).await;
    let peer = parse(&b)["id"].as_str().unwrap().to_string();
    app.db.add_messages_at(&peer, 1, db::now(), Some(&bot));
    let (code, body) = call(port, "DELETE", &format!("/api/bots/{peer}"), &member, "").await;
    assert_eq!(code, 409, "{body}");

    assert_eq!(call(port, "DELETE", &hold, &admin, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("/api/bots/{peer}"), &member, "").await.0, 200);
    let released = audit(port, &admin, "chat.hold_released").await;
    assert_eq!((released.len(), released[0]["details"]["reason"].as_str()), (1, Some("Litigation hold, extended")), "{released:?}");
    assert_eq!(call(port, "DELETE", &format!("/api/bots/{bot}"), &member, "").await.0, 200);
}
