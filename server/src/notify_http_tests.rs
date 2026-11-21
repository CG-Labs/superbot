//! HTTP tests for approval notifications (ADR 0060): admin-only settings, webhook URLs
//! kept as secrets, tests on demand, and a pending approval reaching a webhook through
//! the hook, then findable in the audit log by its target.

use crate::notify::{self, smtp, webhook};
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

#[tokio::test]
async fn only_admins_see_or_change_notifications() {
    let (port, app, admin, _) = serve_app().await;
    let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, false);
    let (_, member) = user_with(port, &admin, "notify-m@example.com", "member").await;
    let bot_path = format!("/api/bots/{}/notifications", bot.id);
    for (m, p, body) in [
        ("GET", "/api/notifications", ""),
        ("PUT", "/api/notifications", r#"{"delaySeconds":5}"#),
        ("POST", "/api/notifications/test", "{}"),
        ("GET", bot_path.as_str(), ""),
        ("PUT", bot_path.as_str(), r#"{"email":false}"#),
    ] {
        assert_eq!(call(port, m, p, &member, body).await.0, 403, "{m} {p}");
        assert_eq!(call(port, m, p, "", body).await.0, 401, "{m} {p}");
    }
    let (code, body) = call(port, "GET", "/api/notifications", &admin, "").await;
    let v = parse(&body);
    assert_eq!(code, 200, "{body}");
    assert_eq!((v["settings"]["email"]["enabled"].as_bool(), v["settings"]["webhook"]["enabled"].as_bool()), (Some(false), Some(false)), "off until configured");
    assert_eq!(call(port, "GET", "/api/bots/nope/notifications", &admin, "").await.0, 404);
}

#[tokio::test]
async fn settings_are_checked_and_webhook_urls_never_come_back() {
    let _turn = notify::tests::GLOBAL_URL.lock().await;
    let (port, app, admin, _) = serve_app().await;
    let _ = app.notifier.set(Arc::new(notify::Notifier::new(None, Some("https://bots.example.com".into()))));
    let token = format!("T0/B0/{}", random_hex(12));
    let url = format!("https://hooks.example.com/services/{token}");

    for bad in [
        r#"{"email":{"enabled":true,"to":["ops@example.com"]}}"#.to_string(),
        r#"{"webhook":{"enabled":true,"url":null}}"#.to_string(),
        r#"{"webhook":{"url":"http://hooks.example.com/x"}}"#.to_string(),
        r#"{"webhook":{"url":"https://user:pw@hooks.example.com/x"}}"#.to_string(),
        r#"{"webhook":{"url":42}}"#.to_string(),
        r#"{"delaySeconds":9999}"#.to_string(),
    ] {
        let (code, body) = call(port, "PUT", "/api/notifications", &admin, &bad).await;
        assert_eq!(code, 400, "{bad}: {body}");
    }
    assert!(!notify::secret_set(webhook::URL), "nothing saved by a refused patch");

    let patch = json!({ "webhook": { "enabled": true, "url": url, "format": "slack" }, "throttleSeconds": 60 }).to_string();
    let (code, body) = call(port, "PUT", "/api/notifications", &admin, &patch).await;
    assert_eq!(code, 200, "{body}");
    assert!(!body.contains(&token), "{body}");
    let v = parse(&body);
    assert_eq!((v["webhook"]["set"].as_bool(), v["webhook"]["host"].as_str(), v["settings"]["webhook"]["enabled"].as_bool()), (Some(true), Some("hooks.example.com"), Some(true)));
    assert_eq!(v["links"]["app"], "https://bots.example.com/app/");
    let (_, got) = call(port, "GET", "/api/notifications", &admin, "").await;
    assert!(!got.contains(&token));

    let (_, audit) = call(port, "GET", "/api/audit?action=notifications.updated", &admin, "").await;
    let e = &audit_list(&audit)[0];
    assert_eq!((e["details"]["webhookUrl"].as_str(), e["details"]["after"]["throttleSeconds"].as_u64()), (Some("set"), Some(60)));
    assert!(!audit.contains(&token));

    let (_, secrets) = call(port, "GET", "/api/secrets", &admin, "").await;
    assert!(secrets.contains("\"NOTIFY_WEBHOOK_URL\"") && !secrets.contains(&token), "listed like botd's other secrets, never shown");

    let (code, body) = call(port, "PUT", "/api/notifications", &admin, r#"{"webhook":{"url":null}}"#).await;
    let v = parse(&body);
    assert_eq!((code, v["webhook"]["set"].as_bool(), v["settings"]["webhook"]["enabled"].as_bool()), (200, Some(false), Some(false)), "removing the URL turns it off");
    assert!(!notify::secret_set(webhook::URL));
}

#[tokio::test]
async fn a_pending_approval_reaches_the_bots_webhook_and_links_to_its_audit_trail() {
    let (port, app, admin, key) = serve_app().await;
    let mail = smtp::fake::start(Default::default()).await;
    let hook = webhook::fake::start("/bot-hook").await;
    let smtp = smtp::Smtp::for_test("127.0.0.1", mail.port, smtp::Tls::None, None, None);
    let _ = app.notifier.set(Arc::new(notify::Notifier::new(Some(smtp), Some("https://bots.example.com".into()))));
    let bot = app.db.create_bot("Pusher", "#fff", "waddle", "claude", None, false);
    let path = format!("/api/bots/{}/notifications", bot.id);

    let (code, body) = call(port, "PUT", &path, &admin, r#"{"webhook":true}"#).await;
    assert_eq!(code, 400, "no URL anywhere yet: {body}");
    let (code, body) = call(port, "PUT", &path, &admin, &json!({ "webhookUrl": hook.url, "format": "json" }).to_string()).await;
    assert_eq!(code, 200, "{body}");
    let v = parse(&body);
    assert_eq!((v["webhook"]["set"].as_bool(), v["override"]["format"].as_str(), v["reaches"]["webhook"].as_str()), (Some(true), Some("json"), Some("own")));
    assert!(!body.contains("/bot-hook"));
    call(port, "PUT", "/api/notifications", &admin, r#"{"delaySeconds":0,"email":{"enabled":true,"to":["ops@example.com"],"deciders":false}}"#).await;

    let (code, body) = call(port, "POST", "/api/notifications/test", &admin, &json!({ "botId": bot.id }).to_string()).await;
    assert_eq!((code, parse(&body)["ok"].as_bool()), (200, Some(true)), "{body}");
    assert_eq!(hook.hits.lock().unwrap()[0].body["type"], "notification.test");
    assert_eq!(mail.got.lock().unwrap().len(), 1);

    let bot_auth = key.auth(&bot.id);
    let check = json!({ "from": bot.id, "harness": "claude", "event": { "tool_name": "Bash", "tool_input": { "command": "git push origin main" }, "cwd": "/tmp" } }).to_string();
    let waiting = tokio::spawn(async move { call(port, "POST", "/api/approvals/check", &bot_auth, &check).await });
    let mut hit = None;
    for _ in 0..300 {
        hit = hook.hits.lock().unwrap().get(1).cloned();
        if hit.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let hit = hit.expect("the approval reached the webhook");
    assert_eq!((hit.body["type"].as_str(), hit.body["bot"]["name"].as_str()), (Some("approval.requested"), Some("Pusher")));
    let item = &hit.body["approvals"][0];
    let id = item["approvalId"].as_str().unwrap().to_string();
    assert_eq!(item["link"], format!("https://bots.example.com/app/home?approval={id}"));
    assert_eq!(item["consoleLink"], format!("https://bots.example.com/console/#audit?target=approval:{id}"));
    assert_eq!(item["subject"], "git push origin main");

    let (code, _) = call(port, "POST", &format!("/api/approvals/{id}/approve"), &admin, "{}").await;
    assert_eq!(code, 200);
    assert_eq!(waiting.await.unwrap().1.lines().next(), Some("allow"));

    let mut trail = Vec::new();
    for _ in 0..100 {
        let (code, audit) = call(port, "GET", &format!("/api/audit?target=approval:{id}"), &admin, "").await;
        assert_eq!(code, 200, "{audit}");
        trail = audit_list(&audit).iter().map(|e| e["action"].as_str().unwrap_or("").to_string()).collect();
        if trail.iter().filter(|a| a.starts_with("notification.")).count() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for want in ["approval.requested", "approval.approved", "notification.sent"] {
        assert!(trail.iter().any(|a| a == want), "{want} in {trail:?}");
    }
    assert_eq!(call(port, "GET", "/api/audit?target=approval:a%20b", &admin, "").await.0, 400);

    call(port, "DELETE", &format!("/api/bots/{}", bot.id), &admin, "").await;
    assert!(!notify::secret_set(&webhook::bot_secret(&bot.id)), "its URL goes with it");
}
