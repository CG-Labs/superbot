//! HTTP tests for the policy editor's API (ADR 0049): class actions, the timeout, a Bot's
//! fields put back to inheriting, and the rule list, with who may change each and the audit trail.

use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

#[tokio::test]
async fn admins_edit_the_global_policy_and_everyone_signed_in_reads_it() {
    let (port, _, admin, _) = serve_app().await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (_, readonly) = user_with(port, &admin, "r@example.com", "readonly").await;

    let patch = r#"{"classes":{"git_push":"deny","network_install":"allow"},"timeoutMinutes":20}"#;
    let (code, body) = call(port, "PUT", "/api/policy", &admin, patch).await;
    assert_eq!(code, 200, "{body}");
    let p = &parse(&body)["policy"];
    assert_eq!((p["classes"]["git_push"].as_str(), p["classes"]["network_install"].as_str(), p["timeoutMinutes"].as_u64()), (Some("deny"), Some("allow"), Some(20)));
    assert_eq!(p["classes"]["shell_destructive"], "ask", "classes not in the patch keep their action");

    for who in [&member, &readonly] {
        assert_eq!(call(port, "PUT", "/api/policy", who, r#"{"timeoutMinutes":1}"#).await.0, 403);
        let (code, body) = call(port, "GET", "/api/policy", who, "").await;
        assert_eq!((code, parse(&body)["policy"]["timeoutMinutes"].as_u64()), (200, Some(20)));
        assert_eq!(parse(&body)["classes"].as_array().map(Vec::len), Some(policy::CLASSES.len()));
    }
    for bad in [r#"{"timeoutMinutes":0}"#, r#"{"timeoutMinutes":1441}"#, r#"{"classes":{"git_push":"maybe"}}"#, r#"{"classes":{"nope":"ask"}}"#, r#"{"classes":{"git_push":null}}"#] {
        assert_eq!(call(port, "PUT", "/api/policy", &admin, bad).await.0, 400, "{bad}");
    }

    let (_, audit) = call(port, "GET", "/api/audit?action=policy.updated", &admin, "").await;
    let e = &audit_list(&audit)[0];
    assert_eq!((e["targetId"].as_str(), e["details"]["after"]["classes"]["git_push"].as_str()), (Some("global"), Some("deny")));
    assert_eq!(e["details"]["before"]["timeoutMinutes"], policy::DEFAULT_TIMEOUT_MINUTES);
}

#[tokio::test]
async fn a_bots_fields_go_back_to_inheriting_one_at_a_time() {
    let (port, app, admin, _) = serve_app().await;
    let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
    let path = format!("/api/bots/{}/policy", bot.id);

    let (code, body) = call(port, "PUT", &path, &admin, r#"{"classes":{"git_push":"deny","outbound_message":"allow"},"timeoutMinutes":5}"#).await;
    assert_eq!(code, 200, "{body}");
    let v = parse(&body);
    assert_eq!((v["policy"]["classes"]["git_push"].as_str(), v["policy"]["timeoutMinutes"].as_u64()), (Some("deny"), Some(5)));
    assert_eq!(v["override"], json!({ "classes": { "git_push": "deny", "outbound_message": "allow" }, "timeoutMinutes": 5 }));

    // The global policy moves underneath; only the fields the Bot set stay its own.
    call(port, "PUT", "/api/policy", &admin, r#"{"classes":{"git_push":"allow"},"timeoutMinutes":30}"#).await;
    let (_, body) = call(port, "PUT", &path, &admin, r#"{"classes":{"git_push":null}}"#).await;
    let v = parse(&body);
    assert_eq!(v["override"], json!({ "classes": { "outbound_message": "allow" }, "timeoutMinutes": 5 }));
    assert_eq!((v["policy"]["classes"]["git_push"].as_str(), v["policy"]["timeoutMinutes"].as_u64()), (Some("allow"), Some(5)));

    // A bad patch changes nothing, even the fields it would have cleared.
    for bad in [r#"{"timeoutMinutes":null,"classes":{"nope":null}}"#, r#"{"timeoutMinutes":null,"mode":"yolo"}"#] {
        assert_eq!(call(port, "PUT", &path, &admin, bad).await.0, 400, "{bad}");
    }
    assert_eq!(app.db.bot_override(&bot.id).unwrap().timeout_minutes, Some(5));

    // Clearing the last field drops the override, as a reset would.
    let (_, body) = call(port, "PUT", &path, &admin, r#"{"timeoutMinutes":null,"classes":{"outbound_message":null},"mode":null}"#).await;
    let v = parse(&body);
    assert!(v["override"].is_null(), "{v}");
    assert_eq!(v["policy"], json!(app.db.global_policy()));
    assert!(app.db.bot_override(&bot.id).is_none());

    let (_, audit) = call(port, "GET", &format!("/api/audit?action=policy.updated&bot={}", bot.id), &admin, "").await;
    let events = audit_list(&audit);
    assert_eq!(events.len(), 3, "{events:?}");
    assert_eq!(events[0]["details"]["before"]["timeoutMinutes"], 5);
    assert_eq!(events[0]["details"]["after"], json!({}));
}

#[tokio::test]
async fn bot_viewers_read_its_policy_and_only_admins_change_it() {
    let (port, app, admin, _) = serve_app().await;
    let (owner_id, owner) = user_with(port, &admin, "o@example.com", "member").await;
    let (op_id, op) = user_with(port, &admin, "op@example.com", "member").await;
    let (_, stranger) = user_with(port, &admin, "s@example.com", "member").await;
    let bot = app.db.create_bot_owned("Mine", "#fff", "waddle", "claude", None, false, &owner_id, Visibility::Private);
    assert_eq!(call(port, "PUT", &format!("/api/bots/{}/grants/{op_id}", bot.id), &admin, r#"{"level":"operator"}"#).await.0, 200);
    let path = format!("/api/bots/{}/policy", bot.id);

    for who in [&owner, &op] {
        assert_eq!(call(port, "GET", &path, who, "").await.0, 200);
        assert_eq!(call(port, "GET", &format!("/api/policy/rules?bot={}", bot.id), who, "").await.0, 200);
        assert_eq!(call(port, "PUT", &path, who, r#"{"classes":{"git_push":"allow"}}"#).await.0, 403);
        assert_eq!(call(port, "DELETE", &path, who, "").await.0, 403);
        let rule = json!({ "botId": bot.id, "action": "allow", "pattern": "git push" }).to_string();
        assert_eq!(call(port, "POST", "/api/policy/rules", who, &rule).await.0, 403);
    }
    assert_eq!(call(port, "GET", &path, &stranger, "").await.0, 404, "a private Bot stays hidden");
    assert_eq!(call(port, "GET", &format!("/api/policy/rules?bot={}", bot.id), &stranger, "").await.0, 404);
    assert!(app.db.bot_override(&bot.id).is_none());
}

#[tokio::test]
async fn rules_are_listed_added_and_deleted_with_bounds_and_audit() {
    let (port, app, admin, _) = serve_app().await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);

    let (code, body) = call(port, "POST", "/api/policy/rules", &admin, r#"{"action":"deny","pattern":"rm -rf *","tool":"shell","note":" keep it safe "}"#).await;
    assert_eq!(code, 201, "{body}");
    let global = parse(&body);
    assert_eq!((global["botId"].is_null(), global["note"].as_str()), (true, Some("keep it safe")));
    let (code, body) = call(port, "POST", "/api/policy/rules", &admin, &json!({ "botId": bot.id, "action": "allow", "pattern": "git push origin *" }).to_string()).await;
    assert_eq!(code, 201, "{body}");
    let mine = parse(&body);
    assert_eq!((mine["tool"].as_str(), mine["note"].is_null()), (Some("*"), true));

    // The global list has only global rules; a Bot's view has both.
    let (_, body) = call(port, "GET", "/api/policy", &member, "").await;
    let ids: Vec<String> = parse(&body)["rules"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(ids, [global["id"].as_str().unwrap()]);
    let (_, body) = call(port, "GET", &format!("/api/bots/{}/policy", bot.id), &member, "").await;
    assert_eq!(parse(&body)["rules"].as_array().map(Vec::len), Some(2));

    let long = |n: usize| "x".repeat(n);
    for bad in [
        json!({ "action": "ask", "pattern": "x" }),
        json!({ "action": "allow", "pattern": "  " }),
        json!({ "action": "allow", "pattern": long(policy::RULE_PATTERN_MAX + 1) }),
        json!({ "action": "allow", "pattern": "x", "tool": "two words" }),
        json!({ "action": "allow", "pattern": "x", "tool": long(policy::RULE_TOOL_MAX + 1) }),
        json!({ "action": "allow", "pattern": "x", "note": long(policy::RULE_NOTE_MAX + 1) }),
    ] {
        assert_eq!(call(port, "POST", "/api/policy/rules", &admin, &bad.to_string()).await.0, 400, "{bad}");
    }
    let at_limit = json!({ "action": "allow", "pattern": long(policy::RULE_PATTERN_MAX), "note": long(policy::RULE_NOTE_MAX) });
    assert_eq!(call(port, "POST", "/api/policy/rules", &admin, &at_limit.to_string()).await.0, 201);
    assert_eq!(call(port, "POST", "/api/policy/rules", &admin, r#"{"botId":"nope","action":"allow","pattern":"x"}"#).await.0, 404);

    let rm = format!("/api/policy/rules/{}", mine["id"].as_str().unwrap());
    assert_eq!(call(port, "DELETE", &rm, &member, "").await.0, 403);
    assert_eq!(call(port, "DELETE", &rm, &admin, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &rm, &admin, "").await.0, 404);
    assert!(app.db.rule(mine["id"].as_str().unwrap()).is_none());

    let (_, audit) = call(port, "GET", "/api/audit?action=rule.*", &admin, "").await;
    let events = audit_list(&audit);
    assert_eq!(events.iter().map(|e| e["action"].as_str().unwrap()).collect::<Vec<_>>(), ["rule.removed", "rule.added", "rule.added", "rule.added"]);
    assert_eq!((events[0]["botId"].as_str(), events[0]["details"]["rule"]["pattern"].as_str()), (Some(bot.id.as_str()), Some("git push origin *")));
}
