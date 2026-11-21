//! Suggested prompts per Bot (ADR 0054), on the real router: who can set them, what
//! everyone who can see the Bot gets, what's refused, and the audit trail.

use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

fn prompts_of(list: &str, id: &str) -> Value {
    parse(list)
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["id"] == id)
        .map(|b| b["prompts"].clone())
        .unwrap_or(Value::Null)
}

#[tokio::test]
async fn owners_set_prompts_and_everyone_who_sees_the_bot_gets_them() {
    let (port, app, admin, _) = serve_app().await;
    let (a_id, a) = user_with(port, &admin, "a@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "b@example.com", "member").await;
    let (_, c) = user_with(port, &admin, "c@example.com", "member").await;
    let bot = app.db.create_bot_owned(
        "Scout",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &a_id,
        Visibility::Private,
    );
    app.db.set_grant(&bot.id, &b_id, acl::Grant::Viewer, &a_id);
    let path = format!("/api/bots/{}", bot.id);

    // New Bots have none saved: clients show their defaults.
    let (_, list) = call(port, "GET", "/api/bots", &a, "").await;
    assert_eq!(prompts_of(&list, &bot.id), Value::Null);

    // Trimmed, blanks and repeats dropped, order kept.
    let body =
        json!({ "prompts": ["  Check the build ", "", "Summarize my inbox…", "Check the build"] })
            .to_string();
    let (code, res) = call(port, "PATCH", &path, &a, &body).await;
    assert_eq!(code, 200, "{res}");
    let want = json!(["Check the build", "Summarize my inbox…"]);
    assert_eq!(parse(&res)["prompts"], want);
    assert_eq!(
        app.db.bot(&bot.id).unwrap().prompts,
        Some(vec![
            "Check the build".to_string(),
            "Summarize my inbox…".to_string()
        ])
    );

    // A viewer sees them; someone who can't see the Bot gets nothing.
    let (_, list) = call(port, "GET", "/api/bots", &b, "").await;
    assert_eq!(prompts_of(&list, &bot.id), want);
    let (_, list) = call(port, "GET", "/api/bots", &c, "").await;
    assert!(!list.contains(&bot.id));

    // An empty list shows none; null goes back to the defaults.
    let (_, res) = call(port, "PATCH", &path, &a, r#"{"prompts":[]}"#).await;
    assert_eq!(parse(&res)["prompts"], json!([]));
    let (_, res) = call(port, "PATCH", &path, &a, r#"{"prompts":null}"#).await;
    assert_eq!(parse(&res)["prompts"], Value::Null);
    assert_eq!(app.db.bot(&bot.id).unwrap().prompts, None);

    // Other settings leave them alone.
    call(port, "PATCH", &path, &a, r#"{"prompts":["Ship it"]}"#).await;
    let (_, res) = call(port, "PATCH", &path, &a, r#"{"name":"Scout 2"}"#).await;
    assert_eq!(parse(&res)["prompts"], json!(["Ship it"]));

    // Each change is audited with what it was and became.
    let (_, body) = call(
        port,
        "GET",
        &format!("/api/audit?bot={}&action=bot.updated&limit=100", bot.id),
        &admin,
        "",
    )
    .await;
    let changes: Vec<Value> = audit_list(&body)
        .into_iter()
        .filter_map(|e| e["details"]["changes"].get("prompts").cloned())
        .collect();
    assert!(
        changes.contains(&json!({ "from": null, "to": want })),
        "{changes:?}"
    );
    assert!(
        changes.contains(&json!({ "from": [], "to": null })),
        "{changes:?}"
    );
    assert_eq!(
        changes.len(),
        4,
        "the rename isn't a prompts change: {changes:?}"
    );
}

#[tokio::test]
async fn only_those_who_manage_the_bot_can_change_its_prompts() {
    let (port, app, admin, key) = serve_app().await;
    let (a_id, a) = user_with(port, &admin, "a@example.com", "member").await;
    let (op_id, op) = user_with(port, &admin, "op@example.com", "member").await;
    let (r_id, r) = user_with(port, &admin, "r@example.com", "readonly").await;
    let (_, stranger) = user_with(port, &admin, "s@example.com", "member").await;
    let bot = app.db.create_bot_owned(
        "Scout",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &a_id,
        Visibility::Private,
    );
    app.db
        .set_grant(&bot.id, &op_id, acl::Grant::Operator, &a_id);
    app.db
        .set_grant(&bot.id, &r_id, acl::Grant::Operator, &a_id);
    let path = format!("/api/bots/{}", bot.id);
    let body = r#"{"prompts":["Do my taxes"]}"#;

    assert_eq!(
        call(port, "PATCH", &path, &op, body).await.0,
        403,
        "operators run it, they don't set it up"
    );
    assert_eq!(call(port, "PATCH", &path, &r, body).await.0, 403);
    assert_eq!(
        call(port, "PATCH", &path, &stranger, body).await.0,
        404,
        "a private Bot stays hidden"
    );
    assert_eq!(app.db.bot(&bot.id).unwrap().prompts, None);

    // A shared Bot (ADR 0046): everyone sees its prompts, only its owner and admins edit them.
    app.db.set_bot_visibility(&bot.id, Visibility::Shared);
    assert_eq!(call(port, "PATCH", &path, &stranger, body).await.0, 403);
    let (_, list) = call(port, "GET", "/api/bots", &stranger, "").await;
    assert_eq!(prompts_of(&list, &bot.id), Value::Null);

    // Its owner and admins manage it; the Bot itself acts as its owner.
    assert_eq!(call(port, "PATCH", &path, &a, body).await.0, 200);
    assert_eq!(call(port, "PATCH", &path, &admin, body).await.0, 200);
    let (code, res) = call(
        port,
        "PATCH",
        &path,
        &key.auth(&bot.id),
        r#"{"prompts":["Check the build"]}"#,
    )
    .await;
    assert_eq!(code, 200, "{res}");
    let (_, list) = call(port, "GET", "/api/bots", &stranger, "").await;
    assert_eq!(prompts_of(&list, &bot.id), json!(["Check the build"]));
}

#[tokio::test]
async fn bad_prompts_are_refused_and_nothing_changes() {
    let (port, app, admin, _) = serve_app().await;
    let (a_id, a) = user_with(port, &admin, "a@example.com", "member").await;
    let bot = app.db.create_bot_owned(
        "Scout",
        "#fff",
        "waddle",
        "claude",
        None,
        false,
        &a_id,
        Visibility::Private,
    );
    let path = format!("/api/bots/{}", bot.id);
    let seven: Vec<String> = (1..=7).map(|n| format!("Prompt {n}")).collect();
    let long = "x".repeat(201);
    for (body, says) in [
        (json!({ "prompts": seven, "name": "Renamed" }), "at most 6"),
        (json!({ "prompts": [long] }), "at most 200 characters"),
        (json!({ "prompts": ["ok", 3] }), "list of text"),
        (json!({ "prompts": "Check the build" }), "list of text"),
    ] {
        let (code, res) = call(port, "PATCH", &path, &a, &body.to_string()).await;
        assert_eq!(code, 400, "{body}");
        assert!(
            parse(&res)["error"].as_str().unwrap().contains(says),
            "{res}"
        );
    }
    let after = app.db.bot(&bot.id).unwrap();
    assert_eq!((after.name.as_str(), after.prompts), ("Scout", None));

    // Six of exactly 200 characters fit; blanks don't count toward the six.
    let mut six: Vec<String> = (1..=6).map(|n| format!("{n}{}", "é".repeat(199))).collect();
    six.push("   ".into());
    assert_eq!(
        call(
            port,
            "PATCH",
            &path,
            &a,
            &json!({ "prompts": six }).to_string()
        )
        .await
        .0,
        200
    );
    assert_eq!(app.db.bot(&bot.id).unwrap().prompts.unwrap().len(), 6);
}
