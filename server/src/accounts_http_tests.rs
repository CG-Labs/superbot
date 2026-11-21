//! HTTP tests for per-user accounts (ADR 0037): only admins see or make a user's
//! account or start a harness login as them, and with the flag off nothing changes.

use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

#[tokio::test]
async fn with_isolation_off_the_endpoints_say_so_and_do_nothing() {
    let (port, _app, admin, _) = serve_app().await;
    let (id, _) = user_with(port, &admin, "a@example.com", "member").await;
    let (code, body) = call(port, "GET", &format!("/api/users/{id}/isolation"), &admin, "").await;
    assert_eq!((code, parse(&body)["isolation"].as_str()), (200, Some("off")), "{body}");
    for (path, body) in [("isolation", ""), ("harness-login", r#"{"harness":"claude"}"#)] {
        let (code, res) = call(port, "POST", &format!("/api/users/{id}/{path}"), &admin, body).await;
        assert_eq!(code, 409, "{path}: {res}");
        assert!(parse(&res)["error"].as_str().unwrap().contains("ISOLATION=users"), "{res}");
    }
    let (_, audit) = call(port, "GET", "/api/audit?action=isolation.*", &admin, "").await;
    assert!(audit_list(&audit).is_empty(), "{audit}");
}

#[tokio::test]
async fn only_admins_reach_a_users_account() {
    let (port, app, admin, bots) = serve_app().await;
    let (a_id, a) = user_with(port, &admin, "a@example.com", "member").await;
    let (_, b) = user_with(port, &admin, "b@example.com", "member").await;
    let bot = app.db.create_bot_owned("A1", "#fff", "waddle", "claude", None, false, &a_id, acl::Visibility::Private);
    let bot_auth = bots.auth(&bot.id);
    for (who, auth) in [("owner", &a), ("other member", &b), ("their own Bot", &bot_auth)] {
        for (method, path, body) in [
            ("GET", "isolation", ""),
            ("POST", "isolation", ""),
            ("POST", "harness-login", r#"{"harness":"claude"}"#),
        ] {
            let (code, res) = call(port, method, &format!("/api/users/{a_id}/{path}"), auth, body).await;
            assert_eq!(code, 403, "{who} {method} {path}: {res}");
        }
    }
}

#[tokio::test]
async fn with_isolation_on_admins_see_the_account_and_failures_are_audited() {
    let (port, app, admin, _) = serve_app().await;
    let root = app.cfg.data_dir.parent().unwrap().join(format!("iso-{}", short_id()));
    std::fs::create_dir_all(&root).unwrap();
    let _ = app.isolation.set(Arc::new(accounts::for_tests(&root, "/bin/false")));
    let (id, _) = user_with(port, &admin, "a@example.com", "member").await;

    let (code, body) = call(port, "GET", &format!("/api/users/{id}/isolation"), &admin, "").await;
    let v = parse(&body);
    assert_eq!(code, 200, "{body}");
    assert_eq!(v["account"], format!("sb-u-{id}"));
    assert_eq!(v["home"], root.join(&id).join("home").display().to_string());
    assert_eq!(v["workspace"], root.join(&id).join("workspace").display().to_string());
    assert_eq!(v["ready"], false);
    assert_eq!(v["harnesses"], json!(["claude", "codex", "pi", "hermes"]));
    assert_eq!(v["logins"], json!(["claude", "codex"]), "Pi and Hermes take API keys");

    // Harnesses it can't log in, and arguments that aren't a short list of strings.
    for body in [
        json!({ "harness": "pi" }),
        json!({ "harness": "hermes" }),
        json!({}),
        json!({ "harness": "claude", "args": "login" }),
        json!({ "harness": "claude", "args": [1] }),
        json!({ "harness": "claude", "args": vec!["x"; 17] }),
    ] {
        let (code, res) = call(port, "POST", &format!("/api/users/{id}/harness-login"), &admin, &body.to_string()).await;
        assert_eq!(code, 400, "{body}: {res}");
    }

    // The account helper fails: 502, audited, and no login started.
    let (code, res) = call(port, "POST", &format!("/api/users/{id}/isolation"), &admin, "").await;
    assert_eq!(code, 502, "{res}");
    let (code, res) = call(port, "POST", &format!("/api/users/{id}/harness-login"), &admin, r#"{"harness":"codex"}"#).await;
    assert_eq!(code, 502, "{res}");
    let (_, audit) = call(port, "GET", "/api/audit?action=isolation.account_failed", &admin, "").await;
    let events = audit_list(&audit);
    assert_eq!(events.len(), 2, "{audit}");
    assert_eq!(events[0]["targetId"], id);
    assert_eq!(events[0]["details"]["account"], format!("sb-u-{id}"));
    let (_, audit) = call(port, "GET", "/api/audit?action=harness.login_started", &admin, "").await;
    assert!(audit_list(&audit).is_empty(), "{audit}");

    let (code, _) = call(port, "GET", "/api/users/nobody/isolation", &admin, "").await;
    assert_eq!(code, 404);
}
