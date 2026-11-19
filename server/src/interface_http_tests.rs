//! The Expo client is the interface for everyone; the console is an admin fallback (ADR 0027).

use crate::sso_http_tests::{header, mock_idp, serve_with, set_cookies, to_callback, OID};
use crate::tests::{call, call_with, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn location(port: u16, path: &str, auth: &str, extra: &str) -> (u16, Option<String>, String) {
    let (code, head, body) = call_with(port, "GET", path, auth, extra, "").await;
    (code, header(&head, "location"), body)
}

#[tokio::test]
async fn people_land_on_the_app_and_admins_keep_the_console() {
    let (port, _, admin, _) = serve_app().await;
    let (_, member) = user_with(port, &admin, "mia@example.com", "member").await;
    let (_, viewer) = user_with(port, &admin, "rex@example.com", "readonly").await;

    // Break-glass (the owner, an admin) still gets the console and its files.
    for path in ["/console/", "/console/index.html", "/console/app.js", "/console/styles.css"] {
        assert_eq!(location(port, path, &admin, "").await.0, 200, "{path}");
    }
    // Without Caddy's web client, /app/ sends admins to the console.
    assert_eq!(location(port, "/app/", &admin, "").await.1.as_deref(), Some("/console/"));

    for who in [&member, &viewer] {
        for path in ["/console/", "/console/index.html", "/console/app.js", "/console/styles.css"] {
            let (code, to, _) = location(port, path, who, "").await;
            assert_eq!((code, to.as_deref()), (303, Some("/app/")), "{path}");
        }
        // No loop back to the console when botd itself answers /app/.
        let (code, to, body) = location(port, "/app/", who, "").await;
        assert_eq!((code, to), (404, None));
        assert!(body.contains("web app isn't installed"), "{body}");
        assert_eq!(location(port, "/app/some/deep/link", who, "").await.0, 404);
    }

    let me = |auth: String| async move { parse(&call(port, "GET", "/api/auth/me", &auth, "").await.1) };
    assert_eq!(me(admin.clone()).await["landing"].as_str(), Some("/console/"));
    assert_eq!(me(member.clone()).await["landing"].as_str(), Some("/app/"));
    assert_eq!(me(viewer.clone()).await["landing"].as_str(), Some("/app/"));
}

#[tokio::test]
async fn sign_in_health_and_the_public_site_stay_open() {
    let (port, _, _, _) = serve_app().await;
    for path in ["/console/", "/app/"] {
        assert_eq!(location(port, path, "", "").await.1.as_deref(), Some("/login"), "{path}");
    }
    let (code, _, body) = location(port, "/login", "", "").await;
    assert!(code == 200 && body.contains("Sign-in code or password"), "{code}");
    assert!(body.contains("me?.landing"), "the sign-in page follows the server's landing");
    for path in ["/healthz", "/", "/get-started"] {
        assert_eq!(location(port, path, "", "").await.0, 200, "{path}");
    }
}

#[tokio::test]
async fn a_members_cookie_session_from_the_sign_in_page_opens_the_app() {
    let (port, _, admin, _) = serve_app().await;
    let (id, _) = user_with(port, &admin, "mia@example.com", "member").await;
    let (_, c) = call(port, "POST", &format!("/api/users/{id}/login-codes"), &admin, "").await;
    let body = json!({ "code": parse(&c)["code"], "session": "cookie" }).to_string();
    let (code, head, _) = call_with(port, "POST", "/api/auth/login", "", &format!("Origin: http://127.0.0.1:{port}\r\n"), &body).await;
    assert_eq!(code, 200);
    let token = header(&head, "set-cookie").unwrap().split(';').next().unwrap().to_string();
    let cookie = format!("Cookie: {token}\r\n");
    assert_eq!(location(port, "/console/", "", &cookie).await.1.as_deref(), Some("/app/"));
    // The app adopts this cookie: /api/auth/me shows a session it can use.
    let (code, _, me) = call_with(port, "GET", "/api/auth/me", "", &cookie, "").await;
    let me = parse(&me);
    assert_eq!((code, me["landing"].as_str(), me["session"].is_object()), (200, Some("/app/"), true));
}

#[tokio::test]
async fn a_new_harness_drops_the_old_model_and_effort() {
    let (port, _, admin, _) = serve_app().await;
    let (code, b) = call(port, "POST", "/api/bots", &admin, &json!({ "name": "Ada", "harness": "claude" }).to_string()).await;
    assert_eq!(code, 201, "{b}");
    let id = parse(&b)["id"].as_str().unwrap().to_string();
    let patch = |body: Value| {
        let (admin, id) = (admin.clone(), id.clone());
        async move {
            let (code, b) = call(port, "PATCH", &format!("/api/bots/{id}"), &admin, &body.to_string()).await;
            assert_eq!(code, 200, "{b}");
            parse(&b)
        }
    };
    let b = patch(json!({ "model": "opus", "effort": "high" })).await;
    assert_eq!((b["model"].as_str(), b["effort"].as_str()), (Some("opus"), Some("high")));
    let b = patch(json!({ "harness": "codex" })).await;
    assert_eq!((b["harness"].as_str(), b["model"].as_str(), b["effort"].as_str()), (Some("codex"), None, None));
    // A model sent with the new harness is kept.
    let b = patch(json!({ "harness": "claude", "model": "sonnet" })).await;
    assert_eq!((b["harness"].as_str(), b["model"].as_str()), (Some("claude"), Some("sonnet")));
    // The same harness again changes nothing.
    assert_eq!(patch(json!({ "harness": "claude" })).await["model"].as_str(), Some("sonnet"));
}

#[tokio::test]
async fn sso_web_sign_ins_land_by_role() {
    let idp = mock_idp().await;
    let (port, app, admin, id) = serve_with(&idp, &[], |_| {}).await;
    let u = app.db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
    let (code, _) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": OID }).to_string()).await;
    assert_eq!(code, 201);

    let sign_in = || async {
        let (path, binder) = to_callback(port, &format!("/api/auth/sso/{id}/start")).await;
        let (code, head, body) = call_with(port, "GET", &path, "", &binder, "").await;
        assert_eq!(code, 200, "{head}");
        assert!(set_cookies(&head).iter().any(|c| c.starts_with("__Host-superbot_session=sbs_")));
        body
    };
    let body = sign_in().await;
    assert!(body.contains("url=/app/") && body.contains(r#"href="/app/""#), "{body}");

    call(port, "PATCH", &format!("/api/users/{}", u.id), &admin, &json!({ "role": "admin" }).to_string()).await;
    let body = sign_in().await;
    assert!(body.contains("url=/console/") && body.contains(r#"href="/console/""#), "{body}");
}
