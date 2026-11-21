//! HTTP tests for the public site and sign-ups (ADR 0022), on the real router.

use crate::sso_http_tests::header;
use crate::tests::{audit_list, call, call_with, serve_app, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

fn form(email: &str) -> Value {
    json!({
        "name": "Ada Lovelace", "email": email, "company": "Analytical Engines", "teamSize": "11-50",
        "useCase": "Daily research briefs", "signIn": "microsoft", "consent": true, "website": "",
    })
}

/// POST /api/signups from client IP `ip` (botd trusts X-Forwarded-For from a loopback proxy).
async fn submit(port: u16, ip: &str, body: &str) -> (u16, String, Value) {
    let (code, head, body) = call_with(
        port,
        "POST",
        "/api/signups",
        "",
        &format!("X-Forwarded-For: {ip}\r\n"),
        body,
    )
    .await;
    (code, head, parse(&body))
}

async fn signups(port: u16, admin: &str, status: &str) -> Vec<Value> {
    let (code, body) = call(
        port,
        "GET",
        &format!("/api/signups?status={status}"),
        admin,
        "",
    )
    .await;
    assert_eq!(code, 200, "{body}");
    parse(&body).as_array().cloned().unwrap()
}

#[tokio::test]
async fn the_site_is_public_and_the_console_moved_to_its_own_path() {
    let (port, _, admin, _) = serve_app().await;
    for (path, kind, has) in [
        ("/", "text/html", "Your always-on AI team"),
        ("/index.html", "text/html", "Your always-on AI team"),
        ("/get-started", "text/html", "Request access"),
        ("/site/site.css", "text/css", "--blue: #2f72e4"),
        ("/site/get-started.js", "text/javascript", "/api/signups"),
        ("/site/mark.svg", "image/svg+xml", "<svg"),
    ] {
        let (code, head, body) = call_with(port, "GET", path, "", "", "").await;
        assert_eq!(code, 200, "{path}");
        assert!(
            header(&head, "content-type").unwrap().starts_with(kind),
            "{path}: {head}"
        );
        assert!(
            header(&head, "content-security-policy")
                .unwrap()
                .contains("frame-ancestors 'none'"),
            "{path}"
        );
        assert!(body.contains(has), "{path}");
    }
    assert_eq!(call(port, "HEAD", "/", "", "").await.0, 200);
    let (_, _, page) = call_with(port, "GET", "/", "", "", "").await;
    assert!(
        !page.contains("<script"),
        "the landing page runs no scripts"
    );

    // The built-in console needs sign-in, as / did before.
    let (code, head, _) = call_with(port, "GET", "/console/", "", "", "").await;
    assert_eq!(
        (code, header(&head, "location").as_deref()),
        (303, Some("/login"))
    );
    let (code, head, _) = call_with(port, "GET", "/console", &admin, "", "").await;
    assert_eq!(
        (code, header(&head, "location").as_deref()),
        (308, Some("/console/"))
    );
    for (path, has) in [
        ("/console/", "app.js"),
        ("/console/app.js", "/api/signups"),
        ("/console/styles.css", "{"),
    ] {
        let (code, body) = call(port, "GET", path, &admin, "").await;
        assert!(code == 200 && body.contains(has), "{path}: {code}");
    }
    // Without Caddy's web client, the landing page's "Sign in" still lands somewhere.
    let (code, head, _) = call_with(port, "GET", "/app/", &admin, "", "").await;
    assert_eq!(
        (code, header(&head, "location").as_deref()),
        (303, Some("/console/"))
    );
    // Only the form's own endpoints are open.
    assert_eq!(call(port, "GET", "/api/state", "", "").await.0, 401);
    assert_eq!(call(port, "GET", "/api/signups", "", "").await.0, 401);
    assert_eq!(call(port, "GET", "/site/nope.js", "", "").await.0, 303);
    let (code, body) = call(port, "GET", "/api/signups/config", "", "").await;
    let cfg = parse(&body);
    assert_eq!(
        (
            code,
            cfg["enabled"].as_bool(),
            cfg["turnstileSiteKey"].is_null()
        ),
        (200, Some(true), true)
    );
}

#[tokio::test]
async fn submissions_are_validated_sized_and_rate_limited() {
    let (port, app, admin, _) = serve_app().await;
    let (code, head, res) =
        submit(port, "198.51.100.1", &form("ada@example.com").to_string()).await;
    assert_eq!((code, res["ok"].as_bool()), (202, Some(true)), "{res}");
    assert_eq!(header(&head, "cache-control").as_deref(), Some("no-store"));
    let list = signups(port, &admin, "pending").await;
    assert_eq!(list.len(), 1);
    let s = &list[0];
    assert_eq!(
        (
            s["email"].as_str(),
            s["teamSize"].as_str(),
            s["signIn"].as_str(),
            s["ip"].as_str()
        ),
        (
            Some("ada@example.com"),
            Some("11-50"),
            Some("microsoft"),
            Some("198.51.100.1")
        )
    );

    for (k, v, field) in [
        ("email", json!("nope"), "email"),
        ("consent", json!(false), "consent"),
        ("teamSize", json!("lots"), "teamSize"),
        ("role", json!("admin"), "role"),
    ] {
        let mut f = form("bob@example.com");
        f[k] = v;
        let (code, _, res) = submit(port, "198.51.100.1", &f.to_string()).await;
        assert_eq!(
            (code, res["field"].as_str()),
            (400, Some(field)),
            "{k}: {res}"
        );
    }
    // Five a window from one IP, valid or not; other IPs are counted on their own.
    let (code, head, res) =
        submit(port, "198.51.100.1", &form("carol@example.com").to_string()).await;
    assert_eq!(code, 429, "{res}");
    assert!(header(&head, "retry-after").is_some_and(|s| s.parse::<i64>().unwrap() > 0));
    assert_eq!(
        submit(port, "198.51.100.2", &form("carol@example.com").to_string())
            .await
            .0,
        202
    );
    assert_eq!(submit(port, "198.51.100.2", "not json").await.0, 400);

    // Bigger than any real form: refused before it's read.
    let mut big = form("dave@example.com");
    big["useCase"] = json!("x".repeat(signups::MAX_BODY));
    assert_eq!(submit(port, "198.51.100.3", &big.to_string()).await.0, 413);

    // A second request for an email that's waiting looks the same, but isn't saved twice.
    let mut again = form("ADA@example.com");
    again["company"] = json!("Someone else");
    assert_eq!(
        submit(port, "198.51.100.4", &again.to_string()).await.0,
        202
    );
    assert_eq!(app.db.pending_signups(), 2);

    let (_, body) = call(port, "GET", "/api/audit?action=signup.*", &admin, "").await;
    let ev = audit_list(&body);
    assert_eq!(
        ev.iter()
            .filter(|e| e["action"] == "signup.submitted")
            .count(),
        2
    );
    let e = ev
        .iter()
        .find(|e| e["action"] == "signup.submitted" && e["actorEmail"] == "ada@example.com")
        .unwrap();
    assert_eq!(
        (
            e["targetType"].as_str(),
            e["details"]["company"].as_str(),
            e["ip"].as_str()
        ),
        (
            Some("signup"),
            Some("Analytical Engines"),
            Some("198.51.100.1")
        ),
        "{e}"
    );
    assert!(
        !body.contains("Daily research briefs"),
        "free text stays out of the audit log"
    );
}

#[tokio::test]
async fn the_honeypot_answers_like_a_success_and_saves_nothing() {
    let (port, app, admin, _) = serve_app().await;
    let mut f = form("bot@example.com");
    f["website"] = json!("https://spam.example");
    let (code, _, res) = submit(port, "203.0.113.9", &f.to_string()).await;
    assert_eq!((code, res["ok"].as_bool()), (202, Some(true)));
    assert_eq!(app.db.pending_signups(), 0);
    let (_, body) = call(port, "GET", "/api/audit?action=signup.*", &admin, "").await;
    let ev = audit_list(&body);
    assert_eq!(ev.len(), 1, "{body}");
    assert_eq!(
        (
            ev[0]["action"].as_str(),
            ev[0]["outcome"].as_str(),
            ev[0]["details"]["reason"].as_str()
        ),
        (Some("signup.refused"), Some("denied"), Some("honeypot"))
    );
}

#[tokio::test]
async fn only_admins_see_and_decide_signups() {
    let (port, app, admin, key) = serve_app().await;
    let bot = key.auth(
        &app.db
            .create_bot("Ops", "#fff", "waddle", "claude", None, false)
            .id,
    );
    assert_eq!(
        submit(port, "192.0.2.1", &form("ada@example.com").to_string())
            .await
            .0,
        202
    );
    let id = signups(port, &admin, "all").await[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (_, readonly) = user_with(port, &admin, "r@example.com", "readonly").await;
    for who in ["", member.as_str(), readonly.as_str(), bot.as_str()] {
        let want = if who.is_empty() { 401 } else { 403 };
        assert_eq!(
            call(port, "GET", "/api/signups", who, "").await.0,
            want,
            "{who}"
        );
        assert_eq!(
            call(port, "GET", &format!("/api/signups/{id}"), who, "")
                .await
                .0,
            want
        );
        assert_eq!(
            call(port, "POST", &format!("/api/signups/{id}/approve"), who, "")
                .await
                .0,
            want
        );
        assert_eq!(
            call(port, "POST", &format!("/api/signups/{id}/reject"), who, "")
                .await
                .0,
            want
        );
    }
    assert_eq!(
        signups(port, &admin, "pending").await.len(),
        1,
        "still waiting"
    );
    assert_eq!(
        call(port, "GET", "/api/signups?status=maybe", &admin, "")
            .await
            .0,
        400
    );
}

#[tokio::test]
async fn approval_makes_the_user_and_a_one_time_code() {
    let (port, app, admin, _) = serve_app().await;
    assert_eq!(
        submit(port, "192.0.2.1", &form("ada@example.com").to_string())
            .await
            .0,
        202
    );
    let id = signups(port, &admin, "pending").await[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let approve = format!("/api/signups/{id}/approve");
    assert_eq!(
        call(port, "POST", &approve, &admin, r#"{"role":"owner"}"#)
            .await
            .0,
        400
    );
    assert_eq!(
        call(port, "POST", "/api/signups/su0/approve", &admin, "")
            .await
            .0,
        404
    );

    let (code, head, body) =
        call_with(port, "POST", &approve, &admin, "", r#"{"role":"readonly"}"#).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(header(&head, "cache-control").as_deref(), Some("no-store"));
    let res = parse(&body);
    let code_ = res["code"].as_str().unwrap();
    assert!(code_.starts_with("sbc_"));
    assert_eq!(
        (
            res["user"]["email"].as_str(),
            res["user"]["name"].as_str(),
            res["user"]["role"].as_str()
        ),
        (
            Some("ada@example.com"),
            Some("Ada Lovelace"),
            Some("readonly")
        )
    );
    assert_eq!(
        (
            res["signup"]["status"].as_str(),
            res["signup"]["role"].as_str(),
            res["emailed"].as_bool()
        ),
        (Some("approved"), Some("readonly"), Some(false))
    );
    let three_days = 3 * 24 * 60 * 60_000;
    assert!((res["expiresAt"].as_i64().unwrap() - db::now() - three_days).abs() < 60_000);
    let user_id = res["user"]["id"].as_str().unwrap();
    assert_eq!(res["signup"]["userId"].as_str(), Some(user_id));

    // The code signs the new user in, once.
    let (code, login) = call(
        port,
        "POST",
        "/api/auth/login",
        "",
        &json!({ "code": code_ }).to_string(),
    )
    .await;
    assert_eq!(
        (code, parse(&login)["user"]["role"].as_str()),
        (200, Some("readonly")),
        "{login}"
    );
    assert_eq!(
        call(
            port,
            "POST",
            "/api/auth/login",
            "",
            &json!({ "code": code_ }).to_string()
        )
        .await
        .0,
        401
    );
    assert!(app.db.signup(&id).unwrap().user_id.is_some());

    // Decided requests stay decided.
    assert_eq!(call(port, "POST", &approve, &admin, "").await.0, 409);
    assert_eq!(
        call(
            port,
            "POST",
            &format!("/api/signups/{id}/reject"),
            &admin,
            ""
        )
        .await
        .0,
        409
    );

    let (_, body) = call(port, "GET", "/api/audit?limit=50", &admin, "").await;
    assert!(!body.contains(code_), "the code is never logged");
    let actions: Vec<String> = audit_list(&body)
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_string())
        .collect();
    for a in [
        "signup.submitted",
        "user.created",
        "user.login_code_created",
        "signup.approved",
        "auth.login",
    ] {
        assert!(actions.contains(&a.to_string()), "{a}: {actions:?}");
    }
    let ev = audit_list(&body);
    let created = ev
        .iter()
        .find(|e| e["action"] == "user.created" && e["targetId"] == user_id)
        .unwrap();
    assert_eq!(
        created["details"]["reason"].as_str(),
        Some(format!("sign-up {id}").as_str())
    );
}

/// The admin portal (ADR 0021) sees an approved request's user like any other, and its
/// "new code" replaces the approval's code.
#[tokio::test]
async fn approved_users_show_in_the_portal_and_their_code_can_be_replaced() {
    let (port, _, admin, _) = serve_app().await;
    assert_eq!(
        submit(port, "192.0.2.1", &form("ada@example.com").to_string())
            .await
            .0,
        202
    );
    let id = signups(port, &admin, "pending").await[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, body) = call(
        port,
        "POST",
        &format!("/api/signups/{id}/approve"),
        &admin,
        "",
    )
    .await;
    let res = parse(&body);
    let (first, user_id) = (
        res["code"].as_str().unwrap().to_string(),
        res["user"]["id"].as_str().unwrap().to_string(),
    );

    let (_, body) = call(port, "GET", "/api/users", &admin, "").await;
    let listed = parse(&body)
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == user_id.as_str())
        .cloned()
        .unwrap();
    assert_eq!(
        (
            listed["role"].as_str(),
            listed["pendingCodes"]["count"].as_i64(),
            listed["lastLogin"].is_null()
        ),
        (Some("member"), Some(1), true),
        "{listed}"
    );

    let (code, body) = call(
        port,
        "POST",
        &format!("/api/users/{user_id}/login-codes"),
        &admin,
        r#"{"ttlMinutes":60,"replace":true}"#,
    )
    .await;
    assert_eq!(code, 200, "{body}");
    let second = parse(&body)["code"].as_str().unwrap().to_string();
    assert_eq!(
        call(
            port,
            "POST",
            "/api/auth/login",
            "",
            &json!({ "code": first }).to_string()
        )
        .await
        .0,
        401,
        "the approval's code stopped working"
    );
    assert_eq!(
        call(
            port,
            "POST",
            "/api/auth/login",
            "",
            &json!({ "code": second }).to_string()
        )
        .await
        .0,
        200
    );
    let (_, body) = call(
        port,
        "GET",
        "/api/audit?action=user.login_code_created",
        &admin,
        "",
    )
    .await;
    let details: Vec<Value> = audit_list(&body)
        .iter()
        .map(|e| e["details"].clone())
        .collect();
    assert_eq!(
        details,
        [
            json!({ "ttlMinutes": 60, "replaced": 1 }),
            json!({ "ttlMinutes": 3 * 24 * 60 })
        ]
    );
}

#[tokio::test]
async fn rejection_and_existing_users() {
    let (port, app, admin, _) = serve_app().await;
    user_with(port, &admin, "taken@example.com", "member").await;
    for (ip, email) in [
        ("192.0.2.1", "taken@example.com"),
        ("192.0.2.2", "eve@example.com"),
    ] {
        assert_eq!(submit(port, ip, &form(email).to_string()).await.0, 202);
    }
    let list = signups(port, &admin, "pending").await;
    let taken = list
        .iter()
        .find(|s| s["email"] == "taken@example.com")
        .unwrap();
    assert_eq!(taken["existingUser"].as_bool(), Some(true));
    let (code, body) = call(
        port,
        "POST",
        &format!("/api/signups/{}/approve", taken["id"].as_str().unwrap()),
        &admin,
        "",
    )
    .await;
    assert_eq!(code, 409, "{body}");
    assert_eq!(app.db.users().len(), 2, "no user was made");
    assert_eq!(
        signups(port, &admin, "pending").await.len(),
        2,
        "and the request still waits"
    );

    let eve = list
        .iter()
        .find(|s| s["email"] == "eve@example.com")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let reject = format!("/api/signups/{eve}/reject");
    assert_eq!(
        call(
            port,
            "POST",
            &reject,
            &admin,
            &json!({ "reason": "x".repeat(501) }).to_string()
        )
        .await
        .0,
        400
    );
    let (code, body) = call(
        port,
        "POST",
        &reject,
        &admin,
        r#"{"reason":"Not a fit yet"}"#,
    )
    .await;
    let s = parse(&body);
    assert_eq!(
        (code, s["status"].as_str(), s["reason"].as_str()),
        (200, Some("rejected"), Some("Not a fit yet")),
        "{body}"
    );
    assert_eq!(signups(port, &admin, "rejected").await.len(), 1);
    // A rejected email may ask again later.
    assert_eq!(
        submit(port, "192.0.2.3", &form("eve@example.com").to_string())
            .await
            .0,
        202
    );
    assert_eq!(app.db.pending_signups(), 2);
    let (_, body) = call(port, "GET", "/api/audit?action=signup.rejected", &admin, "").await;
    assert_eq!(
        audit_list(&body)[0]["details"]["reason"].as_str(),
        Some("Not a fit yet")
    );
}

/// Stands in for Cloudflare: only the token "good", sent with the right secret, passes.
async fn fake_turnstile() -> String {
    use axum::extract::Form;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let r = Router::new().route(
        "/verify",
        post(|Form(f): Form<HashMap<String, String>>| async move {
            let ok = f.get("secret").map(String::as_str) == Some("ts-secret")
                && f.get("response").map(String::as_str) == Some("good");
            Json(json!({ "success": ok }))
        }),
    );
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    format!("http://127.0.0.1:{port}/verify")
}

#[tokio::test]
async fn turnstile_is_checked_when_configured() {
    let verify_url = fake_turnstile().await;
    let (port, app, _, _) = serve_app_with(|a| {
        a.signups.turnstile = Some(signups::Turnstile {
            secret: "ts-secret".into(),
            site_key: "0x4AAA".into(),
            verify_url,
        });
    })
    .await;
    let (_, body) = call(port, "GET", "/api/signups/config", "", "").await;
    assert_eq!(parse(&body)["turnstileSiteKey"].as_str(), Some("0x4AAA"));
    for (ip, token) in [("192.0.2.1", None), ("192.0.2.2", Some("bad"))] {
        let mut f = form("ada@example.com");
        if let Some(t) = token {
            f["turnstileToken"] = json!(t);
        }
        let (code, _, res) = submit(port, ip, &f.to_string()).await;
        assert_eq!(
            (code, res["field"].as_str()),
            (400, Some("turnstileToken")),
            "{token:?}"
        );
    }
    assert_eq!(app.db.pending_signups(), 0);
    let mut f = form("ada@example.com");
    f["turnstileToken"] = json!("good");
    assert_eq!(submit(port, "192.0.2.3", &f.to_string()).await.0, 202);
    assert_eq!(app.db.pending_signups(), 1);
}

#[tokio::test]
async fn signups_can_be_closed() {
    let (port, app, _, _) = serve_app_with(|a| a.signups.enabled = false).await;
    let (_, body) = call(port, "GET", "/api/signups/config", "", "").await;
    assert_eq!(parse(&body)["enabled"].as_bool(), Some(false));
    assert_eq!(
        submit(port, "192.0.2.1", &form("ada@example.com").to_string())
            .await
            .0,
        404
    );
    assert_eq!(app.db.pending_signups(), 0);
    assert_eq!(
        call(port, "GET", "/", "", "").await.0,
        200,
        "the landing page stays up"
    );
}

#[test]
fn caddy_serves_the_site_with_botds_headers() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for file in ["deploy/install.sh", "deploy/docker/Caddyfile"] {
        let text = std::fs::read_to_string(root.join(file)).unwrap();
        assert!(
            text.contains(&format!(
                "header Content-Security-Policy \"{}\"",
                crate::SITE_CSP
            )),
            "{file} has a different CSP than SITE_CSP"
        );
    }
}
