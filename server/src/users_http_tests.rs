//! HTTP tests for sign-in, sessions, and roles (ADR 0012), on the real router.

use crate::tests::{audit_list, basic, call, call_with, serve_app_with};
use crate::users::{self, SessionConfig};
use crate::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static PW: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| random_hex(16));

fn parse(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or(Value::Null)
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()))
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

async fn serve(tweak: impl FnOnce(&mut Auth)) -> (u16, AppState, String, String) {
    serve_app_with(|a| {
        a.password = PW.clone();
        tweak(a);
    })
    .await
}

/// POST /api/auth/login. Returns the status, response head, and body.
async fn login(port: u16, extra: &str, body: Value) -> (u16, String, Value) {
    let (code, head, body) = call_with(port, "POST", "/api/auth/login", "", extra, &body.to_string()).await;
    (code, head, parse(&body))
}

async fn token_for(port: u16, body: Value) -> String {
    let (code, _, res) = login(port, "", body).await;
    assert_eq!(code, 200, "{res}");
    res["token"].as_str().unwrap().to_string()
}

/// A new user with `role`, signed in with a one-time code. Returns its id and Authorization.
async fn user_with(port: u16, admin: &str, email: &str, role: &str) -> (String, String) {
    let (code, u) = call(port, "POST", "/api/users", admin, &json!({ "email": email, "role": role }).to_string()).await;
    assert_eq!(code, 201, "{u}");
    let id = parse(&u)["id"].as_str().unwrap().to_string();
    let (code, c) = call(port, "POST", &format!("/api/users/{id}/login-codes"), admin, "").await;
    assert_eq!(code, 200, "{c}");
    let token = token_for(port, json!({ "code": parse(&c)["code"] })).await;
    (id, bearer(&token))
}

fn origin(port: u16) -> String {
    format!("Origin: http://127.0.0.1:{port}\r\n")
}

fn cookie(token: &str) -> String {
    format!("Cookie: superbot_session={token}\r\n")
}

#[tokio::test]
async fn password_login_makes_token_and_cookie_sessions() {
    let (port, app, admin, _) = serve(|_| {}).await;

    let (code, head, res) = login(port, "", json!({ "password": PW.as_str(), "label": "Phone" })).await;
    assert_eq!(code, 200, "{res}");
    let token = res["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("sbs_") && token.len() == 68);
    assert_eq!(header(&head, "cache-control").as_deref(), Some("no-store"));
    assert!(header(&head, "set-cookie").is_none(), "token sessions set no cookie");
    assert_eq!((res["user"]["id"].as_str(), res["session"]["kind"].as_str()), (Some("operator"), Some("token")));

    let (code, me) = call(port, "GET", "/api/auth/me", &bearer(&token), "").await;
    assert_eq!(code, 200);
    let me = parse(&me);
    assert_eq!((me["role"].as_str(), me["method"].as_str(), me["session"]["label"].as_str()), (Some("admin"), Some("session"), Some("Phone")));
    assert_eq!(me["permissions"], json!(["account", "read", "review", "write", "approve", "admin"]));

    // Cookie sessions, for the web app.
    let (code, head, res) = login(port, &origin(port), json!({ "password": PW.as_str(), "session": "cookie" })).await;
    assert_eq!(code, 200, "{res}");
    assert!(res["token"].is_null(), "the cookie token is never readable by scripts");
    let set = header(&head, "set-cookie").unwrap();
    for attr in ["superbot_session=sbs_", "HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(set.contains(attr), "{set}");
    }
    let ctoken = set.split(';').next().unwrap().trim_start_matches("superbot_session=").to_string();
    let (code, _, state) = call_with(port, "GET", "/api/state", "", &cookie(&ctoken), "").await;
    assert_eq!((code, parse(&state)["me"]["role"].as_str()), (200, Some("admin")));
    // The web app's writes carry its Origin.
    let ok = format!("{}{}", cookie(&ctoken), origin(port));
    assert_eq!(call_with(port, "POST", "/api/bots", "", &ok, r#"{"name":"Web"}"#).await.0, 201);

    // Another site can't sign the browser in.
    let evil = "Origin: https://evil.example\r\n";
    assert_eq!(login(port, evil, json!({ "password": PW.as_str(), "session": "cookie" })).await.0, 403);

    // Wrong password, and the log never holds a secret.
    let (code, _, res) = login(port, "", json!({ "password": "nope" })).await;
    assert_eq!((code, res["error"].as_str()), (401, Some("Wrong password.")));
    assert_eq!(login(port, "", json!({})).await.0, 400);
    assert_eq!(login(port, "", json!({ "password": PW.as_str(), "session": "jwt" })).await.0, 400);

    let (_, body) = call(port, "GET", "/api/audit?action=auth.*&limit=1000", &admin, "").await;
    let ev = audit_list(&body);
    let logins: Vec<_> = ev.iter().filter(|e| e["action"] == "auth.login" && e["details"]["method"] == "password").collect();
    assert!(logins.iter().any(|e| e["details"]["kind"] == "cookie") && logins.iter().any(|e| e["details"]["kind"] == "token"));
    assert!(ev.iter().any(|e| e["action"] == "auth.login_failed"));
    for (i, secret) in [PW.as_str(), token.as_str(), ctoken.as_str(), &users::hash(&token)].into_iter().enumerate() {
        assert!(!body.contains(secret), "audit leaks secret #{i}");
    }
    assert!(app.db.live_session(&token, db::now(), 60_000, 60_000).is_none(), "the raw token is not stored");
}

#[tokio::test]
async fn session_labels_never_hold_a_secret() {
    let (port, app, admin, _) = serve(|_| {}).await;
    crate::secrets::redact::register(PW.as_str());
    let label = format!("laptop {} password=hunter2", PW.as_str());
    let token = token_for(port, json!({ "password": PW.as_str(), "label": label })).await;
    let (_, me) = call(port, "GET", "/api/auth/me", &bearer(&token), "").await;
    let (_, sessions) = call(port, "GET", "/api/sessions", &admin, "").await;
    let (s, _) = app.db.live_session(&users::hash(&token), db::now(), 60_000, 60_000).unwrap();
    let stored = s.label.unwrap_or_default();
    for (what, s) in [("me", me.as_str()), ("sessions", sessions.as_str()), ("sqlite", stored.as_str())] {
        assert!(s.contains("laptop") && !s.contains(PW.as_str()) && !s.contains("hunter2"), "{what}: {s}");
    }
}

#[tokio::test]
async fn cookie_writes_from_other_sites_are_refused() {
    let (port, app, admin, _) = serve(|_| {}).await;
    let (_, head, _) = login(port, &origin(port), json!({ "password": PW.as_str(), "session": "cookie" })).await;
    let set = header(&head, "set-cookie").unwrap();
    let ctoken = set.split(';').next().unwrap().trim_start_matches("superbot_session=").to_string();
    let screen = format!("/api/bots/{}/screen", app.db.create_bot("Shared", "#fff", "waddle", "claude", None, false).id);
    for bad in ["Origin: https://evil.example\r\n", "Origin: null\r\n", "Sec-Fetch-Site: cross-site\r\n", "Sec-Fetch-Site: same-site\r\n"] {
        let extra = format!("{}{bad}", cookie(&ctoken));
        let (code, _, body) = call_with(port, "POST", "/api/bots", "", &extra, r#"{"name":"CSRF"}"#).await;
        assert_eq!(code, 403, "{bad}: {body}");
        // Opening a screen starts it, so that GET counts as a write.
        assert_eq!(call_with(port, "GET", &screen, "", &extra, "").await.0, 403, "{bad}");
        // Reads stay fine: they change nothing, and the response can't be read cross-site.
        assert_eq!(call_with(port, "GET", "/api/state", "", &extra, "").await.0, 200);
    }
    assert_ne!(call_with(port, "GET", &screen, "", &format!("{}Sec-Fetch-Site: same-origin\r\n", cookie(&ctoken)), "").await.0, 403);
    assert!(app.db.bots().iter().all(|b| b.name != "CSRF"));
    let (_, body) = call(port, "GET", "/api/audit?action=access.denied", &admin, "").await;
    assert_eq!(audit_list(&body).iter().filter(|e| e["details"]["reason"] == "cross_site").count(), 8);
}

#[tokio::test]
async fn each_role_gets_exactly_its_permissions() {
    let (port, app, admin, bot) = serve(|_| {}).await;
    let (member_id, member) = user_with(port, &admin, "member@example.com", "member").await;
    let (_, readonly) = user_with(port, &admin, "viewer@example.com", "read-only").await;
    let b = app.db.create_bot("Shared", "#fff", "waddle", "claude", None, false);
    let bid = b.id.as_str();

    let routes: Vec<(&str, String, &str)> = vec![
        ("GET", "/api/state".into(), ""),
        ("GET", "/api/bots".into(), ""),
        ("GET", format!("/api/bots/{bid}/messages"), ""),
        ("GET", "/api/approvals".into(), ""),
        ("GET", "/api/policy".into(), ""),
        ("GET", "/api/auth/me".into(), ""),
        ("POST", "/api/bots".into(), r#"{"name":"New"}"#),
        ("PATCH", format!("/api/bots/{bid}"), r#"{"name":"Renamed"}"#),
        ("POST", format!("/api/bots/{bid}/read"), ""),
        ("GET", format!("/api/bots/{bid}/screen"), ""),
        ("POST", format!("/api/bots/{bid}/routines"), r#"{"name":"R","cron":"0 9 * * *","instruction":"x"}"#),
        ("POST", "/api/approvals/missing/approve".into(), "{}"),
        ("POST", "/api/approvals/missing/approve".into(), r#"{"remember":"bot"}"#),
        ("POST", "/api/approvals/missing/deny".into(), r#"{"remember":"global"}"#),
        ("PUT", "/api/policy".into(), r#"{"mode":"ask"}"#),
        ("PUT", format!("/api/bots/{bid}/policy"), r#"{"mode":"ask"}"#),
        ("POST", "/api/policy/rules".into(), "{}"),
        ("GET", "/api/audit".into(), ""),
        ("GET", "/api/audit/export.csv".into(), ""),
        ("GET", "/api/users".into(), ""),
        ("POST", "/api/users".into(), r#"{"email":"x@example.com"}"#),
        ("PATCH", format!("/api/users/{member_id}"), r#"{"role":"admin"}"#),
        ("POST", format!("/api/users/{member_id}/login-codes"), ""),
        ("GET", "/api/sessions".into(), ""),
        ("DELETE", "/api/sessions/missing".into(), ""),
        ("DELETE", format!("/api/users/{member_id}/sessions"), ""),
        ("GET", "/api/secrets".into(), ""),
        ("PUT", "/api/secrets/RBAC_CHECK_KEY".into(), r#"{"value":"v"}"#),
        ("DELETE", "/api/secrets/RBAC_CHECK_KEY".into(), ""),
    ];
    // Allowed or not, per role, in route order.
    let r = [true, true, true, true, true, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false];
    let m = [true, true, true, true, true, true, true, true, true, true, true, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false];
    let k = [true, true, true, false, true, true, true, true, true, true, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false];
    for (who, auth, allowed) in [("readonly", &readonly, r), ("member", &member, m), ("bot", &bot, k)] {
        for ((method, path, body), ok) in routes.iter().zip(allowed) {
            let (code, res) = call(port, method, path, auth, body).await;
            assert_eq!(code == 403, !ok, "{who} {method} {path}: {code} {res}");
            assert_ne!(code, 401, "{who} {method} {path}");
        }
    }
    // The member's role change landed last; the admin can do everything.
    for (method, path, body) in &routes {
        let (code, res) = call(port, method, path, &admin, body).await;
        assert!(code != 403 && code != 401, "admin {method} {path}: {code} {res}");
    }

    let (_, state) = call(port, "GET", "/api/state", &readonly, "").await;
    assert_eq!(parse(&state)["me"]["role"], "readonly");
    let (_, body) = call(port, "GET", "/api/audit?action=access.denied&limit=1000", &admin, "").await;
    let denied = audit_list(&body);
    assert!(denied.iter().any(|e| e["actorName"] == "viewer" && e["details"]["need"] == "write" && e["details"]["path"] == "/api/bots"));
    assert!(denied.iter().any(|e| e["actorKind"] == "bot" && e["details"]["need"] == "admin"));
    assert!(denied.iter().any(|e| e["actorName"] == "member" && e["details"]["reason"] == "remember"));
}

#[tokio::test]
async fn role_changes_apply_to_live_sessions_and_the_owner_stays_admin() {
    let (port, _, admin, _) = serve(|_| {}).await;
    let (id, member) = user_with(port, &admin, "m@example.com", "member").await;
    assert_eq!(call(port, "POST", "/api/bots", &member, r#"{"name":"A"}"#).await.0, 201);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{id}"), &admin, r#"{"role":"readonly"}"#).await.0, 200);
    assert_eq!(call(port, "POST", "/api/bots", &member, r#"{"name":"B"}"#).await.0, 403, "demotion is immediate");
    assert_eq!(call(port, "PATCH", "/api/users/M@Example.com", &admin, r#"{"role":"admin"}"#).await.0, 200, "by email, any case");
    assert_eq!(call(port, "GET", "/api/users", &member, "").await.0, 200, "promotion too");

    assert_eq!(call(port, "PATCH", "/api/users/operator", &admin, r#"{"role":"member"}"#).await.0, 409);
    assert_eq!(call(port, "PATCH", "/api/users/operator", &admin, r#"{"status":"disabled"}"#).await.0, 409);
    assert_eq!(call(port, "PATCH", "/api/users/operator", &member, r#"{"name":"Boss"}"#).await.0, 200, "other admins can rename it");
    assert_eq!(call(port, "POST", "/api/users", &admin, r#"{"email":"m@EXAMPLE.com"}"#).await.0, 409);
    assert_eq!(call(port, "POST", "/api/users", &admin, r#"{"email":"not-an-email"}"#).await.0, 400);
    assert_eq!(call(port, "POST", "/api/users", &admin, r#"{"email":"r@example.com","role":"root"}"#).await.0, 400);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{id}"), &admin, r#"{"status":"gone"}"#).await.0, 400);
    assert_eq!(call(port, "PATCH", "/api/users/nobody", &admin, r#"{"name":"x"}"#).await.0, 404);

    let (_, body) = call(port, "GET", "/api/audit?action=user.*&limit=100", &admin, "").await;
    let actions: Vec<String> = audit_list(&body).iter().rev().map(|e| e["action"].as_str().unwrap().to_string()).collect();
    assert_eq!(
        actions,
        ["user.created", "user.created", "user.login_code_created", "user.role_changed", "user.role_changed", "user.updated"],
        "owner, the member and its code, two role changes, and the owner's rename"
    );
}

#[tokio::test]
async fn sessions_end_on_logout_revoke_and_disable() {
    let (port, _, admin, _) = serve(|_| {}).await;
    let (id, member) = user_with(port, &admin, "m@example.com", "member").await;

    // Logout ends only this session.
    let t = bearer(&token_for(port, json!({ "password": PW.as_str() })).await);
    let (code, head, _) = call_with(port, "POST", "/api/auth/logout", &t, "", "").await;
    assert_eq!(code, 200);
    assert!(header(&head, "set-cookie").unwrap().contains("Max-Age=0"));
    assert_eq!(call(port, "GET", "/api/state", &t, "").await.0, 401);
    assert_eq!(call(port, "GET", "/api/state", &member, "").await.0, 200);

    // An admin lists and revokes one session.
    let (code, list) = call(port, "GET", &format!("/api/sessions?user={id}"), &admin, "").await;
    assert_eq!(code, 200);
    let list = parse(&list);
    assert_eq!(list.as_array().unwrap().len(), 1);
    let sid = list[0]["id"].as_str().unwrap();
    assert!(list[0].get("tokenHash").is_none() && !list.to_string().contains(member.trim_start_matches("Bearer ")));
    assert_eq!(call(port, "DELETE", &format!("/api/sessions/{sid}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("/api/sessions/{sid}"), &admin, "").await.0, 404, "once");
    assert_eq!(call(port, "GET", "/api/state", &member, "").await.0, 401);

    // Or all of a user's sessions, and unused codes with them.
    let (_, c) = call(port, "POST", &format!("/api/users/{id}/login-codes"), &admin, r#"{"ttlMinutes":5}"#).await;
    let spare = parse(&c)["code"].as_str().unwrap().to_string();
    let a = bearer(&token_for(port, json!({ "code": parse(&call(port, "POST", &format!("/api/users/{id}/login-codes"), &admin, "").await.1)["code"] })).await);
    let b = bearer(&token_for(port, json!({ "code": parse(&call(port, "POST", &format!("/api/users/{id}/login-codes"), &admin, "").await.1)["code"] })).await);
    let (code, n) = call(port, "DELETE", &format!("/api/users/{id}/sessions"), &admin, "").await;
    assert_eq!((code, parse(&n)["revoked"].as_u64()), (200, Some(2)));
    for t in [&a, &b] {
        assert_eq!(call(port, "GET", "/api/state", t, "").await.0, 401);
    }
    assert_eq!(login(port, "", json!({ "code": spare })).await.0, 401, "revoke-all drops unused codes");

    // Disabling a user ends their sessions and blocks new sign-ins.
    let c = bearer(&token_for(port, json!({ "code": parse(&call(port, "POST", &format!("/api/users/{id}/login-codes"), &admin, "").await.1)["code"] })).await);
    let (_, code_json) = call(port, "POST", &format!("/api/users/{id}/login-codes"), &admin, "").await;
    let (code, u) = call(port, "PATCH", &format!("/api/users/{id}"), &admin, r#"{"status":"disabled"}"#).await;
    assert_eq!((code, parse(&u)["status"].as_str()), (200, Some("disabled")));
    assert_eq!(call(port, "GET", "/api/state", &c, "").await.0, 401);
    assert_eq!(login(port, "", json!({ "code": parse(&code_json)["code"] })).await.0, 401);
    assert_eq!(call(port, "POST", &format!("/api/users/{id}/login-codes"), &admin, "").await.0, 409);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{id}"), &admin, r#"{"status":"active"}"#).await.0, 200);
    assert_eq!(call(port, "GET", "/api/state", &c, "").await.0, 401, "re-enabling does not revive old sessions");

    let (_, body) = call(port, "GET", "/api/audit?action=auth.logout,session.*,user.disabled,user.enabled&limit=100", &admin, "").await;
    let actions: Vec<String> = audit_list(&body).iter().rev().map(|e| e["action"].as_str().unwrap().to_string()).collect();
    assert_eq!(actions, ["auth.logout", "session.revoked", "session.revoked_all", "user.disabled", "user.enabled"]);
}

#[tokio::test]
async fn sessions_expire_when_idle_and_stale_cookies_are_cleared() {
    let (port, _, _, _) = serve(|a| a.sessions = SessionConfig { idle_ms: 400, max_ms: 60_000 }).await;
    let t = token_for(port, json!({ "password": PW.as_str() })).await;
    assert_eq!(call(port, "GET", "/api/state", &bearer(&t), "").await.0, 200);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(call(port, "GET", "/api/state", &bearer(&t), "").await.0, 401);

    let (_, head, _) = login(port, &origin(port), json!({ "password": PW.as_str(), "session": "cookie" })).await;
    let ctoken = header(&head, "set-cookie").unwrap().split(';').next().unwrap().trim_start_matches("superbot_session=").to_string();
    tokio::time::sleep(Duration::from_millis(600)).await;
    let (code, head, _) = call_with(port, "GET", "/api/state", "", &cookie(&ctoken), "").await;
    assert_eq!(code, 401);
    assert!(header(&head, "set-cookie").unwrap().contains("Max-Age=0"));
    assert!(header(&head, "www-authenticate").is_none(), "no password box when a cookie session ends");
    let (code, head, _) = call_with(port, "GET", "/", "", &cookie(&ctoken), "").await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login")));
}

#[tokio::test]
async fn sessions_hit_their_absolute_limit() {
    let (port, _, _, _) = serve(|a| a.sessions = SessionConfig { idle_ms: 60_000, max_ms: 500 }).await;
    let t = bearer(&token_for(port, json!({ "password": PW.as_str() })).await);
    for _ in 0..3 {
        assert_eq!(call(port, "GET", "/api/state", &t, "").await.0, 200);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(call(port, "GET", "/api/state", &t, "").await.0, 401, "use does not extend past the max age");
}

#[tokio::test]
async fn the_event_stream_closes_when_its_session_is_revoked() {
    let (port, _, admin, _) = serve(|_| {}).await;
    let (id, member) = user_with(port, &admin, "m@example.com", "member").await;
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!("GET /api/events HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nAuthorization: {member}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut first = [0u8; 12];
    s.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"HTTP/1.0 200");
    call(port, "DELETE", &format!("/api/users/{id}/sessions"), &admin, "").await;
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut rest)).await;
    assert!(closed.is_ok(), "stream still open after revoke");
}

#[tokio::test]
async fn sign_in_codes_work_once() {
    let (port, _, admin, _) = serve(|_| {}).await;
    let (id, _) = user_with(port, &admin, "m@example.com", "member").await;
    let (_, c) = call(port, "POST", &format!("/api/users/{id}/login-codes"), &admin, r#"{"ttlMinutes":10}"#).await;
    let code = parse(&c)["code"].as_str().unwrap().to_string();
    assert!(code.starts_with("sbc_"));
    assert_eq!(call(port, "GET", "/api/state", &bearer(&code), "").await.0, 401, "a code is not a session");
    let (status, _, res) = login(port, "", json!({ "code": code })).await;
    assert_eq!((status, res["user"]["email"].as_str(), res["session"]["method"].as_str()), (200, Some("m@example.com"), Some("code")));
    assert_eq!(login(port, "", json!({ "code": code })).await.0, 401, "used");
    let token = res["token"].as_str().unwrap();
    assert_eq!(login(port, "", json!({ "code": token })).await.0, 401, "a session is not a code");
    for bad in [r#"{"ttlMinutes":0}"#, r#"{"ttlMinutes":10081}"#, r#"{"ttlMinutes":"60"}"#, "not json"] {
        assert_eq!(call(port, "POST", &format!("/api/users/{id}/login-codes"), &admin, bad).await.0, 400, "{bad}");
    }
}

#[tokio::test]
async fn bypass_attempts_fail_closed() {
    let (port, _, admin, bot) = serve(|_| {}).await;
    let (_, readonly) = user_with(port, &admin, "r@example.com", "readonly").await;
    let real = readonly.trim_start_matches("Bearer ").to_string();

    // No credentials: the API says 401; pages go to the sign-in page, which is open.
    let (code, head, body) = call_with(port, "GET", "/api/state", "", "", "").await;
    assert_eq!((code, parse(&body)["error"].as_str()), (401, Some("Login required")));
    assert!(header(&head, "www-authenticate").is_some(), "break-glass Basic is offered to browsers");
    let (_, head, _) = call_with(port, "GET", "/api/state", "", "Sec-Fetch-Mode: cors\r\n", "").await;
    assert!(header(&head, "www-authenticate").is_none(), "but not to the web app's own fetches");
    let (code, head, _) = call_with(port, "GET", "/", "", "", "").await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login")));
    let (code, head, page) = call_with(port, "GET", "/login", "", "", "").await;
    assert!(code == 200 && header(&head, "content-type").unwrap().starts_with("text/html") && page.contains("/api/auth/login"));
    assert_eq!(call(port, "GET", "/api/auth/login", "", "").await.0, 401, "only POST is open");

    // Forged, mangled, or misused credentials.
    let forged = users::new_secret(users::SESSION_PREFIX);
    for (i, auth) in [
        bearer(&forged),
        bearer(&users::hash(&real)),
        bearer(&format!("{real}x")),
        bearer(&real[..real.len() - 1]),
        bearer(""),
        format!("Bearer  {}", &real[1..]),
        format!("bearer {real}"),
        format!("Digest {real}"),
        "Basic !!!".into(),
        basic(&PW[..8]),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(call(port, "GET", "/api/state", &auth, "").await.0, 401, "case #{i}");
    }
    let (code, head, _) = call_with(port, "GET", "/api/state", "", &cookie(&forged), "").await;
    assert_eq!(code, 401);
    assert!(header(&head, "set-cookie").unwrap().contains("Max-Age=0"));
    // A bad Authorization header is refused even next to a good cookie.
    let (_, h, _) = login(port, &origin(port), json!({ "password": PW.as_str(), "session": "cookie" })).await;
    let ctoken = header(&h, "set-cookie").unwrap().split(';').next().unwrap().trim_start_matches("superbot_session=").to_string();
    assert_eq!(call_with(port, "GET", "/api/state", &bearer(&forged), &cookie(&ctoken), "").await.0, 401);
    assert_eq!(call_with(port, "GET", "/api/state", "", &cookie(&ctoken), "").await.0, 200);

    // Paths that dodge the route table land on admin, not on the role of the route they resemble.
    for path in ["/api//users", "/api/users/", "/api/USERS", "/api/bots/x/../../users", "/api/sessions/x/", "/api/%75sers", "/api/state/../users"] {
        let (code, _) = call(port, "GET", path, &readonly, "").await;
        assert_eq!(code, 403, "readonly GET {path}");
        assert_eq!(call(port, "GET", path, &bot, "").await.0, 403, "bot GET {path}");
    }
    for (m, path) in [("POST", "/api/state"), ("DELETE", "/api/bots"), ("PUT", "/api/bots/x"), ("POST", "/api/approvals/x/approve/")] {
        assert_eq!(call(port, m, path, &readonly, "{}").await.0, 403, "readonly {m} {path}");
    }
}

#[tokio::test]
async fn a_password_shaped_like_a_code_still_signs_in() {
    let pw = format!("{}{}", users::CODE_PREFIX, random_hex(8));
    let (port, _, _, _) = serve(|a| a.password = pw.clone()).await;
    let (code, _, res) = login(port, "", json!({ "code": pw })).await;
    assert_eq!((code, res["user"]["id"].as_str()), (200, Some(users::OPERATOR)));
    assert_eq!(login(port, "", json!({ "code": format!("{pw}x") })).await.0, 401);
}

#[tokio::test]
async fn break_glass_off_ignores_the_password() {
    let (port, app, admin, _) = serve(|a| a.break_glass = false).await;
    assert_eq!(call(port, "GET", "/api/state", &admin, "").await.0, 401);
    let (_, head, _) = call_with(port, "GET", "/api/state", "", "", "").await;
    assert!(header(&head, "www-authenticate").is_none(), "no password box");
    let (code, _, res) = login(port, "", json!({ "password": PW.as_str() })).await;
    assert_eq!((code, res["error"].as_str().map(|e| e.contains("off"))), (401, Some(true)));
    assert_eq!(login(port, "", json!({ "code": PW.as_str() })).await.0, 401, "nor as a code");

    // A code (made here by an admin who still has a session) still signs the owner in.
    let code = users::new_secret(users::CODE_PREFIX);
    app.db.add_login_code(&users::hash(&code), users::OPERATOR, users::OPERATOR, db::now() + 60_000);
    let t = bearer(&token_for(port, json!({ "code": code })).await);
    let (_, me) = call(port, "GET", "/api/auth/me", &t, "").await;
    assert_eq!((parse(&me)["role"].as_str(), parse(&me)["breakGlass"].as_bool()), (Some("admin"), Some(false)));
    let (_, body) = call(port, "GET", "/api/audit?action=auth.login_failed", &t, "").await;
    assert!(audit_list(&body).iter().any(|e| e["details"]["reason"] == "break_glass_off"));

    // A browser still sending a cached password reaches the sign-in page, then its cookie wins.
    let (code, head, _) = call_with(port, "GET", "/", &admin, "", "").await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login")));
    let code = users::new_secret(users::CODE_PREFIX);
    app.db.add_login_code(&users::hash(&code), users::OPERATOR, users::OPERATOR, db::now() + 60_000);
    let (_, head, _) = login(port, &origin(port), json!({ "code": code, "session": "cookie" })).await;
    let ctoken = header(&head, "set-cookie").unwrap().split(';').next().unwrap().trim_start_matches("superbot_session=").to_string();
    assert_eq!(call_with(port, "GET", "/api/state", &admin, &cookie(&ctoken), "").await.0, 200);
    assert_eq!(call_with(port, "GET", "/api/state", &basic(&random_hex(16)), &cookie(&ctoken), "").await.0, 200, "the password is ignored, right or wrong");
}

#[tokio::test]
async fn failed_sign_ins_are_rate_limited_per_client_ip() {
    let (port, _, admin, _) = serve(|_| {}).await;
    // Behind the proxy, the client IP is the last X-Forwarded-For entry; a client
    // can add entries in front of it but not change it.
    let from = |spoof: u32, ip: &str| format!("X-Forwarded-For: 203.0.113.{spoof}, {ip}\r\n");
    for i in 0..10 {
        assert_eq!(login(port, &from(i, "198.51.100.1"), json!({ "password": "wrong" })).await.0, 401);
    }
    let (code, head, _) = login(port, &from(99, "198.51.100.1"), json!({ "password": PW.as_str() })).await;
    assert_eq!(code, 429, "even the right password waits");
    assert!(header(&head, "retry-after").unwrap().parse::<u64>().unwrap() > 0);
    assert_eq!(login(port, &from(1, "198.51.100.2"), json!({ "password": PW.as_str() })).await.0, 200);
    // Basic auth (botctl, old clients) is not locked out by the sign-in limiter.
    assert_eq!(call_with(port, "GET", "/api/state", &admin, &from(1, "198.51.100.1"), "").await.0, 200);
}
