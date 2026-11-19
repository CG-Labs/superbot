//! Regression tests from the auth review (docs/security/auth-review-2026-11.md, ADR 0024),
//! on the real router: every route that isn't public refuses callers without the right
//! credentials or role, and credentials a browser sends by itself can't be ridden cross-site.

use crate::rbac::{self, Principal, Role};
use crate::tests::{basic, call, call_with, serve_app_with};
use crate::users_http_tests::user_with;
use crate::*;

/// Routes anyone may call: signing in, the page to do it on, and asking for access.
const PUBLIC: &[(&str, &str)] = &[
    ("GET", "/healthz"),
    ("GET", "/login"),
    ("POST", "/api/auth/login"),
    ("GET", "/api/auth/sso"),
    ("GET", "/api/auth/sso/{id}/start"),
    ("GET", "/api/auth/sso/{id}/callback"),
    ("POST", "/api/auth/sso/{id}/callback"),
    ("POST", "/api/signups"),
    ("GET", "/api/signups/config"),
];

/// Every `(method, path)` in `router()`, read from its source so a new route can't be missed.
fn routes() -> Vec<(String, String)> {
    let src = include_str!("main.rs");
    let body = &src[src.find("\nfn router(").expect("fn router")..];
    let body = &body[..body.find("\n}\n").expect("end of fn router")];
    // Routes before the outer Router are the API, nested under /api.
    let outer = body.find(".route(\"/healthz\"").expect("the outer router");
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = body[at..].find(".route(\"") {
        let start = at + i + ".route(\"".len();
        let path = &body[start..start + body[start..].find('"').unwrap()];
        let end = body[start..].find(".route(\"").map_or(body.len(), |j| start + j);
        let full = if start < outer { format!("/api{path}") } else { path.to_string() };
        let chunk = &body[start..end];
        for m in ["get", "post", "put", "patch", "delete"] {
            let pat = format!("{m}(");
            let called = chunk.match_indices(&pat).any(|(k, _)| k > 0 && matches!(chunk.as_bytes()[k - 1], b' ' | b'.' | b'('));
            if called && !out.contains(&(m.to_ascii_uppercase(), full.clone())) {
                out.push((m.to_ascii_uppercase(), full.clone()));
            }
        }
        at = end;
    }
    out
}

fn concrete(path: &str) -> String {
    path.split('/').map(|s| if s.starts_with('{') { "x1" } else { s }).collect::<Vec<_>>().join("/")
}

#[test]
fn the_route_list_is_read_whole() {
    let r = routes();
    assert!(r.len() >= 60, "{} routes: the parser no longer understands fn router", r.len());
    for (m, p) in [("GET", "/api/state"), ("DELETE", "/api/users/{key}/sessions"), ("POST", "/api/signups/{id}/reject"), ("POST", "/api/auth/sso/{id}/callback"), ("GET", "/healthz")] {
        assert!(r.contains(&(m.into(), p.into())), "{m} {p} missing from {r:?}");
    }
    for (m, p) in PUBLIC {
        assert!(r.contains(&(m.to_string(), p.to_string())), "public {m} {p} is not a route any more");
    }
}

#[tokio::test]
async fn every_route_but_the_public_ones_needs_credentials_and_the_right_role() {
    let (port, _, admin, bot) = serve_app_with(|_| {}).await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (_, readonly) = user_with(port, &admin, "r@example.com", "readonly").await;
    let forged = format!("Bearer {}", users::new_secret(users::SESSION_PREFIX));
    let cookie = format!("Cookie: {}={}\r\n", users::COOKIE, users::new_secret(users::SESSION_PREFIX));
    let mut checked = 0;
    for (m, p) in routes() {
        if PUBLIC.contains(&(m.as_str(), p.as_str())) {
            continue;
        }
        let path = concrete(&p);
        for (who, auth, extra) in [("nobody", "", ""), ("forged token", forged.as_str(), ""), ("forged cookie", "", cookie.as_str())] {
            let (code, _, body) = call_with(port, &m, &path, auth, extra, "{}").await;
            assert_eq!(code, 401, "{who}: {m} {path}: {body}");
        }
        let method = axum::http::Method::from_bytes(m.as_bytes()).unwrap();
        let need = rbac::classify(&method, &path);
        for (who, principal, auth) in [("member", Principal::User(Role::Member), &member), ("readonly", Principal::User(Role::Readonly), &readonly), ("bot", Principal::Bot, &bot)] {
            if !rbac::allows(principal, need) {
                assert_eq!(call(port, &m, &path, auth, "{}").await.0, 403, "{who}: {m} {path} needs {need:?}");
            }
        }
        // Read-only people change nothing (signing out is their own session).
        if m != "GET" && p != "/api/auth/logout" {
            assert!(!rbac::allows(Principal::User(Role::Readonly), need), "readonly could {m} {p}");
        }
        // The admin portal, the audit log, secrets, and signups are admin-only.
        if ["/api/users", "/api/sessions", "/api/audit", "/api/secrets", "/api/signups", "/api/policy"].iter().any(|s| p.starts_with(s)) && !(m == "GET" && p.starts_with("/api/policy")) {
            assert_eq!(need, rbac::Perm::Admin, "{m} {p}");
        }
        checked += 1;
    }
    assert!(checked >= 50, "{checked}");
    // Web pages go to the sign-in page.
    let (code, head, _) = call_with(port, "GET", "/console/", "", "", "").await;
    assert_eq!((code, head.to_ascii_lowercase().contains("location: /login")), (303, true), "{head}");
}

#[tokio::test]
async fn a_cached_break_glass_password_cannot_be_ridden_cross_site() {
    let (port, app, admin, _) = serve_app_with(|_| {}).await;
    let (uid, member) = user_with(port, &admin, "m@example.com", "member").await;
    let bot_id = app.db.create_bot("Shared", "#fff", "waddle", "claude", None, false).id;
    // What a page on another site can make the browser send with its cached password:
    // a form or text/plain fetch, which needs no CORS preflight.
    let codes = format!("/api/users/{uid}/login-codes");
    for bad in ["Origin: https://evil.example\r\n", "Origin: null\r\n", "Sec-Fetch-Site: cross-site\r\n", "Sec-Fetch-Site: same-site\r\n"] {
        let (code, _, body) = call_with(port, "POST", &codes, &admin, bad, r#"{"replace":true}"#).await;
        assert_eq!(code, 403, "{bad}: {body}");
        assert_eq!(call_with(port, "POST", "/api/bots", &admin, bad, r#"{"name":"CSRF"}"#).await.0, 403, "{bad}");
        assert_eq!(call_with(port, "POST", &format!("/api/bots/{bot_id}/stop"), &admin, bad, "").await.0, 403, "{bad}");
        assert_eq!(call_with(port, "GET", &format!("/api/bots/{bot_id}/screen"), &admin, bad, "").await.0, 403, "{bad}: opening a screen starts it");
        // Reads stay fine: the response can't be read cross-site.
        assert_eq!(call_with(port, "GET", "/api/state", &admin, bad, "").await.0, 200);
    }
    assert!(app.db.bots().iter().all(|b| b.name != "CSRF"));
    // Our own pages, and tools that send no browser headers (botctl, curl), still work.
    assert_eq!(call_with(port, "POST", &codes, &admin, &format!("Origin: http://127.0.0.1:{port}\r\n"), "").await.0, 200);
    assert_eq!(call(port, "POST", &codes, &admin, "").await.0, 200);
    // A Bearer token is only sent on purpose, so the client app may run on another origin.
    let evil = "Origin: http://localhost:8081\r\n";
    assert_eq!(call_with(port, "POST", "/api/bots", &member, evil, r#"{"name":"From Expo web"}"#).await.0, 201);
}

#[tokio::test]
async fn allow_no_auth_writes_must_come_from_our_own_pages() {
    let (port, app, _, _) = serve_app_with(|a| a.allow_no_auth = true).await;
    let (code, _, body) = call_with(port, "POST", "/api/bots", "", "Origin: https://evil.example\r\n", r#"{"name":"CSRF"}"#).await;
    assert_eq!(code, 403, "{body}");
    assert!(app.db.bots().iter().all(|b| b.name != "CSRF"));
    assert_eq!(call_with(port, "POST", "/api/bots", "", &format!("Origin: http://127.0.0.1:{port}\r\n"), r#"{"name":"Mine"}"#).await.0, 201);
    assert_eq!(call(port, "POST", "/api/bots", "", r#"{"name":"botctl"}"#).await.0, 201);
}

#[tokio::test]
async fn break_glass_password_guesses_on_any_route_are_rate_limited() {
    let (port, _, admin, _) = serve_app_with(|_| {}).await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let from = |ip: &str| format!("X-Forwarded-For: {ip}\r\n");
    let wrong = basic(&random_hex(16));
    for i in 0..10 {
        assert_eq!(call_with(port, "GET", "/api/state", &wrong, &from("198.51.100.7"), "").await.0, 401, "guess #{i}");
    }
    let (code, head, _) = call_with(port, "GET", "/api/audit", &admin, &from("198.51.100.7"), "").await;
    assert_eq!(code, 429, "even the right password waits");
    assert!(head.to_ascii_lowercase().contains("retry-after:"), "{head}");
    // One limiter for all sign-ins: the sign-in page from that address waits too.
    let (code, _, _) = call_with(port, "POST", "/api/auth/login", "", &from("198.51.100.7"), r#"{"password":"x"}"#).await;
    assert_eq!(code, 429);
    // Other addresses, and sessions already signed in from this one, are not locked out.
    assert_eq!(call_with(port, "GET", "/api/state", &admin, &from("198.51.100.8"), "").await.0, 200);
    assert_eq!(call_with(port, "GET", "/api/state", &member, &from("198.51.100.7"), "").await.0, 200);
}

#[test]
fn secrets_compare_without_showing_their_length() {
    assert!(crate::same(b"sbs_abc", b"sbs_abc"));
    assert!(crate::same(b"", b""));
    let cases = [(&b"sbs_abc"[..], &b"sbs_abd"[..]), (b"sbs_abc", b"sbs_ab"), (b"sbs_ab", b"sbs_abc"), (b"sbs_abcsbs_abc", b"sbs_abc"), (b"", b"x"), (b"x", b"")];
    for (a, b) in cases {
        assert!(!crate::same(a, b), "{a:?} {b:?}");
    }
}
