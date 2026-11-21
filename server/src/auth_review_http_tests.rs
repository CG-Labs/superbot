//! Regression tests from the auth review (docs/security/auth-review-2026-11.md, ADR 0024,
//! and its SCIM addendum, ADR 0026), on the real router: every route that isn't public
//! refuses callers without the right credentials or role, SCIM tokens and other credentials
//! never cross between /scim/v2 and the rest, and credentials a browser sends by itself
//! can't be ridden cross-site.

use crate::rbac::{self, Principal, Role};
use crate::tests::{basic, call, call_with, serve_app_with};
use crate::users_http_tests::{parse, user_with};
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
    // Stripe signs it; checked in `billing` (ADR 0040).
    ("POST", "/billing/stripe/webhook"),
];

/// Every `(method, path)` in `router()`, read from its source so a new route can't be missed.
pub(crate) fn routes() -> Vec<(String, String)> {
    let src = include_str!("main.rs");
    let body = &src[src.find("\nfn router(").expect("fn router")..];
    let body = &body[..body.find("\n}\n").expect("end of fn router")];
    // Routes in `let api` are the API, nested under /api; the rest (SCIM, the outer
    // Router) are mounted where they say.
    let outer = body.find(".route(\"/healthz\"").expect("the outer router");
    let api = body
        .find("let api = Router::new()")
        .expect("the API router");
    let api_end = body[api + 1..]
        .find("\n    let ")
        .map_or(outer, |j| (api + 1 + j).min(outer));
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = body[at..].find(".route(\"") {
        let start = at + i + ".route(\"".len();
        let path = &body[start..start + body[start..].find('"').unwrap()];
        let end = body[start..]
            .find(".route(\"")
            .map_or(body.len(), |j| start + j);
        let full = if (api..api_end).contains(&start) {
            format!("/api{path}")
        } else {
            path.to_string()
        };
        let chunk = &body[start..end];
        for m in ["get", "post", "put", "patch", "delete"] {
            let pat = format!("{m}(");
            let called = chunk
                .match_indices(&pat)
                .any(|(k, _)| k > 0 && matches!(chunk.as_bytes()[k - 1], b' ' | b'.' | b'('));
            if called && !out.contains(&(m.to_ascii_uppercase(), full.clone())) {
                out.push((m.to_ascii_uppercase(), full.clone()));
            }
        }
        at = end;
    }
    out
}

fn concrete(path: &str) -> String {
    path.split('/')
        .map(|s| if s.starts_with('{') { "x1" } else { s })
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn the_route_list_is_read_whole() {
    let r = routes();
    assert!(
        r.len() >= 60,
        "{} routes: the parser no longer understands fn router",
        r.len()
    );
    for (m, p) in [
        ("GET", "/api/state"),
        ("DELETE", "/api/users/{key}/sessions"),
        ("POST", "/api/signups/{id}/reject"),
        ("POST", "/api/auth/sso/{id}/callback"),
        ("GET", "/healthz"),
        ("POST", "/api/scim/tokens"),
        ("PATCH", "/scim/v2/Users/{id}"),
        ("GET", "/api/setup"),
        ("PATCH", "/api/setup"),
        ("PUT", "/api/license"),
    ] {
        assert!(
            r.contains(&(m.into(), p.into())),
            "{m} {p} missing from {r:?}"
        );
    }
    for (m, p) in PUBLIC {
        assert!(
            r.contains(&(m.to_string(), p.to_string())),
            "public {m} {p} is not a route any more"
        );
    }
}

#[tokio::test]
async fn every_route_but_the_public_ones_needs_credentials_and_the_right_role() {
    let (port, app, admin, key) = serve_app_with(|a| {
        a.scim.enabled = true;
        a.scim.failures = users::Limiter::new(10_000, 60_000);
    })
    .await;
    let bot_id = app
        .db
        .create_bot("Walker", "#fff", "waddle", "claude", None, false)
        .id;
    let bot = key.auth(&bot_id);
    // A Bot token from another key (another start, or made up) or for a Bot that's gone.
    let forged_bot = crate::tests::BotKey(crate::random_hex(16), None).auth(&bot_id);
    let gone = app
        .db
        .create_bot("Gone", "#fff", "waddle", "claude", None, false);
    let gone_bot = key.auth(&gone.id);
    app.db.delete_bot(&gone.id);
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (_, readonly) = user_with(port, &admin, "r@example.com", "readonly").await;
    let forged = format!("Bearer {}", users::new_secret(users::SESSION_PREFIX));
    let cookie = format!(
        "Cookie: {}={}\r\n",
        users::COOKIE,
        users::new_secret(users::SESSION_PREFIX)
    );
    let (scim_auth, _) = scim_token(port, &admin, "walk").await;
    let (revoked, revoked_id) = scim_token(port, &admin, "walk").await;
    assert_eq!(
        call(
            port,
            "DELETE",
            &format!("/api/scim/tokens/{revoked_id}"),
            &admin,
            ""
        )
        .await
        .0,
        200
    );
    let forged_scim = format!("Bearer {}", users::new_secret(scim::TOKEN_PREFIX));
    let mut checked = 0;
    for (m, p) in routes() {
        if PUBLIC.contains(&(m.as_str(), p.as_str())) {
            continue;
        }
        let path = concrete(&p);
        for (who, auth, extra) in [
            ("nobody", "", ""),
            ("forged token", forged.as_str(), ""),
            ("forged cookie", "", cookie.as_str()),
            ("forged Bot token", forged_bot.as_str(), ""),
            ("deleted Bot's token", gone_bot.as_str(), ""),
        ] {
            let (code, _, body) = call_with(port, &m, &path, auth, extra, "{}").await;
            assert_eq!(code, 401, "{who}: {m} {path}: {body}");
        }
        // SCIM (ADR 0023) takes only a live SCIM tenant's token: no session, password, or Bot token.
        if p.starts_with("/scim/") {
            for (who, auth) in [
                ("admin password", &admin),
                ("member session", &member),
                ("bot", &bot),
                ("forged SCIM token", &forged_scim),
                ("revoked SCIM token", &revoked),
            ] {
                assert_eq!(
                    call(port, &m, &path, auth, "{}").await.0,
                    401,
                    "{who}: {m} {path}"
                );
            }
            let (code, body) = call(port, &m, &path, &scim_auth, "{}").await;
            assert!(
                ![401, 403, 429].contains(&code),
                "SCIM token: {m} {path}: {code} {body}"
            );
            checked += 1;
            continue;
        }
        // A provisioning token reaches nothing outside /scim/v2.
        assert_eq!(
            call(port, &m, &path, &scim_auth, "{}").await.0,
            401,
            "SCIM token: {m} {path}"
        );
        let method = axum::http::Method::from_bytes(m.as_bytes()).unwrap();
        let need = rbac::classify(&method, &path);
        for (who, principal, auth) in [
            ("member", Principal::User(Role::Member), &member),
            ("readonly", Principal::User(Role::Readonly), &readonly),
            ("bot", Principal::Bot, &bot),
        ] {
            if !rbac::allows(principal, need) {
                assert_eq!(
                    call(port, &m, &path, auth, "{}").await.0,
                    403,
                    "{who}: {m} {path} needs {need:?}"
                );
            }
        }
        // Read-only people change nothing (signing out is their own session).
        if m != "GET" && p != "/api/auth/logout" {
            assert!(
                !rbac::allows(Principal::User(Role::Readonly), need),
                "readonly could {m} {p}"
            );
        }
        // The admin portal, the audit log, secrets, signups, the setup wizard, and the license are admin-only.
        if [
            "/api/users",
            "/api/sessions",
            "/api/audit",
            "/api/secrets",
            "/api/signups",
            "/api/policy",
            "/api/setup",
            "/api/license",
            "/api/usage",
        ]
        .iter()
        .any(|s| p.starts_with(s))
            && !(m == "GET" && p.starts_with("/api/policy"))
        {
            assert_eq!(need, rbac::Perm::Admin, "{m} {p}");
        }
        checked += 1;
    }
    assert!(checked >= 50, "{checked}");
    // Web pages go to the sign-in page.
    let (code, head, _) = call_with(port, "GET", "/console/", "", "", "").await;
    assert_eq!(
        (code, head.to_ascii_lowercase().contains("location: /login")),
        (303, true),
        "{head}"
    );
}

/// A new SCIM token for `tenant`: as an Authorization header, and its id.
async fn scim_token(port: u16, admin: &str, tenant: &str) -> (String, String) {
    let (code, body) = call(
        port,
        "POST",
        "/api/scim/tokens",
        admin,
        &json!({ "tenant": tenant }).to_string(),
    )
    .await;
    assert_eq!(code, 201, "{body}");
    let v = parse(&body);
    (
        format!("Bearer {}", v["token"].as_str().unwrap()),
        v["scimToken"]["id"].as_str().unwrap().to_string(),
    )
}

fn scim_routes() -> Vec<(String, String)> {
    routes()
        .into_iter()
        .filter(|(_, p)| p.starts_with("/scim/"))
        .collect()
}

#[tokio::test]
async fn with_scim_off_every_scim_route_is_a_404_that_never_reads_a_token() {
    let (port, app, admin, _) = serve_app_with(|_| {}).await;
    let (token, _) = scim_token(port, &admin, "okta").await;
    let routes = scim_routes();
    assert!(routes.len() >= 15, "{routes:?}");
    for (m, p) in routes {
        let path = concrete(&p);
        for (who, auth) in [
            ("nobody", ""),
            ("SCIM token", token.as_str()),
            ("admin password", admin.as_str()),
        ] {
            let (code, head, body) = call_with(port, &m, &path, auth, "", "{}").await;
            assert_eq!(code, 404, "{who}: {m} {path}: {body}");
            assert!(
                head.to_ascii_lowercase()
                    .contains("content-type: application/scim+json"),
                "{who}: {m} {path}: {head}"
            );
        }
    }
    assert!(
        app.db
            .scim_tokens()
            .iter()
            .all(|t| t.last_used_at.is_none()),
        "the token was never looked up"
    );
    let (_, audit) = call(port, "GET", "/api/audit?action=scim.*", &admin, "").await;
    let audit = crate::tests::audit_list(&audit);
    assert!(
        audit.iter().all(|e| e["action"] != "scim.auth_failed"),
        "{audit:?}"
    );
}

#[tokio::test]
async fn scim_tokens_get_nowhere_by_odd_paths_or_methods() {
    let (port, _, admin, _) = serve_app_with(|a| a.scim.enabled = true).await;
    let (token, _) = scim_token(port, &admin, "okta").await;
    // Methods no SCIM route has still need a token first.
    for (m, p) in [
        ("TRACE", "/scim/v2/Users"),
        ("HEAD", "/scim/v2/Users"),
        ("PATCH", "/scim/v2/Users"),
        ("POST", "/scim/v2/Users/x1"),
        ("PUT", "/scim/v2/ServiceProviderConfig"),
    ] {
        let (code, head, body) = call_with(port, m, p, "", "", "").await;
        assert_eq!(code, 401, "{m} {p}: {head} {body}");
    }
    // OPTIONS is answered by the CORS layer on every route, before any auth: empty, with no data.
    let (code, _, body) = call_with(port, "OPTIONS", "/scim/v2/Users", "", "", "").await;
    assert_eq!((code, body.as_str()), (200, ""));
    // Paths that look like SCIM but aren't, or that try to climb out of it.
    for p in [
        "/SCIM/v2/Users",
        "/scim/V2/Users",
        "/scim//v2/Users",
        "/scim/Users",
        "/api/../scim/v2/Users",
        "/scim/v2/../../api/state",
        "/scim/v2/%2e%2e/%2e%2e/api/users",
        "/api/scim/v2/Users",
        "/api/users",
        "/api/scim/tokens",
        "/console/",
    ] {
        let (code, body) = call(port, "GET", p, &token, "").await;
        assert!(!(200..300).contains(&code), "{p}: {code} {body}");
    }
}

#[tokio::test]
async fn a_cached_break_glass_password_cannot_be_ridden_cross_site() {
    let (port, app, admin, _) = serve_app_with(|_| {}).await;
    let (uid, member) = user_with(port, &admin, "m@example.com", "member").await;
    let bot_id = app
        .db
        .create_bot("Shared", "#fff", "waddle", "claude", None, false)
        .id;
    // What a page on another site can make the browser send with its cached password:
    // a form or text/plain fetch, which needs no CORS preflight.
    let codes = format!("/api/users/{uid}/login-codes");
    for bad in [
        "Origin: https://evil.example\r\n",
        "Origin: null\r\n",
        "Sec-Fetch-Site: cross-site\r\n",
        "Sec-Fetch-Site: same-site\r\n",
    ] {
        let (code, _, body) =
            call_with(port, "POST", &codes, &admin, bad, r#"{"replace":true}"#).await;
        assert_eq!(code, 403, "{bad}: {body}");
        assert_eq!(
            call_with(port, "POST", "/api/bots", &admin, bad, r#"{"name":"CSRF"}"#)
                .await
                .0,
            403,
            "{bad}"
        );
        assert_eq!(
            call_with(
                port,
                "POST",
                &format!("/api/bots/{bot_id}/stop"),
                &admin,
                bad,
                ""
            )
            .await
            .0,
            403,
            "{bad}"
        );
        assert_eq!(
            call_with(
                port,
                "GET",
                &format!("/api/bots/{bot_id}/screen"),
                &admin,
                bad,
                ""
            )
            .await
            .0,
            403,
            "{bad}: opening a screen starts it"
        );
        // Reads stay fine: the response can't be read cross-site.
        assert_eq!(
            call_with(port, "GET", "/api/state", &admin, bad, "")
                .await
                .0,
            200
        );
    }
    assert!(app.db.bots().iter().all(|b| b.name != "CSRF"));
    // Our own pages, and tools that send no browser headers (botctl, curl), still work.
    assert_eq!(
        call_with(
            port,
            "POST",
            &codes,
            &admin,
            &format!("Origin: http://127.0.0.1:{port}\r\n"),
            ""
        )
        .await
        .0,
        200
    );
    assert_eq!(call(port, "POST", &codes, &admin, "").await.0, 200);
    // A Bearer token is only sent on purpose, so the client app may run on another origin.
    let evil = "Origin: http://localhost:8081\r\n";
    assert_eq!(
        call_with(
            port,
            "POST",
            "/api/bots",
            &member,
            evil,
            r#"{"name":"From Expo web"}"#
        )
        .await
        .0,
        201
    );
}

#[tokio::test]
async fn allow_no_auth_writes_must_come_from_our_own_pages() {
    let (port, app, _, _) = serve_app_with(|a| a.allow_no_auth = true).await;
    let (code, _, body) = call_with(
        port,
        "POST",
        "/api/bots",
        "",
        "Origin: https://evil.example\r\n",
        r#"{"name":"CSRF"}"#,
    )
    .await;
    assert_eq!(code, 403, "{body}");
    assert!(app.db.bots().iter().all(|b| b.name != "CSRF"));
    assert_eq!(
        call_with(
            port,
            "POST",
            "/api/bots",
            "",
            &format!("Origin: http://127.0.0.1:{port}\r\n"),
            r#"{"name":"Mine"}"#
        )
        .await
        .0,
        201
    );
    assert_eq!(
        call(port, "POST", "/api/bots", "", r#"{"name":"botctl"}"#)
            .await
            .0,
        201
    );
}

#[tokio::test]
async fn break_glass_password_guesses_on_any_route_are_rate_limited() {
    let (port, _, admin, _) = serve_app_with(|_| {}).await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let from = |ip: &str| format!("X-Forwarded-For: {ip}\r\n");
    let wrong = basic(&random_hex(16));
    for i in 0..10 {
        assert_eq!(
            call_with(port, "GET", "/api/state", &wrong, &from("198.51.100.7"), "")
                .await
                .0,
            401,
            "guess #{i}"
        );
    }
    let (code, head, _) =
        call_with(port, "GET", "/api/audit", &admin, &from("198.51.100.7"), "").await;
    assert_eq!(code, 429, "even the right password waits");
    assert!(head.to_ascii_lowercase().contains("retry-after:"), "{head}");
    // One limiter for all sign-ins: the sign-in page from that address waits too.
    let (code, _, _) = call_with(
        port,
        "POST",
        "/api/auth/login",
        "",
        &from("198.51.100.7"),
        r#"{"password":"x"}"#,
    )
    .await;
    assert_eq!(code, 429);
    // Other addresses, and sessions already signed in from this one, are not locked out.
    assert_eq!(
        call_with(port, "GET", "/api/state", &admin, &from("198.51.100.8"), "")
            .await
            .0,
        200
    );
    assert_eq!(
        call_with(
            port,
            "GET",
            "/api/state",
            &member,
            &from("198.51.100.7"),
            ""
        )
        .await
        .0,
        200
    );
}

#[test]
fn secrets_compare_without_showing_their_length() {
    assert!(crate::same(b"sbs_abc", b"sbs_abc"));
    assert!(crate::same(b"", b""));
    let cases = [
        (&b"sbs_abc"[..], &b"sbs_abd"[..]),
        (b"sbs_abc", b"sbs_ab"),
        (b"sbs_ab", b"sbs_abc"),
        (b"sbs_abcsbs_abc", b"sbs_abc"),
        (b"", b"x"),
        (b"x", b""),
    ];
    for (a, b) in cases {
        assert!(!crate::same(a, b), "{a:?} {b:?}");
    }
}
