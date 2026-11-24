//! The Expo client is the interface for everyone (ADR 0027); the console is a minimal
//! admin page with no chat, Bots, or screens (ADR 0032).

use crate::sso_http_tests::{header, mock_idp, serve_with, set_cookies, to_callback, OID};
use crate::tests::{call, call_with, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

const CONSOLE_JS: &str = include_str!("../../web/app.js");
const CONSOLE_HTML: &str = include_str!("../../web/index.html");
const CLIENT_API: &str = include_str!("../../apps/client/src/api.ts");

async fn location(port: u16, path: &str, auth: &str, extra: &str) -> (u16, Option<String>, String) {
    let (code, head, body) = call_with(port, "GET", path, auth, extra, "").await;
    (code, header(&head, "location"), body)
}

/// The values a `${...}` hole can take: its quoted strings (`${ok ? "approve" : "deny"}`),
/// else a placeholder id.
fn hole(expr: &str) -> Vec<String> {
    let quoted: Vec<String> = expr.split('"').skip(1).step_by(2).map(String::from).collect();
    if quoted.is_empty() { vec!["x".into()] } else { quoted }
}

/// Every string a JS/TS literal starting at `s[0]` (a `"` or a backtick) can be, and the
/// rest of the line after it.
fn literal(s: &str) -> (Vec<String>, &str) {
    let quote = s.as_bytes()[0];
    let mut out = vec![String::new()];
    let mut i = 1;
    while i < s.len() {
        let c = s.as_bytes()[i];
        if c == quote {
            return (out, &s[i + 1..]);
        }
        if quote == b'`' && s[i..].starts_with("${") {
            let (mut depth, mut j) = (0, i + 1);
            for (k, ch) in s[i + 1..].char_indices() {
                depth += match ch { '{' => 1, '}' => -1, _ => 0 };
                if depth == 0 {
                    j = i + 1 + k;
                    break;
                }
            }
            let options = hole(&s[i + 2..j]);
            out = out.iter().flat_map(|o| options.iter().map(move |v| format!("{o}{v}"))).collect();
            i = j + 1;
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.iter_mut().for_each(|o| o.push(ch));
        i += ch.len_utf8();
    }
    (out, "")
}

/// Each `/api/...` call in a script, with its method: the `"METHOD", ` just before the
/// path, else a `method: "X"` later in the same statement, else GET. Query strings are dropped.
fn api_calls(src: &str) -> Vec<(String, String)> {
    const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
    let lines: Vec<&str> = src.lines().collect();
    let mut out = vec![];
    for (n, line) in lines.iter().enumerate() {
        let mut rest = *line;
        while let Some(at) = rest.find(['"', '`']) {
            let before = line[..line.len() - rest.len() + at].trim_end();
            let (values, after) = literal(&rest[at..]);
            let ahead = format!("{after}\n{}", lines[(n + 1).min(lines.len())..lines.len().min(n + 3)].join("\n"));
            let ahead = ahead.split(';').next().unwrap_or_default();
            for v in values {
                let Some(p) = v.find("/api/") else { continue };
                let path = v[p..].split('?').next().unwrap().to_string();
                let method = METHODS
                    .iter()
                    .find(|m| before.ends_with(&format!("\"{m}\",")))
                    .or_else(|| METHODS.iter().find(|m| ahead.contains(&format!("method: \"{m}\""))))
                    .unwrap_or(&"GET");
                out.push((method.to_string(), path));
            }
            rest = after;
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Just the status line, for responses that stream and never end (`/api/events`).
async fn status_only(port: u16, path: &str, auth: &str) -> u16 {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nAuthorization: {auth}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut line = String::new();
    tokio::io::BufReader::new(s).read_line(&mut line).await.unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// Asserts each call reaches a route for its method: not a 405, and not what a path
/// nothing serves gets.
async fn assert_routed(port: u16, auth: &str, calls: &[(String, String)]) {
    let nothing = call(port, "GET", "/api/no/such/route", auth, "").await;
    assert_eq!(nothing.0, 404);
    for (m, p) in calls {
        let got = if p == "/api/events" { (status_only(port, p, auth).await, String::new()) } else { call(port, m, p, auth, "{}").await };
        assert!(got.0 != 405 && got != nothing, "{m} {p} isn't served: {got:?}");
    }
}

#[test]
fn the_call_finder_reads_templates_and_methods() {
    let src = r#"
        api("POST", `/api/approvals/${id}/${approve ? "approve" : "deny"}`, {});
        this.request("GET", `/api/audit/export.csv${query ? `?${query}` : ""}`);
        const res = await fetch(`${normalizeBaseUrl(baseUrl)}/api/auth/login`, {
          method: "POST",
        return `${this.baseUrl}/api/events`;
    "#;
    let want = [("GET", "/api/audit/export.csv"), ("GET", "/api/events"), ("POST", "/api/approvals/x/approve"), ("POST", "/api/approvals/x/deny"), ("POST", "/api/auth/login")];
    assert_eq!(api_calls(src), want.map(|(m, p)| (m.to_string(), p.to_string())));
}

#[tokio::test]
async fn the_console_is_an_admin_page_without_chat_bots_or_screens() {
    let (port, _, admin, _) = serve_app().await;
    let (code, head, html) = call_with(port, "GET", "/console/", &admin, "", "").await;
    assert_eq!(code, 200);
    assert_eq!(html, CONSOLE_HTML);
    let csp = header(&head, "content-security-policy").unwrap();
    for part in ["script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "connect-src 'self'"] {
        assert!(csp.contains(part), "{csp}");
    }
    for tab in ["Users", "Requests", "Machines", "Teams", "Roles", "Service accounts", "Audit log", "Support", "Settings", "Setup", "Sign out", r#"href="/app/""#] {
        assert!(html.contains(tab), "{tab}");
    }
    // Nothing the CSP would block: one script, from a file, and no inline styles.
    assert_eq!(html.matches("<script").count(), 1);
    assert!(html.contains(r#"<script src="app.js"></script>"#));
    assert!(!html.contains("style=") && !html.contains("<style"));
    for (file, csp_too) in [("/console/app.js", true), ("/console/styles.css", true)] {
        let (code, head, _) = call_with(port, "GET", file, &admin, "", "").await;
        assert_eq!((code, header(&head, "content-security-policy").is_some()), (200, csp_too), "{file}");
    }

    // Chat, Bots, Bot approvals, live events, and screens are the app's.
    for gone in ["/api/state", "/api/events", "EventSource", "/api/bots", "/messages", "/screen", "/api/approvals", "/routines", "/api/harnesses"] {
        assert!(!CONSOLE_JS.contains(gone) && !html.contains(gone), "{gone} is still in the console");
    }
    let calls = api_calls(CONSOLE_JS);
    for want in ["/api/users", "/api/signups/x/approve", "/api/machines", "/api/users/x/machine/suspend", "/api/audit", "/api/audit/export.csv", "/api/policy", "/api/secrets/x", "/api/scim/tokens", "/api/setup", "/api/license", "/api/teams", "/api/teams/x/members/x", "/api/roles", "/api/roles/x/users/x", "/api/roles/x/teams/x/users/x", "/api/role-requests", "/api/role-requests/x/approve", "/api/role-requests/x/deny", "/api/service-accounts", "/api/service-accounts/x", "/api/service-accounts/x/tokens", "/api/service-accounts/x/tokens/x", "/api/service-accounts/x/tokens/x/rotate", "/api/support/onboarding", "/api/support/health-check"] {
        assert!(calls.iter().any(|(_, p)| p == want) || html.contains(want), "the console lost {want}: {calls:?}");
    }
}

/// ADR 0243: the Support tab checks onboarding only when asked, since each check is
/// audited, and sends the skips typed for it.
#[test]
fn the_console_checks_onboarding_only_when_asked() {
    let start = CONSOLE_JS.find("async function loadSupport(").expect("loadSupport");
    let load = &CONSOLE_JS[start..start + CONSOLE_JS[start..].find("\n}\n").expect("function end")];
    assert!(!load.contains("/api/support/onboarding"), "opening the Support tab would record a check");
    let calls: Vec<&str> = CONSOLE_JS.lines().filter(|l| l.contains("/api/support/onboarding")).collect();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].contains("?skip=${key(skip)}"), "{}", calls[0]);
    let submit = CONSOLE_JS.find(r#"$("sup-onboarding-form").addEventListener("submit""#).expect("the check runs from its form");
    let handler = &CONSOLE_JS[submit..submit + CONSOLE_JS[submit..].find("\n});\n").expect("handler end")];
    assert!(handler.contains("/api/support/onboarding"), "the form's handler makes the call");
    assert!(handler.contains("if (mine === onboardingRequest) renderOnboarding(r);"), "an older check's reply could replace a newer one: {handler}");
    for id in ["sup-onboarding-form", "sup-skip", "sup-onboarding", "sup-onboarding-items", "Check onboarding"] {
        assert!(CONSOLE_HTML.contains(id), "{id}");
    }
}

/// ADR 0252: the Support tab runs the monthly health check only when asked, since each
/// check is audited too.
#[test]
fn the_console_runs_the_health_check_only_when_asked() {
    let start = CONSOLE_JS.find("async function loadSupport(").expect("loadSupport");
    let load = &CONSOLE_JS[start..start + CONSOLE_JS[start..].find("\n}\n").expect("function end")];
    assert!(!load.contains("/api/support/health-check"), "opening the Support tab would record a check");
    let calls: Vec<&str> = CONSOLE_JS.lines().filter(|l| l.contains("/api/support/health-check")).collect();
    assert_eq!(calls.len(), 1, "{calls:?}");
    let submit = CONSOLE_JS.find(r#"$("sup-health-check-form").addEventListener("submit""#).expect("the check runs from its form");
    let handler = &CONSOLE_JS[submit..submit + CONSOLE_JS[submit..].find("\n});\n").expect("handler end")];
    assert!(handler.contains("/api/support/health-check"), "the form's handler makes the call");
    assert!(handler.contains("if (mine === healthCheckRequest) renderHealthCheck(r);"), "an older check's reply could replace a newer one: {handler}");
    for id in ["sup-health-check-form", "sup-health-check", "sup-health-check-items", "Run health check"] {
        assert!(CONSOLE_HTML.contains(id), "{id}");
    }
}

/// ADR 0132: the console asks before it takes a custom role away, across the server or
/// within a team, and finds people by email the way the server does (in any case).
#[test]
fn the_console_asks_before_taking_a_role_away_and_matches_emails_in_any_case() {
    let lines: Vec<&str> = CONSOLE_JS.lines().collect();
    let take_aways: Vec<usize> = (0..lines.len()).filter(|&n| lines[n].contains(r#"api("DELETE", `/api/roles/"#) && lines[n].contains("/users/")).collect();
    assert!(take_aways.len() >= 3, "{take_aways:?}");
    for n in take_aways {
        assert!(lines[n.saturating_sub(1)..=n].iter().any(|l| l.contains("confirm(")), "line {} takes a role away without asking: {}", n + 1, lines[n].trim());
    }
    assert!(!CONSOLE_JS.contains(".email =="), "the console compares emails case-sensitively");
}

/// ADR 0152: the console asks before it disables or deletes a service account or revokes a
/// token, and a new token's secret goes only to the shown-once dialog, never to storage.
#[test]
fn the_console_asks_before_stopping_a_service_account_and_keeps_no_token() {
    let lines: Vec<&str> = CONSOLE_JS.lines().collect();
    let stops: Vec<usize> = (0..lines.len()).filter(|&n| lines[n].contains(r#"api("DELETE", `/api/service-accounts/"#) || (lines[n].contains("/api/service-accounts/") && lines[n].contains(r#"status: "disabled""#))).collect();
    assert!(stops.len() >= 3, "{stops:?}");
    for n in stops {
        assert!(lines[n.saturating_sub(1)..=n].iter().any(|l| l.contains("confirm(")), "line {} stops a service account or token without asking: {}", n + 1, lines[n].trim());
    }
    for kept in ["localStorage", "sessionStorage", "document.cookie"] {
        assert!(!CONSOLE_JS.contains(kept), "the console keeps something in {kept}");
    }
    let secret = |l: &str| l.match_indices("r.token").any(|(i, m)| !l[i + m.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_'));
    let uses: Vec<usize> = (0..lines.len()).filter(|&n| secret(lines[n])).collect();
    let elsewhere: Vec<usize> = uses.iter().copied().filter(|&n| !lines[n].contains("value: r.token")).map(|n| n + 1).collect();
    assert!(!uses.is_empty() && elsewhere.is_empty(), "a token's secret goes somewhere but the shown-once dialog, on lines {elsewhere:?}");
}

/// ADR 0152: when two token requests finish together, the second secret waits until the
/// first is closed instead of replacing it before it's copied.
#[test]
fn the_console_queues_a_second_shown_once_value() {
    let body = |name: &str| {
        let start = CONSOLE_JS.find(&format!("function {name}(")).unwrap_or_else(|| panic!("no {name}"));
        let rest = &CONSOLE_JS[start..];
        &rest[..rest.find("\n}\n").expect("function end") + 2]
    };
    let show = body("showOnce");
    let guard = show.find(r#"if (!$("once").hidden) return void onceQueue.push(shown);"#).expect("showOnce doesn't queue while the dialog is open");
    assert!(guard < show.find(r#"$("once-value").textContent"#).unwrap(), "showOnce writes the value before checking the dialog is free");
    let close = body("closeOnce");
    let next = close.find("showOnce(onceQueue.shift())").expect("closing doesn't show the next queued value");
    assert!(close.find(r#"$("once").hidden = true"#).unwrap() < next, "the next value is shown before the dialog is closed");
}

#[tokio::test]
async fn every_call_the_console_makes_is_served_and_admin_only() {
    let (port, _, admin, _) = serve_app().await;
    let (_, member) = user_with(port, &admin, "mia@example.com", "member").await;
    let calls = api_calls(CONSOLE_JS);
    assert!(calls.len() >= 20, "{calls:?}");
    for (m, p) in &calls {
        // Your own session is yours, and anyone may read the approval mode; everything
        // else on the page is for admins.
        if p.starts_with("/api/auth/") || (m.as_str(), p.as_str()) == ("GET", "/api/policy") {
            continue;
        }
        let (code, body) = call(port, m, p, &member, "{}").await;
        // Anyone may see and stop the service accounts they own (ADR 0239). Mia owns none,
        // so she's shown none and finds none.
        if p.starts_with("/api/service-accounts") && code != 403 {
            let none = (m.as_str(), p.as_str()) == ("GET", "/api/service-accounts") && parse(&body)["serviceAccounts"] == json!([]);
            assert!(code == 404 || (code == 200 && none), "{m} {p}: {code} {body}");
            continue;
        }
        assert_eq!(code, 403, "{m} {p}: {body}");
    }
    assert_routed(port, &admin, &calls).await;
}

#[tokio::test]
async fn every_route_the_client_uses_is_still_served() {
    let (port, _, admin, _) = serve_app().await;
    let calls = api_calls(CLIENT_API);
    for want in [("GET", "/api/state"), ("GET", "/api/events"), ("POST", "/api/bots/x/messages"), ("GET", "/api/bots/x/screen"), ("POST", "/api/approvals/x/deny"), ("POST", "/api/auth/login"), ("GET", "/api/audit/export.csv")] {
        assert!(calls.contains(&(want.0.to_string(), want.1.to_string())), "{want:?} not found in api.ts: {calls:?}");
    }
    assert_routed(port, &admin, &calls).await;
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
