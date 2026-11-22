//! HTTP tests for suspicious sign-in detection (ADR 0104), on the real router.

use crate::mfa_http_tests::{code, enrol};
use crate::signin_watch::{Settings, Watch};
use crate::tests::{audit_list, basic, call, call_with, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

static PW: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| random_hex(16));

async fn serve(settings: Settings) -> (u16, AppState, String) {
    let (port, app, basic, _) = serve_app_with(|a| {
        a.password = PW.clone();
        a.watch = Watch::new(settings);
    })
    .await;
    (port, app, basic)
}

fn from(ip: &str) -> String {
    format!("X-Forwarded-For: {ip}\r\n")
}

async fn login(port: u16, ip: &str, body: Value) -> (u16, Value) {
    let (status, _, res) = call_with(port, "POST", "/api/auth/login", "", &from(ip), &body.to_string()).await;
    (status, parse(&res))
}

/// The `auth.suspicious_sign_in` events, oldest first.
async fn detections(port: u16, admin: &str) -> Vec<Value> {
    let (status, body) = call(port, "GET", "/api/audit?action=auth.suspicious_sign_in", admin, "").await;
    assert_eq!(status, 200, "{body}");
    let mut list = audit_list(&body);
    list.reverse();
    list
}

fn metrics(app: &AppState) -> String {
    let mut out = String::new();
    app.db.metrics().render(&mut out);
    out
}

async fn new_code(port: u16, admin: &str, user: &str) -> String {
    let (status, c) = call(port, "POST", &format!("/api/users/{user}/login-codes"), admin, "").await;
    assert_eq!(status, 200, "{c}");
    parse(&c)["code"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_burst_of_wrong_codes_from_one_ip_is_audited_before_the_limiter_steps_in() {
    let (port, app, admin) = serve(Settings::default()).await;
    let guess = |i: usize| json!({ "code": format!("sbc_{i:064x}") });
    for i in 0..9 {
        assert_eq!(login(port, "203.0.113.7", guess(i)).await.0, 401);
    }
    assert!(detections(port, &admin).await.is_empty(), "nine is under the default ten");
    // Another IP's guesses don't add to this one's.
    assert_eq!(login(port, "198.51.100.20", guess(99)).await.0, 401);
    assert_eq!(login(port, "203.0.113.7", guess(9)).await.0, 401);
    let found = detections(port, &admin).await;
    assert_eq!(found.len(), 1, "{found:?}");
    let d = &found[0];
    assert_eq!((d["actorKind"].as_str(), d["actorId"].as_str(), d["outcome"].as_str(), d["ip"].as_str()), (Some("system"), Some("signin_watch"), Some("failure"), Some("203.0.113.7")));
    assert_eq!(d["details"], json!({ "pattern": "ip_failures", "scope": "ip", "method": "code", "failures": 10, "threshold": 10, "windowSeconds": 900 }));
    assert!(d["targetId"].is_null(), "a burst from an IP isn't about one account");
    // The limiter now holds the IP off; nothing more is reported this window.
    assert_eq!(login(port, "203.0.113.7", guess(10)).await.0, 429);
    assert_eq!(detections(port, &admin).await.len(), 1);

    let out = metrics(&app);
    assert!(out.contains(r#"superbot_signin_failures_total{method="code"} 11"#), "{out}");
    assert!(out.contains(r#"superbot_signin_suspicious_total{pattern="ip_failures"} 1"#), "{out}");
    assert!(out.contains(r#"superbot_signin_suspicious_total{pattern="success_after_failures"} 0"#), "{out}");
    assert!(!out.contains("203.0.113"), "no IP is a label: {out}");
}

#[tokio::test]
async fn wrong_second_factors_at_one_account_are_counted_across_ips_then_a_sign_in_is_flagged() {
    let (port, app, admin) = serve(Settings { person_failures: 3, ..Settings::default() }).await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let (key, _) = enrol(port, &ada_auth).await;
    let (bob, _) = user_with(port, &admin, "bob@example.com", "member").await;

    for (i, ip) in ["203.0.113.1", "198.51.100.2"].iter().enumerate() {
        let (status, res) = login(port, ip, json!({ "code": new_code(port, &admin, &ada).await, "totp": format!("00000{i}") })).await;
        assert_eq!((status, res["mfa"].as_str()), (401, Some("totp")), "{res}");
    }
    assert!(detections(port, &admin).await.is_empty());
    // The third wrong code, from a third IP, at the second step this time.
    let (_, res) = login(port, "192.0.2.3", json!({ "code": new_code(port, &admin, &ada).await })).await;
    let (status, _) = login(port, "192.0.2.3", json!({ "challenge": res["challenge"], "recoveryCode": "aaaaa-aaaaa" })).await;
    assert_eq!(status, 401);
    let found = detections(port, &admin).await;
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0]["targetType"].as_str(), found[0]["targetId"].as_str(), found[0]["ip"].as_str()), (Some("user"), Some(ada.as_str()), Some("192.0.2.3")));
    assert_eq!(found[0]["details"], json!({ "pattern": "account_failures", "scope": "account", "method": "recovery_code", "failures": 3, "threshold": 3, "windowSeconds": 900 }));
    let text = found[0].to_string();
    assert!(!text.contains("aaaaa") && !text.contains("sbc_"), "never what was sent: {text}");

    // Bob's sign-in isn't Ada's.
    assert_eq!(login(port, "192.0.2.3", json!({ "code": new_code(port, &admin, &bob).await })).await.0, 200);
    assert_eq!(detections(port, &admin).await.len(), 1);
    // Ada's next good sign-in is flagged once, with the session it made.
    let (status, res) = login(port, "192.0.2.50", json!({ "code": new_code(port, &admin, &ada).await, "totp": code(&key, 1) })).await;
    assert_eq!(status, 200, "{res}");
    let found = detections(port, &admin).await;
    assert_eq!(found.len(), 2, "{found:?}");
    let s = &found[1];
    assert_eq!((s["outcome"].as_str(), s["targetId"].as_str(), s["ip"].as_str()), (Some("success"), Some(ada.as_str()), Some("192.0.2.50")));
    assert_eq!(s["details"]["pattern"], "success_after_failures");
    assert_eq!(s["details"]["scope"], "account");
    assert_eq!(s["details"]["session"], res["session"]["id"]);
    let out = metrics(&app);
    assert!(out.contains(r#"superbot_signin_failures_total{method="totp"} 2"#), "{out}");
    assert!(out.contains(r#"superbot_signin_failures_total{method="recovery_code"} 1"#), "{out}");
    assert!(out.contains(r#"superbot_signin_suspicious_total{pattern="account_failures"} 1"#), "{out}");
    assert!(out.contains(r#"superbot_signin_suspicious_total{pattern="success_after_failures"} 1"#), "{out}");
    assert!(!out.contains("ada@") && !out.contains(&ada), "no person is a label: {out}");
}

#[tokio::test]
async fn break_glass_password_guesses_count_against_the_owner_from_any_ip() {
    let (port, _, basic_owner) = serve(Settings { person_failures: 4, ..Settings::default() }).await;
    // Reading the audit log as the owner over HTTP Basic would be the owner signing in.
    let (_, admin) = user_with(port, &basic_owner, "root@example.com", "admin").await;
    let wrong = basic(&random_hex(16));
    for i in 0..3 {
        assert_eq!(call_with(port, "GET", "/api/state", &wrong, &from(&format!("203.0.113.{i}")), "").await.0, 401);
    }
    assert!(detections(port, &admin).await.is_empty());
    assert_eq!(login(port, "198.51.100.9", json!({ "password": random_hex(16) })).await.0, 401);
    let found = detections(port, &admin).await;
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0]["targetId"].as_str(), found[0]["details"]["pattern"].as_str(), found[0]["details"]["method"].as_str()), (Some("operator"), Some("account_failures"), Some("password")));
    // The right password over HTTP Basic from one of those IPs is the owner signing in after them.
    assert_eq!(call_with(port, "GET", "/api/state", &basic_owner, &from("203.0.113.0"), "").await.0, 200);
    let found = detections(port, &admin).await;
    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!((found[1]["targetId"].as_str(), found[1]["details"]["pattern"].as_str()), (Some("operator"), Some("success_after_failures")));
}

#[tokio::test]
async fn an_admin_signing_in_from_a_new_network_is_reported_and_a_member_is_not() {
    let (port, _, admin) = serve(Settings::default()).await;
    let owner = |ip: &'static str| async move { login(port, ip, json!({ "password": PW.as_str() })).await };
    // The first sign-in has nothing to compare against.
    assert_eq!(owner("203.0.113.5").await.0, 200);
    // The same /24 is the same network.
    assert_eq!(owner("203.0.113.99").await.0, 200);
    assert!(detections(port, &admin).await.is_empty());
    let (status, res) = owner("198.51.100.4").await;
    assert_eq!(status, 200);
    let found = detections(port, &admin).await;
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0]["targetId"].as_str(), found[0]["ip"].as_str(), found[0]["outcome"].as_str()), (Some("operator"), Some("198.51.100.4"), Some("success")));
    assert_eq!(found[0]["details"], json!({ "pattern": "new_ip", "scope": "account", "method": "password", "session": res["session"]["id"] }));
    // Once seen, it isn't new.
    assert_eq!(owner("198.51.100.4").await.0, 200);
    assert_eq!(detections(port, &admin).await.len(), 1);

    let (member, _) = user_with(port, &admin, "mo@example.com", "member").await;
    assert_eq!(login(port, "192.0.2.77", json!({ "code": new_code(port, &admin, &member).await })).await.0, 200);
    assert_eq!(detections(port, &admin).await.len(), 1, "SIGNIN_ALERT_NEW_IP defaults to admins");
}

#[tokio::test]
async fn new_networks_for_everyone_or_no_one() {
    let (port, _, admin) = serve(Settings { new_ip: crate::signin_watch::NewIp::All, ..Settings::default() }).await;
    let (member, _) = user_with(port, &admin, "mo@example.com", "member").await;
    assert_eq!(login(port, "192.0.2.77", json!({ "code": new_code(port, &admin, &member).await })).await.0, 200);
    let found = detections(port, &admin).await;
    assert_eq!((found.len(), found[0]["targetId"].as_str()), (1, Some(member.as_str())), "{found:?}");

    let (port, _, admin) = serve(Settings { new_ip: crate::signin_watch::NewIp::Off, ..Settings::default() }).await;
    assert_eq!(login(port, "203.0.113.5", json!({ "password": PW.as_str() })).await.0, 200);
    assert_eq!(login(port, "198.51.100.4", json!({ "password": PW.as_str() })).await.0, 200);
    assert!(detections(port, &admin).await.is_empty());
}

#[tokio::test]
async fn off_reports_nothing_but_still_counts_failures() {
    let (port, app, admin) = serve(Settings { enabled: false, ip_failures: 2, person_failures: 2, ..Settings::default() }).await;
    for i in 0..4 {
        assert_eq!(login(port, "203.0.113.7", json!({ "code": format!("sbc_{i:064x}") })).await.0, 401);
    }
    assert_eq!(login(port, "203.0.113.5", json!({ "password": PW.as_str() })).await.0, 200);
    assert_eq!(login(port, "198.51.100.4", json!({ "password": PW.as_str() })).await.0, 200);
    assert!(detections(port, &admin).await.is_empty());
    let out = metrics(&app);
    assert!(out.contains(r#"superbot_signin_failures_total{method="code"} 4"#), "{out}");
    assert!(out.contains(r#"superbot_signin_suspicious_total{pattern="ip_failures"} 0"#), "{out}");
}

#[tokio::test]
async fn expired_sessions_and_bot_tokens_are_not_guesses() {
    let (port, app, admin) = serve(Settings { ip_failures: 2, ..Settings::default() }).await;
    for _ in 0..5 {
        assert_eq!(call_with(port, "GET", "/api/state", "Bearer sbs_0000", &from("203.0.113.7"), "").await.0, 401);
        assert_eq!(call_with(port, "GET", "/api/state", "Bearer nope", &from("203.0.113.7"), "").await.0, 401);
    }
    assert!(detections(port, &admin).await.is_empty());
    let out = metrics(&app);
    for m in ["password", "code", "totp", "recovery_code"] {
        assert!(out.contains(&format!(r#"superbot_signin_failures_total{{method="{m}"}} 0"#)), "{out}");
    }
}

#[tokio::test]
async fn a_password_cached_from_before_break_glass_was_turned_off_is_no_attack() {
    let (port, app, admin_basic, _) = serve_app_with(|a| {
        a.password = PW.clone();
        a.break_glass = false;
        a.watch = Watch::new(Settings { ip_failures: 2, person_failures: 2, ..Settings::default() });
    })
    .await;
    for _ in 0..5 {
        assert_eq!(call_with(port, "GET", "/api/state", &admin_basic, &from("203.0.113.7"), "").await.0, 401);
    }
    assert!(app.db.audit_events(&Default::default(), 1000, false).iter().all(|e| e.action != crate::signin_watch::ACTION));
    assert!(metrics(&app).contains(r#"superbot_signin_failures_total{method="password"} 0"#));
}
