//! The customer health score (ADR 0144) on the real router: admins only (no custom role
//! reaches it, ADR 0123), computed from the audit log, sign-ins and approvals, and never a
//! name, email or free-text reason.

use crate::audit::{Actor, Event, Outcome};
use crate::tests::{call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

fn signal<'a>(r: &'a Value, id: &str) -> &'a Value {
    r["signals"].as_array().unwrap().iter().find(|s| s["id"] == id).unwrap_or_else(|| panic!("no {id} in {r:#}"))
}

#[tokio::test]
async fn only_admins_get_it() {
    let (port, app, admin, key) = serve_app().await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (_, readonly) = user_with(port, &admin, "r@example.com", "readonly").await;
    let (delegate_id, delegate) = user_with(port, &admin, "d@example.com", "member").await;
    let every = ["users.manage", "bots.manage", "audit.view", "billing.manage", "signups.approve", "machines.manage"];
    let (code, role) = call(port, "POST", "/api/roles", &admin, &json!({ "name": "Everything delegable", "permissions": every }).to_string()).await;
    assert_eq!(code, 201, "{role}");
    let path = format!("/api/roles/{}/users/{delegate_id}", parse(&role)["id"].as_str().unwrap());
    assert_eq!(call(port, "PUT", &path, &admin, "").await.0, 200);
    let bot = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    for (who, auth) in [("member", member.as_str()), ("readonly", readonly.as_str()), ("custom role", delegate.as_str()), ("bot", key.auth(&bot.id).as_str())] {
        assert_eq!(call(port, "GET", "/api/support/health-score", auth, "").await.0, 403, "{who}");
    }
    assert_eq!(call(port, "GET", "/api/support/health-score", "", "").await.0, 401);

    let (code, body) = call(port, "GET", "/api/support/health-score", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!(r["windowDays"], 30);
    let ids: Vec<&str> = r["signals"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, health_score::SIGNALS.iter().map(|s| s.id).collect::<Vec<_>>());
    assert!(r["score"].is_u64() && r["band"].is_string(), "{r:#}");

    let (code, body) = call(port, "GET", "/api/support/health-score?days=7", &admin, "").await;
    assert_eq!((code, parse(&body)["windowDays"].clone()), (200, json!(7)), "{body}");
    for bad in ["6", "91", "thirty"] {
        let (code, body) = call(port, "GET", &format!("/api/support/health-score?days={bad}"), &admin, "").await;
        assert_eq!(code, 400, "{bad}: {body}");
        assert!(body.contains("days must be"), "{body}");
    }
}

#[tokio::test]
async fn it_counts_what_botd_recorded() {
    let (port, app, admin, _) = serve_app().await;
    user_with(port, &admin, "a@customer.example.com", "member").await;
    user_with(port, &admin, "b@customer.example.com", "member").await;
    for email in ["c@customer.example.com", "d@customer.example.com", "e@customer.example.com"] {
        let (code, body) = call(port, "POST", "/api/users", &admin, &json!({ "email": email, "role": "member" }).to_string()).await;
        assert_eq!(code, 201, "{body}");
    }
    let bot = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    let finished = |result: &str| {
        let outcome = if result == "done" { Outcome::Success } else { Outcome::Failure };
        Event::new(Actor::for_bot(&bot), "bot.run_finished").bot(&bot.id).outcome(outcome).details(json!({ "result": result }))
    };
    for result in ["done"; 8].into_iter().chain(["error", "timeout", "stopped", "done"]) {
        app.db.record(&finished(result));
    }
    app.db.record(&Event::new(Actor::for_bot(&bot), "bot.run_refused").bot(&bot.id).outcome(Outcome::Denied).details(json!({ "reason": "egress_policy_pending" })));
    let sso = Actor { kind: audit::ActorKind::User, email: Some("a@customer.example.com".into()), ..Default::default() }.method("sso");
    for _ in 0..9 {
        app.db.record(&Event::new(sso.clone(), "auth.login"));
    }
    app.db.record(&Event::new(sso.clone(), "auth.login_failed").outcome(Outcome::Failure).details(json!({ "reason": "bad_signature" })));
    app.db.record(&Event::new(Actor::system("scim").method("scim_token"), "scim.auth_failed").outcome(Outcome::Failure).details(json!({ "reason": "unknown" })));
    for _ in 0..10 {
        app.db.record(&Event::new(Actor::for_bot(&bot), "approval.requested").bot(&bot.id));
    }
    app.db.record(&Event::new(Actor::system("approvals"), "approval.expired").bot(&bot.id));

    let (code, body) = call(port, "GET", "/api/support/health-score", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);

    let adoption = signal(&r, "adoption");
    assert_eq!((adoption["facts"]["people"].as_u64(), adoption["facts"]["active"].as_u64()), (Some(5), Some(2)), "{adoption:#}");
    assert_eq!(adoption["status"], "watch", "40% is below 60%");

    let runs = signal(&r, "runs");
    assert_eq!((runs["facts"]["finished"].as_u64(), runs["facts"]["failed"].as_u64()), (Some(12), Some(2)), "{runs:#}");
    assert_eq!(runs["status"], "risk", "17% failed");
    assert_eq!(runs["facts"]["refusedReasons"], json!([{ "code": "egress_policy_pending", "count": 1 }]));

    let identity = signal(&r, "identity");
    assert_eq!((identity["facts"]["ssoAttempts"].as_u64(), identity["facts"]["ssoFailed"].as_u64()), (Some(10), Some(1)), "{identity:#}");
    assert_eq!(identity["status"], "watch", "10% of sign-ins failed");
    assert_eq!(identity["facts"]["scimUnauthenticated"], 1);

    let approvals = signal(&r, "approvals");
    assert_eq!((approvals["facts"]["requested"].as_u64(), approvals["facts"]["expired"].as_u64()), (Some(10), Some(1)));
    assert_eq!(approvals["status"], "watch");

    assert_eq!(r["atRisk"], json!(["runs"]));
    assert_eq!(signal(&r, "backups")["status"], "watch", "no server backups in tests");
    // (25 + 20 + 20 + 10) * 50 points over 95, runs at 0, license n/a in testing mode.
    assert_eq!((r["score"].as_u64(), r["band"].as_str()), (Some(39), Some("at_risk")), "{r:#}");
    assert!(!body.contains("customer.example.com"), "no email: {body}");
    assert!(!body.contains("Walker"), "no Bot names: {body}");
}

#[test]
fn audit_counts_start_where_asked_and_never_say_who() {
    let app = runner::test_app();
    let mut actor = Actor::operator().method("sso");
    actor.email = Some("someone@example.com".into());
    app.db.record(&Event::new(actor, "auth.login_failed").outcome(Outcome::Failure).details(json!({ "reason": "not_linked" })));
    app.db.record(&Event::new(Actor::system("x"), "bot.run_finished").details(json!({ "result": "done", "reason": "ignored" })));
    app.db.record(&Event::new(Actor::system("x"), "scim.user_linked"));
    app.db.record(&Event::new(Actor::system("x"), "unrelated.thing"));
    let counts = app.db.audit_counts(db::now() - 60_000, &["auth.login_failed", "bot.run_finished", "scim.*"]);
    let seen: Vec<(&str, &str, Option<&str>, Option<&str>, u64)> = counts.iter().map(|c| (c.action.as_str(), c.outcome.as_str(), c.method.as_deref(), c.code.as_deref(), c.n)).collect();
    assert_eq!(seen, [("auth.login_failed", "failure", Some("sso"), Some("not_linked"), 1), ("bot.run_finished", "success", None, Some("done"), 1), ("scim.user_linked", "success", None, None, 1)]);
    assert!(app.db.audit_counts(db::now() + 60_000, &["auth.login_failed", "bot.run_finished", "scim.*"]).is_empty());
    assert!(app.db.audit_counts(0, &[]).is_empty());
}

#[test]
fn throttled_sign_in_failures_count_with_the_ones_not_logged() {
    let app = runner::test_app();
    let fail = |missed: u64| Event::new(Actor::operator().method("sso"), "auth.login_failed").outcome(Outcome::Failure).details(json!({ "reason": "bad_signature", "unloggedSinceLast": missed }));
    app.db.record(&fail(0));
    app.db.record(&fail(40));
    for _ in 0..60 {
        app.db.record(&Event::new(Actor::operator().method("sso"), "auth.login"));
    }
    let counts = app.db.audit_counts(db::now() - 60_000, &["auth.login_failed"]);
    assert_eq!((counts.iter().map(|c| c.n).sum::<u64>(), counts.iter().map(|c| c.skipped).sum::<u64>()), (2, 40), "{counts:?}");
    let r = crate::health_score::build(&app, db::now(), 30);
    let identity = r["signals"].as_array().unwrap().iter().find(|s| s["id"] == "identity").unwrap();
    assert_eq!((identity["facts"]["ssoFailed"].as_u64(), identity["facts"]["ssoAttempts"].as_u64()), (Some(42), Some(102)), "{identity:#}");
    assert_eq!(identity["status"], "risk", "a certificate rollover's failures aren't hidden by the throttle: {identity:#}");
    assert_eq!(identity["facts"]["ssoReasons"], json!([{ "code": "throttled", "count": 40 }, { "code": "bad_signature", "count": 2 }]), "the skipped ones' reasons aren't known");
}

#[test]
fn bad_tokens_not_logged_never_count_as_a_revoked_one() {
    let app = runner::test_app();
    let bad = |reason: &str, missed: u64| Event::new(Actor::system("scim").method("scim_token"), "scim.auth_failed").outcome(Outcome::Failure).details(json!({ "reason": reason, "unloggedSinceLast": missed }));
    app.db.record(&bad("unknown", 0));
    app.db.record(&bad("revoked", 10));
    let r = crate::health_score::build(&app, db::now(), 30);
    let identity = r["signals"].as_array().unwrap().iter().find(|s| s["id"] == "identity").unwrap();
    assert_eq!((identity["facts"]["scimFailed"].as_u64(), identity["facts"]["scimUnauthenticated"].as_u64()), (Some(1), Some(11)), "{identity:#}");
    assert_eq!(identity["status"], "watch", "one revoked token in use, not eleven: {identity:#}");
}
