//! The quarterly business review draft (ADR 0262) on the real router: admins only (no
//! custom role reaches it, ADR 0123), audited, drafted from what botd recorded, as JSON or
//! a Markdown download, and never a name, an email or an incident's title.

use crate::audit::{Actor, Event, Outcome};
use crate::business_review::Ym;
use crate::scim_http_tests::events;
use crate::tests::{call, call_with, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

fn this_month() -> String {
    Ym::of_ms(db::now()).id()
}

#[tokio::test]
async fn only_admins_draft_it_and_each_draft_is_audited() {
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
        assert_eq!(call(port, "GET", "/api/support/business-review", auth, "").await.0, 403, "{who}");
    }
    assert_eq!(call(port, "GET", "/api/support/business-review", "", "").await.0, 401);

    let (code, body) = call(port, "GET", "/api/support/business-review", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    let last = Ym::of_ms(db::now()).plus(-1);
    assert_eq!((r["format"].clone(), r["to"].clone(), r["from"].clone(), r["soFar"].clone()), (json!(business_review::FORMAT), json!(last.id()), json!(last.plus(-2).id()), json!(false)));
    assert_eq!(r["months"].as_array().unwrap().len(), 3);
    assert_eq!(r["version"], env!("CARGO_PKG_VERSION"));

    let (code, head, md) = call_with(port, "GET", &format!("/api/support/business-review?to={}&format=markdown", this_month()), &admin, "", "").await;
    assert_eq!(code, 200, "{md}");
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("content-type: text/markdown"), "{head}");
    let first = Ym::of_ms(db::now()).plus(-2).id();
    assert!(lower.contains(&format!("content-disposition: attachment; filename=\"business-review-{first}-to-{}.md\"", this_month())), "{head}");
    assert!(lower.contains("cache-control: no-store"), "{head}");
    assert!(md.starts_with("# `<customer>`: business review, ") && md.contains("**The quarter isn't over**") && md.contains("## 7. Actions"), "{md}");

    let drafted = events(port, &admin, "action=support.business_review_drafted").await;
    assert_eq!(drafted.len(), 2, "{drafted:#?}");
    assert_eq!(drafted[0]["details"], json!({ "from": first, "to": this_month(), "soFar": true, "format": "markdown", "incidents": 0, "healthChecks": 0 }));
    assert_eq!(drafted[1]["details"]["format"], "json");
}

#[tokio::test]
async fn bad_parameters_are_refused_and_not_recorded() {
    let (port, _, admin, _) = serve_app().await;
    let next = Ym::of_ms(db::now()).plus(1).id();
    for (path, want) in [
        ("/api/support/business-review?days=90".to_string(), "Unknown parameter \"days\""),
        ("/api/support/business-review?jane%40example.com=1".to_string(), "Unknown parameter \"[text]\""),
        (format!("/api/support/business-review?to={next}"), "to can't be after this month"),
        ("/api/support/business-review?to=Q3".to_string(), "to must be a month, YYYY-MM"),
        ("/api/support/business-review?format=pdf".to_string(), "format must be json or markdown"),
    ] {
        let (code, body) = call(port, "GET", &path, &admin, "").await;
        assert_eq!(code, 400, "{path}: {body}");
        assert!(parse(&body)["error"].as_str().unwrap().starts_with(want), "{path}: {body}");
    }
    assert!(events(port, &admin, "action=support.business_review_drafted").await.is_empty(), "refused drafts aren't recorded");
}

#[tokio::test]
async fn it_drafts_from_what_botd_recorded() {
    let (port, app, admin, _) = serve_app().await;
    let claude = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    let codex = app.db.create_bot("Runner", "#fff", "waddle", "codex", None, false);
    let run = |bot: &str, result: &str| {
        let outcome = if result == "done" { Outcome::Success } else { Outcome::Failure };
        app.db.record(&Event::new(Actor::system("runner"), "bot.run_finished").bot(bot).outcome(outcome).details(json!({ "result": result })));
    };
    for _ in 0..8 {
        run(&claude.id, "done");
    }
    run(&claude.id, "error");
    run(&codex.id, "done");
    run(&codex.id, "timeout");
    // Runs are counted under the harness that ran them, even once their Bot moved on or went.
    let ran = |bot: &str, harness: &str, run_id: &str| {
        app.db.record(&Event::new(Actor::system("runner"), "bot.run_finished").bot(bot).outcome(Outcome::Success).details(json!({ "result": "done", "runId": run_id })));
        let row = crate::db::TokenRow {
            user_id: "u".into(),
            bot_id: bot.into(),
            run_id: run_id.into(),
            message_id: None,
            harness: harness.into(),
            model: None,
            reported: false,
            input: 0,
            output: 0,
            cache_read: 0,
            cache_write: 0,
            at: crate::db::now(),
            meter: None,
        };
        app.db.record_tokens(&[row]).unwrap();
    };
    ran(&codex.id, "hermes", "run_before_the_switch");
    let gone = app.db.create_bot("Gone", "#fff", "waddle", "codex", None, false);
    ran(&gone.id, "codex", "run_of_a_deleted_bot");
    run(&gone.id, "done");
    app.db.delete_bot(&gone.id);
    for reason in ["tier_limit", "storage_limit", "egress_policy_pending"] {
        app.db.record(&Event::new(Actor::system("runner"), "bot.run_refused").outcome(Outcome::Denied).details(json!({ "reason": reason })));
    }
    app.db.record(&Event::new(Actor::system("botd"), access_review::COMPLETED));
    // One custom role given, which changes the person's built-in role too, and one built-in role changed.
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (bea, _) = user_with(port, &admin, "bea@example.com", "member").await;
    let (code, role) = call(port, "POST", "/api/roles", &admin, &json!({ "name": "Auditor", "base": "readonly", "permissions": ["audit.view"] }).to_string()).await;
    assert_eq!(code, 201, "{role}");
    assert_eq!(call(port, "PUT", &format!("/api/roles/{}/users/{ada}", parse(&role)["id"].as_str().unwrap()), &admin, "").await.0, 200);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{bea}"), &admin, r#"{"role":"readonly"}"#).await.0, 200);
    assert_eq!(events(port, &admin, "action=user.role_changed").await.len(), 2, "the grant wrote role.assigned and user.role_changed");
    let incident = json!({ "title": "Runs failing for Ada Lovelace", "body": "We're looking into it.", "impact": "major" }).to_string();
    let (code, major) = call(port, "POST", "/api/status/incidents", &admin, &incident).await;
    assert_eq!(code, 201, "{major}");
    let major = parse(&major)["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "GET", "/api/support/health-check", &admin, "").await.0, 200);

    let path = format!("/api/support/business-review?to={}", this_month());
    let (code, body) = call(port, "GET", &path, &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    let now = &r["months"][2];
    assert_eq!((now["month"].clone(), now["soFar"].clone()), (json!(this_month()), json!(true)));
    assert_eq!((now["runsFinished"].clone(), now["runsFailed"].clone(), now["refusedAtLimit"].clone()), (json!(14), json!(2), json!(2)), "{now:#}");
    assert_eq!(now["healthChecks"], 1);
    assert!(now["lastCheck"]["open"].as_array().unwrap().contains(&json!("incidents")), "the check saw the incident: {now:#}");
    assert_eq!(
        r["harnesses"],
        json!([
            { "harness": "claude", "finished": 9, "failed": 1 },
            { "harness": "codex", "finished": 3, "failed": 1 },
            { "harness": "hermes", "finished": 1, "failed": 0 },
            { "harness": "unrecorded", "finished": 1, "failed": 0 },
        ])
    );
    assert_eq!(r["incidents"].as_array().unwrap().len(), 1);
    assert_eq!((r["incidents"][0]["id"].as_str(), r["incidents"][0]["reviewed"].as_bool()), (Some(major.as_str()), Some(false)));
    assert_eq!(r["accessReviews"].as_array().unwrap().len(), 1);
    assert_eq!((r["changes"]["customRoles"].clone(), r["changes"]["roleGrants"].clone()), (json!(1), json!(2)), "each change once: {:#}", r["changes"]);

    let (_, md) = call(port, "GET", &format!("{path}&format=markdown"), &admin, "").await;
    for want in [
        format!("**no**: `botctl incident review {major}`"),
        format!("| Resolve incident `{major}`, still open |"),
        "`claude` 9 runs, 1 (11%) failed or timed out; `codex` 3 runs, 1 (33%) failed or timed out; `hermes` 1 run, 0 (0%) failed or timed out; Deleted Bots, harness not recorded: 1 run, 0 (0%) failed or timed out.".into(),
        "- Access review signed off on ".into(),
    ] {
        assert!(md.contains(&want), "no {want:?} in:\n{md}");
    }

    // Reviewed and resolved: nothing left to act on for it.
    assert_eq!(call(port, "GET", &format!("/api/status/incidents/{major}/review"), &admin, "").await.0, 200);
    let resolve = json!({ "state": "resolved", "body": "Fixed." }).to_string();
    assert_eq!(call(port, "POST", &format!("/api/status/incidents/{major}/updates"), &admin, &resolve).await.0, 201);
    let (_, md) = call(port, "GET", &format!("{path}&format=markdown"), &admin, "").await;
    assert!(md.contains(" | yes |") && !md.contains(&format!("incident `{major}`")), "{md}");
    for text in [body.as_str(), md.as_str()] {
        assert!(!text.contains("Ada") && !text.contains("example.com"), "no name, email or incident title: {text}");
    }
}

#[tokio::test]
async fn records_it_cant_read_are_no_draft_rather_than_none() {
    let (port, app, admin, _) = serve_app().await;
    app.db.drop_table("status_incidents");
    let (code, body) = call(port, "GET", "/api/support/business-review?format=markdown", &admin, "").await;
    assert_eq!(code, 500, "{body}");
    assert!(body.contains("Couldn't read botd's records for the business review") && !body.contains("No status page incident"), "{body}");
    assert!(events(port, &admin, "action=support.business_review_drafted").await.is_empty(), "a draft that failed isn't recorded");
}
