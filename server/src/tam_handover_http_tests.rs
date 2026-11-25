//! The TAM handover draft (ADR 0278) on the real router: admins only (no custom role
//! reaches it, ADR 0123), audited, drafted from what botd recorded, as JSON or a Markdown
//! download, and never a name, an email or an incident's title.

use crate::audit::{Actor, Event};
use crate::scim_http_tests::events;
use crate::tests::{call, call_with, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

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
        assert_eq!(call(port, "GET", "/api/support/tam-handover", auth, "").await.0, 403, "{who}");
    }
    assert_eq!(call(port, "GET", "/api/support/tam-handover", "", "").await.0, 401);

    let (code, body) = call(port, "GET", "/api/support/tam-handover", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!((r["format"].clone(), r["guide"].clone()), (json!(tam_handover::FORMAT), json!(tam_handover::GUIDE)));
    assert_eq!(r["deployment"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(r["deployment"]["harnesses"], json!([{ "harness": "claude", "bots": 1 }]));
    let whats: Vec<&str> = r["dates"].as_array().unwrap().iter().filter_map(|d| d["what"].as_str()).collect();
    assert!(whats.contains(&"health_check") && whats.contains(&"business_review") && whats.contains(&"access_review"), "{whats:?}");

    let (code, head, md) = call_with(port, "GET", "/api/support/tam-handover?format=markdown", &admin, "", "").await;
    assert_eq!(code, 200, "{md}");
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("content-type: text/markdown"), "{head}");
    assert!(lower.contains(&format!("content-disposition: attachment; filename=\"tam-handover-{}.md\"", health_history::date_of(db::now()))), "{head}");
    assert!(lower.contains("cache-control: no-store"), "{head}");
    assert!(md.starts_with("# `<customer>`: TAM handover") && md.contains("## 5. Upcoming dates"), "{md}");

    let drafted = events(port, &admin, "action=support.tam_handover_drafted").await;
    assert_eq!(drafted.len(), 2, "{drafted:#?}");
    assert_eq!(drafted[0]["details"]["format"], "markdown");
    assert_eq!(drafted[1]["details"]["format"], "json");
    assert!(events(port, &admin, "action=support.health_checked").await.is_empty(), "a handover isn't the TAM's monthly check");
}

#[tokio::test]
async fn bad_parameters_are_refused_and_not_recorded() {
    let (port, _, admin, _) = serve_app().await;
    for (path, want) in [
        ("/api/support/tam-handover?days=90", "Unknown parameter \"days\""),
        ("/api/support/tam-handover?jane%40example.com=1", "Unknown parameter \"[text]\""),
        ("/api/support/tam-handover?format=pdf", "format must be json or markdown"),
    ] {
        let (code, body) = call(port, "GET", path, &admin, "").await;
        assert_eq!(code, 400, "{path}: {body}");
        assert!(parse(&body)["error"].as_str().unwrap().starts_with(want), "{path}: {body}");
        assert!(!body.contains("jane"), "{body}");
    }
    assert!(events(port, &admin, "action=support.tam_handover_drafted").await.is_empty(), "refused drafts aren't recorded");
}

#[tokio::test]
async fn it_drafts_from_what_botd_recorded() {
    let (port, app, admin, _) = serve_app().await;
    app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    app.db.create_bot("Runner", "#fff", "waddle", "codex", None, false);
    app.db.create_bot("Strider", "#fff", "waddle", "claude", None, false);
    app.db.record(&Event::new(Actor::system("botd"), access_review::COMPLETED));
    let incident = json!({ "title": "Runs failing for Ada Lovelace", "body": "We're looking into it.", "impact": "major" }).to_string();
    let (code, major) = call(port, "POST", "/api/status/incidents", &admin, &incident).await;
    assert_eq!(code, 201, "{major}");
    let major = parse(&major)["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "GET", "/api/support/health-check", &admin, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/support/business-review", &admin, "").await.0, 200);

    let (code, body) = call(port, "GET", "/api/support/tam-handover", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!(r["deployment"]["harnesses"], json!([{ "harness": "claude", "bots": 2 }, { "harness": "codex", "bots": 1 }]));
    assert!(r["lastHealthCheck"]["open"].as_array().unwrap().contains(&json!("incidents")), "{:#}", r["lastHealthCheck"]);
    let last = business_review::Ym::of_ms(db::now()).plus(-1);
    assert_eq!(r["lastBusinessReview"]["to"], json!(last.id()));
    let open: Vec<&str> = r["open"].as_array().unwrap().iter().filter_map(|o| o["id"].as_str()).collect();
    assert!(open.contains(&"incidents"), "{open:?}");
    assert_eq!(r["incidents"].as_array().unwrap().len(), 1);
    assert_eq!((r["incidents"][0]["id"].as_str(), r["incidents"][0]["reviewed"].as_bool()), (Some(major.as_str()), Some(false)));
    let due = |what: &str| r["dates"].as_array().unwrap().iter().find(|d| d["what"] == what).cloned().unwrap_or_else(|| panic!("no {what}: {:#}", r["dates"]));
    assert_eq!(due("business_review")["on"], json!(business_review::date(last.plus(4).start_ms())));
    assert_eq!(due("access_review")["overdue"], json!(false));

    let (_, md) = call(port, "GET", "/api/support/tam-handover?format=markdown", &admin, "").await;
    for want in [format!("| `{major}` | major |"), format!("resolve it; `botctl incident review {major}`"), "`claude` 2, `codex` 1".into()] {
        assert!(md.contains(&want), "no {want:?} in:\n{md}");
    }
    let drafted = events(port, &admin, "action=support.tam_handover_drafted").await;
    assert_eq!(drafted[0]["details"]["incidents"], 1);
    assert!(drafted[0]["details"]["open"].as_array().unwrap().contains(&json!("incidents")), "{:#}", drafted[0]["details"]);

    // Reviewed and resolved: nothing left to hand over for it.
    assert_eq!(call(port, "GET", &format!("/api/status/incidents/{major}/review"), &admin, "").await.0, 200);
    let resolve = json!({ "state": "resolved", "body": "Fixed." }).to_string();
    assert_eq!(call(port, "POST", &format!("/api/status/incidents/{major}/updates"), &admin, &resolve).await.0, 201);
    let (_, md) = call(port, "GET", "/api/support/tam-handover?format=markdown", &admin, "").await;
    assert!(!md.contains(&major) && md.contains("- No status page incident is open"), "{md}");
    for text in [body.as_str(), md.as_str()] {
        assert!(!text.contains("Ada") && !text.contains("example.com") && !text.contains("Walker"), "no name, email, Bot name or incident title: {text}");
    }
}

#[tokio::test]
async fn records_it_cant_read_are_no_draft_rather_than_none() {
    let (port, app, admin, _) = serve_app().await;
    app.db.drop_table("status_incidents");
    let (code, body) = call(port, "GET", "/api/support/tam-handover?format=markdown", &admin, "").await;
    assert_eq!(code, 500, "{body}");
    assert!(body.contains("Couldn't read botd's records for the handover") && !body.contains("No status page incident"), "{body}");
    assert!(events(port, &admin, "action=support.tam_handover_drafted").await.is_empty(), "a draft that failed isn't recorded");
}
