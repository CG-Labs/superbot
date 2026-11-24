//! The monthly health check (ADR 0252) on the real router: admins only (no custom role
//! reaches it, ADR 0123), audited, judged from what botd recorded, and never a name, an
//! email or an incident's title.

use crate::audit::{Actor, Event};
use crate::scim_http_tests::events;
use crate::tests::{call, serve_app, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

fn item<'a>(r: &'a Value, id: &str) -> &'a Value {
    r["items"].as_array().unwrap().iter().find(|i| i["id"] == id).unwrap_or_else(|| panic!("no {id} in {r:#}"))
}

#[tokio::test]
async fn only_admins_get_it_and_each_check_is_audited() {
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
        assert_eq!(call(port, "GET", "/api/support/health-check", auth, "").await.0, 403, "{who}");
    }
    assert_eq!(call(port, "GET", "/api/support/health-check", "", "").await.0, 401);

    let (code, body) = call(port, "GET", "/api/support/health-check", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!(r["format"], health_check::FORMAT);
    let ids: Vec<&str> = r["items"].as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert_eq!(ids, health_check::ITEMS.iter().map(|i| i.id).collect::<Vec<_>>());
    assert_eq!(r["clear"], false, "a test server has its backups to set up: {r:#}");
    assert_eq!(item(&r, "backups")["status"], "open");
    assert_eq!(item(&r, "machine_recovery")["status"], "n/a", "no machines");
    assert_eq!(item(&r, "saml")["status"], "n/a", "no native SAML provider");
    assert_eq!(item(&r, "roles")["detail"], "1 custom role; 1 person holds one across the server, 0 time-bound: confirm each still needs it.");
    assert!(item(&r, "version")["detail"].as_str().unwrap().starts_with(&format!("botd {}. ", env!("CARGO_PKG_VERSION"))), "{r:#}");

    let checked = events(port, &admin, "action=support.health_checked").await;
    assert_eq!(checked.len(), 1, "{checked:#?}");
    assert_eq!(checked[0]["details"]["clear"], false);
    assert_eq!(checked[0]["details"]["open"], r["open"]);
    assert_eq!(checked[0]["details"]["counts"], r["counts"]);
    assert_eq!(checked[0]["details"]["score"], r["score"]);
}

#[tokio::test]
async fn parameters_are_refused_and_not_recorded() {
    let (port, _, admin, _) = serve_app().await;
    let (code, body) = call(port, "GET", "/api/support/health-check?days=90", &admin, "").await;
    assert_eq!(code, 400, "{body}");
    assert!(parse(&body)["error"].as_str().unwrap().starts_with("Unknown parameter \"days\""), "{body}");
    let (code, body) = call(port, "GET", "/api/support/health-check?jane%40example.com=1", &admin, "").await;
    assert_eq!(code, 400, "{body}");
    assert!(parse(&body)["error"].as_str().unwrap().contains("\"[text]\""), "a typed address is never echoed: {body}");
    assert!(events(port, &admin, "action=support.health_checked").await.is_empty(), "refused checks aren't recorded");
}

#[tokio::test]
async fn it_follows_what_botd_recorded() {
    let (port, app, admin, _) = serve_app_with(|a| a.scim.enabled = true).await;
    let r = parse(&call(port, "GET", "/api/support/health-check", &admin, "").await.1);
    assert_eq!(item(&r, "scim")["status"], "open");
    assert!(item(&r, "scim")["detail"].as_str().unwrap().starts_with("SCIM is on, but no tenant has a working token"), "{r:#}");
    assert_eq!(item(&r, "incidents")["status"], "done");
    assert_eq!(item(&r, "usage")["status"], "done");
    assert_eq!(item(&r, "access_review")["status"], "confirm");

    // A major incident with no review, a minor one resolved, runs refused at a plan's
    // limit, and an access review signed off.
    let incident = |impact: &str| json!({ "title": "Runs failing for Ada Lovelace", "body": "We're looking into it.", "impact": impact }).to_string();
    let (code, major) = call(port, "POST", "/api/status/incidents", &admin, &incident("major")).await;
    assert_eq!(code, 201, "{major}");
    let major = parse(&major)["id"].as_str().unwrap().to_string();
    let (code, minor) = call(port, "POST", "/api/status/incidents", &admin, &incident("minor")).await;
    assert_eq!(code, 201, "{minor}");
    let minor = parse(&minor)["id"].as_str().unwrap().to_string();
    let resolve = json!({ "state": "resolved", "body": "Fixed." }).to_string();
    assert_eq!(call(port, "POST", &format!("/api/status/incidents/{minor}/updates"), &admin, &resolve).await.0, 201);
    for reason in ["tier_limit", "tier_limit", "storage_limit", "egress_policy_pending"] {
        app.db.record(&Event::new(Actor::system("runner"), "bot.run_refused").outcome(audit::Outcome::Denied).details(json!({ "reason": reason })));
    }
    app.db.record(&Event::new(Actor::system("botd"), access_review::COMPLETED));

    let (code, body) = call(port, "GET", "/api/support/health-check", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!(item(&r, "incidents")["status"], "open");
    assert_eq!(
        item(&r, "incidents")["detail"],
        format!("Still open on the status page: {major}; of major or critical impact with no review drafted: {major} (botctl incident review).")
    );
    assert_eq!(item(&r, "usage")["status"], "open");
    assert!(item(&r, "usage")["detail"].as_str().unwrap().starts_with("In the last 30 days, 3 runs were refused at a plan's limit (tier_limit 2, storage_limit 1):"), "{r:#}");
    assert_eq!(item(&r, "access_review")["detail"], "An access review was signed off 0 days ago.");
    assert!(!body.contains("Ada") && !body.contains("example.com"), "no name, email or incident title: {body}");

    // Its review drafted and the incident resolved: nothing left about incidents.
    assert_eq!(call(port, "GET", &format!("/api/status/incidents/{major}/review"), &admin, "").await.0, 200);
    assert_eq!(call(port, "POST", &format!("/api/status/incidents/{major}/updates"), &admin, &resolve).await.0, 201);
    let r = parse(&call(port, "GET", "/api/support/health-check", &admin, "").await.1);
    assert_eq!(item(&r, "incidents")["status"], "done", "{:#}", item(&r, "incidents"));
    assert_eq!(item(&r, "incidents")["detail"], "No open incident; 2 incidents resolved in the last 31 days, each major or critical one with a review drafted.");
}
