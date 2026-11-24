//! The onboarding check (ADR 0233) on the real router: admins only (no custom role reaches
//! it, ADR 0123), audited, judged from what botd recorded, and never a name or email.

use crate::audit::{Actor, Event};
use crate::scim_http_tests::{events, okta_user, scim, token};
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
        assert_eq!(call(port, "GET", "/api/support/onboarding", auth, "").await.0, 403, "{who}");
    }
    assert_eq!(call(port, "GET", "/api/support/onboarding", "", "").await.0, 401);

    let (code, body) = call(port, "GET", "/api/support/onboarding", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!(r["format"], onboarding::FORMAT);
    let ids: Vec<&str> = r["items"].as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert_eq!(ids, onboarding::ITEMS.iter().map(|i| i.id).collect::<Vec<_>>());
    assert_eq!(r["ready"], false, "a test server isn't ready to go live: {r:#}");
    assert_eq!(item(&r, "idp")["status"], "open", "no SSO provider");
    assert_eq!(item(&r, "first_bundle")["status"], "open");
    assert_eq!(item(&r, "hardening")["status"], "n/a", "no machines");

    let checked = events(port, &admin, "action=support.onboarding_checked").await;
    assert_eq!(checked.len(), 1, "{checked:#?}");
    assert_eq!(checked[0]["details"]["ready"], false);
    assert_eq!(checked[0]["details"]["open"], r["open"]);
    assert_eq!(checked[0]["details"]["counts"], r["counts"]);
}

#[tokio::test]
async fn skips_and_parameters_are_checked() {
    let (port, _, admin, _) = serve_app().await;
    let (code, body) = call(port, "GET", "/api/support/onboarding?skip=database_encryption,scim", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!(item(&r, "database_encryption")["status"], "skipped");
    assert_eq!(item(&r, "scim")["status"], "skipped", "SCIM off is to confirm, and confirmed by skipping it");
    assert!(r["skipped"].as_array().unwrap().contains(&json!("scim")), "{r:#}");
    for (q, want) in [("skip=nope", "skip: no item \"nope\""), ("days=30", "Unknown parameter \"days\"")] {
        let (code, body) = call(port, "GET", &format!("/api/support/onboarding?{q}"), &admin, "").await;
        assert_eq!(code, 400, "{q}: {body}");
        assert!(parse(&body)["error"].as_str().unwrap().starts_with(want), "{q}: {body}");
    }
    assert_eq!(events(port, &admin, "action=support.onboarding_checked").await.len(), 1, "refused checks aren't recorded");
}

#[tokio::test]
async fn it_follows_what_botd_recorded() {
    let (port, app, admin, _) = serve_app_with(|a| a.scim.enabled = true).await;
    let (code, body) = call(port, "GET", "/api/support/onboarding", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!(item(&r, "scim")["status"], "open");
    assert!(item(&r, "scim")["detail"].as_str().unwrap().contains("no tenant has a working token"), "{r:#}");
    assert_eq!(item(&r, "break_glass")["status"], "open", "the test server signs in with the break-glass password");
    assert_eq!(item(&r, "metrics")["status"], "open", "no server.started with metrics");

    // A SCIM connection that has deprovisioned someone, a support bundle, metrics on,
    // a machine restore, and a team.
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let (code, _, user) = scim(port, &t, "POST", "/scim/v2/Users", okta_user("ada@customer.example.com", "00u1")).await;
    assert_eq!(code, 201, "{user}");
    let patch = json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{ "op": "replace", "value": { "active": false } }] });
    let (code, _, res) = scim(port, &t, "PATCH", &format!("/scim/v2/Users/{}", user["id"].as_str().unwrap()), patch).await;
    assert_eq!(code, 200, "{res}");
    assert_eq!(call(port, "GET", "/api/support/bundle", &admin, "").await.0, 200);
    app.db.record(&Event::new(Actor::system("botd"), "server.started").details(json!({ "metrics": { "loopback": true, "token": false } })));
    app.db.record(&Event::new(Actor::system("machines"), "machine.restored"));
    app.db.create_team("Research", None);

    let (code, body) = call(port, "GET", "/api/support/onboarding", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!(item(&r, "scim")["status"], "done", "{:#}", item(&r, "scim"));
    assert_eq!(item(&r, "scim")["detail"], "1 working token, used in the last 30 days; SCIM has deprovisioned 1 person.");
    assert_eq!(item(&r, "first_bundle")["status"], "done");
    assert_eq!(item(&r, "metrics")["status"], "done");
    assert!(item(&r, "restore_drill")["detail"].as_str().unwrap().starts_with("botd recorded 1 machine restore "), "{r:#}");
    assert!(item(&r, "teams")["detail"].as_str().unwrap().starts_with("1 team on this server"), "{r:#}");
    assert!(!body.contains("customer.example.com") && !body.contains("Ada") && !body.contains("Research"), "no name or email: {body}");

    // Bypass turns approvals open.
    let (code, res) = call(port, "PUT", "/api/policy", &admin, &json!({ "mode": "bypass" }).to_string()).await;
    assert_eq!(code, 200, "{res}");
    let r = parse(&call(port, "GET", "/api/support/onboarding", &admin, "").await.1);
    assert!(item(&r, "approvals")["detail"].as_str().unwrap().starts_with("Approvals are off (bypass)"), "{r:#}");
}

#[tokio::test]
async fn an_admin_who_signed_in_with_sso_counts() {
    let id = format!("h{}", random_hex(4));
    let up = id.to_ascii_uppercase();
    crate::secrets::global().put(&format!("SSO_{up}_CLIENT_SECRET"), "client-secret").unwrap();
    let vars = HashMap::from([("SSO_PROVIDERS".to_string(), id.clone()), (format!("SSO_{up}_TYPE"), "github".into()), (format!("SSO_{up}_CLIENT_ID"), "client".into())]);
    let (port, app, admin) = crate::sso_http_tests::serve_vars(vars).await;
    let (ada, _) = user_with(port, &admin, "ada@customer.example.com", "admin").await;
    let r = parse(&call(port, "GET", "/api/support/onboarding", &admin, "").await.1);
    assert_eq!(item(&r, "idp")["status"], "done", "{:#}", item(&r, "idp"));
    assert_eq!(item(&r, "sso_admin")["status"], "open");
    let mut actor = Actor { kind: audit::ActorKind::User, id: Some(ada.clone()), email: Some("ada@customer.example.com".into()), ..Default::default() }.method("sso");
    actor.role = Some("admin".into());
    app.db.record(&Event::new(actor, "auth.login"));
    let r = parse(&call(port, "GET", "/api/support/onboarding", &admin, "").await.1);
    assert_eq!(item(&r, "sso_admin")["status"], "done", "{:#}", item(&r, "sso_admin"));
    assert_eq!(item(&r, "sso_admin")["detail"], "1 of 1 admin besides the owner has signed in with SSO.");
}
