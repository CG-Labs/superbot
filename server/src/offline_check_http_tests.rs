//! `botctl offline check` on the real router (ADR 0266): admins only (no custom role reaches
//! it), audited, and a setting saved from the console or with `botctl secret set` is judged
//! where it points, never shown.

use crate::scim_http_tests::events;
use crate::tests::{call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

#[tokio::test]
async fn only_admins_run_it_and_each_run_is_audited() {
    let (port, app, admin, key) = serve_app().await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;
    let (delegate_id, delegate) = user_with(port, &admin, "d@example.com", "member").await;
    let every = ["users.manage", "bots.manage", "audit.view", "billing.manage", "signups.approve", "machines.manage"];
    let (code, role) = call(port, "POST", "/api/roles", &admin, &json!({ "name": "Everything delegable", "permissions": every }).to_string()).await;
    assert_eq!(code, 201, "{role}");
    let path = format!("/api/roles/{}/users/{delegate_id}", parse(&role)["id"].as_str().unwrap());
    assert_eq!(call(port, "PUT", &path, &admin, "").await.0, 200);
    let bot = app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false);
    for (who, auth) in [("member", member.as_str()), ("custom role", delegate.as_str()), ("bot", key.auth(&bot.id).as_str())] {
        assert_eq!(call(port, "GET", "/api/offline-check", auth, "").await.0, 403, "{who}");
    }
    assert_eq!(call(port, "GET", "/api/offline-check", "", "").await.0, 401);

    let (code, body) = call(port, "GET", "/api/offline-check?internal=corp.example,10.20.0.0/16", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let r = parse(&body);
    assert_eq!(r["format"], offline_check::FORMAT);
    assert_eq!(r["internal"], json!(["corp.example", "10.20.0.0/16"]));
    assert_eq!(r["settings"]["running"], true);
    assert!(r["text"].as_str().unwrap().starts_with("botctl offline check: what the running botd reaches"), "{r:#}");
    let areas: Vec<&str> = r["findings"].as_array().unwrap().iter().map(|f| f["area"].as_str().unwrap()).collect();
    for a in offline_check::Area::ALL {
        assert!(areas.contains(&a.id()), "{} is in the report: {r:#}", a.id());
    }
    let checked = events(port, &admin, &format!("action={}", offline_check::CHECKED)).await;
    assert_eq!(checked.len(), 1, "{checked:#?}");
    assert_eq!(checked[0]["details"]["counts"], r["counts"]);
    assert_eq!(checked[0]["details"]["offline"], r["offline"]);
    assert_eq!(checked[0]["details"]["internal"], r["internal"]);
}

#[tokio::test]
async fn bad_parameters_are_refused_and_not_recorded() {
    let (port, _, admin, _) = serve_app().await;
    let (code, body) = call(port, "GET", "/api/offline-check?days=1", &admin, "").await;
    assert_eq!(code, 400, "{body}");
    assert!(parse(&body)["error"].as_str().unwrap().starts_with("Unknown parameter \"days\""), "{body}");
    let (code, body) = call(port, "GET", "/api/offline-check?internal=a..b", &admin, "").await;
    assert_eq!(code, 400, "{body}");
    assert!(parse(&body)["error"].as_str().unwrap().starts_with("internal: \"a..b\" is neither"), "{body}");
    assert!(events(port, &admin, &format!("action={}", offline_check::CHECKED)).await.is_empty());
}

#[tokio::test]
async fn a_webhook_saved_from_the_console_is_judged_where_it_points() {
    let (port, _, admin, _) = serve_app().await;
    let name = format!("NOTIFY_WEBHOOK_URL_BOT_{}", random_hex(4).to_ascii_uppercase());
    let hook = format!("https://hooks.slack.com/services/T0/B0/{}", random_hex(12));
    let (code, body) = call(port, "PUT", &format!("/api/secrets/{name}"), &admin, &json!({ "value": hook }).to_string()).await;
    assert_eq!(code, 200, "{body}");

    let (code, body) = call(port, "GET", "/api/offline-check", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    assert!(!body.contains(&hook) && !body.contains("services/T0"), "the URL itself is never shown: {body}");
    let r = parse(&body);
    let f = r["findings"].as_array().unwrap().iter().find(|f| f["setting"] == name.as_str()).unwrap_or_else(|| panic!("{r:#}"));
    assert_eq!((f["status"].as_str(), f["host"].as_str(), f["from"].as_str()), (Some("internet"), Some("hooks.slack.com"), Some("sealed")));
    assert_eq!(r["offline"], false);
    assert_eq!(r["settings"]["from"][&name], "sealed");
    assert!(r["text"].as_str().unwrap().contains(&format!("{name} (saved in botd): Approval notices at hooks.slack.com: Slack, on the internet")), "{r:#}");
    let checked = events(port, &admin, &format!("action={}", offline_check::CHECKED)).await;
    assert!(checked[0]["details"]["internet"].as_array().unwrap().iter().any(|s| s == name.as_str()), "{checked:#?}");
    assert!(!format!("{checked:?}").contains(&hook));

    assert_eq!(call(port, "DELETE", &format!("/api/secrets/{name}"), &admin, "").await.0, 200);
    crate::secrets::redact::forget(&hook);
}
