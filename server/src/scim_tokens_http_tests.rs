//! SCIM tokens expire and rotate (ADR 0195): the real router and audit log.

use crate::scim_http_tests::{events, okta_user, scim, token};
use crate::tests::{call, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const USERS: &str = "/scim/v2/Users";
const DAY: i64 = 86_400_000;
const HOUR: i64 = 3_600_000;

async fn serve() -> (u16, AppState, String) {
    let (port, app, admin, _) = serve_app_with(|a| a.scim.enabled = true).await;
    (port, app, admin)
}

async fn tokens(port: u16, admin: &str) -> Value {
    let (code, body) = call(port, "GET", "/api/scim/tokens", admin, "").await;
    assert_eq!(code, 200, "{body}");
    parse(&body)
}

fn listed<'a>(list: &'a Value, id: &str) -> &'a Value {
    list["tokens"].as_array().unwrap().iter().find(|t| t["id"] == id).unwrap_or_else(|| panic!("no {id} in {list:#}"))
}

async fn rotate(port: u16, admin: &str, id: &str, body: Value) -> (u16, Value) {
    let (code, body) = call(port, "POST", &format!("/api/scim/tokens/{id}/rotate"), admin, &body.to_string()).await;
    (code, parse(&body))
}

fn near(at: Option<i64>, want: i64) -> bool {
    at.is_some_and(|at| (at - want).abs() < 60_000)
}

#[tokio::test]
async fn tokens_expire_after_the_days_asked_for_and_then_stop() {
    let (port, app, admin) = serve().await;
    let (_, default) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let (t, short) = token(port, &admin, json!({ "tenant": "okta", "expiresInDays": 30 })).await;
    let list = tokens(port, &admin).await;
    assert!(near(listed(&list, &default)["expiresAt"].as_i64(), db::now() + 365 * DAY), "{list:#}");
    assert!(near(listed(&list, &short)["expiresAt"].as_i64(), db::now() + 30 * DAY), "{list:#}");
    assert_eq!((listed(&list, &short)["state"].as_str(), list["defaultDays"].as_i64(), list["maxDays"].as_i64(), list["warnDays"].as_i64()), (Some("active"), Some(365), Some(730), Some(14)));
    let made = &events(port, &admin, "action=scim.token_created").await[0];
    assert!(made["details"]["expiresAt"].is_i64(), "{made:#}");
    for bad in [json!(0), json!(731), json!(-1), json!(1.5), json!("30")] {
        let body = json!({ "tenant": "okta", "expiresInDays": bad }).to_string();
        assert_eq!(call(port, "POST", "/api/scim/tokens", &admin, &body).await.0, 400, "{bad}");
    }

    assert_eq!(scim(port, &t, "GET", USERS, Value::Null).await.0, 200);
    app.db.set_scim_token_expiry(&short, Some(db::now() - 1));
    assert_eq!(scim(port, &t, "GET", USERS, Value::Null).await.0, 401, "an expired token stops working");
    assert_eq!(listed(&tokens(port, &admin).await, &short)["state"], "expired");
    let e = &events(port, &admin, "action=scim.auth_failed").await[0];
    assert_eq!((e["details"]["reason"].as_str(), e["details"]["tenant"].as_str(), e["targetId"].as_str()), (Some("expired"), Some("okta"), Some(short.as_str())), "{e:#}");
    assert_eq!(rotate(port, &admin, &short, json!({})).await.0, 409, "an expired token can't be rotated");
    let (_, all) = call(port, "GET", "/api/audit", &admin, "").await;
    assert!(!all.contains(&t) && !all.contains(&users::hash(&t)), "never the token or its hash");
}

/// Tokens made before tokens expired keep working: expiring them on upgrade would stop
/// deprovisioning without anyone having been told.
#[tokio::test]
async fn tokens_from_before_expiry_keep_working_and_are_flagged() {
    let (port, app, admin) = serve().await;
    let (t, id) = token(port, &admin, json!({ "tenant": "entra" })).await;
    app.db.set_scim_token_expiry(&id, None);
    assert_eq!(scim(port, &t, "GET", USERS, Value::Null).await.0, 200);
    let list = tokens(port, &admin).await;
    assert_eq!((listed(&list, &id)["state"].as_str(), listed(&list, &id)["expiresAt"].is_null()), (Some("no_expiry"), true));
    assert_eq!(list["expiringTenants"], json!([]));
    assert_eq!(scim::expiry_notices(&app, db::now()), 0, "nothing to warn of");
    let (code, r) = rotate(port, &admin, &id, json!({ "keepOldHours": 2 })).await;
    assert_eq!(code, 201, "{r}");
    assert!(near(listed(&tokens(port, &admin).await, &id)["expiresAt"].as_i64(), db::now() + 2 * HOUR), "rotating gives it an end");
}

#[tokio::test]
async fn rotating_makes_a_new_token_and_the_old_one_works_until_the_overlap_ends() {
    let (port, app, admin) = serve().await;
    let (_, member) = user_with(port, &admin, "member@example.com", "member").await;
    let (old, id) = token(port, &admin, json!({ "tenant": "okta", "label": "Okta prod" })).await;
    let (_, _, u) = scim(port, &old, "POST", USERS, okta_user("ada@example.com", "00u1")).await;
    let ada = u["id"].as_str().unwrap().to_string();

    assert_eq!(call(port, "POST", &format!("/api/scim/tokens/{id}/rotate"), &member, "{}").await.0, 403);
    assert_eq!(rotate(port, &admin, "st0000", json!({})).await.0, 404);
    for bad in [json!({ "keepOldHours": 169 }), json!({ "keepOldHours": -1 }), json!({ "expiresInDays": 0 }), json!({ "keep": 1 }), json!([])] {
        assert_eq!(rotate(port, &admin, &id, bad.clone()).await.0, 400, "{bad}");
    }

    let (code, r) = rotate(port, &admin, &id, json!({ "expiresInDays": 90 })).await;
    assert_eq!(code, 201, "{r}");
    let new = r["token"].as_str().unwrap().to_string();
    let new_id = r["scimToken"]["id"].as_str().unwrap().to_string();
    assert!(new.starts_with("sbp_") && new != old);
    assert_eq!((r["scimToken"]["tenant"].as_str(), r["scimToken"]["label"].as_str(), r["replaced"]["id"].as_str()), (Some("okta"), Some("Okta prod"), Some(id.as_str())));
    assert!(near(r["scimToken"]["expiresAt"].as_i64(), db::now() + 90 * DAY), "{r:#}");
    assert!(near(r["replaced"]["endsAt"].as_i64(), db::now() + 24 * HOUR), "24 hours by default: {r:#}");

    // Both work: the new one sees the same tenant's users.
    assert_eq!(scim(port, &new, "GET", &format!("{USERS}/{ada}"), Value::Null).await.0, 200);
    assert_eq!(scim(port, &old, "GET", &format!("{USERS}/{ada}"), Value::Null).await.0, 200);
    let list = tokens(port, &admin).await;
    assert_eq!((listed(&list, &id)["state"].as_str(), listed(&list, &id)["rotatedTo"].as_str()), (Some("rotated"), Some(new_id.as_str())));
    assert_eq!(listed(&list, &new_id)["state"], "active");
    assert_eq!(rotate(port, &admin, &id, json!({})).await.0, 409, "a token rotates once");

    let e = &events(port, &admin, "action=scim.token_rotated").await[0];
    assert_eq!((e["targetId"].as_str(), e["details"]["to"].as_str(), e["details"]["tenant"].as_str(), e["actorId"].as_str()), (Some(id.as_str()), Some(new_id.as_str()), Some("okta"), Some("operator")), "{e:#}");
    let (_, all) = call(port, "GET", "/api/audit", &admin, "").await;
    assert!(!all.contains(&new) && !all.contains(&users::hash(&new)), "never the new token or its hash");

    // Once the overlap ends, the old one is refused as expired, naming its replacement.
    app.db.set_scim_token_expiry(&id, Some(db::now() - 1));
    assert_eq!(scim(port, &old, "GET", USERS, Value::Null).await.0, 401);
    let f = &events(port, &admin, "action=scim.auth_failed").await[0];
    assert_eq!((f["details"]["reason"].as_str(), f["details"]["rotatedTo"].as_str()), (Some("expired"), Some(new_id.as_str())), "{f:#}");
    assert_eq!(scim(port, &new, "GET", USERS, Value::Null).await.0, 200);

    // keepOldHours 0 stops the old one at once.
    let (code, r) = rotate(port, &admin, &new_id, json!({ "keepOldHours": 0 })).await;
    assert_eq!(code, 201, "{r}");
    assert_eq!(scim(port, &new, "GET", USERS, Value::Null).await.0, 401);
    assert_eq!(listed(&tokens(port, &admin).await, &new_id)["state"], "revoked");
    assert_eq!(scim(port, r["token"].as_str().unwrap(), "GET", USERS, Value::Null).await.0, 200);
}

/// The overlap never makes a token last longer than it would have.
#[tokio::test]
async fn rotating_never_extends_the_old_token() {
    let (port, app, admin) = serve().await;
    let (_, id) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let soon = db::now() + HOUR;
    app.db.set_scim_token_expiry(&id, Some(soon));
    let (code, r) = rotate(port, &admin, &id, json!({ "keepOldHours": 48 })).await;
    assert_eq!(code, 201, "{r}");
    assert_eq!(r["replaced"]["endsAt"].as_i64(), Some(soon));
    assert_eq!(listed(&tokens(port, &admin).await, &id)["expiresAt"].as_i64(), Some(soon));
}

#[tokio::test]
async fn coming_and_past_ends_are_audited_once_each() {
    let (port, app, admin) = serve().await;
    let (_, a) = token(port, &admin, json!({ "tenant": "okta", "label": "first" })).await;
    let (_, b) = token(port, &admin, json!({ "tenant": "okta", "label": "second" })).await;
    let (_, c) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let at = db::now();
    app.db.set_scim_token_expiry(&a, Some(at + 10 * DAY));
    app.db.set_scim_token_expiry(&c, Some(at + 3 * DAY));
    assert_eq!(scim::expiry_notices(&app, at), 2);
    assert_eq!(scim::expiry_notices(&app, at), 0, "once");
    let warned = events(port, &admin, "action=scim.token_expiring").await;
    let of = |id: &str| warned.iter().find(|e| e["targetId"] == id).unwrap_or_else(|| panic!("{id}: {warned:#?}")).clone();
    let first = of(&a);
    assert_eq!((first["details"]["daysLeft"].as_i64(), first["details"]["tenantWorking"].as_bool(), first["actorId"].as_str()), (Some(10), Some(true), Some("scim")), "{first:#}");
    assert!(near(first["details"]["tenantEndsAt"].as_i64(), at + 365 * DAY), "okta's second token outlasts it: {first:#}");
    assert_eq!(of(&c)["details"]["tenantEndsAt"].as_i64(), Some(at + 3 * DAY), "entra's provisioning stops with it");
    assert_eq!(tokens(port, &admin).await["expiringTenants"], json!(["entra"]));

    app.db.set_scim_token_expiry(&c, Some(at - 1));
    assert_eq!(scim::expiry_notices(&app, at), 1);
    assert_eq!(scim::expiry_notices(&app, at + DAY), 0, "once");
    let ended = &events(port, &admin, "action=scim.token_expired").await;
    assert_eq!(ended.len(), 1, "{ended:#?}");
    assert_eq!((ended[0]["targetId"].as_str(), ended[0]["outcome"].as_str(), ended[0]["details"]["tenantWorking"].as_bool()), (Some(c.as_str()), Some("failure"), Some(false)));

    // Rotated and revoked tokens end as planned.
    let (code, _) = rotate(port, &admin, &b, json!({ "keepOldHours": 1 })).await;
    assert_eq!(code, 201);
    assert_eq!(call(port, "DELETE", &format!("/api/scim/tokens/{a}"), &admin, "").await.0, 200);
    assert_eq!(scim::expiry_notices(&app, at + 2 * HOUR), 0);
}

#[tokio::test]
async fn the_health_score_watches_a_tenant_about_to_lose_provisioning() {
    let (port, app, admin) = serve().await;
    let (t, id) = token(port, &admin, json!({ "tenant": "okta" })).await;
    assert_eq!(scim(port, &t, "GET", USERS, Value::Null).await.0, 200);
    let identity = |r: &Value| r["signals"].as_array().unwrap().iter().find(|s| s["id"] == "identity").unwrap().clone();
    let score = || async { parse(&call(port, "GET", "/api/support/health-score", &admin, "").await.1) };
    assert_eq!(identity(&score().await)["status"], "ok");

    app.db.set_scim_token_expiry(&id, Some(db::now() + 5 * DAY));
    let i = identity(&score().await);
    assert_eq!((i["status"].as_str(), i["facts"]["scimTenantsExpiring"].clone()), (Some("watch"), json!(["okta"])), "{i:#}");
    assert!(i["summary"].as_str().unwrap().contains("okta"), "{i:#}");

    app.db.set_scim_token_expiry(&id, Some(db::now() - 1));
    assert_eq!(scim(port, &t, "GET", USERS, Value::Null).await.0, 401);
    let i = identity(&score().await);
    assert_eq!(i["facts"]["scimReasons"], json!([{ "code": "expired_token", "count": 1 }]), "{i:#}");
    assert_eq!(i["status"], "watch");
}
