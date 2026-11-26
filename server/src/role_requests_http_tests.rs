//! Requests for roles (ADR 0209), on the real router: people ask for a requestable,
//! time-bound role for some hours with a reason, admins approve (for as long or shorter)
//! or deny, and an approval gives the role by hand until the hours are up. A request never
//! changes a built-in role nor replaces a role, everything is checked again as it's
//! approved, and each step is audited.

use crate::service_accounts_http_tests::{account, token};
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;

async fn json_call(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(port, method, path, who, body).await;
    (code, parse(&body))
}

async fn events(port: u16, admin: &str, action: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?action={action}&limit=200"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

/// A new custom role from `body`. Returns its id.
async fn role(port: u16, admin: &str, body: Value) -> String {
    let (code, v) = json_call(port, "POST", "/api/roles", admin, &body.to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

/// A requestable role on `base`, for at most `days`.
async fn requestable(port: u16, admin: &str, name: &str, base: &str, perms: &[&str], days: i64) -> String {
    role(port, admin, json!({ "name": name, "base": base, "permissions": perms, "maxDays": days, "requestable": true })).await
}

async fn ask(port: u16, who: &str, body: Value) -> (u16, Value) {
    json_call(port, "POST", "/api/me/role-requests", who, &body.to_string()).await
}

/// Files a request that must succeed. Returns its id.
async fn asked(port: u16, who: &str, body: Value) -> String {
    let (code, v) = ask(port, who, body).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_person_asks_for_a_requestable_role_and_an_admin_approves_it_for_some_hours() {
    let (port, app, admin, _) = serve_app().await;
    let (bo, bo_auth) = user_with(port, &admin, "bo@example.com", "member").await;
    let oncall = requestable(port, &admin, "On-call", "member", &["machines.manage"], 1).await;
    role(port, &admin, json!({ "name": "Hidden", "permissions": ["audit.view"], "maxDays": 7 })).await;

    // Only requestable roles are offered, and only names a person may see.
    let (code, mine) = json_call(port, "GET", "/api/me/role-requests", &bo_auth, "").await;
    assert_eq!(code, 200, "{mine}");
    let offered = mine["requestable"].as_array().unwrap();
    assert_eq!(offered.len(), 1, "{mine}");
    assert_eq!((offered[0]["name"].as_str(), offered[0]["maxHours"].as_i64(), offered[0]["org"]["ok"].as_bool()), (Some("On-call"), Some(24), Some(true)));
    assert_eq!((offered[0]["team"].clone(), mine["team"].clone(), mine["requests"].clone()), (Value::Null, Value::Null, json!([])));

    for (body, code, why) in [
        (json!({ "role": "On-call", "hours": 25, "reason": "Incident 42" }), 400, "beyond its limit"),
        (json!({ "role": "On-call", "hours": 0, "reason": "Incident 42" }), 400, "at least an hour"),
        (json!({ "role": "On-call", "hours": 1.5, "reason": "Incident 42" }), 400, "whole hours"),
        (json!({ "role": "On-call", "hours": 8 }), 400, "a reason is needed"),
        (json!({ "role": "On-call", "hours": 8, "reason": "  " }), 400, "a reason is needed"),
        (json!({ "role": "On-call", "hours": 8, "reason": "x", "until": 5 }), 400, "unknown field"),
        (json!({ "role": "On-call", "hours": 8, "reason": "x", "scope": "everywhere" }), 400, "a scope"),
        (json!({ "role": "On-call", "hours": 8, "reason": "x", "scope": "team" }), 409, "not on a team"),
        (json!({ "role": "Hidden", "hours": 8, "reason": "x" }), 404, "not requestable reads as missing"),
        (json!({ "role": "Nope", "hours": 8, "reason": "x" }), 404, "no such role"),
    ] {
        let (got, v) = ask(port, &bo_auth, body).await;
        assert_eq!(got, code, "{why}: {v}");
    }
    let (code, q) = ask(port, &bo_auth, json!({ "role": "on-call", "hours": 8, "reason": "Incident 42: restart the build hosts" })).await;
    assert_eq!((code, q["status"].as_str(), q["hours"].as_i64(), q["scope"].as_str()), (201, Some("pending"), Some(8), Some("org")), "{q}");
    let id = q["id"].as_str().unwrap().to_string();
    assert!(q["expiresAt"].as_i64().unwrap() > db::now() + 6 * roles::DAY, "lapses in a week: {q}");
    assert_eq!(ask(port, &bo_auth, json!({ "role": oncall, "hours": 4, "reason": "again" })).await.0, 409, "one pending request per role");
    // Asking gives nothing yet.
    let perms = |me: &Value| me["permissions"].as_array().unwrap().iter().filter_map(Value::as_str).map(str::to_string).collect::<Vec<_>>();
    let (_, me) = json_call(port, "GET", "/api/auth/me", &bo_auth, "").await;
    assert!(!perms(&me).contains(&"machines.manage".to_string()), "{me}");

    // Only admins see and decide requests.
    assert_eq!(call(port, "GET", "/api/role-requests", &bo_auth, "").await.0, 403);
    assert_eq!(call(port, "POST", &format!("/api/role-requests/{id}/approve"), &bo_auth, "{}").await.0, 403);
    let (code, list) = json_call(port, "GET", "/api/role-requests", &admin, "").await;
    assert_eq!((code, list["pending"].as_i64()), (200, Some(1)), "{list}");
    let row = &list["requests"][0];
    assert_eq!((row["user"]["email"].as_str(), row["reason"].as_str(), row["current"].clone()), (Some("bo@example.com"), Some("Incident 42: restart the build hosts"), Value::Null), "{row}");
    assert_eq!(row["role"]["applies"], json!(["machines.manage"]));

    // An approval can shorten a request, never lengthen it.
    assert_eq!(call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, r#"{"hours":9}"#).await.0, 400);
    assert_eq!(call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, r#"{"hours":4,"by":"me"}"#).await.0, 400);
    let before = db::now();
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, r#"{"hours":4,"note":"Shorter is enough"}"#).await;
    assert_eq!((code, v["request"]["status"].as_str(), v["role"]["name"].as_str()), (200, Some("approved"), Some("On-call")), "{v}");
    let ends = v["role"]["expiresAt"].as_i64().unwrap();
    assert!((before + 4 * 3_600_000..=db::now() + 4 * 3_600_000).contains(&ends), "{v}");
    assert_eq!((v["request"]["grantedUntil"].as_i64(), v["request"]["note"].as_str()), (Some(ends), Some("Shorter is enough")));
    let u = app.db.user(&bo).unwrap();
    assert_eq!((u.role_id.as_deref(), u.role_expires_at, u.role), (Some(oncall.as_str()), Some(ends), rbac::Role::Member), "its base is theirs already");
    // At once, in the same session.
    let (_, me) = json_call(port, "GET", "/api/auth/me", &bo_auth, "").await;
    assert_eq!(me["customRole"], json!({ "id": oncall, "name": "On-call", "expiresAt": ends }));
    assert!(perms(&me).contains(&"machines.manage".to_string()), "{me}");
    assert_eq!(call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await.0, 409, "once");
    assert_eq!(call(port, "POST", &format!("/api/role-requests/{id}/deny"), &admin, "{}").await.0, 409);

    let (_, mine) = json_call(port, "GET", "/api/me/role-requests", &bo_auth, "").await;
    assert_eq!((mine["requests"][0]["status"].as_str(), mine["requests"][0]["decidedBy"]["id"].as_str()), (Some("approved"), Some("operator")), "{mine}");
    assert_eq!(json_call(port, "GET", "/api/role-requests", &admin, "").await.1["pending"], 0);
    let (_, all) = json_call(port, "GET", "/api/role-requests?status=all", &admin, "").await;
    assert_eq!(all["requests"].as_array().unwrap().len(), 1);
    assert_eq!(call(port, "GET", "/api/role-requests?status=maybe", &admin, "").await.0, 400);

    let requested = events(port, &admin, "role.requested").await;
    assert_eq!((requested.len(), requested[0]["actorId"].as_str(), requested[0]["targetId"].as_str()), (1, Some(bo.as_str()), Some(oncall.as_str())));
    assert_eq!((requested[0]["details"]["hours"].as_i64(), requested[0]["details"]["reason"].as_str()), (Some(8), Some("Incident 42: restart the build hosts")));
    let approved = events(port, &admin, "role.request_approved").await;
    assert_eq!(approved[0]["details"]["request"].as_str(), Some(id.as_str()));
    assert_eq!((approved[0]["details"]["hours"].as_i64(), approved[0]["details"]["requestedHours"].as_i64(), approved[0]["details"]["expiresAt"].as_i64()), (Some(4), Some(8), Some(ends)));
    // The grant itself reads as any role given by hand, with the request it came from.
    let assigned = events(port, &admin, "role.assigned").await;
    let d = &assigned[0]["details"];
    assert_eq!((d["user"].as_str(), d["scope"].as_str(), d["expiresAt"].as_i64(), d["request"].as_str()), (Some(bo.as_str()), Some("org"), Some(ends), Some(id.as_str())), "{d}");
    assert_eq!(d["reason"].as_str(), Some("Incident 42: restart the build hosts"));

    // It ends as any time-bound role does.
    app.db.move_role_end(&bo, db::now() - 1);
    let (_, me) = json_call(port, "GET", "/api/auth/me", &bo_auth, "").await;
    assert!(!perms(&me).contains(&"machines.manage".to_string()), "{me}");
    assert_eq!(roles::expire_due(&app), 1);
    assert_eq!(app.db.user(&bo).unwrap().role, rbac::Role::Member);
}

#[tokio::test]
async fn a_request_never_changes_a_built_in_role_nor_replaces_a_role() {
    let (port, _, admin, _) = serve_app().await;
    let (_, ro_auth) = user_with(port, &admin, "ro@example.com", "readonly").await;
    let (cy, cy_auth) = user_with(port, &admin, "cy@example.com", "member").await;
    let (_, boss_auth) = user_with(port, &admin, "boss@example.com", "admin").await;
    requestable(port, &admin, "On-call", "member", &["machines.manage"], 1).await;
    let auditor = requestable(port, &admin, "Auditor", "readonly", &["audit.view"], 30).await;
    let ops = role(port, &admin, json!({ "name": "Ops", "permissions": ["bots.manage"] })).await;

    // Read-only people may ask for a role built on read-only, and only that.
    let (code, v) = ask(port, &ro_auth, json!({ "role": "On-call", "hours": 2, "reason": "x" })).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("never changes anyone's built-in role"), "{v}");
    let (_, mine) = json_call(port, "GET", "/api/me/role-requests", &ro_auth, "").await;
    let by_name = |n: &str| mine["requestable"].as_array().unwrap().iter().find(|r| r["name"] == n).unwrap().clone();
    assert_eq!((by_name("On-call")["org"]["ok"].as_bool(), by_name("Auditor")["org"]["ok"].as_bool()), (Some(false), Some(true)), "{mine}");
    assert_eq!(ask(port, &ro_auth, json!({ "role": "Auditor", "hours": 48, "reason": "Q4 audit window" })).await.0, 201);
    // And members not one built on read-only, which would leave them read-only.
    assert_eq!(ask(port, &cy_auth, json!({ "role": "Auditor", "hours": 48, "reason": "x" })).await.0, 409);
    // Admins hold everything already.
    let (code, v) = ask(port, &boss_auth, json!({ "role": "On-call", "hours": 2, "reason": "x" })).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("an admin"), "{v}");

    // Not over another custom role they hold.
    assert_eq!(call(port, "PUT", &format!("/api/roles/{ops}/users/{cy}"), &admin, "").await.0, 200);
    let (code, v) = ask(port, &cy_auth, json!({ "role": "On-call", "hours": 2, "reason": "x" })).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("never replaces one"), "{v}");
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{ops}/users/{cy}"), &admin, "").await.0, 200);

    // The same role held with no end: nothing to ask for. With an end: asking renews it.
    let (dee, dee_auth) = user_with(port, &admin, "dee@example.com", "readonly").await;
    let soon = db::now() + 3_600_000;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{auditor}/users/{dee}"), &admin, &json!({ "expiresAt": soon }).to_string()).await.0, 200);
    let id = asked(port, &dee_auth, json!({ "role": auditor, "hours": 24, "reason": "Another day" })).await;
    let (_, list) = json_call(port, "GET", "/api/role-requests", &admin, "").await;
    let row = list["requests"].as_array().unwrap().iter().find(|r| r["id"] == id.as_str()).unwrap().clone();
    assert_eq!(row["current"], json!({ "id": auditor, "name": "Auditor", "expiresAt": soon }), "admins see what it renews");
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await;
    assert_eq!(code, 200, "{v}");
    assert!(v["role"]["expiresAt"].as_i64().unwrap() > soon + 22 * 3_600_000, "{v}");
    let assigned = events(port, &admin, "role.assigned").await;
    assert_eq!(assigned[0]["details"]["from"]["expiresAt"].as_i64(), Some(soon));
}

#[tokio::test]
async fn an_approval_checks_everything_again_as_it_gives_the_role() {
    let (port, app, admin, _) = serve_app().await;
    let (bo, bo_auth) = user_with(port, &admin, "bo@example.com", "member").await;
    let oncall = requestable(port, &admin, "On-call", "member", &["machines.manage"], 2).await;
    let ops = role(port, &admin, json!({ "name": "Ops", "permissions": ["bots.manage"] })).await;

    // Given another role meanwhile: approving would replace it.
    let id = asked(port, &bo_auth, json!({ "role": oncall, "hours": 8, "reason": "x" })).await;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{ops}/users/{bo}"), &admin, "").await.0, 200);
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("They hold another custom role"), "{v}");
    assert_eq!(app.db.user(&bo).unwrap().role_id.as_deref(), Some(ops.as_str()), "nothing written");
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{ops}/users/{bo}"), &admin, "").await.0, 200);

    // Made an admin meanwhile: then they can't approve it themselves either.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{bo}"), &admin, r#"{"role":"admin"}"#).await.0, 200);
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{id}/approve"), &bo_auth, "{}").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("your own request"), "{v}");
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("an admin"), "{v}");
    assert_eq!(call(port, "PATCH", &format!("/api/users/{bo}"), &admin, r#"{"role":"member"}"#).await.0, 200);

    // A shorter limit meanwhile: approve it for fewer hours.
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{oncall}"), &admin, r#"{"maxDays":1}"#).await.0, 200);
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await;
    assert_eq!(code, 200, "8 hours fits a day: {v}");
    app.db.move_role_end(&bo, db::now() - 1);
    roles::expire_due(&app);

    // No longer requestable: it can't be approved, and the sweep lapses it.
    let id = asked(port, &bo_auth, json!({ "role": oncall, "hours": 24, "reason": "x" })).await;
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{oncall}"), &admin, r#"{"requestable":false}"#).await.0, 200);
    assert_eq!(role_requests::lapse_due(&app), 1);
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await;
    assert_eq!(code, 409, "{v}");
    assert_eq!(v["error"].as_str(), Some("This request lapsed already."));
    let lapsed = events(port, &admin, "role.request_lapsed").await;
    assert_eq!((lapsed[0]["details"]["why"].as_str(), lapsed[0]["actorKind"].as_str(), lapsed[0]["actorId"].as_str()), (Some("not_requestable"), Some("system"), Some("roles")), "{lapsed:?}");
    assert_eq!(app.db.role_request(&id).unwrap().status, "lapsed");
    assert!(app.db.user(&bo).unwrap().role_id.is_none());

    // Disabled meanwhile: lapsed too.
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{oncall}"), &admin, r#"{"requestable":true}"#).await.0, 200);
    let id = asked(port, &bo_auth, json!({ "role": oncall, "hours": 2, "reason": "x" })).await;
    assert_eq!(call(port, "PATCH", &format!("/api/users/{bo}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert_eq!(call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await.0, 409, "every handler lapses what's due first");
    assert_eq!(app.db.role_request(&id).unwrap().status, "lapsed");
    assert_eq!(events(port, &admin, "role.request_lapsed").await[0]["details"]["why"].as_str(), Some("disabled"));

    // Undone before the sweep: the change itself ends the request, so it can't come back.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{bo}"), &admin, r#"{"status":"active"}"#).await.0, 200);
    let bo_auth = crate::users_http_tests::signed_in(port, &admin, &bo).await.unwrap();
    let id = asked(port, &bo_auth, json!({ "role": oncall, "hours": 2, "reason": "x" })).await;
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{oncall}"), &admin, r#"{"requestable":false}"#).await.0, 200);
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{oncall}"), &admin, r#"{"requestable":true}"#).await.0, 200);
    assert_eq!(app.db.role_request(&id).unwrap().status, "pending", "not swept yet");
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await;
    assert_eq!((code, v["error"].as_str()), (409, Some("This request lapsed already.")), "{v}");
    assert_eq!(events(port, &admin, "role.request_lapsed").await[0]["details"]["why"].as_str(), Some("not_requestable"));

    let id = asked(port, &bo_auth, json!({ "role": oncall, "hours": 2, "reason": "x" })).await;
    assert_eq!(call(port, "PATCH", &format!("/api/users/{bo}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{bo}"), &admin, r#"{"status":"active"}"#).await.0, 200);
    // Even without the handlers' sweep, the database won't approve it.
    assert!(matches!(app.db.approve_role_request(&id, None, None, None, |_| Ok(()), |_| false), Err(db::RoleRequestError::NotPending(s)) if s == "lapsed"));
    assert_eq!(role_requests::lapse_due(&app), 1);
    assert_eq!(events(port, &admin, "role.request_lapsed").await[0]["details"]["why"].as_str(), Some("disabled"));
    assert!(app.db.user(&bo).unwrap().role_id.is_none());
}

#[tokio::test]
async fn a_team_request_applies_only_in_its_team() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (cy, cy_auth) = user_with(port, &admin, "cy@example.com", "member").await;
    let (ro, ro_auth) = user_with(port, &admin, "ro@example.com", "readonly").await;
    let (_, t) = json_call(port, "POST", "/api/teams", &admin, &json!({ "name": "Alpha", "owner": ada }).to_string()).await;
    let team = t["id"].as_str().unwrap().to_string();
    for u in [&cy, &ro] {
        assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/members/{u}"), &admin, r#"{"role":"member"}"#).await.0, 200);
    }
    // Built on read-only, though in a team only its team permissions count.
    requestable(port, &admin, "Team helpdesk", "readonly", &["users.manage", "audit.view"], 7).await;

    let (_, mine) = json_call(port, "GET", "/api/me/role-requests", &cy_auth, "").await;
    assert_eq!(mine["team"]["name"].as_str(), Some("Alpha"));
    let offer = &mine["requestable"][0];
    assert_eq!((offer["org"]["ok"].as_bool(), offer["team"]["ok"].as_bool(), offer["teamPermissions"].clone()), (Some(false), Some(true), json!(["users.manage"])), "{mine}");
    let (code, v) = ask(port, &ro_auth, json!({ "role": "Team helpdesk", "scope": "team", "hours": 8, "reason": "x" })).await;
    assert_eq!(code, 409, "read-only people change nothing in a team: {v}");

    let id = asked(port, &cy_auth, json!({ "role": "Team helpdesk", "scope": "team", "hours": 48, "reason": "Onboarding week" })).await;
    assert_eq!(call(port, "POST", "/api/team/invites", &cy_auth, r#"{"email":"new@example.com"}"#).await.0, 403);
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await;
    assert_eq!((code, v["applies"].clone(), v["request"]["team"]["name"].as_str()), (200, json!(["users.manage"]), Some("Alpha")), "{v}");
    let (_, mine) = json_call(port, "GET", "/api/team", &cy_auth, "").await;
    assert_eq!(mine["permissions"], json!(["users.manage"]), "{mine}");
    assert_eq!(call(port, "POST", "/api/team/invites", &cy_auth, r#"{"email":"new@example.com"}"#).await.0, 201);
    // Their role across the server is untouched.
    let u = app.db.user(&cy).unwrap();
    assert_eq!((u.role, u.role_id), (rbac::Role::Member, None));
    assert_eq!(call(port, "GET", "/api/audit", &cy_auth, "").await.0, 403);
    let assigned = events(port, &admin, "role.assigned").await;
    assert_eq!((assigned[0]["details"]["scope"].as_str(), assigned[0]["details"]["team"].as_str()), (Some("team"), Some(team.as_str())));

    // Off the team before it's approved: refused.
    let id = asked(port, &cy_auth, json!({ "role": "Team helpdesk", "scope": "team", "hours": 8, "reason": "renew" })).await;
    assert_eq!(call(port, "POST", "/api/team/leave", &cy_auth, "").await.0, 200);
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("not on that team"), "{v}");
}

#[tokio::test]
async fn requests_are_withdrawn_denied_or_lapse_and_each_is_audited() {
    let (port, app, admin, _) = serve_app().await;
    let (bo, bo_auth) = user_with(port, &admin, "bo@example.com", "member").await;
    let (_, cy_auth) = user_with(port, &admin, "cy@example.com", "member").await;
    let oncall = requestable(port, &admin, "On-call", "member", &["machines.manage"], 1).await;

    let id = asked(port, &bo_auth, json!({ "role": oncall, "hours": 2, "reason": "x" })).await;
    assert_eq!(call(port, "POST", &format!("/api/me/role-requests/{id}/cancel"), &cy_auth, "").await.0, 404, "only your own");
    let (code, v) = json_call(port, "POST", &format!("/api/me/role-requests/{id}/cancel"), &bo_auth, "").await;
    assert_eq!((code, v["status"].as_str()), (200, Some("cancelled")), "{v}");
    let (code, v) = json_call(port, "POST", &format!("/api/me/role-requests/{id}/cancel"), &bo_auth, "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("withdrawn"), "{v}");
    assert_eq!(call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await.0, 409);
    assert_eq!(events(port, &admin, "role.request_cancelled").await[0]["actorId"].as_str(), Some(bo.as_str()));

    let id = asked(port, &bo_auth, json!({ "role": oncall, "hours": 2, "reason": "x" })).await;
    assert_eq!(call(port, "POST", &format!("/api/role-requests/{id}/deny"), &admin, r#"{"note":5}"#).await.0, 400);
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{id}/deny"), &admin, r#"{"note":"Use the runbook"}"#).await;
    assert_eq!((code, v["status"].as_str(), v["note"].as_str()), (200, Some("denied"), Some("Use the runbook")), "{v}");
    let denied = events(port, &admin, "role.request_denied").await;
    assert_eq!((denied[0]["details"]["note"].as_str(), denied[0]["details"]["user"].as_str()), (Some("Use the runbook"), Some(bo.as_str())));
    assert!(app.db.user(&bo).unwrap().role_id.is_none());

    // Undecided for a week, it lapses.
    let id = asked(port, &bo_auth, json!({ "role": oncall, "hours": 2, "reason": "x" })).await;
    app.db.move_role_request_lapse(&id, db::now() - 1);
    assert_eq!(role_requests::lapse_due(&app), 1);
    assert_eq!(role_requests::lapse_due(&app), 0, "once");
    assert_eq!(call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await.0, 409);
    let lapsed = events(port, &admin, "role.request_lapsed").await;
    assert_eq!((lapsed[0]["details"]["request"].as_str(), lapsed[0]["details"]["why"].as_str()), (Some(id.as_str()), Some("expired")));

    // At most a few pending at once.
    for n in 0..role_requests::MAX_PENDING {
        let r = requestable(port, &admin, &format!("R{n}"), "member", &["bots.manage"], 1).await;
        asked(port, &bo_auth, json!({ "role": r, "hours": 1, "reason": "x" })).await;
    }
    let (code, v) = ask(port, &bo_auth, json!({ "role": oncall, "hours": 1, "reason": "x" })).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("Withdraw one first"), "{v}");
}

#[tokio::test]
async fn asking_and_withdrawing_is_capped_each_day() {
    let (port, _, admin, _) = serve_app().await;
    let (_, bo_auth) = user_with(port, &admin, "bo@example.com", "member").await;
    let oncall = requestable(port, &admin, "On-call", "member", &["machines.manage"], 1).await;
    for _ in 0..role_requests::MAX_DAILY {
        let id = asked(port, &bo_auth, json!({ "role": oncall, "hours": 1, "reason": "x" })).await;
        assert_eq!(call(port, "POST", &format!("/api/me/role-requests/{id}/cancel"), &bo_auth, "").await.0, 200);
    }
    let (code, v) = ask(port, &bo_auth, json!({ "role": oncall, "hours": 1, "reason": "x" })).await;
    assert_eq!(code, 429, "withdrawing doesn't free the day's requests: {v}");
    assert!(v["error"].as_str().unwrap().contains("Try again tomorrow"), "{v}");
    assert_eq!(events(port, &admin, "role.requested").await.len(), role_requests::MAX_DAILY);
}

#[tokio::test]
async fn only_a_time_bound_role_is_requestable() {
    let (port, _, admin, _) = serve_app().await;
    let (_, bo_auth) = user_with(port, &admin, "bo@example.com", "member").await;
    let (code, v) = json_call(port, "POST", "/api/roles", &admin, r#"{"name":"X","permissions":[],"requestable":true}"#).await;
    assert_eq!(code, 400, "{v}");
    assert_eq!(call(port, "POST", "/api/roles", &admin, r#"{"name":"X","permissions":[],"maxDays":3,"requestable":"yes"}"#).await.0, 400);
    let plain = role(port, &admin, json!({ "name": "Plain", "permissions": ["audit.view"] })).await;
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{plain}"), &admin, r#"{"requestable":true}"#).await.0, 400);
    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{plain}"), &admin, r#"{"requestable":true,"maxDays":3}"#).await;
    assert_eq!((code, v["requestable"].as_bool(), v["maxDays"].as_i64()), (200, Some(true), Some(3)), "{v}");
    let updated = events(port, &admin, "role.updated").await;
    assert_eq!(updated[0]["details"]["changes"]["requestable"], json!({ "from": false, "to": true }));

    // Its limit stays while it's requestable.
    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{plain}"), &admin, r#"{"maxDays":null}"#).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("keeps a time limit"), "{v}");
    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{plain}"), &admin, r#"{"maxDays":null,"requestable":false}"#).await;
    assert_eq!((code, v["requestable"].as_bool(), v["maxDays"].clone()), (200, Some(false), Value::Null), "{v}");

    // Deleting a role takes its requests with it.
    let tb = requestable(port, &admin, "Break glass", "member", &["users.manage"], 1).await;
    let id = asked(port, &bo_auth, json!({ "role": tb, "hours": 1, "reason": "x" })).await;
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{tb}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "POST", &format!("/api/role-requests/{id}/approve"), &admin, "{}").await.0, 404);
}

#[tokio::test]
async fn bots_and_service_accounts_never_ask_for_roles() {
    let (port, app, admin, key) = serve_app().await;
    requestable(port, &admin, "On-call", "member", &["machines.manage"], 1).await;
    let sa = account(port, &admin, json!({ "name": "CI" })).await;
    let (sa_auth, _) = token(port, &admin, &sa, json!({ "name": "ci" })).await;
    assert_eq!(call(port, "GET", "/api/me/role-requests", &sa_auth, "").await.0, 403);
    assert_eq!(ask(port, &sa_auth, json!({ "role": "On-call", "hours": 1, "reason": "x" })).await.0, 403);
    let bot = key.auth(&app.db.create_bot("Walker", "#fff", "waddle", "claude", None, false).id);
    assert_eq!(ask(port, &bot, json!({ "role": "On-call", "hours": 1, "reason": "x" })).await.0, 403);
    assert!(events(port, &admin, "role.requested").await.is_empty());
}
