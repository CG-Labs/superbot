//! Two approvers for chosen roles (ADR 0320), on the real router: a role marked
//! `approvals: 2` is given by request only once two different people approve it. The first
//! approval is saved on the request, which stays pending; the second, by someone else, gives
//! the role for the first's hours or fewer. A first approval counts only while its approver
//! could still approve the request, and every step is audited.

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

/// A requestable role from `body` (with `maxDays` and `requestable`). Returns its id.
async fn role(port: u16, admin: &str, body: Value) -> String {
    let (code, v) = json_call(port, "POST", "/api/roles", admin, &body.to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

async fn asked(port: u16, who: &str, body: Value) -> String {
    let (code, v) = json_call(port, "POST", "/api/me/role-requests", who, &body.to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

async fn approve(port: u16, who: &str, id: &str, body: Value) -> (u16, Value) {
    json_call(port, "POST", &format!("/api/role-requests/{id}/approve"), who, &body.to_string()).await
}

fn team_at(id: &str, verb: &str) -> String {
    format!("/api/team/role-requests/{id}/{verb}")
}

#[tokio::test]
async fn a_role_needing_two_approvals_is_given_only_by_a_second_approver() {
    let (port, app, admin, _) = serve_app().await;
    let body = json!({ "name": "Root", "permissions": ["machines.manage", "users.manage"], "maxDays": 1, "requestable": true, "approvals": 2 });

    // With one admin, nobody could give a second approval across the server.
    let (code, v) = json_call(port, "POST", "/api/roles", &admin, &body.to_string()).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("Only 1 active admin"), "{v}");
    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "admin").await;
    for bad in [json!(3), json!(0), json!("2"), json!(true)] {
        let mut b = body.clone();
        b["approvals"] = bad.clone();
        assert_eq!(call(port, "POST", "/api/roles", &admin, &b.to_string()).await.0, 400, "{bad}");
    }
    let root = role(port, &admin, body).await;
    let plain = role(port, &admin, json!({ "name": "On-call", "permissions": ["audit.view"], "maxDays": 1, "requestable": true })).await;
    let (_, list) = json_call(port, "GET", "/api/roles", &admin, "").await;
    let approvals = |id: &str| list["roles"].as_array().unwrap().iter().find(|r| r["id"] == id).unwrap()["approvals"].clone();
    assert_eq!((approvals(&root), approvals(&plain)), (json!(2), json!(1)), "one approval unless asked: {list}");
    let created = &events(port, &admin, "role.created").await;
    assert!(created.iter().any(|e| e["targetId"] == root.as_str() && e["details"]["approvals"] == 2), "{created:?}");

    // The person asking sees that it needs two.
    let (bo, bo_auth) = user_with(port, &admin, "bo@example.com", "member").await;
    let (_, mine) = json_call(port, "GET", "/api/me/role-requests", &bo_auth, "").await;
    let offered = mine["requestable"].as_array().unwrap().iter().find(|r| r["id"] == root.as_str()).unwrap().clone();
    assert_eq!(offered["approvals"], 2, "{mine}");
    let id = asked(port, &bo_auth, json!({ "role": "Root", "hours": 8, "reason": "Rotate the host keys" })).await;

    // The first approval is saved, for fewer hours if the approver says so; nothing is given yet.
    let (code, v) = approve(port, &admin, &id, json!({ "hours": 6, "note": "Fine by me" })).await;
    assert_eq!((code, v["request"]["status"].as_str(), v["approvals"].clone(), v["role"].clone()), (200, Some("pending"), json!({ "needed": 2, "given": 1 }), Value::Null), "{v}");
    let first = &v["request"]["firstApproval"];
    assert_eq!((first["by"]["id"].as_str(), first["hours"].as_i64(), first["note"].as_str()), (Some("operator"), Some(6), Some("Fine by me")), "{v}");
    assert_eq!(app.db.user(&bo).unwrap().role_id, None, "nothing given yet");
    let (_, me) = json_call(port, "GET", "/api/auth/me", &bo_auth, "").await;
    assert!(!me["permissions"].as_array().unwrap().contains(&json!("machines.manage")), "{me}");
    let firsts = events(port, &admin, "role.request_first_approved").await;
    let d = &firsts[0]["details"];
    assert_eq!((firsts.len(), firsts[0]["actorId"].as_str(), d["request"].as_str(), d["hours"].as_i64(), d["requestedHours"].as_i64(), d["approvals"].as_i64()), (1, Some("operator"), Some(id.as_str()), Some(6), Some(8), Some(2)), "{firsts:?}");
    assert!(d.get("replaced").is_none() && d.get("via").is_none(), "{d}");
    assert!(events(port, &admin, "role.request_approved").await.is_empty());
    assert!(events(port, &admin, "role.assigned").await.is_empty());

    // Still pending for every admin, showing who gave the first approval; the asker sees it too.
    let (_, pending) = json_call(port, "GET", "/api/role-requests", &ana_auth, "").await;
    assert_eq!((pending["pending"].as_i64(), pending["requests"][0]["firstApproval"]["by"]["id"].as_str(), pending["requests"][0]["approvals"].as_i64()), (Some(1), Some("operator"), Some(2)), "{pending}");
    let (_, mine) = json_call(port, "GET", "/api/me/role-requests", &bo_auth, "").await;
    assert_eq!((mine["requests"][0]["status"].as_str(), mine["requests"][0]["firstApproval"]["hours"].as_i64()), (Some("pending"), Some(6)), "{mine}");

    // The first approver can't give the second, and the second can't give more than the first did.
    let (code, v) = approve(port, &admin, &id, json!({})).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("first approval"), "{v}");
    let (code, v) = approve(port, &ana_auth, &id, json!({ "hours": 7 })).await;
    assert_eq!(code, 400, "{v}");
    assert!(v["error"].as_str().unwrap().contains("6 hours"), "{v}");
    assert_eq!(app.db.role_request(&id).unwrap().status, "pending", "refusals leave it pending");

    // Someone else's approval gives it, for the first's hours unless they say fewer.
    let before = db::now();
    let (code, v) = approve(port, &ana_auth, &id, json!({ "note": "Second" })).await;
    assert_eq!((code, v["request"]["status"].as_str(), v["approvals"].clone()), (200, Some("approved"), json!({ "needed": 2, "given": 2 })), "{v}");
    let ends = v["role"]["expiresAt"].as_i64().unwrap();
    assert!((before + 6 * 3_600_000..=db::now() + 6 * 3_600_000).contains(&ends), "{v}");
    assert_eq!((v["request"]["decidedBy"]["id"].as_str(), v["request"]["note"].as_str()), (Some(ana.as_str()), Some("Second")), "{v}");
    let u = app.db.user(&bo).unwrap();
    assert_eq!((u.role_id.as_deref(), u.role_expires_at), (Some(root.as_str()), Some(ends)));
    let approved = &events(port, &admin, "role.request_approved").await[0];
    let d = &approved["details"];
    assert_eq!((approved["actorId"].as_str(), d["approvers"].clone(), d["hours"].as_i64(), d["firstApproval"]["by"].as_str(), d["firstApproval"]["note"].as_str()), (Some(ana.as_str()), json!(["operator", ana]), Some(6), Some("operator"), Some("Fine by me")), "{approved}");
    let given = &events(port, &admin, "role.assigned").await[0];
    assert_eq!((given["details"]["approvers"].clone(), given["details"]["request"].as_str()), (json!(["operator", ana]), Some(id.as_str())), "{given}");
    assert_eq!(approve(port, &admin, &id, json!({})).await.0, 409, "decided already");

    // A role that needs one is approved by one, as before, with no approvers listed.
    let (dee, dee_auth) = user_with(port, &admin, "dee@example.com", "member").await;
    let q = asked(port, &dee_auth, json!({ "role": "On-call", "hours": 2, "reason": "Audit" })).await;
    let (code, v) = approve(port, &ana_auth, &q, json!({})).await;
    assert_eq!((code, v["request"]["status"].as_str(), v["approvals"].clone(), v["request"]["firstApproval"].clone()), (200, Some("approved"), json!({ "needed": 1, "given": 1 }), Value::Null), "{v}");
    assert!(events(port, &admin, "role.request_approved").await[0]["details"].get("approvers").is_none());
    assert_eq!(app.db.user(&dee).unwrap().role_id.as_deref(), Some(plain.as_str()));
}

#[tokio::test]
async fn a_first_approval_counts_only_while_its_approver_could_still_approve() {
    let (port, app, admin, _) = serve_app().await;
    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "admin").await;
    let (cy, cy_auth) = user_with(port, &admin, "cy@example.com", "admin").await;
    let root = role(port, &admin, json!({ "name": "Root", "permissions": ["machines.manage"], "maxDays": 1, "requestable": true, "approvals": 2 })).await;
    let (bo, bo_auth) = user_with(port, &admin, "bo@example.com", "member").await;

    // An approver who stops being an admin no longer counts: the next approval is the first again.
    let id = asked(port, &bo_auth, json!({ "role": root, "hours": 8, "reason": "Rebuild" })).await;
    assert_eq!(approve(port, &ana_auth, &id, json!({ "hours": 2 })).await.0, 200);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"role":"member"}"#).await.0, 200);
    let (code, v) = approve(port, &cy_auth, &id, json!({})).await;
    assert_eq!((code, v["request"]["status"].as_str(), v["request"]["firstApproval"]["by"]["id"].as_str()), (200, Some("pending"), Some(cy.as_str())), "{v}");
    assert_eq!(v["request"]["firstApproval"]["hours"], 8, "the hours asked, not the stale approval's: {v}");
    let firsts = events(port, &admin, "role.request_first_approved").await;
    assert_eq!((firsts[0]["actorId"].as_str(), firsts[0]["details"]["replaced"]["by"].as_str()), (Some(cy.as_str()), Some(ana.as_str())), "{firsts:?}");
    assert_eq!(app.db.user(&bo).unwrap().role_id, None);
    let (code, v) = approve(port, &admin, &id, json!({})).await;
    assert_eq!((code, v["request"]["status"].as_str()), (200, Some("approved")), "{v}");
    assert_eq!(events(port, &admin, "role.request_approved").await[0]["details"]["approvers"], json!([cy, "operator"]));

    // Any approver may deny after a first approval, the first approver too; one denial ends it.
    let (dee, dee_auth) = user_with(port, &admin, "dee@example.com", "member").await;
    let q = asked(port, &dee_auth, json!({ "role": root, "hours": 4, "reason": "Cover" })).await;
    assert_eq!(approve(port, &cy_auth, &q, json!({})).await.0, 200);
    let (code, v) = json_call(port, "POST", &format!("/api/role-requests/{q}/deny"), &cy_auth, r#"{"note":"On second thought"}"#).await;
    assert_eq!((code, v["status"].as_str(), v["note"].as_str()), (200, Some("denied"), Some("On second thought")), "{v}");
    assert_eq!(app.db.user(&dee).unwrap().role_id, None);

    // Approvals needed are read as each approval is made: lowered to one, the next one gives it.
    let q = asked(port, &dee_auth, json!({ "role": root, "hours": 4, "reason": "Cover again" })).await;
    assert_eq!(approve(port, &cy_auth, &q, json!({})).await.0, 200);
    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{root}"), &admin, r#"{"approvals":1}"#).await;
    assert_eq!((code, v["approvals"].as_i64()), (200, Some(1)), "{v}");
    let updated = &events(port, &admin, "role.updated").await[0];
    assert_eq!(updated["details"]["changes"]["approvals"], json!({ "from": 2, "to": 1 }), "{updated}");
    let (code, v) = approve(port, &admin, &q, json!({})).await;
    assert_eq!((code, v["request"]["status"].as_str()), (200, Some("approved")), "{v}");
    assert_eq!(app.db.user(&dee).unwrap().role_id.as_deref(), Some(root.as_str()));

    // Raised again with one admin left, it's refused, as nobody could give the second.
    for who in [&ana, &cy] {
        assert_eq!(call(port, "PATCH", &format!("/api/users/{who}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    }
    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{root}"), &admin, r#"{"approvals":2}"#).await;
    assert_eq!(code, 409, "{v}");
    assert_eq!(app.db.custom_role(&root).unwrap().approvals, 1);
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{root}"), &admin, r#"{"approvals":"two"}"#).await.0, 400);
}

#[tokio::test]
async fn team_owners_and_admins_give_either_approval_within_their_team() {
    let (port, app, admin, _) = serve_app().await;
    user_with(port, &admin, "ana@example.com", "admin").await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let (eve, eve_auth) = user_with(port, &admin, "eve@example.com", "member").await;
    let (cy, cy_auth) = user_with(port, &admin, "cy@example.com", "member").await;
    let (dee, dee_auth) = user_with(port, &admin, "dee@example.com", "member").await;
    let (code, t) = json_call(port, "POST", "/api/teams", &admin, &json!({ "name": "Alpha", "owner": ada }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let alpha = t["id"].as_str().unwrap().to_string();
    for (u, r) in [(&eve, "admin"), (&cy, "member"), (&dee, "member")] {
        assert_eq!(call(port, "PUT", &format!("/api/teams/{alpha}/members/{u}"), &admin, &json!({ "role": r }).to_string()).await.0, 200);
    }
    let helpdesk = role(port, &admin, json!({ "name": "Team helpdesk", "permissions": ["users.manage"], "maxDays": 7, "requestable": true, "approvals": 2 })).await;

    // A team admin gives the first, not the second; the team's owner gives the second.
    let q = asked(port, &cy_auth, json!({ "role": helpdesk, "scope": "team", "hours": 24, "reason": "Onboarding" })).await;
    let (code, v) = json_call(port, "POST", &team_at(&q, "approve"), &eve_auth, r#"{"hours":12}"#).await;
    assert_eq!((code, v["request"]["status"].as_str(), v["approvals"]["given"].as_i64()), (200, Some("pending"), Some(1)), "{v}");
    assert_eq!(events(port, &admin, "role.request_first_approved").await[0]["details"]["via"], "team");
    let (_, mine) = json_call(port, "GET", "/api/team/role-requests", &ada_auth, "").await;
    assert_eq!((mine["pending"].as_i64(), mine["requests"][0]["firstApproval"]["by"]["id"].as_str()), (Some(1), Some(eve.as_str())), "{mine}");
    assert_eq!(call(port, "POST", &team_at(&q, "approve"), &eve_auth, "{}").await.0, 409, "not both approvals");
    let (code, v) = json_call(port, "POST", &team_at(&q, "approve"), &ada_auth, "{}").await;
    assert_eq!((code, v["request"]["status"].as_str()), (200, Some("approved")), "{v}");
    assert!((v["role"]["expiresAt"].as_i64().unwrap() - db::now() - 12 * 3_600_000).abs() < 60_000, "the first's hours: {v}");
    let approved = &events(port, &admin, "role.request_approved").await[0];
    assert_eq!((approved["details"]["approvers"].clone(), approved["details"]["via"].as_str()), (json!([eve, ada]), Some("team")), "{approved}");
    assert_eq!(app.db.team_member(&cy).unwrap().role_id.as_deref(), Some(helpdesk.as_str()));

    // A team admin and a server admin make two approvers too.
    let q = asked(port, &dee_auth, json!({ "role": helpdesk, "scope": "team", "hours": 8, "reason": "Invites" })).await;
    assert_eq!(json_call(port, "POST", &team_at(&q, "approve"), &eve_auth, "{}").await.0, 200);
    // But a team admin who's since become a plain member no longer counts.
    assert_eq!(call(port, "PUT", &format!("/api/teams/{alpha}/members/{eve}"), &admin, r#"{"role":"member"}"#).await.0, 200);
    let (code, v) = approve(port, &admin, &q, json!({})).await;
    assert_eq!((code, v["request"]["status"].as_str(), v["request"]["firstApproval"]["by"]["id"].as_str()), (200, Some("pending"), Some("operator")), "{v}");
    assert_eq!(events(port, &admin, "role.request_first_approved").await[0]["details"]["replaced"]["by"], eve.as_str());
    let (code, v) = json_call(port, "POST", &team_at(&q, "approve"), &ada_auth, "{}").await;
    assert_eq!((code, v["request"]["status"].as_str()), (200, Some("approved")), "{v}");
    assert_eq!(events(port, &admin, "role.request_approved").await[0]["details"]["approvers"], json!(["operator", ada]));
    assert_eq!(app.db.team_member(&dee).unwrap().role_id.as_deref(), Some(helpdesk.as_str()));
}

#[test]
fn a_first_approval_counts_for_admins_and_the_teams_deciders_only() {
    use crate::db::{RequestState, RoleRequest, TeamMember, User};
    use rbac::Role;
    let person = |id: &str, role: Role| User {
        id: id.into(),
        email: None,
        name: id.into(),
        role,
        status: "active".into(),
        idp_issuer: None,
        idp_subject: None,
        created_at: 0,
        updated_at: 0,
        last_login_at: None,
        last_login_method: None,
        last_login_idp_provider: None,
        tier: None,
        region: None,
        erased_at: None,
        erased_as: None,
        role_id: None,
        role_expires_at: None,
        service: false,
    };
    let member = |user: &str, role: &str| TeamMember { user_id: user.into(), team_id: "t1".into(), role: role.into(), joined_at: 0, added_by: None, role_id: None, role_expires_at: None };
    let q = |team: Option<&str>| RoleRequest {
        id: "rq1".into(),
        user_id: "bo".into(),
        role_id: "r1".into(),
        team_id: team.map(str::to_string),
        hours: 8,
        reason: "x".into(),
        status: "pending".into(),
        created_at: 0,
        expires_at: 1,
        decided_at: None,
        decided_by: None,
        note: None,
        granted_until: None,
        first: None,
    };
    let role = db::CustomRole {
        id: "r1".into(),
        name: "Root".into(),
        description: String::new(),
        base: Role::Member,
        permissions: vec![],
        max_days: Some(1),
        requestable: true,
        approvals: 2,
        created_at: 0,
        created_by: None,
        updated_at: 0,
    };
    let bo = person("bo", Role::Member);
    let bo_in = member("bo", "member");
    let counts = |req: &RoleRequest, asker: Option<&TeamMember>, from_idp: bool, first: Option<(&User, Option<&TeamMember>)>| {
        role_requests::first_counts(&RequestState { request: req, role: &role, user: &bo, member: asker, from_idp, first })
    };
    let (org, team) = (q(None), q(Some("t1")));
    let admin = person("ana", Role::Admin);
    let owner = person("ada", Role::Member);
    let owner_in = member("ada", "owner");
    let mut disabled = person("ana", Role::Admin);
    disabled.status = "disabled".into();
    let mut service = person("sa", Role::Admin);
    service.service = true;
    let readonly = person("rae", Role::Readonly);
    let readonly_in = member("rae", "admin");

    assert!(!counts(&org, None, false, None), "no first approval");
    assert!(counts(&org, None, false, Some((&admin, None))));
    assert!(counts(&team, Some(&bo_in), false, Some((&admin, None))), "an admin counts in a team too");
    assert!(!counts(&org, None, false, Some((&disabled, None))));
    assert!(!counts(&org, None, false, Some((&service, None))));
    assert!(!counts(&org, None, false, Some((&bo, None))), "never the asker");
    assert!(!counts(&org, None, false, Some((&owner, Some(&owner_in)))), "a team's owner decides nothing across the server");
    assert!(counts(&team, Some(&bo_in), false, Some((&owner, Some(&owner_in)))));
    assert!(!counts(&team, Some(&bo_in), false, Some((&owner, None))), "off the team");
    assert!(!counts(&team, Some(&bo_in), false, Some((&owner, Some(&member("ada", "member"))))), "no longer an owner or admin");
    assert!(!counts(&team, Some(&bo_in), true, Some((&owner, Some(&owner_in)))), "the asker's team role is from the IdP");
    assert!(!counts(&team, Some(&member("bo", "admin")), false, Some((&owner, Some(&owner_in)))), "the asker became a team admin");
    assert!(!counts(&team, Some(&bo_in), false, Some((&readonly, Some(&readonly_in)))), "read-only people decide nothing");
}
