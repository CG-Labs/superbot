//! Custom roles (ADR 0123), on the real router: admins build roles from the fixed set of
//! delegable permissions and give them across the server or within a team; each one
//! opens only its routes, never more than a delegate may do there, and every change is
//! audited. The built-in roles behave as before.

use crate::rbac::Role;
use crate::tests::{audit_list, call, call_with, serve_app};
use crate::users_http_tests::{parse, signed_in, user_with};
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

/// A new custom role. Returns its id.
async fn role(port: u16, admin: &str, name: &str, base: &str, perms: &[&str]) -> String {
    let (code, v) = json_call(port, "POST", "/api/roles", admin, &json!({ "name": name, "base": base, "permissions": perms }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

async fn give(port: u16, admin: &str, role: &str, user: &str) -> Value {
    let (code, v) = json_call(port, "PUT", &format!("/api/roles/{role}/users/{user}"), admin, "").await;
    assert_eq!(code, 200, "{v}");
    v
}

#[tokio::test]
async fn admins_build_roles_from_the_fixed_permissions_and_every_change_is_audited() {
    let (port, _, admin, _) = serve_app().await;
    let (_, member) = user_with(port, &admin, "m@example.com", "member").await;

    let (code, v) = json_call(port, "GET", "/api/roles", &admin, "").await;
    assert_eq!(code, 200, "{v}");
    let names: Vec<&str> = v["permissions"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["users.manage", "bots.manage", "audit.view", "billing.manage", "signups.approve", "machines.manage"]);
    let team: Vec<&str> = v["permissions"].as_array().unwrap().iter().filter(|p| p["team"] == true).map(|p| p["name"].as_str().unwrap()).collect();
    assert_eq!(team, ["users.manage", "billing.manage", "machines.manage"]);
    // The built-in roles are presets of the same permissions.
    let presets: Vec<(&str, usize)> = v["builtIn"].as_array().unwrap().iter().map(|r| (r["id"].as_str().unwrap(), r["permissions"].as_array().unwrap().len())).collect();
    assert_eq!(presets, [("admin", 12), ("member", 5), ("readonly", 3)]);
    assert_eq!(v["builtIn"][2]["permissions"], json!(["account", "read", "review"]));
    assert_eq!(v["roles"], json!([]));

    // Deny by default: only the fixed names, never admin.
    for (body, why) in [
        (json!({ "name": "X", "permissions": ["secrets.manage"] }), "unknown permission"),
        (json!({ "name": "X", "permissions": ["admin"] }), "admin isn't delegable"),
        (json!({ "name": "X", "permissions": ["write"] }), "built-in permissions come from the base"),
        (json!({ "name": "X", "permissions": "audit.view" }), "a list"),
        (json!({ "name": "X", "base": "admin", "permissions": [] }), "admin base"),
        (json!({ "name": "X", "base": "owner", "permissions": [] }), "unknown base"),
        (json!({ "name": "Admin", "permissions": [] }), "a built-in name"),
        (json!({ "name": " read-only ", "permissions": [] }), "a built-in name"),
        (json!({ "name": "", "permissions": [] }), "no name"),
        (json!({ "name": "X", "permissions": [], "extra": 1 }), "unknown field"),
    ] {
        assert_eq!(call(port, "POST", "/api/roles", &admin, &body.to_string()).await.0, 400, "{why}");
    }

    let id = role(port, &admin, "Auditor", "readonly", &["audit.view", "audit.view", "signups.approve"]).await;
    assert_eq!(call(port, "POST", "/api/roles", &admin, &json!({ "name": "auditor", "permissions": [] }).to_string()).await.0, 409);
    let (_, v) = json_call(port, "GET", "/api/roles/auditor", &admin, "").await;
    assert_eq!((v["id"].as_str(), v["base"].as_str()), (Some(id.as_str()), Some("readonly")));
    assert_eq!(v["permissions"], json!(["audit.view", "signups.approve"]));
    assert_eq!(v["effective"], json!(["account", "read", "review", "audit.view", "signups.approve"]));
    assert_eq!(v["holders"], json!({ "users": [], "teams": [] }));

    // Only admins see or change roles.
    for (m, p) in [("GET", "/api/roles".to_string()), ("POST", "/api/roles".to_string()), ("PATCH", format!("/api/roles/{id}")), ("DELETE", format!("/api/roles/{id}"))] {
        assert_eq!(call(port, m, &p, &member, r#"{"name":"Mine","permissions":[]}"#).await.0, 403, "{m} {p}");
    }

    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{id}"), &admin, r#"{"name":"Reviewer","permissions":["audit.view"],"description":"Quarterly access reviews"}"#).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["name"].as_str(), v["permissions"].clone()), (Some("Reviewer"), json!(["audit.view"])));
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{id}"), &admin, r#"{"permissions":["root"]}"#).await.0, 400);
    assert_eq!(call(port, "PATCH", "/api/roles/r0", &admin, r#"{"name":"Nope"}"#).await.0, 404);
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{id}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "GET", &format!("/api/roles/{id}"), &admin, "").await.0, 404);

    let created = events(port, &admin, "role.created").await;
    assert_eq!(created[0]["details"]["permissions"], json!(["audit.view", "signups.approve"]));
    let updated = events(port, &admin, "role.updated").await;
    assert_eq!(updated[0]["details"]["changes"]["name"], json!({ "from": "Auditor", "to": "Reviewer" }));
    assert_eq!(updated[0]["details"]["changes"]["permissions"]["to"], json!(["audit.view"]));
    assert_eq!(events(port, &admin, "role.deleted").await[0]["targetId"].as_str(), Some(id.as_str()));
    // The member's refusals are logged as before.
    assert!(events(port, &admin, "access.denied").await.iter().any(|e| e["details"]["path"] == "/api/roles"));
}

#[tokio::test]
async fn a_custom_role_opens_its_routes_and_nothing_else() {
    let (port, _, admin, _) = serve_app().await;
    let (bo, bo_auth) = user_with(port, &admin, "bo@example.com", "member").await;
    let auditor = role(port, &admin, "Auditor", "readonly", &["audit.view"]).await;
    assert_eq!(call(port, "GET", "/api/audit", &bo_auth, "").await.0, 403);

    let v = give(port, &admin, &auditor, &bo).await;
    assert_eq!((v["user"]["role"].as_str(), v["user"]["roleId"].as_str(), v["role"]["name"].as_str()), (Some("readonly"), Some(auditor.as_str()), Some("Auditor")));
    // The same session: roles are read on every request.
    let (_, me) = json_call(port, "GET", "/api/auth/me", &bo_auth, "").await;
    assert_eq!((me["role"].as_str(), me["customRole"]["name"].as_str()), (Some("readonly"), Some("Auditor")));
    assert_eq!(me["permissions"], json!(["account", "read", "review", "audit.view"]));
    for (m, p, want) in [
        ("GET", "/api/audit", 200),
        ("GET", "/api/audit/export.csv", 200),
        ("GET", "/api/access-review", 200),
        // Signing off a review is still the admins'.
        ("POST", "/api/access-review/complete", 403),
        ("GET", "/api/users", 403),
        ("GET", "/api/secrets", 403),
        ("GET", "/api/signups", 403),
        ("PUT", "/api/policy", 403),
        // Its base is read-only, so it can't write either.
        ("POST", "/api/bots", 403),
    ] {
        assert_eq!(call(port, m, p, &bo_auth, r#"{"name":"B"}"#).await.0, want, "{m} {p}");
    }
    let (_, denied) = call(port, "GET", "/api/users", &bo_auth, "").await;
    assert_eq!(parse(&denied)["error"].as_str(), Some("Your role (Auditor) can't do this."));

    // Taken away: back to its base, with nothing on top.
    let (code, v) = json_call(port, "DELETE", &format!("/api/roles/{auditor}/users/{bo}"), &admin, "").await;
    assert_eq!((code, v["user"]["role"].as_str(), v["user"]["roleId"].clone()), (200, Some("readonly"), Value::Null), "{v}");
    assert_eq!(call(port, "GET", "/api/audit", &bo_auth, "").await.0, 403);
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{auditor}/users/{bo}"), &admin, "").await.0, 404);

    let assigned = events(port, &admin, "role.assigned").await;
    assert_eq!((assigned[0]["details"]["user"].as_str(), assigned[0]["details"]["scope"].as_str()), (Some(bo.as_str()), Some("org")));
    let changed = events(port, &admin, "user.role_changed").await;
    assert_eq!((changed[0]["details"]["from"].as_str(), changed[0]["details"]["to"].as_str()), (Some("member"), Some("readonly")));
    assert_eq!(events(port, &admin, "role.unassigned").await[0]["details"]["keeps"].as_str(), Some("readonly"));
}

#[tokio::test]
async fn each_permission_opens_its_own_routes() {
    let (port, _, admin, _) = serve_app().await;
    let (target, _) = user_with(port, &admin, "t@example.com", "member").await;
    // (permission, a route it opens, a route of another permission it doesn't)
    let cases = [
        ("users.manage", "/api/users".to_string(), "/api/audit".to_string()),
        ("bots.manage", format!("/api/users/{target}/bots"), format!("/api/users/{target}")),
        ("audit.view", "/api/access-review".to_string(), "/api/usage".to_string()),
        ("billing.manage", "/api/usage".to_string(), "/api/signups".to_string()),
        ("signups.approve", "/api/signups".to_string(), "/api/machines".to_string()),
        ("machines.manage", format!("/api/users/{target}/machine"), format!("/api/users/{target}/routines")),
    ];
    for (i, (perm, opens, other)) in cases.iter().enumerate() {
        let id = role(port, &admin, &format!("Only {perm}"), "member", &[perm]).await;
        let (u, auth) = user_with(port, &admin, &format!("p{i}@example.com"), "member").await;
        assert_eq!(call(port, "GET", opens, &auth, "").await.0, 403, "{perm} {opens} needs the role");
        give(port, &admin, &id, &u).await;
        let code = call(port, "GET", opens, &auth, "").await.0;
        assert!(code != 403 && code != 401, "{perm} opens {opens}: {code}");
        assert_eq!(call(port, "GET", other, &auth, "").await.0, 403, "{perm} doesn't open {other}");
        // A machine's screens, logins and files stay with admins.
        assert_eq!(call(port, "GET", &format!("/api/users/{target}/machine/screens"), &auth, "").await.0, 403, "{perm}");
        assert_eq!(call(port, "GET", &format!("/api/users/{target}/machine/folder-sync"), &auth, "").await.0, 403, "{perm}");
        assert_eq!(call(port, "GET", &format!("/api/users/{target}/secrets"), &auth, "").await.0, 403, "{perm}");
    }
}

#[tokio::test]
async fn user_managers_never_reach_admins_or_make_them() {
    let (port, app, admin, _) = serve_app().await;
    let support = role(port, &admin, "Support", "member", &["users.manage"]).await;
    let (sam, sam_auth) = user_with(port, &admin, "sam@example.com", "member").await;
    let (root, _) = user_with(port, &admin, "root@example.com", "admin").await;
    let (peer, _) = user_with(port, &admin, "peer@example.com", "member").await;
    let (cy, _) = user_with(port, &admin, "cy@example.com", "member").await;
    give(port, &admin, &support, &sam).await;
    give(port, &admin, &support, &peer).await;

    assert_eq!(call(port, "GET", "/api/users", &sam_auth, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/sessions", &sam_auth, "").await.0, 200);
    assert_eq!(call(port, "POST", "/api/users", &sam_auth, r#"{"email":"x@example.com","role":"admin"}"#).await.0, 403);
    let (code, made) = json_call(port, "POST", "/api/users", &sam_auth, r#"{"email":"dee@example.com","role":"readonly"}"#).await;
    assert_eq!(code, 201, "{made}");
    let dee = made["id"].as_str().unwrap();
    assert_eq!(call(port, "PATCH", &format!("/api/users/{dee}"), &sam_auth, r#"{"name":"Dee","role":"member"}"#).await.0, 200);
    assert_eq!(call(port, "POST", &format!("/api/users/{dee}/login-codes"), &sam_auth, "").await.0, 200);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{cy}"), &sam_auth, r#"{"status":"disabled"}"#).await.0, 200);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{cy}"), &sam_auth, r#"{"status":"active"}"#).await.0, 200);

    for (m, path, body, why) in [
        ("PATCH", format!("/api/users/{dee}"), r#"{"role":"admin"}"#, "make an admin"),
        ("PATCH", format!("/api/users/{dee}"), r#"{"tier":null}"#, "change a tier without billing.manage"),
        ("PATCH", format!("/api/users/{root}"), r#"{"name":"R"}"#, "change an admin"),
        ("PATCH", "/api/users/operator".to_string(), r#"{"name":"R"}"#, "change the owner"),
        ("PATCH", format!("/api/users/{peer}"), r#"{"status":"disabled"}"#, "change someone with a custom role"),
        ("PATCH", format!("/api/users/{sam}"), r#"{"name":"Sam"}"#, "change themselves: they have one too"),
        ("POST", format!("/api/users/{root}/login-codes"), "", "sign in as an admin"),
        ("POST", "/api/users/operator/login-codes".to_string(), "", "sign in as the owner"),
        ("POST", format!("/api/users/{peer}/login-codes"), "", "sign in as a peer"),
        ("DELETE", format!("/api/users/{root}/sessions"), "", "sign an admin out"),
        ("POST", format!("/api/users/{dee}/identities"), "{}", "link identities"),
        ("DELETE", format!("/api/users/{dee}/mfa"), "", "reset a second factor"),
        ("POST", format!("/api/users/{dee}/erase"), "{}", "erase someone"),
        ("PUT", format!("/api/roles/{support}/users/{dee}"), "", "give roles"),
    ] {
        assert_eq!(call(port, m, &path, &sam_auth, body).await.0, 403, "{why}");
    }
    // An admin's session can't be ended one by one either.
    let root_auth = signed_in(port, &admin, &root).await.unwrap();
    let root_session = parse(&call(port, "GET", "/api/auth/me", &root_auth, "").await.1)["session"]["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "DELETE", &format!("/api/sessions/{root_session}"), &sam_auth, "").await.0, 403);
    assert_eq!(call(port, "GET", "/api/auth/me", &root_auth, "").await.0, 200);
    assert_eq!(app.db.user(&root).unwrap().role, Role::Admin);
    assert_eq!(app.db.user(dee).unwrap().role, Role::Member);

    let limits: Vec<String> = events(port, &admin, "access.denied").await.iter().filter(|e| e["details"]["reason"] == "delegate_limit").map(|e| e["details"]["limit"].as_str().unwrap().to_string()).collect();
    for l in ["admin_role", "tier", "protected_user"] {
        assert!(limits.contains(&l.to_string()), "{l}: {limits:?}");
    }

    // With billing.manage too, tiers are theirs to change.
    let both = role(port, &admin, "Support and billing", "member", &["users.manage", "billing.manage"]).await;
    let (sue, sue_auth) = user_with(port, &admin, "sue@example.com", "member").await;
    give(port, &admin, &both, &sue).await;
    assert_eq!(call(port, "PATCH", &format!("/api/users/{dee}"), &sue_auth, r#"{"tier":null}"#).await.0, 200);
}

#[tokio::test]
async fn signup_approvers_let_people_in_but_never_as_admins() {
    let (port, _, admin, _) = serve_app().await;
    let approvers = role(port, &admin, "Approvers", "member", &["signups.approve"]).await;
    let (ann, ann_auth) = user_with(port, &admin, "ann@example.com", "member").await;
    give(port, &admin, &approvers, &ann).await;
    for (i, email) in ["one@example.com", "two@example.com"].iter().enumerate() {
        let form = json!({ "name": "Ada Lovelace", "email": email, "company": "Analytical Engines", "teamSize": "11-50", "useCase": "Daily research briefs", "signIn": "microsoft", "consent": true, "website": "" });
        let (code, _, body) = call_with(port, "POST", "/api/signups", "", &format!("X-Forwarded-For: 203.0.113.{}\r\n", i + 1), &form.to_string()).await;
        assert_eq!(code, 202, "{body}");
    }
    let (_, list) = json_call(port, "GET", "/api/signups?status=pending", &ann_auth, "").await;
    let ids: Vec<String> = list.as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(ids.len(), 2, "{list}");
    assert_eq!(call(port, "POST", &format!("/api/signups/{}/approve", ids[0]), &ann_auth, r#"{"role":"admin"}"#).await.0, 403);
    let (code, v) = json_call(port, "POST", &format!("/api/signups/{}/approve", ids[0]), &ann_auth, r#"{"role":"member"}"#).await;
    assert_eq!((code, v["user"]["role"].as_str()), (200, Some("member")), "{v}");
    assert_eq!(call(port, "POST", &format!("/api/signups/{}/reject", ids[1]), &ann_auth, "").await.0, 200);
    // Approving is not managing people.
    assert_eq!(call(port, "GET", "/api/users", &ann_auth, "").await.0, 403);
}

#[tokio::test]
async fn a_new_base_follows_its_holders_and_held_roles_stay() {
    let (port, app, admin, _) = serve_app().await;
    let ops = role(port, &admin, "Ops", "member", &["machines.manage"]).await;
    let (al, al_auth) = user_with(port, &admin, "al@example.com", "admin").await;
    give(port, &admin, &ops, &al).await;
    // An admin given a custom role is one no longer.
    assert_eq!(app.db.user(&al).unwrap().role, Role::Member);
    assert_eq!(call(port, "GET", "/api/users", &al_auth, "").await.0, 403);

    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{ops}"), &admin, r#"{"base":"readonly"}"#).await;
    assert_eq!((code, v["users"].as_i64()), (200, Some(1)), "{v}");
    assert_eq!(app.db.user(&al).unwrap().role, Role::Readonly);
    assert_eq!(call(port, "POST", "/api/bots", &al_auth, r#"{"name":"B"}"#).await.0, 403);
    let moved = events(port, &admin, "user.role_changed").await;
    assert_eq!((moved[0]["details"]["to"].as_str(), moved[0]["details"]["reason"].as_str()), (Some("readonly"), Some("role_updated")));
    assert_eq!(events(port, &admin, "role.updated").await[0]["details"]["usersMoved"], 1);

    let (code, v) = json_call(port, "DELETE", &format!("/api/roles/{ops}"), &admin, "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("1 person"), "{v}");

    // A built-in role replaces the custom one, audited.
    let (code, v) = json_call(port, "PATCH", &format!("/api/users/{al}"), &admin, r#"{"role":"member"}"#).await;
    assert_eq!((code, v["roleId"].clone(), v["role"].as_str()), (200, Value::Null, Some("member")), "{v}");
    assert_eq!(events(port, &admin, "role.unassigned").await[0]["details"]["reason"].as_str(), Some("role_set"));
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{ops}"), &admin, "").await.0, 200);
}

#[tokio::test]
async fn erasing_a_holder_frees_their_role() {
    let (port, _, admin, _) = serve_app().await;
    let r = role(port, &admin, "Auditor", "readonly", &["audit.view"]).await;
    let (bo, _) = user_with(port, &admin, "bo@example.com", "member").await;
    give(port, &admin, &r, &bo).await;
    let (code, v) = json_call(port, "POST", &format!("/api/users/{bo}/erase"), &admin, "{}").await;
    assert_eq!(code, 200, "{v}");
    let (_, v) = json_call(port, "GET", &format!("/api/roles/{r}"), &admin, "").await;
    assert_eq!(v["users"], 0, "{v}");
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{r}"), &admin, "").await.0, 200);
}

#[tokio::test]
async fn the_owner_and_yourself_keep_your_roles() {
    let (port, _, admin, _) = serve_app().await;
    let r = role(port, &admin, "Viewer plus", "readonly", &["audit.view"]).await;
    let (code, v) = json_call(port, "PUT", &format!("/api/roles/{r}/users/operator"), &admin, "").await;
    assert_eq!(code, 409, "{v}");
    let (al, al_auth) = user_with(port, &admin, "al@example.com", "admin").await;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{r}/users/{al}"), &al_auth, "").await.0, 409);
    assert_eq!(call(port, "PUT", &format!("/api/roles/{r}/users/nobody@example.com"), &admin, "").await.0, 404);
    assert_eq!(call(port, "PUT", &format!("/api/roles/r0/users/{al}"), &admin, "").await.0, 404);
}

#[tokio::test]
async fn names_the_server_doesnt_know_grant_nothing() {
    let (port, app, admin, _) = serve_app().await;
    // As a newer version, or a hand edit, might leave it.
    let r = app.db.create_custom_role("Future", "", Role::Member, &["audit.view", "secrets.manage", "admin"], None).unwrap();
    let (cy, cy_auth) = user_with(port, &admin, "cy@example.com", "member").await;
    give(port, &admin, &r.id, &cy).await;
    let (_, v) = json_call(port, "GET", &format!("/api/roles/{}", r.id), &admin, "").await;
    assert_eq!((v["permissions"].clone(), v["unknown"].clone()), (json!(["audit.view"]), json!(["secrets.manage", "admin"])));
    assert_eq!(call(port, "GET", "/api/audit", &cy_auth, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/secrets", &cy_auth, "").await.0, 403);
    assert_eq!(call(port, "PUT", "/api/policy", &cy_auth, "{}").await.0, 403);
}

#[tokio::test]
async fn a_team_role_applies_only_in_its_team() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let (cy, cy_auth) = user_with(port, &admin, "cy@example.com", "member").await;
    let (dee, _) = user_with(port, &admin, "dee@example.com", "member").await;
    let (eve, _) = user_with(port, &admin, "eve@example.com", "member").await;
    let (out, _) = user_with(port, &admin, "out@example.com", "member").await;
    let (code, t) = json_call(port, "POST", "/api/teams", &admin, &json!({ "name": "Alpha", "owner": ada }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = t["id"].as_str().unwrap().to_string();
    for (u, r) in [(&cy, "member"), (&dee, "member"), (&eve, "admin")] {
        assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/members/{u}"), &admin, &json!({ "role": r }).to_string()).await.0, 200);
    }
    let people = role(port, &admin, "Team people", "member", &["users.manage", "audit.view"]).await;

    // Plain members can't manage the team.
    assert_eq!(call(port, "POST", "/api/team/invites", &cy_auth, r#"{"email":"new@example.com"}"#).await.0, 403);
    assert_eq!(call(port, "PUT", &format!("/api/roles/{people}/teams/{team}/users/{out}"), &admin, "").await.0, 404);
    let (code, v) = json_call(port, "PUT", &format!("/api/roles/{people}/teams/{team}/users/{cy}"), &admin, "").await;
    assert_eq!((code, v["applies"].clone()), (200, json!(["users.manage"])), "{v}");
    // Their role across the server doesn't change, and the team role adds nothing there.
    assert_eq!((app.db.user(&cy).unwrap().role, app.db.user(&cy).unwrap().role_id), (Role::Member, None));
    assert_eq!(call(port, "GET", "/api/audit", &cy_auth, "").await.0, 403);
    assert_eq!(call(port, "GET", "/api/users", &cy_auth, "").await.0, 403);

    let (_, mine) = json_call(port, "GET", "/api/team", &cy_auth, "").await;
    assert_eq!((mine["customRole"]["name"].as_str(), mine["permissions"].clone()), (Some("Team people"), json!(["users.manage"])));
    assert!(mine["invites"].is_array() && mine.get("machineDays").is_none(), "{mine}");
    let (code, inv) = json_call(port, "POST", "/api/team/invites", &cy_auth, r#"{"email":"new@example.com"}"#).await;
    assert_eq!(code, 201, "{inv}");
    assert_eq!(call(port, "POST", "/api/team/invites", &cy_auth, r#"{"email":"boss@example.com","role":"admin"}"#).await.0, 403);
    assert_eq!(call(port, "DELETE", &format!("/api/team/invites/{}", inv["id"].as_str().unwrap()), &cy_auth, "").await.0, 200);
    // An admin's invite can't be turned into a member's, and so withdrawn.
    assert_eq!(call(port, "POST", "/api/team/invites", &ada_auth, r#"{"email":"lead@example.com","role":"admin"}"#).await.0, 201);
    assert_eq!(call(port, "POST", "/api/team/invites", &cy_auth, r#"{"email":"lead@example.com","role":"member"}"#).await.0, 403);
    let (_, invites) = json_call(port, "GET", "/api/team", &ada_auth, "").await;
    assert!(invites["invites"].as_array().unwrap().iter().any(|i| i["email"] == "lead@example.com" && i["role"] == "admin"), "{invites}");
    // Not the team's machines, not roles in it, and not its owners or admins.
    assert_eq!(call(port, "POST", &format!("/api/team/members/{dee}/machine"), &cy_auth, "").await.0, 403);
    assert_eq!(call(port, "PATCH", &format!("/api/team/members/{dee}"), &cy_auth, r#"{"role":"admin"}"#).await.0, 403);
    assert_eq!(call(port, "PATCH", &format!("/api/team/members/{cy}"), &cy_auth, r#"{"role":"admin"}"#).await.0, 403);
    assert_eq!(call(port, "DELETE", &format!("/api/team/members/{ada}"), &cy_auth, "").await.0, 403);
    assert_eq!(call(port, "DELETE", &format!("/api/team/members/{eve}"), &cy_auth, "").await.0, 403);
    let refused = events(port, &admin, "access.denied").await;
    assert_eq!(refused.iter().filter(|e| e["details"]["limit"] == "team_role" && e["targetId"] == team.as_str()).count(), 4, "{refused:?}");
    let (_, preview) = json_call(port, "GET", &format!("/api/team/members/{eve}/offboarding"), &cy_auth, "").await;
    assert_eq!(preview["blocked"].as_str(), Some("admin"), "{preview}");
    // A plain member, they can take off.
    assert_eq!(call(port, "DELETE", &format!("/api/team/members/{dee}"), &cy_auth, "").await.0, 200);
    assert!(app.db.team_member(&dee).is_none());

    // The team's admins see who holds which role.
    let (_, team_view) = json_call(port, "GET", "/api/team", &ada_auth, "").await;
    let cy_row = team_view["members"].as_array().unwrap().iter().find(|m| m["id"] == cy.as_str()).unwrap().clone();
    assert_eq!(cy_row["customRole"]["name"].as_str(), Some("Team people"));

    // Read-only people change nothing, in a team too: not given a team role, and one they
    // hold does nothing while they're read-only.
    let (ro, _) = user_with(port, &admin, "ro@example.com", "readonly").await;
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/members/{ro}"), &admin, r#"{"role":"member"}"#).await.0, 200);
    assert_eq!(call(port, "PUT", &format!("/api/roles/{people}/teams/{team}/users/{ro}"), &admin, "").await.0, 409);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{cy}"), &admin, r#"{"role":"readonly"}"#).await.0, 200);
    let (_, mine) = json_call(port, "GET", "/api/team", &cy_auth, "").await;
    assert_eq!(mine["permissions"], json!([]), "{mine}");
    assert!(mine.get("invites").is_none(), "{mine}");
    assert_eq!(call(port, "GET", &format!("/api/team/members/{eve}/offboarding"), &cy_auth, "").await.0, 403);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{cy}"), &admin, r#"{"role":"member"}"#).await.0, 200);

    // Leaving the team takes the role with it.
    assert_eq!(call(port, "POST", "/api/team/leave", &cy_auth, "").await.0, 200);
    let (_, r) = json_call(port, "GET", &format!("/api/roles/{people}"), &admin, "").await;
    assert_eq!(r["teamMembers"], 0, "{r}");
    let assigned = events(port, &admin, "role.assigned").await;
    assert_eq!((assigned[0]["details"]["scope"].as_str(), assigned[0]["details"]["team"].as_str()), (Some("team"), Some(team.as_str())));
}

#[tokio::test]
async fn the_access_review_shows_custom_roles() {
    let (port, _, admin, _) = serve_app().await;
    let (bo, _) = user_with(port, &admin, "bo@example.com", "member").await;
    let before = parse(&call(port, "GET", "/api/access-review", &admin, "").await.1)["digest"].clone();
    let r = role(port, &admin, "Auditor", "readonly", &["audit.view"]).await;
    give(port, &admin, &r, &bo).await;
    let (_, report) = json_call(port, "GET", "/api/access-review", &admin, "").await;
    assert_ne!(report["digest"], before);
    let me = report["groups"].as_array().unwrap().iter().flat_map(|g| g["people"].as_array().unwrap().clone()).find(|p| p["id"] == bo.as_str()).unwrap();
    assert_eq!(me["customRole"], json!({ "id": r, "name": "Auditor", "permissions": ["audit.view"] }));
    let (_, csv) = call(port, "GET", "/api/access-review/export.csv", &admin, "").await;
    assert!(csv.contains("readonly; Auditor: audit.view"), "{csv}");
}
