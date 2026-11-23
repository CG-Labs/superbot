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

/// The roles editors in the apps show what each person can do from these lists (ADR 0132).
#[tokio::test]
async fn admin_user_views_list_each_persons_effective_permissions() {
    let (port, _, admin, _) = serve_app().await;
    let (bo, _) = user_with(port, &admin, "bo@example.com", "member").await;
    let (_, viewer) = user_with(port, &admin, "rex@example.com", "readonly").await;
    let perms_of = |users: &Value, email: &str| users.as_array().unwrap().iter().find(|u| u["email"] == email).map(|u| u["permissions"].clone()).unwrap();

    let (_, users) = json_call(port, "GET", "/api/users", &admin, "").await;
    assert_eq!(perms_of(&users, "bo@example.com"), json!(["account", "read", "review", "write", "approve"]));
    assert_eq!(perms_of(&users, "rex@example.com"), json!(["account", "read", "review"]));
    assert_eq!(users.as_array().unwrap().iter().find(|u| u["breakGlass"] == true).unwrap()["permissions"].as_array().unwrap().len(), 12);

    let support = role(port, &admin, "Support", "readonly", &["users.manage", "audit.view"]).await;
    give(port, &admin, &support, &bo).await;
    let (_, v) = json_call(port, "GET", &format!("/api/users/{bo}"), &admin, "").await;
    assert_eq!(v["permissions"], json!(["account", "read", "review", "users.manage", "audit.view"]), "{v}");
    assert_eq!(v["customRole"], json!({ "id": support, "name": "Support" }));

    // A change to the role shows at once, as it applies at once.
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{support}"), &admin, r#"{"base":"member","permissions":["users.manage"]}"#).await.0, 200);
    let (_, users) = json_call(port, "GET", "/api/users", &admin, "").await;
    assert_eq!(perms_of(&users, "bo@example.com"), json!(["account", "read", "review", "write", "approve", "users.manage"]));
    // Read-only people don't see anyone's.
    assert_eq!(call(port, "GET", "/api/users", &viewer, "").await.0, 403);
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
async fn an_email_in_any_case_finds_the_person() {
    // So the console has to match emails the same way before it warns about an admin.
    let (port, app, admin, _) = serve_app().await;
    let r = role(port, &admin, "Ops", "member", &["machines.manage"]).await;
    let (al, _) = user_with(port, &admin, "al@example.com", "admin").await;
    let v = give(port, &admin, &r, "Al@Example.COM").await;
    assert_eq!(v["user"]["id"].as_str(), Some(al.as_str()), "{v}");
    assert_eq!(app.db.user(&al).unwrap().role, Role::Member);
}

#[tokio::test]
async fn names_the_server_doesnt_know_grant_nothing() {
    let (port, app, admin, _) = serve_app().await;
    // As a newer version, or a hand edit, might leave it.
    let r = app.db.create_custom_role("Future", "", Role::Member, &["audit.view", "secrets.manage", "admin"], None, None).unwrap();
    let (cy, cy_auth) = user_with(port, &admin, "cy@example.com", "member").await;
    give(port, &admin, &r.id, &cy).await;
    let (_, v) = json_call(port, "GET", &format!("/api/roles/{}", r.id), &admin, "").await;
    assert_eq!((v["permissions"].clone(), v["unknown"].clone()), (json!(["audit.view"]), json!(["secrets.manage", "admin"])));
    assert_eq!(call(port, "GET", "/api/audit", &cy_auth, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/secrets", &cy_auth, "").await.0, 403);
    assert_eq!(call(port, "PUT", "/api/policy", &cy_auth, "{}").await.0, 403);

    // A save without permissions keeps them; the editor always sends them for such a role.
    let path = format!("/api/roles/{}", r.id);
    let (_, v) = json_call(port, "PATCH", &path, &admin, r#"{"name":"Future 2"}"#).await;
    assert_eq!(v["unknown"], json!(["secrets.manage", "admin"]), "{v}");
    let (code, v) = json_call(port, "PATCH", &path, &admin, r#"{"name":"Future 3","permissions":["audit.view"]}"#).await;
    assert_eq!((code, v["permissions"].clone(), v["unknown"].clone()), (200, json!(["audit.view"]), json!([])), "{v}");
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
    // An expired one protects nothing.
    app.db.put_team_invite(&team, "old@example.com", "admin", None, db::now() - 1);
    assert_eq!(call(port, "POST", "/api/team/invites", &cy_auth, r#"{"email":"old@example.com","role":"member"}"#).await.0, 201);
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

/// A role given until an end (ADR 0197): the end shows wherever the role does, it grants
/// nothing once it passes, in the same session and before any sweep, and the sweep takes
/// it away, audited as the server's.
#[tokio::test]
async fn a_role_given_until_an_end_stops_when_it_passes() {
    let (port, app, admin, _) = serve_app().await;
    let (bo, bo_auth) = user_with(port, &admin, "bo@example.com", "member").await;
    let auditor = role(port, &admin, "Auditor", "readonly", &["audit.view"]).await;
    let ends = db::now() + 2 * roles::DAY;
    let path = format!("/api/roles/{auditor}/users/{bo}");
    let body = json!({ "expiresAt": ends, "reason": "Q3 SOX walkthrough" }).to_string();
    let (code, v) = json_call(port, "PUT", &path, &admin, &body).await;
    assert_eq!((code, v["role"]["expiresAt"].as_i64(), v["user"]["roleExpiresAt"].as_i64()), (200, Some(ends), Some(ends)), "{v}");
    let (_, me) = json_call(port, "GET", "/api/auth/me", &bo_auth, "").await;
    assert_eq!(me["customRole"], json!({ "id": auditor, "name": "Auditor", "expiresAt": ends }));
    let (_, u) = json_call(port, "GET", &format!("/api/users/{bo}"), &admin, "").await;
    assert_eq!(u["customRole"]["expiresAt"].as_i64(), Some(ends), "{u}");
    let (_, r) = json_call(port, "GET", &format!("/api/roles/{auditor}"), &admin, "").await;
    assert_eq!(r["holders"]["users"][0]["expiresAt"].as_i64(), Some(ends), "{r}");
    assert_eq!(call(port, "GET", "/api/audit", &bo_auth, "").await.0, 200);
    let given = events(port, &admin, "role.assigned").await;
    assert_eq!((given[0]["details"]["expiresAt"].as_i64(), given[0]["details"]["reason"].as_str()), (Some(ends), Some("Q3 SOX walkthrough")));

    // Given again, the end moves, audited with the end it had.
    let later = ends + roles::DAY;
    assert_eq!(call(port, "PUT", &path, &admin, &json!({ "expiresAt": later }).to_string()).await.0, 200);
    let given = events(port, &admin, "role.assigned").await;
    assert_eq!((given.len(), given[0]["details"]["expiresAt"].as_i64(), given[0]["details"]["from"]["expiresAt"].as_i64()), (2, Some(later), Some(ends)));
    // The same end again changes nothing, so isn't audited.
    assert_eq!(call(port, "PUT", &path, &admin, &json!({ "expiresAt": later }).to_string()).await.0, 200);
    assert_eq!(events(port, &admin, "role.assigned").await.len(), 2);

    let past = db::now() - 1;
    app.db.move_role_end(&bo, past);
    assert_eq!(call(port, "GET", "/api/audit", &bo_auth, "").await.0, 403, "at once, in the same session");
    let (_, me) = json_call(port, "GET", "/api/auth/me", &bo_auth, "").await;
    assert_eq!((me["customRole"].clone(), me["permissions"].clone()), (Value::Null, json!(["account", "read", "review"])), "its base stays");
    assert!(events(port, &admin, "role.expired").await.is_empty(), "not swept yet");
    assert_eq!(roles::expire_due(&app), 1);
    let expired = events(port, &admin, "role.expired").await;
    assert_eq!(expired.len(), 1);
    let e = &expired[0];
    assert_eq!((e["targetId"].as_str(), e["actorKind"].as_str(), e["actorId"].as_str()), (Some(auditor.as_str()), Some("system"), Some("roles")), "{e}");
    assert_eq!(e["details"], json!({ "name": "Auditor", "user": bo, "scope": "org", "expiresAt": past, "keeps": "readonly" }));
    assert_eq!(roles::expire_due(&app), 0, "once");
    assert_eq!(app.db.user(&bo).unwrap().role, Role::Readonly);
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{auditor}"), &admin, "").await.0, 200, "nobody holds it");
}

#[tokio::test]
async fn ends_are_checked_and_a_time_bound_role_needs_one_within_its_limit() {
    let (port, _, admin, _) = serve_app().await;
    let (bo, _) = user_with(port, &admin, "bo@example.com", "member").await;
    let (cy, _) = user_with(port, &admin, "cy@example.com", "member").await;
    for (body, why) in [
        (json!({ "name": "X", "permissions": [], "maxDays": 0 }), "at least a day"),
        (json!({ "name": "X", "permissions": [], "maxDays": 366 }), "at most a year"),
        (json!({ "name": "X", "permissions": [], "maxDays": "7" }), "a number"),
        (json!({ "name": "X", "permissions": [], "maxDays": 1.5 }), "whole days"),
    ] {
        assert_eq!(call(port, "POST", "/api/roles", &admin, &body.to_string()).await.0, 400, "{why}");
    }
    let (code, v) = json_call(port, "POST", "/api/roles", &admin, r#"{"name":"Break glass","base":"member","permissions":["users.manage","machines.manage"],"maxDays":7}"#).await;
    assert_eq!((code, v["maxDays"].as_i64()), (201, Some(7)), "{v}");
    let tb = v["id"].as_str().unwrap().to_string();
    assert_eq!(events(port, &admin, "role.created").await[0]["details"]["maxDays"], 7);
    let plain = role(port, &admin, "Auditor", "readonly", &["audit.view"]).await;

    let day = roles::DAY;
    let now = db::now();
    let give = |role: &str, user: &str| format!("/api/roles/{role}/users/{user}");
    for (role, body, why) in [
        (&tb, String::new(), "a time-bound role needs an end"),
        (&tb, json!({ "expiresAt": null }).to_string(), "a time-bound role needs an end"),
        (&tb, json!({ "expiresAt": now + 8 * day }).to_string(), "beyond its limit"),
        (&plain, json!({ "expiresAt": now - 1 }).to_string(), "an end gone already"),
        (&plain, json!({ "expiresAt": now + 366 * day }).to_string(), "beyond a year"),
        (&plain, json!({ "expiresAt": "tomorrow" }).to_string(), "a time"),
        (&plain, json!({ "until": now + day }).to_string(), "unknown field"),
        (&plain, json!({ "reason": 5 }).to_string(), "reason is text"),
        (&plain, "[]".to_string(), "an object"),
        (&plain, "{".to_string(), "JSON"),
        (&plain, "  ".to_string(), "a body that isn't JSON is never read as none"),
    ] {
        let (code, v) = json_call(port, "PUT", &give(role, &bo), &admin, &body).await;
        assert_eq!(code, 400, "{why}: {v}");
    }
    let (_, v) = json_call(port, "PUT", &give(&tb, &bo), &admin, "").await;
    assert!(v["error"].as_str().unwrap().contains("at most 7 days"), "{v}");
    assert_eq!(call(port, "PUT", &give(&tb, &bo), &admin, &json!({ "expiresAt": now + 6 * day }).to_string()).await.0, 200);
    // A role with no limit can still be given with no end, as before.
    assert_eq!(call(port, "PUT", &give(&plain, &cy), &admin, "").await.0, 200);

    // The limit can't shrink under someone who holds it longer, nor be set on a role held with no end.
    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{tb}"), &admin, r#"{"maxDays":3}"#).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("1 holds it with no end or a later one"), "{v}");
    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{plain}"), &admin, r#"{"maxDays":30}"#).await;
    assert_eq!(code, 409, "{v}");
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{tb}"), &admin, r#"{"maxDays":10}"#).await.0, 200);
    let updated = events(port, &admin, "role.updated").await;
    assert_eq!(updated[0]["details"]["changes"]["maxDays"], json!({ "from": 7, "to": 10 }));
    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{tb}"), &admin, r#"{"maxDays":null}"#).await;
    assert_eq!((code, v["maxDays"].clone()), (200, Value::Null), "{v}");
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{tb}"), &admin, r#"{"maxDays":7}"#).await.0, 200);

    // Service accounts hold their role for as long as they exist, so never a time-bound one.
    let (code, v) = json_call(port, "POST", "/api/service-accounts", &admin, &json!({ "name": "CI", "role": tb }).to_string()).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("time-bound"), "{v}");
    let (_, list) = json_call(port, "GET", "/api/service-accounts", &admin, "").await;
    assert!(!list["choices"].to_string().contains(&tb), "not offered: {list}");
    assert!(list["choices"]["server"].to_string().contains(&plain), "{list}");
}

#[tokio::test]
async fn a_team_role_can_end_too() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (cy, cy_auth) = user_with(port, &admin, "cy@example.com", "member").await;
    let (_, t) = json_call(port, "POST", "/api/teams", &admin, &json!({ "name": "Alpha", "owner": ada }).to_string()).await;
    let team = t["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/members/{cy}"), &admin, r#"{"role":"member"}"#).await.0, 200);
    let people = role(port, &admin, "Team people", "member", &["users.manage"]).await;
    let path = format!("/api/roles/{people}/teams/{team}/users/{cy}");
    assert_eq!(call(port, "PUT", &path, &admin, &json!({ "expiresAt": db::now() - 1 }).to_string()).await.0, 400);
    let ends = db::now() + roles::DAY;
    let (code, v) = json_call(port, "PUT", &path, &admin, &json!({ "expiresAt": ends, "reason": "Onboarding week" }).to_string()).await;
    assert_eq!((code, v["role"]["expiresAt"].as_i64()), (200, Some(ends)), "{v}");
    let (_, mine) = json_call(port, "GET", "/api/team", &cy_auth, "").await;
    assert_eq!((mine["customRole"]["expiresAt"].as_i64(), mine["permissions"].clone()), (Some(ends), json!(["users.manage"])), "{mine}");
    let (_, r) = json_call(port, "GET", &format!("/api/roles/{people}"), &admin, "").await;
    assert_eq!(r["holders"]["teams"][0]["expiresAt"].as_i64(), Some(ends), "{r}");
    assert_eq!(call(port, "POST", "/api/team/invites", &cy_auth, r#"{"email":"new@example.com"}"#).await.0, 201);

    app.db.move_role_end(&cy, db::now() - 1);
    assert_eq!(call(port, "POST", "/api/team/invites", &cy_auth, r#"{"email":"two@example.com"}"#).await.0, 403);
    let (_, mine) = json_call(port, "GET", "/api/team", &cy_auth, "").await;
    assert_eq!((mine["customRole"].clone(), mine["permissions"].clone()), (Value::Null, json!([])), "{mine}");
    // Any roles route sweeps first, so what it shows is what's held.
    let (_, r) = json_call(port, "GET", &format!("/api/roles/{people}"), &admin, "").await;
    assert_eq!(r["teamMembers"], 0, "{r}");
    let expired = events(port, &admin, "role.expired").await;
    assert_eq!((expired[0]["details"]["scope"].as_str(), expired[0]["details"]["team"].as_str(), expired[0]["details"]["user"].as_str()), (Some("team"), Some(team.as_str()), Some(cy.as_str())));
    assert!(app.db.team_member(&cy).is_some(), "still on the team");
}

#[tokio::test]
async fn the_access_review_shows_when_a_role_ends() {
    let (port, app, admin, _) = serve_app().await;
    let (bo, _) = user_with(port, &admin, "bo@example.com", "member").await;
    let r = role(port, &admin, "Auditor", "readonly", &["audit.view"]).await;
    give(port, &admin, &r, &bo).await;
    let digest = |v: &Value| v["digest"].as_str().unwrap().to_string();
    let standing = parse(&call(port, "GET", "/api/access-review", &admin, "").await.1);
    let ends = db::now() + 3 * roles::DAY;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{r}/users/{bo}"), &admin, &json!({ "expiresAt": ends }).to_string()).await.0, 200);
    let (_, report) = json_call(port, "GET", "/api/access-review", &admin, "").await;
    assert_ne!(digest(&report), digest(&standing), "an end is part of what was signed off");
    let me = report["groups"].as_array().unwrap().iter().flat_map(|g| g["people"].as_array().unwrap().clone()).find(|p| p["id"] == bo.as_str()).unwrap();
    assert_eq!(me["customRole"], json!({ "id": r, "name": "Auditor", "permissions": ["audit.view"], "expiresAt": ends }));
    let (_, csv) = call(port, "GET", "/api/access-review/export.csv", &admin, "").await;
    assert!(csv.contains("readonly; Auditor: audit.view until 20"), "{csv}");
    // A later end makes an earlier sign-off stale.
    assert_eq!(call(port, "PUT", &format!("/api/roles/{r}/users/{bo}"), &admin, &json!({ "expiresAt": ends + roles::DAY }).to_string()).await.0, 200);
    assert_ne!(digest(&parse(&call(port, "GET", "/api/access-review", &admin, "").await.1)), digest(&report));
    // Back to no end, the digest is the one a standing role has.
    assert_eq!(call(port, "PUT", &format!("/api/roles/{r}/users/{bo}"), &admin, "").await.0, 200);
    assert_eq!(digest(&parse(&call(port, "GET", "/api/access-review", &admin, "").await.1)), digest(&standing));
    assert!(app.db.user(&bo).unwrap().role_expires_at.is_none());
}
