//! SCIM role groups (ADR 0180) on the real router: declared by an admin, taken on when
//! the IdP pushes the group, never a team, so they overlap teams and each other; never
//! admin nor a role that reaches admins; the next role group in line takes over when one
//! stops giving a role; an IdP delete puts the declaration back to waiting. Every step
//! audited.

use crate::rbac::Role;
use crate::scim_http_tests::{events, okta_user, scim, session_for, token};
use crate::tests::{call, serve_app_with};
use crate::users_http_tests::parse;
use crate::*;

const GROUPS: &str = "/scim/v2/Groups";
const ROLE_GROUPS: &str = "/api/scim/role-groups";
const PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

async fn serve(roles: bool) -> (u16, AppState, String) {
    let (port, app, admin, _) = serve_app_with(move |a| {
        a.scim.enabled = true;
        a.scim.groups = true;
        a.scim.group_roles = roles;
    })
    .await;
    (port, app, admin)
}

async fn json_call(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(port, method, path, who, body).await;
    (code, parse(&body))
}

async fn person(port: u16, token: &str, email: &str) -> String {
    let (code, _, u) = scim(port, token, "POST", "/scim/v2/Users", okta_user(email, email)).await;
    assert_eq!(code, 201, "{u}");
    u["id"].as_str().unwrap().to_string()
}

fn group_body(name: &str, external_id: Option<&str>, members: &[&str]) -> Value {
    let mut v = json!({ "displayName": name, "members": members.iter().map(|m| json!({ "value": m })).collect::<Vec<_>>() });
    if let Some(x) = external_id {
        v["externalId"] = json!(x);
    }
    v
}

async fn push(port: u16, token: &str, name: &str, members: &[&str]) -> String {
    let (code, _, g) = scim(port, token, "POST", GROUPS, group_body(name, None, members)).await;
    assert_eq!(code, 201, "{g}");
    g["id"].as_str().unwrap().to_string()
}

async fn members(port: u16, token: &str, group: &str, op: &str, users: &[&str]) {
    let body = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": op, "path": "members", "value": users.iter().map(|u| json!({ "value": u })).collect::<Vec<_>>() }] });
    let (code, _, v) = scim(port, token, "PATCH", &format!("{GROUPS}/{group}"), body).await;
    assert_eq!(code, 204, "{v}");
}

async fn role(port: u16, admin: &str, name: &str, base: &str, perms: &[&str]) -> String {
    let (code, v) = json_call(port, "POST", "/api/roles", admin, &json!({ "name": name, "base": base, "permissions": perms }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

async fn declare(port: u16, admin: &str, body: Value) -> (u16, Value) {
    json_call(port, "POST", ROLE_GROUPS, admin, &body.to_string()).await
}

async fn declared(port: u16, admin: &str, tenant: &str, name: &str, role: &str) -> String {
    let (code, v) = declare(port, admin, json!({ "tenant": tenant, "displayName": name, "role": role })).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

fn role_of(app: &AppState, user: &str) -> Option<String> {
    app.db.user(user).and_then(|u| u.role_id)
}

#[tokio::test]
async fn role_groups_are_off_by_default_and_never_reach_admins() {
    let (port, _, admin) = serve(false).await;
    let audit = role(port, &admin, "Auditor", "member", &["audit.view"]).await;
    let (code, v) = json_call(port, "GET", ROLE_GROUPS, &admin, "").await;
    assert_eq!((code, v["enabled"].clone(), v["roleGroups"].clone()), (200, json!(false), json!([])));
    let (code, v) = declare(port, &admin, json!({ "tenant": "entra", "displayName": "Auditors", "role": audit })).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("SCIM_GROUP_ROLES=on"), "{v}");

    let (port, _, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "entra" })).await;
    push(port, &t, "Eng", &[]).await;
    let audit = role(port, &admin, "Auditor", "member", &["audit.view"]).await;
    let bots = role(port, &admin, "Bot keeper", "member", &["bots.manage"]).await;
    assert_eq!(call(port, "GET", ROLE_GROUPS, &format!("Bearer {t}"), "").await.0, 401, "a SCIM token can't reach the admin API");
    for (body, code, why) in [
        (json!({ "tenant": "entra", "displayName": "Admins", "role": "admin" }), 400, "never admin"),
        (json!({ "tenant": "entra", "displayName": "Readers", "role": "readonly" }), 400, "custom roles only"),
        (json!({ "tenant": "entra", "displayName": "Keepers", "role": bots }), 400, "bots.manage acts on admins' Bots"),
        (json!({ "tenant": "entra", "displayName": "Auditors", "role": "nope" }), 404, "unknown role"),
        (json!({ "tenant": "entra", "role": audit }), 400, "a displayName is needed"),
        (json!({ "tenant": "entra", "displayName": "Auditors" }), 400, "a role is needed"),
        (json!({ "tenant": "entra", "displayName": "Auditors", "role": audit, "kind": "team" }), 400, "unknown field"),
        (json!({ "tenant": "entra", "displayName": "Auditors", "role": audit, "scope": "everywhere" }), 400, "org or team"),
        (json!({ "tenant": "Not a tenant", "displayName": "Auditors", "role": audit }), 400, "tenant names are checked"),
        (json!({ "tenant": "entra", "displayName": "eng", "role": audit }), 409, "Eng is a team group already"),
    ] {
        let (got, v) = declare(port, &admin, body).await;
        assert_eq!(got, code, "{why}: {v}");
    }
    let refused = events(port, &admin, "action=scim.role_map_refused").await;
    let reasons: Vec<&str> = refused.iter().map(|e| e["details"]["reason"].as_str().unwrap()).collect();
    assert_eq!(reasons, ["reaches_admins", "built_in", "admin"], "newest first");
    assert_eq!((refused[0]["details"]["kind"].as_str(), refused[0]["outcome"].as_str()), (Some("role_group"), Some("denied")));

    let (code, g) = declare(port, &admin, json!({ "tenant": "entra", "displayName": "Auditors", "role": "Auditor" })).await;
    assert_eq!((code, g["state"].as_str(), g["applies"].clone()), (201, Some("waiting"), json!(["audit.view"])), "{g}");
    let (code, v) = declare(port, &admin, json!({ "tenant": "entra", "displayName": "AUDITORS", "role": audit })).await;
    assert_eq!(code, 409, "one declaration per name, any case: {v}");
    let (code, _) = declare(port, &admin, json!({ "tenant": "okta", "displayName": "Auditors", "role": audit })).await;
    assert_eq!(code, 201, "another tenant may have its own");
    let (_, v) = json_call(port, "GET", ROLE_GROUPS, &admin, "").await;
    assert_eq!((v["enabled"].clone(), v["roleGroups"].as_array().unwrap().len()), (json!(true), 2));
    assert_eq!(events(port, &admin, "action=scim.role_group_declared").await.len(), 2);
    // Waiting: the IdP doesn't see it.
    let (_, _, list) = scim(port, &t, "GET", GROUPS, Value::Null).await;
    assert_eq!(list["totalResults"], 1, "{list}");
    assert_eq!(scim(port, &t, "GET", &format!("{GROUPS}/{}", g["id"].as_str().unwrap()), Value::Null).await.0, 404);
}

fn names(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect()
}

/// The console offers only what the routes take (ADR 0253): each scope's roles are exactly
/// the ones a mapping and a role group may give there, and a group's mapped scopes go.
#[tokio::test]
async fn choices_offer_exactly_what_mappings_and_role_groups_take() {
    let (port, _, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let perms: [(&str, &[&str], Option<i64>); 5] = [
        ("Auditor", &["audit.view"], None),
        ("Bot keeper", &["bots.manage"], None),
        ("Machine keeper", &["machines.manage"], None),
        ("Help desk", &["users.manage"], None),
        ("Break glass", &["audit.view"], Some(7)),
    ];
    let mut ids = Vec::new();
    for (name, p, days) in perms {
        let (code, v) = json_call(port, "POST", "/api/roles", &admin, &json!({ "name": name, "base": "member", "permissions": p, "maxDays": days }).to_string()).await;
        assert_eq!(code, 201, "{v}");
        ids.push((name, v["id"].as_str().unwrap().to_string()));
    }
    let (_, v) = json_call(port, "GET", ROLE_GROUPS, &admin, "").await;
    let offered = v["choices"]["roles"].clone();
    assert_eq!(names(&offered["org"]), ["Auditor", "Help desk"], "{offered}");
    assert_eq!(names(&offered["team"]), ["Auditor", "Bot keeper", "Help desk"], "{offered}");
    let applies: Vec<Value> = offered["team"].as_array().unwrap().iter().map(|r| r["applies"].clone()).collect();
    assert_eq!(applies, [json!([]), json!([]), json!(["users.manage"])], "with what each gives there: only team permissions count in a team");
    assert_eq!(v["choices"]["tenants"], json!(["entra"]), "tenants with a token");
    assert_eq!(v["choices"]["undeclared"], json!([]), "no Google sync");
    let (_, m) = json_call(port, "GET", "/api/scim/role-mappings", &admin, "").await;
    assert_eq!(m["choices"]["roles"], offered, "the same roles for mappings");
    assert_eq!(m["choices"]["groups"], json!([]), "no team groups yet");

    for (i, (name, id)) in ids.iter().enumerate() {
        let team = push(port, &t, &format!("Team {i}"), &[]).await;
        for scope in ["org", "team"] {
            let shown = names(&offered[scope]).contains(name);
            let (code, v) = declare(port, &admin, json!({ "tenant": "okta", "displayName": format!("{name} {scope}"), "role": id, "scope": scope })).await;
            assert_eq!(code == 201, shown, "a role group of {name} in {scope}: {v}");
            let (code, v) = json_call(port, "POST", "/api/scim/role-mappings", &admin, &json!({ "team": team, "role": id, "scope": scope }).to_string()).await;
            assert_eq!(code == 201, shown, "a mapping of {name} in {scope}: {v}");
        }
    }

    let (_, v) = json_call(port, "GET", ROLE_GROUPS, &admin, "").await;
    assert_eq!(v["choices"]["tenants"], json!(["entra", "okta"]), "and tenants with a declaration");
    let (_, m) = json_call(port, "GET", "/api/scim/role-mappings", &admin, "").await;
    let left: Vec<(&str, Value)> = m["choices"]["groups"].as_array().unwrap().iter().map(|g| (g["displayName"].as_str().unwrap(), g["scopes"].clone())).collect();
    assert_eq!(
        left,
        [("Team 1", json!(["org"])), ("Team 2", json!(["team", "org"])), ("Team 4", json!(["team", "org"]))],
        "a group with both scopes mapped drops out; one with a scope left offers it"
    );
    let g = &m["choices"]["groups"][0];
    assert_eq!((g["tenant"].as_str(), g["team"]["name"].as_str()), (Some("entra"), Some("Team 1")), "{g}");

    // Changing a mapping's role (ADR 0265) takes exactly the same roles.
    for mapping in m["mappings"].as_array().unwrap() {
        let scope = mapping["scope"].as_str().unwrap();
        for (name, id) in &ids {
            let (code, v) = json_call(port, "PATCH", &format!("/api/scim/role-mappings/{}", mapping["id"].as_str().unwrap()), &admin, &json!({ "role": id }).to_string()).await;
            assert_eq!(code == 200, names(&offered[scope]).contains(name), "changing a mapping in {scope} to {name}: {v}");
        }
    }
}

#[tokio::test]
async fn a_pushed_role_group_overlaps_teams_and_gives_the_role_across_the_server() {
    let (port, app, admin) = serve(true).await;
    let (t, tid) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let ada = person(port, &t, "ada@contoso.example").await;
    let bo = person(port, &t, "bo@contoso.example").await;
    let cy = person(port, &t, "cy@contoso.example").await;
    let eng = push(port, &t, "Eng", &[&ada, &bo]).await;
    let audit = role(port, &admin, "Auditor", "readonly", &["audit.view"]).await;
    let gid = declared(port, &admin, "entra", "Auditors", &audit).await;

    // Entra pushes the group: it is the role group, not a team, and Eng keeps its people.
    let (code, headers, g) = scim(port, &t, "POST", GROUPS, group_body("Auditors", Some("8aa1-auditors"), &[&ada, &bo])).await;
    assert_eq!((code, g["id"].as_str(), g["externalId"].as_str()), (201, Some(gid.as_str()), Some("8aa1-auditors")), "{g}");
    assert!(headers.to_ascii_lowercase().contains("location: ") && headers.contains(&format!("/Groups/{gid}")), "{headers}");
    assert_eq!(g["members"].as_array().unwrap().len(), 2);
    for u in [&ada, &bo] {
        assert_eq!(app.db.team_member(u).map(|m| m.team_id), Some(eng.clone()), "still on Eng");
        assert_eq!(role_of(&app, u), Some(audit.clone()));
    }
    assert_eq!(app.db.user(&ada).unwrap().role, Role::Readonly, "the role's base is their built-in role");
    assert_eq!(app.db.teams().len(), 1, "no team was made");
    let adopted = &events(port, &admin, "action=scim.role_group_adopted").await[0];
    assert_eq!((adopted["actorId"].clone(), adopted["targetId"].as_str()), (json!(format!("scim:{tid}")), Some(gid.as_str())));
    let assigned = events(port, &admin, "action=role.assigned").await;
    assert!(assigned.iter().all(|e| e["details"]["roleGroup"] == gid.as_str() && e["details"]["via"] == "scim" && e["details"]["scope"] == "org"), "{assigned:?}");
    let ada_auth = session_for(port, &admin, &ada).await;
    assert_eq!(call(port, "GET", "/api/audit", &ada_auth, "").await.0, 200, "the role works");

    // The IdP sees both groups, and finds the role group like any other.
    let (_, _, list) = scim(port, &t, "GET", GROUPS, Value::Null).await;
    assert_eq!(list["totalResults"], 2, "{list}");
    let (_, _, found) = scim(port, &t, "GET", &format!("{GROUPS}?filter=externalId%20eq%20%228aa1-auditors%22"), Value::Null).await;
    assert_eq!(found["Resources"][0]["id"], gid.as_str(), "{found}");
    let (_, _, found) = scim(port, &t, "GET", &format!("{GROUPS}?filter=members%20eq%20%22{bo}%22"), Value::Null).await;
    assert_eq!(found["totalResults"], 2, "Bo is in both: {found}");
    // A team group can't take its name.
    let (code, _, v) = scim(port, &t, "POST", GROUPS, group_body("auditors", None, &[])).await;
    assert_eq!(code, 409, "{v}");
    let (code, _, v) = scim(port, &t, "PATCH", &format!("{GROUPS}/{eng}"), json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "replace", "path": "displayName", "value": "Auditors" }] })).await;
    assert_eq!(code, 409, "{v}");

    // Cy joins; Ada leaves and her role goes, audited with why.
    members(port, &t, &gid, "Add", &[&cy]).await;
    assert_eq!(role_of(&app, &cy), Some(audit.clone()));
    members(port, &t, &gid, "Remove", &[&ada]).await;
    let u = app.db.user(&ada).unwrap();
    assert_eq!((u.role, u.role_id), (Role::Member, None), "back to the role she had");
    assert_eq!(call(port, "GET", "/api/audit", &ada_auth, "").await.0, 403);
    let gone = &events(port, &admin, "action=role.unassigned").await[0];
    assert_eq!((gone["details"]["user"].as_str(), gone["details"]["reason"].as_str(), gone["details"]["roleGroup"].as_str()), (Some(ada.as_str()), Some("left_group"), Some(gid.as_str())));
    let updated = &events(port, &admin, "action=scim.group_updated").await[0];
    assert_eq!((updated["details"]["kind"].as_str(), updated["details"]["removed"].clone()), (Some("role"), json!([ada])));

    // A PUT renames it and sets everyone; externalId can't change.
    let (code, _, v) = scim(port, &t, "PUT", &format!("{GROUPS}/{gid}"), group_body("SuperBot Auditors", Some("8aa1-auditors"), &[&ada])).await;
    assert_eq!((code, v["displayName"].as_str(), v["members"].as_array().map(Vec::len)), (200, Some("SuperBot Auditors"), Some(1)), "{v}");
    assert_eq!((role_of(&app, &ada), role_of(&app, &bo), role_of(&app, &cy)), (Some(audit.clone()), None, None));
    let (code, _, _) = scim(port, &t, "PUT", &format!("{GROUPS}/{gid}"), group_body("SuperBot Auditors", Some("other"), &[])).await;
    assert_eq!(code, 400);

    let (_, v) = json_call(port, "GET", &format!("/api/roles/{audit}"), &admin, "").await;
    assert_eq!(v["scimRoleGroups"], 1, "{v}");
    assert_eq!(v["holders"]["users"][0]["scimMapping"], gid.as_str(), "{v}");
    let (code, v) = json_call(port, "GET", &format!("{ROLE_GROUPS}/{gid}"), &admin, "").await;
    assert_eq!((code, v["state"].as_str(), v["members"].as_u64(), v["holders"][0]["user"]["id"].as_str()), (200, Some("pushed"), Some(1), Some(ada.as_str())), "{v}");
}

#[tokio::test]
async fn the_next_role_group_in_line_takes_over() {
    let (port, app, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let cy = person(port, &t, "cy@example.com").await;
    let dee = person(port, &t, "dee@example.com").await;
    let audit = role(port, &admin, "Auditor", "member", &["audit.view"]).await;
    let bill = role(port, &admin, "Biller", "member", &["billing.manage"]).await;
    let ops = role(port, &admin, "Operator", "member", &["users.manage"]).await;
    let a = declared(port, &admin, "okta", "Auditors", &audit).await;
    let b = declared(port, &admin, "okta", "Billing", &bill).await;
    push(port, &t, "Billing", &[&cy]).await;
    push(port, &t, "Auditors", &[&cy]).await;
    assert_eq!(role_of(&app, &cy), Some(bill.clone()), "Billing pushed first gave it");
    let skip = &events(port, &admin, "action=scim.role_skipped").await[0];
    assert_eq!((skip["details"]["roleGroup"].as_str(), skip["details"]["reason"].as_str()), (Some(a.as_str()), Some("has_role")));

    // Out of Billing: Auditors, declared first, takes over.
    members(port, &t, &b, "Remove", &[&cy]).await;
    assert_eq!(role_of(&app, &cy), Some(audit.clone()));
    members(port, &t, &b, "Add", &[&cy, &dee]).await;
    assert_eq!((role_of(&app, &cy), role_of(&app, &dee)), (Some(audit.clone()), Some(bill.clone())), "one custom role each");

    // An admin changes what Auditors gives: Cy gets the new one at once.
    let (code, v) = json_call(port, "PATCH", &format!("{ROLE_GROUPS}/{a}"), &admin, &json!({ "role": "Operator" }).to_string()).await;
    assert_eq!((code, v["revoked"].clone(), v["granted"].clone()), (200, json!([cy]), json!([cy])), "{v}");
    assert_eq!(role_of(&app, &cy), Some(ops.clone()));
    let changed = &events(port, &admin, "action=scim.role_group_changed").await[0];
    assert_eq!((changed["details"]["from"]["name"].as_str(), changed["details"]["to"]["name"].as_str()), (Some("Auditor"), Some("Operator")));
    assert_eq!(json_call(port, "PATCH", &format!("{ROLE_GROUPS}/{a}"), &admin, r#"{"role":"admin"}"#).await.0, 400);

    // Removing a declaration hands Cy on to the next one.
    let (code, v) = json_call(port, "DELETE", &format!("{ROLE_GROUPS}/{a}"), &admin, "").await;
    assert_eq!((code, v["revoked"].clone(), v["wasPushed"].clone()), (200, json!([cy]), json!(true)), "{v}");
    assert_eq!(role_of(&app, &cy), Some(bill.clone()));
    assert_eq!(events(port, &admin, "action=scim.role_group_removed").await[0]["details"]["revoked"], json!([cy]));
    assert_eq!(scim(port, &t, "GET", &format!("{GROUPS}/{a}"), Value::Null).await.0, 404);

    // A role given by hand ends the group's claim: leaving it changes nothing.
    let (code, _) = json_call(port, "PUT", &format!("/api/roles/{bill}/users/{dee}"), &admin, "").await;
    assert_eq!(code, 200);
    assert_eq!(events(port, &admin, "action=role.assigned").await[0]["details"]["takenFromScim"], b.as_str());
    assert!(app.db.scim_role_group_grant_of_user(&dee).is_none());
    members(port, &t, &b, "Remove", &[&dee]).await;
    assert_eq!(role_of(&app, &dee), Some(bill.clone()));
}

#[tokio::test]
async fn an_idp_delete_puts_the_declaration_back_to_waiting() {
    let (port, app, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let eve = person(port, &t, "eve@example.com").await;
    let audit = role(port, &admin, "Auditor", "member", &["audit.view"]).await;
    // Declared by externalId: Entra's name for it doesn't matter.
    let (code, d) = declare(port, &admin, json!({ "tenant": "entra", "displayName": "Auditors", "externalId": "8aa1", "role": audit })).await;
    assert_eq!(code, 201, "{d}");
    let gid = d["id"].as_str().unwrap().to_string();
    let (code, _, v) = scim(port, &t, "POST", GROUPS, group_body("Auditors", Some("other"), &[])).await;
    assert_eq!(code, 409, "the name is taken by a declaration for another externalId: {v}");
    let (code, _, g) = scim(port, &t, "POST", GROUPS, group_body("SG-Audit", Some("8aa1"), &[&eve])).await;
    assert_eq!((code, g["id"].as_str(), g["displayName"].as_str()), (201, Some(gid.as_str()), Some("SG-Audit")), "{g}");
    assert_eq!(role_of(&app, &eve), Some(audit.clone()));
    let (code, _, v) = scim(port, &t, "POST", GROUPS, group_body("SG-Audit", Some("8aa1"), &[])).await;
    assert_eq!(code, 409, "pushed already: {v}");

    let (code, _, _) = scim(port, &t, "DELETE", &format!("{GROUPS}/{gid}"), Value::Null).await;
    assert_eq!(code, 204);
    assert_eq!(role_of(&app, &eve), None);
    assert_eq!(events(port, &admin, "action=role.unassigned").await[0]["details"]["reason"], "group_removed");
    let deleted = &events(port, &admin, "action=scim.group_deleted").await[0];
    assert_eq!((deleted["details"]["kind"].as_str(), deleted["details"]["revoked"].clone()), (Some("role"), json!([eve])));
    assert_eq!(scim(port, &t, "GET", &format!("{GROUPS}/{gid}"), Value::Null).await.0, 404);
    let (_, v) = json_call(port, "GET", &format!("{ROLE_GROUPS}/{gid}"), &admin, "").await;
    assert_eq!((v["state"].as_str(), v["externalId"].as_str(), v["members"].as_u64()), (Some("waiting"), Some("8aa1"), Some(0)), "{v}");

    // Pushed again, it is the role group again, never a team.
    let (code, _, g) = scim(port, &t, "POST", GROUPS, group_body("SG-Audit", Some("8aa1"), &[&eve])).await;
    assert_eq!((code, g["id"].as_str()), (201, Some(gid.as_str())));
    assert_eq!(role_of(&app, &eve), Some(audit.clone()));
    assert!(app.db.teams().is_empty());

    // A SCIM delete of Eve takes the role, and she's out of the group.
    let (code, _, _) = scim(port, &t, "DELETE", &format!("/scim/v2/Users/{eve}"), Value::Null).await;
    assert_eq!(code, 204);
    assert_eq!(role_of(&app, &eve), None);
    assert!(app.db.scim_role_group_member_ids(&gid).is_empty());
    assert_eq!(events(port, &admin, "action=role.unassigned").await[0]["details"]["reason"], "user_deleted");
}

#[tokio::test]
async fn a_user_delete_cut_short_is_finished_by_a_retry_or_a_restore() {
    let (port, app, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let eve = person(port, &t, "eve@example.com").await;
    let fay = person(port, &t, "fay@example.com").await;
    let audit = role(port, &admin, "Auditor", "member", &["audit.view"]).await;
    let gid = declared(port, &admin, "entra", "Auditors", &audit).await;
    push(port, &t, "Auditors", &[&eve, &fay]).await;
    assert_eq!((role_of(&app, &eve), role_of(&app, &fay)), (Some(audit.clone()), Some(audit.clone())));

    // A restart after each was marked deleted, before the role group let go of them.
    assert!(app.db.delete_scim_user("entra", &eve) && app.db.delete_scim_user("entra", &fay));

    // The IdP's retried DELETE finishes it.
    let (code, _, _) = scim(port, &t, "DELETE", &format!("/scim/v2/Users/{eve}"), Value::Null).await;
    assert_eq!(code, 204);
    assert_eq!(role_of(&app, &eve), None);
    assert!(!app.db.scim_role_group_has(&gid, &eve) && app.db.scim_role_group_grant_of_user(&eve).is_none());
    let (code, _, _) = scim(port, &t, "DELETE", &format!("/scim/v2/Users/{eve}"), Value::Null).await;
    assert_eq!(code, 404, "nothing left to finish");

    // A restore finishes it first: no role comes back with her.
    let (code, _, u) = scim(port, &t, "POST", "/scim/v2/Users", okta_user("fay@example.com", "fay@example.com")).await;
    assert_eq!((code, u["id"].as_str()), (201, Some(fay.as_str())), "{u}");
    assert_eq!(role_of(&app, &fay), None);
    assert!(!app.db.scim_role_group_has(&gid, &fay) && app.db.scim_role_group_grant_of_user(&fay).is_none());
    let gone: Vec<_> = events(port, &admin, "action=role.unassigned").await.iter().map(|e| (e["details"]["user"].clone(), e["details"]["reason"].clone())).collect();
    assert_eq!(gone, [(json!(fay), json!("user_deleted")), (json!(eve), json!("user_deleted"))]);
}

#[tokio::test]
async fn a_role_group_never_shares_a_teams_id_and_a_reset_restores_its_declared_name() {
    let (port, app, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let ivy = person(port, &t, "ivy@example.com").await;
    let (code, _, _) = scim(port, &t, "POST", GROUPS, group_body("Eng", Some("x1"), &[&ivy])).await;
    assert_eq!(code, 201);
    let audit = role(port, &admin, "Auditor", "member", &["audit.view"]).await;
    let gid = declared(port, &admin, "entra", "Auditors", &audit).await;
    let (code, _, v) = scim(port, &t, "POST", GROUPS, group_body("Auditors", Some("x1"), &[&ivy])).await;
    assert_eq!(code, 409, "Eng has that externalId: {v}");
    assert_eq!(app.db.scim_role_group(&gid).unwrap().provisioned_at, None, "still waiting");
    let (code, _, _) = scim(port, &t, "POST", GROUPS, group_body("Auditors", Some("x2"), &[&ivy])).await;
    assert_eq!(code, 201);
    assert_eq!(role_of(&app, &ivy), Some(audit.clone()));

    // Entra renames it, then deletes it: the declaration waits under the name declared.
    let rename = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "replace", "path": "displayName", "value": "Audit team" }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{gid}"), rename).await.0, 204);
    assert_eq!(scim(port, &t, "DELETE", &format!("{GROUPS}/{gid}"), Value::Null).await.0, 204);
    let (_, v) = json_call(port, "GET", &format!("{ROLE_GROUPS}/{gid}"), &admin, "").await;
    assert_eq!((v["state"].as_str(), v["displayName"].as_str(), v["externalId"].clone()), (Some("waiting"), Some("Auditors"), Value::Null), "{v}");
    let (code, _, g) = scim(port, &t, "POST", GROUPS, group_body("Auditors", Some("x3"), &[&ivy])).await;
    assert_eq!((code, g["id"].as_str()), (201, Some(gid.as_str())), "pushed again by its declared name, it's the role group: {g}");
    assert_eq!(app.db.teams().len(), 1);

    // Renamed again, a team takes the declared name meanwhile: the reset keeps the IdP's.
    let rename = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "replace", "path": "displayName", "value": "Audit team" }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{gid}"), rename).await.0, 204);
    assert_eq!(scim(port, &t, "POST", GROUPS, group_body("Auditors", Some("x4"), &[])).await.0, 201);
    assert_eq!(scim(port, &t, "DELETE", &format!("{GROUPS}/{gid}"), Value::Null).await.0, 204);
    let (_, v) = json_call(port, "GET", &format!("{ROLE_GROUPS}/{gid}"), &admin, "").await;
    assert_eq!((v["state"].as_str(), v["displayName"].as_str()), (Some("waiting"), Some("Audit team")), "never the team's name: {v}");
}

#[tokio::test]
async fn a_role_change_cut_short_is_finished_by_the_same_change_again() {
    let (port, app, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let ann = person(port, &t, "ann@example.com").await;
    let audit = role(port, &admin, "Auditor", "member", &["audit.view"]).await;
    let review = role(port, &admin, "Reviewer", "member", &["audit.view"]).await;
    let gid = declared(port, &admin, "okta", "Auditors", &audit).await;
    push(port, &t, "Auditors", &[&ann]).await;
    assert_eq!(role_of(&app, &ann), Some(audit.clone()));

    // The new role was saved, then the server stopped before it took the old one away.
    app.db.set_scim_role_group_role(&gid, &review).unwrap();
    assert_eq!(role_of(&app, &ann), Some(audit.clone()));
    let (code, v) = json_call(port, "PATCH", &format!("{ROLE_GROUPS}/{gid}"), &admin, &json!({ "role": review }).to_string()).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["revoked"].clone(), v["granted"].clone()), (json!([ann]), json!([ann])), "{v}");
    assert_eq!(role_of(&app, &ann), Some(review.clone()));
    let gone = &events(port, &admin, "action=role.unassigned").await[0];
    assert_eq!(gone["targetId"].as_str(), Some(audit.as_str()), "the role it gave goes: {gone}");

    // Cut short after the old role went but before the new one came: again gives it.
    let ben = person(port, &t, "ben@example.com").await;
    let add = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "add", "path": "members", "value": [{ "value": ben }] }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{gid}"), add).await.0, 204);
    let g = app.db.scim_role_group(&gid).unwrap();
    assert!(app.db.revoke_scim_role_group(&g, &ben, false).is_some());
    assert_eq!(role_of(&app, &ben), None);
    let (code, v) = json_call(port, "PATCH", &format!("{ROLE_GROUPS}/{gid}"), &admin, &json!({ "role": review }).to_string()).await;
    assert_eq!((code, v["revoked"].clone(), v["granted"].clone()), (200, json!([]), json!([ben])), "{v}");
    assert_eq!(role_of(&app, &ben), Some(review.clone()));

    // Again, there's nothing left to do, and nothing is audited.
    let changes = events(port, &admin, "action=scim.role_group_changed").await.len();
    let (code, v) = json_call(port, "PATCH", &format!("{ROLE_GROUPS}/{gid}"), &admin, &json!({ "role": review }).to_string()).await;
    assert_eq!((code, v["revoked"].clone(), v["granted"].clone()), (200, json!([]), json!([])), "{v}");
    assert_eq!(events(port, &admin, "action=scim.role_group_changed").await.len(), changes);
    // Leaving the group takes away the role it gave.
    let leave = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "remove", "path": format!("members[value eq \"{ann}\"]") }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{gid}"), leave).await.0, 204);
    assert_eq!(role_of(&app, &ann), None);
}

#[tokio::test]
async fn role_groups_skip_admins_and_hold_their_role_still() {
    let (port, app, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let adm = person(port, &t, "adm@example.com").await;
    let mem = person(port, &t, "mem@example.com").await;
    assert_eq!(call(port, "PATCH", &format!("/api/users/{adm}"), &admin, r#"{"role":"admin"}"#).await.0, 200);
    let audit = role(port, &admin, "Auditor", "member", &["audit.view"]).await;
    let gid = declared(port, &admin, "okta", "Auditors", &audit).await;
    push(port, &t, "Auditors", &[&adm, &mem]).await;
    assert_eq!((app.db.user(&adm).unwrap().role, role_of(&app, &adm)), (Role::Admin, None), "never changes an admin");
    assert_eq!(role_of(&app, &mem), Some(audit.clone()));
    let skip = &events(port, &admin, "action=scim.role_skipped").await[0];
    assert_eq!((skip["details"]["user"].as_str(), skip["details"]["reason"].as_str()), (Some(adm.as_str()), Some("admin")));

    // Its role can't grow to reach admins, nor be deleted, while the group gives it.
    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{audit}"), &admin, &json!({ "permissions": ["audit.view", "bots.manage"] }).to_string()).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains(&gid), "{v}");
    assert_eq!(json_call(port, "DELETE", &format!("/api/roles/{audit}"), &admin, "").await.0, 409);
    assert_eq!(json_call(port, "DELETE", &format!("{ROLE_GROUPS}/{gid}"), &admin, "").await.0, 200);
    assert_eq!(role_of(&app, &mem), None);
    assert_eq!(json_call(port, "DELETE", &format!("/api/roles/{audit}"), &admin, "").await.0, 200);
    assert_eq!(json_call(port, "DELETE", &format!("{ROLE_GROUPS}/{gid}"), &admin, "").await.0, 404);
    // Gone, the group is the IdP's to push again: as a team now.
    let (code, _, _) = scim(port, &t, "DELETE", &format!("{GROUPS}/{gid}"), Value::Null).await;
    assert_eq!(code, 404);
}

#[tokio::test]
async fn with_group_roles_off_a_declared_group_is_still_no_team_but_gives_nothing() {
    let (port, app, admin) = serve(false).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let fay = person(port, &t, "fay@example.com").await;
    let audit = role(port, &admin, "Auditor", "member", &["audit.view"]).await;
    // Declared while group roles were on.
    let g = app.db.declare_scim_role_group("okta", "org", "Auditors", None, &audit, None).unwrap();
    let id = push(port, &t, "Auditors", &[&fay]).await;
    assert_eq!(id, g.id);
    assert!(app.db.teams().is_empty());
    assert_eq!(role_of(&app, &fay), None);
    assert_eq!(app.db.scim_role_group_member_ids(&g.id), vec![fay.clone()]);
    assert_eq!(json_call(port, "PATCH", &format!("{ROLE_GROUPS}/{}", g.id), &admin, r#"{"role":"Auditor"}"#).await.0, 409);
    // What it gave before is still taken away.
    app.db.add_scim_role_group_member(&g.id, &fay);
    let pushed = app.db.scim_role_group(&g.id).unwrap();
    assert!(app.db.grant_scim_role_group(&pushed, &fay));
    assert_eq!(role_of(&app, &fay), Some(audit.clone()));
    members(port, &t, &g.id, "Remove", &[&fay]).await;
    assert_eq!(role_of(&app, &fay), None);
}
