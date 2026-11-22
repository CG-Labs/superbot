//! SCIM groups mapped to custom roles (ADR 0138) on the real router: off by default,
//! never admin nor a role that reaches admins, given and taken away as SCIM moves people
//! in and out of the group, and never touching a role given by hand. Every step audited.

use crate::rbac::Role;
use crate::scim_http_tests::{events, okta_user, scim, token};
use crate::tests::{call, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const GROUPS: &str = "/scim/v2/Groups";
const MAPPINGS: &str = "/api/scim/role-mappings";
const PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// SCIM, its groups, and (with `roles`) group roles on.
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

async fn group(port: u16, token: &str, name: &str, members: &[&str]) -> String {
    let body = json!({ "displayName": name, "members": members.iter().map(|m| json!({ "value": m })).collect::<Vec<_>>() });
    let (code, _, g) = scim(port, token, "POST", GROUPS, body).await;
    assert_eq!(code, 201, "{g}");
    g["id"].as_str().unwrap().to_string()
}

async fn members(port: u16, token: &str, team: &str, op: &str, users: &[&str]) {
    let body = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": op, "path": "members", "value": users.iter().map(|u| json!({ "value": u })).collect::<Vec<_>>() }] });
    let (code, _, v) = scim(port, token, "PATCH", &format!("{GROUPS}/{team}"), body).await;
    assert_eq!(code, 204, "{v}");
}

async fn role(port: u16, admin: &str, name: &str, base: &str, perms: &[&str]) -> String {
    let (code, v) = json_call(port, "POST", "/api/roles", admin, &json!({ "name": name, "base": base, "permissions": perms }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

async fn map(port: u16, admin: &str, body: Value) -> (u16, Value) {
    json_call(port, "POST", MAPPINGS, admin, &body.to_string()).await
}

fn team_role(app: &AppState, user: &str) -> Option<String> {
    app.db.team_member(user).and_then(|m| m.role_id)
}

fn ids(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    out.sort();
    out
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

#[tokio::test]
async fn mappings_are_off_by_default_and_never_reach_admins() {
    let (port, _, admin) = serve(false).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let team = group(port, &t, "Eng", &[]).await;
    let audit = role(port, &admin, "Auditor", "member", &["audit.view"]).await;
    let (code, v) = json_call(port, "GET", MAPPINGS, &admin, "").await;
    assert_eq!((code, v["enabled"].clone(), v["mappings"].clone()), (200, json!(false), json!([])));
    let (code, v) = map(port, &admin, json!({ "team": team, "role": audit })).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("SCIM_GROUP_ROLES=on"), "{v}");
    let (_, s) = json_call(port, "GET", "/api/scim/tokens", &admin, "").await;
    assert_eq!(s["groupRoles"], false);

    let (port, _, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let team = group(port, &t, "Eng", &[]).await;
    let audit = role(port, &admin, "Auditor", "member", &["audit.view"]).await;
    let bots = role(port, &admin, "Bot keeper", "member", &["bots.manage"]).await;
    let machines = role(port, &admin, "Machine keeper", "member", &["machines.manage", "billing.manage"]).await;
    let (code, _) = call(port, "GET", MAPPINGS, &format!("Bearer {t}"), "").await;
    assert_eq!(code, 401, "a SCIM token can't reach the admin API");
    for (body, code, why) in [
        (json!({ "team": team, "role": "admin" }), 400, "never admin"),
        (json!({ "team": team, "role": "Admin", "scope": "org" }), 400, "never admin, any case"),
        (json!({ "team": team, "role": "member" }), 400, "custom roles only"),
        (json!({ "team": team, "role": bots, "scope": "org" }), 400, "bots.manage acts on admins' Bots"),
        (json!({ "team": team, "role": machines }), 400, "machines.manage acts on admins' machines in a team too"),
        (json!({ "team": team, "role": machines, "scope": "org" }), 400, "and across the server"),
        (json!({ "team": team, "role": "nope" }), 404, "unknown role"),
        (json!({ "team": "t-nope", "role": audit }), 404, "not a SCIM group"),
        (json!({ "team": team, "role": audit, "scope": "server" }), 400, "scope is team or org"),
        (json!({ "team": team, "role": audit, "extra": 1 }), 400, "unknown field"),
        (json!({ "team": team }), 400, "a role is needed"),
    ] {
        let (got, v) = map(port, &admin, body).await;
        assert_eq!(got, code, "{why}: {v}");
    }
    let refused = events(port, &admin, "action=scim.role_map_refused").await;
    let reasons: Vec<&str> = refused.iter().map(|e| e["details"]["reason"].as_str().unwrap()).collect();
    assert_eq!(reasons, ["reaches_admins", "reaches_admins", "reaches_admins", "admin", "admin"], "newest first");
    assert_eq!(refused[0]["outcome"], "denied");
    assert_eq!(refused[0]["details"]["permissions"], json!(["machines.manage"]));

    // bots.manage means nothing in a team, so a team mapping may hold it.
    let (code, v) = map(port, &admin, json!({ "team": team, "role": bots })).await;
    assert_eq!((code, v["applies"].clone(), v["scope"].clone()), (201, json!([]), json!("team")), "{v}");
    let (code, v) = map(port, &admin, json!({ "team": team, "role": audit })).await;
    assert_eq!(code, 409, "one team role per group: {v}");
    let (code, v) = map(port, &admin, json!({ "team": team, "role": audit, "scope": "org" })).await;
    assert_eq!((code, v["applies"].clone()), (201, json!(["audit.view"])), "{v}");
    let (code, v) = json_call(port, "GET", MAPPINGS, &admin, "").await;
    assert_eq!((code, v["enabled"].clone(), v["mappings"].as_array().unwrap().len()), (200, json!(true), 2));
    assert_eq!(v["mappings"][0]["group"], "Eng");
    assert_eq!(v["mappings"][0]["tenant"], "okta");
    let mapped = events(port, &admin, "action=scim.role_mapped").await;
    assert_eq!(mapped.len(), 2);
    assert_eq!((mapped[0]["targetId"].as_str(), mapped[0]["details"]["role"]["name"].as_str()), (Some(team.as_str()), Some("Auditor")));
}

#[tokio::test]
async fn group_members_get_the_role_in_the_team_and_lose_it_when_they_leave() {
    let (port, app, admin) = serve(true).await;
    let (t, tid) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let ada = person(port, &t, "ada@contoso.example").await;
    let al = person(port, &t, "al@contoso.example").await;
    let bo = person(port, &t, "bo@contoso.example").await;
    let cy = person(port, &t, "cy@contoso.example").await;
    let team = group(port, &t, "Support", &[&ada, &cy]).await;
    let lead = role(port, &admin, "Support Lead", "member", &["users.manage", "billing.manage", "audit.view"]).await;
    let other = role(port, &admin, "Biller", "member", &["billing.manage"]).await;
    // Cy has a team role given by hand: the group never changes it.
    assert_eq!(call(port, "PUT", &format!("/api/roles/{other}/teams/{team}/users/{cy}"), &admin, "").await.0, 200);

    let (code, m) = map(port, &admin, json!({ "team": team, "role": "Support Lead" })).await;
    assert_eq!(code, 201, "{m}");
    let mid = m["id"].as_str().unwrap().to_string();
    assert_eq!((m["granted"].clone(), m["skipped"].clone()), (json!([ada]), json!([{ "user": cy, "reason": "has_role" }])));
    assert_eq!(m["applies"], json!(["users.manage", "billing.manage"]), "only team permissions apply in a team");
    assert_eq!((team_role(&app, &ada), team_role(&app, &cy)), (Some(lead.clone()), Some(other.clone())));
    assert_eq!(app.db.user(&ada).unwrap().role_id, None, "nothing across the server");

    // Entra adds two: both get it.
    members(port, &t, &team, "Add", &[&al, &bo]).await;
    assert_eq!((team_role(&app, &al), team_role(&app, &bo)), (Some(lead.clone()), Some(lead.clone())));
    let assigned = events(port, &admin, "action=role.assigned").await;
    let by_scim: Vec<&Value> = assigned.iter().filter(|e| e["details"]["via"] == "scim").collect();
    assert_eq!(by_scim.len(), 3);
    assert_eq!(by_scim[0]["actorId"], format!("scim:{tid}"), "the join's grant is SCIM's");
    assert_eq!((by_scim[0]["details"]["mapping"].as_str(), by_scim[0]["details"]["team"].as_str(), by_scim[0]["details"]["scope"].as_str()), (Some(mid.as_str()), Some(team.as_str()), Some("team")));
    let (_, v) = json_call(port, "GET", &format!("/api/roles/{lead}"), &admin, "").await;
    assert_eq!(v["scimMappings"], 1);
    assert!(v["holders"]["teams"].as_array().unwrap().iter().all(|h| h["scimMapping"] == mid.as_str()), "{v}");

    // Ada leaves the group: her grant goes, audited with why.
    members(port, &t, &team, "Remove", &[&ada]).await;
    assert!(app.db.team_member(&ada).is_none());
    let gone = &events(port, &admin, "action=role.unassigned").await[0];
    assert_eq!((gone["details"]["user"].as_str(), gone["details"]["reason"].as_str(), gone["details"]["via"].as_str()), (Some(ada.as_str()), Some("left_group"), Some("scim")));
    assert!(app.db.scim_role_grants_of_user(&ada).is_empty());
    // She comes back: she gets it again.
    members(port, &t, &team, "Add", &[&ada]).await;
    assert_eq!(team_role(&app, &ada), Some(lead.clone()));

    // Al's role is given by hand now: it stays his when the mapping goes.
    let (code, v) = json_call(port, "PUT", &format!("/api/roles/{lead}/teams/{team}/users/{al}"), &admin, "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(events(port, &admin, "action=role.assigned").await[0]["details"]["takenFromScim"], mid.as_str());
    let (code, v) = json_call(port, "GET", &format!("{MAPPINGS}/{mid}"), &admin, "").await;
    let held: Vec<String> = v["holders"].as_array().unwrap().iter().map(|h| h["user"]["id"].as_str().unwrap().to_string()).collect();
    assert_eq!((code, sorted(held)), (200, sorted(vec![ada.clone(), bo.clone()])), "{v}");

    // Bo's is taken away by hand: it's gone, and the mapping can't give it back until he rejoins.
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{lead}/teams/{team}/users/{bo}"), &admin, "").await.0, 200);
    assert_eq!(events(port, &admin, "action=role.unassigned").await[0]["details"]["scimMapping"], mid.as_str());
    assert!(app.db.scim_role_grants_of_user(&bo).is_empty());

    let (code, v) = json_call(port, "DELETE", &format!("{MAPPINGS}/{mid}"), &admin, "").await;
    assert_eq!((code, v["revoked"].clone()), (200, json!([ada])), "{v}");
    assert_eq!((team_role(&app, &ada), team_role(&app, &al), team_role(&app, &bo), team_role(&app, &cy)), (None, Some(lead.clone()), None, Some(other)));
    let unmapped = &events(port, &admin, "action=scim.role_unmapped").await[0];
    assert_eq!((unmapped["details"]["reason"].as_str(), unmapped["details"]["revoked"].clone()), (Some("mapping_removed"), json!([ada])));
    assert_eq!(json_call(port, "GET", &format!("{MAPPINGS}/{mid}"), &admin, "").await.0, 404);
    // Nobody is given anything once it's gone.
    let dee = person(port, &t, "dee@contoso.example").await;
    members(port, &t, &team, "Add", &[&dee]).await;
    assert_eq!(team_role(&app, &dee), None);
}

#[tokio::test]
async fn a_server_wide_role_skips_admins_and_gives_back_the_role_they_had() {
    let (port, app, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let ro = person(port, &t, "ro@example.com").await;
    let mem = person(port, &t, "mem@example.com").await;
    let adm = person(port, &t, "adm@example.com").await;
    let hand = person(port, &t, "hand@example.com").await;
    for (u, r) in [(&ro, "readonly"), (&adm, "admin")] {
        assert_eq!(call(port, "PATCH", &format!("/api/users/{u}"), &admin, &json!({ "role": r }).to_string()).await.0, 200);
    }
    let auditor = role(port, &admin, "Auditor", "member", &["audit.view", "users.manage"]).await;
    let viewer = role(port, &admin, "Viewer", "readonly", &["audit.view"]).await;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{viewer}/users/{hand}"), &admin, "").await.0, 200);
    let team = group(port, &t, "Ops", &[&ro, &mem, &adm, &hand]).await;

    let (code, m) = map(port, &admin, json!({ "team": team, "role": auditor, "scope": "org" })).await;
    assert_eq!(code, 201, "{m}");
    let mid = m["id"].as_str().unwrap().to_string();
    assert_eq!(ids(&m["granted"]), sorted(vec![ro.clone(), mem.clone()]));
    let skipped: Vec<(String, String)> = m["skipped"].as_array().unwrap().iter().map(|s| (s["user"].as_str().unwrap().into(), s["reason"].as_str().unwrap().into())).collect();
    assert_eq!(sorted(skipped.iter().map(|(u, r)| format!("{u}:{r}")).collect()), sorted(vec![format!("{adm}:admin"), format!("{hand}:has_role")]));
    let u = app.db.user(&ro).unwrap();
    assert_eq!((u.role, u.role_id.as_deref()), (Role::Member, Some(auditor.as_str())), "the role's base replaces read-only");
    assert_eq!(app.db.user(&adm).unwrap().role, Role::Admin, "never changes an admin");
    let changed = events(port, &admin, &format!("action=user.role_changed&target=user:{ro}")).await;
    assert_eq!((changed[0]["details"]["from"].as_str(), changed[0]["details"]["to"].as_str(), changed[0]["details"]["reason"].as_str()), (Some("readonly"), Some("member"), Some("scim_group")));
    let skips = events(port, &admin, "action=scim.role_skipped").await;
    assert_eq!(skips.len(), 2);

    // Ro can now read the audit log, as the role says.
    let ro_auth = crate::scim_http_tests::session_for(port, &admin, &ro).await;
    assert_eq!(call(port, "GET", "/api/audit", &ro_auth, "").await.0, 200);

    // An admin sets Mem's role by hand: the group's claim on it ends.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{mem}"), &admin, r#"{"role":"member"}"#).await.0, 200);
    assert!(app.db.scim_role_grants_of_user(&mem).is_empty());
    assert_eq!(app.db.user(&mem).unwrap().role_id, None);

    // The IdP deletes the group: everyone leaves it, Ro is read-only again, the mapping goes.
    let (code, _, v) = scim(port, &t, "DELETE", &format!("{GROUPS}/{team}"), Value::Null).await;
    assert_eq!(code, 204, "{v}");
    let u = app.db.user(&ro).unwrap();
    assert_eq!((u.role, u.role_id), (Role::Readonly, None));
    assert_eq!(call(port, "GET", "/api/audit", &ro_auth, "").await.0, 403);
    let h = app.db.user(&hand).unwrap();
    assert_eq!((h.role, h.role_id.as_deref()), (Role::Readonly, Some(viewer.as_str())), "a role given by hand stays");
    assert!(app.db.scim_role_mapping(&mid).is_none());
    let gone = &events(port, &admin, &format!("action=role.unassigned&target=role:{auditor}")).await[0];
    assert_eq!((gone["details"]["user"].as_str(), gone["details"]["reason"].as_str(), gone["details"]["keeps"].as_str()), (Some(ro.as_str()), Some("left_group"), Some("readonly")));
    let unmapped = &events(port, &admin, "action=scim.role_unmapped").await[0];
    assert_eq!((unmapped["details"]["reason"].as_str(), unmapped["details"]["revoked"].clone()), (Some("group_removed"), json!([])));
}

#[tokio::test]
async fn mapped_roles_cant_grow_to_reach_admins_or_be_deleted() {
    let (port, _, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let org = group(port, &t, "Org", &[]).await;
    let eng = group(port, &t, "Eng", &[]).await;
    let wide = role(port, &admin, "Wide", "member", &["audit.view"]).await;
    let narrow = role(port, &admin, "Narrow", "member", &["users.manage"]).await;
    let (_, w) = map(port, &admin, json!({ "team": org, "role": wide, "scope": "org" })).await;
    let (_, n) = map(port, &admin, json!({ "team": eng, "role": narrow })).await;

    let edit = |r: &str, perms: &[&str]| (format!("/api/roles/{r}"), json!({ "permissions": perms }).to_string());
    let (path, body) = edit(&wide, &["audit.view", "bots.manage"]);
    let (code, v) = json_call(port, "PATCH", &path, &admin, &body).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains(w["id"].as_str().unwrap()), "{v}");
    let (path, body) = edit(&narrow, &["users.manage", "machines.manage"]);
    assert_eq!(json_call(port, "PATCH", &path, &admin, &body).await.0, 409);
    let (path, body) = edit(&narrow, &["users.manage", "bots.manage"]);
    assert_eq!(json_call(port, "PATCH", &path, &admin, &body).await.0, 200, "bots.manage means nothing in a team");
    assert_eq!(json_call(port, "PATCH", &format!("/api/roles/{wide}"), &admin, r#"{"name":"Wider"}"#).await.0, 200, "other edits are fine");

    let (code, v) = json_call(port, "DELETE", &format!("/api/roles/{wide}"), &admin, "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("SCIM group"), "{v}");
    assert_eq!(call(port, "DELETE", &format!("{MAPPINGS}/{}", w["id"].as_str().unwrap()), &admin, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{wide}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("{MAPPINGS}/{}", n["id"].as_str().unwrap()), &admin, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("{MAPPINGS}/{}", n["id"].as_str().unwrap()), &admin, "").await.0, 404);
}

#[tokio::test]
async fn leaving_by_hand_and_unlinking_take_the_role_away_too() {
    let (port, app, admin) = serve(true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let ana = person(port, &t, "ana@example.com").await;
    let ben = person(port, &t, "ben@example.com").await;
    let (owner, _) = user_with(port, &admin, "owner@example.com", "member").await;
    let (code, v) = json_call(port, "POST", "/api/teams", &admin, &json!({ "name": "Platform", "owner": owner }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    let team = v["id"].as_str().unwrap().to_string();
    for u in [&ana, &ben] {
        assert_eq!(call(port, "PUT", &format!("/api/teams/{team}/members/{u}"), &admin, "{}").await.0, 200);
    }
    let r = role(port, &admin, "Team admin", "member", &["users.manage"]).await;
    // A team made by hand, linked for the IdP: the tenant's people on it are the group.
    let (code, v) = json_call(port, "POST", "/api/scim/groups", &admin, &json!({ "tenant": "okta", "team": team }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    let (code, m) = map(port, &admin, json!({ "team": team, "role": r })).await;
    assert_eq!((code, ids(&m["granted"])), (201, sorted(vec![ana.clone(), ben.clone()])), "{m}");

    // An admin takes Ana off the team: the group's role goes with her.
    assert_eq!(call(port, "DELETE", &format!("/api/teams/{team}/members/{ana}"), &admin, "").await.0, 200);
    assert!(app.db.scim_role_grants_of_user(&ana).is_empty());
    assert_eq!(events(port, &admin, "action=role.unassigned").await[0]["details"]["reason"], "left_group");

    // Unlinking ends the mapping and takes back what it gave; Ben stays on the team.
    assert_eq!(call(port, "DELETE", &format!("/api/scim/groups/{team}"), &admin, "").await.0, 200);
    assert_eq!(team_role(&app, &ben), None);
    assert_eq!(app.db.team_member(&ben).map(|m| m.team_id), Some(team.clone()));
    let unmapped = &events(port, &admin, "action=scim.role_unmapped").await[0];
    assert_eq!((unmapped["details"]["reason"].as_str(), unmapped["details"]["revoked"].clone()), (Some("group_removed"), json!([ben])));
    assert_eq!(json_call(port, "GET", MAPPINGS, &admin, "").await.1["mappings"], json!([]));
}
