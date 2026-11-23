//! Team role groups (ADR 0206) on the real router: a role group declared with
//! `scope: "team"` gives its custom role within the team each member is on, when that
//! team is one of the tenant's team groups; never to read-only people, over a team role
//! held already, nor a role reaching admins in a team. The grant follows the person onto
//! and off the tenant's teams, the next team role group in line takes over, and a removed
//! mapping or an unlinked team hands on or takes back what it should. Every step audited.

use crate::scim_http_tests::{events, okta_user, scim, token};
use crate::tests::{call, serve_app_with};
use crate::users_http_tests::parse;
use crate::*;

const GROUPS: &str = "/scim/v2/Groups";
const ROLE_GROUPS: &str = "/api/scim/role-groups";
const PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

async fn serve() -> (u16, AppState, String) {
    let (port, app, admin, _) = serve_app_with(|a| {
        a.scim.enabled = true;
        a.scim.groups = true;
        a.scim.group_roles = true;
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

async fn push(port: u16, token: &str, name: &str, members: &[&str]) -> String {
    let body = json!({ "displayName": name, "members": members.iter().map(|m| json!({ "value": m })).collect::<Vec<_>>() });
    let (code, _, g) = scim(port, token, "POST", GROUPS, body).await;
    assert_eq!(code, 201, "{g}");
    g["id"].as_str().unwrap().to_string()
}

async fn members(port: u16, token: &str, group: &str, op: &str, users: &[&str]) {
    let body = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": op, "path": "members", "value": users.iter().map(|u| json!({ "value": u })).collect::<Vec<_>>() }] });
    let (code, _, v) = scim(port, token, "PATCH", &format!("{GROUPS}/{group}"), body).await;
    assert_eq!(code, 204, "{v}");
}

async fn role(port: u16, admin: &str, name: &str, perms: &[&str]) -> String {
    let (code, v) = json_call(port, "POST", "/api/roles", admin, &json!({ "name": name, "base": "member", "permissions": perms }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

async fn declare(port: u16, admin: &str, tenant: &str, name: &str, role: &str, scope: &str) -> (u16, Value) {
    json_call(port, "POST", ROLE_GROUPS, admin, &json!({ "tenant": tenant, "displayName": name, "role": role, "scope": scope }).to_string()).await
}

async fn declared(port: u16, admin: &str, tenant: &str, name: &str, role: &str) -> String {
    let (code, v) = declare(port, admin, tenant, name, role, "team").await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

/// `user`'s custom role within their team, and the team.
fn team_role(app: &AppState, user: &str) -> Option<(String, String)> {
    app.db.team_member(user).and_then(|m| m.role_id.map(|r| (m.team_id, r)))
}

fn org_role(app: &AppState, user: &str) -> Option<String> {
    app.db.user(user).and_then(|u| u.role_id)
}

#[tokio::test]
async fn team_role_groups_refuse_only_what_reaches_admins_in_a_team() {
    let (port, _, admin) = serve().await;
    let machines = role(port, &admin, "Fleet", &["machines.manage"]).await;
    let bots = role(port, &admin, "Bot keeper", &["bots.manage", "users.manage"]).await;
    let lead = role(port, &admin, "Lead", &["users.manage", "billing.manage", "audit.view"]).await;

    let (code, v) = declare(port, &admin, "entra", "Fleet", &machines, "team").await;
    assert_eq!(code, 400, "machines.manage reaches admins' machines on a team: {v}");
    assert!(v["error"].as_str().unwrap().contains("in a team"), "{v}");
    let refused = &events(port, &admin, "action=scim.role_map_refused").await[0];
    assert_eq!((refused["details"]["scope"].as_str(), refused["details"]["kind"].as_str()), (Some("team"), Some("role_group")));
    assert_eq!(declare(port, &admin, "entra", "Keepers", &bots, "org").await.0, 400, "bots.manage reaches admins across the server");
    assert_eq!(declare(port, &admin, "entra", "Admins", "admin", "team").await.0, 400, "never admin");

    // In a team, bots.manage gives nothing and reaches nobody, so the role may be given there.
    let (code, v) = declare(port, &admin, "entra", "Keepers", &bots, "team").await;
    assert_eq!((code, v["scope"].as_str(), v["applies"].clone()), (201, Some("team"), json!(["users.manage"])), "{v}");
    let (code, v) = declare(port, &admin, "entra", "Leads", &lead, "team").await;
    assert_eq!((code, v["applies"].clone()), (201, json!(["users.manage", "billing.manage"])), "only its team permissions: {v}");
    let gid = v["id"].as_str().unwrap().to_string();
    let declared = &events(port, &admin, "action=scim.role_group_declared").await[0];
    assert_eq!(declared["details"]["scope"], "team");
    let (_, list) = json_call(port, "GET", ROLE_GROUPS, &admin, "").await;
    assert!(list["roleGroups"].as_array().unwrap().iter().all(|g| g["scope"] == "team"), "{list}");

    // Its role can't change to one reaching admins in a team, nor gain such a permission.
    let (code, v) = json_call(port, "PATCH", &format!("{ROLE_GROUPS}/{gid}"), &admin, &json!({ "role": machines }).to_string()).await;
    assert_eq!(code, 400, "{v}");
    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{lead}"), &admin, &json!({ "permissions": ["users.manage", "machines.manage"] }).to_string()).await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains(&gid), "{v}");
    let (code, v) = json_call(port, "PATCH", &format!("/api/roles/{lead}"), &admin, &json!({ "permissions": ["users.manage", "bots.manage"] }).to_string()).await;
    assert_eq!(code, 200, "bots.manage reaches nobody in a team: {v}");
}

#[tokio::test]
async fn a_team_role_group_gives_its_role_within_each_members_team() {
    let (port, app, admin) = serve().await;
    let (t, tid) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let ada = person(port, &t, "ada@contoso.example").await;
    let bo = person(port, &t, "bo@contoso.example").await;
    let cy = person(port, &t, "cy@contoso.example").await;
    let dee = person(port, &t, "dee@contoso.example").await;
    let ro = person(port, &t, "ro@contoso.example").await;
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ro}"), &admin, r#"{"role":"readonly"}"#).await.0, 200);
    let support = push(port, &t, "Support", &[&ada, &bo, &ro]).await;
    let sales = push(port, &t, "Sales", &[&cy]).await;
    let lead = role(port, &admin, "Lead", &["users.manage", "billing.manage"]).await;
    let helper = role(port, &admin, "Helper", &["billing.manage"]).await;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{helper}/teams/{support}/users/{bo}"), &admin, "").await.0, 200, "Bo's team role is by hand");
    let gid = declared(port, &admin, "entra", "Team Leads", &lead).await;

    // Entra pushes it: each member gets the role in their own team, and it is no team.
    let lead_in = |team: &str| Some((team.to_string(), lead.clone()));
    let gid2 = push(port, &t, "Team Leads", &[&ada, &bo, &cy, &dee, &ro]).await;
    assert_eq!(gid2, gid);
    assert_eq!(app.db.teams().len(), 2, "no team was made");
    assert_eq!((team_role(&app, &ada), team_role(&app, &cy)), (lead_in(&support), lead_in(&sales)));
    assert_eq!(team_role(&app, &bo), Some((support.clone(), helper.clone())), "a team role by hand stays");
    assert_eq!((team_role(&app, &ro), app.db.team_member(&dee).is_none()), (None, true));
    assert_eq!((org_role(&app, &ada), app.db.user(&ada).unwrap().role), (None, crate::rbac::Role::Member), "nothing across the server");
    let assigned = events(port, &admin, "action=role.assigned").await;
    let ada_got = assigned.iter().find(|e| e["details"]["user"] == ada.as_str()).unwrap();
    assert_eq!(
        (ada_got["details"]["scope"].as_str(), ada_got["details"]["team"].as_str(), ada_got["details"]["roleGroup"].as_str(), ada_got["actorId"].clone()),
        (Some("team"), Some(support.as_str()), Some(gid.as_str()), json!(format!("scim:{tid}")))
    );
    let mut skips: Vec<(String, String)> = events(port, &admin, "action=scim.role_skipped").await.iter().map(|e| (e["details"]["user"].as_str().unwrap().into(), e["details"]["reason"].as_str().unwrap().into())).collect();
    skips.sort();
    let mut want = vec![(bo.clone(), "has_role".to_string()), (dee.clone(), "not_on_team".into()), (ro.clone(), "readonly".into())];
    want.sort();
    assert_eq!(skips, want);

    // Admins see who holds it and where.
    let (_, v) = json_call(port, "GET", &format!("{ROLE_GROUPS}/{gid}"), &admin, "").await;
    assert_eq!((v["scope"].as_str(), v["grants"].as_u64(), v["members"].as_u64()), (Some("team"), Some(2), Some(5)), "{v}");
    assert!(v["holders"].as_array().unwrap().iter().any(|h| h["user"]["id"] == ada.as_str() && h["team"] == support.as_str()), "{v}");
    let (_, v) = json_call(port, "GET", &format!("/api/roles/{lead}"), &admin, "").await;
    let held = v["holders"]["teams"].as_array().unwrap();
    assert!(held.iter().all(|h| h["scimMapping"] == gid.as_str()) && held.len() == 2, "{v}");

    // Cy moves from Sales to Support: the role goes with Sales and comes back in Support.
    members(port, &t, &sales, "Remove", &[&cy]).await;
    assert_eq!(team_role(&app, &cy), None);
    let gone = &events(port, &admin, "action=role.unassigned").await[0];
    assert_eq!((gone["details"]["reason"].as_str(), gone["details"]["team"].as_str(), gone["details"]["scope"].as_str()), (Some("left_team"), Some(sales.as_str()), Some("team")));
    members(port, &t, &support, "Add", &[&cy]).await;
    assert_eq!(team_role(&app, &cy), lead_in(&support));
    // Dee joins Sales: she gets it there.
    members(port, &t, &sales, "Add", &[&dee]).await;
    assert_eq!(team_role(&app, &dee), lead_in(&sales));

    // Ada leaves the group: her team role goes, she stays on Support.
    members(port, &t, &gid, "Remove", &[&ada]).await;
    assert_eq!((team_role(&app, &ada), app.db.team_member(&ada).map(|m| m.team_id)), (None, Some(support.clone())));
    let gone = &events(port, &admin, "action=role.unassigned").await[0];
    assert_eq!((gone["details"]["user"].as_str(), gone["details"]["reason"].as_str(), gone["details"]["held"].clone()), (Some(ada.as_str()), Some("left_group"), json!(true)));

    // A hand change ends the group's claim: leaving the group then takes nothing.
    assert_eq!(call(port, "PUT", &format!("/api/roles/{helper}/teams/{support}/users/{cy}"), &admin, "").await.0, 200);
    assert!(app.db.scim_team_role_group_grant_of_user(&cy).is_none());
    members(port, &t, &gid, "Remove", &[&cy]).await;
    assert_eq!(team_role(&app, &cy), Some((support.clone(), helper.clone())));
}

#[tokio::test]
async fn the_next_team_role_group_in_line_takes_over_beside_org_role_groups() {
    let (port, app, admin) = serve().await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let eve = person(port, &t, "eve@example.com").await;
    let eng = push(port, &t, "Eng", &[&eve]).await;
    let lead = role(port, &admin, "Lead", &["users.manage"]).await;
    let biller = role(port, &admin, "Biller", &["billing.manage"]).await;
    let audit = role(port, &admin, "Auditor", &["audit.view"]).await;
    let first = declared(port, &admin, "okta", "Leads", &lead).await;
    let second = declared(port, &admin, "okta", "Billing", &biller).await;
    let (code, v) = declare(port, &admin, "okta", "Auditors", &audit, "org").await;
    assert_eq!(code, 201, "{v}");
    push(port, &t, "Billing", &[&eve]).await;
    push(port, &t, "Leads", &[&eve]).await;
    push(port, &t, "Auditors", &[&eve]).await;
    assert_eq!(team_role(&app, &eve), Some((eng.clone(), biller.clone())), "Billing pushed first gave it");
    assert_eq!(org_role(&app, &eve), Some(audit.clone()), "a role across the server beside a team role");

    // Out of Billing: Leads, declared first, takes over; her role across the server stays.
    members(port, &t, &second, "Remove", &[&eve]).await;
    assert_eq!((team_role(&app, &eve), org_role(&app, &eve)), (Some((eng.clone(), lead.clone())), Some(audit.clone())));
    // Its role changes: hers does at once.
    let (code, v) = json_call(port, "PATCH", &format!("{ROLE_GROUPS}/{first}"), &admin, &json!({ "role": biller }).to_string()).await;
    assert_eq!((code, v["revoked"].clone(), v["granted"].clone()), (200, json!([eve]), json!([eve])), "{v}");
    assert_eq!(team_role(&app, &eve), Some((eng.clone(), biller.clone())));
    // Its declaration goes: so does the role, and nothing in line is left.
    let (code, v) = json_call(port, "DELETE", &format!("{ROLE_GROUPS}/{first}"), &admin, "").await;
    assert_eq!((code, v["revoked"].clone()), (200, json!([eve])), "{v}");
    assert_eq!((team_role(&app, &eve), org_role(&app, &eve)), (None, Some(audit.clone())));
}

#[tokio::test]
async fn a_removed_mapping_hands_on_and_an_unlinked_team_takes_back() {
    let (port, app, admin) = serve().await;
    let (t, _) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let fay = person(port, &t, "fay@example.com").await;
    let gus = person(port, &t, "gus@example.com").await;
    let ops = push(port, &t, "Ops", &[&fay, &gus]).await;
    let member_plus = role(port, &admin, "Member plus", &["billing.manage"]).await;
    let lead = role(port, &admin, "Lead", &["users.manage"]).await;
    let audit = role(port, &admin, "Auditor", &["audit.view"]).await;
    let (code, m) = json_call(port, "POST", "/api/scim/role-mappings", &admin, &json!({ "team": ops, "role": member_plus }).to_string()).await;
    assert_eq!(code, 201, "{m}");
    let (code, om) = json_call(port, "POST", "/api/scim/role-mappings", &admin, &json!({ "team": ops, "role": audit, "scope": "org" }).to_string()).await;
    assert_eq!(code, 201, "{om}");
    let gid = declared(port, &admin, "entra", "Ops Leads", &lead).await;
    let (code, v) = declare(port, &admin, "entra", "Auditors", &audit, "org").await;
    assert_eq!(code, 201, "{v}");
    push(port, &t, "Ops Leads", &[&fay]).await;
    push(port, &t, "Auditors", &[&gus]).await;
    assert_eq!(team_role(&app, &fay), Some((ops.clone(), member_plus.clone())), "the team's mapping gave her a team role first");
    assert_eq!(events(port, &admin, "action=scim.role_skipped").await.iter().filter(|e| e["details"]["roleGroup"] == gid.as_str()).count(), 1);

    // The mapping goes: the team role group she's in gives its role at once.
    let (code, _) = json_call(port, "DELETE", &format!("/api/scim/role-mappings/{}", m["id"].as_str().unwrap()), &admin, "").await;
    assert_eq!(code, 200);
    assert_eq!((team_role(&app, &fay), team_role(&app, &gus)), (Some((ops.clone(), lead.clone())), None));

    // The team is unlinked: it isn't the tenant's any more, so the role goes; Fay stays.
    // The org mapping goes too, and Gus is offered the org role group he's in.
    assert_eq!(org_role(&app, &gus), Some(audit.clone()));
    assert_eq!(json_call(port, "DELETE", &format!("/api/scim/groups/{ops}"), &admin, "").await.0, 200);
    assert_eq!((team_role(&app, &fay), app.db.team_member(&fay).map(|m| m.team_id)), (None, Some(ops.clone())));
    let gone = events(port, &admin, "action=role.unassigned").await;
    assert!(gone.iter().any(|e| e["details"]["user"] == fay.as_str() && e["details"]["reason"] == "team_unlinked"), "{gone:?}");
    let gus_role = app.db.scim_role_group_grant_of_user(&gus).map(|h| h.role_id);
    assert_eq!((org_role(&app, &gus), gus_role), (Some(audit.clone()), Some(audit.clone())), "the role group took over from the mapping");

    // Linked again: Fay is offered it again.
    let (code, v) = json_call(port, "POST", "/api/scim/groups", &admin, &json!({ "tenant": "entra", "team": ops, "displayName": "Ops" }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    assert_eq!(team_role(&app, &fay), Some((ops.clone(), lead.clone())));
    // A team of another tenant is never one this tenant's group gives a role in.
    let (t2, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let hal = person(port, &t2, "hal@example.com").await;
    push(port, &t2, "Okta Eng", &[&hal]).await;
    let other = app.db.declare_scim_role_group("entra", "team", "Everyone", None, &lead, None).unwrap();
    app.db.save_scim_role_group(&other.id, None, "Everyone", true).unwrap();
    app.db.add_scim_role_group_member(&other.id, &hal);
    assert_eq!(app.db.grant_scim_team_role_group(&app.db.scim_role_group(&other.id).unwrap(), &hal), None);
}

#[tokio::test]
async fn an_idp_delete_or_a_user_delete_takes_the_team_role() {
    let (port, app, admin) = serve().await;
    let (t, _) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let ivy = person(port, &t, "ivy@example.com").await;
    let jo = person(port, &t, "jo@example.com").await;
    let eng = push(port, &t, "Eng", &[&ivy, &jo]).await;
    let lead = role(port, &admin, "Lead", &["users.manage"]).await;
    let gid = declared(port, &admin, "entra", "Leads", &lead).await;
    push(port, &t, "Leads", &[&ivy, &jo]).await;
    assert_eq!(team_role(&app, &jo), Some((eng.clone(), lead.clone())));

    let (code, _, _) = scim(port, &t, "DELETE", &format!("/scim/v2/Users/{jo}"), Value::Null).await;
    assert_eq!(code, 204);
    assert!(app.db.scim_team_role_group_grant_of_user(&jo).is_none());
    assert!(!app.db.scim_role_group_has(&gid, &jo));

    assert_eq!(scim(port, &t, "DELETE", &format!("{GROUPS}/{gid}"), Value::Null).await.0, 204);
    assert_eq!(team_role(&app, &ivy), None);
    assert_eq!(events(port, &admin, "action=role.unassigned").await[0]["details"]["reason"], "group_removed");
    let (_, v) = json_call(port, "GET", &format!("{ROLE_GROUPS}/{gid}"), &admin, "").await;
    assert_eq!((v["state"].as_str(), v["scope"].as_str()), (Some("waiting"), Some("team")), "{v}");
    // Pushed again, it is the team role group again.
    push(port, &t, "Leads", &[&ivy]).await;
    assert_eq!(team_role(&app, &ivy), Some((eng.clone(), lead.clone())));
}

#[tokio::test]
async fn leaving_a_mapped_team_hands_on_to_an_org_role_group() {
    let (port, app, admin) = serve().await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let kim = person(port, &t, "kim@example.com").await;
    let lee = person(port, &t, "lee@example.com").await;
    let eng = push(port, &t, "Eng", &[&kim, &lee]).await;
    let audit = role(port, &admin, "Auditor", &["audit.view"]).await;
    let reader = role(port, &admin, "Reader", &["audit.view"]).await;
    let (code, v) = json_call(port, "POST", "/api/scim/role-mappings", &admin, &json!({ "team": eng, "role": audit, "scope": "org" }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    let (code, v) = declare(port, &admin, "okta", "Readers", &reader, "org").await;
    assert_eq!(code, 201, "{v}");
    push(port, &t, "Readers", &[&kim, &lee]).await;
    assert_eq!((org_role(&app, &kim), org_role(&app, &lee)), (Some(audit.clone()), Some(audit.clone())), "the mapping gave it first");

    // The IdP takes Kim off Eng: the mapping's role goes, and the role group she's in gives its own.
    members(port, &t, &eng, "Remove", &[&kim]).await;
    assert_eq!(org_role(&app, &kim), Some(reader.clone()));
    // The IdP deletes Eng: the same for Lee.
    assert_eq!(scim(port, &t, "DELETE", &format!("{GROUPS}/{eng}"), Value::Null).await.0, 204);
    assert_eq!(org_role(&app, &lee), Some(reader.clone()));
}

#[tokio::test]
async fn a_retried_join_finishes_what_a_restart_cut_short() {
    let (port, app, admin) = serve().await;
    let (t, _) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let nia = person(port, &t, "nia@example.com").await;
    let oli = person(port, &t, "oli@example.com").await;
    let eng = push(port, &t, "Eng", &[&oli]).await;
    let lead = role(port, &admin, "Lead", &["users.manage"]).await;
    let audit = role(port, &admin, "Auditor", &["audit.view"]).await;
    let (code, v) = json_call(port, "POST", "/api/scim/role-mappings", &admin, &json!({ "team": eng, "role": audit, "scope": "org" }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    declared(port, &admin, "entra", "Leads", &lead).await;
    push(port, &t, "Leads", &[&nia, &oli]).await;
    assert_eq!((team_role(&app, &oli), org_role(&app, &oli)), (Some((eng.clone(), lead.clone())), Some(audit.clone())));

    // An admin takes Oli's roles away by hand: they stay away on every push.
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{lead}/teams/{eng}/users/{oli}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{audit}/users/{oli}"), &admin, "").await.0, 200);
    // Nia's join was saved, then the server restarted before her roles were offered.
    assert!(app.db.begin_scim_join(&eng, &nia) && app.db.add_team_member(&eng, &nia, teams::MEMBER, None));
    assert_eq!((team_role(&app, &nia), org_role(&app, &nia)), (None, None));
    // A leave from another team, finishing late, leaves this join pending.
    app.db.end_scim_join("t-old-team", &nia);
    assert_eq!(app.db.scim_pending_joins(&eng), vec![nia.clone()]);

    // Okta's PUT names both again: Nia's join finishes, Oli's removed role stays removed.
    let body = json!({ "displayName": "Eng", "members": [{ "value": nia }, { "value": oli }] });
    assert_eq!(scim(port, &t, "PUT", &format!("{GROUPS}/{eng}"), body.clone()).await.0, 200);
    assert_eq!((team_role(&app, &nia), org_role(&app, &nia)), (Some((eng.clone(), lead.clone())), Some(audit.clone())));
    assert_eq!((team_role(&app, &oli), org_role(&app, &oli)), (None, None), "a role an admin took away stays away");
    assert!(app.db.scim_pending_joins(&eng).is_empty());
    assert_eq!(scim(port, &t, "PUT", &format!("{GROUPS}/{eng}"), body).await.0, 200);
    assert_eq!(team_role(&app, &oli), None);
    assert_eq!(events(port, &admin, "action=role.assigned").await.iter().filter(|e| e["details"]["user"] == nia.as_str()).count(), 2, "given once each");
}

#[tokio::test]
async fn role_group_events_say_their_scope() {
    let (port, _, admin) = serve().await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let pam = person(port, &t, "pam@example.com").await;
    push(port, &t, "Eng", &[&pam]).await;
    let lead = role(port, &admin, "Lead", &["users.manage"]).await;
    let biller = role(port, &admin, "Biller", &["billing.manage"]).await;
    let gid = declared(port, &admin, "okta", "Leads", &lead).await;
    push(port, &t, "Leads", &[&pam]).await;
    let body = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "replace", "path": "displayName", "value": "Team Leads" }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{gid}"), body).await.0, 204);
    assert_eq!(json_call(port, "PATCH", &format!("{ROLE_GROUPS}/{gid}"), &admin, &json!({ "role": biller }).to_string()).await.0, 200);
    assert_eq!(scim(port, &t, "DELETE", &format!("{GROUPS}/{gid}"), Value::Null).await.0, 204);
    assert_eq!(json_call(port, "DELETE", &format!("{ROLE_GROUPS}/{gid}"), &admin, "").await.0, 200);
    for action in ["scim.role_group_adopted", "scim.group_updated", "scim.role_group_changed", "scim.group_deleted", "scim.role_group_removed"] {
        let all = events(port, &admin, &format!("action={action}")).await;
        let e = all.iter().find(|e| e["details"]["roleGroup"] == gid.as_str()).unwrap_or_else(|| panic!("{action}: {all:?}"));
        assert_eq!(e["details"]["scope"], "team", "{action}: {e}");
    }
}
