//! SCIM groups as teams (ADR 0095) end to end: the real router, the request shapes
//! Entra ID and Okta send, tenants kept apart, and joining and leaving with the same
//! offboarding and seat sync as a team admin's add and remove.

use crate::acl::{Grant, Visibility};
use crate::billing::Billing;
use crate::billing_http_tests::{FakeStripe, KEY, PUBLIC, SECRET, World, audit, deliver, fake_stripe, world_with_auth};
use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::scim::groups::GROUP_SCHEMA;
use crate::scim_http_tests::{events, is_scim_error, okta_user, scim, token};
use crate::sso_http_tests::header;
use crate::team_billing_http_tests::{seat_posts, team_event, tier};
use crate::tests::{call, call_with, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const GROUPS: &str = "/scim/v2/Groups";
const ENTRA_GROUP: &str = "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group";
const PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// SCIM and its groups on, with the in-memory machine provider.
async fn serve() -> (u16, AppState, String) {
    let p: Arc<dyn MachineProvider> = Arc::new(Fake::default());
    let (port, app, admin, _) = serve_app_with(move |a| {
        a.scim.enabled = true;
        a.scim.groups = true;
        a.machines = Arc::new(ControlPlane::for_tests(p));
    })
    .await;
    (port, app, admin)
}

/// A user provisioned by `token`'s tenant. Returns their id.
async fn person(port: u16, token: &str, email: &str, external_id: &str) -> String {
    let (code, _, u) = scim(port, token, "POST", "/scim/v2/Users", okta_user(email, external_id)).await;
    assert_eq!(code, 201, "{u}");
    u["id"].as_str().unwrap().to_string()
}

/// A query value, encoded.
fn q(s: &str) -> String {
    s.replace(' ', "%20").replace('"', "%22").replace('[', "%5B").replace(']', "%5D")
}

fn ids(v: &Value) -> Vec<String> {
    v.as_array().unwrap_or(&vec![]).iter().map(|m| m["value"].as_str().unwrap().to_string()).collect()
}

/// Who is on `team`, with their team role.
fn on_team(app: &AppState, team: &str) -> Vec<(String, String)> {
    app.db.team_members(team).into_iter().map(|m| (m.user_id, m.role)).collect()
}

fn add(users: &[&str]) -> Value {
    json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "Add", "path": "members", "value": users.iter().map(|u| json!({ "$ref": null, "value": u })).collect::<Vec<_>>() }] })
}

fn remove(users: &[&str]) -> Value {
    json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "Remove", "path": "members", "value": users.iter().map(|u| json!({ "$ref": null, "value": u })).collect::<Vec<_>>() }] })
}

async fn json_call(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(port, method, path, who, body).await;
    (code, parse(&body))
}

async fn make_team(port: u16, admin: &str, name: &str, owner: &str) -> String {
    let (code, v) = json_call(port, "POST", "/api/teams", admin, &json!({ "name": name, "owner": owner }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

async fn link(port: u16, admin: &str, body: Value) -> (u16, Value) {
    json_call(port, "POST", "/api/scim/groups", admin, &body.to_string()).await
}

async fn reconcile(port: u16, admin: &str) {
    let (code, v) = json_call(port, "POST", "/api/machines/reconcile", admin, "").await;
    assert_eq!(code, 200, "{v}");
}

#[tokio::test]
async fn groups_need_their_own_switch_and_discovery_says_so() {
    // SCIM_GROUPS without SCIM: nothing at all.
    let (port, _, admin, _) = serve_app_with(|a| a.scim.groups = true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    for (m, p) in [("GET", GROUPS.to_string()), ("POST", GROUPS.to_string()), ("GET", format!("{GROUPS}/t1")), ("PATCH", format!("{GROUPS}/t1")), ("DELETE", format!("{GROUPS}/t1"))] {
        let (code, head, body) = scim(port, &t, m, &p, json!({ "displayName": "Eng" })).await;
        assert_eq!(code, 404, "{m} {p}");
        is_scim_error(&head, &body, 404);
    }

    // Both on: a Group resource type and schema, and the settings say so.
    let (port, _, admin) = serve().await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let (_, _, types) = scim(port, &t, "GET", "/scim/v2/ResourceTypes", Value::Null).await;
    assert_eq!(types["totalResults"], 2, "{types}");
    let group = types["Resources"].as_array().unwrap().iter().find(|r| r["id"] == "Group").unwrap().clone();
    assert_eq!((group["endpoint"].as_str(), group["schema"].as_str()), (Some("/Groups"), Some(GROUP_SCHEMA)));
    let (code, _, one) = scim(port, &t, "GET", "/scim/v2/ResourceTypes/Group", Value::Null).await;
    assert_eq!((code, one["meta"]["location"].clone()), (200, json!(format!("http://127.0.0.1:{port}/scim/v2/ResourceTypes/Group"))));
    let (_, _, schemas) = scim(port, &t, "GET", "/scim/v2/Schemas", Value::Null).await;
    let found: Vec<&str> = schemas["Resources"].as_array().unwrap().iter().filter_map(|s| s["id"].as_str()).collect();
    assert_eq!(found, [scim::USER_SCHEMA, GROUP_SCHEMA]);
    let (code, _, s) = scim(port, &t, "GET", &format!("/scim/v2/Schemas/{GROUP_SCHEMA}"), Value::Null).await;
    let names: Vec<&str> = s["attributes"].as_array().unwrap().iter().filter_map(|a| a["name"].as_str()).collect();
    assert_eq!((code, names), (200, vec!["displayName", "members"]));
    let (code, settings) = json_call(port, "GET", "/api/scim/tokens", &admin, "").await;
    assert_eq!((code, settings["groups"].clone()), (200, json!(true)));
    let (code, links) = json_call(port, "GET", "/api/scim/groups", &admin, "").await;
    assert_eq!((code, links["enabled"].clone(), links["groups"].clone(), links["links"].clone()), (200, json!(true), json!(true), json!([])));
}

#[tokio::test]
async fn entra_pushes_a_group_and_patches_its_members() {
    let (port, app, admin) = serve().await;
    let (t, tid) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let ada = person(port, &t, "ada@contoso.example", "ada").await;
    let al = person(port, &t, "al@contoso.example", "al").await;

    // Entra looks the group up by name, leaving members out, before it creates it.
    let lookup = format!("{GROUPS}?excludedAttributes=members&filter={}", q(r#"displayName eq "Eng""#));
    let (code, _, none) = scim(port, &t, "GET", &lookup, Value::Null).await;
    assert_eq!((code, none["totalResults"].clone()), (200, json!(0)));
    let (code, head, g) = scim(port, &t, "POST", GROUPS, json!({ "schemas": [GROUP_SCHEMA, ENTRA_GROUP], "externalId": "8aa1-eng", "displayName": "Eng" })).await;
    assert_eq!(code, 201, "{g}");
    assert_eq!(header(&head, "content-type").as_deref(), Some("application/scim+json"));
    let id = g["id"].as_str().unwrap().to_string();
    let at = format!("http://127.0.0.1:{port}/scim/v2/Groups/{id}");
    assert_eq!((header(&head, "location"), g["meta"]["location"].as_str()), (Some(at.clone()), Some(at.as_str())));
    assert_eq!((g["displayName"].as_str(), g["externalId"].as_str(), g["members"].clone(), g["schemas"].clone()), (Some("Eng"), Some("8aa1-eng"), json!([]), json!([GROUP_SCHEMA])));
    // The group is a team with no owner and no machines until an admin gives them.
    let team = app.db.team(&id).expect("a team");
    assert_eq!((team.name.as_str(), team.machines), ("Eng", false));
    assert!(on_team(&app, &id).is_empty());
    let created = &events(port, &admin, "action=team.created").await[0];
    assert_eq!((created["targetId"].as_str(), created["details"]["via"].as_str(), created["details"]["owner"].clone()), (Some(id.as_str()), Some("scim"), Value::Null));
    assert_eq!(created["actorId"], format!("scim:{tid}"));
    assert_eq!(events(port, &admin, "action=scim.group_created").await[0]["details"]["externalId"], "8aa1-eng");

    // Found again by name in any case, without members.
    let (_, _, found) = scim(port, &t, "GET", &format!("{GROUPS}?excludedAttributes=members&filter={}", q(r#"displayName eq "ENG""#)), Value::Null).await;
    assert_eq!((found["totalResults"].clone(), found["Resources"][0]["id"].as_str(), found["Resources"][0].get("members")), (json!(1), Some(id.as_str()), None));
    let (code, _, one) = scim(port, &t, "GET", &format!("{GROUPS}/{id}?excludedAttributes=members"), Value::Null).await;
    assert_eq!((code, one.get("members")), (200, None));

    // Add: 204 and no body; both join as plain members, through the team's own join.
    let (code, _, body) = scim(port, &t, "PATCH", &format!("{GROUPS}/{id}"), add(&[&ada, &al])).await;
    assert_eq!((code, body), (204, Value::Null));
    assert_eq!(on_team(&app, &id), vec![(ada.clone(), "member".to_string()), (al.clone(), "member".to_string())]);
    let joined = events(port, &admin, "action=team.member_joined").await;
    assert_eq!(joined.len(), 2, "{joined:?}");
    assert!(joined.iter().all(|e| e["details"]["via"] == "scim" && e["details"]["role"] == "member" && e["actorId"] == format!("scim:{tid}").as_str()), "{joined:?}");
    for u in [&ada, &al] {
        assert_eq!(app.db.user(u).unwrap().role, rbac::Role::Member, "never an org role");
    }

    // Entra checks a membership with a filter.
    for (who, n) in [(&ada, 1), (&al, 1), (&"u-nobody".to_string(), 0)] {
        let f = q(&format!(r#"id eq "{id}" and members eq "{who}""#));
        let (_, _, r) = scim(port, &t, "GET", &format!("{GROUPS}?excludedAttributes=members&filter={f}"), Value::Null).await;
        assert_eq!(r["totalResults"], n, "{who}");
    }

    // The same add again changes nothing and logs nothing.
    let updated = events(port, &admin, "action=scim.group_updated").await.len();
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{id}"), add(&[&ada])).await.0, 204);
    assert_eq!((events(port, &admin, "action=team.member_joined").await.len(), events(port, &admin, "action=scim.group_updated").await.len()), (2, updated));

    // Remove: Al leaves as if a team admin had removed him; again, nothing more.
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{id}"), remove(&[&al])).await.0, 204);
    assert_eq!(app.db.team_id_of(&al), None);
    let left = events(port, &admin, "action=team.member_left").await;
    assert_eq!((left.len(), left[0]["details"]["user"].as_str(), left[0]["details"]["reason"].as_str()), (1, Some(al.as_str()), Some("scim")));
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{id}"), remove(&[&al])).await.0, 204);
    assert_eq!(events(port, &admin, "action=team.member_left").await.len(), 1);
    let upd = &events(port, &admin, "action=scim.group_updated").await[0];
    assert_eq!((upd["details"]["removed"].clone(), upd["details"]["added"].clone(), upd["details"]["ownerless"].clone()), (json!([al]), json!([]), json!(false)));

    // Rename: the team's name follows.
    let rename = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "Replace", "path": "displayName", "value": "Engineering" }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{id}"), rename).await.0, 204);
    assert_eq!(app.db.team(&id).unwrap().name, "Engineering");
    assert_eq!(events(port, &admin, "action=scim.group_updated").await[0]["details"]["changes"]["displayName"], json!({ "from": "Eng", "to": "Engineering" }));

    // Refused, with nothing changed: a new externalId, someone the tenant never provisioned, bad JSON.
    let (code, head, body) = scim(port, &t, "PATCH", &format!("{GROUPS}/{id}"), json!({ "Operations": [{ "op": "Replace", "path": "externalId", "value": "other" }] })).await;
    assert_eq!((code, body["scimType"].as_str()), (400, Some("mutability")));
    is_scim_error(&head, &body, 400);
    let (code, _, body) = scim(port, &t, "PATCH", &format!("{GROUPS}/{id}"), add(&["u-nobody", &al])).await;
    assert_eq!((code, body["scimType"].as_str()), (400, Some("invalidValue")), "{body}");
    assert_eq!(app.db.team_id_of(&al), None, "all or nothing");
    let (code, _, body) = call_with(port, "PATCH", &format!("{GROUPS}/{id}"), &format!("Bearer {t}"), "", "{not json").await;
    assert_eq!((code, parse(&body)["scimType"].as_str()), (400, Some("invalidSyntax")));
    let (code, _, body) = scim(port, &t, "PATCH", &format!("{GROUPS}/{id}"), json!({ "Operations": [{ "op": "Add", "path": "members", "value": [{ "value": "t9", "type": "Group" }] }] })).await;
    assert_eq!(code, 400, "groups in groups: {body}");

    // Delete: its people leave, and the team the IdP made goes with it.
    let (code, head, body) = call_with(port, "DELETE", &format!("{GROUPS}/{id}"), &format!("Bearer {t}"), "", "").await;
    assert_eq!((code, body.as_str()), (204, ""), "{head}");
    assert!(app.db.team(&id).is_none());
    assert_eq!(app.db.team_id_of(&ada), None);
    let gone = &events(port, &admin, "action=scim.group_deleted").await[0];
    assert_eq!((gone["details"]["teamFate"].as_str(), gone["details"]["removed"].clone(), gone["actorId"].as_str()), (Some("deleted"), json!([ada]), Some(format!("scim:{tid}").as_str())));
    assert_eq!(events(port, &admin, "action=team.deleted").await[0]["details"]["reason"], "scim");
    for (m, body) in [("GET", Value::Null), ("DELETE", Value::Null), ("PATCH", add(&[&ada])), ("PUT", json!({ "displayName": "Eng" }))] {
        assert_eq!(scim(port, &t, m, &format!("{GROUPS}/{id}"), body).await.0, 404, "{m}");
    }
    assert_eq!(app.db.user(&ada).unwrap().role, rbac::Role::Member);

    // Names fold ASCII case only, the same for uniqueness and filters: "Équipe" and
    // "éQUIPE" are two groups, and each filter finds just its own.
    let (_, _, upper) = scim(port, &t, "POST", GROUPS, json!({ "displayName": "Équipe" })).await;
    let (code, _, lower) = scim(port, &t, "POST", GROUPS, json!({ "displayName": "éQUIPE" })).await;
    assert_eq!(code, 201, "{lower}");
    for (filter, want) in [("%C3%89quipe", &upper), ("%C3%A9quipe", &lower)] {
        let (_, _, found) = scim(port, &t, "GET", &format!("{GROUPS}?filter=displayName%20eq%20%22{filter}%22"), Value::Null).await;
        assert_eq!((found["totalResults"].clone(), &found["Resources"][0]["id"]), (json!(1), &want["id"]), "{filter}: {found}");
    }
}

#[tokio::test]
async fn okta_pushes_groups_with_put_and_patch() {
    let (port, app, admin) = serve().await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let u1 = person(port, &t, "u1@example.com", "00u1").await;
    let u2 = person(port, &t, "u2@example.com", "00u2").await;
    let u3 = person(port, &t, "u3@example.com", "00u3").await;

    // Okta checks by name, a page of 100, then creates it with an empty member list.
    let (_, _, none) = scim(port, &t, "GET", &format!("{GROUPS}?filter={}&startIndex=1&count=100", q(r#"displayName eq "Sales""#)), Value::Null).await;
    assert_eq!(none["totalResults"], 0);
    let (code, _, g) = scim(port, &t, "POST", GROUPS, json!({ "schemas": [GROUP_SCHEMA], "displayName": "Sales", "members": [] })).await;
    assert_eq!(code, 201, "{g}");
    let id = g["id"].as_str().unwrap().to_string();
    assert_eq!((g.get("externalId"), g["members"].clone()), (None, json!([])));
    // A name is unique in the tenant, in any case.
    let (code, head, body) = scim(port, &t, "POST", GROUPS, json!({ "displayName": "SALES" })).await;
    assert_eq!((code, body["scimType"].as_str()), (409, Some("uniqueness")));
    is_scim_error(&head, &body, 409);

    // Members added with path members; GET shows them, with their names and locations.
    let ops = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "add", "path": "members", "value": [{ "value": u1, "display": "u1@example.com" }, { "value": u2, "display": "u2@example.com" }] }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{id}"), ops).await.0, 204);
    let (code, _, g) = scim(port, &t, "GET", &format!("{GROUPS}/{id}"), Value::Null).await;
    assert_eq!((code, ids(&g["members"])), (200, vec![u1.clone(), u2.clone()]));
    assert_eq!(g["members"][0], json!({ "value": u1, "display": "Ada Lovelace", "type": "User", "$ref": format!("http://127.0.0.1:{port}/scim/v2/Users/{u1}") }));

    // A rename with no path, carrying the id; a remove by filter.
    let rename = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "replace", "value": { "id": id, "displayName": "Sales EMEA" } }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{id}"), rename).await.0, 204);
    assert_eq!(app.db.team(&id).unwrap().name, "Sales EMEA");
    let drop = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "remove", "path": format!("members[value eq \"{u1}\"]") }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{id}"), drop).await.0, 204);
    assert_eq!(app.db.team_id_of(&u1), None);

    // PUT (Okta's AIW apps): the member list sent is the list.
    let put = json!({ "schemas": [GROUP_SCHEMA], "id": id, "displayName": "Sales EMEA", "members": [{ "value": u2 }, { "value": u3 }] });
    let (code, _, g) = scim(port, &t, "PUT", &format!("{GROUPS}/{id}"), put.clone()).await;
    assert_eq!((code, ids(&g["members"])), (200, vec![u2.clone(), u3.clone()]), "{g}");
    let joined = events(port, &admin, "action=team.member_joined").await.len();
    assert_eq!(scim(port, &t, "PUT", &format!("{GROUPS}/{id}"), put).await.0, 200);
    assert_eq!(events(port, &admin, "action=team.member_joined").await.len(), joined, "the same PUT twice changes nothing");
    // Without members, they stay; the name changes.
    let (code, _, g) = scim(port, &t, "PUT", &format!("{GROUPS}/{id}"), json!({ "displayName": "Sales" })).await;
    assert_eq!((code, g["displayName"].as_str(), ids(&g["members"])), (200, Some("Sales"), vec![u2.clone(), u3.clone()]));
    // An empty list empties it; the group and its team stay.
    let (code, _, g) = scim(port, &t, "PUT", &format!("{GROUPS}/{id}"), json!({ "displayName": "Sales", "members": [] })).await;
    assert_eq!((code, g["members"].clone()), (200, json!([])));
    assert!(app.db.team(&id).is_some() && on_team(&app, &id).is_empty());
    let (code, _, body) = scim(port, &t, "PUT", &format!("{GROUPS}/{id}"), json!({ "members": [] })).await;
    assert_eq!((code, body["scimType"].as_str()), (400, Some("invalidValue")), "displayName is required");

    // Pages, 1-based, oldest first; filters it doesn't know are refused.
    assert_eq!(scim(port, &t, "POST", GROUPS, json!({ "displayName": "Support", "members": [{ "value": u1 }] })).await.0, 201);
    let (_, _, page) = scim(port, &t, "GET", &format!("{GROUPS}?startIndex=2&count=1"), Value::Null).await;
    assert_eq!((page["totalResults"].clone(), page["itemsPerPage"].clone(), page["Resources"][0]["displayName"].as_str()), (json!(2), json!(1), Some("Support")));
    assert_eq!(ids(&page["Resources"][0]["members"]), vec![u1.clone()]);
    let (_, _, by_member) = scim(port, &t, "GET", &format!("{GROUPS}?filter={}", q(&format!(r#"members[value eq "{u1}"]"#))), Value::Null).await;
    assert_eq!((by_member["totalResults"].clone(), by_member["Resources"][0]["displayName"].as_str()), (json!(1), Some("Support")));
    for bad in [r#"displayName sw "S""#, r#"displayName eq "Sales" or displayName eq "Support""#, r#"meta.created gt "2020""#] {
        let (code, _, body) = scim(port, &t, "GET", &format!("{GROUPS}?filter={}", q(bad)), Value::Null).await;
        assert_eq!((code, body["scimType"].as_str()), (400, Some("invalidFilter")), "{bad}");
    }
    assert_eq!(scim(port, &t, "GET", &format!("{GROUPS}?startIndex=x"), Value::Null).await.0, 400);

    // A PUT carries every member: far past the users' body limit, it's still read.
    let many: Vec<Value> = (0..2000).map(|i| json!({ "value": format!("u-{i:08}"), "display": format!("person-{i}@example.com") })).collect();
    let big = json!({ "displayName": "Sales", "members": many });
    assert!(big.to_string().len() > scim::MAX_BODY);
    let (code, _, body) = scim(port, &t, "PUT", &format!("{GROUPS}/{id}"), big).await;
    assert_eq!((code, body["scimType"].as_str()), (400, Some("invalidValue")), "read, then refused for unknown users");
    let (code, _, _) = call_with(port, "PUT", &format!("{GROUPS}/{id}"), &format!("Bearer {t}"), "", &format!("{{\"displayName\":\"{}\"}}", "x".repeat(scim::groups::MAX_BODY))).await;
    assert_eq!(code, 413);
}

#[tokio::test]
async fn tenants_and_manual_teams_stay_apart() {
    let (port, app, admin) = serve().await;
    let (a, _) = token(port, &admin, json!({ "tenant": "a" })).await;
    let (b, _) = token(port, &admin, json!({ "tenant": "b" })).await;
    let ann = person(port, &a, "ann@example.com", "x1").await;
    let ari = person(port, &a, "ari@example.com", "x2").await;
    let bo = person(port, &b, "bo@example.com", "y1").await;
    let (manual, _) = user_with(port, &admin, "manual@example.com", "member").await;
    let (_, _, g) = scim(port, &a, "POST", GROUPS, json!({ "displayName": "Eng", "members": [{ "value": ann }] })).await;
    let eng = g["id"].as_str().unwrap().to_string();

    // Tenant b doesn't see or touch a's group.
    assert_eq!(scim(port, &b, "GET", GROUPS, Value::Null).await.2["totalResults"], 0);
    assert_eq!(scim(port, &b, "GET", &format!("{GROUPS}?filter={}", q(&format!(r#"id eq "{eng}""#))), Value::Null).await.2["totalResults"], 0);
    for (m, body) in [("GET", Value::Null), ("PATCH", remove(&[&ann])), ("PUT", json!({ "displayName": "Mine", "members": [] })), ("DELETE", Value::Null)] {
        assert_eq!(scim(port, &b, m, &format!("{GROUPS}/{eng}"), body).await.0, 404, "{m}");
    }
    assert_eq!((app.db.team(&eng).unwrap().name.as_str(), on_team(&app, &eng).len()), ("Eng", 1));
    // Names are unique per tenant: b has its own Eng, holding only b's people.
    let (code, _, g) = scim(port, &b, "POST", GROUPS, json!({ "displayName": "Eng", "members": [{ "value": bo }] })).await;
    assert_eq!(code, 201, "{g}");
    let b_eng = g["id"].as_str().unwrap().to_string();
    assert_ne!(b_eng, eng);
    for stranger in [&ari, &manual] {
        let (code, _, body) = scim(port, &b, "PATCH", &format!("{GROUPS}/{b_eng}"), add(&[stranger])).await;
        assert_eq!((code, body["scimType"].as_str()), (400, Some("invalidValue")), "{body}");
        assert_eq!(app.db.team_id_of(stranger), None);
    }
    // Nor can a filter tell b whether a's people are anywhere.
    assert_eq!(scim(port, &b, "GET", &format!("{GROUPS}?filter={}", q(&format!(r#"members eq "{ann}""#))), Value::Null).await.2["totalResults"], 0);

    // A team made by hand isn't a group to anyone.
    let ops = make_team(port, &admin, "Ops", "manual@example.com").await;
    for t in [&a, &b] {
        for (m, body) in [("GET", Value::Null), ("PATCH", add(&[&ann])), ("PUT", json!({ "displayName": "Ops", "members": [] })), ("DELETE", Value::Null)] {
            assert_eq!(scim(port, t, m, &format!("{GROUPS}/{ops}"), body).await.0, 404, "{m}");
        }
    }
    assert_eq!(on_team(&app, &ops), vec![(manual.clone(), "owner".to_string())]);
    // Its name is free for a group: groups and hand-made teams are apart.
    assert_eq!(scim(port, &a, "POST", GROUPS, json!({ "displayName": "Ops" })).await.0, 201);

    // Someone on another team is never moved: a 409, audited, and nothing changes.
    assert_eq!(call(port, "PUT", &format!("/api/teams/{ops}/members/{ari}"), &admin, "{}").await.0, 200);
    let (code, _, body) = scim(port, &a, "PATCH", &format!("{GROUPS}/{eng}"), add(&[&ari])).await;
    assert_eq!((code, body["scimType"].as_str()), (409, Some("uniqueness")), "{body}");
    assert_eq!(app.db.team_id_of(&ari).as_deref(), Some(ops.as_str()));
    let refused = &events(port, &admin, "action=scim.group_member_refused").await[0];
    assert_eq!((refused["outcome"].as_str(), refused["details"]["reason"].as_str(), refused["details"]["users"].clone()), (Some("denied"), Some("other_team"), json!([ari])));
    let before = app.db.scim_groups("a").len();
    let (code, _, _) = scim(port, &a, "POST", GROUPS, json!({ "displayName": "New", "members": [{ "value": ari }] })).await;
    assert_eq!((code, app.db.scim_groups("a").len()), (409, before), "no group made");
}

#[tokio::test]
async fn an_admin_links_a_team_for_the_idp_to_take_on() {
    let (port, app, admin) = serve().await;
    let (entra, tid) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let (okta, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let (ada, ada_s) = user_with(port, &admin, "ada@example.com", "member").await;
    let al = person(port, &entra, "al@contoso.example", "al").await;
    let platform = make_team(port, &admin, "Platform", "ada@example.com").await;
    assert_eq!(call(port, "PUT", &format!("/api/teams/{platform}/members/{al}"), &admin, r#"{"role":"admin"}"#).await.0, 200);

    // Only server admins link; a SCIM token isn't a sign-in at all.
    assert_eq!(link(port, &ada_s, json!({ "tenant": "entra", "team": platform })).await.0, 403);
    assert_eq!(call(port, "POST", "/api/scim/groups", &format!("Bearer {entra}"), &json!({ "tenant": "entra", "team": platform }).to_string()).await.0, 401);
    for (body, want) in [
        (json!({ "tenant": "Entra", "team": platform }), 400),
        (json!({ "tenant": "entra", "team": "t-none" }), 404),
        (json!({ "tenant": "entra", "team": platform, "externalId": 7 }), 400),
        (json!({ "tenant": "entra", "team": platform, "displayName": "x".repeat(257) }), 400),
    ] {
        assert_eq!(link(port, &admin, body.clone()).await.0, want, "{body}");
    }
    let (code, l) = link(port, &admin, json!({ "tenant": "entra", "team": platform, "externalId": "8bb2" })).await;
    assert_eq!(code, 201, "{l}");
    assert_eq!((l["origin"].as_str(), l["displayName"].as_str(), l["provisionedAt"].clone(), l["members"].clone(), l["provisionedMembers"].clone()), (Some("admin"), Some("Platform"), Value::Null, json!(2), json!(1)));
    assert_eq!(link(port, &admin, json!({ "tenant": "okta", "team": platform })).await.0, 409, "one group per team");
    user_with(port, &admin, "otto@example.com", "member").await;
    let other = make_team(port, &admin, "Other", "otto@example.com").await;
    assert_eq!(link(port, &admin, json!({ "tenant": "entra", "team": other, "externalId": "8bb2" })).await.0, 409);
    let linked = events(port, &admin, "action=scim.group_linked").await;
    assert_eq!((linked.len(), linked[0]["actorKind"].as_str(), linked[0]["details"]["tenant"].as_str()), (1, Some("user"), Some("entra")));
    let (_, view) = json_call(port, "GET", &format!("/api/teams/{platform}"), &admin, "").await;
    assert_eq!(view["scimGroup"], json!({ "tenant": "entra", "displayName": "Platform", "externalId": "8bb2", "origin": "admin", "provisioned": false }));
    let (_, mine) = json_call(port, "GET", "/api/team", &ada_s, "").await;
    assert!(mine.get("scimGroup").is_none(), "only server admins see the link: {mine}");

    // Entra pushes it: the same team, renamed; Ada, whom it doesn't manage, stays its owner.
    let (code, _, g) = scim(port, &entra, "POST", GROUPS, json!({ "schemas": [GROUP_SCHEMA, ENTRA_GROUP], "externalId": "8bb2", "displayName": "Platform Team" })).await;
    assert_eq!((code, g["id"].as_str(), ids(&g["members"])), (201, Some(platform.as_str()), vec![al.clone()]), "{g}");
    assert_eq!(app.db.team(&platform).unwrap().name, "Platform Team");
    assert!(on_team(&app, &platform).contains(&(ada.clone(), "owner".to_string())));
    let adopted = &events(port, &admin, "action=scim.group_adopted").await[0];
    assert_eq!((adopted["targetId"].as_str(), adopted["actorId"].as_str()), (Some(platform.as_str()), Some(format!("scim:{tid}").as_str())));
    assert_eq!(scim(port, &entra, "POST", GROUPS, json!({ "externalId": "8bb2", "displayName": "Platform Team" })).await.0, 409, "taken on once");
    assert_eq!(scim(port, &okta, "GET", &format!("{GROUPS}/{platform}"), Value::Null).await.0, 404);
    // Taking Al out leaves the people it doesn't manage alone.
    assert_eq!(scim(port, &entra, "PATCH", &format!("{GROUPS}/{platform}"), remove(&[&al])).await.0, 204);
    assert_eq!(on_team(&app, &platform), vec![(ada.clone(), "owner".to_string())]);

    // Okta sends no externalId: a link with none is taken on by name.
    user_with(port, &admin, "dee@example.com", "member").await;
    let design = make_team(port, &admin, "Design", "dee@example.com").await;
    assert_eq!(link(port, &admin, json!({ "tenant": "okta", "team": design })).await.0, 201);
    let (_, _, found) = scim(port, &okta, "GET", &format!("{GROUPS}?filter={}", q(r#"displayName eq "design""#)), Value::Null).await;
    assert_eq!(found["Resources"][0]["id"].as_str(), Some(design.as_str()));
    let (code, _, g) = scim(port, &okta, "POST", GROUPS, json!({ "displayName": "Design", "members": [] })).await;
    assert_eq!((code, g["id"].as_str()), (201, Some(design.as_str())));
    assert_eq!(on_team(&app, &design).len(), 1, "its owner stays");

    // Unlinked, the team is the admins' again: everyone stays, the IdP's group is gone.
    let (code, _) = json_call(port, "DELETE", &format!("/api/scim/groups/{platform}"), &ada_s, "").await;
    assert_eq!(code, 403);
    let (code, _) = json_call(port, "DELETE", &format!("/api/scim/groups/{platform}"), &admin, "").await;
    assert_eq!(code, 200);
    assert_eq!(scim(port, &entra, "GET", &format!("{GROUPS}/{platform}"), Value::Null).await.0, 404);
    assert_eq!(on_team(&app, &platform), vec![(ada.clone(), "owner".to_string())]);
    assert_eq!(events(port, &admin, "action=scim.group_unlinked").await[0]["details"]["origin"], "admin");
    assert_eq!(json_call(port, "DELETE", &format!("/api/scim/groups/{platform}"), &admin, "").await.0, 404);
    let (_, links) = json_call(port, "GET", "/api/scim/groups", &admin, "").await;
    assert_eq!(links["links"].as_array().unwrap().len(), 1, "{links}");
}

#[tokio::test]
async fn leaving_a_group_offboards_like_leaving_the_team() {
    let (port, app, admin) = serve().await;
    let (t, tid) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let alpha = make_team(port, &admin, "Alpha", "ada@example.com").await;
    assert!(app.db.team(&alpha).unwrap().machines);
    assert_eq!(link(port, &admin, json!({ "tenant": "okta", "team": alpha })).await.0, 201);
    let al = person(port, &t, "al@example.com", "00u1").await;
    let mut off = okta_user("cy@example.com", "00u2");
    off["active"] = json!(false);
    let (_, _, cy) = scim(port, &t, "POST", "/scim/v2/Users", off).await;
    let cy = cy["id"].as_str().unwrap().to_string();

    // Okta pushes Alpha with Al and Cy: Al gets the team's machine; Cy, disabled, joins
    // with none until she's enabled.
    let (code, _, g) = scim(port, &t, "POST", GROUPS, json!({ "displayName": "Alpha", "members": [{ "value": al }, { "value": cy }] })).await;
    assert_eq!((code, g["id"].as_str()), (201, Some(alpha.as_str())), "{g}");
    assert_eq!(on_team(&app, &alpha).len(), 3);
    reconcile(port, &admin).await;
    let machine = app.db.user_machine(&al).expect("joining gave Al a machine");
    assert!(app.db.team_machine(&machine.id).is_some_and(|m| m.team_id == alpha));
    assert!(app.db.user_machine(&cy).is_none(), "no machine for a disabled person");
    // Enabled, she gets the team's machine, as joining would have given her.
    let on = json!({ "Operations": [{ "op": "replace", "value": { "active": true } }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("/scim/v2/Users/{cy}"), on).await.0, 200);
    let cy_machine = app.db.user_machine(&cy).expect("enabling gave Cy the team's machine");
    assert!(app.db.team_machine(&cy_machine.id).is_some_and(|m| m.team_id == alpha));
    let asked = events(port, &admin, "action=team.machine_requested").await;
    assert!(asked.iter().any(|e| e["details"]["user"] == cy.as_str()), "{asked:?}");

    // Sharing inside the team, both ways.
    let ledger = app.db.create_bot_owned("Ledger", "#fff", "waddle", "claude", None, false, &ada, Visibility::Private).id;
    let notes = app.db.create_bot_owned("Notes", "#fff", "waddle", "claude", None, false, &al, Visibility::Private).id;
    app.db.set_grant(&ledger, &al, Grant::Operator, &ada);
    app.db.set_grant(&notes, &ada, Grant::Viewer, &al);

    // Okta takes Al out: grants go both ways, his machine is suspended and released,
    // each step audited with the token as the actor.
    let drop = json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "remove", "path": format!("members[value eq \"{al}\"]") }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{alpha}"), drop).await.0, 204);
    assert!(app.db.grant(&ledger, &al).is_none() && app.db.grant(&notes, &ada).is_none());
    let revoked = events(port, &admin, "action=bot.access_revoked").await;
    assert_eq!(revoked.len(), 2, "{revoked:?}");
    assert!(revoked.iter().all(|e| e["details"]["reason"] == "left_team" && e["actorId"] == format!("scim:{tid}").as_str()), "{revoked:?}");
    let left = &events(port, &admin, "action=team.member_left").await[0];
    assert_eq!((left["details"]["user"].as_str(), left["details"]["reason"].as_str()), (Some(al.as_str()), Some("scim")));
    assert_eq!(app.db.machine(&machine.id).unwrap().state, crate::machines::State::Suspended);
    assert!(app.db.team_machine(&machine.id).unwrap().released_at.is_some());
    assert_eq!(on_team(&app, &alpha).len(), 2);
    // Enabling someone who has a machine asks for no other.
    let before = app.db.machines(None).len();
    assert!(!crate::teams::user_enabled(&app, &crate::audit::Who::system("test"), &cy).await);
    assert_eq!(app.db.machines(None).len(), before);
}

#[tokio::test]
async fn deleting_a_group_deletes_only_what_the_idp_made_and_owners_are_never_set_by_scim() {
    let (port, app, admin) = serve().await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let u1 = person(port, &t, "u1@example.com", "00u1").await;
    let u2 = person(port, &t, "u2@example.com", "00u2").await;
    let (manual, _) = user_with(port, &admin, "manual@example.com", "member").await;
    let made = |name: &str, members: &[&str]| {
        let body = json!({ "displayName": name, "members": members.iter().map(|m| json!({ "value": m })).collect::<Vec<_>>() });
        let t = t.clone();
        async move {
            let (code, _, g) = scim(port, &t, "POST", GROUPS, body).await;
            assert_eq!(code, 201, "{g}");
            g["id"].as_str().unwrap().to_string()
        }
    };

    // An admin names an owner of a team the IdP made; the IdP taking them out leaves it
    // ownerless, which is audited for an admin to fix.
    let own = made("Own", &[&u1]).await;
    assert_eq!(call(port, "PUT", &format!("/api/teams/{own}/members/{u1}"), &admin, r#"{"role":"owner"}"#).await.0, 200);
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{own}"), remove(&[&u1])).await.0, 204);
    assert!(on_team(&app, &own).is_empty() && app.db.team(&own).is_some(), "an empty group keeps its team");
    assert_eq!(events(port, &admin, "action=scim.group_updated").await[0]["details"]["ownerless"], false, "no one left to lead");
    let shared = made("Shared", &[&u1]).await;
    assert_eq!(call(port, "PUT", &format!("/api/teams/{shared}/members/{manual}"), &admin, "{}").await.0, 200);
    assert_eq!(call(port, "PUT", &format!("/api/teams/{shared}/members/{u1}"), &admin, r#"{"role":"owner"}"#).await.0, 200);
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{shared}"), remove(&[&u1])).await.0, 204);
    assert_eq!(on_team(&app, &shared), vec![(manual.clone(), "member".to_string())]);
    assert_eq!(events(port, &admin, "action=scim.group_updated").await[0]["details"]["ownerless"], true);

    // Deleting a group with someone the IdP doesn't manage keeps the team for them.
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{shared}"), add(&[&u2])).await.0, 204);
    assert_eq!(scim(port, &t, "DELETE", &format!("{GROUPS}/{shared}"), Value::Null).await.0, 204);
    assert_eq!(on_team(&app, &shared), vec![(manual.clone(), "member".to_string())]);
    let gone = &events(port, &admin, "action=scim.group_deleted").await[0];
    assert_eq!((gone["details"]["teamFate"].as_str(), gone["details"]["removed"].clone()), (Some("kept"), json!([u2])));
    let (_, view) = json_call(port, "GET", &format!("/api/teams/{shared}"), &admin, "").await;
    assert!(view.get("scimGroup").is_none(), "unlinked: {view}");
    // An empty team the IdP made goes with its group.
    assert_eq!(scim(port, &t, "DELETE", &format!("{GROUPS}/{own}"), Value::Null).await.0, 204);
    assert!(app.db.team(&own).is_none());

    // A SCIM DELETE of a user takes them off their group's team too, logged like a
    // removal from the group, the last owner's included.
    let hook = made("Hook", &[&u1, &u2]).await;
    assert_eq!(call(port, "PUT", &format!("/api/teams/{hook}/members/{u1}"), &admin, r#"{"role":"owner"}"#).await.0, 200);
    assert_eq!(scim(port, &t, "DELETE", &format!("/scim/v2/Users/{u1}"), Value::Null).await.0, 204);
    assert_eq!(on_team(&app, &hook), vec![(u2.clone(), "member".to_string())]);
    let left = &events(port, &admin, "action=team.member_left").await[0];
    assert_eq!((left["details"]["user"].as_str(), left["details"]["reason"].as_str()), (Some(u1.as_str()), Some("scim")));
    let upd = &events(port, &admin, "action=scim.group_updated").await[0];
    assert_eq!((upd["targetId"].as_str(), upd["details"]["removed"].clone(), upd["details"]["ownerless"].clone()), (Some(hook.as_str()), json!([u1]), json!(true)));
    let (_, _, g) = scim(port, &t, "GET", &format!("{GROUPS}/{hook}"), Value::Null).await;
    assert_eq!(ids(&g["members"]), vec![u2.clone()]);
    // Nothing the IdP sends makes anyone an owner or admin.
    let (code, _, _) = scim(port, &t, "PATCH", &format!("{GROUPS}/{hook}"), json!({ "Operations": [{ "op": "add", "path": "roles", "value": [{ "value": "owner" }] }] })).await;
    assert_eq!(code, 204);
    assert_eq!(on_team(&app, &hook), vec![(u2.clone(), "member".to_string())]);
    assert_eq!(app.db.user(&u2).unwrap().role, rbac::Role::Member);
}

/// The billing world with checkout on a fake Stripe, SCIM groups on, and Alpha (Ada its
/// owner, Bea a member) paying for pro with 2 seats, linked to the okta tenant.
async fn paying() -> (World, FakeStripe, String, String) {
    let (url, f) = fake_stripe().await;
    let w = world_with_auth(Some(Billing::with_checkout(SECRET, KEY, &url, PUBLIC)), |a| {
        a.scim.enabled = true;
        a.scim.groups = true;
    })
    .await;
    let (code, v) = json_call(w.port, "POST", "/api/teams", &w.admin, &json!({ "name": "Alpha", "owner": w.a_id }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    let alpha = v["id"].as_str().unwrap().to_string();
    assert_eq!(call(w.port, "PUT", &format!("/api/teams/{alpha}/members/{}", w.b_id), &w.admin, "{}").await.0, 200);
    assert_eq!(deliver(w.port, &team_event(&alpha, "evt_s1", 1_795_000_000, |_| {}), None).await.1["outcome"], "tier_changed");
    assert_eq!(team_billing::sync_seats(&w.app).await, 0);
    let (t, _) = token(w.port, &w.admin, json!({ "tenant": "okta" })).await;
    assert_eq!(link(w.port, &w.admin, json!({ "tenant": "okta", "team": alpha })).await.0, 201);
    (w, f, alpha, t)
}

#[tokio::test]
async fn seats_follow_the_group_and_a_paying_team_outlives_it() {
    let (w, stripe, alpha, t) = paying().await;
    let port = w.port;
    let cy = person(port, &t, "cy@example.com", "00u3").await;

    // Okta pushes Alpha with Cy: on the team's plan at once, and billed a seat.
    let (code, _, g) = scim(port, &t, "POST", GROUPS, json!({ "displayName": "Alpha", "members": [{ "value": cy }] })).await;
    assert_eq!((code, g["id"].as_str()), (201, Some(alpha.as_str())), "{g}");
    assert_eq!(tier(&w, &cy), "pro");
    assert_eq!(team_billing::sync_seats(&w.app).await, 1);
    assert_eq!(seat_posts(&stripe).last().unwrap().get("quantity"), Some("3"));
    // Taken out: back on their own plan, and the seat goes.
    assert_eq!(scim(port, &t, "PATCH", &format!("{GROUPS}/{alpha}"), remove(&[&cy])).await.0, 204);
    assert_eq!(tier(&w, &cy), "starter");
    assert_eq!(team_billing::sync_seats(&w.app).await, 1);
    assert_eq!(seat_posts(&stripe).last().unwrap().get("quantity"), Some("2"));

    // A team the IdP made that pays outlives its group until the plan is cancelled.
    let (_, _, g) = scim(port, &t, "POST", GROUPS, json!({ "displayName": "Paid", "members": [{ "value": cy }] })).await;
    let paid = g["id"].as_str().unwrap().to_string();
    let sub = team_event(&paid, "evt_p1", 1_795_000_100, |v| {
        let o = &mut v["data"]["object"];
        o["id"] = json!("sub_test_paid");
        o["customer"] = json!("cus_test_paid");
        o["items"]["data"][0]["id"] = json!("si_test_paid");
        o["items"]["data"][0]["quantity"] = json!(1);
    });
    assert_eq!(deliver(port, &sub, None).await.1["outcome"], "tier_changed");
    assert_eq!(tier(&w, &cy), "pro");
    assert_eq!(scim(port, &t, "DELETE", &format!("{GROUPS}/{paid}"), Value::Null).await.0, 204);
    assert!(w.app.db.team(&paid).is_some());
    assert_eq!((w.app.db.team_id_of(&cy), tier(&w, &cy)), (None, "starter".to_string()));
    let gone = &audit(port, &w.admin, "action=scim.group_deleted").await[0];
    assert_eq!(gone["details"]["teamFate"], "kept_paying");
    let refused = &audit(port, &w.admin, "action=team.delete_refused").await[0];
    assert_eq!((refused["details"]["reason"].as_str(), refused["details"]["via"].as_str()), (Some("team_pays"), Some("scim")));
    assert_eq!(scim(port, &t, "GET", &format!("{GROUPS}/{paid}"), Value::Null).await.0, 404);
}
