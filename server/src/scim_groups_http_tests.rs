//! SCIM groups as teams (ADR 0095), end to end: the real router, the in-memory machine
//! provider, and the group requests Entra ID and Okta send.

use crate::acl::Visibility;
use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::sso_http_tests::header;
use crate::tests::{audit_list, call, call_with, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const GROUPS: &str = "/scim/v2/Groups";

struct World {
    port: u16,
    app: AppState,
    admin: String,
    entra: String,
    token_id: String,
}

async fn world(groups: bool) -> World {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, admin, _) = serve_app_with(move |a| {
        a.scim.enabled = true;
        a.scim.groups = groups;
        a.machines = Arc::new(ControlPlane::for_tests(p));
    })
    .await;
    let (entra, token_id) = token(port, &admin, "entra").await;
    World { port, app, admin, entra, token_id }
}

async fn token(port: u16, admin: &str, tenant: &str) -> (String, String) {
    let (code, res) = call(port, "POST", "/api/scim/tokens", admin, &json!({ "tenant": tenant }).to_string()).await;
    assert_eq!(code, 201, "{res}");
    let res = parse(&res);
    (res["token"].as_str().unwrap().to_string(), res["scimToken"]["id"].as_str().unwrap().to_string())
}

async fn scim(port: u16, token: &str, method: &str, path: &str, body: Value) -> (u16, String, Value) {
    let body = if body.is_null() { String::new() } else { body.to_string() };
    let (code, head, res) = call_with(port, method, path, &format!("Bearer {token}"), "", &body).await;
    (code, head, parse(&res))
}

/// A user the tenant provisions. Returns its id.
async fn person(w: &World, token: &str, email: &str, active: bool) -> String {
    let body = json!({ "userName": email, "externalId": format!("x-{email}"), "emails": [{ "value": email, "primary": true }], "active": active });
    let (code, _, u) = scim(w.port, token, "POST", "/scim/v2/Users", body).await;
    assert_eq!(code, 201, "{u}");
    u["id"].as_str().unwrap().to_string()
}

async fn json_call(w: &World, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(w.port, method, path, who, body).await;
    (code, parse(&body))
}

async fn events(w: &World, action: &str) -> Vec<Value> {
    let (code, body) = call(w.port, "GET", &format!("/api/audit?action={action}&limit=200"), &w.admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn session_for(w: &World, user: &str) -> String {
    let (code, c) = call(w.port, "POST", &format!("/api/users/{user}/login-codes"), &w.admin, "").await;
    assert_eq!(code, 200, "{c}");
    let (code, res) = call(w.port, "POST", "/api/auth/login", "", &json!({ "code": parse(&c)["code"] }).to_string()).await;
    assert_eq!(code, 200, "{res}");
    format!("Bearer {}", parse(&res)["token"].as_str().unwrap())
}

fn add(ids: &[&str]) -> Value {
    let value: Vec<Value> = ids.iter().map(|id| json!({ "value": id })).collect();
    json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{ "op": "Add", "path": "members", "value": value }] })
}

fn remove(id: &str) -> Value {
    json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{ "op": "Remove", "path": format!("members[value eq \"{id}\"]") }] })
}

fn members(w: &World, team: &str) -> Vec<String> {
    w.app.db.team_members(team).into_iter().map(|m| m.user_id).collect()
}

#[tokio::test]
async fn groups_stay_off_unless_scim_groups_is_on() {
    let w = world(false).await;
    let (code, _, list) = scim(w.port, &w.entra, "GET", &format!("{GROUPS}?startIndex=1&count=100"), Value::Null).await;
    assert_eq!((code, list["totalResults"].clone(), list["Resources"].clone()), (200, json!(0), json!([])));
    for (m, p) in [("POST", GROUPS.to_string()), ("PUT", format!("{GROUPS}/t1")), ("PATCH", format!("{GROUPS}/t1")), ("DELETE", format!("{GROUPS}/t1"))] {
        let (code, _, body) = scim(w.port, &w.entra, m, &p, json!({ "displayName": "Eng" })).await;
        assert_eq!(code, 501, "{m} {p}: {body}");
        assert!(body["detail"].as_str().unwrap().contains("SCIM_GROUPS=on"), "{body}");
    }
    assert_eq!(scim(w.port, &w.entra, "GET", &format!("{GROUPS}/t1"), Value::Null).await.0, 404);
    let (_, _, types) = scim(w.port, &w.entra, "GET", "/scim/v2/ResourceTypes", Value::Null).await;
    assert_eq!(types["totalResults"], 1, "{types}");
    assert_eq!(scim(w.port, &w.entra, "GET", "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group", Value::Null).await.0, 404);
    assert!(w.app.db.teams().is_empty());
}

#[tokio::test]
async fn a_group_is_a_team_and_its_members_join_and_leave_it() {
    let w = world(true).await;
    let (_, _, types) = scim(w.port, &w.entra, "GET", "/scim/v2/ResourceTypes", Value::Null).await;
    assert_eq!(types["Resources"][1]["endpoint"], "/Groups", "{types}");
    let (code, _, schema) = scim(w.port, &w.entra, "GET", "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group", Value::Null).await;
    assert_eq!((code, schema["name"].as_str()), (200, Some("Group")), "{schema}");

    let ada = person(&w, &w.entra, "ada@example.com", true).await;
    let al = person(&w, &w.entra, "al@example.com", true).await;
    let bea = person(&w, &w.entra, "bea@example.com", true).await;

    // Entra's create: a team with its first member, who gets a machine.
    let body = json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Engineering", "externalId": "g-eng", "members": [{ "value": ada }] });
    let (code, head, g) = scim(w.port, &w.entra, "POST", GROUPS, body.clone()).await;
    assert_eq!(code, 201, "{g}");
    let team = g["id"].as_str().unwrap().to_string();
    assert_eq!(header(&head, "location"), Some(format!("http://127.0.0.1:{}/scim/v2/Groups/{team}", w.port)));
    assert_eq!((g["displayName"].as_str(), g["externalId"].as_str(), g["members"][0]["value"].as_str()), (Some("Engineering"), Some("g-eng"), Some(ada.as_str())), "{g}");
    assert_eq!(w.app.db.team(&team).unwrap().name, "Engineering");
    assert_eq!(w.app.db.team_member(&ada).unwrap().role, "member", "SCIM never sets team roles");
    let ada_machine = w.app.db.user_machine(&ada).expect("joining gave Ada a machine");
    assert!(w.app.db.team_machine(&ada_machine.id).is_some_and(|t| t.team_id == team));

    // A retry makes no second team.
    let (code, _, err) = scim(w.port, &w.entra, "POST", GROUPS, body).await;
    assert_eq!((code, err["scimType"].as_str()), (409, Some("uniqueness")), "{err}");
    let (code, _, err) = scim(w.port, &w.entra, "POST", GROUPS, json!({ "displayName": "ENGINEERING" })).await;
    assert_eq!(code, 409, "displayName is unique in any case: {err}");
    assert_eq!(w.app.db.teams().len(), 1);

    // Entra looks groups up by name, without members.
    let q = format!("{GROUPS}?filter=displayName%20eq%20%22engineering%22&excludedAttributes=members");
    let (code, _, found) = scim(w.port, &w.entra, "GET", &q, Value::Null).await;
    assert_eq!((code, found["totalResults"].clone(), found["Resources"][0]["id"].as_str()), (200, json!(1), Some(team.as_str())), "{found}");
    assert!(found["Resources"][0].get("members").is_none(), "{found}");
    let (code, _, err) = scim(w.port, &w.entra, "GET", &format!("{GROUPS}?filter=members%20pr"), Value::Null).await;
    assert_eq!((code, err["scimType"].as_str()), (400, Some("invalidFilter")), "{err}");

    // Adding Al, twice, joins him once; he now reaches Ada's shared Bot, and Bea doesn't.
    let path = format!("{GROUPS}/{team}");
    for _ in 0..2 {
        let (code, _, g) = scim(w.port, &w.entra, "PATCH", &path, add(&[&al])).await;
        assert_eq!((code, g["members"].as_array().map(Vec::len)), (200, Some(2)), "{g}");
    }
    let joined: Vec<Value> = events(&w, "team.member_joined").await.into_iter().filter(|e| e["details"]["user"] == al.as_str()).collect();
    assert_eq!(joined.len(), 1, "{joined:?}");
    assert_eq!((joined[0]["details"]["via"].as_str(), joined[0]["actorId"].as_str(), joined[0]["authMethod"].as_str()), (Some("scim"), Some(format!("scim:{}", w.token_id).as_str()), Some("scim_token")));
    let shared = w.app.db.create_bot_owned("Ops", "#fff", "waddle", "claude", None, false, &ada, Visibility::Shared).id;
    let ledger = w.app.db.create_bot_owned("Ledger", "#fff", "waddle", "claude", None, false, &ada, Visibility::Private).id;
    w.app.db.set_grant(&ledger, &al, crate::acl::Grant::Operator, &ada);
    let (al_auth, bea_auth) = (session_for(&w, &al).await, session_for(&w, &bea).await);
    assert_eq!(call(w.port, "GET", &format!("/api/bots/{shared}/messages"), &al_auth, "").await.0, 200);
    assert_eq!(call(w.port, "GET", &format!("/api/bots/{shared}/messages"), &bea_auth, "").await.0, 404);

    // Only the IdP changes who's on the team: not its admins, nor the server's.
    let (code, v) = json_call(&w, "GET", &format!("/api/teams/{team}"), &w.admin, "").await;
    assert_eq!((code, v["scimTenant"].as_str()), (200, Some("entra")), "{v}");
    for (m, p, b) in [
        ("PUT", format!("/api/teams/{team}/members/{bea}"), "{}"),
        ("DELETE", format!("/api/teams/{team}/members/{al}"), ""),
        ("DELETE", format!("/api/teams/{team}"), ""),
        ("PATCH", format!("/api/teams/{team}"), r#"{"name":"Renamed"}"#),
    ] {
        let (code, res) = call(w.port, m, &p, &w.admin, b).await;
        assert_eq!(code, 409, "{m} {p}: {res}");
        assert!(res.contains("identity provider"), "{res}");
    }
    let (code, v) = json_call(&w, "PATCH", &format!("/api/teams/{team}"), &w.admin, r#"{"machines":false}"#).await;
    assert_eq!((code, v["machines"].as_bool()), (200, Some(false)), "{v}");
    w.app.db.update_team(&team, None, Some(true));
    // Server admins choose its owners; an owner manages machines and roles, never members.
    let (code, v) = json_call(&w, "PUT", &format!("/api/teams/{team}/members/{ada}"), &w.admin, r#"{"role":"owner"}"#).await;
    assert_eq!((code, v["role"].as_str()), (200, Some("owner")), "{v}");
    let ada_auth = session_for(&w, &ada).await;
    for (m, p, b) in [
        ("POST", "/api/team/invites".to_string(), r#"{"email":"cy@example.com"}"#),
        ("DELETE", format!("/api/team/members/{al}"), ""),
        ("POST", "/api/team/leave".to_string(), ""),
    ] {
        let (code, res) = call(w.port, m, &p, &ada_auth, b).await;
        assert_eq!(code, 409, "{m} {p}: {res}");
    }
    let (code, v) = json_call(&w, "GET", &format!("/api/team/members/{al}/offboarding"), &ada_auth, "").await;
    assert_eq!((code, v["allowed"].as_bool(), v["blocked"].as_str()), (200, Some(false), Some("scim")), "{v}");

    // Members must be this tenant's users, on no other team; a bad request changes nothing.
    let (stranger, _) = user_with(w.port, &w.admin, "stranger@example.com", "member").await;
    let (code, _, err) = scim(w.port, &w.entra, "PATCH", &path, add(&[&bea, &stranger])).await;
    assert_eq!((code, err["scimType"].as_str()), (400, Some("invalidValue")), "{err}");
    assert_eq!(members(&w, &team), vec![ada.clone(), al.clone()]);
    let (code, _, ops) = scim(w.port, &w.entra, "POST", GROUPS, json!({ "displayName": "Ops", "members": [{ "value": bea }] })).await;
    assert_eq!(code, 201, "{ops}");
    let ops = ops["id"].as_str().unwrap().to_string();
    let (code, _, err) = scim(w.port, &w.entra, "PATCH", &format!("{GROUPS}/{ops}"), add(&[&ada])).await;
    assert_eq!((code, err["scimType"].as_str()), (409, Some("uniqueness")), "{err}");
    assert_eq!((members(&w, &team).len(), members(&w, &ops)), (2, vec![bea.clone()]));

    // Removing Al offboards him as any leaver: grants with teammates go, his team machine is released.
    for _ in 0..2 {
        let (code, _, g) = scim(w.port, &w.entra, "PATCH", &path, remove(&al)).await;
        assert_eq!((code, g["members"].as_array().map(Vec::len)), (200, Some(1)), "{g}");
    }
    assert!(w.app.db.team_member(&al).is_none() && w.app.db.grant(&ledger, &al).is_none());
    let left = events(&w, "team.member_left").await;
    assert_eq!(left.len(), 1, "removed once: {left:?}");
    assert_eq!((left[0]["details"]["user"].as_str(), left[0]["details"]["reason"].as_str()), (Some(al.as_str()), Some("scim_removed")));
    assert!(events(&w, "bot.access_revoked").await.iter().any(|e| e["details"]["user"] == al.as_str() && e["details"]["reason"] == "left_team"));
    assert!(events(&w, "team.machine_released").await.iter().any(|e| e["details"]["user"] == al.as_str()));
    assert_eq!(call(w.port, "GET", &format!("/api/bots/{shared}/messages"), &al_auth, "").await.0, 404, "off the team, Al no longer reaches Ada's shared Bot");

    // The IdP removes even the team's last owner while others remain.
    scim(w.port, &w.entra, "PATCH", &path, add(&[&al])).await;
    let (code, _, g) = scim(w.port, &w.entra, "PATCH", &path, remove(&ada)).await;
    assert_eq!((code, g["members"][0]["value"].as_str()), (200, Some(al.as_str())), "{g}");
    assert!(w.app.db.team_member(&ada).is_none());

    // Okta's rename, with no path; PUT replaces the members; externalId never changes.
    let (code, _, g) = scim(w.port, &w.entra, "PATCH", &path, json!({ "Operations": [{ "op": "replace", "value": { "id": team, "displayName": "Platform" } }] })).await;
    assert_eq!((code, g["displayName"].as_str()), (200, Some("Platform")), "{g}");
    assert_eq!(w.app.db.team(&team).unwrap().name, "Platform");
    let renamed = events(&w, "scim.group_updated").await;
    assert_eq!(renamed[0]["details"]["changes"]["displayName"], json!({ "from": "Engineering", "to": "Platform" }), "{renamed:?}");
    let (code, _, g) = scim(w.port, &w.entra, "PUT", &path, json!({ "displayName": "Platform", "members": [{ "value": ada }] })).await;
    assert_eq!((code, g["externalId"].as_str(), g["members"].as_array().map(Vec::len)), (200, Some("g-eng"), Some(1)), "{g}");
    assert_eq!(members(&w, &team), vec![ada.clone()]);
    let (code, _, err) = scim(w.port, &w.entra, "PATCH", &path, json!({ "Operations": [{ "op": "replace", "path": "externalId", "value": "g-other" }] })).await;
    assert_eq!((code, err["scimType"].as_str()), (400, Some("mutability")), "{err}");

    // Deleting a user takes them off their group's team.
    assert_eq!(scim(w.port, &w.entra, "DELETE", &format!("/scim/v2/Users/{bea}"), Value::Null).await.0, 204);
    assert!(w.app.db.team_member(&bea).is_none());
    assert!(events(&w, "team.member_left").await.iter().any(|e| e["details"]["user"] == bea.as_str() && e["details"]["reason"] == "scim_user_deleted"));

    // Deleting the group offboards everyone and the team goes.
    assert_eq!(scim(w.port, &w.entra, "DELETE", &path, Value::Null).await.0, 204);
    assert!(w.app.db.team(&team).is_none() && w.app.db.team_member(&ada).is_none());
    assert_eq!(scim(w.port, &w.entra, "GET", &path, Value::Null).await.0, 404);
    assert_eq!(scim(w.port, &w.entra, "DELETE", &path, Value::Null).await.0, 404, "deleted once");
    let gone = events(&w, "scim.group_deleted").await;
    assert_eq!((gone[0]["details"]["membersRemoved"].as_u64(), gone[0]["details"]["teamDeleted"].as_bool()), (Some(1), Some(true)), "{gone:?}");
    assert!(events(&w, "team.deleted").await.iter().any(|e| e["targetId"] == team.as_str() && e["details"]["reason"] == "scim"));
    let (_, all) = call(w.port, "GET", "/api/audit?limit=500", &w.admin, "").await;
    assert!(!all.contains(&w.entra), "the token is never logged");
}

#[tokio::test]
async fn a_tenant_sees_and_changes_only_its_own_groups() {
    let w = world(true).await;
    let (okta, _) = token(w.port, &w.admin, "okta").await;
    let ada = person(&w, &w.entra, "ada@example.com", true).await;
    let (_, _, g) = scim(w.port, &w.entra, "POST", GROUPS, json!({ "displayName": "Eng", "members": [{ "value": ada }] })).await;
    let path = format!("{GROUPS}/{}", g["id"].as_str().unwrap());
    let (code, _, list) = scim(w.port, &okta, "GET", GROUPS, Value::Null).await;
    assert_eq!((code, list["totalResults"].clone()), (200, json!(0)), "{list}");
    for (m, b) in [("GET", Value::Null), ("PATCH", remove(&ada)), ("PUT", json!({ "displayName": "Mine" })), ("DELETE", Value::Null)] {
        assert_eq!(scim(w.port, &okta, m, &path, b).await.0, 404, "{m}");
    }
    // Nor can it put another tenant's people on its own groups; the same name is fine.
    let (code, _, err) = scim(w.port, &okta, "POST", GROUPS, json!({ "displayName": "Eng", "members": [{ "value": ada }] })).await;
    assert_eq!((code, err["scimType"].as_str()), (400, Some("invalidValue")), "{err}");
    let (code, _, own) = scim(w.port, &okta, "POST", GROUPS, json!({ "displayName": "Eng" })).await;
    assert_eq!(code, 201, "{own}");
    assert_eq!(w.app.db.team_members(g["id"].as_str().unwrap()).len(), 1);
}

#[tokio::test]
async fn deleting_a_paying_teams_group_removes_everyone_and_keeps_the_team() {
    let w = world(true).await;
    let ada = person(&w, &w.entra, "ada@example.com", true).await;
    let (_, _, g) = scim(w.port, &w.entra, "POST", GROUPS, json!({ "displayName": "Eng", "members": [{ "value": ada }] })).await;
    let team = g["id"].as_str().unwrap().to_string();
    let sub = crate::db::TeamSubscription {
        team_id: team.clone(),
        provider: "stripe".into(),
        customer_id: Some("cus_test_eng".into()),
        subscription_id: "sub_test_eng".into(),
        status: "active".into(),
        price_id: Some("price_test".into()),
        tier: Some("self-host".into()),
        item_id: None,
        quantity: Some(1),
        period_start: None,
        period_end: None,
        cancel_at: None,
        started: 1,
        event_created: 1,
        updated_at: 1,
        paid_by: None,
        seat_tries: 0,
        seat_failures: 0,
        seat_next_at: 0,
        seat_error: None,
    };
    w.app.db.apply_team_subscription("evt_test_eng", "customer.subscription.updated", &sub, true, &|_| vec![]).unwrap();
    assert!(w.app.db.team_paying(&team).is_some());

    assert_eq!(scim(w.port, &w.entra, "DELETE", &format!("{GROUPS}/{team}"), Value::Null).await.0, 204);
    assert!(w.app.db.team_member(&ada).is_none(), "its people lose access at once");
    let kept = w.app.db.team(&team).expect("a team that pays stays until its plan ends");
    assert!(w.app.db.scim_group_of(&kept.id).is_none(), "and is no longer the tenant's");
    assert_eq!(scim(w.port, &w.entra, "GET", &format!("{GROUPS}/{team}"), Value::Null).await.0, 404);
    let gone = events(&w, "scim.group_deleted").await;
    assert_eq!(gone[0]["details"]["teamDeleted"].as_bool(), Some(false), "{gone:?}");
    assert!(events(&w, "team.delete_refused").await.iter().any(|e| e["details"]["reason"] == "team_pays" && e["details"]["via"] == "scim"));
    // A server admin can delete it once it no longer pays, as any team.
    let (code, res) = call(w.port, "DELETE", &format!("/api/teams/{team}"), &w.admin, "").await;
    assert_eq!(code, 409, "still paying: {res}");
    assert!(res.contains("pays for a plan"), "{res}");
}

#[tokio::test]
async fn someone_disabled_joins_without_a_machine_and_gets_it_once_enabled() {
    let w = world(true).await;
    let cy = person(&w, &w.entra, "cy@example.com", false).await;
    let (code, _, g) = scim(w.port, &w.entra, "POST", GROUPS, json!({ "displayName": "Eng", "members": [{ "value": cy }] })).await;
    assert_eq!(code, 201, "{g}");
    assert!(w.app.db.team_member(&cy).is_some() && w.app.db.user_machine(&cy).is_none());
    let on = json!({ "Operations": [{ "op": "replace", "path": "active", "value": true }] });
    assert_eq!(scim(w.port, &w.entra, "PATCH", &format!("/scim/v2/Users/{cy}"), on).await.0, 200);
    let m = w.app.db.user_machine(&cy).expect("enabled, Cy gets the team's machine");
    assert!(w.app.db.team_machine(&m.id).is_some_and(|t| t.team_id == g["id"].as_str().unwrap()));
}
