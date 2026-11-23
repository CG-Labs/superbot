//! SCIM Bulk (ADR 0141) end to end: the real router, each operation through the same
//! handler as a single request, `bulkId` references, `failOnErrors`, the advertised
//! limits, the tenant's rate limit, tenants kept apart, and deprovisioning.

use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::machines::{ControlPlane, State};
use crate::scim_http_tests::{events, is_scim_error, okta_user, scim, session_for, token};
use crate::sso_http_tests::header;
use crate::tests::{call, call_with, serve_app_with};
use crate::users_http_tests::parse;
use crate::*;

const BULK: &str = "/scim/v2/Bulk";
const USERS: &str = "/scim/v2/Users";
const GROUPS: &str = "/scim/v2/Groups";
const REQUEST: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
const RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";

struct World {
    port: u16,
    app: AppState,
    admin: String,
    fake: Arc<Fake>,
}

/// SCIM and its groups on, with the in-memory machine provider.
async fn world(tweak: impl FnOnce(&mut Auth)) -> World {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, admin, _) = serve_app_with(move |a| {
        a.scim.enabled = true;
        a.scim.groups = true;
        a.machines = Arc::new(ControlPlane::for_tests(p));
        tweak(a);
    })
    .await;
    World { port, app, admin, fake }
}

fn req(ops: Value) -> Value {
    json!({ "schemas": [REQUEST], "Operations": ops })
}

async fn bulk(port: u16, token: &str, body: Value) -> (u16, String, Value) {
    scim(port, token, "POST", BULK, body).await
}

/// A bulk request that must be read: 200, with a BulkResponse. Returns its operations.
async fn ran(port: u16, token: &str, body: Value) -> Vec<Value> {
    let (code, head, res) = bulk(port, token, body).await;
    assert_eq!(code, 200, "{res}");
    assert_eq!(header(&head, "content-type").as_deref(), Some("application/scim+json"));
    assert_eq!(res["schemas"], json!([RESPONSE]), "{res}");
    res["Operations"].as_array().unwrap().clone()
}

fn statuses(ops: &[Value]) -> Vec<&str> {
    ops.iter().map(|o| o["status"].as_str().unwrap()).collect()
}

/// The id at the end of a result's location.
fn id_of(op: &Value) -> String {
    op["location"].as_str().unwrap().rsplit('/').next().unwrap().to_string()
}

async fn person(port: u16, token: &str, email: &str, external_id: &str) -> String {
    let (code, _, u) = scim(port, token, "POST", USERS, okta_user(email, external_id)).await;
    assert_eq!(code, 201, "{u}");
    u["id"].as_str().unwrap().to_string()
}

fn deactivate(id: &str) -> Value {
    json!({ "method": "PATCH", "path": format!("/Users/{id}"), "data": { "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{ "op": "replace", "value": { "active": false } }] } })
}

async fn signed_in(port: u16, auth: &str) -> u16 {
    call(port, "GET", "/api/auth/me", auth, "").await.0
}

#[tokio::test]
async fn bulk_runs_each_operation_as_its_single_request_would() {
    let w = world(|_| {}).await;
    let (t, tid) = token(w.port, &w.admin, json!({ "tenant": "okta" })).await;
    let bob = person(w.port, &t, "bob@example.com", "00u2").await;
    let dee = person(w.port, &t, "dee@example.com", "00u3").await;
    let (bob_session, dee_session) = (session_for(w.port, &w.admin, &bob).await, session_for(w.port, &w.admin, &dee).await);
    let mut put = okta_user("bob@example.com", "00u2");
    put["name"]["familyName"] = json!("King");
    put["displayName"] = json!("Bob King");

    // RFC 7644 section 3.7.3's example: create, update, replace, deactivate, delete.
    let ops = ran(
        w.port,
        &t,
        req(json!([
            { "method": "POST", "path": "/Users", "bulkId": "qwerty", "data": okta_user("alice@example.com", "00u1") },
            { "method": "PATCH", "path": "/Users/bulkId:qwerty", "data": { "Operations": [{ "op": "replace", "path": "displayName", "value": "Alice A." }] } },
            { "method": "PUT", "path": format!("/Users/{bob}"), "version": "W/\"3694e05e9dff591\"", "data": put },
            deactivate(&bob),
            { "method": "DELETE", "path": format!("/Users/{dee}") },
        ])),
    )
    .await;
    assert_eq!(statuses(&ops), ["201", "200", "200", "200", "204"], "{ops:?}");
    let alice = id_of(&ops[0]);
    let base = format!("http://127.0.0.1:{}/scim/v2", w.port);
    assert_eq!((ops[0]["method"].as_str(), ops[0]["bulkId"].as_str()), (Some("POST"), Some("qwerty")));
    assert_eq!(ops[0]["location"], format!("{base}/Users/{alice}"));
    assert_eq!(ops[1]["location"], format!("{base}/Users/{alice}"), "the bulkId in the path is the new user");
    assert_eq!(ops[4]["location"], format!("{base}/Users/{dee}"));
    assert!(ops.iter().all(|o| o.get("response").is_none()), "no bodies on success: {ops:?}");

    let a = w.app.db.scim_user("okta", &alice).unwrap();
    assert_eq!((a.user.name.as_str(), a.user.role, a.user.active()), ("Alice A.", rbac::Role::Member, true));
    let b = w.app.db.user(&bob).unwrap();
    assert_eq!((b.name.as_str(), b.active()), ("Bob King", false));
    assert_eq!(signed_in(w.port, &bob_session).await, 401, "deactivating ends every session");
    assert_eq!(signed_in(w.port, &dee_session).await, 401);
    assert!(w.app.db.scim_user("okta", &dee).is_none() && !w.app.db.user(&dee).unwrap().active(), "deleted softly");

    // The same audit trail as single requests, with the token as the actor.
    let actor = format!("scim:{tid}");
    for (action, target) in [("user.created", &alice), ("user.updated", &bob), ("user.disabled", &bob), ("scim.user_deleted", &dee)] {
        let e = events(w.port, &w.admin, &format!("action={action}")).await;
        let e = e.iter().find(|e| e["targetId"] == target.as_str()).unwrap_or_else(|| panic!("{action}: {e:?}"));
        assert_eq!((e["actorId"].as_str(), e["authMethod"].as_str()), (Some(actor.as_str()), Some("scim_token")), "{action}");
    }
    let gone: Vec<(String, String)> = events(w.port, &w.admin, "action=user.deprovisioned").await.iter().map(|e| (e["targetId"].as_str().unwrap().into(), e["details"]["via"].as_str().unwrap().into())).collect();
    assert_eq!(gone, [(dee.clone(), "scim_delete".to_string()), (bob.clone(), "scim".to_string())]);

    let e = &events(w.port, &w.admin, "action=scim.bulk").await[0];
    assert_eq!((e["actorId"].as_str(), e["authMethod"].as_str(), e["outcome"].as_str()), (Some(actor.as_str()), Some("scim_token"), Some("success")));
    let d = &e["details"];
    assert_eq!((d["tenant"].as_str(), d["operations"].clone(), d["run"].clone(), d["failed"].clone(), d["stopped"].clone()), (Some("okta"), json!(5), json!(5), json!(0), Value::Null));
    assert_eq!(d["results"][1], json!({ "method": "PATCH", "path": format!("/Users/{alice}"), "bulkId": null, "status": "200" }));
}

/// RFC 7644 section 3.7.2: new users put in a new group by `bulkId`, even when the
/// group comes first in the request.
#[tokio::test]
async fn bulk_ids_put_new_users_in_new_groups_whatever_the_order() {
    let w = world(|_| {}).await;
    let (t, _) = token(w.port, &w.admin, json!({ "tenant": "okta" })).await;
    let ops = ran(
        w.port,
        &t,
        req(json!([
            { "method": "POST", "path": "/Groups", "bulkId": "guides", "data": { "displayName": "Tour Guides", "members": [{ "type": "User", "value": "bulkId:alice" }] } },
            { "method": "POST", "path": "/Users", "bulkId": "alice", "data": okta_user("alice@example.com", "00u1") },
            { "method": "PATCH", "path": "/Groups/bulkId:guides", "data": { "Operations": [{ "op": "add", "path": "members", "value": [{ "value": "bulkId:bob" }] }] } },
            { "method": "POST", "path": "/Users", "bulkId": "bob", "data": okta_user("bob@example.com", "00u2") },
        ])),
    )
    .await;
    let order: Vec<(&str, Option<&str>, &str)> = ops.iter().map(|o| (o["method"].as_str().unwrap(), o["bulkId"].as_str(), o["status"].as_str().unwrap())).collect();
    assert_eq!(order, [("POST", Some("alice"), "201"), ("POST", Some("guides"), "201"), ("POST", Some("bob"), "201"), ("PATCH", None, "204")], "each POST runs just before the first operation that names it");
    let (alice, team, bob) = (id_of(&ops[0]), id_of(&ops[1]), id_of(&ops[2]));
    assert_eq!(ops[3]["location"].as_str().map(|l| l.ends_with(&format!("/Groups/{team}"))), Some(true));

    let (_, _, g) = scim(w.port, &t, "GET", &format!("{GROUPS}/{team}"), Value::Null).await;
    let mut members: Vec<&str> = g["members"].as_array().unwrap().iter().map(|m| m["value"].as_str().unwrap()).collect();
    members.sort();
    let mut want = vec![alice.as_str(), bob.as_str()];
    want.sort();
    assert_eq!((g["displayName"].as_str(), members), (Some("Tour Guides"), want));
    let on_team: Vec<String> = w.app.db.team_members(&team).into_iter().map(|m| m.user_id).collect();
    assert!(on_team.contains(&alice) && on_team.contains(&bob), "{on_team:?}");
    assert_eq!(events(w.port, &w.admin, "action=scim.group_created").await.len(), 1);
    assert_eq!(events(w.port, &w.admin, "action=team.member_joined").await.len(), 2);
}

/// Only a referenced POST moves: writes after the operation that needs it still run
/// after it. And a reference in a filtered PATCH path is the new id, not the literal.
#[tokio::test]
async fn pulling_a_post_forward_keeps_later_writes_later() {
    let w = world(|_| {}).await;
    let (t, _) = token(w.port, &w.admin, json!({ "tenant": "okta" })).await;
    let carol = person(w.port, &t, "carol@example.com", "00u9").await;
    let (code, _, g) = scim(w.port, &t, "POST", GROUPS, json!({ "displayName": "Eng", "members": [{ "value": carol }] })).await;
    assert_eq!(code, 201, "{g}");
    let team = g["id"].as_str().unwrap().to_string();
    let add = |r: &str| json!({ "Operations": [{ "op": "add", "path": "members", "value": [{ "value": format!("bulkId:{r}") }] }] });
    let ops = ran(
        w.port,
        &t,
        req(json!([
            { "method": "PATCH", "path": format!("/Groups/{team}"), "data": add("u") },
            { "method": "PUT", "path": format!("/Groups/{team}"), "data": { "displayName": "Eng", "members": [] } },
            { "method": "POST", "path": "/Users", "bulkId": "u", "data": okta_user("u@example.com", "00u1") },
        ])),
    )
    .await;
    let order: Vec<(&str, &str)> = ops.iter().map(|o| (o["method"].as_str().unwrap(), o["status"].as_str().unwrap())).collect();
    assert_eq!(order, [("POST", "201"), ("PATCH", "204"), ("PUT", "200")], "{ops:?}");
    let (_, _, g) = scim(w.port, &t, "GET", &format!("{GROUPS}/{team}"), Value::Null).await;
    assert_eq!(g["members"].as_array().map_or(0, Vec::len), 0, "the PUT, sent after the PATCH, still wins: {g}");

    let mut both = add("v");
    both["Operations"].as_array_mut().unwrap().push(json!({ "op": "remove", "path": "members[value eq \"bulkId:v\"]" }));
    let ops = ran(
        w.port,
        &t,
        req(json!([
            { "method": "POST", "path": "/Users", "bulkId": "v", "data": okta_user("v@example.com", "00u2") },
            { "method": "PATCH", "path": format!("/Groups/{team}"), "data": both },
            { "method": "PATCH", "path": format!("/Groups/{team}"), "data": add("v") },
            { "method": "PATCH", "path": format!("/Groups/{team}"), "data": { "Operations": [{ "op": "remove", "path": "members[value eq \"bulkId:v\"]" }] } },
        ])),
    )
    .await;
    assert_eq!(statuses(&ops), ["201", "204", "204", "204"], "{ops:?}");
    let v = id_of(&ops[0]);
    let (_, _, g) = scim(w.port, &t, "GET", &format!("{GROUPS}/{team}"), Value::Null).await;
    assert_eq!(g["members"].as_array().map_or(0, Vec::len), 0, "both filtered removes took {v} out again: {g}");
    assert!(!w.app.db.team_members(&team).iter().any(|m| m.user_id == v));
}

#[tokio::test]
async fn references_to_failed_unknown_or_circular_bulk_ids_are_409() {
    let w = world(|_| {}).await;
    let (t, _) = token(w.port, &w.admin, json!({ "tenant": "okta" })).await;
    person(w.port, &t, "carol@example.com", "00u9").await;
    let ops = ran(
        w.port,
        &t,
        req(json!([
            { "method": "POST", "path": "/Users", "bulkId": "dup", "data": okta_user("carol@example.com", "00u9") },
            { "method": "PATCH", "path": "/Users/bulkId:dup", "data": { "Operations": [{ "op": "replace", "path": "active", "value": false }] } },
            { "method": "POST", "path": "/Users", "bulkId": "c1", "data": { "userName": "c1@example.com", "externalId": "bulkId:c2" } },
            { "method": "POST", "path": "/Users", "bulkId": "c2", "data": { "userName": "c2@example.com", "externalId": "bulkId:c1" } },
            { "method": "DELETE", "path": "/Users/bulkId:nobody" },
            { "method": "POST", "path": "/Users", "bulkId": "ok", "data": okta_user("ok@example.com", "00u8") },
        ])),
    )
    .await;
    let order: Vec<(Option<&str>, &str)> = ops.iter().map(|o| (o["bulkId"].as_str(), o["status"].as_str().unwrap())).collect();
    assert_eq!(order, [(Some("dup"), "409"), (None, "409"), (Some("c2"), "409"), (Some("c1"), "409"), (None, "409"), (Some("ok"), "201")], "{ops:?}");
    assert_eq!(ops[0]["response"]["scimType"], "uniqueness", "the handler's own error");
    assert!(ops[0].get("location").is_none(), "a failed POST has no location");
    for (i, says) in [(1, "failed"), (2, "circular"), (3, "circular"), (4, "isn't the bulkId of a POST")] {
        let r = &ops[i]["response"];
        assert_eq!((r["schemas"].clone(), r["status"].as_str()), (json!(["urn:ietf:params:scim:api:messages:2.0:Error"]), Some("409")));
        assert!(r["detail"].as_str().unwrap().contains(says), "{i}: {r}");
    }
    for name in ["c1@example.com", "c2@example.com"] {
        assert!(w.app.db.scim_find("okta", &db::ScimKey::UserName(name.into())).is_none(), "{name} never ran");
    }
    let e = &events(w.port, &w.admin, "action=scim.bulk").await[0];
    assert_eq!((e["outcome"].as_str(), e["details"]["failed"].clone(), e["details"]["run"].clone()), (Some("failure"), json!(5), json!(6)));
}

#[tokio::test]
async fn fail_on_errors_stops_after_that_many_failures() {
    let w = world(|_| {}).await;
    let (t, _) = token(w.port, &w.admin, json!({ "tenant": "okta" })).await;
    person(w.port, &t, "ada@example.com", "00u1").await;
    let exists = |name: &str| w.app.db.scim_find("okta", &db::ScimKey::UserName(name.into())).is_some();
    for (round, fail_on, want) in [(1, json!(1), vec!["409"]), (2, json!(2), vec!["409", "201", "404"]), (3, Value::Null, vec!["409", "201", "404", "201"])] {
        let (first, second) = (format!("first{round}@example.com"), format!("second{round}@example.com"));
        let mut body = req(json!([
            { "method": "POST", "path": "/Users", "bulkId": "again", "data": okta_user("ada@example.com", "00u1") },
            { "method": "POST", "path": "/Users", "bulkId": "a", "data": okta_user(&first, &format!("f{round}")) },
            { "method": "DELETE", "path": "/Users/nobody" },
            { "method": "POST", "path": "/Users", "bulkId": "b", "data": okta_user(&second, &format!("s{round}")) },
        ]));
        if !fail_on.is_null() {
            body["failOnErrors"] = fail_on.clone();
        }
        let ops = ran(w.port, &t, body).await;
        assert_eq!(statuses(&ops), want, "round {round}");
        assert_eq!((exists(&first), exists(&second)), (round >= 2, round == 3), "round {round}: nothing after the stop runs");
        let d = &events(w.port, &w.admin, "action=scim.bulk").await[0]["details"];
        assert_eq!((d["failOnErrors"].clone(), d["run"].clone()), (fail_on.clone(), json!(want.len())));
        assert_eq!(d["stopped"].as_str(), (round < 3).then_some("failOnErrors"), "round {round}");
    }
}

#[tokio::test]
async fn limits_are_advertised_and_enforced() {
    let w = world(|_| {}).await;
    let (t, _) = token(w.port, &w.admin, json!({ "tenant": "okta" })).await;
    let (_, _, spc) = scim(w.port, &t, "GET", "/scim/v2/ServiceProviderConfig", Value::Null).await;
    assert_eq!(spc["bulk"], json!({ "supported": true, "maxOperations": 100, "maxPayloadSize": 1048576 }));
    assert_eq!((scim::bulk::MAX_OPERATIONS, scim::bulk::MAX_PAYLOAD), (100, 1048576));
    let users = || async { scim(w.port, &t, "GET", USERS, Value::Null).await.2["totalResults"].clone() };

    // More operations than maxOperations: 413, naming the limit, and nothing runs.
    let many: Vec<Value> = (0..=100).map(|i| json!({ "method": "POST", "path": "/Users", "bulkId": format!("b{i}"), "data": { "userName": format!("u{i}@example.com") } })).collect();
    let (code, head, body) = bulk(w.port, &t, req(json!(many))).await;
    assert_eq!(code, 413);
    is_scim_error(&head, &body, 413);
    assert!(body["detail"].as_str().unwrap().contains("maxOperations (100)"), "{body}");
    assert_eq!(users().await, 0);
    // maxOperations itself is fine.
    let deletes: Vec<Value> = (0..100).map(|i| json!({ "method": "DELETE", "path": format!("/Users/missing-{i}") })).collect();
    let ops = ran(w.port, &t, req(json!(deletes))).await;
    assert!(ops.len() == 100 && ops.iter().all(|o| o["status"] == "404"), "{:?}", statuses(&ops));

    // A body over maxPayloadSize: 413, naming the limit.
    let huge = req(json!([{ "method": "POST", "path": "/Users", "bulkId": "x", "data": { "userName": "x@example.com", "title": "t".repeat(scim::bulk::MAX_PAYLOAD) } }])).to_string();
    let (code, head, body) = call_with(w.port, "POST", BULK, &format!("Bearer {t}"), "", &huge).await;
    assert_eq!(code, 413);
    let body = parse(&body);
    is_scim_error(&head, &body, 413);
    assert_eq!(body["detail"], "The size of the bulk operation exceeds the maxPayloadSize (1048576).");
    assert_eq!(users().await, 0);

    // Each operation keeps its endpoint's own limit: 64 KiB for a user, 1 MiB for a group.
    let big_user = json!({ "userName": "big@example.com", "title": "t".repeat(scim::MAX_BODY) });
    let big_group = json!({ "displayName": "Big", "members": (0..1200).map(|i| json!({ "value": format!("{i:064}") })).collect::<Vec<_>>() });
    assert!(big_group.to_string().len() > scim::MAX_BODY);
    let ops = ran(w.port, &t, req(json!([{ "method": "POST", "path": "/Users", "bulkId": "u", "data": big_user }, { "method": "POST", "path": "/Groups", "bulkId": "g", "data": big_group }]))).await;
    assert_eq!(statuses(&ops), ["413", "400"], "{ops:?}");
    assert!(ops[1]["response"]["detail"].as_str().unwrap().contains("isn't a user this tenant provisioned"), "the group's own check ran");

    // A malformed operation anywhere refuses the whole request before anything runs.
    let ok = json!({ "method": "POST", "path": "/Users", "bulkId": "ok", "data": okta_user("ok@example.com", "00u1") });
    for (bad, scim_type) in [
        (req(json!([ok.clone(), { "method": "GET", "path": "/Users" }])), "invalidSyntax"),
        (req(json!([ok.clone(), { "method": "POST", "path": "/Users", "data": {} }])), "invalidValue"),
        (req(json!([ok.clone(), { "method": "POST", "path": "/Users", "bulkId": "ok", "data": {} }])), "invalidValue"),
        (req(json!([ok.clone(), { "method": "PATCH", "path": "/Users" , "data": {} }])), "invalidPath"),
        (req(json!([ok.clone(), { "method": "POST", "path": "/Bulk", "bulkId": "b", "data": {} }])), "invalidPath"),
        (req(json!([ok.clone(), { "method": "PUT", "path": "/Users/x" }])), "invalidSyntax"),
        (json!({ "schemas": [REQUEST], "failOnErrors": 0, "Operations": [ok.clone()] }), "invalidValue"),
        (json!({ "schemas": [REQUEST], "Operations": [] }), "invalidSyntax"),
        (json!({ "schemas": [REQUEST], "Operations": [ok.clone()], "operations": [] }), "invalidValue"),
    ] {
        let (code, head, body) = bulk(w.port, &t, bad.clone()).await;
        assert_eq!((code, body["scimType"].as_str()), (400, Some(scim_type)), "{bad}: {body}");
        is_scim_error(&head, &body, 400);
    }
    let (code, _, body) = call_with(w.port, "POST", BULK, &format!("Bearer {t}"), "", "{not json").await;
    assert_eq!((code, parse(&body)["scimType"].as_str()), (400, Some("invalidSyntax")));
    assert_eq!(users().await, 0, "none of them ran");
    assert!(events(w.port, &w.admin, "action=user.created&method=scim_token").await.is_empty());

    // Only a SCIM token, as everywhere under /scim/v2.
    let body = req(json!([ok])).to_string();
    assert_eq!(call_with(w.port, "POST", BULK, "", "", &body).await.0, 401);
    assert_eq!(call_with(w.port, "POST", BULK, &w.admin, "", &body).await.0, 401);
    assert_eq!(users().await, 0);
}

#[tokio::test]
async fn bulk_operations_count_against_the_tenants_rate_limit() {
    let w = world(|a| a.scim.limiter = users::Limiter::new(3, 60_000)).await;
    let (a, _) = token(w.port, &w.admin, json!({ "tenant": "a" })).await;
    let (b, _) = token(w.port, &w.admin, json!({ "tenant": "b" })).await;
    let posts: Vec<Value> = (0..5).map(|i| json!({ "method": "POST", "path": "/Users", "bulkId": format!("p{i}"), "data": okta_user(&format!("p{i}@example.com"), &format!("x{i}")) })).collect();
    let ops = ran(w.port, &a, req(json!(posts))).await;
    assert_eq!(statuses(&ops), ["201", "201", "201", "429"], "the request and two more, then stop");
    assert!(ops[3]["response"]["detail"].as_str().unwrap().contains("seconds"), "{}", ops[3]);
    assert!(w.app.db.scim_find("a", &db::ScimKey::UserName("p4@example.com".into())).is_none(), "the rest never ran");
    let d = &events(w.port, &w.admin, "action=scim.bulk").await[0]["details"];
    assert_eq!((d["stopped"].as_str(), d["run"].clone(), d["failed"].clone()), (Some("rateLimited"), json!(4), json!(1)));
    let (code, head, _) = bulk(w.port, &a, req(json!([{ "method": "DELETE", "path": "/Users/x" }]))).await;
    assert_eq!((code, header(&head, "retry-after").is_some()), (429, true), "the tenant is over its limit");
    assert_eq!(statuses(&ran(w.port, &b, req(json!([{ "method": "DELETE", "path": "/Users/x" }]))).await), ["404"], "other tenants aren't slowed");
    assert!(events(w.port, &w.admin, "action=scim.request_failed").await.is_empty(), "a 429 isn't a failed request, in Bulk or not");
}

#[tokio::test]
async fn tenants_stay_apart_in_bulk() {
    let w = world(|_| {}).await;
    let (a, _) = token(w.port, &w.admin, json!({ "tenant": "a" })).await;
    let (b, b_id) = token(w.port, &w.admin, json!({ "tenant": "b" })).await;
    let ada = person(w.port, &a, "ada@example.com", "x1").await;
    let (code, _, g) = scim(w.port, &a, "POST", GROUPS, json!({ "displayName": "Eng", "members": [{ "value": ada }] })).await;
    assert_eq!(code, 201, "{g}");
    let eng = g["id"].as_str().unwrap().to_string();
    let session = session_for(w.port, &w.admin, &ada).await;

    // Tenant b names a's user and group directly: each operation is 404 or refused.
    let ops = ran(
        w.port,
        &b,
        req(json!([
            { "method": "PUT", "path": format!("/Users/{ada}"), "data": okta_user("ada@example.com", "x1") },
            deactivate(&ada),
            { "method": "DELETE", "path": format!("/Users/{ada}") },
            { "method": "POST", "path": "/Groups", "bulkId": "mine", "data": { "displayName": "Takeover", "members": [{ "value": ada }] } },
            { "method": "PATCH", "path": format!("/Groups/{eng}"), "data": { "Operations": [{ "op": "remove", "path": "members" }] } },
            { "method": "PUT", "path": format!("/Groups/{eng}"), "data": { "displayName": "Eng", "members": [] } },
            { "method": "DELETE", "path": format!("/Groups/{eng}") },
            { "method": "POST", "path": "/Users", "bulkId": "same", "data": okta_user("ada@example.com", "x1") },
        ])),
    )
    .await;
    assert_eq!(statuses(&ops), ["404", "404", "404", "400", "404", "404", "404", "409"], "{ops:?}");
    assert_eq!(ops[7]["response"]["scimType"], "uniqueness", "email is never the key");

    // Nothing of a's changed, and nothing was done to Ada.
    let kept = w.app.db.scim_user("a", &ada).expect("still a's");
    assert!(kept.user.active());
    assert_eq!(signed_in(w.port, &session).await, 200);
    assert_eq!(w.app.db.team_id_of(&ada).as_deref(), Some(eng.as_str()));
    assert_eq!(scim(w.port, &b, "GET", GROUPS, Value::Null).await.2["totalResults"], 0, "b made no group");
    for action in ["user.disabled", "user.updated", "scim.user_deleted", "user.deprovisioned", "scim.group_deleted", "scim.group_updated", "team.member_left"] {
        assert!(events(w.port, &w.admin, &format!("action={action}")).await.is_empty(), "{action}");
    }
    let e = &events(w.port, &w.admin, "action=scim.bulk").await[0];
    assert_eq!((e["actorId"].as_str(), e["details"]["tenant"].as_str(), e["details"]["failed"].clone()), (Some(format!("scim:{b_id}").as_str()), Some("b"), json!(8)));
    // Each failed operation is a failed SCIM request for the health score, as on its own; 404s aren't.
    let mut failed: Vec<(Option<&str>, Option<u64>, Option<&str>, Option<&str>)> = Vec::new();
    let list = events(w.port, &w.admin, "action=scim.request_failed").await;
    for e in &list {
        assert_eq!((e["actorId"].as_str(), e["details"]["tenant"].as_str()), (Some(format!("scim:{b_id}").as_str()), Some("b")), "{e}");
        failed.push((e["details"]["method"].as_str(), e["details"]["status"].as_u64(), e["details"]["resource"].as_str(), (e["details"]["status"] == 409).then(|| e["details"]["reason"].as_str()).flatten()));
    }
    failed.sort();
    assert_eq!(failed, [(Some("POST"), Some(400), Some("Groups"), None), (Some("POST"), Some(409), Some("Users"), Some("uniqueness"))], "{list:#?}");

    // bulkIds live only in their own request: b can't reach what a's request made.
    let made = ran(w.port, &a, req(json!([{ "method": "POST", "path": "/Users", "bulkId": "new", "data": okta_user("new@example.com", "x2") }]))).await;
    let new = id_of(&made[0]);
    let ops = ran(w.port, &b, req(json!([deactivate("bulkId:new"), deactivate(&new)]))).await;
    assert_eq!(statuses(&ops), ["409", "404"]);
    assert!(w.app.db.user(&new).unwrap().active());
}

#[tokio::test]
async fn bulk_deprovisioning_suspends_and_resumes_the_machine() {
    let w = world(|_| {}).await;
    let (t, _) = token(w.port, &w.admin, json!({ "tenant": "okta" })).await;
    let ops = ran(w.port, &t, req(json!([{ "method": "POST", "path": "/Users", "bulkId": "ada", "data": okta_user("ada@example.com", "00u1") }]))).await;
    let ada = id_of(&ops[0]);
    let (code, m) = call(w.port, "POST", &format!("/api/users/{ada}/machine"), &w.admin, "").await;
    assert_eq!(code, 202, "{m}");
    assert_eq!(call(w.port, "POST", "/api/machines/reconcile", &w.admin, "").await.0, 200);
    let m = w.app.db.user_machine(&ada).unwrap();
    assert_eq!(m.state, State::Running);

    assert_eq!(statuses(&ran(w.port, &t, req(json!([deactivate(&ada)]))).await), ["200"]);
    assert_eq!(w.app.db.machine(&m.id).unwrap().state, State::Suspended);
    assert_eq!(w.fake.calls("shutdown"), 1);
    let d = &events(w.port, &w.admin, "action=user.deprovisioned").await[0];
    assert_eq!((d["details"]["via"].as_str(), d["details"]["machine"].clone()), (Some("scim"), json!({ "id": m.id, "state": "suspended" })));
    assert!(d["actorId"].as_str().unwrap().starts_with("scim:"), "{d}");

    let on = json!({ "method": "PATCH", "path": format!("/Users/{ada}"), "data": { "Operations": [{ "op": "replace", "path": "active", "value": true }] } });
    assert_eq!(statuses(&ran(w.port, &t, req(json!([on]))).await), ["200"]);
    assert_eq!(w.app.db.machine(&m.id).unwrap().state, State::Running, "enabling resumes what the disable suspended");

    assert_eq!(statuses(&ran(w.port, &t, req(json!([{ "method": "DELETE", "path": format!("/Users/{ada}") }]))).await), ["204"]);
    assert_eq!(w.app.db.machine(&m.id).unwrap().state, State::Suspended);
    assert_eq!(events(w.port, &w.admin, "action=user.deprovisioned").await[0]["details"]["via"], "scim_delete");
}

#[tokio::test]
async fn group_operations_follow_scim_groups() {
    let w = world(|a| a.scim.groups = false).await;
    let (t, _) = token(w.port, &w.admin, json!({ "tenant": "okta" })).await;
    let ops = ran(
        w.port,
        &t,
        req(json!([
            { "method": "POST", "path": "/Users", "bulkId": "u", "data": okta_user("ada@example.com", "00u1") },
            { "method": "POST", "path": "/Groups", "bulkId": "g", "data": { "displayName": "Eng", "members": [{ "value": "bulkId:u" }] } },
        ])),
    )
    .await;
    assert_eq!(statuses(&ops), ["201", "501"], "groups off: the same 501 as POST /Groups");
    assert!(ops[1]["response"]["detail"].as_str().unwrap().contains("SCIM_GROUPS=on"));
}
