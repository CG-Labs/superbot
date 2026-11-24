//! SCIM token scopes (ADR 0224) end to end: the real router, every SCIM route under each
//! scope, Bulk's operations one by one, rotation, and tokens made before scopes.

use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::scim_http_tests::{events, is_scim_error, okta_user, scim, token};
use crate::sso_http_tests::header;
use crate::tests::{call, serve_app_with};
use crate::users_http_tests::parse;
use crate::*;

const USERS: &str = "/scim/v2/Users";
const GROUPS: &str = "/scim/v2/Groups";
const BULK: &str = "/scim/v2/Bulk";
const PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ALL: [&str; 4] = ["users:read", "users:write", "groups:read", "groups:write"];

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

async fn listed(port: u16, admin: &str, id: &str) -> Value {
    let (code, body) = call(port, "GET", "/api/scim/tokens", admin, "").await;
    assert_eq!(code, 200, "{body}");
    parse(&body)["tokens"].as_array().unwrap().iter().find(|t| t["id"] == id).cloned().unwrap_or_else(|| panic!("no {id}"))
}

fn deactivate() -> Value {
    json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "replace", "value": { "active": false } }] })
}

/// A 403 for a scope the token lacks: a SCIM error, RFC 6750's challenge naming the scope,
/// and `scim.request_failed` saying which.
async fn refused(port: u16, admin: &str, head: &str, body: &Value, scope: &str) {
    is_scim_error(head, body, 403);
    assert!(body.get("scimType").is_none(), "{body}");
    assert!(body["detail"].as_str().unwrap().contains(scope), "{body}");
    let challenge = header(head, "www-authenticate").unwrap_or_default();
    assert!(challenge.contains("error=\"insufficient_scope\"") && challenge.contains(&format!("scope=\"{scope}\"")), "{challenge}");
    let e = &events(port, admin, "action=scim.request_failed").await[0];
    assert_eq!((e["details"]["reason"].as_str(), e["details"]["scope"].as_str(), e["details"]["status"].as_u64()), (Some("insufficient_scope"), Some(scope), Some(403)), "{e:#}");
}

#[tokio::test]
async fn tokens_have_every_scope_unless_told_otherwise() {
    let (port, _, admin) = serve().await;
    let (_, full) = token(port, &admin, json!({ "tenant": "okta" })).await;
    assert_eq!(listed(port, &admin, &full).await["scopes"], json!(ALL));
    let (_, users) = token(port, &admin, json!({ "tenant": "okta", "scopes": ["users:write"] })).await;
    assert_eq!(listed(port, &admin, &users).await["scopes"], json!(["users:read", "users:write"]), "a write scope brings its read");
    let made = &events(port, &admin, "action=scim.token_created").await[0];
    assert_eq!((made["targetId"].as_str(), &made["details"]["scopes"]), (Some(users.as_str()), &json!(["users:read", "users:write"])), "{made:#}");
    let (_, list) = call(port, "GET", "/api/scim/tokens", &admin, "").await;
    assert_eq!(parse(&list)["scopes"], json!(ALL), "the scopes there are");

    for bad in [json!([]), json!("users:write"), json!(["users"]), json!(["admin"]), json!(["users:write", "teams:write"]), json!([1])] {
        let (code, body) = call(port, "POST", "/api/scim/tokens", &admin, &json!({ "tenant": "okta", "scopes": bad }).to_string()).await;
        assert_eq!(code, 400, "{bad}: {body}");
    }
    assert_eq!(events(port, &admin, "action=scim.token_created").await.len(), 2, "a refused one makes nothing");
}

#[tokio::test]
async fn a_users_only_token_never_touches_groups() {
    let (port, _, admin) = serve().await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta", "scopes": ["users:write"] })).await;
    let (code, _, u) = scim(port, &t, "POST", USERS, okta_user("ada@example.com", "00u1")).await;
    assert_eq!(code, 201, "{u}");
    let id = u["id"].as_str().unwrap();
    for path in ["/scim/v2/ServiceProviderConfig", "/scim/v2/ResourceTypes", "/scim/v2/ResourceTypes/Group", "/scim/v2/Schemas"] {
        assert_eq!(scim(port, &t, "GET", path, Value::Null).await.0, 200, "discovery is open: {path}");
    }

    let (code, head, body) = scim(port, &t, "GET", GROUPS, Value::Null).await;
    assert_eq!(code, 403);
    refused(port, &admin, &head, &body, "groups:read").await;
    let group = json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Eng", "members": [{ "value": id }] });
    let (code, head, body) = scim(port, &t, "POST", GROUPS, group.clone()).await;
    assert_eq!(code, 403);
    refused(port, &admin, &head, &body, "groups:write").await;
    assert!(events(port, &admin, "action=scim.group_created").await.is_empty());

    let (full, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let (code, _, list) = scim(port, &full, "GET", GROUPS, Value::Null).await;
    assert_eq!((code, list["totalResults"].as_i64()), (200, Some(0)), "no team was made: {list}");
    let (code, _, g) = scim(port, &full, "POST", GROUPS, group).await;
    assert_eq!(code, 201, "{g}");
    let gid = g["id"].as_str().unwrap();
    for (method, body) in [("PATCH", json!({ "schemas": [PATCH_OP], "Operations": [{ "op": "remove", "path": "members" }] })), ("PUT", json!({ "displayName": "Eng", "members": [] })), ("DELETE", Value::Null)] {
        let (code, _, res) = scim(port, &t, method, &format!("{GROUPS}/{gid}"), body).await;
        assert_eq!(code, 403, "{method}: {res}");
    }
    let (_, _, g) = scim(port, &full, "GET", &format!("{GROUPS}/{gid}"), Value::Null).await;
    assert_eq!(g["members"].as_array().map(Vec::len), Some(1), "untouched: {g}");
}

#[tokio::test]
async fn a_read_only_token_can_look_but_never_deprovision() {
    let (port, _, admin) = serve().await;
    let (full, _) = token(port, &admin, json!({ "tenant": "entra" })).await;
    let (read, read_id) = token(port, &admin, json!({ "tenant": "entra", "scopes": ["users:read", "groups:read"] })).await;
    let (_, _, u) = scim(port, &full, "POST", USERS, okta_user("ada@example.com", "00u1")).await;
    let id = u["id"].as_str().unwrap();
    let at = format!("{USERS}/{id}");

    let (code, _, list) = scim(port, &read, "GET", &format!("{USERS}?filter=userName%20eq%20%22ada@example.com%22"), Value::Null).await;
    assert_eq!((code, list["totalResults"].as_i64()), (200, Some(1)), "{list}");
    assert_eq!(scim(port, &read, "GET", &at, Value::Null).await.0, 200);
    assert_eq!(scim(port, &read, "GET", GROUPS, Value::Null).await.0, 200);

    let (code, head, body) = scim(port, &read, "PATCH", &at, deactivate()).await;
    assert_eq!(code, 403);
    refused(port, &admin, &head, &body, "users:write").await;
    let e = &events(port, &admin, "action=scim.request_failed").await[0];
    assert_eq!((e["actorId"].as_str(), e["details"]["method"].as_str(), e["details"]["resource"].as_str()), (Some(format!("scim:{read_id}").as_str()), Some("PATCH"), Some("Users")), "{e:#}");
    for (method, body) in [("PUT", okta_user("ada@example.com", "00u1")), ("DELETE", Value::Null)] {
        assert_eq!(scim(port, &read, method, &at, body).await.0, 403, "{method}");
    }
    assert_eq!(scim(port, &read, "POST", USERS, okta_user("bob@example.com", "00u2")).await.0, 403);
    let (_, _, u) = scim(port, &full, "GET", &at, Value::Null).await;
    assert_eq!(u["active"], json!(true), "still active: {u}");
    assert!(events(port, &admin, "action=user.disabled").await.is_empty());
    assert_eq!(scim(port, &full, "GET", &format!("{USERS}?filter=userName%20eq%20%22bob@example.com%22"), Value::Null).await.2["totalResults"], json!(0));
}

#[tokio::test]
async fn bulk_checks_each_operation_against_the_scopes() {
    let (port, _, admin) = serve().await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta", "scopes": ["users:write"] })).await;
    let ops = json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [
        { "method": "POST", "path": "/Users", "bulkId": "ada", "data": okta_user("ada@example.com", "00u1") },
        { "method": "POST", "path": "/Groups", "bulkId": "eng", "data": { "displayName": "Eng", "members": [{ "value": "bulkId:ada" }] } },
        { "method": "PATCH", "path": "/Groups/bulkId:eng", "data": { "schemas": [PATCH_OP], "Operations": [] } },
    ] });
    let (code, _, res) = scim(port, &t, "POST", BULK, ops.clone()).await;
    assert_eq!(code, 200, "{res}");
    let statuses: Vec<&str> = res["Operations"].as_array().unwrap().iter().map(|o| o["status"].as_str().unwrap()).collect();
    assert_eq!(statuses, ["201", "403", "403"], "the scope is checked before an unresolved bulkId: {res:#}");
    let group = &res["Operations"][1]["response"];
    assert!(group["detail"].as_str().unwrap().contains("groups:write"), "{group}");
    let failed = events(port, &admin, "action=scim.request_failed").await;
    assert_eq!(failed.len(), 2, "each refused operation is audited as its own request would be");
    assert!(failed.iter().all(|e| e["details"]["reason"] == "insufficient_scope" && e["details"]["scope"] == "groups:write" && e["details"]["resource"] == "Groups"), "{failed:#?}");
    assert!(events(port, &admin, "action=scim.group_created").await.is_empty());
    let bulk = &events(port, &admin, "action=scim.bulk").await[0];
    assert_eq!((bulk["details"]["failed"].as_u64(), bulk["outcome"].as_str()), (Some(2), Some("failure")), "{bulk:#}");

    let (read, _) = token(port, &admin, json!({ "tenant": "okta", "scopes": ["users:read", "groups:read"] })).await;
    let (_, _, u) = scim(port, &read, "GET", &format!("{USERS}?filter=userName%20eq%20%22ada@example.com%22"), Value::Null).await;
    let id = u["Resources"][0]["id"].as_str().unwrap().to_string();
    let off = json!({ "Operations": [{ "method": "PATCH", "path": format!("/Users/{id}"), "data": deactivate() }, { "method": "DELETE", "path": format!("/Users/{id}") }] });
    let (code, _, res) = scim(port, &read, "POST", BULK, off).await;
    assert_eq!(code, 200, "{res}");
    assert!(res["Operations"].as_array().unwrap().iter().all(|o| o["status"] == "403"), "{res:#}");
    assert!(events(port, &admin, "action=user.disabled").await.is_empty(), "Bulk is no way round a read-only token");
}

/// Every SCIM route, called by a token with each single scope: refused (403) exactly when
/// the route's resource and access aren't in its scopes, and never for discovery or Bulk
/// itself. A route added without a scope shows up here.
#[tokio::test]
async fn every_route_needs_the_scope_of_what_it_reaches() {
    let (port, _, admin) = serve().await;
    let routes: [(&str, &str, Option<&str>); 18] = [
        ("GET", "/scim/v2/ServiceProviderConfig", None),
        ("GET", "/scim/v2/ResourceTypes", None),
        ("GET", "/scim/v2/ResourceTypes/User", None),
        ("GET", "/scim/v2/Schemas", None),
        ("GET", "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", None),
        ("POST", BULK, None),
        ("GET", USERS, Some("users:read")),
        ("POST", USERS, Some("users:write")),
        ("GET", "/scim/v2/Users/x", Some("users:read")),
        ("PUT", "/scim/v2/Users/x", Some("users:write")),
        ("PATCH", "/scim/v2/Users/x", Some("users:write")),
        ("DELETE", "/scim/v2/Users/x", Some("users:write")),
        ("GET", GROUPS, Some("groups:read")),
        ("POST", GROUPS, Some("groups:write")),
        ("GET", "/scim/v2/Groups/x", Some("groups:read")),
        ("PUT", "/scim/v2/Groups/x", Some("groups:write")),
        ("PATCH", "/scim/v2/Groups/x", Some("groups:write")),
        ("DELETE", "/scim/v2/Groups/x", Some("groups:write")),
    ];
    for scope in ALL {
        let (t, _) = token(port, &admin, json!({ "tenant": "okta", "scopes": [scope] })).await;
        let resource = scope.split(':').next().unwrap();
        for (method, path, need) in routes {
            let body = if method == "GET" || method == "DELETE" { Value::Null } else { json!({}) };
            let (code, head, res) = scim(port, &t, method, path, body).await;
            let allowed = need.is_none_or(|n| n == scope || (scope.ends_with(":write") && n == format!("{resource}:read")));
            assert_eq!(code == 403, !allowed, "{scope} {method} {path}: {code} {res}");
            if !allowed {
                assert!(header(&head, "www-authenticate").unwrap_or_default().contains(need.unwrap()), "{scope} {method} {path}: {head}");
            }
            assert_ne!(code, 401, "{scope} {method} {path}");
        }
        for (method, path) in [("GET", "/scim/v2/users"), ("GET", "/scim/v2//Groups"), ("POST", "/scim/v2/GROUPS/x/y")] {
            let (code, _, res) = scim(port, &t, method, path, Value::Null).await;
            assert!(code == 403 || code == 404, "{scope} {method} {path}: {code} {res}");
        }
        for path in ["/scim/v2", "/scim/v2/Me", "/scim/v2/bulk"] {
            assert_eq!(scim(port, &t, "GET", path, Value::Null).await.0, 403, "a path with no scope is for full tokens only: {scope} {path}");
        }
    }
    let (full, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    for path in ["/scim/v2", "/scim/v2/Me", "/scim/v2/bulk"] {
        assert_eq!(scim(port, &full, "GET", path, Value::Null).await.0, 404, "{path}");
    }
}

#[tokio::test]
async fn rotation_keeps_the_scopes_unless_told_and_audits_a_change() {
    let (port, _, admin) = serve().await;
    let (_, id) = token(port, &admin, json!({ "tenant": "okta", "scopes": ["users:write"] })).await;
    let rotate = |id: String, body: Value| {
        let admin = admin.clone();
        async move {
            let (code, res) = call(port, "POST", &format!("/api/scim/tokens/{id}/rotate"), &admin, &body.to_string()).await;
            (code, parse(&res))
        }
    };
    for bad in [json!([]), json!(["groups:admin"])] {
        let (code, res) = rotate(id.clone(), json!({ "scopes": bad })).await;
        assert_eq!(code, 400, "{res}");
    }
    assert_eq!(listed(port, &admin, &id).await["state"], "active", "a refused rotation changes nothing");

    let (code, res) = rotate(id.clone(), json!({ "keepOldHours": 0 })).await;
    assert_eq!(code, 201, "{res}");
    assert_eq!(res["scimToken"]["scopes"], json!(["users:read", "users:write"]));
    let e = &events(port, &admin, "action=scim.token_rotated").await[0];
    assert_eq!((&e["details"]["scopes"], e["details"].get("oldScopes")), (&json!(["users:read", "users:write"]), None), "{e:#}");

    let next = res["scimToken"]["id"].as_str().unwrap().to_string();
    let (code, res) = rotate(next.clone(), json!({ "keepOldHours": 0, "scopes": ["users:read"] })).await;
    assert_eq!(code, 201, "{res}");
    let (new, new_id) = (res["token"].as_str().unwrap().to_string(), res["scimToken"]["id"].as_str().unwrap().to_string());
    assert_eq!(listed(port, &admin, &new_id).await["scopes"], json!(["users:read"]));
    let e = &events(port, &admin, "action=scim.token_rotated").await[0];
    assert_eq!((&e["details"]["scopes"], &e["details"]["oldScopes"]), (&json!(["users:read"]), &json!(["users:read", "users:write"])), "{e:#}");
    assert_eq!(scim(port, &new, "GET", USERS, Value::Null).await.0, 200);
    assert_eq!(scim(port, &new, "POST", USERS, okta_user("ada@example.com", "00u1")).await.0, 403, "narrowed");
}

/// Tokens made before scopes have all four, so upgrading changes nothing an IdP can do;
/// scopes stored that this version doesn't know grant nothing.
#[tokio::test]
async fn tokens_from_before_scopes_keep_every_scope_and_unknown_ones_grant_nothing() {
    let (port, app, admin) = serve().await;
    let (t, id) = token(port, &admin, json!({ "tenant": "okta", "scopes": ["users:read"] })).await;
    app.db.set_scim_token_scopes(&id, None);
    assert_eq!(listed(port, &admin, &id).await["scopes"], json!(ALL));
    assert_eq!(scim(port, &t, "POST", USERS, okta_user("ada@example.com", "00u1")).await.0, 201);
    assert_eq!(scim(port, &t, "GET", GROUPS, Value::Null).await.0, 200);

    app.db.set_scim_token_scopes(&id, Some(r#"["teams:write"]"#));
    assert_eq!(listed(port, &admin, &id).await["scopes"], json!([]));
    let (code, _, body) = scim(port, &t, "GET", USERS, Value::Null).await;
    assert_eq!(code, 403, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("(none)"), "{body}");
    assert_eq!(scim(port, &t, "GET", "/scim/v2/ServiceProviderConfig", Value::Null).await.0, 200);
}
