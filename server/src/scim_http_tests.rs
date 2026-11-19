//! SCIM provisioning end to end (ADR 0023): the real router, with the request shapes
//! Okta and Entra ID send.

use crate::sso_http_tests::{header, mock_idp, serve_with, set_cookies, to_callback, web_sign_in, OID};
use crate::tests::{audit_list, call, call_with, serve_app_with};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const USERS: &str = "/scim/v2/Users";

async fn serve(tweak: impl FnOnce(&mut Auth)) -> (u16, AppState, String) {
    let (port, app, admin, _) = serve_app_with(|a| {
        a.scim.enabled = true;
        tweak(a);
    })
    .await;
    (port, app, admin)
}

/// A new SCIM token. Returns its value and id.
async fn token(port: u16, admin: &str, body: Value) -> (String, String) {
    let (code, head, res) = call_with(port, "POST", "/api/scim/tokens", admin, "", &body.to_string()).await;
    assert_eq!(code, 201, "{res}");
    assert_eq!(header(&head, "cache-control").as_deref(), Some("no-store"));
    let res = parse(&res);
    (res["token"].as_str().unwrap().to_string(), res["scimToken"]["id"].as_str().unwrap().to_string())
}

/// A SCIM request with `token`. Returns the status, response head, and body.
async fn scim(port: u16, token: &str, method: &str, path: &str, body: Value) -> (u16, String, Value) {
    let body = if body.is_null() { String::new() } else { body.to_string() };
    let (code, head, res) = call_with(port, method, path, &format!("Bearer {token}"), "", &body).await;
    (code, head, parse(&res))
}

async fn events(port: u16, admin: &str, query: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?{query}"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

/// A session for an existing user, from a one-time code.
async fn session_for(port: u16, admin: &str, user: &str) -> String {
    let (code, c) = call(port, "POST", &format!("/api/users/{user}/login-codes"), admin, "").await;
    assert_eq!(code, 200, "{c}");
    let (code, res) = call(port, "POST", "/api/auth/login", "", &json!({ "code": parse(&c)["code"] }).to_string()).await;
    assert_eq!(code, 200, "{res}");
    format!("Bearer {}", parse(&res)["token"].as_str().unwrap())
}

async fn me(port: u16, auth: &str) -> u16 {
    call(port, "GET", "/api/auth/me", auth, "").await.0
}

fn okta_user(user_name: &str, external_id: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": user_name, "externalId": external_id,
        "name": { "givenName": "Ada", "familyName": "Lovelace" },
        "emails": [{ "primary": true, "value": user_name, "type": "work" }],
        "displayName": "Ada Lovelace", "locale": "en-US",
        "password": "OktaPlaceholder1!", "groups": [], "active": true,
    })
}

fn is_scim_error(head: &str, body: &Value, status: u16) {
    assert_eq!(header(head, "content-type").as_deref(), Some("application/scim+json"), "{head}");
    assert_eq!(body["schemas"], json!(["urn:ietf:params:scim:api:messages:2.0:Error"]), "{body}");
    assert_eq!(body["status"], status.to_string(), "{body}");
}

#[tokio::test]
async fn scim_is_off_by_default() {
    let (port, _, admin, _) = serve_app_with(|_| {}).await;
    let (code, body) = call(port, "GET", "/api/scim/tokens", &admin, "").await;
    assert_eq!((code, parse(&body)["enabled"].clone()), (200, json!(false)));
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    for path in ["/scim/v2/Users", "/scim/v2/ServiceProviderConfig"] {
        let (code, head, body) = scim(port, &t, "GET", path, Value::Null).await;
        assert_eq!(code, 404);
        is_scim_error(&head, &body, 404);
        assert!(body["detail"].as_str().unwrap().contains("SCIM=on"));
    }
}

#[tokio::test]
async fn tokens_are_admin_only_shown_once_and_revocable() {
    let (port, _, admin) = serve(|_| {}).await;
    let (_, member) = user_with(port, &admin, "member@example.com", "member").await;
    assert_eq!(call(port, "POST", "/api/scim/tokens", &member, r#"{"tenant":"okta"}"#).await.0, 403);
    assert_eq!(call(port, "GET", "/api/scim/tokens", &member, "").await.0, 403);
    for bad in [json!({}), json!({ "tenant": "Okta" }), json!({ "tenant": "a b" }), json!({ "tenant": "okta", "sso": "nope" }), json!({ "tenant": "okta", "sso": 1 })] {
        assert_eq!(call(port, "POST", "/api/scim/tokens", &admin, &bad.to_string()).await.0, 400, "{bad}");
    }

    let (t, id) = token(port, &admin, json!({ "tenant": "okta", "label": "Okta prod" })).await;
    assert!(t.starts_with("sbp_") && t.len() == 68, "{t}");
    let (_, list) = call(port, "GET", "/api/scim/tokens", &admin, "").await;
    assert!(!list.contains(&t) && !list.contains(&users::hash(&t)), "never the token or its hash: {list}");
    let list = parse(&list);
    assert_eq!((list["enabled"].clone(), list["defaultRole"].clone()), (json!(true), json!("member")));
    assert_eq!((list["tokens"][0]["id"].as_str(), list["tokens"][0]["tenant"].as_str(), list["tokens"][0]["label"].as_str()), (Some(id.as_str()), Some("okta"), Some("Okta prod")));
    assert_eq!(scim(port, &t, "GET", USERS, Value::Null).await.0, 200);
    assert!(list["tokens"][0]["lastUsedAt"].is_null());
    assert!(!parse(&call(port, "GET", "/api/scim/tokens", &admin, "").await.1)["tokens"][0]["lastUsedAt"].is_null(), "use is recorded");

    let made = &events(port, &admin, "action=scim.token_created").await[0];
    assert_eq!((made["targetId"].as_str(), made["details"]["tenant"].as_str(), made["actorId"].as_str()), (Some(id.as_str()), Some("okta"), Some("operator")));
    assert_eq!(call(port, "DELETE", &format!("/api/scim/tokens/{id}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("/api/scim/tokens/{id}"), &admin, "").await.0, 404, "revoked once");
    assert_eq!(scim(port, &t, "GET", USERS, Value::Null).await.0, 401, "a revoked token stops working");
    assert_eq!(events(port, &admin, "action=scim.token_revoked").await[0]["targetId"].as_str(), Some(id.as_str()));
    let (_, all) = call(port, "GET", "/api/audit", &admin, "").await;
    assert!(!all.contains(&t), "the token is never logged");
}

#[tokio::test]
async fn only_a_scim_token_works_and_bad_ones_are_throttled() {
    let (port, _, admin) = serve(|_| {}).await;
    let (_, member) = user_with(port, &admin, "member@example.com", "member").await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let fake = users::new_secret(scim::TOKEN_PREFIX);
    for (n, auth) in ["".to_string(), format!("Bearer {fake}"), "Bearer sbp_short".into(), admin.clone(), member.clone(), format!("Basic {t}")].iter().enumerate() {
        let (code, head, body) = call_with(port, "GET", USERS, auth, "", "").await;
        assert_eq!(code, 401, "credential {n}");
        is_scim_error(&head, &parse(&body), 401);
        assert_eq!(header(&head, "www-authenticate").as_deref(), Some("Bearer realm=\"SuperBot SCIM\""));
    }
    assert_eq!(call(port, "GET", "/api/state", &format!("Bearer {t}"), "").await.0, 401, "a SCIM token is not a session");
    assert_eq!(call(port, "GET", "/api/scim/tokens", &format!("Bearer {t}"), "").await.0, 401);
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(format!("GET {USERS} HTTP/1.0\r\nHost: evil.example\r\nAuthorization: Bearer {t}\r\n\r\n").as_bytes()).await.unwrap();
    let mut res = String::new();
    s.read_to_string(&mut res).await.unwrap();
    assert!(res.starts_with("HTTP/1.0 403"), "an unknown Host: {res}");

    let failed = events(port, &admin, "action=scim.auth_failed").await;
    assert_eq!(failed.len(), 1, "throttled: {failed:?}");
    assert_eq!((failed[0]["outcome"].as_str(), failed[0]["details"]["reason"].as_str(), failed[0]["authMethod"].as_str()), (Some("failure"), Some("missing"), Some("scim_token")));
    let (_, all) = call(port, "GET", "/api/audit", &admin, "").await;
    assert!(!all.contains(&fake), "a guessed token is never logged");

    let mut limited = None;
    for n in 0..30 {
        let (code, head, _) = call_with(port, "GET", USERS, &format!("Bearer {fake}"), "", "").await;
        if code == 429 {
            limited = Some((n, header(&head, "retry-after")));
            break;
        }
    }
    let (_, retry) = limited.expect("bad tokens are rate limited per IP");
    assert!(retry.is_some_and(|r| r.parse::<i64>().unwrap() > 0));
    assert_eq!(scim(port, &t, "GET", USERS, Value::Null).await.0, 429, "even good tokens wait out the block from this IP");
}

#[tokio::test]
async fn each_tenant_is_rate_limited() {
    let (port, _, admin) = serve(|a| a.scim.limiter = users::Limiter::new(3, 60_000)).await;
    let (a, _) = token(port, &admin, json!({ "tenant": "a" })).await;
    let (b, _) = token(port, &admin, json!({ "tenant": "b" })).await;
    for _ in 0..3 {
        assert_eq!(scim(port, &a, "GET", USERS, Value::Null).await.0, 200);
    }
    let (code, head, body) = scim(port, &a, "GET", USERS, Value::Null).await;
    assert_eq!(code, 429);
    is_scim_error(&head, &body, 429);
    assert!(header(&head, "retry-after").is_some());
    assert_eq!(scim(port, &b, "GET", USERS, Value::Null).await.0, 200, "other tenants aren't slowed");
}

#[tokio::test]
async fn discovery_describes_users_only() {
    let (port, _, admin) = serve(|_| {}).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    let (code, head, spc) = scim(port, &t, "GET", "/scim/v2/ServiceProviderConfig", Value::Null).await;
    assert_eq!((code, header(&head, "content-type").as_deref()), (200, Some("application/scim+json")));
    assert_eq!((spc["patch"]["supported"].clone(), spc["bulk"]["supported"].clone(), spc["filter"]["supported"].clone()), (json!(true), json!(false), json!(true)));
    assert_eq!(spc["authenticationSchemes"][0]["type"], "oauthbearertoken");

    let (_, _, types) = scim(port, &t, "GET", "/scim/v2/ResourceTypes", Value::Null).await;
    assert_eq!((types["totalResults"].clone(), types["Resources"][0]["endpoint"].clone()), (json!(1), json!("/Users")));
    assert_eq!(scim(port, &t, "GET", "/scim/v2/ResourceTypes/User", Value::Null).await.0, 200);
    assert_eq!(scim(port, &t, "GET", "/scim/v2/ResourceTypes/Group", Value::Null).await.0, 404);
    let (_, _, schemas) = scim(port, &t, "GET", "/scim/v2/Schemas", Value::Null).await;
    assert_eq!(schemas["Resources"][0]["id"], scim::USER_SCHEMA);
    assert_eq!(scim(port, &t, "GET", &format!("/scim/v2/Schemas/{}", scim::USER_SCHEMA), Value::Null).await.0, 200);

    // Groups: an empty list for connection tests, and a clear refusal for the rest.
    let (code, _, groups) = scim(port, &t, "GET", "/scim/v2/Groups?startIndex=1&count=100", Value::Null).await;
    assert_eq!((code, groups["totalResults"].clone(), groups["Resources"].clone()), (200, json!(0), json!([])));
    let (code, head, body) = scim(port, &t, "POST", "/scim/v2/Groups", json!({ "displayName": "Eng" })).await;
    assert_eq!(code, 501);
    is_scim_error(&head, &body, 501);
    assert_eq!(scim(port, &t, "GET", "/scim/v2/Groups/g1", Value::Null).await.0, 404);
    let (code, head, body) = scim(port, &t, "GET", "/scim/v2/Bulk", Value::Null).await;
    assert_eq!(code, 404);
    is_scim_error(&head, &body, 404);
}

#[tokio::test]
async fn okta_provisions_finds_updates_and_deactivates() {
    let (port, app, admin) = serve(|_| {}).await;
    let (t, tid) = token(port, &admin, json!({ "tenant": "okta" })).await;

    let (code, head, u) = scim(port, &t, "POST", USERS, okta_user("ada@example.com", "00u1")).await;
    assert_eq!(code, 201, "{u}");
    assert_eq!(header(&head, "content-type").as_deref(), Some("application/scim+json"));
    let id = u["id"].as_str().unwrap().to_string();
    assert_eq!((u["userName"].as_str(), u["externalId"].as_str(), u["active"].clone(), u["displayName"].as_str()), (Some("ada@example.com"), Some("00u1"), json!(true), Some("Ada Lovelace")));
    assert_eq!(u["emails"], json!([{ "value": "ada@example.com", "type": "work", "primary": true }]));
    assert_eq!(u["meta"]["location"], format!("http://127.0.0.1:{port}/scim/v2/Users/{id}"));
    assert!(u.get("password").is_none() && u.get("groups").is_none());
    let user = app.db.user(&id).unwrap();
    assert_eq!((user.email.as_deref(), user.role, user.active()), (Some("ada@example.com"), rbac::Role::Member, true));

    // Okta checks before creating: by userName, any case.
    let (_, _, found) = scim(port, &t, "GET", "/scim/v2/Users?filter=userName%20eq%20%22ADA%40example.com%22&startIndex=1&count=100", Value::Null).await;
    assert_eq!((found["totalResults"].clone(), found["Resources"][0]["id"].as_str()), (json!(1), Some(id.as_str())));
    let (_, _, found) = scim(port, &t, "GET", "/scim/v2/Users?filter=externalId+eq+%2200u1%22", Value::Null).await;
    assert_eq!(found["totalResults"], 1);
    let (_, _, none) = scim(port, &t, "GET", "/scim/v2/Users?filter=externalId+eq+%2200U1%22", Value::Null).await;
    assert_eq!(none["totalResults"], 0, "externalId is case-exact");
    let (code, head, body) = scim(port, &t, "GET", "/scim/v2/Users?filter=name.givenName+sw+%22A%22", Value::Null).await;
    assert_eq!((code, body["scimType"].as_str()), (400, Some("invalidFilter")));
    is_scim_error(&head, &body, 400);
    assert_eq!(scim(port, &t, "GET", "/scim/v2/Users?startIndex=x", Value::Null).await.0, 400);

    // Creating twice: the same externalId, or the same userName, is a conflict.
    for again in [okta_user("ada@example.com", "00u1"), okta_user("ADA@example.com", "00u9")] {
        let (code, head, body) = scim(port, &t, "POST", USERS, again).await;
        assert_eq!((code, body["scimType"].as_str()), (409, Some("uniqueness")), "{body}");
        is_scim_error(&head, &body, 409);
    }
    // Pages, 1-based.
    assert_eq!(scim(port, &t, "POST", USERS, okta_user("grace@example.com", "00u2")).await.0, 201);
    let (_, _, page) = scim(port, &t, "GET", "/scim/v2/Users?startIndex=2&count=1", Value::Null).await;
    assert_eq!((page["totalResults"].clone(), page["startIndex"].clone(), page["itemsPerPage"].clone(), page["Resources"][0]["userName"].as_str()), (json!(2), json!(2), json!(1), Some("grace@example.com")));
    let (_, _, counted) = scim(port, &t, "GET", "/scim/v2/Users?count=0", Value::Null).await;
    assert_eq!((counted["totalResults"].clone(), counted["Resources"].clone()), (json!(2), json!([])));

    // PUT (Okta's AIW apps) replaces the profile.
    let mut put = okta_user("ada@example.com", "00u1");
    put["name"] = json!({ "givenName": "Ada", "familyName": "King" });
    put["displayName"] = json!("Ada King");
    let (code, _, u) = scim(port, &t, "PUT", &format!("{USERS}/{id}"), put).await;
    assert_eq!((code, u["name"]["familyName"].as_str(), u["displayName"].as_str()), (200, Some("King"), Some("Ada King")));
    let upd = &events(port, &admin, "action=user.updated").await[0];
    assert_eq!(upd["details"]["changes"]["name"], json!({ "from": "Ada Lovelace", "to": "Ada King" }));
    assert_eq!(upd["details"]["changes"]["familyName"], json!({ "from": "Lovelace", "to": "King" }));

    // Deactivation (Okta's OIN apps): PATCH without a path. Their sessions end.
    let session = session_for(port, &admin, &id).await;
    assert_eq!(me(port, &session).await, 200);
    let off = json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{ "op": "replace", "value": { "active": false } }] });
    let (code, _, u) = scim(port, &t, "PATCH", &format!("{USERS}/{id}"), off).await;
    assert_eq!((code, u["active"].clone()), (200, json!(false)));
    assert_eq!(me(port, &session).await, 401, "deprovisioning ends every session");
    assert!(!app.db.user(&id).unwrap().active());
    let disabled = &events(port, &admin, "action=user.disabled").await[0];
    assert_eq!(
        (disabled["actorKind"].as_str(), disabled["actorId"].as_str(), disabled["actorName"].as_str(), disabled["authMethod"].as_str()),
        (Some("system"), Some(format!("scim:{tid}").as_str()), Some("SCIM okta"), Some("scim_token"))
    );
    assert_eq!((disabled["targetId"].as_str(), disabled["details"]["sessionsRevoked"].clone()), (Some(id.as_str()), json!(1)));
    let mine = events(port, &admin, &format!("actor=system:scim:{tid}")).await;
    assert!(mine.iter().any(|e| e["action"] == "user.created") && mine.iter().any(|e| e["action"] == "user.disabled"), "{mine:?}");
    assert_eq!(call(port, "POST", &format!("/api/users/{id}/login-codes"), &admin, "").await.0, 409, "a disabled user can't sign in");

    // Deactivated users are still found, so Okta can reactivate them.
    let (_, _, found) = scim(port, &t, "GET", "/scim/v2/Users?filter=userName+eq+%22ada%40example.com%22", Value::Null).await;
    assert_eq!((found["totalResults"].clone(), found["Resources"][0]["active"].clone()), (json!(1), json!(false)));
    let on = json!({ "Operations": [{ "op": "replace", "value": { "active": true } }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{USERS}/{id}"), on).await.2["active"], true);
    assert_eq!(events(port, &admin, "action=user.enabled").await[0]["targetId"].as_str(), Some(id.as_str()));
    let (_, all) = call(port, "GET", "/api/audit", &admin, "").await;
    assert!(!all.contains("OktaPlaceholder1!"), "the placeholder password is never kept or logged");
}

#[tokio::test]
async fn entra_patches_deletes_softly_and_provisions_again() {
    let (port, app, admin) = serve(|_| {}).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "entra" })).await;
    // Entra's default mapping: mailNickname -> externalId, UPN -> userName, mail -> work email.
    let grace = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
        "externalId": "grace", "userName": "grace@contoso.example", "active": true, "displayName": "Grace Hopper",
        "emails": [{ "primary": true, "type": "work", "value": "grace.hopper@contoso.example" }],
        "name": { "formatted": "Grace Hopper", "familyName": "Hopper", "givenName": "Grace" },
        "title": "Rear Admiral", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { "department": "Navy" },
        "roles": [{ "primary": "True", "type": "WindowsAzureActiveDirectoryRole", "value": "Admin" }],
    });
    let (code, _, u) = scim(port, &t, "POST", USERS, grace.clone()).await;
    assert_eq!(code, 201, "{u}");
    let id = u["id"].as_str().unwrap().to_string();
    assert_eq!(app.db.user(&id).unwrap().role, rbac::Role::Member, "SCIM never sets roles");
    assert_eq!(app.db.user(&id).unwrap().email.as_deref(), Some("grace.hopper@contoso.example"));

    let patch = json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
        { "op": "Replace", "path": "emails[type eq \"work\"].value", "value": "grace@navy.example" },
        { "op": "Replace", "path": "displayName", "value": "Amazing Grace" },
        { "op": "Add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager", "value": "x" },
        { "op": "Replace", "path": "active", "value": "False" },
    ]});
    let (code, _, u) = scim(port, &t, "PATCH", &format!("{USERS}/{id}"), patch).await;
    assert_eq!((code, u["emails"][0]["value"].as_str(), u["displayName"].as_str(), u["active"].clone()), (200, Some("grace@navy.example"), Some("Amazing Grace"), json!(false)));
    for bad in [
        json!({ "Operations": [{ "op": "Replace", "path": "externalId", "value": "other" }] }),
        json!({ "Operations": [{ "op": "Remove", "path": "userName" }] }),
        json!({ "Operations": [{ "op": "Copy", "path": "active", "value": true }] }),
    ] {
        let (code, head, body) = scim(port, &t, "PATCH", &format!("{USERS}/{id}"), bad.clone()).await;
        assert_eq!(code, 400, "{bad}");
        is_scim_error(&head, &body, 400);
    }
    assert_eq!(scim(port, &t, "PATCH", &format!("{USERS}/{id}"), json!({ "Operations": [{ "op": "Replace", "path": "externalId", "value": "other" }] })).await.2["scimType"], "mutability");
    let (code, _, body) = call_with(port, "POST", USERS, &format!("Bearer {t}"), "", "{not json").await;
    assert_eq!((code, parse(&body)["scimType"].as_str()), (400, Some("invalidSyntax")));
    let (code, head, body) = call_with(port, "POST", USERS, &format!("Bearer {t}"), "", &format!("{{\"userName\":\"{}\"}}", "x".repeat(scim::MAX_BODY))).await;
    assert_eq!(code, 413);
    is_scim_error(&head, &parse(&body), 413);

    // Removing the email removes it, even when the userName is an address.
    let (code, _, u) = scim(port, &t, "PATCH", &format!("{USERS}/{id}"), json!({ "Operations": [{ "op": "Remove", "path": "emails" }] })).await;
    assert_eq!((code, u.get("emails")), (200, None), "{u}");
    assert_eq!(app.db.user(&id).unwrap().email, None);
    // name.formatted is kept as sent; the shown name stays the displayName.
    let (_, _, u) = scim(port, &t, "PATCH", &format!("{USERS}/{id}"), json!({ "Operations": [{ "op": "Replace", "path": "name.formatted", "value": "G. Hopper" }] })).await;
    assert_eq!((u["name"]["formatted"].as_str(), u["displayName"].as_str()), (Some("G. Hopper"), Some("Amazing Grace")));

    // Turn it back on, sign in, then DELETE: disabled, sessions gone, history kept.
    assert_eq!(scim(port, &t, "PATCH", &format!("{USERS}/{id}"), json!({ "Operations": [{ "op": "Replace", "path": "active", "value": true }] })).await.0, 200);
    let session = session_for(port, &admin, &id).await;
    let (code, head, body) = call_with(port, "DELETE", &format!("{USERS}/{id}"), &format!("Bearer {t}"), "", "").await;
    assert_eq!((code, body.as_str()), (204, ""), "{head}");
    assert_eq!(me(port, &session).await, 401);
    assert_eq!(scim(port, &t, "GET", &format!("{USERS}/{id}"), Value::Null).await.0, 404);
    assert_eq!(scim(port, &t, "PATCH", &format!("{USERS}/{id}"), json!({ "Operations": [{ "op": "replace", "path": "active", "value": true }] })).await.0, 404);
    assert_eq!(scim(port, &t, "DELETE", &format!("{USERS}/{id}"), Value::Null).await.0, 404);
    assert_eq!(scim(port, &t, "GET", "/scim/v2/Users?filter=externalId+eq+%22grace%22", Value::Null).await.2["totalResults"], 0);
    let kept = app.db.user(&id).expect("never destroyed");
    assert!(!kept.active());
    // An update that read the user before the DELETE can't bring them back.
    let stale = db::ScimFields { user_name: "grace@contoso.example", external_id: Some("grace"), given_name: None, family_name: None, scim_display_name: None, formatted: None, display_name: "Grace", email: None, active: true };
    assert_eq!(app.db.save_scim_user("entra", &id, &stale, false), Err(db::ScimConflict::Gone));
    assert!(!app.db.user(&id).unwrap().active());
    let deleted = &events(port, &admin, "action=scim.user_deleted").await[0];
    assert_eq!((deleted["targetId"].as_str(), deleted["details"]["sessionsRevoked"].clone(), deleted["details"]["externalId"].as_str()), (Some(id.as_str()), json!(1), Some("grace")));

    // The same person provisioned again: the same user, active again.
    let (code, _, again) = scim(port, &t, "POST", USERS, grace).await;
    assert_eq!((code, again["id"].as_str(), again["active"].clone()), (201, Some(id.as_str()), json!(true)), "{again}");
    assert!(app.db.user(&id).unwrap().active());
    assert_eq!(events(port, &admin, "action=scim.user_restored").await[0]["targetId"].as_str(), Some(id.as_str()));
}

#[tokio::test]
async fn tenants_are_isolated_and_never_take_over_users() {
    let (port, app, admin) = serve(|a| a.scim.default_role = rbac::Role::Readonly).await;
    let (a, _) = token(port, &admin, json!({ "tenant": "a" })).await;
    let (b, _) = token(port, &admin, json!({ "tenant": "b" })).await;
    let (_, _, u) = scim(port, &a, "POST", USERS, okta_user("ada@example.com", "x1")).await;
    let id = u["id"].as_str().unwrap().to_string();
    assert_eq!(app.db.user(&id).unwrap().role, rbac::Role::Readonly, "SCIM_DEFAULT_ROLE");

    for (method, body) in [("GET", Value::Null), ("PUT", okta_user("ada@example.com", "x1")), ("PATCH", json!({ "Operations": [{ "op": "replace", "path": "active", "value": false }] })), ("DELETE", Value::Null)] {
        assert_eq!(scim(port, &b, method, &format!("{USERS}/{id}"), body).await.0, 404, "{method}");
    }
    assert_eq!(scim(port, &b, "GET", USERS, Value::Null).await.2["totalResults"], 0);
    assert!(app.db.user(&id).unwrap().active());

    // Email is never the key: another tenant, or an existing user, keeps its address.
    let (code, _, body) = scim(port, &b, "POST", USERS, okta_user("ada@example.com", "x1")).await;
    assert_eq!((code, body["scimType"].as_str()), (409, Some("uniqueness")));
    let (boss, _) = user_with(port, &admin, "boss@example.com", "admin").await;
    let (code, _, body) = scim(port, &a, "POST", USERS, okta_user("boss@example.com", "x2")).await;
    assert_eq!(code, 409);
    assert!(body["detail"].as_str().unwrap().contains("botctl user link"), "{body}");
    assert_eq!(app.db.user(&boss).unwrap().role, rbac::Role::Admin);

    // A restore that fails (the email is someone else's now) leaves no restore event.
    let (_, _, u) = scim(port, &a, "POST", USERS, okta_user("dee@example.com", "x3")).await;
    let dee = u["id"].as_str().unwrap().to_string();
    assert_eq!(scim(port, &a, "DELETE", &format!("{USERS}/{dee}"), Value::Null).await.0, 204);
    assert_eq!(call(port, "PATCH", &format!("/api/users/{dee}"), &admin, r#"{"email":"dee.old@example.com"}"#).await.0, 200);
    assert_eq!(call(port, "POST", "/api/users", &admin, r#"{"email":"dee@example.com"}"#).await.0, 201);
    assert_eq!(scim(port, &a, "POST", USERS, okta_user("dee@example.com", "x3")).await.0, 409);
    assert!(events(port, &admin, "action=scim.user_restored").await.is_empty());

    // Admins still own roles: a promotion survives SCIM updates.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{id}"), &admin, r#"{"role":"admin"}"#).await.0, 200);
    let (code, _, _) = scim(port, &a, "PUT", &format!("{USERS}/{id}"), okta_user("ada@example.com", "x1")).await;
    assert_eq!(code, 200);
    assert_eq!(app.db.user(&id).unwrap().role, rbac::Role::Admin);
}

#[tokio::test]
async fn an_sso_linked_tenant_provisions_people_who_then_sign_in() {
    let idp = mock_idp().await;
    let (port, app, admin, sso) = serve_with(&idp, &[], |a| a.scim.enabled = true).await;
    let (t, _) = token(port, &admin, json!({ "tenant": "entra", "sso": sso })).await;
    let (code, body) = call(port, "POST", "/api/scim/tokens", &admin, r#"{"tenant":"entra"}"#).await;
    assert_eq!(code, 409, "a tenant's tokens all link the same provider: {body}");

    let mut ada = okta_user("ada@corp.example", "");
    ada.as_object_mut().unwrap().remove("externalId");
    let (code, _, body) = scim(port, &t, "POST", USERS, ada.clone()).await;
    assert_eq!(code, 400, "the externalId is the person's subject: {body}");
    assert!(body["detail"].as_str().unwrap().contains("objectId"), "{body}");
    ada["externalId"] = json!("not-a-guid");
    assert_eq!(scim(port, &t, "POST", USERS, ada.clone()).await.0, 400);

    // Before provisioning, nobody is linked; after, the person signs in as the new user.
    assert_eq!(header(&web_sign_in(port, &sso).await.1, "location").as_deref(), Some("/login?error=sso_not_linked"));
    ada["externalId"] = json!(OID.to_uppercase());
    let (code, _, u) = scim(port, &t, "POST", USERS, ada).await;
    assert_eq!(code, 201, "{u}");
    let id = u["id"].as_str().unwrap().to_string();
    let (_, ids) = call(port, "GET", &format!("/api/users/{id}/identities"), &admin, "").await;
    assert_eq!(parse(&ids)[0]["subject"], OID, "{ids}");
    let linked = &events(port, &admin, "action=user.identity_linked").await[0];
    assert_eq!((linked["authMethod"].as_str(), linked["idpProvider"].as_str(), linked["idp"].as_str()), (Some("scim_token"), Some(sso.as_str()), Some("entra")));

    let (path, binder) = to_callback(port, &format!("/api/auth/sso/{sso}/start")).await;
    let (code, head, _) = call_with(port, "GET", &path, "", &binder, "").await;
    assert_eq!(code, 200, "{head}");
    let cookie = set_cookies(&head).into_iter().find(|c| c.starts_with("superbot_session=sbs_")).unwrap();
    let cookie = format!("Cookie: {}\r\n", cookie.split(';').next().unwrap());
    let (_, _, who) = call_with(port, "GET", "/api/auth/me", "", &cookie, "").await;
    assert_eq!(parse(&who)["user"]["id"].as_str(), Some(id.as_str()));

    // Deprovisioned: the session ends and SSO sign-in is refused.
    let off = json!({ "Operations": [{ "op": "Replace", "path": "active", "value": "False" }] });
    assert_eq!(scim(port, &t, "PATCH", &format!("{USERS}/{id}"), off).await.0, 200);
    assert_eq!(call_with(port, "GET", "/api/auth/me", "", &cookie, "").await.0, 401);
    let (code, head) = web_sign_in(port, &sso).await;
    assert!(code == 303 && header(&head, "location").is_some_and(|l| l.contains("error=")), "{head}");

    // Someone an admin already linked becomes the tenant's: the same user, not a new one.
    let other = "aaaaaaaa-0000-0000-0000-0000000000b2";
    let (_, made) = call(port, "POST", "/api/users", &admin, r#"{"email":"bob@corp.example","name":"Bob"}"#).await;
    let bob = parse(&made)["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "POST", &format!("/api/users/{bob}/identities"), &admin, &json!({ "provider": sso, "subject": other }).to_string()).await.0, 201);
    let (code, _, u) = scim(port, &t, "POST", USERS, okta_user("bob@corp.example", other)).await;
    assert_eq!((code, u["id"].as_str()), (201, Some(bob.as_str())), "{u}");
    assert_eq!(events(port, &admin, "action=scim.user_linked").await[0]["targetId"].as_str(), Some(bob.as_str()));
    let (code, _, _) = scim(port, &t, "POST", USERS, okta_user("bob2@corp.example", other)).await;
    assert_eq!(code, 409, "provisioned once");

    // Two tenants on the same IdP: a user one of them deleted stays its own.
    let (t2, _) = token(port, &admin, json!({ "tenant": "entra-2", "sso": sso })).await;
    let carol = "aaaaaaaa-0000-0000-0000-0000000000c4";
    let (_, _, u) = scim(port, &t, "POST", USERS, okta_user("carol@corp.example", carol)).await;
    let carol_id = u["id"].as_str().unwrap().to_string();
    assert_eq!(scim(port, &t, "DELETE", &format!("{USERS}/{carol_id}"), Value::Null).await.0, 204);
    let (code, _, body) = scim(port, &t2, "POST", USERS, okta_user("carol@corp.example", carol)).await;
    assert_eq!((code, body["scimType"].as_str()), (409, Some("uniqueness")), "{body}");
    assert!(!app.db.user(&carol_id).unwrap().active());
    assert_eq!(app.db.scim_user_of(&carol_id).unwrap().tenant, "entra");
    let (code, _, u) = scim(port, &t, "POST", USERS, okta_user("carol@corp.example", carol)).await;
    assert_eq!((code, u["id"].as_str()), (201, Some(carol_id.as_str())), "only its own tenant restores");

    // Never the owner: the break-glass account stays out of SCIM's reach.
    let boss = "aaaaaaaa-0000-0000-0000-0000000000b3";
    assert_eq!(call(port, "POST", "/api/users/operator/identities", &admin, &json!({ "provider": sso, "subject": boss }).to_string()).await.0, 201);
    let (code, _, body) = scim(port, &t, "POST", USERS, okta_user("owner@corp.example", boss)).await;
    assert_eq!(code, 409, "{body}");
    assert!(app.db.scim_user_of(users::OPERATOR).is_none());
}
