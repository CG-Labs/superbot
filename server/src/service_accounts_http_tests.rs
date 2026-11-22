//! Service accounts (ADR 0143), on the real router: non-human callers that hold a built-in
//! or custom role (never admin), across the server or in one team, act only through
//! hashed, scoped, expiring tokens shown once, never get more than their owner holds,
//! can't sign in, and show in the audit log as themselves.

use crate::acl::Visibility;
use crate::tests::{audit_list, call, call_with, serve_app};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::users_http_tests::{parse, user_with};
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

async fn role(port: u16, admin: &str, name: &str, base: &str, perms: &[&str]) -> String {
    let (code, v) = json_call(port, "POST", "/api/roles", admin, &json!({ "name": name, "base": base, "permissions": perms }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

/// A new service account. Returns its id.
async fn account(port: u16, who: &str, body: Value) -> String {
    let (code, v) = json_call(port, "POST", "/api/service-accounts", who, &body.to_string()).await;
    assert_eq!(code, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

/// A new token for `sa`. Returns its Authorization and the reply.
async fn token(port: u16, who: &str, sa: &str, body: Value) -> (String, Value) {
    let (code, head, v) = call_with(port, "POST", &format!("/api/service-accounts/{sa}/tokens"), who, "", &body.to_string()).await;
    assert_eq!(code, 201, "{v}");
    assert!(head.to_ascii_lowercase().contains("cache-control: no-store"), "{head}");
    let v = parse(&v);
    (format!("Bearer {}", v["token"].as_str().unwrap()), v)
}

#[tokio::test]
async fn admins_make_service_accounts_that_never_hold_admin_and_are_not_people() {
    let (port, app, admin, _) = serve_app().await;
    let seats = app.db.active_seats();
    let auditor = role(port, &admin, "Auditor", "readonly", &["audit.view"]).await;
    for (body, code) in [
        (json!({ "name": "Root", "role": "admin" }), 400),
        (json!({ "name": "Root", "role": "Admin" }), 400),
        (json!({ "name": "", "role": "member" }), 400),
        (json!({ "name": "X", "role": "owner" }), 400),
        (json!({ "name": "X", "email": "x@example.com" }), 400),
        (json!({ "name": "X", "team": "nope" }), 404),
        (json!([]), 400),
    ] {
        assert_eq!(json_call(port, "POST", "/api/service-accounts", &admin, &body.to_string()).await.0, code, "{body}");
    }

    let (code, ci) = json_call(port, "POST", "/api/service-accounts", &admin, r#"{"name":"CI","description":"Deploys main"}"#).await;
    assert_eq!(code, 201, "{ci}");
    assert_eq!((ci["role"].as_str(), ci["status"].as_str(), ci["owner"]["id"].as_str()), (Some("readonly"), Some("active"), Some(users::OPERATOR)), "read-only by default, owned by its maker");
    assert_eq!((ci["permissions"].clone(), ci["effective"].clone(), ci["tokens"].clone()), (json!(["account", "read", "review"]), json!(["account", "read", "review"]), json!(0)));
    let aud = account(port, &admin, json!({ "name": "Audit export", "role": "Auditor" })).await;
    let (_, v) = json_call(port, "GET", &format!("/api/service-accounts/{aud}"), &admin, "").await;
    assert_eq!((v["customRole"]["id"].as_str(), v["permissions"].clone(), v["tokenList"].clone()), (Some(auditor.as_str()), json!(["account", "read", "review", "audit.view"]), json!([])), "{v}");
    let (code, list) = json_call(port, "GET", "/api/service-accounts", &admin, "").await;
    assert_eq!((code, list["serviceAccounts"].as_array().unwrap().len(), list["defaultDays"].clone(), list["maxDays"].clone()), (200, 2, json!(90), json!(365)), "{list}");
    assert!(!list["scopes"].as_array().unwrap().contains(&json!("admin")), "{list}");

    // Never admin, whichever route tries.
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{aud}"), &admin, r#"{"role":"admin"}"#).await.0, 400);
    assert_eq!(app.db.user(&aud).unwrap().role, rbac::Role::Readonly);
    // Not a person: the people routes don't find it, so they can't make it one, or an admin.
    let (_, users) = json_call(port, "GET", "/api/users", &admin, "").await;
    assert!(!users.to_string().contains(&aud), "{users}");
    for (i, (method, path, body)) in [
        ("GET", format!("/api/users/{aud}"), ""),
        ("PATCH", format!("/api/users/{aud}"), r#"{"role":"admin"}"#),
        ("POST", format!("/api/users/{aud}/login-codes"), ""),
        ("PUT", format!("/api/roles/{auditor}/users/{aud}"), ""),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(call(port, method, &path, &admin, body).await.0, 404, "{method}, route {i}");
    }
    assert_eq!(app.db.active_seats(), seats, "takes no seat");

    let made = events(port, &admin, "service_account.created").await;
    assert_eq!(made.len(), 2);
    assert_eq!((made[0]["targetId"].as_str(), made[0]["details"]["permissions"].clone()), (Some(aud.as_str()), json!(["account", "read", "review", "audit.view"])));
    assert_eq!(made[0]["actorId"].as_str(), Some(users::OPERATOR));
    // A role a service account holds can't be deleted from under it.
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{auditor}"), &admin, "").await.0, 409);
}

#[tokio::test]
async fn tokens_are_shown_once_scoped_and_the_audit_log_names_the_service_account() {
    let (port, app, admin, _) = serve_app().await;
    role(port, &admin, "Helpdesk", "member", &["users.manage"]).await;
    let sa = account(port, &admin, json!({ "name": "Onboarding", "role": "Helpdesk" })).await;
    let (t, made) = token(port, &admin, &sa, json!({ "name": "hr-sync", "expiresInDays": 30 })).await;
    let secret = made["token"].as_str().unwrap().to_string();
    let tid = made["tokenInfo"]["id"].as_str().unwrap().to_string();
    assert!(secret.starts_with("sbsa_"), "{made}");
    assert_eq!((made["tokenInfo"]["state"].as_str(), made["tokenInfo"]["scopes"].clone()), (Some("active"), Value::Null));
    assert_eq!(made["tokenInfo"]["preview"].as_str().unwrap(), format!("sbsa_…{}", &secret[secret.len() - 4..]));
    let days = (made["tokenInfo"]["expiresAt"].as_i64().unwrap() - db::now()) / (24 * 60 * 60_000);
    assert!((29..=30).contains(&days), "{days}");
    // Only its hash is kept, and nothing shows the secret again.
    assert_eq!(app.db.service_token_by_hash(&users::hash(&secret)).map(|t| t.id), Some(tid.clone()));
    let (_, again) = call(port, "GET", &format!("/api/service-accounts/{sa}"), &admin, "").await;
    assert!(!again.contains(&secret) && again.contains(&tid), "{again}");

    // It works as the account, with exactly what its role holds.
    let (code, me) = json_call(port, "GET", "/api/auth/me", &t, "").await;
    assert_eq!(code, 200, "{me}");
    assert_eq!((me["user"]["id"].as_str(), me["method"].as_str(), me["serviceAccount"]["token"].as_str()), (Some(sa.as_str()), Some("service_token"), Some(tid.as_str())), "{me}");
    assert_eq!(me["permissions"], json!(["account", "read", "review", "write", "approve", "users.manage"]));
    assert_eq!(me["serviceAccount"]["owner"]["id"].as_str(), Some(users::OPERATOR));
    let (code, u) = json_call(port, "POST", "/api/users", &t, r#"{"email":"new@example.com","role":"member"}"#).await;
    assert_eq!(code, 201, "{u}");
    assert_eq!(call(port, "GET", "/api/audit", &t, "").await.0, 403, "its role has no audit.view");
    // A delegate's limits hold: no admins.
    assert_eq!(call(port, "POST", "/api/users", &t, r#"{"email":"boss@example.com","role":"admin"}"#).await.0, 403);

    let ev = events(port, &admin, "user.created").await;
    let e = ev.iter().find(|e| e["targetId"] == u["id"]).unwrap();
    assert_eq!((e["actorKind"].as_str(), e["actorId"].as_str(), e["actorName"].as_str()), (Some("user"), Some(sa.as_str()), Some("Onboarding")), "{e}");
    assert_eq!((e["authMethod"].as_str(), e["sessionId"].as_str(), e["actorRole"].as_str()), (Some("service_token"), Some(tid.as_str()), Some("member")), "{e}");
    let (_, log) = call(port, "GET", "/api/audit?limit=500", &admin, "").await;
    assert!(!log.contains(&secret), "the secret is never logged");
    let created = events(port, &admin, "service_token.created").await;
    assert_eq!((created[0]["targetId"].as_str(), created[0]["details"]["account"].as_str()), (Some(tid.as_str()), Some(sa.as_str())));
    let (_, list) = json_call(port, "GET", &format!("/api/service-accounts/{sa}/tokens"), &admin, "").await;
    assert!(list["tokens"][0]["lastUsedAt"].is_i64(), "{list}");

    // A scoped token gets only its scopes (and `account`, to ask who it is).
    let (read, v) = token(port, &admin, &sa, json!({ "scopes": ["read"] })).await;
    assert_eq!(v["tokenInfo"]["scopes"], json!(["read"]));
    let (_, me) = json_call(port, "GET", "/api/auth/me", &read, "").await;
    assert_eq!(me["permissions"], json!(["account", "read"]), "{me}");
    assert_eq!(call(port, "GET", "/api/bots", &read, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/users", &read, "").await.0, 403);
    let denied = events(port, &admin, "access.denied").await;
    assert_eq!((denied[0]["details"]["reason"].as_str(), denied[0]["actorId"].as_str()), (Some("token_scope"), Some(sa.as_str())), "{denied:?}");
    // Scopes are names the account holds; never admin.
    for scopes in [json!(["admin"]), json!(["audit.view"]), json!(["nope"]), json!([]), json!("read")] {
        let body = json!({ "scopes": scopes }).to_string();
        assert_eq!(call(port, "POST", &format!("/api/service-accounts/{sa}/tokens"), &admin, &body).await.0, 400, "{body}");
    }
    for days in [json!(0), json!(366), json!("30"), json!(1.5)] {
        let body = json!({ "expiresInDays": days }).to_string();
        assert_eq!(call(port, "POST", &format!("/api/service-accounts/{sa}/tokens"), &admin, &body).await.0, 400, "{body}");
    }
    let (_, d) = token(port, &admin, &sa, json!({})).await;
    let days = (d["tokenInfo"]["expiresAt"].as_i64().unwrap() - db::now()) / (24 * 60 * 60_000);
    assert!((89..=90).contains(&days), "every token expires, in 90 days by default");
}

#[tokio::test]
async fn expired_revoked_and_rotated_tokens_stop_working() {
    let (port, app, admin, _) = serve_app().await;
    let sa = account(port, &admin, json!({ "name": "Nightly", "role": "member" })).await;
    let base = format!("/api/service-accounts/{sa}/tokens");

    // Expired.
    let (old, v) = token(port, &admin, &sa, json!({ "name": "old", "expiresInDays": 1 })).await;
    let old_id = v["tokenInfo"]["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "GET", "/api/bots", &old, "").await.0, 200);
    app.db.set_service_token_expiry(&old_id, db::now() - 1);
    assert_eq!(call(port, "GET", "/api/bots", &old, "").await.0, 401);
    let failed = events(port, &admin, "auth.login_failed").await;
    assert_eq!((failed[0]["details"]["method"].as_str(), failed[0]["details"]["reason"].as_str()), (Some("service_token"), Some("expired")), "{failed:?}");
    let (_, list) = json_call(port, "GET", &base, &admin, "").await;
    assert_eq!(list["tokens"][0]["state"].as_str(), Some("expired"));
    assert_eq!(call(port, "POST", &format!("{base}/{old_id}/rotate"), &admin, "{}").await.0, 409, "an expired token can't be rotated");

    // Revoked.
    let (t, v) = token(port, &admin, &sa, json!({ "name": "revoke-me" })).await;
    let tid = v["tokenInfo"]["id"].as_str().unwrap().to_string();
    assert_eq!(call(port, "GET", "/api/bots", &t, "").await.0, 200);
    assert_eq!(call(port, "DELETE", &format!("{base}/{tid}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/bots", &t, "").await.0, 401);
    assert_eq!(call(port, "DELETE", &format!("{base}/{tid}"), &admin, "").await.0, 404, "once");
    assert_eq!(call(port, "POST", &format!("{base}/{tid}/rotate"), &admin, "{}").await.0, 409);
    let revoked = events(port, &admin, "service_token.revoked").await;
    assert_eq!((revoked.len(), revoked[0]["targetId"].as_str(), revoked[0]["details"]["account"].as_str()), (1, Some(tid.as_str()), Some(sa.as_str())));
    let other = account(port, &admin, json!({ "name": "Other" })).await;
    assert_eq!(call(port, "DELETE", &format!("/api/service-accounts/{other}/tokens/{tid}"), &admin, "").await.0, 404, "a token is its account's");

    // Rotated: the old one stops at once, or after the overlap asked for.
    let (a, v) = token(port, &admin, &sa, json!({ "name": "deploy", "scopes": ["read", "write"] })).await;
    let a_id = v["tokenInfo"]["id"].as_str().unwrap().to_string();
    let (code, r) = json_call(port, "POST", &format!("{base}/{a_id}/rotate"), &admin, "{}").await;
    assert_eq!(code, 201, "{r}");
    let b = format!("Bearer {}", r["token"].as_str().unwrap());
    assert_eq!((r["tokenInfo"]["name"].as_str(), r["tokenInfo"]["scopes"].clone()), (Some("deploy"), json!(["read", "write"])), "same name and scopes");
    assert_eq!((call(port, "GET", "/api/bots", &a, "").await.0, call(port, "GET", "/api/bots", &b, "").await.0), (401, 200));
    assert_eq!(call(port, "POST", &format!("{base}/{a_id}/rotate"), &admin, "{}").await.0, 409, "only once");
    let b_id = r["tokenInfo"]["id"].as_str().unwrap().to_string();
    for body in [r#"{"keepOldMinutes":-1}"#, r#"{"keepOldMinutes":1441}"#, r#"{"keepOldMinutes":"5"}"#, r#"{"keep":5}"#] {
        assert_eq!(call(port, "POST", &format!("{base}/{b_id}/rotate"), &admin, body).await.0, 400, "{body}");
    }
    let (code, r) = json_call(port, "POST", &format!("{base}/{b_id}/rotate"), &admin, r#"{"keepOldMinutes":30}"#).await;
    assert_eq!(code, 201, "{r}");
    let c = format!("Bearer {}", r["token"].as_str().unwrap());
    assert_eq!((call(port, "GET", "/api/bots", &b, "").await.0, call(port, "GET", "/api/bots", &c, "").await.0), (200, 200), "both work while callers switch");
    let ends = r["replaced"]["endsAt"].as_i64().unwrap() - db::now();
    assert!((29 * 60_000..=30 * 60_000).contains(&ends), "{ends}");
    assert_eq!(app.db.service_token(&b_id).unwrap().expires_at, r["replaced"]["endsAt"].as_i64().unwrap());
    let rotated = events(port, &admin, "service_token.rotated").await;
    assert_eq!((rotated.len(), rotated[0]["targetId"].as_str(), rotated[0]["details"]["to"].clone()), (2, Some(b_id.as_str()), r["tokenInfo"]["id"].clone()));

    // Disabled: every token stops, and starts again once it's enabled.
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{sa}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert_eq!(call(port, "GET", "/api/bots", &c, "").await.0, 401);
    assert_eq!(call(port, "POST", &base, &admin, "{}").await.0, 409, "no new tokens while disabled");
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{sa}"), &admin, r#"{"status":"active"}"#).await.0, 200);
    assert_eq!(call(port, "GET", "/api/bots", &c, "").await.0, 200);
    assert_eq!((events(port, &admin, "service_account.disabled").await.len(), events(port, &admin, "service_account.enabled").await.len()), (1, 1));

    // Deleted: its tokens are revoked, and it's gone but still named in the log.
    let (code, v) = json_call(port, "DELETE", &format!("/api/service-accounts/{sa}"), &admin, "").await;
    assert_eq!((code, v["tokensRevoked"].clone()), (200, json!(2)), "{v}");
    assert_eq!(call(port, "GET", "/api/bots", &c, "").await.0, 401);
    assert_eq!(call(port, "GET", "/api/bots", &b, "").await.0, 401);
    assert_eq!(call(port, "GET", &format!("/api/service-accounts/{sa}"), &admin, "").await.0, 404);
    assert_eq!(call(port, "DELETE", &format!("/api/service-accounts/{sa}"), &admin, "").await.0, 404);
    let (_, list) = json_call(port, "GET", "/api/service-accounts", &admin, "").await;
    assert!(!list.to_string().contains(&sa), "{list}");
    let gone = events(port, &admin, "service_account.deleted").await;
    assert_eq!((gone[0]["targetId"].as_str(), gone[0]["details"]["name"].as_str()), (Some(sa.as_str()), Some("Nightly")));
    assert_eq!(app.db.user(&sa).map(|u| u.name), Some("Nightly".to_string()));
}

#[tokio::test]
async fn service_accounts_cannot_sign_in_or_do_a_persons_things() {
    let (port, app, admin, _) = serve_app().await;
    let sa = account(port, &admin, json!({ "name": "Robot", "role": "member" })).await;
    let (t, _) = token(port, &admin, &sa, json!({})).await;

    // No sign-in code works for it, even one written straight to the database.
    let code = random_hex(8);
    app.db.add_login_code(&users::hash(&code), &sa, users::OPERATOR, db::now() + 60_000);
    let (status, _, body) = call_with(port, "POST", "/api/auth/login", "", "", &json!({ "code": code }).to_string()).await;
    assert_eq!(status, 401, "{body}");
    // No session works for it either.
    let secret = users::new_secret(users::SESSION_PREFIX);
    let s = db::NewSession { user_id: &sa, token_hash: &users::hash(&secret), kind: "token", method: "code", idp_subject: None, idp_provider: None, label: None, ip: None, user_agent: None, expires_at: db::now() + 60_000, mfa: None };
    app.db.create_session(&s);
    assert_eq!(call(port, "GET", "/api/auth/me", &format!("Bearer {secret}"), "").await.0, 401);
    // Nor does a token with a typo, or someone else's prefix.
    assert_eq!(call(port, "GET", "/api/auth/me", &format!("{t}x"), "").await.0, 401);
    assert_eq!(call(port, "GET", "/api/auth/me", &t.replace("sbsa_", "sbs_"), "").await.0, 401);

    // Whatever its role, a person's routes are refused, and the refusal is logged.
    for (method, path) in [
        ("POST", "/api/auth/logout"),
        ("POST", "/api/auth/mfa/enroll"),
        ("GET", "/api/me/secrets"),
        ("GET", "/api/machine"),
        ("GET", "/api/billing"),
        ("POST", "/api/team/leave"),
        ("GET", "/api/service-accounts"),
        ("POST", "/api/service-accounts"),
        ("POST", "/api/bots"),
    ] {
        assert_eq!(call(port, method, path, &t, "{}").await.0, 403, "{method} {path}");
    }
    let denied = events(port, &admin, "access.denied").await;
    assert!(denied.iter().filter(|e| e["details"]["reason"] == "service_account" && e["actorId"] == json!(sa)).count() >= 9, "{denied:?}");
    // It still works.
    assert_eq!(call(port, "GET", "/api/auth/me", &t, "").await.0, 200);
}

#[tokio::test]
async fn delegates_manage_only_their_own_and_never_beyond_what_they_hold() {
    let (port, app, admin, _) = serve_app().await;
    let helpdesk = role(port, &admin, "Helpdesk", "member", &["users.manage"]).await;
    let auditor = role(port, &admin, "Auditor", "readonly", &["audit.view"]).await;
    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "member").await;
    let (_, plain) = user_with(port, &admin, "plain@example.com", "member").await;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{helpdesk}/users/{ana}"), &admin, "").await.0, 200);

    // Without users.manage, nothing.
    assert_eq!(call(port, "GET", "/api/service-accounts", &plain, "").await.0, 403);
    assert_eq!(call(port, "POST", "/api/service-accounts", &plain, r#"{"name":"X"}"#).await.0, 403);

    // A delegate can make one with what they hold, never more.
    let mine = account(port, &ana_auth, json!({ "name": "Ana's sync", "role": "Helpdesk" })).await;
    for (body, missing) in [(json!({ "name": "Peek", "role": "Auditor" }), json!(["audit.view"])), (json!({ "name": "Peek", "role": auditor }), json!(["audit.view"]))] {
        let (code, v) = json_call(port, "POST", "/api/service-accounts", &ana_auth, &body.to_string()).await;
        assert_eq!(code, 403, "{v}");
        let denied = events(port, &admin, "access.denied").await;
        assert_eq!((denied[0]["details"]["limit"].as_str(), denied[0]["details"]["missing"].clone()), (Some("service_account_escalation"), missing));
    }
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{mine}"), &ana_auth, r#"{"role":"Auditor"}"#).await.0, 403);
    let (code, v) = json_call(port, "PATCH", &format!("/api/service-accounts/{mine}"), &ana_auth, r#"{"name":"Ana's HR sync","description":"From HR"}"#).await;
    assert_eq!((code, v["name"].as_str()), (200, Some("Ana's HR sync")), "{v}");
    let upd = events(port, &admin, "service_account.updated").await;
    assert_eq!(upd[0]["details"]["changes"]["name"], json!({ "from": "Ana's sync", "to": "Ana's HR sync" }));

    // Only the ones they own; an admin's are out of reach, and only admins move ownership.
    let admins = account(port, &admin, json!({ "name": "Admin's", "role": "member" })).await;
    let (_, list) = json_call(port, "GET", "/api/service-accounts", &ana_auth, "").await;
    let ids: Vec<&str> = list["serviceAccounts"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, [mine.as_str()]);
    for (i, (method, path)) in [
        ("GET", format!("/api/service-accounts/{admins}")),
        ("PATCH", format!("/api/service-accounts/{admins}")),
        ("DELETE", format!("/api/service-accounts/{admins}")),
        ("GET", format!("/api/service-accounts/{admins}/tokens")),
        ("POST", format!("/api/service-accounts/{admins}/tokens")),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(call(port, method, &path, &ana_auth, "{}").await.0, 403, "{method}, route {i}");
    }
    let denied = events(port, &admin, "access.denied").await;
    assert_eq!(denied[0]["details"]["limit"].as_str(), Some("service_account_owner"));
    let body = json!({ "owner": users::OPERATOR }).to_string();
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{mine}"), &ana_auth, &body).await.0, 403, "can't hand it off");

    // Its tokens get at most what Ana holds now, whatever its role says.
    let (t, _) = token(port, &ana_auth, &mine, json!({})).await;
    assert_eq!(call(port, "GET", "/api/users", &t, "").await.0, 200);
    assert_eq!(call(port, "POST", "/api/service-accounts", &t, r#"{"name":"Child"}"#).await.0, 403, "it can't make service accounts");
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{helpdesk}/users/{ana}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/users", &t, "").await.0, 403, "Ana lost users.manage, so it did");
    let denied = events(port, &admin, "access.denied").await;
    assert_eq!(denied[0]["details"]["reason"].as_str(), Some("token_scope"));
    let (_, v) = json_call(port, "GET", &format!("/api/service-accounts/{mine}"), &admin, "").await;
    assert!(v["permissions"].as_array().unwrap().contains(&json!("users.manage")) && !v["effective"].as_array().unwrap().contains(&json!("users.manage")), "{v}");
    assert_eq!(call(port, "PUT", &format!("/api/roles/{helpdesk}/users/{ana}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/users", &t, "").await.0, 200);
    // A role grown after the fact is capped the same way.
    let body = json!({ "permissions": ["users.manage", "audit.view"] }).to_string();
    assert_eq!(call(port, "PATCH", &format!("/api/roles/{helpdesk}"), &admin, &body).await.0, 200);
    assert_eq!(call(port, "GET", "/api/audit", &t, "").await.0, 200, "Ana holds Helpdesk too");
    let lead = role(port, &admin, "Lead", "member", &["users.manage"]).await;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{lead}/users/{ana}"), &admin, "").await.0, 200);
    assert_eq!(call(port, "GET", "/api/audit", &t, "").await.0, 403, "Ana's Lead role has no audit.view");

    // Disabled, the owner lends nothing; an admin can hand the account to someone else.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert_eq!(call(port, "GET", "/api/auth/me", &t, "").await.0, 401);
    let failed = events(port, &admin, "auth.login_failed").await;
    assert!(failed.iter().any(|e| e["details"]["reason"] == "owner_inactive"), "{failed:?}");
    let (_, v) = json_call(port, "GET", &format!("/api/service-accounts/{mine}"), &admin, "").await;
    assert_eq!((v["ownerActive"].clone(), v["effective"].clone()), (json!(false), json!([])), "{v}");
    let (code, v) = json_call(port, "PATCH", &format!("/api/service-accounts/{mine}"), &admin, &body_owner(users::OPERATOR)).await;
    assert_eq!((code, v["owner"]["id"].as_str()), (200, Some(users::OPERATOR)), "{v}");
    assert_eq!(call(port, "GET", "/api/audit", &t, "").await.0, 200);
    let (_, v) = json_call(port, "PATCH", &format!("/api/service-accounts/{mine}"), &admin, &body_owner(&ana)).await;
    assert!(v.to_string().contains("active person"), "{v}");
    assert_eq!(app.db.service_account(&mine).unwrap().owner_id, users::OPERATOR);
}

fn body_owner(id: &str) -> String {
    json!({ "owner": id }).to_string()
}

#[tokio::test]
async fn a_team_service_account_acts_only_in_its_team() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, ada_auth) = user_with(port, &admin, "ada@example.com", "member").await;
    let (code, t) = json_call(port, "POST", "/api/teams", &admin, &json!({ "name": "Alpha", "owner": ada }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = t["id"].as_str().unwrap().to_string();
    let people = role(port, &admin, "Team people", "member", &["users.manage", "audit.view"]).await;
    let viewer = role(port, &admin, "Team viewer", "readonly", &["users.manage"]).await;
    let seats = app.db.active_seats();

    let body = json!({ "name": "Alpha HR", "role": viewer, "team": team }).to_string();
    assert_eq!(call(port, "POST", "/api/service-accounts", &admin, &body).await.0, 409, "a read-only team role does nothing");
    // The team's owner holds all of the team's permissions there, and can't give more.
    let body = json!({ "name": "Alpha HR", "role": "Team people", "team": team }).to_string();
    assert_eq!(call(port, "POST", "/api/service-accounts", &ada_auth, &body).await.0, 403, "Ada can't manage service accounts");
    let (code, v) = json_call(port, "POST", "/api/service-accounts", &admin, &body).await;
    assert_eq!(code, 201, "{v}");
    let sa = v["id"].as_str().unwrap().to_string();
    assert_eq!((v["team"]["id"].as_str(), v["teamRole"]["id"].as_str(), v["customRole"].clone()), (Some(team.as_str()), Some(people.as_str()), Value::Null), "{v}");
    assert_eq!((v["permissions"].clone(), v["teamPermissions"].clone()), (json!(["account", "read", "review", "write", "approve"]), json!(["users.manage"])), "only the team part applies there");

    let (tok, _) = token(port, &admin, &sa, json!({})).await;
    let (code, mine) = json_call(port, "GET", "/api/team", &tok, "").await;
    assert_eq!((code, mine["id"].as_str()), (200, Some(team.as_str())), "{mine}");
    assert!(mine["invites"].is_array(), "{mine}");
    assert!(!mine["members"].to_string().contains(&sa), "not on the team's list");
    let (code, inv) = json_call(port, "POST", "/api/team/invites", &tok, r#"{"email":"new@example.com"}"#).await;
    assert_eq!(code, 201, "{inv}");
    assert_eq!(call(port, "POST", "/api/team/invites", &tok, r#"{"email":"boss@example.com","role":"admin"}"#).await.0, 403, "a team delegate's limits");
    assert_eq!(call(port, "GET", "/api/users", &tok, "").await.0, 403, "not across the server");
    assert_eq!(call(port, "GET", "/api/audit", &tok, "").await.0, 403, "audit.view isn't a team permission");
    let invited = events(port, &admin, "team.invited").await;
    assert_eq!((invited[0]["actorId"].as_str(), invited[0]["authMethod"].as_str()), (Some(sa.as_str()), Some("service_token")));
    assert_eq!(app.db.active_seats(), seats, "takes no seat in the team either");
    assert!(app.db.team_member(&sa).is_none());

    // A token scoped without users.manage can't manage the team's people.
    let (read, _) = token(port, &admin, &sa, json!({ "scopes": ["read"] })).await;
    assert_eq!(call(port, "POST", "/api/team/invites", &read, r#"{"email":"two@example.com"}"#).await.0, 403);
    let (_, mine) = json_call(port, "GET", "/api/team", &read, "").await;
    assert!(mine.get("invites").is_none(), "{mine}");

    // A role a team's service account holds can't be deleted from under it.
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{people}"), &admin, "").await.0, 409);
    // Out of the team, its team role goes too, and it's no one's teammate.
    let (code, v) = json_call(port, "PATCH", &format!("/api/service-accounts/{sa}"), &admin, r#"{"team":null,"role":"member"}"#).await;
    assert_eq!((code, v["team"].clone(), v["teamRole"].clone()), (200, Value::Null, Value::Null), "{v}");
    assert_eq!(call(port, "GET", "/api/team", &tok, "").await.0, 404);
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{people}"), &admin, "").await.0, 200);
}

fn bot_ids(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().filter_map(|b| b["id"].as_str().map(String::from)).collect()
}

/// Opens `GET /api/events` as `who`. Returns the stream once it answered 200.
async fn stream(port: u16, who: &str) -> tokio::net::TcpStream {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!("GET /api/events HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nAuthorization: {who}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut first = [0u8; 12];
    s.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"HTTP/1.0 200");
    s
}

/// What the stream sends up to and including `needle`, within a few seconds.
async fn read_until(s: &mut tokio::net::TcpStream, needle: &str) -> String {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let read = async {
        while !String::from_utf8_lossy(&got).contains(needle) {
            let n = s.read(&mut buf).await.unwrap();
            assert!(n > 0, "stream closed");
            got.extend_from_slice(&buf[..n]);
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), read).await.expect("timed out on the stream");
    String::from_utf8_lossy(&got).into_owned()
}

async fn closes(mut s: tokio::net::TcpStream) -> bool {
    let mut rest = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), s.read_to_end(&mut rest)).await.is_ok()
}

#[tokio::test]
async fn scopes_hold_inside_routes_and_live_streams_end_with_their_token() {
    let (port, app, admin, _) = serve_app().await;
    let sa = account(port, &admin, json!({ "name": "Watcher", "role": "member" })).await;
    let bot = app.db.create_bot_owned("Ops", "#fff", "waddle", "claude", None, false, users::OPERATOR, Visibility::Shared);
    app.db.add_approval(&bot.id, "claude", "Bash", "shell", "git push", &json!({ "command": "git push" }), "git_push", "Pushes", db::now() + 60_000);

    // A token without `review` doesn't see pending approvals, through any route.
    let (all, _) = token(port, &admin, &sa, json!({})).await;
    let (read, _) = token(port, &admin, &sa, json!({ "scopes": ["read"] })).await;
    let (_, st) = json_call(port, "GET", "/api/state", &all, "").await;
    assert_eq!(st["approvals"].as_array().map(Vec::len), Some(1), "{st}");
    let (code, st) = json_call(port, "GET", "/api/state", &read, "").await;
    assert_eq!((code, st["approvals"].clone()), (200, json!([])), "{st}");
    assert_eq!(call(port, "GET", "/api/approvals", &read, "").await.0, 403);

    // A stream ends once its token would be refused: revoked, the account disabled, the
    // owner disabled, or the owner no longer able to read.
    let tid = |v: &Value| v["tokenInfo"]["id"].as_str().unwrap().to_string();
    let (t, v) = token(port, &admin, &sa, json!({})).await;
    let s = stream(port, &t).await;
    assert_eq!(call(port, "DELETE", &format!("/api/service-accounts/{sa}/tokens/{}", tid(&v)), &admin, "").await.0, 200);
    assert!(closes(s).await, "still streaming after revoke");

    let s = stream(port, &all).await;
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{sa}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert!(closes(s).await, "still streaming after the account was disabled");
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{sa}"), &admin, r#"{"status":"active"}"#).await.0, 200);

    let (ana, ana_auth) = user_with(port, &admin, "ana@example.com", "member").await;
    let helpdesk = role(port, &admin, "Helpdesk", "member", &["users.manage"]).await;
    assert_eq!(call(port, "PUT", &format!("/api/roles/{helpdesk}/users/{ana}"), &admin, "").await.0, 200);
    let hers = account(port, &ana_auth, json!({ "name": "Ana's", "role": "member" })).await;
    let (t, _) = token(port, &ana_auth, &hers, json!({})).await;
    let s = stream(port, &t).await;
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"role":"readonly"}"#).await.0, 200);
    let quiet = stream(port, &t).await;
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert!(closes(s).await && closes(quiet).await, "still streaming after the owner was disabled");
    // An expired token's stream ends too.
    let (t, v) = token(port, &admin, &sa, json!({})).await;
    let s = stream(port, &t).await;
    app.db.set_service_token_expiry(&tid(&v), db::now() - 1);
    assert!(closes(s).await, "still streaming after expiry");
}

#[tokio::test]
async fn a_team_service_account_shares_bots_only_within_its_team() {
    let (port, app, admin, _) = serve_app().await;
    let (ada, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (solo, _) = user_with(port, &admin, "solo@example.com", "member").await;
    let (code, t) = json_call(port, "POST", "/api/teams", &admin, &json!({ "name": "Alpha", "owner": ada }).to_string()).await;
    assert_eq!(code, 201, "{t}");
    let team = t["id"].as_str().unwrap().to_string();
    let teams_bot = app.db.create_bot_owned("Alpha ops", "#fff", "waddle", "claude", None, false, &ada, Visibility::Shared).id;
    let solos_bot = app.db.create_bot_owned("Solo desk", "#fff", "waddle", "claude", None, false, &solo, Visibility::Shared).id;

    let in_team = account(port, &admin, json!({ "name": "Alpha bot", "role": "member", "team": team })).await;
    let (tok, _) = token(port, &admin, &in_team, json!({})).await;
    let (_, list) = json_call(port, "GET", "/api/bots", &tok, "").await;
    let sees = bot_ids(&list);
    assert!(sees.contains(&teams_bot) && !sees.contains(&solos_bot), "{sees:?}");
    assert_eq!(call(port, "GET", &format!("/api/bots/{teams_bot}/messages"), &tok, "").await.0, 200);
    assert_eq!(call(port, "GET", &format!("/api/bots/{solos_bot}/messages"), &tok, "").await.0, 404);
    assert_eq!(call(port, "POST", &format!("/api/bots/{solos_bot}/messages"), &tok, r#"{"text":"hi"}"#).await.0, 404);

    // One across the server is in no team: as a person in none, it reaches no team's Bots.
    let org = account(port, &admin, json!({ "name": "Org bot", "role": "member" })).await;
    let (tok, _) = token(port, &admin, &org, json!({})).await;
    let (_, list) = json_call(port, "GET", "/api/bots", &tok, "").await;
    let sees = bot_ids(&list);
    assert!(!sees.contains(&teams_bot) && sees.contains(&solos_bot), "{sees:?}");
    assert_eq!(call(port, "GET", &format!("/api/bots/{teams_bot}/messages"), &tok, "").await.0, 404);

    // Out of the team, it's in none, at once, in streams already open too.
    let (tok, _) = token(port, &admin, &in_team, json!({})).await;
    let mut s = stream(port, &tok).await;
    app.send(json!({ "type": "probe", "botId": teams_bot, "n": "before-move" }));
    assert!(read_until(&mut s, "before-move").await.contains(&teams_bot), "the stream has the team's Bot");
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{in_team}"), &admin, r#"{"team":null}"#).await.0, 200);
    read_until(&mut s, "resync").await;
    app.send(json!({ "type": "probe", "botId": teams_bot, "n": "old-team" }));
    app.send(json!({ "type": "probe", "botId": solos_bot, "n": "no-team" }));
    let got = read_until(&mut s, "no-team").await;
    assert!(!got.contains("old-team"), "the old team's Bot still streams: {got}");
    assert_eq!(app.db.team_id_of(&in_team), None);
    let (tok, _) = token(port, &admin, &in_team, json!({})).await;
    assert_eq!(call(port, "GET", &format!("/api/bots/{teams_bot}/messages"), &tok, "").await.0, 404);
    assert!(app.db.team_members(&team).iter().all(|m| m.user_id != in_team), "never on the team's list");
}

#[tokio::test]
async fn a_read_token_never_streams_approvals() {
    let (port, app, admin, _) = serve_app().await;
    let sa = account(port, &admin, json!({ "name": "Watcher", "role": "member" })).await;
    let bot = app.db.create_bot_owned("Ops", "#fff", "waddle", "claude", None, false, users::OPERATOR, Visibility::Shared).id;
    let (all, _) = token(port, &admin, &sa, json!({})).await;
    let (read, _) = token(port, &admin, &sa, json!({ "scopes": ["read"] })).await;
    let (mut full, mut quiet) = (stream(port, &all).await, stream(port, &read).await);
    app.send(json!({ "type": "approval", "approval": { "id": "ap1", "botId": bot, "input": { "command": "secret-cmd" } } }));
    app.send(json!({ "type": "probe", "botId": bot, "n": "after-approval" }));
    assert!(read_until(&mut full, "after-approval").await.contains("secret-cmd"), "a token with review sees approvals");
    let got = read_until(&mut quiet, "after-approval").await;
    assert!(!got.contains("secret-cmd"), "a read token streamed an approval: {got}");
}

#[tokio::test]
async fn disabling_or_deleting_a_service_account_stops_its_runs() {
    use crate::deprovision_http_tests::{held_claude, run_token, send, until};
    let (port, app, admin, _) = serve_app().await;
    let env = held_claude(&app);
    let desk = app.db.create_bot_owned("Desk", "#fff", "waddle", "claude", None, false, users::OPERATOR, Visibility::Shared).id;
    let sa = account(port, &admin, json!({ "name": "Runner", "role": "member" })).await;
    let (tok, _) = token(port, &admin, &sa, json!({})).await;
    let path = format!("/api/service-accounts/{sa}");

    send(port, &tok, &desk, "for the script").await;
    run_token(&env).await;
    assert_eq!(call(port, "PATCH", &path, &admin, r#"{"status":"disabled"}"#).await.0, 200);
    until("its run on someone else's Bot went on after it was disabled", || !app.busy(&desk)).await;
    assert_eq!(events(port, &admin, "service_account.disabled").await[0]["details"]["runsStopped"], json!([desk]));

    assert_eq!(call(port, "PATCH", &path, &admin, r#"{"status":"active"}"#).await.0, 200);
    send(port, &tok, &desk, "again").await;
    run_token(&env).await;
    assert_eq!(call(port, "DELETE", &path, &admin, "").await.0, 200);
    until("its run went on after it was deleted", || !app.busy(&desk)).await;
    assert_eq!(events(port, &admin, "service_account.deleted").await[0]["details"]["runsStopped"], json!([desk]));
}

#[tokio::test]
async fn scheduled_work_stops_with_the_owner() {
    let (port, app, admin, _) = serve_app().await;
    let (ana, _) = user_with(port, &admin, "ana@example.com", "member").await;
    let hers = account(port, &admin, json!({ "name": "Nightly", "role": "member" })).await;
    assert_eq!(call(port, "PATCH", &format!("/api/service-accounts/{hers}"), &admin, &body_owner(&ana)).await.0, 200);
    assert_eq!(handover::blocked(&app.db, users::OPERATOR, Some(&hers)), None);
    // Its routines on someone else's Bot are refused once its owner is off, as its tokens are.
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert_eq!(handover::blocked(&app.db, users::OPERATOR, Some(&hers)), Some((handover::AUTHOR_DISABLED, hers.clone())));
    assert_eq!(call(port, "PATCH", &format!("/api/users/{ana}"), &admin, r#"{"status":"active"}"#).await.0, 200);
    assert_eq!(handover::blocked(&app.db, users::OPERATOR, Some(&hers)), None);
    assert_eq!(call(port, "DELETE", &format!("/api/service-accounts/{hers}"), &admin, "").await.0, 200);
    assert_eq!(handover::blocked(&app.db, users::OPERATOR, Some(&hers)), Some((handover::AUTHOR_DISABLED, hers)));
}
