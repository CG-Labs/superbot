//! SSO end to end (ADR 0014): the real router against a mock Entra tenant that serves
//! discovery, keys, an authorize endpoint, and a token endpoint checking PKCE.

use crate::sso::jwt::test_keys::{jwks, keys};
use crate::tests::{audit_list, call, call_with, serve_app_with};
use crate::*;
use axum::extract::{Form, Query};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

pub(super) const T1: &str = "11111111-1111-1111-1111-111111111111";
const T2: &str = "22222222-2222-2222-2222-222222222222";
pub(super) const OID: &str = "aaaaaaaa-0000-0000-0000-000000000001";
const OID2: &str = "aaaaaaaa-0000-0000-0000-000000000002";
pub(super) const CLIENT: &str = "client-1";

#[derive(Default)]
pub(super) struct Idp {
    pub(super) authority: String,
    pub(super) secret: String,
    /// Claims to change in the next ID token (and the key to sign it with).
    next: Mutex<(Value, usize)>,
    /// The next authorize answers with this error instead of a code.
    error: Mutex<Option<String>>,
    /// code -> (PKCE challenge, nonce, redirect_uri)
    codes: Mutex<HashMap<String, (String, String, String)>>,
}

pub(super) fn s256(v: &str) -> String {
    B64.encode(Sha256::digest(v.as_bytes()))
}

pub(super) async fn mock_idp() -> Arc<Idp> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let authority = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let idp = Arc::new(Idp { authority: authority.clone(), secret: random_hex(16), next: Mutex::new((json!({}), 0)), ..Default::default() });
    let (a, b, c) = (idp.clone(), idp.clone(), idp.clone());
    let r = Router::new()
        .route(
            "/{tenant}/v2.0/.well-known/openid-configuration",
            get(move |Path(tenant): Path<String>| async move {
                let base = format!("{authority}/{tenant}");
                Json(json!({
                    "issuer": format!("{authority}/{{tenantid}}/v2.0"),
                    "authorization_endpoint": format!("{base}/oauth2/v2.0/authorize"),
                    "token_endpoint": format!("{base}/oauth2/v2.0/token"),
                    "jwks_uri": format!("{authority}/discovery/v2.0/keys"),
                    "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt", "client_secret_basic"],
                }))
            }),
        )
        .route("/discovery/v2.0/keys", get(|| async { Json(jwks(&[&keys()[0]])) }))
        .route(
            "/{tenant}/oauth2/v2.0/authorize",
            get(move |Query(q): Query<HashMap<String, String>>| async move {
                let back = |pairs: &[(&str, &str)]| {
                    let mut u = url::Url::parse(&q["redirect_uri"]).unwrap();
                    u.query_pairs_mut().extend_pairs(pairs);
                    (StatusCode::SEE_OTHER, [(header::LOCATION, u.to_string())]).into_response()
                };
                if let Some(e) = a.error.lock().unwrap().take() {
                    return back(&[("error", &e), ("state", &q["state"])]);
                }
                assert_eq!((q["client_id"].as_str(), q["code_challenge_method"].as_str(), q["response_type"].as_str()), (CLIENT, "S256", "code"));
                let code = random_hex(8);
                a.codes.lock().unwrap().insert(code.clone(), (q["code_challenge"].clone(), q["nonce"].clone(), q["redirect_uri"].clone()));
                back(&[("code", &code), ("state", &q["state"])])
            }),
        )
        .route(
            "/{tenant}/oauth2/v2.0/token",
            post(move |Form(f): Form<HashMap<String, String>>| async move {
                let found = b.codes.lock().unwrap().remove(&f["code"]);
                let ok = |(challenge, _, redirect): &(String, String, String)| {
                    f["grant_type"] == "authorization_code"
                        && f["client_id"] == CLIENT
                        && f.get("client_secret") == Some(&b.secret)
                        && &f["redirect_uri"] == redirect
                        && &s256(&f["code_verifier"]) == challenge
                };
                let Some((_, nonce, _)) = found.filter(ok) else {
                    return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant" }))).into_response();
                };
                let now = db::now() / 1000;
                let mut claims = json!({
                    "iss": format!("{}/{T1}/v2.0", b.authority), "aud": CLIENT, "tid": T1, "oid": OID, "sub": "pairwise-sub",
                    "name": "Ada Lovelace", "email": "ada@example.com", "nonce": nonce, "iat": now, "nbf": now, "exp": now + 3600,
                });
                let (over, key) = b.next.lock().unwrap().clone();
                claims.as_object_mut().unwrap().extend(over.as_object().unwrap().clone());
                Json(json!({ "token_type": "Bearer", "id_token": keys()[key].sign(&claims) })).into_response()
            }),
        );
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    c
}

/// botd with one Entra provider (a fresh id per test, so their secrets don't mix) on `idp`.
async fn serve(idp: &Idp, extra: &[(&str, &str)]) -> (u16, AppState, String, String) {
    let id = format!("e{}", random_hex(4));
    let up = id.to_ascii_uppercase();
    crate::secrets::global().put(&format!("SSO_{up}_CLIENT_SECRET"), &idp.secret).unwrap();
    let mut vars: HashMap<String, String> = HashMap::from([
        ("SSO_PROVIDERS".into(), id.clone()),
        (format!("SSO_{up}_TYPE"), "entra".into()),
        (format!("SSO_{up}_CLIENT_ID"), CLIENT.into()),
        (format!("SSO_{up}_TENANT"), T1.into()),
        (format!("SSO_{up}_AUTHORITY"), idp.authority.clone()),
    ]);
    for (k, v) in extra {
        vars.insert(k.replace("{ID}", &up), v.to_string());
    }
    let (port, app, admin) = serve_vars(vars).await;
    (port, app, admin, id)
}

/// botd with the SSO settings in `vars` (SSO_PUBLIC_URL defaults to botd's own address).
pub(super) async fn serve_vars(mut vars: HashMap<String, String>) -> (u16, AppState, String) {
    let (port, app, admin, _) = serve_app_with(|a| {
        // The port is only known now, and the public URL must name it.
        let port = a.hosts[0].rsplit(':').next().unwrap().to_string();
        let public = vars.get("SSO_PUBLIC_URL").cloned().unwrap_or(format!("http://127.0.0.1:{port}")).replace("{PORT}", &port);
        vars.insert("SSO_PUBLIC_URL".into(), public);
        a.sso = sso::Sso::from_vars(&|k| vars.get(k).cloned()).unwrap();
        a.sso.refresh_gap = Duration::ZERO;
    })
    .await;
    (port, app, admin)
}

pub(super) fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()))
}

pub(super) fn set_cookies(head: &str) -> Vec<String> {
    head.lines().filter_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).map(|(_, v)| v.trim().to_string())).collect()
}

pub(super) fn http() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

/// Starts at botd, signs in at the IdP, and returns the callback path and the binder
/// cookie botd set (if any), ready to be sent back.
pub(super) async fn to_callback(port: u16, start: &str) -> (String, String) {
    let (code, head, body) = call_with(port, "GET", start, "", "", "").await;
    assert_eq!(code, 303, "{head}\n{body}");
    let to_idp = header(&head, "location").unwrap();
    let binder = set_cookies(&head).into_iter().find(|c| c.starts_with("superbot_sso=")).map(|c| format!("Cookie: {}\r\n", c.split(';').next().unwrap())).unwrap_or_default();
    let res = http().get(&to_idp).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let back = res.headers()["location"].to_str().unwrap().to_string();
    let path = back.strip_prefix(&format!("http://127.0.0.1:{port}")).unwrap_or(&back).to_string();
    (path, binder)
}

/// The whole web sign-in. Returns the callback's status and response head.
pub(super) async fn web_sign_in(port: u16, id: &str) -> (u16, String) {
    let (path, binder) = to_callback(port, &format!("/api/auth/sso/{id}/start")).await;
    let (code, head, _) = call_with(port, "GET", &path, "", &binder, "").await;
    (code, head)
}

pub(super) async fn failures(port: u16, admin: &str) -> Vec<Value> {
    audit_list(&call(port, "GET", "/api/audit?action=auth.login_failed", admin, "").await.1)
}

#[tokio::test]
async fn web_sign_in_needs_a_linked_identity_then_sets_a_session_cookie() {
    let idp = mock_idp().await;
    let (port, app, admin, id) = serve(&idp, &[]).await;

    let (code, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    assert_eq!((code, serde_json::from_str::<Value>(&body).unwrap()["providers"].clone()), (200, json!([{ "id": id, "label": "Microsoft", "type": "entra" }])));

    let (code, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/start"), "", "", "").await;
    assert_eq!(code, 303);
    let to_idp = url::Url::parse(&header(&head, "location").unwrap()).unwrap();
    let q: HashMap<_, _> = to_idp.query_pairs().into_owned().collect();
    assert!(to_idp.as_str().starts_with(&format!("{}/{T1}/oauth2/v2.0/authorize?", idp.authority)));
    assert_eq!(q["redirect_uri"], format!("http://127.0.0.1:{port}/api/auth/sso/{id}/callback"));
    assert_eq!((q["code_challenge_method"].as_str(), q["prompt"].as_str(), q["scope"].as_str()), ("S256", "select_account", "openid profile email"));
    assert!(q["state"].len() >= 43 && q["nonce"].len() >= 43 && q["code_challenge"].len() == 43);
    let binder = set_cookies(&head).into_iter().find(|c| c.starts_with("superbot_sso=")).unwrap();
    for attr in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/api/auth/sso", "Max-Age=600"] {
        assert!(binder.contains(attr), "{binder}");
    }

    // A real person from the right tenant, but nobody linked them: refused, by subject.
    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login?error=sso_not_linked")));
    let f = failures(port, &admin).await;
    assert_eq!((f[0]["details"]["reason"].as_str(), f[0]["details"]["subject"].as_str(), f[0]["details"]["tenant"].as_str()), (Some("not_linked"), Some(OID), Some(T1)));
    assert!(app.db.find_user("ada@example.com").is_none(), "just-in-time sign-up is off by default");

    // An admin links the identity to a user (whose email differs: email is never the key).
    let (code, u) = call(port, "POST", "/api/users", &admin, &json!({ "email": "ada@corp.example", "name": "Ada" }).to_string()).await;
    assert_eq!(code, 201);
    let uid = serde_json::from_str::<Value>(&u).unwrap()["id"].as_str().unwrap().to_string();
    let link = |body: Value| {
        let (admin, uid) = (admin.clone(), uid.clone());
        async move { call(port, "POST", &format!("/api/users/{uid}/identities"), &admin, &body.to_string()).await }
    };
    assert_eq!(link(json!({ "provider": id, "subject": "not-a-guid" })).await.0, 400);
    assert_eq!(link(json!({ "provider": id, "subject": OID, "tenant": T2 })).await.0, 400, "a tenant we don't trust");
    assert_eq!(link(json!({ "provider": "nope", "subject": OID })).await.0, 400);
    let (code, i) = link(json!({ "provider": id, "subject": OID.to_uppercase() })).await;
    assert_eq!(code, 201, "{i}");
    let i: Value = serde_json::from_str(&i).unwrap();
    assert_eq!((i["subject"].as_str(), i["tenant"].as_str(), i["issuer"].as_str()), (Some(OID), Some(T1), Some(format!("{}/{T1}/v2.0", idp.authority).as_str())));
    assert_eq!(link(json!({ "provider": id, "subject": OID })).await.0, 409, "linked once");

    let (path, binder) = to_callback(port, &format!("/api/auth/sso/{id}/start")).await;
    let (code, head, body) = call_with(port, "GET", &path, "", &binder, "").await;
    assert_eq!(code, 200, "{head}");
    assert!(body.contains("url=/"), "{body}");
    assert_eq!(header(&head, "cache-control").as_deref(), Some("no-store"));
    let cookies = set_cookies(&head);
    let session = cookies.iter().find(|c| c.starts_with("superbot_session=sbs_")).expect("a session cookie");
    assert!(session.contains("SameSite=Strict") && session.contains("HttpOnly"));
    assert!(cookies.iter().any(|c| c.starts_with("superbot_sso=;") && c.contains("Max-Age=0")), "binder cleared");
    let token = session.split(';').next().unwrap().trim_start_matches("superbot_session=");
    let (code, _, me) = call_with(port, "GET", "/api/auth/me", "", &format!("Cookie: superbot_session={token}\r\n"), "").await;
    let me: Value = serde_json::from_str(&me).unwrap();
    assert_eq!((code, me["user"]["id"].as_str(), me["session"]["method"].as_str()), (200, Some(uid.as_str()), Some("sso")));
    let logins = audit_list(&call(port, "GET", "/api/audit?action=auth.login", &admin, "").await.1);
    let d = &logins[0]["details"];
    assert_eq!((d["method"].as_str(), d["provider"].as_str(), d["subject"].as_str(), d["kind"].as_str()), (Some("sso"), Some(id.as_str()), Some(OID), Some("cookie")));
    assert_eq!(logins[0]["actorSubject"].as_str(), Some(format!("{}/{T1}/v2.0|{OID}", idp.authority).as_str()));
    let (_, seen) = call(port, "GET", &format!("/api/users/{uid}/identities"), &admin, "").await;
    assert!(serde_json::from_str::<Value>(&seen).unwrap()[0]["lastLoginAt"].is_i64());

    // The same callback again: the state was used up.
    let (code, head, _) = call_with(port, "GET", &path, "", &binder, "").await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login?error=sso_expired")));

    // Unlinked: refused again. Disabled users can't sign in either.
    let (code, _) = call(port, "DELETE", &format!("/api/users/{uid}/identities/{}", i["id"].as_str().unwrap()), &admin, "").await;
    assert_eq!(code, 200);
    assert_eq!(header(&web_sign_in(port, &id).await.1, "location").as_deref(), Some("/login?error=sso_not_linked"));
    link(json!({ "provider": id, "subject": OID })).await;
    call(port, "PATCH", &format!("/api/users/{uid}"), &admin, &json!({ "status": "disabled" }).to_string()).await;
    assert_eq!(header(&web_sign_in(port, &id).await.1, "location").as_deref(), Some("/login?error=sso_not_allowed"));
}

#[tokio::test]
async fn bad_tokens_and_stray_callbacks_are_refused() {
    let idp = mock_idp().await;
    let (port, app, admin, id) = serve(&idp, &[]).await;
    let u = app.db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
    let (code, _) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": OID }).to_string()).await;
    assert_eq!(code, 201);

    // Finished in another browser (no binder cookie): refused.
    let (path, _) = to_callback(port, &format!("/api/auth/sso/{id}/start")).await;
    let (_, head, _) = call_with(port, "GET", &path, "", "", "").await;
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_expired"));
    let (_, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/callback?code=x&state=made-up"), "", "", "").await;
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_expired"));

    // The IdP vouches, but the token is wrong in some way.
    for (claims, key, reason) in [
        (json!({ "tid": T2, "iss": format!("{}/{T2}/v2.0", idp.authority) }), 0, "wrong_tenant"),
        (json!({ "iss": format!("{}/{T2}/v2.0", idp.authority) }), 0, "wrong_issuer"),
        (json!({ "aud": "someone-else" }), 0, "wrong_audience"),
        (json!({ "exp": db::now() / 1000 - 3600 }), 0, "expired"),
        (json!({ "nonce": "replayed-from-elsewhere" }), 0, "nonce_mismatch"),
        (json!({}), 1, "unknown_key"),
    ] {
        *idp.next.lock().unwrap() = (claims, key);
        let (code, head) = web_sign_in(port, &id).await;
        assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login?error=sso_failed")), "{reason}");
        assert_eq!(failures(port, &admin).await[0]["details"]["reason"].as_str(), Some(reason));
    }
    *idp.next.lock().unwrap() = (json!({}), 0);

    // The person said no at the IdP.
    *idp.error.lock().unwrap() = Some("access_denied".into());
    let (path, binder) = to_callback(port, &format!("/api/auth/sso/{id}/start")).await;
    let (_, head, _) = call_with(port, "GET", &path, "", &binder, "").await;
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_cancelled"));

    // After all that, a good sign-in still works (only real failures count toward the limit).
    assert_eq!(web_sign_in(port, &id).await.0, 200);
    let n = failures(port, &admin).await.len();
    assert!(n >= 7, "{n}");
}

#[tokio::test]
async fn the_app_trades_a_one_time_code_and_its_verifier_for_a_token() {
    let idp = mock_idp().await;
    let (port, app, admin, id) = serve(&idp, &[("SSO_{ID}_JIT_ROLE", "member"), ("SSO_APP_REDIRECTS", "superbot://auth,http://localhost:8081/auth")]).await;
    let verifier = B64.encode(random_bytes(32));
    let start = |redirect: &str, challenge: &str| format!("/api/auth/sso/{id}/start?session=token&redirect={}&challenge={challenge}&state=st-1&label=Phone", url::form_urlencoded::byte_serialize(redirect.as_bytes()).collect::<String>());

    assert_eq!(call(port, "GET", &start("https://evil.example/auth", &s256(&verifier)), "", "").await.0, 400);
    assert_eq!(call(port, "GET", &start("superbot://auth", "short"), "", "").await.0, 400);

    let back = |path: String| async move {
        let (code, head, _) = call_with(port, "GET", &path, "", "", "").await;
        assert_eq!(code, 303);
        let mut u = url::Url::parse(&header(&head, "location").unwrap()).unwrap();
        let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
        u.set_query(None);
        (u.to_string(), q)
    };
    let (path, binder) = to_callback(port, &start("superbot://auth", &s256(&verifier))).await;
    assert!(binder.is_empty(), "the app flow sets no cookie");
    let (to, q) = back(path).await;
    assert_eq!((to.as_str(), q["state"].as_str()), ("superbot://auth", "st-1"));
    let handoff = q["code"].clone();
    assert!(handoff.starts_with("sbh_"));

    let redeem = |code: &str, verifier: &str| {
        let body = json!({ "sso": code, "verifier": verifier, "label": "Phone" }).to_string();
        async move { call(port, "POST", "/api/auth/login", "", &body).await }
    };
    assert_eq!(redeem(&handoff, "the-wrong-verifier-xxxxxxxxxxxxxxxxxxxxxxxx").await.0, 401);
    assert_eq!(redeem(&handoff, &verifier).await.0, 401, "a wrong verifier spends the code");

    let (path, _) = to_callback(port, &start("http://localhost:8081/auth", &s256(&verifier))).await;
    let (to, q) = back(path).await;
    assert_eq!(to, "http://localhost:8081/auth");
    let (code, res) = redeem(&q["code"], &verifier).await;
    assert_eq!(code, 200, "{res}");
    let res: Value = serde_json::from_str(&res).unwrap();
    assert!(res["token"].as_str().unwrap().starts_with("sbs_"));
    assert_eq!((res["user"]["role"].as_str(), res["user"]["email"].as_str(), res["session"]["label"].as_str()), (Some("member"), Some("ada@example.com"), Some("Phone")));
    let token = format!("Bearer {}", res["token"].as_str().unwrap());
    assert_eq!(call(port, "POST", "/api/bots", &token, r#"{"name":"From the app"}"#).await.0, 201);
    let made = &audit_list(&call(port, "GET", "/api/audit?action=bot.created", &admin, "").await.1)[0];
    assert_eq!(
        (made["authMethod"].as_str(), made["idpProvider"].as_str(), made["idp"].as_str(), made["sessionId"].as_str()),
        (Some("sso"), Some(id.as_str()), Some("entra"), res["session"]["id"].as_str()),
        "an app token from SSO acts with its IdP"
    );
    assert_eq!(redeem(&q["code"], &verifier).await.0, 401, "used once");
    let created = audit_list(&call(port, "GET", "/api/audit?action=user.created", &admin, "").await.1);
    assert!(created.iter().any(|e| e["details"]["reason"] == "just-in-time sign-up" && e["details"]["subject"] == OID && e["actorKind"] == "system"));

    // A code issued before an admin unlinks the identity is no longer good.
    let (path, _) = to_callback(port, &start("superbot://auth", &s256(&verifier))).await;
    let (_, q) = back(path).await;
    let (identity, user) = app.db.identity(&format!("{}/{T1}/v2.0", idp.authority), OID).unwrap();
    assert_eq!(call(port, "DELETE", &format!("/api/users/{}/identities/{}", user.id, identity.id), &admin, "").await.0, 200);
    assert_eq!(redeem(&q["code"], &verifier).await.0, 401, "unlinked since the code was issued");

    // Just in time never takes over an existing account with the same email.
    *idp.next.lock().unwrap() = (json!({ "oid": OID2, "email": "ADA@example.com" }), 0);
    let (path, _) = to_callback(port, &start("superbot://auth", &s256(&verifier))).await;
    let (_, q) = back(path).await;
    assert_eq!((q.get("error").map(String::as_str), q.get("code")), (Some("sso_email_taken"), None));
    assert!(app.db.identity(&format!("{}/{T1}/v2.0", idp.authority), OID2).is_none());
}

#[tokio::test]
async fn web_sign_in_moves_to_the_public_address_first() {
    let idp = mock_idp().await;
    let (port, _, _, id) = serve(&idp, &[("SSO_PUBLIC_URL", "http://localhost:{PORT}")]).await;
    let (code, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/start?label=Web"), "", "", "").await;
    assert_eq!((code, header(&head, "location")), (303, Some(format!("http://localhost:{port}/api/auth/sso/{id}/start?label=Web"))));
    assert!(set_cookies(&head).is_empty(), "the binder is set on the public address only");
}

#[tokio::test]
async fn the_client_secret_stays_with_botd() {
    let idp = mock_idp().await;
    let (port, _, admin, id) = serve(&idp, &[]).await;
    let name = format!("SSO_{}_CLIENT_SECRET", id.to_ascii_uppercase());
    assert!(crate::secrets::global().harness_env().iter().all(|(n, _)| n != &name), "never in a Bot's environment");
    let (_, list) = call(port, "GET", "/api/secrets", &admin, "").await;
    let listed: Value = serde_json::from_str(&list).unwrap();
    assert!(!list.contains(&idp.secret), "values are never listed");
    let entry = listed["secrets"].as_array().unwrap().iter().find(|s| s["name"] == name.as_str()).cloned();
    assert_eq!(entry.map(|s| s["forBots"].clone()), Some(json!(false)), "{listed}");
    assert_eq!(crate::secrets::redact::text(&format!("x {} y", idp.secret)), "x [redacted] y");
}

/// A mock IdP with one issuer (Google, Okta, Keycloak, …) at `{origin}{path}`.
pub(super) struct Oidc {
    pub(super) issuer: String,
    pub(super) secret: String,
    /// Claims every ID token carries, besides the protocol ones.
    claims: Value,
    /// Claims to change in the next ID token; null removes one.
    pub(super) next: Mutex<Value>,
    /// Sign the next ID tokens with a key the IdP doesn't publish, under the name of one it does.
    pub(super) forge: Mutex<bool>,
    /// code -> (PKCE challenge, nonce, redirect_uri)
    codes: Mutex<HashMap<String, (String, String, String)>>,
}

/// `basic`: the token endpoint takes the client secret only as HTTP Basic.
pub(super) async fn mock_oidc(path: &str, basic: bool, claims: Value) -> Arc<Oidc> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let issuer = format!("http://127.0.0.1:{}{path}", listener.local_addr().unwrap().port());
    let idp = Arc::new(Oidc { issuer: issuer.clone(), secret: random_hex(16), claims, next: Mutex::new(json!({})), forge: Mutex::new(false), codes: Mutex::default() });
    let (a, b) = (idp.clone(), idp.clone());
    let methods = if basic { json!(["client_secret_basic"]) } else { json!(["client_secret_post", "client_secret_basic"]) };
    let meta = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/keys"),
        "token_endpoint_auth_methods_supported": methods,
    });
    let r = Router::new()
        .route(&format!("{path}/.well-known/openid-configuration"), get(move || async move { Json(meta) }))
        .route(&format!("{path}/keys"), get(|| async { Json(jwks(&[&keys()[0]])) }))
        .route(
            &format!("{path}/authorize"),
            get(move |Query(q): Query<HashMap<String, String>>| async move {
                assert_eq!((q["client_id"].as_str(), q["code_challenge_method"].as_str(), q["response_type"].as_str()), (CLIENT, "S256", "code"));
                let code = random_hex(8);
                a.codes.lock().unwrap().insert(code.clone(), (q["code_challenge"].clone(), q["nonce"].clone(), q["redirect_uri"].clone()));
                let mut u = url::Url::parse(&q["redirect_uri"]).unwrap();
                u.query_pairs_mut().extend_pairs([("code", &code), ("state", &q["state"])]);
                (StatusCode::SEE_OTHER, [(header::LOCATION, u.to_string())]).into_response()
            }),
        )
        .route(
            &format!("{path}/token"),
            post(move |headers: axum::http::HeaderMap, Form(f): Form<HashMap<String, String>>| async move {
                let found = b.codes.lock().unwrap().remove(&f["code"]);
                let basic_ok = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok())
                    == Some(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT}:{}", b.secret)))).as_deref();
                let secret_ok = if basic { basic_ok && !f.contains_key("client_secret") } else { f.get("client_secret") == Some(&b.secret) };
                let ok = |(challenge, _, redirect): &(String, String, String)| {
                    secret_ok && f["grant_type"] == "authorization_code" && &f["redirect_uri"] == redirect && &s256(&f["code_verifier"]) == challenge
                };
                let Some((_, nonce, _)) = found.filter(ok) else {
                    return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant" }))).into_response();
                };
                let now = db::now() / 1000;
                let mut claims = json!({ "iss": b.issuer, "aud": CLIENT, "nonce": nonce, "iat": now, "exp": now + 3600 });
                let c = claims.as_object_mut().unwrap();
                c.extend(b.claims.as_object().unwrap().clone());
                c.extend(b.next.lock().unwrap().as_object().unwrap().clone());
                c.retain(|_, v| !v.is_null());
                let id_token = if *b.forge.lock().unwrap() { keys()[1].sign_with(&json!({ "alg": "RS256", "kid": keys()[0].kid }), &claims) } else { keys()[0].sign(&claims) };
                Json(json!({ "token_type": "Bearer", "id_token": id_token })).into_response()
            }),
        );
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    idp
}

/// Settings for a provider `id` of `ty` on `idp`, with its client secret saved.
pub(super) fn provider_vars(id: &str, ty: &str, issuer: &str, secret: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let up = id.to_ascii_uppercase();
    crate::secrets::global().put(&format!("SSO_{up}_CLIENT_SECRET"), secret).unwrap();
    let mut v = vec![(format!("SSO_{up}_TYPE"), ty.to_string()), (format!("SSO_{up}_CLIENT_ID"), CLIENT.to_string())];
    v.push((format!("SSO_{up}_{}", if ty == "entra" { "AUTHORITY" } else { "ISSUER" }), issuer.to_string()));
    v.extend(extra.iter().map(|(k, val)| (format!("SSO_{up}_{k}"), val.to_string())));
    v
}

/// The user a successful web callback signed in, by its session cookie.
pub(super) async fn signed_in_as(port: u16, head: &str) -> Option<String> {
    let session = set_cookies(head).into_iter().find(|c| c.starts_with("superbot_session=sbs_"))?;
    let (_, _, me) = call_with(port, "GET", "/api/auth/me", "", &format!("Cookie: {}\r\n", session.split(';').next().unwrap()), "").await;
    serde_json::from_str::<Value>(&me).ok()?["user"]["id"].as_str().map(String::from)
}

pub(super) fn google_claims() -> Value {
    json!({ "sub": "1077", "email": "ada@example.com", "email_verified": true, "hd": "example.com", "name": "Ada Lovelace" })
}

#[tokio::test]
async fn google_checks_the_workspace_domain_and_a_verified_email_before_sign_up() {
    let idp = mock_oidc("", false, google_claims()).await;
    let id = format!("g{}", random_hex(4));
    let vars = provider_vars(&id, "google", &idp.issuer, &idp.secret, &[("HOSTED_DOMAINS", "example.com"), ("JIT_ROLE", "member")]);
    let (port, app, admin) = serve_vars(vars.into_iter().chain([("SSO_PROVIDERS".into(), id.clone())]).collect()).await;

    let (_, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["providers"], json!([{ "id": id, "label": "Google", "type": "google" }]));
    let (code, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/start"), "", "", "").await;
    assert_eq!(code, 303);
    let to_idp = url::Url::parse(&header(&head, "location").unwrap()).unwrap();
    let q: HashMap<_, _> = to_idp.query_pairs().into_owned().collect();
    assert!(to_idp.as_str().starts_with(&format!("{}/authorize?", idp.issuer)));
    assert_eq!((q["hd"].as_str(), q["prompt"].as_str(), q["scope"].as_str(), q["code_challenge_method"].as_str()), ("example.com", "select_account", "openid profile email", "S256"));

    // Each is a real Google account, but not one this server takes. Nobody is created.
    for (claims, reason) in [
        (json!({ "hd": null }), "wrong_domain"),
        (json!({ "hd": "evil.example", "email": "ada@example.com" }), "wrong_domain"),
        (json!({ "email_verified": false }), "email_unverified"),
        (json!({ "iss": "https://accounts.google.com" }), "wrong_issuer"),
    ] {
        *idp.next.lock().unwrap() = claims;
        let (code, head) = web_sign_in(port, &id).await;
        let page = if reason == "wrong_issuer" { "sso_failed" } else { "sso_wrong_account" };
        assert_eq!((code, header(&head, "location")), (303, Some(format!("/login?error={page}"))), "{reason}");
        assert_eq!(failures(port, &admin).await[0]["details"]["reason"].as_str(), Some(reason));
        assert!(app.db.find_user("ada@example.com").is_none(), "{reason}");
    }
    *idp.next.lock().unwrap() = json!({});

    // A verified account in the Workspace domain: made just in time, then signed in.
    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!(code, 200, "{head}");
    let user = app.db.find_user("ada@example.com").expect("made just in time");
    assert_eq!((user.role, signed_in_as(port, &head).await), (Role::Member, Some(user.id.clone())));
    let (identity, _) = app.db.identity(&idp.issuer, "1077").expect("stored under the issuer and sub");
    assert_eq!((identity.provider.as_str(), identity.tenant), (id.as_str(), None));

    // Leaving the Workspace (or a token for another domain) locks a known identity out too.
    *idp.next.lock().unwrap() = json!({ "hd": "other.example" });
    assert_eq!(header(&web_sign_in(port, &id).await.1, "location").as_deref(), Some("/login?error=sso_wrong_account"));
}

#[tokio::test]
async fn generic_oidc_maps_claims_sends_basic_auth_and_restricts_email_domains() {
    let claims = json!({ "sub": "pairwise-1", "uid": "u-1", "mail": "ada@example.com", "email_verified": "true", "display": "Ada L." });
    let idp = mock_oidc("/realms/acme", true, claims).await;
    let id = format!("o{}", random_hex(4));
    let extra = [("SUBJECT_CLAIM", "uid"), ("EMAIL_CLAIM", "mail"), ("NAME_CLAIM", "display"), ("ALLOWED_DOMAINS", "example.com"), ("LABEL", "Acme SSO")];
    let vars = provider_vars(&id, "oidc", &idp.issuer, &idp.secret, &extra);
    let (port, app, admin) = serve_vars(vars.into_iter().chain([("SSO_PROVIDERS".into(), id.clone())]).collect()).await;

    let (_, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["providers"], json!([{ "id": id, "label": "Acme SSO", "type": "oidc" }]));
    let (_, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/start"), "", "", "").await;
    let q: HashMap<_, _> = url::Url::parse(&header(&head, "location").unwrap()).unwrap().query_pairs().into_owned().collect();
    assert!(!q.contains_key("prompt") && !q.contains_key("hd"), "{q:?}");

    // Valid, but nobody linked the mapped subject: the audit event names it for the admin.
    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login?error=sso_not_linked")), "the code exchange used Basic auth");
    assert_eq!(failures(port, &admin).await[0]["details"]["subject"].as_str(), Some("u-1"));

    let u = app.db.create_user(None, Some("ada@corp.example"), "Ada", Role::Member).unwrap();
    let (code, i) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": "u-1" }).to_string()).await;
    assert_eq!(code, 201, "{i}");
    assert_eq!(serde_json::from_str::<Value>(&i).unwrap()["issuer"].as_str(), Some(idp.issuer.as_str()));
    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!((code, signed_in_as(port, &head).await), (200, Some(u.id.clone())));
    let logins = audit_list(&call(port, "GET", "/api/audit?action=auth.login", &admin, "").await.1);
    assert_eq!(logins[0]["actorSubject"].as_str(), Some(format!("{}|u-1", idp.issuer).as_str()));

    for (claims, reason) in [
        (json!({ "mail": "ada@evil.example" }), "wrong_domain"),
        (json!({ "email_verified": "false" }), "email_unverified"),
        (json!({ "uid": null }), "missing_subject"),
    ] {
        *idp.next.lock().unwrap() = claims;
        let (_, head) = web_sign_in(port, &id).await;
        let page = if reason == "missing_subject" { "sso_failed" } else { "sso_wrong_account" };
        assert_eq!(header(&head, "location"), Some(format!("/login?error={page}")), "{reason}");
        assert_eq!(failures(port, &admin).await[0]["details"]["reason"].as_str(), Some(reason));
    }
}

#[tokio::test]
async fn entra_google_and_oidc_side_by_side_sign_in_to_one_linked_user() {
    let (entra, google, okta) = (mock_idp().await, mock_oidc("", false, google_claims()).await, mock_oidc("/oauth2/default", false, json!({ "sub": "00u1", "email": "ada@example.com", "email_verified": true })).await);
    let ids = [format!("e{}", random_hex(4)), format!("g{}", random_hex(4)), format!("o{}", random_hex(4))];
    let mut vars: HashMap<String, String> = HashMap::from([("SSO_PROVIDERS".into(), ids.join(","))]);
    vars.extend(provider_vars(&ids[0], "entra", &entra.authority, &entra.secret, &[("TENANT", T1)]));
    vars.extend(provider_vars(&ids[1], "google", &google.issuer, &google.secret, &[]));
    vars.extend(provider_vars(&ids[2], "oidc", &okta.issuer, &okta.secret, &[("LABEL", "Okta")]));
    let (port, app, admin) = serve_vars(vars).await;

    let (_, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    let listed: Vec<(String, String)> = serde_json::from_str::<Value>(&body).unwrap()["providers"].as_array().unwrap().iter().map(|p| (p["id"].as_str().unwrap().into(), p["label"].as_str().unwrap().into())).collect();
    assert_eq!(listed, [(ids[0].clone(), "Microsoft".into()), (ids[1].clone(), "Google".into()), (ids[2].clone(), "Okta".into())], "in SSO_PROVIDERS order");

    // One person, three identities, linked by an admin to the same user. Email never links them.
    let u = app.db.create_user(None, Some("ada@corp.example"), "Ada", Role::Member).unwrap();
    for (id, subject) in [(&ids[0], OID), (&ids[1], "1077"), (&ids[2], "00u1")] {
        let (code, i) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": subject }).to_string()).await;
        assert_eq!(code, 201, "{i}");
    }
    for id in &ids {
        let (code, head) = web_sign_in(port, id).await;
        assert_eq!((code, signed_in_as(port, &head).await), (200, Some(u.id.clone())), "{id}");
    }
    let logins = audit_list(&call(port, "GET", "/api/audit?action=auth.login", &admin, "").await.1);
    let providers: Vec<&str> = logins.iter().take(3).filter_map(|e| e["details"]["provider"].as_str()).collect();
    assert_eq!(providers, [ids[2].as_str(), ids[1].as_str(), ids[0].as_str()]);
    let (_, list) = call(port, "GET", &format!("/api/users/{}/identities", u.id), &admin, "").await;
    assert_eq!(serde_json::from_str::<Value>(&list).unwrap().as_array().unwrap().len(), 3);

    // A sign-in started with one provider can't be finished at another's callback.
    let (path, binder) = to_callback(port, &format!("/api/auth/sso/{}/start", ids[1])).await;
    let swapped = path.replace(&format!("/sso/{}/", ids[1]), &format!("/sso/{}/", ids[2]));
    let (_, head, _) = call_with(port, "GET", &swapped, "", &binder, "").await;
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_failed"));
    assert_eq!(failures(port, &admin).await[0]["details"]["reason"].as_str(), Some("wrong_provider"));
}

#[tokio::test]
async fn each_providers_sessions_put_its_idp_on_every_audit_event() {
    let (entra, google, okta) = (mock_idp().await, mock_oidc("", false, google_claims()).await, mock_oidc("/oauth2/default", false, json!({ "sub": "00u1", "email": "ada@example.com", "email_verified": true })).await);
    let ids = [format!("e{}", random_hex(4)), format!("g{}", random_hex(4)), format!("o{}", random_hex(4))];
    let mut vars: HashMap<String, String> = HashMap::from([("SSO_PROVIDERS".into(), ids.join(","))]);
    vars.extend(provider_vars(&ids[0], "entra", &entra.authority, &entra.secret, &[("TENANT", T1)]));
    vars.extend(provider_vars(&ids[1], "google", &google.issuer, &google.secret, &[]));
    vars.extend(provider_vars(&ids[2], "oidc", &okta.issuer, &okta.secret, &[]));
    let (port, app, admin) = serve_vars(vars).await;
    let u = app.db.create_user(None, Some("ada@corp.example"), "Ada", Role::Member).unwrap();
    let mut keys = Vec::new();
    for (id, subject) in ids.iter().zip([OID, "1077", "00u1"]) {
        let (code, i) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": subject }).to_string()).await;
        assert_eq!(code, 201, "{i}");
        keys.push(format!("{}|{subject}", serde_json::from_str::<Value>(&i).unwrap()["issuer"].as_str().unwrap()));
    }

    for (n, ty) in ["entra", "google", "oidc"].into_iter().enumerate() {
        let (code, head) = web_sign_in(port, &ids[n]).await;
        assert_eq!(code, 200, "{head}");
        let cookie = set_cookies(&head).into_iter().find(|c| c.starts_with("superbot_session=sbs_")).unwrap();
        let web = format!("Cookie: {}\r\nOrigin: http://127.0.0.1:{port}\r\n", cookie.split(';').next().unwrap());
        let (_, _, me) = call_with(port, "GET", "/api/auth/me", "", &web, "").await;
        let session = serde_json::from_str::<Value>(&me).unwrap()["session"].clone();
        assert_eq!(session["idpProvider"].as_str(), Some(ids[n].as_str()));
        let session = session["id"].as_str().unwrap().to_string();
        assert_eq!(call_with(port, "POST", "/api/bots", "", &web, &json!({ "name": ty }).to_string()).await.0, 201);

        let all = audit_list(&call(port, "GET", &format!("/api/audit?session={session}"), &admin, "").await.1);
        let actions: Vec<&str> = all.iter().map(|e| e["action"].as_str().unwrap()).collect();
        assert_eq!(actions, ["bot.created", "auth.login"], "{ty}");
        for e in &all {
            assert_eq!(
                (e["actorId"].as_str(), e["actorEmail"].as_str(), e["actorRole"].as_str(), e["authMethod"].as_str()),
                (Some(u.id.as_str()), Some("ada@corp.example"), Some("member"), Some("sso")),
                "{ty}"
            );
            assert_eq!((e["idpProvider"].as_str(), e["idp"].as_str(), e["actorSubject"].as_str()), (Some(ids[n].as_str()), Some(ty), Some(keys[n].as_str())), "{ty}");
        }
    }

    // Filter by provider, provider type, or the exact IdP subject.
    let q = |query: String| {
        let admin = admin.clone();
        async move { audit_list(&call(port, "GET", &format!("/api/audit?action=bot.created&{query}"), &admin, "").await.1) }
    };
    let names = |ev: Vec<Value>| ev.iter().map(|e| e["details"]["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(names(q("idp=google".into()).await), ["google"]);
    assert_eq!(names(q(format!("idpProvider={}", ids[2])).await), ["oidc"]);
    assert_eq!(names(q("method=sso".into()).await), ["oidc", "google", "entra"]);
    let subject: String = url::form_urlencoded::byte_serialize(keys[0].as_bytes()).collect();
    assert_eq!(names(q(format!("subject={subject}")).await), ["entra"]);

    // A failed SSO sign-in names the provider it was tried at.
    let (path, binder) = to_callback(port, &format!("/api/auth/sso/{}/start", ids[1])).await;
    let swapped = path.replace(&format!("/sso/{}/", ids[1]), &format!("/sso/{}/", ids[2]));
    call_with(port, "GET", &swapped, "", &binder, "").await;
    let failed = &failures(port, &admin).await[0];
    assert_eq!((failed["authMethod"].as_str(), failed["idpProvider"].as_str(), failed["idp"].as_str(), failed["actorId"].as_str()), (Some("sso"), Some(ids[2].as_str()), Some("oidc"), None));
}
