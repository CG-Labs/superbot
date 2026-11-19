//! SSO end to end (ADR 0013): the real router against a mock Entra tenant that serves
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

const T1: &str = "11111111-1111-1111-1111-111111111111";
const T2: &str = "22222222-2222-2222-2222-222222222222";
const OID: &str = "aaaaaaaa-0000-0000-0000-000000000001";
const OID2: &str = "aaaaaaaa-0000-0000-0000-000000000002";
const CLIENT: &str = "client-1";

#[derive(Default)]
struct Idp {
    authority: String,
    secret: String,
    /// Claims to change in the next ID token (and the key to sign it with).
    next: Mutex<(Value, usize)>,
    /// The next authorize answers with this error instead of a code.
    error: Mutex<Option<String>>,
    /// code -> (PKCE challenge, nonce, redirect_uri)
    codes: Mutex<HashMap<String, (String, String, String)>>,
}

fn s256(v: &str) -> String {
    B64.encode(Sha256::digest(v.as_bytes()))
}

async fn mock_idp() -> Arc<Idp> {
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
    let (port, app, admin, _) = serve_app_with(|a| {
        // The port is only known now, and the public URL must name it.
        let port = a.hosts[0].rsplit(':').next().unwrap().to_string();
        let public = vars.get("SSO_PUBLIC_URL").cloned().unwrap_or(format!("http://127.0.0.1:{port}")).replace("{PORT}", &port);
        vars.insert("SSO_PUBLIC_URL".into(), public);
        a.sso = sso::Sso::from_vars(&|k| vars.get(k).cloned()).unwrap();
        a.sso.refresh_gap = Duration::ZERO;
    })
    .await;
    (port, app, admin, id)
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()))
}

fn set_cookies(head: &str) -> Vec<String> {
    head.lines().filter_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).map(|(_, v)| v.trim().to_string())).collect()
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

/// Starts at botd, signs in at the IdP, and returns the callback path and the binder
/// cookie botd set (if any), ready to be sent back.
async fn to_callback(port: u16, start: &str) -> (String, String) {
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
async fn web_sign_in(port: u16, id: &str) -> (u16, String) {
    let (path, binder) = to_callback(port, &format!("/api/auth/sso/{id}/start")).await;
    let (code, head, _) = call_with(port, "GET", &path, "", &binder, "").await;
    (code, head)
}

async fn failures(port: u16, admin: &str) -> Vec<Value> {
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
