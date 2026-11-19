//! GitHub and Apple sign-in end to end (ADR 0018): the real router against a mock GitHub
//! (OAuth endpoints and the REST API) and a mock Apple (discovery, keys, an authorize
//! step that posts its answer back, and a token endpoint that checks our ES256 secret).

use crate::sso::apple;
use crate::sso::jwt::test_keys::{jwks, keys};
use crate::sso_http_tests::*;
use crate::tests::{audit_list, call, call_with};
use crate::*;
use axum::extract::{Form, Query};
use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use std::collections::HashMap;
use std::sync::Mutex;

const GH_ID: &str = "583231";

#[derive(Default)]
struct Gh {
    url: String,
    secret: String,
    user: Mutex<Value>,
    emails: Mutex<Value>,
    /// Organization (lowercase) -> membership state.
    orgs: Mutex<HashMap<String, String>>,
    /// The membership endpoint fails.
    orgs_down: Mutex<bool>,
    /// code -> (PKCE challenge, redirect_uri)
    codes: Mutex<HashMap<String, (String, String)>>,
    live: Mutex<Vec<String>>,
    issued: Mutex<Vec<String>>,
    revoked: Mutex<Vec<String>>,
}

fn ada() -> Value {
    json!({ "id": 583231, "login": "ada-l", "name": "Ada Lovelace" })
}

fn ada_emails() -> Value {
    json!([{ "email": "ada@old.example", "primary": false, "verified": true }, { "email": "ada@example.com", "primary": true, "verified": true }])
}

async fn mock_github() -> Arc<Gh> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let gh = Arc::new(Gh { url, secret: random_hex(16), user: Mutex::new(ada()), emails: Mutex::new(ada_emails()), ..Default::default() });
    let signed_in = |gh: &Gh, h: &HeaderMap| h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).is_some_and(|t| gh.live.lock().unwrap().iter().any(|l| l == t));
    let (a, b, c, d, e, f) = (gh.clone(), gh.clone(), gh.clone(), gh.clone(), gh.clone(), gh.clone());
    let r = Router::new()
        .route(
            "/login/oauth/authorize",
            get(move |Query(q): Query<HashMap<String, String>>| async move {
                assert_eq!((q["client_id"].as_str(), q["code_challenge_method"].as_str(), q["code_challenge"].len()), (CLIENT, "S256", 43));
                assert!(!q.contains_key("nonce") && !q.contains_key("response_mode"), "GitHub is not OIDC: {q:?}");
                let code = random_hex(8);
                a.codes.lock().unwrap().insert(code.clone(), (q["code_challenge"].clone(), q["redirect_uri"].clone()));
                let mut u = url::Url::parse(&q["redirect_uri"]).unwrap();
                u.query_pairs_mut().extend_pairs([("code", &code), ("state", &q["state"])]);
                (StatusCode::SEE_OTHER, [(header::LOCATION, u.to_string())]).into_response()
            }),
        )
        .route(
            "/login/oauth/access_token",
            post(move |headers: HeaderMap, Form(f): Form<HashMap<String, String>>| async move {
                assert_eq!(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()), Some("application/json"));
                let found = b.codes.lock().unwrap().remove(&f["code"]);
                let ok = |(challenge, redirect): &(String, String)| {
                    f["client_id"] == CLIENT && f.get("client_secret") == Some(&b.secret) && &f["redirect_uri"] == redirect && &s256(&f["code_verifier"]) == challenge
                };
                if found.filter(ok).is_none() {
                    // GitHub answers errors with 200.
                    return Json(json!({ "error": "bad_verification_code", "error_description": "The code passed is incorrect or expired." }));
                }
                let token = format!("gho_{}", random_hex(18));
                b.live.lock().unwrap().push(token.clone());
                b.issued.lock().unwrap().push(token.clone());
                Json(json!({ "access_token": token, "token_type": "bearer", "scope": "read:org,read:user,user:email" }))
            }),
        )
        .route(
            "/api/user",
            get(move |h: HeaderMap| async move {
                if !signed_in(&c, &h) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                Json(c.user.lock().unwrap().clone()).into_response()
            }),
        )
        .route(
            "/api/user/emails",
            get(move |h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
                if !signed_in(&d, &h) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                // Paged like GitHub's: 30 by default, per_page up to 100.
                let n = |k: &str, default: usize| q.get(k).and_then(|v| v.parse().ok()).unwrap_or(default);
                let (per, page) = (n("per_page", 30).min(100), n("page", 1).max(1));
                let all = d.emails.lock().unwrap().as_array().cloned().unwrap_or_default();
                Json(all.into_iter().skip((page - 1) * per).take(per).collect::<Vec<_>>()).into_response()
            }),
        )
        .route(
            "/api/user/memberships/orgs/{org}",
            get(move |Path(org): Path<String>, h: HeaderMap| async move {
                if !signed_in(&e, &h) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                if *e.orgs_down.lock().unwrap() {
                    return StatusCode::BAD_GATEWAY.into_response();
                }
                match e.orgs.lock().unwrap().get(&org) {
                    Some(state) => Json(json!({ "state": state, "role": "member", "organization": { "login": org.to_uppercase() } })).into_response(),
                    None => (StatusCode::NOT_FOUND, Json(json!({ "message": "Not Found" }))).into_response(),
                }
            }),
        )
        .route(
            "/api/applications/{client}/token",
            delete(move |Path(client): Path<String>, h: HeaderMap, Json(body): Json<Value>| async move {
                let basic = format!("Basic {}", STANDARD.encode(format!("{CLIENT}:{}", f.secret)));
                if client != CLIENT || h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some(basic.as_str()) {
                    return StatusCode::UNAUTHORIZED;
                }
                let t = body["access_token"].as_str().unwrap_or_default().to_string();
                f.live.lock().unwrap().retain(|l| *l != t);
                f.revoked.lock().unwrap().push(t);
                StatusCode::NO_CONTENT
            }),
        );
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    gh
}

fn github_vars(id: &str, gh: &Gh, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let up = id.to_ascii_uppercase();
    crate::secrets::global().put(&format!("SSO_{up}_CLIENT_SECRET"), &gh.secret).unwrap();
    let mut v = vec![("TYPE", "github".to_string()), ("CLIENT_ID", CLIENT.into()), ("URL", gh.url.clone()), ("API_URL", format!("{}/api", gh.url))];
    v.extend(extra.iter().map(|(k, val)| (*k, val.to_string())));
    v.into_iter().map(|(k, val)| (format!("SSO_{up}_{k}"), val)).collect()
}

async fn serve_github(gh: &Gh, extra: &[(&str, &str)]) -> (u16, AppState, String, String) {
    let id = format!("h{}", random_hex(4));
    let vars = github_vars(&id, gh, extra).into_iter().chain([("SSO_PROVIDERS".into(), id.clone())]).collect();
    let (port, app, admin) = serve_vars(vars).await;
    (port, app, admin, id)
}

fn start_query(head: &str) -> (url::Url, HashMap<String, String>) {
    let u = url::Url::parse(&header(head, "location").unwrap()).unwrap();
    let q = u.query_pairs().into_owned().collect();
    (u, q)
}

/// Every token GitHub issued has been revoked (in the background, so wait a little).
async fn all_revoked(gh: &Gh) -> bool {
    for _ in 0..100 {
        if !gh.issued.lock().unwrap().is_empty() && *gh.issued.lock().unwrap() == *gh.revoked.lock().unwrap() && gh.live.lock().unwrap().is_empty() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

fn reason(events: &[Value]) -> Option<&str> {
    events.first()?["details"]["reason"].as_str()
}

#[tokio::test]
async fn github_signs_in_by_numeric_id_with_the_verified_primary_email_then_revokes_the_token() {
    let gh = mock_github().await;
    let (port, app, admin, id) = serve_github(&gh, &[]).await;

    let (_, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["providers"], json!([{ "id": id, "label": "GitHub Enterprise", "type": "github" }]));
    let (code, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/start"), "", "", "").await;
    assert_eq!(code, 303);
    let (to, q) = start_query(&head);
    assert!(to.as_str().starts_with(&format!("{}/login/oauth/authorize?", gh.url)));
    assert_eq!((q["scope"].as_str(), q["prompt"].as_str(), q["allow_signup"].as_str()), ("read:user user:email", "select_account", "false"));
    assert!(set_cookies(&head).iter().any(|c| c.starts_with("superbot_sso=")), "the same binder cookie as OIDC");

    // A real GitHub account nobody linked: refused, and the audit log says who it was.
    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login?error=sso_not_linked")));
    let f = failures(port, &admin).await;
    let d = &f[0]["details"];
    assert_eq!((d["subject"].as_str(), d["username"].as_str(), d["idp"].as_str(), d["issuer"].as_str()), (Some(GH_ID), Some("ada-l"), Some("github"), Some(gh.url.as_str())));
    assert!(all_revoked(&gh).await, "botd keeps no GitHub token");

    // Linked by the numeric id; the login can change hands, so it can't be the subject.
    let u = app.db.create_user(None, Some("ada@corp.example"), "Ada", Role::Member).unwrap();
    let link = |subject: &str| {
        let (admin, uid, body) = (admin.clone(), u.id.clone(), json!({ "provider": id, "subject": subject }).to_string());
        async move { call(port, "POST", &format!("/api/users/{uid}/identities"), &admin, &body).await }
    };
    assert_eq!(link("ada-l").await.0, 400);
    let (code, i) = link(GH_ID).await;
    assert_eq!(code, 201, "{i}");
    assert_eq!(serde_json::from_str::<Value>(&i).unwrap()["issuer"].as_str(), Some(gh.url.as_str()));
    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!((code, signed_in_as(port, &head).await), (200, Some(u.id.clone())));
    let logins = audit_list(&call(port, "GET", "/api/audit?action=auth.login", &admin, "").await.1);
    let d = &logins[0]["details"];
    assert_eq!((d["provider"].as_str(), d["idp"].as_str(), d["username"].as_str()), (Some(id.as_str()), Some("github"), Some("ada-l")));
    assert_eq!(logins[0]["actorSubject"].as_str(), Some(format!("{}|{GH_ID}", gh.url).as_str()));

    // Renamed on GitHub: still the same person.
    *gh.user.lock().unwrap() = json!({ "id": 583231, "login": "ada-renamed" });
    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!((code, signed_in_as(port, &head).await), (200, Some(u.id.clone())));
    // Someone else took the old login: a different id, so not Ada.
    *gh.user.lock().unwrap() = json!({ "id": 99, "login": "ada-l" });
    assert_eq!(header(&web_sign_in(port, &id).await.1, "location").as_deref(), Some("/login?error=sso_not_linked"));
    *gh.user.lock().unwrap() = ada();

    // Only the primary address counts, and only when GitHub verified it.
    for (emails, why) in [
        (json!([{ "email": "ada@example.com", "primary": true, "verified": false }, { "email": "ada@other.example", "primary": false, "verified": true }]), "unverified primary"),
        (json!([]), "no addresses"),
    ] {
        *gh.emails.lock().unwrap() = emails;
        assert_eq!(header(&web_sign_in(port, &id).await.1, "location").as_deref(), Some("/login?error=sso_wrong_account"), "{why}");
        assert_eq!(reason(&failures(port, &admin).await), Some("email_unverified"), "{why}");
    }
    // Past the first page: the primary is still found.
    let mut many: Vec<Value> = (0..150).map(|i| json!({ "email": format!("ada+{i}@example.org"), "primary": false, "verified": true })).collect();
    many.push(json!({ "email": "ada@example.com", "primary": true, "verified": true }));
    *gh.emails.lock().unwrap() = json!(many);
    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!((code, signed_in_as(port, &head).await), (200, Some(u.id.clone())), "primary on the second page");
    *gh.emails.lock().unwrap() = ada_emails();

    // GitHub refuses the code (here: botd has the wrong client secret).
    crate::secrets::global().put(&format!("SSO_{}_CLIENT_SECRET", id.to_ascii_uppercase()), "the-wrong-secret").unwrap();
    assert_eq!(header(&web_sign_in(port, &id).await.1, "location").as_deref(), Some("/login?error=sso_failed"));
    assert_eq!(reason(&failures(port, &admin).await), Some("code_exchange_failed"));
    assert!(all_revoked(&gh).await, "{:?} vs {:?}", gh.issued.lock().unwrap(), gh.revoked.lock().unwrap());
}

#[tokio::test]
async fn github_org_membership_gates_sign_in_and_just_in_time() {
    let gh = mock_github().await;
    let (port, app, admin, id) = serve_github(&gh, &[("ALLOWED_ORGS", "Acme, acme-labs"), ("JIT_ROLE", "member"), ("LABEL", "GitHub")]).await;
    let (_, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/start"), "", "", "").await;
    assert_eq!(start_query(&head).1["scope"], "read:user user:email read:org");

    // Real GitHub accounts, but not active members of an allowed org. Nobody is created.
    for (orgs, why) in [(vec![], "no orgs"), (vec![("acme", "pending")], "an invitation"), (vec![("evil", "active")], "another org")] {
        *gh.orgs.lock().unwrap() = orgs.into_iter().map(|(o, s)| (o.to_string(), s.to_string())).collect();
        let (code, head) = web_sign_in(port, &id).await;
        assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login?error=sso_wrong_account")), "{why}");
        assert_eq!(reason(&failures(port, &admin).await), Some("wrong_org"), "{why}");
        assert!(app.db.find_user("ada@example.com").is_none(), "{why}");
    }
    *gh.orgs_down.lock().unwrap() = true;
    *gh.orgs.lock().unwrap() = HashMap::from([("acme".into(), "active".into())]);
    assert_eq!(header(&web_sign_in(port, &id).await.1, "location").as_deref(), Some("/login?error=sso_failed"), "can't tell, so no");
    assert_eq!(reason(&failures(port, &admin).await), Some("idp_bad_response"));
    *gh.orgs_down.lock().unwrap() = false;

    // An active member of the second org: made just in time from the verified primary email.
    *gh.orgs.lock().unwrap() = HashMap::from([("acme-labs".into(), "active".into())]);
    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!(code, 200, "{head}");
    let user = app.db.find_user("ada@example.com").expect("made just in time");
    assert_eq!((user.role, user.name.as_str(), signed_in_as(port, &head).await), (Role::Member, "Ada Lovelace", Some(user.id.clone())));
    let (identity, _) = app.db.identity(&gh.url, GH_ID).expect("stored under the GitHub address and the numeric id");
    assert_eq!(identity.provider, id);
    let created = audit_list(&call(port, "GET", "/api/audit?action=user.created", &admin, "").await.1);
    assert!(created.iter().any(|e| e["details"]["subject"] == GH_ID && e["details"]["username"] == "ada-l" && e["actorKind"] == "system"));

    // Leaving the org locks a known identity out too.
    gh.orgs.lock().unwrap().clear();
    assert_eq!(header(&web_sign_in(port, &id).await.1, "location").as_deref(), Some("/login?error=sso_wrong_account"));
    assert!(all_revoked(&gh).await);
}

const TEAM: &str = "TEAM123456";
const KEY: &str = "KEY1234567";
const APPLE_SUB: &str = "001234.5678abcd.0123";

struct AppleIdp {
    issuer: String,
    /// The team key's public half, to check the client secrets botd signs.
    public: Vec<u8>,
    /// Claims to change in the next ID token; null removes one.
    next: Mutex<Value>,
    /// code -> (PKCE challenge, nonce, redirect_uri)
    codes: Mutex<HashMap<String, (String, String, String)>>,
    /// The claims of each client secret botd sent.
    secrets: Mutex<Vec<Value>>,
}

async fn mock_apple(public: Vec<u8>) -> Arc<AppleIdp> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let idp = Arc::new(AppleIdp { issuer: issuer.clone(), public, next: Mutex::new(json!({})), codes: Mutex::default(), secrets: Mutex::default() });
    let (a, b) = (idp.clone(), idp.clone());
    // Apple's discovery document, pointed here.
    let meta = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/auth/authorize"),
        "token_endpoint": format!("{issuer}/auth/token"),
        "jwks_uri": format!("{issuer}/auth/keys"),
        "response_modes_supported": ["query", "fragment", "form_post"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "id_token_signing_alg_values_supported": ["RS256"],
    });
    let r = Router::new()
        .route("/.well-known/openid-configuration", get(move || async move { Json(meta) }))
        .route("/auth/keys", get(|| async { Json(jwks(&[&keys()[0]])) }))
        .route(
            "/auth/authorize",
            // Apple's page then posts these to redirect_uri; the test does that part.
            get(move |Query(q): Query<HashMap<String, String>>| async move {
                assert_eq!((q["client_id"].as_str(), q["response_mode"].as_str(), q["response_type"].as_str(), q["code_challenge_method"].as_str()), (CLIENT, "form_post", "code", "S256"));
                let code = random_hex(8);
                a.codes.lock().unwrap().insert(code.clone(), (q["code_challenge"].clone(), q["nonce"].clone(), q["redirect_uri"].clone()));
                Json(json!({ "redirect_uri": q["redirect_uri"], "code": code, "state": q["state"] }))
            }),
        )
        .route(
            "/auth/token",
            post(move |Form(f): Form<HashMap<String, String>>| async move {
                let now = db::now() / 1000;
                let secret = apple::test_key::verify(f.get("client_secret").map(String::as_str).unwrap_or(""), &b.public);
                let secret_ok = secret.as_ref().is_some_and(|(h, c)| {
                    h["alg"] == "ES256" && h["kid"] == KEY && c["iss"] == TEAM && c["sub"] == CLIENT && c["aud"] == b.issuer.as_str() && c["exp"].as_i64().is_some_and(|e| e > now)
                });
                if let Some((_, c)) = &secret {
                    b.secrets.lock().unwrap().push(c.clone());
                }
                let found = b.codes.lock().unwrap().remove(&f["code"]);
                let ok = |(challenge, _, redirect): &(String, String, String)| {
                    secret_ok && f["grant_type"] == "authorization_code" && f["client_id"] == CLIENT && &f["redirect_uri"] == redirect && &s256(&f["code_verifier"]) == challenge
                };
                let Some((_, nonce, _)) = found.filter(ok) else {
                    return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_client" }))).into_response();
                };
                let mut claims = json!({
                    "iss": b.issuer, "aud": CLIENT, "sub": APPLE_SUB, "email": "ada@example.com", "email_verified": "true",
                    "is_private_email": "false", "nonce": nonce, "nonce_supported": true, "iat": now, "exp": now + 600,
                });
                let c = claims.as_object_mut().unwrap();
                c.extend(b.next.lock().unwrap().as_object().unwrap().clone());
                c.retain(|_, v| !v.is_null());
                Json(json!({ "token_type": "Bearer", "access_token": "a1", "refresh_token": "r1", "id_token": keys()[0].sign(&claims) })).into_response()
            }),
        );
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    idp
}

fn apple_vars(id: &str, idp: &AppleIdp, pem: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let up = id.to_ascii_uppercase();
    crate::secrets::global().put(&format!("SSO_{up}_PRIVATE_KEY"), pem).unwrap();
    let mut v = vec![("TYPE", "apple".to_string()), ("CLIENT_ID", CLIENT.into()), ("ISSUER", idp.issuer.clone()), ("TEAM_ID", TEAM.into()), ("KEY_ID", KEY.into())];
    v.extend(extra.iter().map(|(k, val)| (*k, val.to_string())));
    v.into_iter().map(|(k, val)| (format!("SSO_{up}_{k}"), val)).collect()
}

async fn serve_apple(idp: &AppleIdp, pem: &str, extra: &[(&str, &str)]) -> (u16, AppState, String, String) {
    let id = format!("a{}", random_hex(4));
    let vars = apple_vars(&id, idp, pem, extra).into_iter().chain([("SSO_PROVIDERS".into(), id.clone())]).collect();
    let (port, app, admin) = serve_vars(vars).await;
    (port, app, admin, id)
}

/// Apple's page posts its answer to botd: a cross-site POST, so the browser sends no
/// cookies with it. Returns where botd sent the browser next.
async fn apple_posts(form: &[(&str, &str)], to: &str) -> String {
    let res = http().post(to).form(form).send().await.unwrap();
    assert_eq!(res.status(), 303);
    assert!(res.headers().get_all(header::SET_COOKIE).iter().next().is_none(), "nothing is decided on the POST");
    res.headers()["location"].to_str().unwrap().to_string()
}

/// Starts at botd, signs in at Apple (with the name Apple posts the first time), and
/// returns the GET callback botd bounced to and the binder cookie (if any).
async fn apple_to_callback(port: u16, start: &str, user: Option<&str>) -> (String, String) {
    let (code, head, body) = call_with(port, "GET", start, "", "", "").await;
    assert_eq!(code, 303, "{head}\n{body}");
    let binder = set_cookies(&head).into_iter().find(|c| c.starts_with("superbot_sso=")).map(|c| format!("Cookie: {}\r\n", c.split(';').next().unwrap())).unwrap_or_default();
    let answer: Value = http().get(header(&head, "location").unwrap()).send().await.unwrap().json().await.unwrap();
    let (code, state) = (answer["code"].as_str().unwrap(), answer["state"].as_str().unwrap());
    let mut form = vec![("code", code), ("state", state)];
    form.extend(user.map(|u| ("user", u)));
    (apple_posts(&form, answer["redirect_uri"].as_str().unwrap()).await, binder)
}

async fn apple_web_sign_in(port: u16, id: &str, user: Option<&str>) -> (u16, String) {
    let (path, binder) = apple_to_callback(port, &format!("/api/auth/sso/{id}/start"), user).await;
    let (code, head, _) = call_with(port, "GET", &path, "", &binder, "").await;
    (code, head)
}

const ADA_POSTED: &str = r#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"ada@example.com"}"#;

#[tokio::test]
async fn apple_posts_back_and_signs_in_with_a_fresh_es256_client_secret() {
    let (pem, public) = apple::test_key::p8();
    let idp = mock_apple(public).await;
    let (port, app, admin, id) = serve_apple(&idp, &pem, &[("ALLOWED_DOMAINS", "example.com"), ("JIT_ROLE", "member")]).await;

    let (_, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["providers"], json!([{ "id": id, "label": "Apple", "type": "apple" }]));
    let (_, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/start"), "", "", "").await;
    let (to, q) = start_query(&head);
    assert!(to.as_str().starts_with(&format!("{}/auth/authorize?", idp.issuer)));
    assert_eq!((q["response_mode"].as_str(), q["scope"].as_str()), ("form_post", "name email"));
    assert!(q["nonce"].len() >= 43 && !q.contains_key("prompt"));

    // The first sign-in: Apple posts the name beside the code. botd bounces the browser to
    // the GET callback, where the binder cookie arrives and the sign-in is finished.
    let (path, binder) = apple_to_callback(port, &format!("/api/auth/sso/{id}/start"), Some(ADA_POSTED)).await;
    assert!(path.starts_with(&format!("/api/auth/sso/{id}/callback?code=")), "{path}");
    assert!(!binder.is_empty());
    let (code, head, _) = call_with(port, "GET", &path, "", &binder, "").await;
    assert_eq!(code, 200, "{head}");
    let user = app.db.find_user("ada@example.com").expect("made just in time");
    assert_eq!((user.role, user.name.as_str(), signed_in_as(port, &head).await), (Role::Member, "Ada Lovelace", Some(user.id.clone())));
    let (identity, _) = app.db.identity(&idp.issuer, APPLE_SUB).unwrap();
    assert_eq!(identity.provider, id);
    let secrets = idp.secrets.lock().unwrap().clone();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0]["exp"].as_i64().unwrap() - secrets[0]["iat"].as_i64().unwrap(), 300, "short-lived, made for this exchange");
    let logins = audit_list(&call(port, "GET", "/api/audit?action=auth.login", &admin, "").await.1);
    let sso = logins.iter().find(|e| e["details"]["method"] == "sso").unwrap();
    assert_eq!((sso["details"]["idp"].as_str(), sso["details"]["subject"].as_str()), (Some("apple"), Some(APPLE_SUB)));

    // Later sign-ins carry no name; the user keeps theirs.
    let (code, head) = apple_web_sign_in(port, &id, None).await;
    assert_eq!((code, signed_in_as(port, &head).await), (200, Some(user.id.clone())));
    assert_eq!(app.db.find_user("ada@example.com").unwrap().name, "Ada Lovelace");
    assert_eq!(idp.secrets.lock().unwrap().len(), 2, "a new secret each time");

    // The binder is still checked: finishing in another browser fails.
    let (path, _) = apple_to_callback(port, &format!("/api/auth/sso/{id}/start"), None).await;
    let (_, head, _) = call_with(port, "GET", &path, "", "", "").await;
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_expired"));

    // Real Apple Accounts this server doesn't take: Hide My Email, unverified. Nobody is created.
    for (claims, reason_, page) in [
        (json!({ "sub": "002", "email": "x7k2@privaterelay.appleid.com", "is_private_email": "true" }), "wrong_domain", "sso_wrong_account"),
        (json!({ "sub": "003", "email": "eve@example.com", "email_verified": "false" }), "email_unverified", "sso_wrong_account"),
        (json!({ "sub": "004", "email": null }), "email_unverified", "sso_wrong_account"),
        (json!({ "iss": "https://appleid.apple.com" }), "wrong_issuer", "sso_failed"),
        (json!({ "aud": "com.example.other" }), "wrong_audience", "sso_failed"),
    ] {
        *idp.next.lock().unwrap() = claims;
        let (code, head) = apple_web_sign_in(port, &id, Some(ADA_POSTED)).await;
        assert_eq!((code, header(&head, "location")), (303, Some(format!("/login?error={page}"))), "{reason_}");
        assert_eq!(reason(&failures(port, &admin).await), Some(reason_));
    }
    *idp.next.lock().unwrap() = json!({});
    assert_eq!(app.db.users().len(), 2, "the owner and Ada");

    // Cancelled at Apple: posted as an error, shown as cancelled.
    let (_, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/start"), "", "", "").await;
    let state = start_query(&head).1["state"].clone();
    let binder = format!("Cookie: {}\r\n", set_cookies(&head).into_iter().find(|c| c.starts_with("superbot_sso=")).unwrap().split(';').next().unwrap());
    let path = apple_posts(&[("error", "user_cancelled_authorize"), ("state", &state)], &format!("http://127.0.0.1:{port}/api/auth/sso/{id}/callback")).await;
    let (_, head, _) = call_with(port, "GET", &path, "", &binder, "").await;
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_cancelled"));

    // Only providers that use form_post take a POST.
    let to = apple_posts(&[("code", "x"), ("state", "y")], &format!("http://127.0.0.1:{port}/api/auth/sso/nope/callback")).await;
    assert_eq!(to, "/login?error=sso_failed");
}

#[tokio::test]
async fn apple_app_sign_in_links_a_hide_my_email_account_and_needs_a_good_key() {
    let (pem, public) = apple::test_key::p8();
    let idp = mock_apple(public).await;
    let (port, app, admin, id) = serve_apple(&idp, &pem, &[]).await;
    *idp.next.lock().unwrap() = json!({ "email": "x7k2@privaterelay.appleid.com", "is_private_email": true });

    // Not linked: refused, even with a name posted.
    assert_eq!(header(&apple_web_sign_in(port, &id, Some(ADA_POSTED)).await.1, "location").as_deref(), Some("/login?error=sso_not_linked"));
    assert_eq!(failures(port, &admin).await[0]["details"]["subject"].as_str(), Some(APPLE_SUB));

    let u = app.db.create_user(None, Some("ada@corp.example"), "Ada", Role::Member).unwrap();
    let (code, i) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": APPLE_SUB }).to_string()).await;
    assert_eq!(code, 201, "{i}");

    // The client app: same POST, then a one-time code to the app's redirect.
    let verifier = B64.encode(random_bytes(32));
    let start = format!("/api/auth/sso/{id}/start?session=token&redirect=superbot%3A%2F%2Fauth&challenge={}&state=st-1&label=Phone", s256(&verifier));
    let (path, binder) = apple_to_callback(port, &start, None).await;
    assert!(binder.is_empty());
    let (code, head, _) = call_with(port, "GET", &path, "", "", "").await;
    assert_eq!(code, 303);
    let back = url::Url::parse(&header(&head, "location").unwrap()).unwrap();
    let q: HashMap<String, String> = back.query_pairs().into_owned().collect();
    assert_eq!((back.scheme(), q["state"].as_str()), ("superbot", "st-1"));
    let (code, res) = call(port, "POST", "/api/auth/login", "", &json!({ "sso": q["code"], "verifier": verifier }).to_string()).await;
    assert_eq!(code, 200, "{res}");
    assert_eq!(serde_json::from_str::<Value>(&res).unwrap()["user"]["id"].as_str(), Some(u.id.as_str()));
    let (identity, _) = app.db.identity(&idp.issuer, APPLE_SUB).unwrap();
    assert_eq!(identity.email.as_deref(), Some("x7k2@privaterelay.appleid.com"), "the relay address is kept for display");

    // A key Apple doesn't know: Apple refuses the client secret.
    let up = id.to_ascii_uppercase();
    crate::secrets::global().put(&format!("SSO_{up}_PRIVATE_KEY"), &apple::test_key::p8().0).unwrap();
    assert_eq!(header(&apple_web_sign_in(port, &id, None).await.1, "location").as_deref(), Some("/login?error=sso_failed"));
    assert_eq!(reason(&failures(port, &admin).await), Some("code_exchange_failed"));

    // A key that isn't one: Apple isn't offered at all.
    crate::secrets::global().put(&format!("SSO_{up}_PRIVATE_KEY"), "not a key at all").unwrap();
    let (_, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["providers"], json!([]));
    let (_, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/start"), "", "", "").await;
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_unavailable"));
}

#[tokio::test]
async fn google_github_and_apple_side_by_side_sign_in_to_one_linked_user() {
    let (pem, public) = apple::test_key::p8();
    let (google, gh, apple_idp) = (mock_oidc("", false, google_claims()).await, mock_github().await, mock_apple(public).await);
    let ids = [format!("g{}", random_hex(4)), format!("h{}", random_hex(4)), format!("a{}", random_hex(4))];
    let mut vars: HashMap<String, String> = HashMap::from([("SSO_PROVIDERS".into(), ids.join(","))]);
    vars.extend(provider_vars(&ids[0], "google", &google.issuer, &google.secret, &[]));
    vars.extend(github_vars(&ids[1], &gh, &[("LABEL", "GitHub")]));
    vars.extend(apple_vars(&ids[2], &apple_idp, &pem, &[]));
    let (port, app, admin) = serve_vars(vars).await;

    let (_, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    let listed: Vec<(String, String)> = serde_json::from_str::<Value>(&body).unwrap()["providers"].as_array().unwrap().iter().map(|p| (p["label"].as_str().unwrap().into(), p["type"].as_str().unwrap().into())).collect();
    assert_eq!(listed, [("Google".into(), "google".into()), ("GitHub".into(), "github".into()), ("Apple".into(), "apple".into())]);

    // One person, three identities, linked to one user. Their emails differ; email never links.
    let u = app.db.create_user(None, Some("ada@corp.example"), "Ada", Role::Member).unwrap();
    for (id, subject) in [(&ids[0], "1077"), (&ids[1], GH_ID), (&ids[2], APPLE_SUB)] {
        let (code, i) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": subject }).to_string()).await;
        assert_eq!(code, 201, "{i}");
    }
    for (code, head) in [web_sign_in(port, &ids[0]).await, web_sign_in(port, &ids[1]).await, apple_web_sign_in(port, &ids[2], None).await] {
        assert_eq!((code, signed_in_as(port, &head).await), (200, Some(u.id.clone())));
    }
    let logins = audit_list(&call(port, "GET", "/api/audit?action=auth.login", &admin, "").await.1);
    let idps: Vec<&str> = logins.iter().take(3).filter_map(|e| e["details"]["idp"].as_str()).collect();
    assert_eq!(idps, ["apple", "github", "google"]);
    // The audit actor carries the IdP too, so any later action is attributed to it.
    let actors: Vec<(&str, &str, &str)> = logins.iter().take(3).map(|e| (e["authMethod"].as_str().unwrap(), e["idp"].as_str().unwrap(), e["idpProvider"].as_str().unwrap())).collect();
    assert_eq!(actors, [("sso", "apple", ids[2].as_str()), ("sso", "github", ids[1].as_str()), ("sso", "google", ids[0].as_str())]);
    let github = audit_list(&call(port, "GET", "/api/audit?idp=github", &admin, "").await.1);
    assert!(!github.is_empty() && github.iter().all(|e| e["actorId"] == u.id.as_str() && e["sessionId"].is_string()));

    // A GitHub sign-in can't be finished at Apple's callback, POST or GET.
    let (path, binder) = to_callback(port, &format!("/api/auth/sso/{}/start", ids[1])).await;
    let swapped = path.replace(&format!("/sso/{}/", ids[1]), &format!("/sso/{}/", ids[2]));
    let (_, head, _) = call_with(port, "GET", &swapped, "", &binder, "").await;
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_failed"));
    assert_eq!(reason(&failures(port, &admin).await), Some("wrong_provider"));
    // And GitHub's callback takes no POST.
    let to = apple_posts(&[("code", "x"), ("state", "y")], &format!("http://127.0.0.1:{port}/api/auth/sso/{}/callback", ids[1])).await;
    assert_eq!(to, "/login?error=sso_failed");
}
