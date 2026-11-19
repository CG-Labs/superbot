//! The SAML bridge end to end (ADR 0019): the real router against a mock OIDC broker
//! (Keycloak) whose ID tokens say which SAML IdP it used and that IdP's NameID. The SAML
//! hop is the broker's; botd checks the broker's signed answer and who vouched in it.

use crate::sso_http_tests::*;
use crate::tests::{audit_list, call, call_with};
use crate::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use std::collections::HashMap;

const ADFS: &str = "http://adfs.example.com/adfs/services/trust";
const NAME_ID: &str = "G-94f06852-D353-persistent";
/// How botd stores it: Keycloak lowercases the NameID it passes on, so botd compares without case.
const STORED: &str = "g-94f06852-d353-persistent";

/// What Keycloak puts in its ID token after a login brokered through its IdP `adfs`, with
/// User Session Note mappers for `identity_provider` and `identity_provider_identity`.
fn brokered() -> Value {
    json!({
        "sub": "kc-user-uuid", "azp": CLIENT, "preferred_username": "ada",
        "identity_provider": "adfs", "identity_provider_identity": NAME_ID,
        "email": "ada@example.com", "email_verified": true, "name": "Ada Lovelace",
    })
}

/// botd with one SAML bridge provider (a fresh id) on a mock broker realm, plus `others`.
async fn serve_bridge(extra: &[(&str, &str)], others: Vec<(String, String)>, also: &[String]) -> (u16, AppState, String, String, Arc<Oidc>) {
    let broker = mock_oidc("/realms/superbot", false, brokered()).await;
    let id = format!("s{}", random_hex(4));
    let mut settings = vec![("IDP_ALIAS", "adfs"), ("IDP_ENTITY_ID", ADFS)];
    settings.extend_from_slice(extra);
    let mut vars: HashMap<String, String> = provider_vars(&id, "saml", &broker.issuer, &broker.secret, &settings).into_iter().chain(others).collect();
    vars.insert("SSO_PROVIDERS".into(), also.iter().cloned().chain([id.clone()]).collect::<Vec<_>>().join(","));
    let (port, app, admin) = serve_vars(vars).await;
    (port, app, admin, id, broker)
}

#[tokio::test]
async fn saml_bridge_signs_in_only_people_the_saml_idp_vouched_for() {
    let (port, app, admin, id, broker) = serve_bridge(&[("LABEL", "Contoso")], vec![], &[]).await;

    let (_, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["providers"], json!([{ "id": id, "label": "Contoso", "type": "saml" }]));
    let (code, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/start"), "", "", "").await;
    assert_eq!(code, 303);
    let to_broker = url::Url::parse(&header(&head, "location").unwrap()).unwrap();
    let q: HashMap<_, _> = to_broker.query_pairs().into_owned().collect();
    assert!(to_broker.as_str().starts_with(&format!("{}/authorize?", broker.issuer)));
    assert_eq!((q["kc_idp_hint"].as_str(), q["scope"].as_str(), q["code_challenge_method"].as_str()), ("adfs", "openid profile email", "S256"), "straight to the SAML IdP");
    assert!(q["nonce"].len() >= 43 && !q.contains_key("prompt"));

    // Vouched for by the SAML IdP, but nobody linked them: the audit event names the NameID and the IdP.
    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login?error=sso_not_linked")));
    let f = &failures(port, &admin).await[0]["details"];
    assert_eq!((f["reason"].as_str(), f["subject"].as_str(), f["issuer"].as_str(), f["idp"].as_str()), (Some("not_linked"), Some(STORED), Some(ADFS), Some("saml")));

    let u = app.db.create_user(None, Some("ada@corp.example"), "Ada", Role::Member).unwrap();
    let (code, i) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": NAME_ID }).to_string()).await;
    assert_eq!(code, 201, "{i}");
    let i: Value = serde_json::from_str(&i).unwrap();
    assert_eq!((i["issuer"].as_str(), i["subject"].as_str()), (Some(ADFS), Some(STORED)), "linked under the SAML IdP, not the broker, as typed from the IdP");

    let (path, binder) = to_callback(port, &format!("/api/auth/sso/{id}/start")).await;
    let (code, head, _) = call_with(port, "GET", &path, "", &binder, "").await;
    assert_eq!((code, signed_in_as(port, &head).await), (200, Some(u.id.clone())));
    let login = &audit_list(&call(port, "GET", "/api/audit?action=auth.login", &admin, "").await.1)[0];
    assert_eq!((login["actorSubject"].as_str(), login["details"]["idp"].as_str(), login["details"]["provider"].as_str()), (Some(format!("{ADFS}|{STORED}").as_str()), Some("saml"), Some(id.as_str())));

    // Replayed: the same callback again finds no pending sign-in.
    let (_, head, _) = call_with(port, "GET", &path, "", &binder, "").await;
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_expired"));
    assert_eq!(failures(port, &admin).await[0]["details"]["reason"].as_str(), Some("unknown_state"));
    // An answer to a sign-in nobody started here, or one finished in another browser.
    let (_, head, _) = call_with(port, "GET", &format!("/api/auth/sso/{id}/callback?code=x&state=made-up"), "", "", "").await;
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_expired"));
    let (path, _) = to_callback(port, &format!("/api/auth/sso/{id}/start")).await;
    let (_, head, _) = call_with(port, "GET", &path, "", "", "").await;
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_expired"));

    // Disabled users can't sign in through the bridge either.
    call(port, "PATCH", &format!("/api/users/{}", u.id), &admin, &json!({ "status": "disabled" }).to_string()).await;
    assert_eq!(header(&web_sign_in(port, &id).await.1, "location").as_deref(), Some("/login?error=sso_not_allowed"));
}

#[tokio::test]
async fn broker_answers_for_another_idp_person_app_time_or_sign_in_are_refused() {
    let (port, app, admin, id, broker) = serve_bridge(&[], vec![], &[]).await;
    let u = app.db.create_user(None, Some("ada@corp.example"), "Ada", Role::Member).unwrap();
    let (code, _) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": NAME_ID }).to_string()).await;
    assert_eq!(code, 201);

    let now = db::now() / 1000;
    for (claims, page, reason) in [
        (json!({ "identity_provider": null, "identity_provider_identity": null }), "sso_wrong_account", "not_brokered"),
        (json!({ "identity_provider": "github", "identity_provider_identity": "583231" }), "sso_wrong_account", "not_brokered"),
        (json!({ "identity_provider_identity": null }), "sso_failed", "missing_subject"),
        (json!({ "iss": "https://sso.example.com/realms/other" }), "sso_failed", "wrong_issuer"),
        (json!({ "aud": "another-app", "azp": "another-app" }), "sso_failed", "wrong_audience"),
        (json!({ "iat": now - 7200, "exp": now - 3600 }), "sso_failed", "expired"),
        (json!({ "nonce": "an-answer-to-another-sign-in" }), "sso_failed", "nonce_mismatch"),
    ] {
        *broker.next.lock().unwrap() = claims;
        let (code, head) = web_sign_in(port, &id).await;
        assert_eq!((code, header(&head, "location")), (303, Some(format!("/login?error={page}"))), "{reason}");
        assert_eq!(failures(port, &admin).await[0]["details"]["reason"].as_str(), Some(reason));
    }
    *broker.next.lock().unwrap() = json!({});
    *broker.forge.lock().unwrap() = true;
    assert_eq!(header(&web_sign_in(port, &id).await.1, "location").as_deref(), Some("/login?error=sso_failed"));
    assert_eq!(failures(port, &admin).await[0]["details"]["reason"].as_str(), Some("bad_signature"));
    *broker.forge.lock().unwrap() = false;

    let (code, head) = web_sign_in(port, &id).await;
    assert_eq!((code, signed_in_as(port, &head).await), (200, Some(u.id)), "still fine afterwards");
}

#[tokio::test]
async fn the_app_signs_in_through_the_bridge_and_just_in_time_gets_the_role_set() {
    let (port, app, admin, id, broker) = serve_bridge(&[("JIT_ROLE", "readonly"), ("ALLOWED_DOMAINS", "example.com")], vec![], &[]).await;
    let verifier = B64.encode(random_bytes(32));
    let start = format!("/api/auth/sso/{id}/start?session=token&redirect=superbot%3A%2F%2Fauth&challenge={}&state=st-1&label=Phone", s256(&verifier));
    let back = |path: String| async move {
        let (code, head, _) = call_with(port, "GET", &path, "", "", "").await;
        assert_eq!(code, 303);
        url::Url::parse(&header(&head, "location").unwrap()).unwrap().query_pairs().into_owned().collect::<HashMap<String, String>>()
    };
    let redeem = |code: String| {
        let body = json!({ "sso": code, "verifier": verifier, "label": "Phone" }).to_string();
        async move { call(port, "POST", "/api/auth/login", "", &body).await }
    };

    // An email outside the allowed domains is refused before anyone is made.
    *broker.next.lock().unwrap() = json!({ "email": "ada@evil.example" });
    let q = back(to_callback(port, &start).await.0).await;
    assert_eq!(q.get("error").map(String::as_str), Some("sso_wrong_account"));
    assert!(app.db.find_user("ada@evil.example").is_none());
    *broker.next.lock().unwrap() = json!({});

    let q = back(to_callback(port, &start).await.0).await;
    assert_eq!(q["state"], "st-1");
    let (code, res) = redeem(q["code"].clone()).await;
    assert_eq!(code, 200, "{res}");
    let res: Value = serde_json::from_str(&res).unwrap();
    assert_eq!((res["user"]["role"].as_str(), res["user"]["email"].as_str(), res["user"]["name"].as_str()), (Some("readonly"), Some("ada@example.com"), Some("Ada Lovelace")));
    let (identity, user) = app.db.identity(ADFS, STORED).expect("stored under the IdP's entity ID and NameID");
    assert_eq!((identity.provider.as_str(), user.email.as_deref()), (id.as_str(), Some("ada@example.com")));
    let created = audit_list(&call(port, "GET", "/api/audit?action=user.created", &admin, "").await.1);
    assert!(created.iter().any(|e| e["details"]["subject"] == STORED && e["details"]["issuer"] == ADFS));

    // The same RBAC as everyone else: a read-only user can't make Bots.
    let auth = format!("Bearer {}", res["token"].as_str().unwrap());
    assert_eq!(call(port, "GET", "/api/bots", &auth, "").await.0, 200);
    assert_eq!(call(port, "POST", "/api/bots", &auth, r#"{"name":"Mine"}"#).await.0, 403);

    // Someone else at the IdP with the same email doesn't get Ada's account.
    *broker.next.lock().unwrap() = json!({ "identity_provider_identity": "_someone-else", "email": "ADA@example.com" });
    let q = back(to_callback(port, &start).await.0).await;
    assert_eq!((q.get("error").map(String::as_str), q.get("code")), (Some("sso_email_taken"), None));
    assert!(app.db.identity(ADFS, "_someone-else").is_none());
}

#[tokio::test]
async fn one_person_on_entra_and_saml_is_one_user() {
    let entra = mock_idp().await;
    let eid = format!("e{}", random_hex(4));
    let others = provider_vars(&eid, "entra", &entra.authority, &entra.secret, &[("TENANT", T1)]);
    let (port, app, admin, id, _) = serve_bridge(&[], others, std::slice::from_ref(&eid)).await;
    let (_, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    let types: Vec<String> = serde_json::from_str::<Value>(&body).unwrap()["providers"].as_array().unwrap().iter().map(|p| p["type"].as_str().unwrap().into()).collect();
    assert_eq!(types, ["entra", "saml"]);

    let u = app.db.create_user(None, Some("ada@corp.example"), "Ada", Role::Member).unwrap();
    for (provider, subject) in [(&eid, OID), (&id, NAME_ID)] {
        let (code, i) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": provider, "subject": subject }).to_string()).await;
        assert_eq!(code, 201, "{i}");
    }
    for provider in [&eid, &id] {
        let (code, head) = web_sign_in(port, provider).await;
        assert_eq!((code, signed_in_as(port, &head).await), (200, Some(u.id.clone())), "{provider}");
    }
    let (_, list) = call(port, "GET", &format!("/api/users/{}/identities", u.id), &admin, "").await;
    let issuers: Vec<String> = serde_json::from_str::<Value>(&list).unwrap().as_array().unwrap().iter().map(|i| i["issuer"].as_str().unwrap().into()).collect();
    assert!(issuers.contains(&ADFS.to_string()) && issuers.len() == 2, "{issuers:?}");
}
