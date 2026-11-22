//! Native SAML end to end (ADR 0127): the real router as the SP, a test IdP that signs
//! responses, and the browser's POST to the ACS done by hand.

use crate::scim_http_tests::session_for;
use crate::sso::saml_sp::test_idp::{self, IDP, Response, SSO_URL};
use crate::sso_http_tests::*;
use crate::tests::{audit_list, call};
use crate::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::collections::HashMap;

const NAME_ID: &str = "00u1ADA-Persistent";
const STORED: &str = "00u1ada-persistent";

struct Sp {
    port: u16,
    app: AppState,
    admin: String,
    id: String,
    sp_entity: Option<String>,
}

impl Sp {
    fn acs(&self) -> String {
        format!("http://127.0.0.1:{}/api/auth/sso/{}/acs", self.port, self.id)
    }

    fn entity(&self) -> String {
        self.sp_entity.clone().unwrap_or_else(|| format!("http://127.0.0.1:{}/api/auth/sso/{}/metadata", self.port, self.id))
    }

    /// Starts a web sign-in: the AuthnRequest's ID, the RelayState, and the binder cookie.
    async fn start(&self) -> (String, String, String) {
        let (code, head, body) = crate::tests::call_with(self.port, "GET", &format!("/api/auth/sso/{}/start", self.id), "", "", "").await;
        assert_eq!(code, 303, "{head}\n{body}");
        let to_idp = url::Url::parse(&header(&head, "location").unwrap()).unwrap();
        assert_eq!(format!("{}://{}{}", to_idp.scheme(), to_idp.host_str().unwrap(), to_idp.path()), SSO_URL);
        let q: HashMap<_, _> = to_idp.query_pairs().into_owned().collect();
        let request = String::from_utf8(miniz_oxide::inflate::decompress_to_vec(&STANDARD.decode(&q["SAMLRequest"]).unwrap()).unwrap()).unwrap();
        assert!(request.contains(&format!(r#"AssertionConsumerServiceURL="{}""#, self.acs())), "{request}");
        assert!(request.contains(&format!("<saml:Issuer>{}</saml:Issuer>", self.entity())), "{request}");
        let id = request.split(" ID=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
        let binder = set_cookies(&head).into_iter().find(|c| c.starts_with("__Host-superbot_saml=")).expect("binder cookie");
        assert!(binder.contains("SameSite=None") && binder.contains("Secure") && binder.contains("HttpOnly"), "{binder}");
        (id, q["RelayState"].clone(), binder.split(';').next().unwrap().to_string())
    }

    /// The browser's POST to the ACS. Returns the status, where it goes next, and the head.
    async fn post(&self, response: Option<&str>, relay: Option<&str>, cookie: &str) -> (u16, String, String) {
        let mut form = vec![];
        form.extend(response.map(|r| ("SAMLResponse", r)));
        form.extend(relay.map(|r| ("RelayState", r)));
        let mut req = http().post(self.acs()).form(&form);
        if !cookie.is_empty() {
            req = req.header("cookie", cookie);
        }
        let res = req.send().await.unwrap();
        let head: String = res.headers().iter().map(|(k, v)| format!("{k}: {}\n", v.to_str().unwrap())).collect();
        let to = res.headers().get("location").map(|l| l.to_str().unwrap().to_string()).unwrap_or_default();
        (res.status().as_u16(), to, head)
    }

    /// A whole sign-in with the response `tweak` makes.
    async fn sign_in(&self, tweak: impl FnOnce(&mut Response)) -> (u16, String, String) {
        let (request, relay, cookie) = self.start().await;
        let mut r = Response::new(&self.acs(), &self.entity(), &request, db::now());
        tweak(&mut r);
        self.post(Some(&r.posted()), Some(&relay), &cookie).await
    }

    async fn last_failure(&self) -> Value {
        failures(self.port, &self.admin).await.remove(0)["details"].clone()
    }
}

/// botd with one native SAML provider (a fresh id), its IdP metadata imported as botctl does.
async fn serve(extra: &[(&str, &str)]) -> Sp {
    serve_with(extra, |_| {}).await
}

async fn serve_with(extra: &[(&str, &str)], tweak: impl FnOnce(&mut Auth)) -> Sp {
    let id = format!("n{}", random_hex(4));
    let up = id.to_ascii_uppercase();
    let mut vars: HashMap<String, String> = HashMap::from([("SSO_PROVIDERS".into(), id.clone()), (format!("SSO_{up}_TYPE"), "saml".into()), (format!("SSO_{up}_IDP_ENTITY_ID"), IDP.into())]);
    vars.extend(extra.iter().map(|(k, v)| (format!("SSO_{up}_{k}"), v.to_string())));
    let (port, app, admin) = serve_vars_with(vars, tweak).await;
    let sp = Sp { port, app, admin, id, sp_entity: None };
    let (_, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["providers"], json!([]), "not offered before its IdP metadata is in");
    let setup: Value = serde_json::from_str(&call(port, "GET", "/api/setup", &sp.admin, "").await.1).unwrap();
    let detail = setup["checklist"].as_array().unwrap().iter().find(|c| c["id"] == "signin").unwrap()["detail"].as_str().unwrap().to_string();
    assert!(detail.starts_with("Waiting for IdP metadata:") && !detail.contains("secret"), "{detail}");
    let (code, view) = call(port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", sp.id), &sp.admin, &json!({ "xml": test_idp::metadata() }).to_string()).await;
    assert_eq!(code, 200, "{view}");
    sp
}

#[tokio::test]
async fn native_saml_signs_in_a_linked_user_once_per_assertion() {
    let sp = serve(&[("LABEL", "Okta")]).await;
    let (port, admin, id) = (sp.port, sp.admin.clone(), sp.id.clone());

    let (_, body) = call(port, "GET", "/api/auth/sso", "", "").await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["providers"], json!([{ "id": id, "label": "Okta", "type": "saml" }]));
    let res = http().get(format!("http://127.0.0.1:{port}/api/auth/sso/{id}/metadata")).send().await.unwrap();
    assert_eq!(res.headers()["content-type"], "application/samlmetadata+xml");
    let md = res.text().await.unwrap();
    assert!(md.contains(&format!(r#"entityID="{}""#, sp.entity())) && md.contains(&format!(r#"Location="{}""#, sp.acs())), "{md}");

    // Signed by the IdP, but nobody linked the NameID yet.
    let (code, to, _) = sp.sign_in(|_| {}).await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_not_linked"));
    let failed = &failures(port, &admin).await[0];
    let f = &failed["details"];
    assert_eq!((f["reason"].as_str(), f["subject"].as_str(), f["issuer"].as_str(), f["idp"].as_str()), (Some("not_linked"), Some(STORED), Some(IDP), Some("saml")));
    assert_eq!((failed["actorSubject"].as_str(), failed["idpProvider"].as_str()), (Some(format!("{IDP}|{STORED}").as_str()), Some(id.as_str())));

    let u = sp.app.db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
    let (code, i) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": NAME_ID }).to_string()).await;
    assert_eq!(code, 201, "{i}");
    assert_eq!(serde_json::from_str::<Value>(&i).unwrap()["issuer"], IDP);

    let (request, relay, cookie) = sp.start().await;
    let first = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    let (code, to, head) = sp.post(Some(&first.posted()), Some(&relay), &cookie).await;
    assert_eq!((code, to.as_str()), (200, ""));
    assert_eq!(signed_in_as(port, &head).await, Some(u.id.clone()));
    let login = &audit_list(&call(port, "GET", "/api/audit?action=auth.login", &admin, "").await.1)[0];
    assert_eq!((login["actorId"].as_str(), login["idp"].as_str(), login["idpProvider"].as_str()), (Some(u.id.as_str()), Some("saml"), Some(id.as_str())));
    assert_eq!((login["actorEmail"].as_str(), login["details"]["subject"].as_str()), (Some("ada@example.com"), Some(STORED)));

    // The same post again: its sign-in is spent.
    let (_, to, _) = sp.post(Some(&first.posted()), Some(&relay), &cookie).await;
    assert_eq!(to, "/login?error=sso_expired");
    assert_eq!(sp.last_failure().await["reason"], "unknown_state");
    // The same assertion, answering a new request: still once only.
    let (_, to, _) = sp.sign_in(|r| r.assertion_id = first.assertion_id.clone()).await;
    assert_eq!(to, "/login?error=sso_failed");
    let f = sp.last_failure().await;
    assert_eq!((f["reason"].as_str(), f["assertion"].as_str()), (Some("replayed"), Some(first.assertion_id.as_str())));

    // Disabled (by an admin or a SCIM deprovision): the IdP's word isn't enough.
    call(port, "PATCH", &format!("/api/users/{}", u.id), &admin, &json!({ "status": "disabled" }).to_string()).await;
    let (_, to, _) = sp.sign_in(|_| {}).await;
    assert_eq!(to, "/login?error=sso_not_allowed");
    assert_eq!(sp.last_failure().await["reason"], "user_disabled");
}

#[tokio::test]
async fn forged_misdirected_and_stale_responses_are_refused() {
    let sp = serve_with(&[], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    let u = sp.app.db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
    call(sp.port, "POST", &format!("/api/users/{}/identities", u.id), &sp.admin, &json!({ "provider": sp.id, "subject": NAME_ID }).to_string()).await;
    let now = db::now();
    type Tweak = Box<dyn FnOnce(&mut Response)>;
    let cases: Vec<(&str, Tweak)> = vec![
        ("unsigned", Box::new(|r| r.sign_assertion = false)),
        ("bad_signature", Box::new(|r| r.signer = 1)),
        ("wrong_audience", Box::new(|r| r.audience = "https://other.example/sp".into())),
        ("wrong_recipient", Box::new(|r| r.recipient = "https://other.example/acs".into())),
        ("wrong_destination", Box::new(|r| r.destination = Some("https://other.example/acs".into()))),
        ("wrong_issuer", Box::new(|r| r.issuer = "https://evil.example/saml".into())),
        ("in_response_to_mismatch", Box::new(|r| r.in_response_to = "_other".into())),
        ("in_response_to_mismatch", Box::new(|r| r.confirm_in_response_to = "_other".into())),
        ("expired", Box::new(move |r| r.not_on_or_after = now - 300_000)),
        ("expired", Box::new(move |r| r.confirm_not_on_or_after = now - 300_000)),
        ("not_yet_valid", Box::new(move |r| r.not_before = now + 600_000)),
        ("transient_subject", Box::new(|r| r.name_id_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".into())),
        ("idp_error", Box::new(|r| r.status = "urn:oasis:names:tc:SAML:2.0:status:Requester".into())),
    ];
    for (want, tweak) in cases {
        let (code, to, head) = sp.sign_in(tweak).await;
        assert!(code == 303 && to.starts_with("/login?error="), "{want}: {code} {to}");
        assert!(signed_in_as(sp.port, &head).await.is_none(), "{want}");
        // Failures nobody vouched for are audited at most once a minute per client.
        if !["bad_signature", "idp_error"].contains(&want) {
            assert_eq!(sp.last_failure().await["reason"], want);
        }
    }

    // Wrapping: the signed assertion moved aside, an unsigned one in its place.
    let (request, relay, cookie) = sp.start().await;
    let r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    let signed = r.assertion_id.clone();
    let xml = r.xml_with(|a| {
        let evil = a.replace(&signed, "_evil").replace(NAME_ID, "admin");
        let evil = evil.split("<ds:Signature").next().unwrap().to_string() + &evil[evil.find("</ds:Signature>").unwrap() + 15..];
        format!("{evil}<samlp:Extensions>{a}</samlp:Extensions>")
    });
    let (_, to, _) = sp.post(Some(&STANDARD.encode(xml)), Some(&relay), &cookie).await;
    assert_eq!(to, "/login?error=sso_failed");

    // Another browser's sign-in (no binder cookie), and posts botd never asked for.
    let (request, relay, _) = sp.start().await;
    let r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    assert_eq!(sp.post(Some(&r.posted()), Some(&relay), "").await.1, "/login?error=sso_expired");
    assert_eq!(sp.post(Some(&r.posted()), None, "").await.1, "/login?error=sso_expired");
    let (_, relay, cookie) = sp.start().await;
    assert_eq!(sp.post(None, Some(&relay), &cookie).await.1, "/login?error=sso_failed");
    let (_, relay, cookie) = sp.start().await;
    assert_eq!(sp.post(Some("not base64 <xml>"), Some(&relay), &cookie).await.1, "/login?error=sso_failed");
    let all = failures(sp.port, &sp.admin).await;
    assert!(all.iter().all(|f| f["details"]["idp"] == "saml" && f["outcome"] == "failure"), "{all:?}");
}

#[tokio::test]
async fn posts_from_another_browser_or_never_asked_for_are_refused() {
    let sp = serve(&[]).await;
    let (request, relay, _) = sp.start().await;
    let r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    assert_eq!(sp.post(Some(&r.posted()), Some(&relay), "").await.1, "/login?error=sso_expired");
    assert_eq!(sp.last_failure().await["reason"], "binder_mismatch");
}

#[tokio::test]
async fn just_in_time_sign_up_follows_the_allow_list() {
    let sp = serve(&[("ALLOWED_DOMAINS", "example.com"), ("JIT_ROLE", "member")]).await;
    let (code, _, head) = sp.sign_in(|_| {}).await;
    assert_eq!(code, 200);
    let uid = signed_in_as(sp.port, &head).await.unwrap();
    let u = sp.app.db.user(&uid).unwrap();
    assert_eq!((u.email.as_deref(), u.name.as_str(), u.role), (Some("ada@example.com"), "Ada Lovelace", Role::Member));

    let (_, to, _) = sp
        .sign_in(|r| {
            r.name_id = "someone-else".into();
            r.attributes = vec![("email".into(), "eve@evil.example".into())];
        })
        .await;
    assert_eq!(to, "/login?error=sso_wrong_account");
    assert_eq!(sp.last_failure().await["reason"], "wrong_domain");
    let (_, to, _) = sp
        .sign_in(|r| {
            r.name_id = "no-email".into();
            r.attributes = vec![];
        })
        .await;
    assert_eq!(to, "/login?error=sso_wrong_account");
    assert_eq!(sp.last_failure().await["reason"], "email_unverified");
}

#[tokio::test]
async fn only_admins_see_or_replace_the_idp_metadata() {
    let sp = serve(&[]).await;
    let (port, admin, id) = (sp.port, sp.admin.clone(), sp.id.clone());
    let (code, v) = call(port, "GET", &format!("/api/sso/{id}/saml"), &admin, "").await;
    assert_eq!(code, 200, "{v}");
    let v: Value = serde_json::from_str(&v).unwrap();
    assert_eq!((v["acsUrl"].as_str(), v["spEntityId"].as_str(), v["source"].as_str(), v["ready"].as_bool()), (Some(sp.acs().as_str()), Some(sp.entity().as_str()), Some("botctl"), Some(true)));
    assert_eq!(v["idp"]["ssoUrl"], SSO_URL);
    assert_eq!(v["idp"]["certificates"][0]["sha256"].as_str().unwrap().len(), 95);
    let imported = audit_list(&call(port, "GET", "/api/audit?action=sso.saml_metadata_imported", &admin, "").await.1);
    assert_eq!((imported.len(), imported[0]["details"]["entityId"].as_str()), (1, Some(IDP)));
    assert_eq!(sp.app.db.setting(&format!("sso_saml_idp_metadata_{id}")).as_deref(), Some(test_idp::metadata().as_str()));

    let member = sp.app.db.create_user(None, Some("bob@example.com"), "Bob", Role::Member).unwrap();
    let bob = session_for(port, &admin, &member.id).await;
    assert_eq!(call(port, "GET", &format!("/api/sso/{id}/saml"), &bob, "").await.0, 403);
    assert_eq!(call(port, "PUT", &format!("/api/sso/{id}/saml/idp-metadata"), &bob, &json!({ "xml": test_idp::metadata() }).to_string()).await.0, 403);

    let other = test_idp::metadata_with("https://other.example/saml", &[&crate::sso::xmldsig::test_signer::signers()[0]], "");
    let (code, e) = call(port, "PUT", &format!("/api/sso/{id}/saml/idp-metadata"), &admin, &json!({ "xml": other }).to_string()).await;
    assert_eq!(code, 400, "{e}");
    assert_eq!(call(port, "GET", "/api/sso/nope/saml", &admin, "").await.0, 400);
}

#[tokio::test]
async fn metadata_from_a_file_is_read_at_startup_and_not_replaced() {
    let dir = std::env::temp_dir().join(format!("saml-{}", random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("idp.xml");
    std::fs::write(&file, test_idp::metadata()).unwrap();
    let id = format!("n{}", random_hex(4));
    let up = id.to_ascii_uppercase();
    let vars = HashMap::from([
        ("SSO_PROVIDERS".into(), id.clone()),
        (format!("SSO_{up}_TYPE"), "saml".into()),
        (format!("SSO_{up}_IDP_ENTITY_ID"), IDP.into()),
        (format!("SSO_{up}_IDP_METADATA_FILE"), file.to_string_lossy().into_owned()),
        (format!("SSO_{up}_SP_ENTITY_ID"), "urn:superbot:test".into()),
    ]);
    let (port, app, admin) = serve_vars(vars).await;
    let sp = Sp { port, app, admin, id, sp_entity: Some("urn:superbot:test".into()) };
    let (code, e) = call(port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", sp.id), &sp.admin, &json!({ "xml": test_idp::metadata() }).to_string()).await;
    assert_eq!(code, 409, "{e}");
    let u = sp.app.db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
    call(port, "POST", &format!("/api/users/{}/identities", u.id), &sp.admin, &json!({ "provider": sp.id, "subject": NAME_ID }).to_string()).await;
    let (request, relay, cookie) = sp.start().await;
    let r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    let (code, _, head) = sp.post(Some(&r.posted()), Some(&relay), &cookie).await;
    assert_eq!(code, 200);
    assert_eq!(signed_in_as(port, &head).await, Some(u.id));
    std::fs::remove_dir_all(dir).ok();
}
