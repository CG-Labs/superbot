//! Native SAML end to end (ADR 0127): the real router as the SP, a test IdP that signs
//! responses, and the browser's POST to the ACS done by hand.

use crate::scim_http_tests::session_for;
use crate::db::{NewIdentity, User};
use crate::sso::saml_slo::test_idp::Logout;
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

// Signed AuthnRequests and single logout (ADR 0137)

impl Sp {
    fn slo(&self) -> String {
        format!("http://127.0.0.1:{}/api/auth/sso/{}/slo", self.port, self.id)
    }

    /// Our certificate, as our metadata publishes it.
    async fn sp_cert(&self) -> crate::sso::xmldsig::Cert {
        let md = http().get(format!("http://127.0.0.1:{}/api/auth/sso/{}/metadata", self.port, self.id)).send().await.unwrap().text().await.unwrap();
        let cert = md.split("<ds:X509Certificate>").nth(1).expect("a signing certificate").split('<').next().unwrap();
        crate::sso::xmldsig::Cert::from_base64(cert).unwrap()
    }

    fn link(&self) -> User {
        let u = self.app.db.create_user(None, Some("ada@example.com"), "Ada", Role::Member).unwrap();
        self.app.db.link_identity(&u.id, &NewIdentity { provider: &self.id, issuer: IDP, subject: STORED, tenant: None, email: None, created_by: Some("test") }).unwrap();
        u
    }

    /// A web sign-in in the IdP session `index`: the session cookie header.
    async fn cookie(&self, index: &str) -> String {
        let (code, _, head) = self.sign_in(|r| r.session_index = index.into()).await;
        assert_eq!(code, 200, "{head}");
        let session = set_cookies(&head).into_iter().find(|c| c.starts_with("__Host-superbot_session=sbs_")).unwrap();
        format!("Cookie: {}\r\n", session.split(';').next().unwrap())
    }

    async fn who(&self, cookie: &str) -> Option<String> {
        let (_, _, me) = crate::tests::call_with(self.port, "GET", "/api/auth/me", "", cookie, "").await;
        serde_json::from_str::<Value>(&me).ok()?["user"]["id"].as_str().map(String::from)
    }

    /// The IdP's browser at our SLO URL over the redirect binding: the status and where it goes.
    async fn slo_get(&self, query: &str) -> (u16, String) {
        answered(http().get(format!("{}?{query}", self.slo())).send().await.unwrap())
    }

    async fn slo_post(&self, form: &HashMap<String, String>) -> (u16, String) {
        answered(http().post(self.slo()).form(form).send().await.unwrap())
    }

    async fn audit(&self, action: &str) -> Vec<Value> {
        audit_list(&call(self.port, "GET", &format!("/api/audit?action={action}"), &self.admin, "").await.1)
    }
}

/// The SLO URL's answer: its status and where it sends the browser. It never touches the
/// browser's cookie, which may be for a session the message didn't name.
fn answered(res: reqwest::Response) -> (u16, String) {
    assert!(res.headers().get("set-cookie").is_none(), "{:?}", res.headers());
    (res.status().as_u16(), res.headers().get("location").map(|l| l.to_str().unwrap().to_string()).unwrap_or_default())
}

/// A native provider whose IdP has an SLO URL.
async fn serve_slo(extra: &[(&str, &str)]) -> Sp {
    let sp = serve(extra).await;
    let xml = test_idp::with_slo(&test_idp::metadata());
    let (code, view) = call(sp.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", sp.id), &sp.admin, &json!({ "xml": xml }).to_string()).await;
    assert_eq!(code, 200, "{view}");
    sp
}

/// A redirect-binding message: its XML, after checking it is signed by `cert`.
fn signed_redirect(url: &str, cert: &crate::sso::xmldsig::Cert) -> (String, crate::sso::saml_sp::Redirected) {
    let (base, query) = url.split_once('?').unwrap();
    let r = crate::sso::saml_sp::from_redirect(query).unwrap();
    assert_eq!(r.verify(std::slice::from_ref(cert)), Ok(true), "signed by our key");
    (base.to_string(), r)
}

#[tokio::test]
async fn signed_authn_requests_verify_against_the_published_certificate() {
    let sp = serve(&[("SIGN_REQUESTS", "true")]).await;
    let md = http().get(format!("http://127.0.0.1:{}/api/auth/sso/{}/metadata", sp.port, sp.id)).send().await.unwrap().text().await.unwrap();
    assert!(md.contains(r#"AuthnRequestsSigned="true""#) && md.contains(r#"<md:KeyDescriptor use="signing">"#), "{md}");
    assert!(md.contains(&format!(r#"Location="{}""#, sp.slo())), "{md}");
    let cert = sp.sp_cert().await;
    assert_eq!(sp.sp_cert().await.sha256, cert.sha256, "made once, then kept");
    let made = sp.audit("sso.saml_sp_key_created").await;
    assert_eq!((made.len(), made[0]["details"]["certificate"].as_str()), (1, Some(cert.sha256.as_str())));
    let sealed = sp.app.db.setting(&format!("sso_saml_sp_key_{}", sp.id)).unwrap();
    assert!(crate::secrets::sealed::is_sealed(&sealed), "the key is sealed at rest");

    let (code, head, _) = crate::tests::call_with(sp.port, "GET", &format!("/api/auth/sso/{}/start", sp.id), "", "", "").await;
    assert_eq!(code, 303);
    let (to, r) = signed_redirect(&header(&head, "location").unwrap(), &cert);
    assert_eq!(to, SSO_URL);
    assert!(r.xml.contains("<samlp:AuthnRequest") && r.relay.is_some(), "{}", r.xml);
    let q: HashMap<_, _> = url::Url::parse(&header(&head, "location").unwrap()).unwrap().query_pairs().into_owned().collect();
    assert_eq!(q["SigAlg"], crate::sso::xmldsig::RSA_SHA256);
    // Still signs in as before: the IdP's half doesn't change.
    let u = sp.link();
    assert_eq!(sp.who(&sp.cookie("_s1").await).await, Some(u.id));

    let (_, v) = call(sp.port, "GET", &format!("/api/sso/{}/saml", sp.id), &sp.admin, "").await;
    let v: Value = serde_json::from_str(&v).unwrap();
    assert_eq!((v["signRequests"].as_bool(), v["spKey"]["from"].as_str(), v["spKey"]["certificate"]["sha256"].as_str()), (Some(true), Some("generated"), Some(cert.sha256.as_str())));
    assert_eq!((v["sloUrl"].as_str(), v["singleLogout"].as_bool()), (Some(sp.slo().as_str()), Some(false)), "the IdP has no SLO URL");

    // Unsigned, the redirect has no signature, and an IdP that wants one is refused at import.
    let plain = serve(&[]).await;
    let (_, head, _) = crate::tests::call_with(plain.port, "GET", &format!("/api/auth/sso/{}/start", plain.id), "", "", "").await;
    assert!(!header(&head, "location").unwrap().contains("Signature="));
    let wants = test_idp::metadata_with(IDP, &[&crate::sso::xmldsig::test_signer::signers()[0]], r#" WantAuthnRequestsSigned="true""#);
    let (code, e) = call(plain.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", plain.id), &plain.admin, &json!({ "xml": wants }).to_string()).await;
    assert!(code == 400 && e.contains("SIGN_REQUESTS"), "{code} {e}");
    let (code, e) = call(sp.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", sp.id), &sp.admin, &json!({ "xml": wants }).to_string()).await;
    assert_eq!(code, 200, "{e}");
}

#[tokio::test]
async fn an_idp_logout_request_revokes_the_sessions_it_names_once() {
    let sp = serve_slo(&[]).await;
    let u = sp.link();
    let (first, second) = (sp.cookie("_s1").await, sp.cookie("_s2").await);
    assert_eq!((sp.who(&first).await, sp.who(&second).await), (Some(u.id.clone()), Some(u.id.clone())));
    let cert = sp.sp_cert().await;
    let now = db::now();

    // The IdP ends its session _s1: only the SuperBot session it made goes.
    let l = Logout::request(&sp.slo(), NAME_ID, Some("_s1"), now);
    let (code, to) = sp.slo_get(&l.redirect()).await;
    assert_eq!(code, 303, "{to}");
    let (base, answer) = signed_redirect(&to, &cert);
    assert_eq!((base.as_str(), answer.param, answer.relay.as_deref()), (test_idp::SLO_URL, "SAMLResponse", Some("idp-relay")));
    assert!(answer.xml.contains(&format!(r#"InResponseTo="{}""#, l.id)) && answer.xml.contains("status:Success"), "{}", answer.xml);
    assert_eq!((sp.who(&first).await, sp.who(&second).await), (None, Some(u.id.clone())));
    let slo = &sp.audit("auth.slo").await[0];
    assert_eq!((slo["actorId"].as_str(), slo["actorSubject"].as_str()), (Some(u.id.as_str()), Some(format!("{IDP}|{STORED}").as_str())));
    assert_eq!((slo["details"]["revoked"].as_u64(), slo["details"]["requestId"].as_str(), slo["details"]["sessionIndexes"].clone()), (Some(1), Some(l.id.as_str()), json!(["_s1"])));

    // The same message again, from elsewhere, unsigned, or badly signed: refused, and kept.
    let refused = |code: u16| assert_eq!(code, 400);
    refused(sp.slo_get(&l.redirect()).await.0);
    assert_eq!(sp.audit("auth.slo_failed").await[0]["details"]["reason"], "replayed");
    refused(sp.slo_get(&Logout { issuer: "https://evil.example/saml".into(), ..Logout::request(&sp.slo(), NAME_ID, None, now) }.redirect()).await.0);
    assert_eq!(sp.audit("auth.slo_failed").await[0]["details"]["reason"], "wrong_issuer");
    refused(sp.slo_get(&Logout { signer: None, ..Logout::request(&sp.slo(), NAME_ID, None, now) }.redirect()).await.0);
    assert_eq!(sp.audit("auth.slo_failed").await[0]["details"]["reason"], "unsigned");
    refused(sp.slo_get(&Logout { signer: Some(1), ..Logout::request(&sp.slo(), NAME_ID, None, now) }.redirect()).await.0);
    refused(sp.slo_post(&Logout { signer: Some(1), ..Logout::request(&sp.slo(), NAME_ID, None, now) }.post()).await.0);
    refused(sp.slo_get(&Logout { destination: Some("https://other.example/slo".into()), ..Logout::request(&sp.slo(), NAME_ID, None, now) }.redirect()).await.0);
    refused(sp.slo_get(&Logout { issued_ms: now - 3_600_000, ..Logout::request(&sp.slo(), NAME_ID, None, now) }.redirect()).await.0);
    refused(sp.slo_get("SAMLRequest=not-deflate").await.0);
    // Someone else, or another IdP session of Ada's: nothing to revoke, and still answered.
    assert_eq!(sp.slo_get(&Logout::request(&sp.slo(), "someone-else", None, now).redirect()).await.0, 303);
    assert_eq!(sp.slo_get(&Logout::request(&sp.slo(), NAME_ID, Some("_s9"), now).redirect()).await.0, 303);
    assert_eq!(sp.who(&second).await, Some(u.id.clone()));
    // A message issued before this session (beyond the clock skew), as one replayed after a
    // restart would be, can't reach it.
    let earlier = now - crate::sso::saml_sp::SKEW_MS - 60_000;
    assert_eq!(sp.slo_get(&Logout { issued_ms: earlier, ..Logout::request(&sp.slo(), NAME_ID, None, now) }.redirect()).await.0, 303);
    assert_eq!(sp.who(&second).await, Some(u.id.clone()));
    assert_eq!(sp.audit("auth.slo").await[0]["details"]["revoked"], 0);

    // Over the POST binding with no SessionIndex: all of Ada's sessions from this IdP.
    let (code, to) = sp.slo_post(&Logout::request(&sp.slo(), NAME_ID, None, now).post()).await;
    assert_eq!(code, 303, "{to}");
    assert_eq!(sp.who(&second).await, None);
    assert_eq!(sp.audit("auth.slo").await[0]["details"]["revoked"], 1);
    let failed = sp.audit("auth.slo_failed").await;
    assert!(failed.iter().all(|f| f["outcome"] == "failure" && f["details"]["provider"] == sp.id.as_str()), "{failed:?}");
}

#[tokio::test]
async fn signing_out_sends_the_idp_a_signed_logout_request() {
    let sp = serve_slo(&[]).await;
    let u = sp.link();
    let cookie = sp.cookie("_s1").await;
    let (code, _, body) = crate::tests::call_with(sp.port, "POST", "/api/auth/logout", "", &cookie, "").await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(sp.who(&cookie).await, None, "signed out here first");
    let url = serde_json::from_str::<Value>(&body).unwrap()["logoutUrl"].as_str().expect("logoutUrl").to_string();
    let (base, request) = signed_redirect(&url, &sp.sp_cert().await);
    assert_eq!((base.as_str(), request.param, request.relay.as_deref()), (test_idp::SLO_URL, "SAMLRequest", None));
    assert!(request.xml.contains(&format!(">{NAME_ID}</saml:NameID>")) && request.xml.contains("<samlp:SessionIndex>_s1</samlp:SessionIndex>"), "the NameID as the IdP sent it: {}", request.xml);
    let id = request.xml.split(" ID=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let logout = &sp.audit("auth.logout").await[0];
    assert_eq!((logout["actorId"].as_str(), logout["details"]["slo"].as_str()), (Some(u.id.as_str()), Some(id.as_str())));

    // The IdP's answer: audited against the session it was for, once.
    let answer = Logout::response(&sp.slo(), &id, db::now());
    assert_eq!(sp.slo_get(&answer.redirect()).await, (303, "/login".to_string()));
    let done = &sp.audit("auth.slo_response").await[0];
    assert_eq!((done["outcome"].as_str(), done["details"]["requestId"].as_str(), done["details"]["status"].as_str()), (Some("success"), Some(id.as_str()), Some("Success")));
    assert_eq!(sp.slo_get(&answer.redirect()).await.0, 400);
    assert_eq!(sp.audit("auth.slo_failed").await[0]["details"]["reason"], "replayed");
    assert_eq!(sp.slo_get(&Logout::response(&sp.slo(), &id, db::now()).redirect()).await.0, 400, "a second answer to it");
    assert_eq!(sp.audit("auth.slo_failed").await[0]["details"]["reason"], "unknown_request");

    // An IdP without an SLO URL: signing out ends only SuperBot's session.
    let plain = serve(&[]).await;
    plain.link();
    let cookie = plain.cookie("_s1").await;
    let (_, _, body) = crate::tests::call_with(plain.port, "POST", "/api/auth/logout", "", &cookie, "").await;
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), json!({ "ok": true }));
}

#[tokio::test]
async fn logouts_load_metadata_from_a_url_without_waiting_for_a_sign_in() {
    let md = test_idp::with_slo(&test_idp::metadata());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp_port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().route("/md", axum::routing::get(move || std::future::ready(md.clone())));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let id = format!("n{}", random_hex(4));
    let up = id.to_ascii_uppercase();
    let vars = HashMap::from([
        ("SSO_PROVIDERS".into(), id.clone()),
        (format!("SSO_{up}_TYPE"), "saml".into()),
        (format!("SSO_{up}_IDP_ENTITY_ID"), IDP.into()),
        (format!("SSO_{up}_IDP_METADATA_URL"), format!("http://127.0.0.1:{idp_port}/md")),
    ]);
    let (port, app, admin) = serve_vars(vars).await;
    let sp = Sp { port, app, admin, id, sp_entity: None };
    // As after a restart: nothing has loaded the metadata yet.
    let (code, to) = sp.slo_get(&Logout::request(&sp.slo(), NAME_ID, None, db::now()).redirect()).await;
    assert_eq!(code, 303, "{to}");
    assert!(to.starts_with(test_idp::SLO_URL), "{to}");
}

#[tokio::test]
async fn refusals_before_a_signature_is_checked_are_logged_sparingly() {
    let sp = serve(&[]).await;
    let (code, view) = call(sp.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", sp.id), &sp.admin, &json!({ "xml": test_idp::metadata() }).to_string()).await;
    assert_eq!(code, 200, "{view}");
    for _ in 0..5 {
        assert_eq!(sp.slo_get("").await.0, 400);
    }
    let failed = sp.audit("auth.slo_failed").await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["details"]["reason"], "no_slo");
}

// Encrypted assertions (ADR 0150)

impl Sp {
    /// The certificate our metadata asks IdPs to encrypt to.
    async fn enc_cert(&self) -> String {
        let md = http().get(format!("http://127.0.0.1:{}/api/auth/sso/{}/metadata", self.port, self.id)).send().await.unwrap().text().await.unwrap();
        let kd = md.split(r#"<md:KeyDescriptor use="encryption">"#).nth(1).expect("an encryption certificate");
        kd.split("<ds:X509Certificate>").nth(1).unwrap().split('<').next().unwrap().to_string()
    }
}

fn encrypted_to(cert: &str) -> impl FnOnce(&mut Response) {
    let cert = cert.to_string();
    move |r| {
        r.encrypt = Some(Encrypt::default());
        r.encrypt_to = cert;
    }
}

use crate::sso::xmlenc::test_encrypter::Encrypt;

#[tokio::test]
async fn encrypted_assertions_sign_in_with_a_sealed_key_of_their_own() {
    let sp = serve(&[("ENCRYPTED_ASSERTIONS", "require"), ("SIGN_REQUESTS", "true")]).await;
    let cert = sp.enc_cert().await;
    assert_eq!(sp.enc_cert().await, cert, "made once, then kept");
    let enc_sha = crate::sso::xmldsig::Cert::from_base64(&cert).unwrap().sha256;
    assert_ne!(sp.sp_cert().await.sha256, enc_sha, "never the signing key");
    let made = sp.audit("sso.saml_sp_key_created").await;
    let uses: Vec<(&str, &str)> = made.iter().map(|m| (m["details"]["use"].as_str().unwrap(), m["details"]["certificate"].as_str().unwrap())).collect();
    assert!(uses.contains(&("encryption", enc_sha.as_str())) && uses.iter().filter(|u| u.0 == "encryption").count() == 1, "{uses:?}");
    let sealed = sp.app.db.setting(&format!("sso_saml_sp_key_{}_encryption", sp.id)).unwrap();
    assert!(crate::secrets::sealed::is_sealed(&sealed), "the key is sealed at rest");
    assert_eq!(sp.app.db.setting(&format!("sso_saml_sp_cert_{}_encryption", sp.id)), Some(cert.clone()));

    let u = sp.link();
    let (code, _, head) = sp.sign_in(encrypted_to(&cert)).await;
    assert_eq!(code, 200, "{head}");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(u.id.clone()));
    let login = &sp.audit("auth.login").await[0];
    assert_eq!((login["actorId"].as_str(), login["details"]["subject"].as_str()), (Some(u.id.as_str()), Some(STORED)));

    // Required: a plain assertion, however well signed, is refused. (Unvouched failures after
    // this one are audited at most once a minute, so only the sign-in is checked below.)
    let (_, to, _) = sp.sign_in(|_| {}).await;
    assert_eq!(to, "/login?error=sso_failed");
    assert_eq!(sp.last_failure().await["reason"], "unencrypted_assertion");
    // Anyone can encrypt to our certificate: the assertion inside must still be the IdP's.
    let (_, to, head) = sp
        .sign_in(|r| {
            encrypted_to(&cert)(r);
            r.sign_assertion = false;
        })
        .await;
    assert_eq!(to, "/login?error=sso_failed");
    assert!(signed_in_as(sp.port, &head).await.is_none());
    let (_, to, _) = sp
        .sign_in(|r| {
            encrypted_to(&cert)(r);
            r.signer = 1;
        })
        .await;
    assert_eq!(to, "/login?error=sso_failed");
    // To another key, or with a cipher botd refuses: no sign-in.
    let (other, _) = crate::sso::saml_sp::SpKey::generate("other").unwrap();
    for tweak in [
        Box::new(encrypted_to(&other.cert)) as Box<dyn FnOnce(&mut Response)>,
        Box::new({
            let cert = cert.clone();
            move |r: &mut Response| {
                r.encrypt = Some(Encrypt { data_alg: crate::sso::xmlenc::AES256_CBC.into(), ..Default::default() });
                r.encrypt_to = cert;
            }
        }),
        Box::new({
            let cert = cert.clone();
            move |r: &mut Response| {
                r.encrypt = Some(Encrypt { key_alg: crate::sso::xmlenc::RSA_1_5.into(), ..Default::default() });
                r.encrypt_to = cert;
            }
        }),
    ] {
        let (code, to, head) = sp.sign_in(tweak).await;
        assert_eq!((code, to.as_str()), (303, "/login?error=sso_failed"));
        assert!(signed_in_as(sp.port, &head).await.is_none());
    }

    let (_, v) = call(sp.port, "GET", &format!("/api/sso/{}/saml", sp.id), &sp.admin, "").await;
    let v: Value = serde_json::from_str(&v).unwrap();
    assert_eq!(
        (v["encryptedAssertions"].as_str(), v["spEncryptionKey"]["from"].as_str(), v["spEncryptionKey"]["certificate"]["sha256"].as_str()),
        (Some("require"), Some("generated"), Some(enc_sha.as_str()))
    );
}

#[tokio::test]
async fn encryption_is_off_unless_asked_and_allow_takes_both() {
    let off = serve(&[]).await;
    let md = http().get(format!("http://127.0.0.1:{}/api/auth/sso/{}/metadata", off.port, off.id)).send().await.unwrap().text().await.unwrap();
    assert!(!md.contains("encryption"), "{md}");
    let (_, v) = call(off.port, "GET", &format!("/api/sso/{}/saml", off.id), &off.admin, "").await;
    let v: Value = serde_json::from_str(&v).unwrap();
    assert_eq!((v["encryptedAssertions"].as_str(), v["spEncryptionKey"].clone()), (Some("off"), Value::Null));
    assert!(off.app.db.setting(&format!("sso_saml_sp_key_{}_encryption", off.id)).is_none(), "no key made");
    off.link();
    let (other, _) = crate::sso::saml_sp::SpKey::generate("other").unwrap();
    let (_, to, _) = off.sign_in(encrypted_to(&other.cert)).await;
    assert_eq!(to, "/login?error=sso_failed");
    assert_eq!(off.last_failure().await["reason"], "encrypted_assertion");

    let allow = serve(&[("ENCRYPTED_ASSERTIONS", "allow")]).await;
    let u = allow.link();
    let cert = allow.enc_cert().await;
    assert_eq!(allow.who(&allow.cookie("_s1").await).await, Some(u.id.clone()), "plain");
    let (code, _, head) = allow.sign_in(encrypted_to(&cert)).await;
    assert_eq!(code, 200);
    assert_eq!(signed_in_as(allow.port, &head).await, Some(u.id));
}

// Encrypted NameIDs, ECDSA, and signed IdP metadata (ADR 0151)

#[tokio::test]
async fn encrypted_name_ids_sign_in_and_out_as_plain_ones() {
    let sp = serve_slo(&[("ENCRYPTED_ASSERTIONS", "allow")]).await;
    let u = sp.link();
    let cert = sp.enc_cert().await;
    let (code, _, head) = sp
        .sign_in(|r| {
            r.encrypt_name_id_to = Some(cert.clone());
            r.session_index = "_s1".into();
        })
        .await;
    assert_eq!(code, 200, "{head}");
    let session = set_cookies(&head).into_iter().find(|c| c.starts_with("__Host-superbot_session=sbs_")).unwrap();
    let cookie = format!("Cookie: {}\r\n", session.split(';').next().unwrap());
    assert_eq!(sp.who(&cookie).await, Some(u.id.clone()));
    assert_eq!(sp.audit("auth.login").await[0]["details"]["subject"], STORED, "the decrypted NameID");
    // In an encrypted assertion too.
    let (code, _, _) = sp
        .sign_in(|r| {
            encrypted_to(&cert)(r);
            r.encrypt_name_id_to = Some(cert.clone());
        })
        .await;
    assert_eq!(code, 200);

    // The IdP's LogoutRequest names Ada by an EncryptedID: her session goes.
    let mut l = Logout::request(&sp.slo(), NAME_ID, Some("_s1"), db::now());
    l.encrypt_name_id_to = Some(cert.clone());
    let (code, to) = sp.slo_post(&l.post()).await;
    assert_eq!(code, 303, "{to}");
    assert_eq!(sp.who(&cookie).await, None);
    let slo = &sp.audit("auth.slo").await[0];
    assert_eq!((slo["details"]["subject"].as_str(), slo["details"]["revoked"].as_u64()), (Some(STORED), Some(1)));
    // Encrypted to someone else: refused.
    let (other, _) = crate::sso::saml_sp::SpKey::generate("other").unwrap();
    let mut l = Logout::request(&sp.slo(), NAME_ID, None, db::now());
    l.encrypt_name_id_to = Some(other.cert.clone());
    assert_eq!(sp.slo_post(&l.post()).await.0, 400);
    assert_eq!(sp.audit("auth.slo_failed").await[0]["details"]["reason"], "bad_encryption");

    // Without ENCRYPTED_ASSERTIONS there is no key to decrypt with: refused with a reason.
    let off = serve_slo(&[]).await;
    off.link();
    let (_, to, _) = off.sign_in(|r| r.encrypt_name_id_to = Some(cert.clone())).await;
    assert_eq!(to, "/login?error=sso_failed");
    assert_eq!(off.last_failure().await["reason"], "encrypted_id");
    let mut l = Logout::request(&off.slo(), NAME_ID, None, db::now());
    l.encrypt_name_id_to = Some(cert.clone());
    assert_eq!(off.slo_post(&l.post()).await.0, 400);
    assert_eq!(off.audit("auth.slo_failed").await[0]["details"]["reason"], "encrypted_id");
}

#[tokio::test]
async fn ecdsa_idp_keys_and_an_ecdsa_sp_key_sign_in_and_out() {
    let dir = std::env::temp_dir().join(format!("saml-ec-{}", random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, "SuperBot SAML SP");
    let cert_file = dir.join("sp.pem");
    std::fs::write(&cert_file, params.self_signed(&key).unwrap().pem()).unwrap();
    let sp = serve(&[("SIGN_REQUESTS", "true"), ("SP_CERT_FILE", &cert_file.to_string_lossy())]).await;
    crate::secrets::global().put(&format!("SSO_{}_PRIVATE_KEY", sp.id.to_ascii_uppercase()), &key.serialize_pem()).unwrap();

    // The IdP signs with P-384.
    let md = test_idp::with_slo(&test_idp::metadata_signed_by(3));
    let (code, view) = call(sp.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", sp.id), &sp.admin, &json!({ "xml": md }).to_string()).await;
    assert_eq!(code, 200, "{view}");
    let u = sp.link();
    let (code, _, head) = sp.sign_in(|r| r.signer = 3).await;
    assert_eq!(code, 200, "{head}");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(u.id.clone()));
    for wrong in [0, 2] {
        let (_, to, _) = sp.sign_in(|r| r.signer = wrong).await;
        assert_eq!(to, "/login?error=sso_failed", "signer {wrong}");
    }
    let mut l = Logout::request(&sp.slo(), NAME_ID, None, db::now());
    l.signer = Some(3);
    let (code, to) = sp.slo_get(&l.redirect()).await;
    assert_eq!(code, 303, "{to}");

    // Our requests and answers are signed with ecdsa-sha256, and verify with our published certificate.
    let cert = sp.sp_cert().await;
    let (_, head, _) = crate::tests::call_with(sp.port, "GET", &format!("/api/auth/sso/{}/start", sp.id), "", "", "").await;
    let location = header(&head, "location").unwrap();
    let q: HashMap<_, _> = url::Url::parse(&location).unwrap().query_pairs().into_owned().collect();
    assert_eq!(q["SigAlg"], crate::sso::xmldsig::ECDSA_SHA256);
    signed_redirect(&location, &cert);
    signed_redirect(&to, &cert);
    let (_, v) = call(sp.port, "GET", &format!("/api/sso/{}/saml", sp.id), &sp.admin, "").await;
    let v: Value = serde_json::from_str(&v).unwrap();
    assert_eq!((v["spKey"]["from"].as_str(), v["ready"].as_bool()), (Some("secret"), Some(true)));
    std::fs::remove_dir_all(dir).ok();
}

/// A native provider whose metadata must be signed by test signer 1, with no metadata yet.
async fn serve_trusting(mode: &str, source: Option<(&str, String)>) -> (Sp, std::path::PathBuf, Arc<crate::sso::Provider>) {
    let dir = std::env::temp_dir().join(format!("saml-md-{}", random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let anchor = dir.join("anchor.pem");
    std::fs::write(&anchor, format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", crate::sso::xmldsig::test_signer::signers()[1].cert)).unwrap();
    let id = format!("n{}", random_hex(4));
    let up = id.to_ascii_uppercase();
    let mut vars = HashMap::from([
        ("SSO_PROVIDERS".into(), id.clone()),
        (format!("SSO_{up}_TYPE"), "saml".into()),
        (format!("SSO_{up}_IDP_ENTITY_ID"), IDP.into()),
        (format!("SSO_{up}_METADATA_SIGNING_CERT_FILE"), anchor.to_string_lossy().into_owned()),
        (format!("SSO_{up}_SIGNED_METADATA"), mode.into()),
    ]);
    vars.extend(source.map(|(k, v)| (format!("SSO_{up}_{k}"), v)));
    let mut provider = None;
    let (port, app, admin) = serve_vars_with(vars, |a| provider = a.sso.providers.first().cloned()).await;
    (Sp { port, app, admin, id, sp_entity: None }, dir, provider.unwrap())
}

#[tokio::test]
async fn imported_metadata_must_be_signed_and_a_bad_copy_keeps_the_last_good_one() {
    let (sp, dir, _) = serve_trusting("require", None).await;
    let signer = |i: usize| crate::sso::xmldsig::test_signer::signer(i);
    let import = |xml: String| {
        let (port, admin, id) = (sp.port, sp.admin.clone(), sp.id.clone());
        async move { call(port, "PUT", &format!("/api/sso/{id}/saml/idp-metadata"), &admin, &json!({ "xml": xml }).to_string()).await }
    };

    let (code, e) = import(test_idp::metadata()).await;
    assert!(code == 400 && e.contains("isn't signed"), "{code} {e}");
    let refused = &sp.audit("sso.saml_metadata_refused").await[0];
    assert_eq!((refused["outcome"].as_str(), refused["details"]["reason"].as_str(), refused["details"]["source"].as_str()), (Some("failure"), Some("unsigned"), Some("botctl")));
    assert_eq!(refused["details"]["kept"], false, "nothing loaded yet");

    let good = test_idp::signed_metadata(&test_idp::metadata(), signer(1));
    let (code, v) = import(good.clone()).await;
    assert_eq!(code, 200, "{v}");
    let v: Value = serde_json::from_str(&v).unwrap();
    assert_eq!((v["signedMetadata"].as_str(), v["ready"].as_bool()), (Some("require"), Some(true)));
    assert_eq!(v["metadataSigningCertificates"][0]["sha256"], signer(1).cert().sha256);

    // Signed by someone else, or changed after signing: refused, audited, and the good copy stays.
    let forged = test_idp::signed_metadata(&test_idp::metadata_with(IDP, &[signer(2)], ""), signer(0));
    let (code, e) = import(forged).await;
    assert!(code == 400 && e.contains("bad_signature"), "{code} {e}");
    let tampered = good.replace(&signer(0).cert, &signer(2).cert);
    assert_eq!(import(tampered).await.0, 400);
    let refused = sp.audit("sso.saml_metadata_refused").await;
    assert_eq!((refused.len(), refused[0]["details"]["reason"].as_str(), refused[0]["details"]["kept"].as_bool()), (3, Some("bad_signature"), Some(true)));
    assert_eq!(sp.app.db.setting(&format!("sso_saml_idp_metadata_{}", sp.id)), Some(good.clone()), "the stored copy is the good one");
    let u = sp.link();
    let (code, _, head) = sp.sign_in(|_| {}).await;
    assert_eq!(code, 200, "still signs in with the last good metadata");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(u.id));
    // Metadata that just can't be used isn't a trust failure: refused, not audited as one.
    let (code, _) = import(test_idp::signed_metadata(&test_idp::metadata_with("https://other.example/saml", &[signer(0)], ""), signer(1))).await;
    assert_eq!(code, 400);
    assert_eq!(sp.audit("sso.saml_metadata_refused").await.len(), 3);

    let (allow, allow_dir, _) = serve_trusting("allow", None).await;
    let (code, _) = call(allow.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", allow.id), &allow.admin, &json!({ "xml": test_idp::metadata() }).to_string()).await;
    assert_eq!(code, 200, "allow: unsigned is taken");
    let forged = test_idp::signed_metadata(&test_idp::metadata(), signer(0));
    let (code, _) = call(allow.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", allow.id), &allow.admin, &json!({ "xml": forged }).to_string()).await;
    assert_eq!(code, 400, "allow: a bad signature is still refused");
    std::fs::remove_dir_all(dir).ok();
    std::fs::remove_dir_all(allow_dir).ok();
}

#[tokio::test]
async fn metadata_from_a_url_is_checked_each_time_it_is_fetched() {
    let signer = |i: usize| crate::sso::xmldsig::test_signer::signer(i);
    let served = std::sync::Arc::new(std::sync::Mutex::new(test_idp::signed_metadata(&test_idp::metadata(), signer(0))));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp_port = listener.local_addr().unwrap().port();
    let s = served.clone();
    let app = axum::Router::new().route("/md", axum::routing::get(move || std::future::ready(s.lock().unwrap().clone())));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (sp, dir, provider) = serve_trusting("require", Some(("IDP_METADATA_URL", format!("http://127.0.0.1:{idp_port}/md")))).await;

    // Badly signed: no sign-in, and the refusal is audited.
    let (code, head, _) = crate::tests::call_with(sp.port, "GET", &format!("/api/auth/sso/{}/start", sp.id), "", "", "").await;
    assert_eq!(code, 303);
    assert_eq!(header(&head, "location").as_deref(), Some("/login?error=sso_failed"));
    let refused = &sp.audit("sso.saml_metadata_refused").await[0];
    assert_eq!((refused["details"]["reason"].as_str(), refused["details"]["source"].as_str(), refused["details"]["kept"].as_bool()), (Some("bad_signature"), Some("url"), Some(false)));

    // Signed by the anchor: it loads and signs in.
    *served.lock().unwrap() = test_idp::signed_metadata(&test_idp::metadata(), signer(1));
    let u = sp.link();
    let (code, _, head) = sp.sign_in(|_| {}).await;
    assert_eq!(code, 200);
    assert_eq!(signed_in_as(sp.port, &head).await, Some(u.id.clone()));
    assert_eq!(sp.audit("sso.saml_metadata_refused").await.len(), 1);

    // A day later the refresh is badly signed: refused and audited, and the good copy still signs in.
    *served.lock().unwrap() = test_idp::signed_metadata(&test_idp::metadata_with(IDP, &[signer(2)], ""), signer(0));
    provider.age_idp(std::time::Duration::from_secs(25 * 3600));
    let (code, _, head) = sp.sign_in(|_| {}).await;
    assert_eq!(code, 200, "the last good copy");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(u.id));
    let refused = sp.audit("sso.saml_metadata_refused").await;
    // Tests retry at once (no refresh gap), so the start and the ACS each fetch it.
    assert!(refused.len() > 1, "{refused:?}");
    assert_eq!((refused[0]["details"]["reason"].as_str(), refused[0]["details"]["kept"].as_bool()), (Some("bad_signature"), Some(true)));
    std::fs::remove_dir_all(dir).ok();
}
