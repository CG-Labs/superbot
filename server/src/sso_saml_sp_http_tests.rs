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
    serve_importing(extra, tweak, &test_idp::metadata()).await
}

async fn serve_importing(extra: &[(&str, &str)], tweak: impl FnOnce(&mut Auth), metadata: &str) -> Sp {
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
    let (code, view) = call(port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", sp.id), &sp.admin, &json!({ "xml": metadata }).to_string()).await;
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

// Back-channel (SOAP) logout (ADR 0208)

impl Sp {
    fn slo_soap(&self) -> String {
        format!("{}/soap", self.slo())
    }

    /// The IdP's server at our SOAP SLO URL: the status, the content type, and the body.
    async fn soap(&self, envelope: &str) -> (u16, String, String) {
        let res = http().post(self.slo_soap()).header("content-type", "text/xml; charset=utf-8").header("soapaction", crate::sso::saml_slo::SOAP_ACTION).body(envelope.to_string()).send().await.unwrap();
        assert!(res.headers().get("set-cookie").is_none(), "{:?}", res.headers());
        let ty = res.headers().get("content-type").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        (res.status().as_u16(), ty, res.text().await.unwrap())
    }

    /// A client-app sign-in in the IdP session `index`: its bearer token.
    async fn app_token(&self, index: &str) -> String {
        let verifier = "v".repeat(64);
        let start = format!("/api/auth/sso/{}/start?session=token&redirect=superbot%3A%2F%2Fauth&challenge={}&state=st-1&label=Phone", self.id, s256(&verifier));
        let (code, head, _) = crate::tests::call_with(self.port, "GET", &start, "", "", "").await;
        assert_eq!(code, 303, "{head}");
        let to_idp = url::Url::parse(&header(&head, "location").unwrap()).unwrap();
        let q: HashMap<_, _> = to_idp.query_pairs().into_owned().collect();
        let request = String::from_utf8(miniz_oxide::inflate::decompress_to_vec(&STANDARD.decode(&q["SAMLRequest"]).unwrap()).unwrap()).unwrap();
        let id = request.split(" ID=\"").nth(1).unwrap().split('"').next().unwrap();
        let mut r = Response::new(&self.acs(), &self.entity(), id, db::now());
        r.session_index = index.into();
        let (code, to, _) = self.post(Some(&r.posted()), Some(&q["RelayState"]), "").await;
        assert_eq!(code, 303, "{to}");
        let back: HashMap<_, _> = url::Url::parse(&to).unwrap().query_pairs().into_owned().collect();
        let (code, res) = call(self.port, "POST", "/api/auth/login", "", &json!({ "sso": back["code"], "verifier": verifier }).to_string()).await;
        assert_eq!(code, 200, "{res}");
        format!("Bearer {}", serde_json::from_str::<Value>(&res).unwrap()["token"].as_str().unwrap())
    }

    /// The newest `action` event, waiting for one botd records in the background.
    async fn audited(&self, action: &str, after: usize) -> Value {
        for _ in 0..100 {
            let all = self.audit(action).await;
            if all.len() > after {
                return all[0].clone();
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("no {action} event");
    }
}

/// The LogoutResponse in a SOAP answer, after checking it is signed by `cert`.
fn signed_soap_answer(body: &str, cert: &crate::sso::xmldsig::Cert) -> String {
    let doc = crate::sso::xmldsig::parse(body).unwrap();
    let m = doc.descendants().find(|n| crate::sso::xmldsig::is(*n, crate::sso::saml_sp::PROTOCOL, "LogoutResponse")).expect("a LogoutResponse");
    assert!(crate::sso::xmldsig::is(m.parent().unwrap(), crate::sso::saml_slo::SOAP11, "Body"), "{body}");
    assert_eq!(crate::sso::xmldsig::verify_enveloped(m, std::slice::from_ref(cert)), Ok(true), "signed by our key");
    body[m.range()].to_string()
}

#[tokio::test]
async fn an_idp_logout_request_over_soap_revokes_the_sessions_it_names_and_is_answered_signed() {
    // The IdP's metadata has no SLO URL at all: the answer goes back on the same connection.
    let sp = serve(&[]).await;
    let u = sp.link();
    let (first, second) = (sp.cookie("_s1").await, sp.cookie("_s2").await);
    let cert = sp.sp_cert().await;
    let md = http().get(format!("http://127.0.0.1:{}/api/auth/sso/{}/metadata", sp.port, sp.id)).send().await.unwrap().text().await.unwrap();
    assert!(md.contains(&format!(r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="{}"/>"#, sp.slo_soap())), "{md}");
    let now = db::now();
    let request = |index: Option<&str>| Logout { relay: None, ..Logout::request(&sp.slo_soap(), NAME_ID, index, now) };

    let l = request(Some("_s1"));
    let (code, ty, body) = sp.soap(&l.soap()).await;
    assert_eq!((code, ty.as_str()), (200, "text/xml; charset=utf-8"), "{body}");
    let answer = signed_soap_answer(&body, &cert);
    assert!(answer.contains(&format!(r#"InResponseTo="{}""#, l.id)) && answer.contains("status:Success") && !answer.contains("Destination="), "{answer}");
    assert_eq!((sp.who(&first).await, sp.who(&second).await), (None, Some(u.id.clone())));
    let slo = &sp.audit("auth.slo").await[0];
    assert_eq!((slo["actorId"].as_str(), slo["details"]["binding"].as_str(), slo["details"]["revoked"].as_u64()), (Some(u.id.as_str()), Some("soap"), Some(1)));

    // Refusals are SOAP faults, audited like the front channel's, with the binding.
    let fault = |code: u16, body: &str| {
        assert_eq!(code, 500, "{body}");
        assert!(body.contains("<soap11:Fault>") && !body.contains("LogoutResponse"), "{body}");
    };
    let (code, _, body) = sp.soap(&l.soap()).await;
    fault(code, &body);
    let failed = &sp.audit("auth.slo_failed").await[0]["details"];
    assert_eq!((failed["reason"].as_str(), failed["binding"].as_str()), (Some("replayed"), Some("soap")));
    let (code, _, body) = sp.soap(&Logout { signer: None, ..request(None) }.soap()).await;
    fault(code, &body);
    assert_eq!(sp.audit("auth.slo_failed").await[0]["details"]["reason"], "unsigned");
    let (code, _, body) = sp.soap(&Logout { relay: None, ..Logout::request(&sp.slo(), NAME_ID, None, now) }.soap()).await;
    fault(code, &body);
    assert_eq!(sp.audit("auth.slo_failed").await[0]["details"]["reason"], "wrong_destination", "signed for the front channel's URL");
    let header = request(None).soap().replacen("<soap11:Body>", r#"<soap11:Header><x:Sec xmlns:x="urn:x" soap11:mustUnderstand="1"/></soap11:Header><soap11:Body>"#, 1);
    let (code, _, body) = sp.soap(&header).await;
    assert!(code == 500 && body.contains("soap11:MustUnderstand"), "{body}");
    // Over the front channel's binding, a SOAP envelope is just a bad form.
    assert_eq!(http().post(sp.slo()).header("content-type", "text/xml").body(request(None).soap()).send().await.unwrap().status().as_u16(), 415);
    assert_eq!(http().get(sp.slo_soap()).send().await.unwrap().status().as_u16(), 405);
    assert_eq!(sp.who(&second).await, Some(u.id.clone()));

    // No SessionIndex: every session Ada has from this IdP.
    let (code, _, body) = sp.soap(&request(None).soap()).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(sp.who(&second).await, None);
}

/// A stand-in for the IdP's SOAP SLO URL: what it was sent, and what it answers.
#[derive(Clone, Default)]
struct SoapIdp {
    got: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    /// `ok`, `fault`, `other` (answers another request) or `partial`.
    answer: Arc<std::sync::Mutex<&'static str>>,
}

impl SoapIdp {
    async fn start() -> (SoapIdp, String) {
        let idp = SoapIdp { answer: Arc::new(std::sync::Mutex::new("ok")), ..Default::default() };
        let state = idp.clone();
        let app = axum::Router::new().route(
            "/soap",
            axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
                let state = state.clone();
                async move {
                    let action = headers.get("soapaction").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                    state.got.lock().unwrap().push((action, body.clone()));
                    let id = body.split(" ID=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
                    let answer = *state.answer.lock().unwrap();
                    let mut r = Logout { destination: None, ..Logout::response("", &id, db::now()) };
                    match answer {
                        "fault" => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, crate::sso::saml_slo::soap_fault("x")),
                        "other" => r.in_response_to = "_not-yours".into(),
                        "partial" => r.sub_status = Some("urn:oasis:names:tc:SAML:2.0:status:PartialLogout".into()),
                        _ => {}
                    }
                    (axum::http::StatusCode::OK, r.soap())
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}/soap", listener.local_addr().unwrap().port());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (idp, url)
    }

    fn last(&self) -> (String, String) {
        self.got.lock().unwrap().last().cloned().expect("a SOAP request")
    }
}

#[tokio::test]
async fn signing_out_without_a_browser_sends_the_idp_a_logout_request_over_soap() {
    let (stub, soap_url) = SoapIdp::start().await;
    let sp = serve(&[]).await;
    let xml = test_idp::with_soap_slo(&test_idp::with_slo(&test_idp::metadata()), &soap_url);
    let (code, view) = call(sp.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", sp.id), &sp.admin, &json!({ "xml": xml }).to_string()).await;
    assert_eq!(code, 200, "{view}");
    let view: Value = serde_json::from_str(&view).unwrap();
    assert_eq!((view["backChannelLogout"].as_bool(), view["sloSoapUrl"].as_str(), view["idp"]["sloSoapUrl"].as_str()), (Some(true), Some(sp.slo_soap().as_str()), Some(soap_url.as_str())));
    let u = sp.link();
    let cert = sp.sp_cert().await;

    // The phone app signs out: botd tells the IdP itself, and answers the app at once.
    let token = sp.app_token("_s1").await;
    let (code, body) = call(sp.port, "POST", "/api/auth/logout", &token, "").await;
    assert_eq!((code, serde_json::from_str::<Value>(&body).unwrap()), (200, json!({ "ok": true })), "nothing for the app to follow");
    let done = sp.audited("auth.slo_response", 0).await;
    let (action, sent) = stub.last();
    assert_eq!(action, crate::sso::saml_slo::SOAP_ACTION);
    let doc = crate::sso::xmldsig::parse(&sent).unwrap();
    let m = doc.descendants().find(|n| crate::sso::xmldsig::is(*n, crate::sso::saml_sp::PROTOCOL, "LogoutRequest")).expect("a LogoutRequest");
    assert!(crate::sso::xmldsig::is(m.parent().unwrap(), crate::sso::saml_slo::SOAP11, "Body"));
    assert_eq!(crate::sso::xmldsig::verify_enveloped(m, std::slice::from_ref(&cert)), Ok(true), "signed by our key");
    assert_eq!(m.attribute("Destination"), Some(soap_url.as_str()));
    assert!(sent.contains(&format!(">{NAME_ID}</saml:NameID>")) && sent.contains("<samlp:SessionIndex>_s1</samlp:SessionIndex>"), "{sent}");
    let id = m.attribute("ID").unwrap().to_string();
    let logout = &sp.audit("auth.logout").await[0];
    assert_eq!((logout["actorId"].as_str(), logout["details"]["slo"].as_str(), logout["details"]["sloBinding"].as_str()), (Some(u.id.as_str()), Some(id.as_str()), Some("soap")));
    let d = &done["details"];
    assert_eq!((done["outcome"].as_str(), d["requestId"].as_str(), d["status"].as_str(), d["binding"].as_str()), (Some("success"), Some(id.as_str()), Some("Success"), Some("soap")));
    assert_eq!((done["targetType"].as_str(), done["targetId"].as_str()), (Some("session"), logout["targetId"].as_str()));
    assert_eq!(call(sp.port, "GET", "/api/auth/me", &token, "").await.0, 401, "signed out here first");

    // A browser, with the front channel there, still goes to the IdP itself.
    let cookie = sp.cookie("_s2").await;
    let (_, _, body) = crate::tests::call_with(sp.port, "POST", "/api/auth/logout", "", &cookie, "").await;
    assert!(serde_json::from_str::<Value>(&body).unwrap()["logoutUrl"].as_str().unwrap().starts_with(test_idp::SLO_URL), "{body}");
    assert_eq!(stub.got.lock().unwrap().len(), 1);

    // Answers that don't say it worked are audited as failures, with why.
    for (answer, status, reason) in [("partial", "Success/PartialLogout", None), ("fault", "none", Some("soap_fault")), ("other", "none", Some("unknown_request"))] {
        *stub.answer.lock().unwrap() = answer;
        let before = sp.audit("auth.slo_response").await.len();
        let token = sp.app_token("_s3").await;
        assert_eq!(call(sp.port, "POST", "/api/auth/logout", &token, "").await.0, 200);
        let e = sp.audited("auth.slo_response", before).await;
        assert_eq!((e["outcome"].as_str(), e["details"]["status"].as_str(), e["details"]["reason"].as_str()), (Some("failure"), Some(status), reason), "{answer}");
    }
}

#[tokio::test]
async fn a_browser_signs_out_over_soap_when_the_idp_has_no_front_channel() {
    let (stub, soap_url) = SoapIdp::start().await;
    let sp = serve(&[]).await;
    let xml = test_idp::with_soap_slo(&test_idp::metadata(), &soap_url);
    let (code, view) = call(sp.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", sp.id), &sp.admin, &json!({ "xml": xml }).to_string()).await;
    assert_eq!(code, 200, "{view}");
    let view: Value = serde_json::from_str(&view).unwrap();
    assert_eq!((view["singleLogout"].as_bool(), view["backChannelLogout"].as_bool()), (Some(false), Some(true)));
    sp.link();
    let cookie = sp.cookie("_s1").await;
    let (code, _, body) = crate::tests::call_with(sp.port, "POST", "/api/auth/logout", "", &cookie, "").await;
    assert_eq!((code, serde_json::from_str::<Value>(&body).unwrap()), (200, json!({ "ok": true })));
    assert_eq!(sp.audited("auth.slo_response", 0).await["outcome"], "success");
    assert!(stub.last().1.contains("<samlp:SessionIndex>_s1</samlp:SessionIndex>"));
    // An IdP that is down: the sign-out here stands, and the failure is audited.
    let down = serve(&[]).await;
    let xml = test_idp::with_soap_slo(&test_idp::metadata(), "http://127.0.0.1:9/soap");
    call(down.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", down.id), &down.admin, &json!({ "xml": xml }).to_string()).await;
    down.link();
    let cookie = down.cookie("_s1").await;
    assert_eq!(crate::tests::call_with(down.port, "POST", "/api/auth/logout", "", &cookie, "").await.0, 200);
    assert_eq!(down.who(&cookie).await, None);
    let e = down.audited("auth.slo_response", 0).await;
    assert_eq!((e["outcome"].as_str(), e["details"]["reason"].as_str()), (Some("failure"), Some("unreachable")));
}

// Back-channel logout when sessions end without a sign-out (ADR 0258)

impl Sp {
    /// Imports IdP metadata with both a browser and a SOAP SLO URL.
    async fn with_soap_idp(&self, soap_url: &str) {
        let xml = test_idp::with_soap_slo(&test_idp::with_slo(&test_idp::metadata()), soap_url);
        let (code, view) = call(self.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", self.id), &self.admin, &json!({ "xml": xml }).to_string()).await;
        assert_eq!(code, 200, "{view}");
    }

    /// The id of `user`'s live session in the IdP session `index`.
    fn session_in(&self, user: &str, index: &str) -> String {
        let cfg = crate::users::SessionConfig::default();
        let live = self.app.db.live_sessions(Some(user), db::now(), cfg.idle_ms, cfg.max_ms);
        live.into_iter().find(|s| self.app.db.saml_session(&s.id).and_then(|l| l.session_index).as_deref() == Some(index)).expect("a session in that IdP session").id
    }
}

impl SoapIdp {
    /// The SessionIndex of each LogoutRequest it got after the first `after`, each signed by `cert`.
    fn indexes(&self, after: usize, cert: &crate::sso::xmldsig::Cert) -> Vec<String> {
        let got = self.got.lock().unwrap().clone();
        got[after..]
            .iter()
            .map(|(_, sent)| {
                let doc = crate::sso::xmldsig::parse(sent).unwrap();
                let m = doc.descendants().find(|n| crate::sso::xmldsig::is(*n, crate::sso::saml_sp::PROTOCOL, "LogoutRequest")).unwrap();
                assert_eq!(crate::sso::xmldsig::verify_enveloped(m, std::slice::from_ref(cert)), Ok(true), "signed by our key");
                assert!(sent.contains(&format!(">{NAME_ID}</saml:NameID>")), "{sent}");
                sent.split("<samlp:SessionIndex>").nth(1).unwrap().split('<').next().unwrap().to_string()
            })
            .collect()
    }
}

#[tokio::test]
async fn an_admin_ending_sessions_ends_their_idp_sessions_over_soap() {
    let (stub, soap_url) = SoapIdp::start().await;
    let sp = serve(&[]).await;
    sp.with_soap_idp(&soap_url).await;
    let u = sp.link();
    let cert = sp.sp_cert().await;

    // One session revoked by an admin: its IdP session ends too, even with a browser front channel.
    let first = sp.cookie("_s1").await;
    let id = sp.session_in(&u.id, "_s1");
    let (code, body) = call(sp.port, "DELETE", &format!("/api/sessions/{id}"), &sp.admin, "").await;
    assert_eq!(code, 200, "{body}");
    let done = sp.audited("auth.slo_response", 0).await;
    assert_eq!(stub.indexes(0, &cert), ["_s1"]);
    let revoked = &sp.audit("session.revoked").await[0];
    let d = &done["details"];
    assert_eq!(revoked["details"]["idpLogouts"], json!([d["requestId"]]));
    assert_eq!((done["outcome"].as_str(), done["targetId"].as_str(), d["binding"].as_str(), d["revokeReason"].as_str()), (Some("success"), Some(id.as_str()), Some("soap"), Some("revoked by admin")));
    assert_eq!(sp.who(&first).await, None);

    // All of someone's sessions: one LogoutRequest per IdP session, not per SuperBot session.
    let (web, _) = (sp.cookie("_s2").await, sp.app_token("_s2").await);
    sp.cookie("_s3").await;
    let (code, body) = call(sp.port, "DELETE", &format!("/api/users/{}/sessions", u.id), &sp.admin, "").await;
    assert_eq!((code, serde_json::from_str::<Value>(&body).unwrap()["revoked"].as_u64()), (200, Some(3)), "{body}");
    sp.audited("auth.slo_response", 2).await;
    let mut sent = stub.indexes(1, &cert);
    sent.sort();
    assert_eq!(sent, ["_s2", "_s3"]);
    let all = &sp.audit("session.revoked_all").await[0]["details"];
    assert_eq!((all["count"].as_u64(), all["idpLogouts"].as_array().map(Vec::len)), (Some(3), Some(2)));
    assert!(sp.audit("auth.slo_response").await.iter().take(2).all(|e| e["details"]["revokeReason"] == "revoked by admin"));
    assert_eq!(sp.who(&web).await, None);

    // A session no IdP vouched for tells nobody.
    let code_session = session_for(sp.port, &sp.admin, &u.id).await;
    let (code, body) = call(sp.port, "DELETE", &format!("/api/users/{}/sessions", u.id), &sp.admin, "").await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(call(sp.port, "GET", "/api/auth/me", &code_session, "").await.0, 401);
    assert!(sp.audit("session.revoked_all").await[0]["details"].get("idpLogouts").is_none());

    // Disabling someone ends their IdP sessions as well.
    sp.cookie("_s4").await;
    let (code, body) = call(sp.port, "PATCH", &format!("/api/users/{}", u.id), &sp.admin, &json!({ "status": "disabled" }).to_string()).await;
    assert_eq!(code, 200, "{body}");
    let done = sp.audited("auth.slo_response", 3).await;
    assert_eq!(stub.indexes(3, &cert), ["_s4"], "nothing for the code session");
    assert_eq!(done["details"]["revokeReason"], "user disabled");
    assert_eq!(sp.audit("user.disabled").await[0]["details"]["idpLogouts"], json!([done["details"]["requestId"]]));
}

#[tokio::test]
async fn an_idp_down_or_without_soap_logout_never_holds_up_an_admin() {
    // No SOAP SLO URL: the session just ends here, as before.
    let sp = serve_slo(&[]).await;
    let u = sp.link();
    let cookie = sp.cookie("_s1").await;
    let (code, _) = call(sp.port, "DELETE", &format!("/api/users/{}/sessions", u.id), &sp.admin, "").await;
    assert_eq!((code, sp.who(&cookie).await), (200, None));
    assert!(sp.audit("session.revoked_all").await[0]["details"].get("idpLogouts").is_none());
    assert!(sp.audit("auth.slo_response").await.is_empty());

    // A sign-in whose assertion named no IdP session: a NameID-only request would end the
    // person's IdP sessions on every device, so the IdP isn't told.
    let (stub, soap_url) = SoapIdp::start().await;
    let quiet = serve(&[]).await;
    quiet.with_soap_idp(&soap_url).await;
    let u = quiet.link();
    let cookie = quiet.cookie("").await;
    let (code, body) = call(quiet.port, "DELETE", &format!("/api/users/{}/sessions", u.id), &quiet.admin, "").await;
    assert_eq!((code, serde_json::from_str::<Value>(&body).unwrap()["revoked"].as_u64()), (200, Some(1)), "{body}");
    assert_eq!(quiet.who(&cookie).await, None);
    assert!(quiet.audit("session.revoked_all").await[0]["details"].get("idpLogouts").is_none());
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(stub.got.lock().unwrap().is_empty() && quiet.audit("auth.slo_response").await.is_empty());

    // An IdP that is down: the revoke stands, and the failure is audited.
    let down = serve(&[]).await;
    down.with_soap_idp("http://127.0.0.1:9/soap").await;
    let u = down.link();
    let cookie = down.cookie("_s1").await;
    let id = down.session_in(&u.id, "_s1");
    assert_eq!(call(down.port, "DELETE", &format!("/api/sessions/{id}"), &down.admin, "").await.0, 200);
    assert_eq!(down.who(&cookie).await, None);
    let e = down.audited("auth.slo_response", 0).await;
    assert_eq!((e["outcome"].as_str(), e["details"]["reason"].as_str(), e["details"]["revokeReason"].as_str()), (Some("failure"), Some("unreachable"), Some("revoked by admin")));
}

#[tokio::test]
async fn scim_deprovisioning_ends_idp_sessions_over_soap() {
    use crate::scim_http_tests::{okta_user, scim, token};
    let (stub, soap_url) = SoapIdp::start().await;
    let sp = serve_with(&[], |a| a.scim.enabled = true).await;
    sp.with_soap_idp(&soap_url).await;
    let cert = sp.sp_cert().await;
    let (scim_token, _) = token(sp.port, &sp.admin, json!({ "tenant": "okta" })).await;
    let (code, _, created) = scim(sp.port, &scim_token, "POST", "/scim/v2/Users", okta_user("ada@example.com", "ext-1")).await;
    assert_eq!(code, 201, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    sp.app.db.link_identity(&id, &NewIdentity { provider: &sp.id, issuer: IDP, subject: STORED, tenant: None, email: None, created_by: Some("test") }).unwrap();
    let active = |on: bool| json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{ "op": "replace", "value": { "active": on } }] });

    let cookie = sp.cookie("_s1").await;
    let (code, _, body) = scim(sp.port, &scim_token, "PATCH", &format!("/scim/v2/Users/{id}"), active(false)).await;
    assert_eq!(code, 200, "{body}");
    let done = sp.audited("auth.slo_response", 0).await;
    assert_eq!(stub.indexes(0, &cert), ["_s1"]);
    assert_eq!(done["details"]["revokeReason"], "deprovisioned by SCIM");
    assert_eq!(sp.audit("user.disabled").await[0]["details"]["idpLogouts"], json!([done["details"]["requestId"]]));
    assert_eq!(sp.who(&cookie).await, None);

    assert_eq!(scim(sp.port, &scim_token, "PATCH", &format!("/scim/v2/Users/{id}"), active(true)).await.0, 200);
    sp.cookie("_s2").await;
    let (code, _, body) = scim(sp.port, &scim_token, "DELETE", &format!("/scim/v2/Users/{id}"), Value::Null).await;
    assert_eq!(code, 204, "{body}");
    let done = sp.audited("auth.slo_response", 1).await;
    assert_eq!(stub.indexes(1, &cert), ["_s2"]);
    assert_eq!(done["details"]["revokeReason"], "deleted by SCIM");
    assert_eq!(sp.audit("scim.user_deleted").await[0]["details"]["idpLogouts"], json!([done["details"]["requestId"]]));
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

// AES-CBC in signed responses, for Entra ID and ADFS (ADR 0218)

/// An assertion encrypted as Entra ID and ADFS do (AES-256-CBC, RSA-OAEP), in a response that
/// is signed too ("Sign SAML response and assertion", `MessageAndAssertion`) or not.
fn cbc_to(cert: &str, sign_response: bool) -> impl FnOnce(&mut Response) {
    let cert = cert.to_string();
    move |r| {
        r.encrypt = Some(Encrypt { data_alg: crate::sso::xmlenc::AES256_CBC.into(), ..Default::default() });
        r.encrypt_to = cert;
        r.sign_response = sign_response;
    }
}

#[tokio::test]
async fn aes_cbc_assertions_sign_in_only_in_a_signed_response() {
    let sp = serve(&[("ENCRYPTED_ASSERTIONS", "require"), ("AES_CBC", "signed-response")]).await;
    let cert = sp.enc_cert().await;
    let md = http().get(format!("http://127.0.0.1:{}/api/auth/sso/{}/metadata", sp.port, sp.id)).send().await.unwrap().text().await.unwrap();
    let (gcm, cbc) = (md.find("xmlenc11#aes256-gcm").unwrap(), md.find("xmlenc#aes256-cbc").expect("CBC offered"));
    assert!(gcm < cbc, "after GCM: {md}");
    assert_eq!(sp.view().await["aesCbc"], "signed-response");
    let u = sp.link();

    // Only the assertion signed: nothing covers the ciphertext, so it isn't decrypted.
    let (_, to, head) = sp.sign_in(cbc_to(&cert, false)).await;
    assert_eq!(to, "/login?error=sso_failed");
    assert!(signed_in_as(sp.port, &head).await.is_none());
    assert_eq!(sp.last_failure().await["reason"], "cbc_unsigned_response");
    // The response signed too: signed in, with the cipher in the audit log.
    let (code, _, head) = sp.sign_in(cbc_to(&cert, true)).await;
    assert_eq!(code, 200, "{head}");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(u.id.clone()));
    assert_eq!(sp.audit("auth.login").await[0]["details"]["assertionEncryption"], "aes256-cbc");
    // An IdP that moves to GCM shows it, so the admin knows CBC can go.
    let (code, _, _) = sp.sign_in(encrypted_to(&cert)).await;
    assert_eq!(code, 200);
    assert_eq!(sp.audit("auth.login").await[0]["details"]["assertionEncryption"], "aes256-gcm");
    // A response signed by someone else around it: refused.
    let (_, to, head) = sp
        .sign_in(|r| {
            cbc_to(&cert, true)(r);
            r.signer = 1;
        })
        .await;
    assert_eq!(to, "/login?error=sso_failed");
    assert!(signed_in_as(sp.port, &head).await.is_none());

    // Without the setting, CBC stays refused, however it's signed.
    let off = serve(&[("ENCRYPTED_ASSERTIONS", "require")]).await;
    let cert = off.enc_cert().await;
    let md = http().get(format!("http://127.0.0.1:{}/api/auth/sso/{}/metadata", off.port, off.id)).send().await.unwrap().text().await.unwrap();
    // The algorithm URIs only: a certificate's base64 may hold "cbc" by chance.
    assert!(!md.contains("-cbc\""), "no CBC cipher offered");
    assert_eq!(off.view().await["aesCbc"], "off");
    off.link();
    let (_, to, head) = off.sign_in(cbc_to(&cert, true)).await;
    assert_eq!(to, "/login?error=sso_failed");
    assert!(signed_in_as(off.port, &head).await.is_none());
    assert_eq!(off.last_failure().await["reason"], "weak_algorithm");
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

#[tokio::test]
async fn mdq_answers_are_fetched_for_the_one_entity_and_held_to_mdqs_rules() {
    let signer = |i: usize| crate::sso::xmldsig::test_signer::signer(i);
    let valid_until = |days: i64| {
        let at = crate::sso::saml_sp::test_instant(crate::db::now() + days * 86_400_000);
        test_idp::metadata().replacen("<md:EntityDescriptor ", &format!(r#"<md:EntityDescriptor validUntil="{at}" "#), 1)
    };
    let served = std::sync::Arc::new(std::sync::Mutex::new(test_idp::metadata()));
    let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mdq_port = listener.local_addr().unwrap().port();
    let (s, a) = (served.clone(), asked.clone());
    let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
        a.lock().unwrap().push(uri.path().to_string());
        std::future::ready(s.lock().unwrap().clone())
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (sp, dir, provider) = serve_trusting("require", Some(("IDP_MDQ_URL", format!("http://127.0.0.1:{mdq_port}/mdq/")))).await;

    // Unsigned: no sign-in, audited with the source.
    let (code, head, _) = crate::tests::call_with(sp.port, "GET", &format!("/api/auth/sso/{}/start", sp.id), "", "", "").await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login?error=sso_failed")));
    assert_eq!(asked.lock().unwrap()[0], "/mdq/entities/https%3A%2F%2Fidp.example%2Fsaml", "the one entity, its ID in one path segment");
    let refused = &sp.audit("sso.saml_metadata_refused").await[0];
    assert_eq!((refused["details"]["reason"].as_str(), refused["details"]["source"].as_str()), (Some("unsigned"), Some("mdq")));

    // Signed by the federation but with no validUntil, or one too far ahead: refused too.
    for (xml, reason) in [(test_idp::signed_metadata(&test_idp::metadata(), signer(1)), "no_valid_until"), (test_idp::signed_metadata(&valid_until(31), signer(1)), "valid_too_long")] {
        *served.lock().unwrap() = xml;
        let (code, _, _) = crate::tests::call_with(sp.port, "GET", &format!("/api/auth/sso/{}/start", sp.id), "", "", "").await;
        assert_eq!(code, 303);
        assert_eq!(sp.audit("sso.saml_metadata_refused").await[0]["details"]["reason"].as_str(), Some(reason));
    }

    // A signed answer valid for a week: it loads, signs in, and shows when it ends.
    *served.lock().unwrap() = test_idp::signed_metadata(&valid_until(7), signer(1));
    let u = sp.link();
    let (code, _, head) = sp.sign_in(|_| {}).await;
    assert_eq!(code, 200);
    assert_eq!(signed_in_as(sp.port, &head).await, Some(u.id.clone()));
    let (_, v) = call(sp.port, "GET", &format!("/api/sso/{}/saml", sp.id), &sp.admin, "").await;
    let v: Value = serde_json::from_str(&v).unwrap();
    assert_eq!((v["source"].as_str(), v["idp"]["expired"].as_bool()), (Some("mdq"), Some(false)));
    assert!(v["from"].as_str().unwrap().ends_with("/mdq/entities/https%3A%2F%2Fidp.example%2Fsaml"), "{}", v["from"]);
    assert!(v["idp"]["validUntil"].as_i64().unwrap() > crate::db::now() + 6 * 86_400_000);

    // A day later the federation serves an aggregate: refused, and the good copy still signs in.
    *served.lock().unwrap() = test_idp::signed_metadata(&format!(r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">{}</md:EntitiesDescriptor>"#, valid_until(7).replacen(r#"<?xml version="1.0"?>"#, "", 1)), signer(1));
    provider.age_idp(std::time::Duration::from_secs(25 * 3600));
    let (code, _, head) = sp.sign_in(|_| {}).await;
    assert_eq!(code, 200, "the last good copy, still within its validUntil");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(u.id));
    let refused = &sp.audit("sso.saml_metadata_refused").await[0];
    assert_eq!((refused["details"]["reason"].as_str(), refused["details"]["source"].as_str(), refused["details"]["kept"].as_bool()), (Some("not_one_entity"), Some("mdq"), Some(true)));
    std::fs::remove_dir_all(dir).ok();
}

// Groups: required groups and group-to-role mapping (ADR 0160)

fn in_groups(groups: &[&str]) -> impl FnOnce(&mut Response) + use<> {
    let groups: Vec<String> = groups.iter().map(|g| g.to_string()).collect();
    move |r| r.multi_attributes = vec![("groups".into(), groups)]
}

/// Entra's overage claim: too many groups to list, so none are.
fn overage(r: &mut Response) {
    r.multi_attributes = vec![("groups".into(), vec!["Auditors".into()]), (crate::sso::saml_sp::GROUPS_OVERAGE.into(), vec!["https://graph.example/v1.0/users/x/getMemberObjects".into()])];
}

#[tokio::test]
async fn required_groups_keep_out_anyone_in_none_of_them_before_just_in_time() {
    let sp = serve_with(&[("GROUPS_ATTRIBUTE", "groups"), ("REQUIRED_GROUPS", "SuperBot Users,Admins"), ("ALLOWED_DOMAINS", "example.com"), ("JIT_ROLE", "member")], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    let refused = async |tweak: Box<dyn FnOnce(&mut Response)>, reason: &str| {
        let (code, to, head) = sp.sign_in(tweak).await;
        assert_eq!((code, to.as_str()), (303, "/login?error=sso_not_allowed"), "{reason}");
        assert_eq!(signed_in_as(sp.port, &head).await, None);
        let f = sp.last_failure().await;
        assert_eq!((f["reason"].as_str(), f["subject"].as_str()), (Some(reason), Some(STORED)));
        f
    };
    refused(Box::new(|r| r.multi_attributes.clear()), "not_in_group").await;
    refused(Box::new(in_groups(&[])), "not_in_group").await;
    refused(Box::new(in_groups(&["Everyone", "Engineering"])), "not_in_group").await;
    refused(Box::new(in_groups(&["superbot users", "ADMINS"])), "not_in_group").await;
    // Only the named attribute counts.
    refused(Box::new(|r| r.multi_attributes = vec![("memberOf".into(), vec!["Admins".into()])]), "not_in_group").await;
    let f = refused(Box::new(overage), "groups_unknown").await;
    assert_eq!(f["groups"], "overage");
    let many: Vec<String> = (0..=crate::sso::saml_sp::MAX_GROUPS).map(|i| format!("g{i}")).chain(["Admins".into()]).collect();
    let f = refused(Box::new(move |r| r.multi_attributes = vec![("groups".into(), many)]), "groups_unknown").await;
    assert_eq!(f["groups"], "too_many");
    assert!(sp.app.db.identity(IDP, STORED).is_none(), "no account made");

    let (code, _, head) = sp.sign_in(in_groups(&["Everyone", "Admins"])).await;
    assert_eq!(code, 200);
    let uid = signed_in_as(sp.port, &head).await.expect("in a required group");
    assert_eq!(sp.app.db.user(&uid).unwrap().role, Role::Member);
    // Checked on every sign-in, not only the first.
    refused(Box::new(in_groups(&["Everyone"])), "not_in_group").await;
}

#[tokio::test]
async fn only_admins_map_a_saml_group_and_only_to_a_safe_custom_role() {
    let sp = serve(&[("GROUPS_ATTRIBUTE", "groups")]).await;
    let (port, admin, id) = (sp.port, sp.admin.clone(), sp.id.clone());
    sp.app.db.create_custom_role("Auditor", "", Role::Member, &["audit.view"], None, None).unwrap();
    sp.app.db.create_custom_role("Ops", "", Role::Member, &["bots.manage"], None, None).unwrap();
    let map = async |body: Value| call(port, "POST", "/api/sso/role-mappings", &admin, &body.to_string()).await;
    for (body, code) in [
        (json!({ "provider": id, "group": "Admins", "role": "admin" }), 400),
        (json!({ "provider": id, "group": "Admins", "role": "member" }), 400),
        (json!({ "provider": id, "group": "Admins", "role": "Ops" }), 400),
        (json!({ "provider": id, "group": "Admins", "role": "Nobody" }), 404),
        (json!({ "provider": id, "group": "  ", "role": "Auditor" }), 400),
        (json!({ "provider": id, "group": "Auditors" }), 400),
        (json!({ "provider": "nope", "group": "Auditors", "role": "Auditor" }), 400),
        (json!({ "provider": id, "group": "Auditors", "role": "Auditor", "scope": "team" }), 400),
    ] {
        let (got, e) = map(body.clone()).await;
        assert_eq!(got, code, "{body} {e}");
    }
    let refused = sp.audit("sso.saml_role_map_refused").await;
    let reasons: Vec<&str> = refused.iter().filter_map(|e| e["details"]["reason"].as_str()).collect();
    assert_eq!(reasons, ["reaches_admins", "built_in", "admin"]);
    assert!(refused.iter().all(|e| e["outcome"] == "denied"));
    assert_eq!(refused[0]["details"]["permissions"], json!(["bots.manage"]));

    let (code, m) = map(json!({ "provider": id, "group": "Auditors", "role": "Auditor" })).await;
    assert_eq!(code, 201, "{m}");
    let m: Value = serde_json::from_str(&m).unwrap();
    assert_eq!((m["group"].as_str(), m["role"]["name"].as_str(), m["groupsAttribute"].as_str(), m["active"].as_bool(), m["grants"].as_u64()), (Some("Auditors"), Some("Auditor"), Some("groups"), Some(true), Some(0)));
    assert_eq!(sp.audit("sso.saml_role_mapped").await[0]["details"]["group"], "Auditors");
    assert_eq!(map(json!({ "provider": id, "group": "Auditors", "role": "Auditor" })).await.0, 409, "one role per group");
    let (code, all) = call(port, "GET", "/api/sso/role-mappings", &sp.admin, "").await;
    assert_eq!(code, 200);
    let all: Value = serde_json::from_str(&all).unwrap();
    assert_eq!((all["mappings"].as_array().unwrap().len(), all["providers"][0]["groupsAttribute"].as_str()), (1, Some("groups")));
    let (_, saml) = call(port, "GET", &format!("/api/sso/{id}/saml"), &sp.admin, "").await;
    assert_eq!(serde_json::from_str::<Value>(&saml).unwrap()["roleMappings"], 1);

    let member = sp.app.db.create_user(None, Some("bob@example.com"), "Bob", Role::Member).unwrap();
    let bob = session_for(port, &sp.admin, &member.id).await;
    assert_eq!(call(port, "GET", "/api/sso/role-mappings", &bob, "").await.0, 403);
    assert_eq!(call(port, "GET", &format!("/api/sso/role-mappings/{}", m["id"].as_str().unwrap()), &bob, "").await.0, 403);
    assert_eq!(call(port, "POST", "/api/sso/role-mappings", &bob, &json!({ "provider": id, "group": "Ops", "role": "Auditor" }).to_string()).await.0, 403);
    assert_eq!(call(port, "DELETE", &format!("/api/sso/role-mappings/{}", m["id"].as_str().unwrap()), &bob, "").await.0, 403);
    assert_eq!(call(port, "DELETE", "/api/sso/role-mappings/gmnope", &sp.admin, "").await.0, 404);

    // A provider that reads no groups has nothing to map.
    let plain = serve(&[]).await;
    plain.app.db.create_custom_role("Auditor", "", Role::Member, &["audit.view"], None, None).unwrap();
    let (code, e) = call(plain.port, "POST", "/api/sso/role-mappings", &plain.admin, &json!({ "provider": plain.id, "group": "Auditors", "role": "Auditor" }).to_string()).await;
    assert_eq!(code, 409, "{e}");
    assert!(e.contains("GROUPS_ATTRIBUTE"), "{e}");
}

#[tokio::test]
async fn a_mapped_saml_group_gives_its_role_only_while_sign_ins_list_it() {
    let sp = serve(&[("GROUPS_ATTRIBUTE", "groups")]).await;
    let (port, admin, id) = (sp.port, sp.admin.clone(), sp.id.clone());
    let auditor = sp.app.db.create_custom_role("Auditor", "", Role::Member, &["audit.view"], None, None).unwrap();
    let (code, m) = call(port, "POST", "/api/sso/role-mappings", &admin, &json!({ "provider": id, "group": "Auditors", "role": auditor.id }).to_string()).await;
    assert_eq!(code, 201, "{m}");
    let mid = serde_json::from_str::<Value>(&m).unwrap()["id"].as_str().unwrap().to_string();
    let u = sp.app.db.create_user(None, Some("ada@example.com"), "Ada", Role::Readonly).unwrap();
    let (code, i) = call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": NAME_ID }).to_string()).await;
    assert_eq!(code, 201, "{i}");
    let roles = || {
        let u = sp.app.db.user(&u.id).unwrap();
        (u.role, u.role_id)
    };
    let given = (Role::Member, Some(auditor.id.clone()));
    let sign_in = async |tweak: Box<dyn FnOnce(&mut Response)>| {
        let (code, _, head) = sp.sign_in(tweak).await;
        assert_eq!(code, 200);
        assert_eq!(signed_in_as(port, &head).await.as_deref(), Some(u.id.as_str()));
    };

    // Not in the group: nothing.
    sign_in(Box::new(in_groups(&["Everyone"]))).await;
    assert_eq!(roles(), (Role::Readonly, None));
    // In it: the role, its base role, and the audit trail.
    sign_in(Box::new(in_groups(&["Everyone", "Auditors"]))).await;
    assert_eq!(roles(), given);
    let a = &sp.audit("role.assigned").await[0]["details"];
    assert_eq!((a["via"].as_str(), a["mapping"].as_str(), a["group"].as_str(), a["provider"].as_str()), (Some("saml"), Some(mid.as_str()), Some("Auditors"), Some(id.as_str())));
    let changed = &sp.audit("user.role_changed").await[0]["details"];
    assert_eq!((changed["reason"].as_str(), changed["from"].as_str(), changed["to"].as_str()), (Some("saml_group"), Some("readonly"), Some("member")));
    let (_, held) = call(port, "GET", &format!("/api/sso/role-mappings/{mid}"), &admin, "").await;
    let held: Value = serde_json::from_str(&held).unwrap();
    assert_eq!((held["holders"][0]["user"]["id"].as_str(), held["holders"][0]["priorRole"].as_str(), held["grants"].as_u64()), (Some(u.id.as_str()), Some("readonly"), Some(1)));
    let (_, r) = call(port, "GET", &format!("/api/roles/{}", auditor.id), &admin, "").await;
    assert_eq!(serde_json::from_str::<Value>(&r).unwrap()["samlMappings"], 1, "{r}");
    // Again: nothing new.
    sign_in(Box::new(in_groups(&["Auditors"]))).await;
    assert_eq!((roles(), sp.audit("role.assigned").await.len()), (given.clone(), 1));

    // The role can't grow to act on admins, nor go, while a group maps to it.
    let (code, e) = call(port, "PATCH", &format!("/api/roles/{}", auditor.id), &admin, &json!({ "permissions": ["audit.view", "bots.manage"] }).to_string()).await;
    assert_eq!(code, 409, "{e}");
    assert!(e.contains("SAML"), "{e}");
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{}", auditor.id), &admin, "").await.0, 409);

    // Leaving the group takes it back to what they had before.
    sign_in(Box::new(in_groups(&["Everyone"]))).await;
    assert_eq!(roles(), (Role::Readonly, None));
    let gone = &sp.audit("role.unassigned").await[0]["details"];
    assert_eq!((gone["via"].as_str(), gone["reason"].as_str()), (Some("saml"), Some("left_group")));
    // Groups the IdP couldn't list count as none.
    sign_in(Box::new(in_groups(&["Auditors"]))).await;
    assert_eq!(roles(), given);
    sign_in(Box::new(overage)).await;
    assert_eq!(roles(), (Role::Readonly, None));
    assert_eq!(sp.audit("role.unassigned").await[0]["details"]["reason"], "groups_unknown");
    // Group names are exact.
    sign_in(Box::new(in_groups(&["auditors"]))).await;
    assert_eq!(roles(), (Role::Readonly, None));

    // An admin's change by hand stands while the group still lists them.
    sign_in(Box::new(in_groups(&["Auditors"]))).await;
    assert_eq!(roles(), given);
    let (code, e) = call(port, "PATCH", &format!("/api/users/{}", u.id), &admin, &json!({ "role": "member" }).to_string()).await;
    assert_eq!(code, 200, "{e}");
    assert_eq!(roles(), (Role::Member, None));
    sign_in(Box::new(in_groups(&["Auditors"]))).await;
    assert_eq!(roles(), (Role::Member, None), "not given back");
    sign_in(Box::new(overage)).await;
    sign_in(Box::new(in_groups(&["Auditors"]))).await;
    assert_eq!(roles(), (Role::Member, None), "unknown groups don't end the hand change");
    sign_in(Box::new(in_groups(&["Everyone"]))).await;
    assert_eq!(roles(), (Role::Member, None), "nothing to take: it was never the group's");
    // Once a sign-in no longer lists the group, it maps again.
    sign_in(Box::new(in_groups(&["Auditors"]))).await;
    assert_eq!(roles(), given);
    // So does unassigning the custom role by hand: the base role stays.
    let (code, e) = call(port, "DELETE", &format!("/api/roles/{}/users/{}", auditor.id, u.id), &admin, "").await;
    assert_eq!(code, 200, "{e}");
    assert_eq!(sp.audit("role.unassigned").await[0]["details"]["samlMapping"], mid.as_str());
    sign_in(Box::new(in_groups(&["Auditors"]))).await;
    assert_eq!(roles().1, None, "held by the hand change");
    sign_in(Box::new(in_groups(&[]))).await;
    sign_in(Box::new(in_groups(&["Auditors"]))).await;
    assert_eq!(roles(), given);

    // Admins are never touched; it is audited.
    let boss = sp.app.db.create_user(None, Some("boss@example.com"), "Boss", Role::Admin).unwrap();
    call(port, "POST", &format!("/api/users/{}/identities", boss.id), &admin, &json!({ "provider": id, "subject": "00u1BOSS" }).to_string()).await;
    let (code, _, _) = sp
        .sign_in(|r| {
            r.name_id = "00u1BOSS".into();
            r.attributes = vec![("email".into(), "boss@example.com".into())];
            r.multi_attributes = vec![("groups".into(), vec!["Auditors".into()])];
        })
        .await;
    assert_eq!(code, 200);
    assert_eq!((sp.app.db.user(&boss.id).unwrap().role, sp.app.db.user(&boss.id).unwrap().role_id), (Role::Admin, None));
    assert_eq!(sp.audit("sso.saml_role_skipped").await[0]["details"]["reason"], "admin");

    // Unlinking their identity at this provider takes it back.
    let iid = serde_json::from_str::<Value>(&i).unwrap()["id"].as_str().unwrap().to_string();
    let (code, e) = call(port, "DELETE", &format!("/api/users/{}/identities/{iid}", u.id), &admin, "").await;
    assert_eq!(code, 200, "{e}");
    let before = (Role::Member, None);
    assert_eq!(roles(), before, "back to the role they had when it was given");
    assert_eq!(sp.audit("role.unassigned").await[0]["details"]["reason"], "unlinked");
    call(port, "POST", &format!("/api/users/{}/identities", u.id), &admin, &json!({ "provider": id, "subject": NAME_ID }).to_string()).await;
    sign_in(Box::new(in_groups(&["Auditors"]))).await;
    assert_eq!(roles(), given);

    // Removing the mapping takes the role from everyone it gave it to.
    let (code, gone) = call(port, "DELETE", &format!("/api/sso/role-mappings/{mid}"), &admin, "").await;
    assert_eq!(code, 200, "{gone}");
    assert_eq!(serde_json::from_str::<Value>(&gone).unwrap()["revoked"], json!([u.id]));
    assert_eq!(roles(), before);
    assert_eq!(sp.audit("role.unassigned").await[0]["details"]["reason"], "mapping_removed");
    assert_eq!(sp.audit("sso.saml_role_unmapped").await.len(), 1);
    sign_in(Box::new(in_groups(&["Auditors"]))).await;
    assert_eq!(roles(), before);
    assert_eq!(call(port, "DELETE", &format!("/api/roles/{}", auditor.id), &admin, "").await.0, 200);
}

#[tokio::test]
async fn a_provider_that_stops_reading_groups_takes_back_what_its_groups_gave() {
    let sp = serve(&[]).await;
    let u = sp.link();
    let auditor = sp.app.db.create_custom_role("Auditor", "", Role::Member, &["audit.view"], None, None).unwrap();
    // Mapped while it read groups, then restarted without.
    let m = sp.app.db.create_saml_role_mapping(&sp.id, None, "Auditors", &auditor.id, None).unwrap();
    assert!(sp.app.db.grant_saml_role(&m, &u.id));
    let (code, _, _) = sp.sign_in(in_groups(&["Auditors"])).await;
    assert_eq!(code, 200);
    assert_eq!((sp.app.db.user(&u.id).unwrap().role, sp.app.db.user(&u.id).unwrap().role_id), (Role::Member, None));
    assert_eq!(sp.audit("role.unassigned").await[0]["details"]["reason"], "groups_unknown");
    let (_, v) = call(sp.port, "GET", &format!("/api/sso/role-mappings/{}", m.id), &sp.admin, "").await;
    assert_eq!(serde_json::from_str::<Value>(&v).unwrap()["active"], false, "{v}");
}

#[tokio::test]
async fn a_change_by_hand_to_another_providers_grant_holds_against_this_ones_groups() {
    let sp = serve(&[("GROUPS_ATTRIBUTE", "groups")]).await;
    let u = sp.link();
    let auditor = sp.app.db.create_custom_role("Auditor", "", Role::Member, &["audit.view"], None, None).unwrap();
    sp.app.db.create_saml_role_mapping(&sp.id, None, "Auditors", &auditor.id, None).unwrap();
    let theirs = sp.app.db.create_saml_role_mapping("other", None, "Auditors", &auditor.id, None).unwrap();
    assert!(sp.app.db.grant_saml_role(&theirs, &u.id));
    let (code, e) = call(sp.port, "DELETE", &format!("/api/roles/{}/users/{}", auditor.id, u.id), &sp.admin, "").await;
    assert_eq!(code, 200, "{e}");
    let (code, _, _) = sp.sign_in(in_groups(&["Auditors"])).await;
    assert_eq!(code, 200);
    assert_eq!(sp.app.db.user(&u.id).unwrap().role_id, None, "only the other provider can say they left its group");
    assert_eq!(sp.app.db.saml_role_released(&u.id), Some(theirs.id));
    assert!(sp.audit("role.assigned").await.is_empty());
}

#[tokio::test]
async fn a_sign_in_refused_for_required_groups_still_takes_back_what_a_left_group_gave() {
    let sp = serve_with(&[("GROUPS_ATTRIBUTE", "groups"), ("REQUIRED_GROUPS", "SuperBot Users")], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    let u = sp.link();
    let auditor = sp.app.db.create_custom_role("Auditor", "", Role::Member, &["audit.view"], None, None).unwrap();
    sp.app.db.create_saml_role_mapping(&sp.id, None, "Auditors", &auditor.id, None).unwrap();
    let role_id = || sp.app.db.user(&u.id).unwrap().role_id;

    // Refused: never given anything.
    let (_, to, _) = sp.sign_in(in_groups(&["Auditors"])).await;
    assert_eq!((to.as_str(), role_id()), ("/login?error=sso_not_allowed", None));
    let (code, _, _) = sp.sign_in(in_groups(&["SuperBot Users", "Auditors"])).await;
    assert_eq!((code, role_id()), (200, Some(auditor.id.clone())));
    // Refused, but still in the mapped group: kept.
    let (_, to, _) = sp.sign_in(in_groups(&["Auditors"])).await;
    assert_eq!((to.as_str(), role_id()), ("/login?error=sso_not_allowed", Some(auditor.id.clone())));
    // Refused, and out of it too: taken back.
    let (_, to, _) = sp.sign_in(in_groups(&["Everyone"])).await;
    assert_eq!((to.as_str(), role_id()), ("/login?error=sso_not_allowed", None));
    let gone = &sp.audit("role.unassigned").await[0]["details"];
    assert_eq!((gone["reason"].as_str(), gone["via"].as_str()), (Some("left_group"), Some("saml")));
    assert_eq!(sp.app.db.user(&u.id).unwrap().role, Role::Member);
    // Unknown groups count as none here too.
    let (code, _, _) = sp.sign_in(in_groups(&["SuperBot Users", "Auditors"])).await;
    assert_eq!((code, role_id()), (200, Some(auditor.id.clone())));
    let (_, to, _) = sp.sign_in(overage).await;
    assert_eq!((to.as_str(), role_id()), ("/login?error=sso_not_allowed", None));
    assert_eq!(sp.audit("role.unassigned").await[0]["details"]["reason"], "groups_unknown");
}

// IdP-initiated sign-in (ADR 0175)

impl Sp {
    /// What an IdP's app tile posts: a response that answers no request.
    fn unsolicited(&self) -> Response {
        Response::new(&self.acs(), &self.entity(), "", db::now())
    }
}

const RESTART: &str = "__Host-superbot_saml_restart";

#[tokio::test]
async fn idp_initiated_posts_are_refused_unless_the_provider_restarts_them() {
    let sp = serve(&[]).await;
    sp.link();
    let (code, to, head) = sp.post(Some(&sp.unsolicited().posted()), None, "").await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_expired"));
    assert!(signed_in_as(sp.port, &head).await.is_none());
    assert_eq!(sp.last_failure().await["reason"], "unknown_state");
    assert!(sp.audit("auth.saml_idp_initiated").await.is_empty());
    let v: Value = serde_json::from_str(&call(sp.port, "GET", &format!("/api/sso/{}/saml", sp.id), &sp.admin, "").await.1).unwrap();
    assert_eq!(v["idpInitiated"], "off");
}

#[tokio::test]
async fn an_idp_initiated_post_restarts_as_an_sp_initiated_sign_in() {
    let sp = serve_with(&[("IDP_INITIATED", "restart")], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    let u = sp.link();
    let v: Value = serde_json::from_str(&call(sp.port, "GET", &format!("/api/sso/{}/saml", sp.id), &sp.admin, "").await.1).unwrap();
    assert_eq!(v["idpInitiated"], "restart");

    // The tile's post signs nobody in: it sends the browser to start a sign-in of our own,
    // whatever RelayState the IdP sent (Okta's default RelayState, say). It names someone else
    // (Mallory, linked too), so only the later answer can say who gets the session.
    let logins = || async { audit_list(&call(sp.port, "GET", "/api/audit?action=auth.login", &sp.admin, "").await.1).len() };
    let before = logins().await;
    let mallory = sp.app.db.create_user(None, Some("mallory@example.com"), "Mallory", Role::Member).unwrap();
    sp.app.db.link_identity(&mallory.id, &NewIdentity { provider: &sp.id, issuer: IDP, subject: "mallory-1", tenant: None, email: None, created_by: Some("test") }).unwrap();
    let mut tile = sp.unsolicited();
    tile.name_id = "mallory-1".into();
    tile.attributes = vec![("email".into(), "mallory@example.com".into())];
    let (code, to, head) = sp.post(Some(&tile.posted()), Some("https://evil.example/next"), "").await;
    assert_eq!((code, to), (303, format!("http://127.0.0.1:{}/api/auth/sso/{}/start", sp.port, sp.id)));
    assert!(signed_in_as(sp.port, &head).await.is_none());
    let marker = set_cookies(&head).into_iter().find(|c| c.starts_with(&format!("{RESTART}="))).expect("restart marker");
    assert!(marker.starts_with(&format!("{RESTART}={};", sp.id)), "it names the provider: {marker}");
    assert!(marker.contains("Max-Age=120") && marker.contains("SameSite=None") && marker.contains("Secure") && marker.contains("HttpOnly"), "{marker}");
    let restarted = &sp.audit("auth.saml_idp_initiated").await[0];
    let d = &restarted["details"];
    assert_eq!((d["outcome"].as_str(), d["subject"].as_str(), d["issuer"].as_str(), d["assertion"].as_str()), (Some("restarted"), Some("mallory-1"), Some(IDP), Some(tile.assertion_id.as_str())));
    assert_eq!((restarted["actorSubject"].as_str(), restarted["idpProvider"].as_str()), (Some(format!("{IDP}|mallory-1").as_str()), Some(sp.id.as_str())));
    assert_eq!(logins().await, before);

    // The browser follows it, and the IdP answers that request for whoever this browser is at
    // the IdP (Ada): she is signed in, not the tile's Mallory, and the marker is cleared.
    let (request, relay, binder) = sp.start().await;
    let cookie = format!("{binder}; {RESTART}={}", sp.id);
    let (code, _, head) = sp.post(Some(&Response::new(&sp.acs(), &sp.entity(), &request, db::now()).posted()), Some(&relay), &cookie).await;
    assert_eq!(code, 200);
    assert_eq!(signed_in_as(sp.port, &head).await, Some(u.id.clone()));
    assert!(set_cookies(&head).iter().any(|c| c.starts_with(&format!("{RESTART}=;")) && c.contains("Max-Age=0")), "{head}");

    // The tile's assertion is spent: posted again, it's a replay.
    let (_, to, _) = sp.post(Some(&tile.posted()), None, "").await;
    assert_eq!(to, "/login?error=sso_failed");
    let f = sp.last_failure().await;
    assert_eq!((f["reason"].as_str(), f["idpInitiated"].as_bool()), (Some("replayed"), Some(true)));

    // An IdP that answers our request unsolicited again would go round forever: refused.
    let (_, to, head) = sp.post(Some(&sp.unsolicited().posted()), None, &format!("{RESTART}={}", sp.id)).await;
    assert_eq!(to, "/login?error=sso_failed");
    assert_eq!(sp.last_failure().await["reason"], "idp_initiated_loop");
    assert!(set_cookies(&head).iter().any(|c| c.starts_with(&format!("{RESTART}=;"))), "the marker goes, so the next tile works");
    assert_eq!(sp.audit("auth.saml_idp_initiated").await.len(), 1);
    // A marker another provider's restart left isn't a loop here.
    let (code, to, _) = sp.post(Some(&sp.unsolicited().posted()), None, &format!("{RESTART}=other")).await;
    assert_eq!((code, to.ends_with("/start")), (303, true), "{to}");
    assert_eq!(sp.audit("auth.saml_idp_initiated").await.len(), 2);
}

#[tokio::test]
async fn idp_initiated_posts_are_checked_as_fully_as_any_other() {
    let sp = serve_with(&[("IDP_INITIATED", "restart")], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    sp.link();
    // A response to a request botd no longer holds (it expired, or another browser's) isn't
    // unsolicited: refused as before.
    let mut stale = sp.unsolicited();
    stale.in_response_to = "_gone".into();
    stale.confirm_in_response_to = "_gone".into();
    assert_eq!(sp.post(Some(&stale.posted()), Some("not-ours"), "").await.1, "/login?error=sso_expired");
    assert_eq!(sp.last_failure().await["reason"], "unknown_state");
    let now = db::now();
    type Tweak = Box<dyn FnOnce(&mut Response)>;
    let cases: Vec<(&str, Tweak)> = vec![
        ("wrong_audience", Box::new(|r| r.audience = "https://other.example/sp".into())),
        ("wrong_recipient", Box::new(|r| r.recipient = "https://other.example/acs".into())),
        ("wrong_issuer", Box::new(|r| r.issuer = "https://evil.example/saml".into())),
        ("expired", Box::new(move |r| r.confirm_not_on_or_after = now - 300_000)),
        ("transient_subject", Box::new(|r| r.name_id_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".into())),
        ("unsigned", Box::new(|r| r.sign_assertion = false)),
    ];
    for (want, tweak) in cases {
        let mut r = sp.unsolicited();
        tweak(&mut r);
        let (code, to, head) = sp.post(Some(&r.posted()), None, "").await;
        assert_eq!((code, to.as_str()), (303, "/login?error=sso_failed"), "{want}");
        assert!(set_cookies(&head).iter().all(|c| !c.starts_with(&format!("{RESTART}=1"))), "{want}: no restart");
        // Failures nobody vouched for are audited at most once a minute per client.
        if want != "unsigned" {
            let f = sp.last_failure().await;
            assert_eq!((f["reason"].as_str(), f["idpInitiated"].as_bool()), (Some(want), Some(true)));
        }
    }
    // Nothing posted, or nothing that parses.
    assert_eq!(sp.post(None, None, "").await.1, "/login?error=sso_expired");
    assert_eq!(sp.post(Some("not base64 <xml>"), None, "").await.1, "/login?error=sso_failed");
    assert!(sp.audit("auth.saml_idp_initiated").await.is_empty());
}

#[tokio::test]
async fn an_idp_initiated_encrypted_assertion_restarts_too() {
    let sp = serve(&[("IDP_INITIATED", "restart"), ("ENCRYPTED_ASSERTIONS", "require")]).await;
    sp.link();
    let mut tile = sp.unsolicited();
    encrypted_to(&sp.enc_cert().await)(&mut tile);
    let (code, to, _) = sp.post(Some(&tile.posted()), None, "").await;
    assert_eq!((code, to.ends_with("/start")), (303, true), "{to}");
    // Plain, it's refused as encryption requires.
    let (_, to, _) = sp.post(Some(&sp.unsolicited().posted()), None, "").await;
    assert_eq!(to, "/login?error=sso_failed");
    assert_eq!(sp.last_failure().await["reason"], "unencrypted_assertion");
}

// Rolling over botd's own SP keys (ADR 0181)

impl Sp {
    async fn sp_metadata(&self) -> String {
        http().get(format!("http://127.0.0.1:{}/api/auth/sso/{}/metadata", self.port, self.id)).send().await.unwrap().text().await.unwrap()
    }

    /// The certificates our metadata publishes for `key_use`, in order.
    async fn published(&self, key_use: &str) -> Vec<String> {
        let md = self.sp_metadata().await;
        md.split(&format!(r#"<md:KeyDescriptor use="{key_use}">"#)).skip(1).map(|kd| kd.split("<ds:X509Certificate>").nth(1).unwrap().split('<').next().unwrap().to_string()).collect()
    }

    /// One step of a rollover, as botctl takes it: the status and the provider's view after.
    async fn key_step(&self, method: &str, key_use: &str, end: &str) -> (u16, Value) {
        let (code, body) = call(self.port, method, &format!("/api/sso/{}/saml/keys/{key_use}/{end}", self.id), &self.admin, "").await;
        (code, serde_json::from_str(&body).unwrap_or(json!({ "error": body })))
    }
}

fn sha_of(cert: &str) -> String {
    crate::sso::xmldsig::Cert::from_base64(cert).unwrap().sha256
}

#[tokio::test]
async fn an_encryption_key_rolls_over_without_refusing_a_sign_in() {
    let sp = serve(&[("ENCRYPTED_ASSERTIONS", "require")]).await;
    let u = sp.link();
    let old = sp.enc_cert().await;
    let signing = sp.published("signing").await;
    let signs_in = |cert: &str| {
        let cert = cert.to_string();
        let sp = &sp;
        async move {
            let (code, to, head) = sp.sign_in(encrypted_to(&cert)).await;
            (code == 200).then_some(()).and(signed_in_as(sp.port, &head).await).ok_or(to)
        }
    };
    assert_eq!(signs_in(&old).await, Ok(u.id.clone()));

    // A next key: published after the one in use, and it decrypts, before the IdP is told.
    let (code, v) = sp.key_step("POST", "encryption", "next").await;
    assert_eq!(code, 200, "{v}");
    let next_sha = v["spEncryptionKey"]["next"]["certificate"]["sha256"].as_str().unwrap().to_string();
    assert_eq!(v["spEncryptionKey"]["certificate"]["sha256"].as_str(), Some(sha_of(&old).as_str()), "the one in use stays");
    let published = sp.published("encryption").await;
    assert_eq!((published.len(), published[0] == old, sha_of(&published[1])), (2, true, next_sha.clone()));
    assert_eq!(sp.published("signing").await, signing, "the signing key is left alone");
    let made = &sp.audit("sso.saml_sp_key_created").await[0];
    assert_eq!((made["details"]["use"].as_str(), made["details"]["stage"].as_str(), made["details"]["certificate"].as_str()), (Some("encryption"), Some("next"), Some(next_sha.as_str())));
    assert_eq!(made["actorId"].as_str(), sp.app.db.users().iter().find(|u| u.role == Role::Admin).map(|u| u.id.as_str()), "made by the admin");
    let next = published[1].clone();
    let view = |sp: &Sp| {
        let (port, id, admin) = (sp.port, sp.id.clone(), sp.admin.clone());
        async move { serde_json::from_str::<Value>(&call(port, "GET", &format!("/api/sso/{id}/saml"), &admin, "").await.1).unwrap()["spEncryptionKey"].clone() }
    };
    assert_eq!(view(&sp).await["next"]["lastUsedSecondsAgo"], Value::Null, "the IdP hasn't used it yet");
    assert_eq!(signs_in(&next).await, Ok(u.id.clone()), "an IdP that took up the new metadata early");
    assert!(view(&sp).await["next"]["lastUsedSecondsAgo"].is_u64(), "now it has");
    assert_eq!(signs_in(&old).await, Ok(u.id.clone()));
    let (code, e) = sp.key_step("POST", "encryption", "next").await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("already a next"), "{e}");

    // Promoted: the new key is the one published; the old one still decrypts until retired.
    let (code, v) = sp.key_step("POST", "encryption", "promote").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["spEncryptionKey"]["certificate"]["sha256"].as_str(), v["spEncryptionKey"]["next"].clone()), (Some(next_sha.as_str()), Value::Null));
    assert_eq!(v["spEncryptionKey"]["previous"]["certificate"]["sha256"].as_str(), Some(sha_of(&old).as_str()));
    assert_eq!(sp.published("encryption").await, vec![next.clone()], "never the previous key");
    assert_eq!(sp.app.db.setting(&format!("sso_saml_sp_cert_{}_encryption", sp.id)), Some(next.clone()));
    assert_eq!(sp.app.db.setting(&format!("sso_saml_sp_cert_{}_encryption_previous", sp.id)), Some(old.clone()));
    assert!(sp.app.db.setting(&format!("sso_saml_sp_key_{}_encryption_next", sp.id)).is_none());
    for stage in ["", "_previous"] {
        let sealed = sp.app.db.setting(&format!("sso_saml_sp_key_{}_encryption{stage}", sp.id)).unwrap();
        assert!(crate::secrets::sealed::is_sealed(&sealed), "sealed again where it now is: {stage}");
    }
    let promoted = &sp.audit("sso.saml_sp_key_promoted").await[0];
    let d = &promoted["details"];
    assert_eq!((d["use"].as_str(), d["certificate"].as_str(), d["replaced"].as_str(), d["previousKept"].as_bool()), (Some("encryption"), Some(next_sha.as_str()), Some(sha_of(&old).as_str()), Some(true)));
    let promoted_view = view(&sp).await;
    assert!(promoted_view["previous"]["lastUsedSecondsAgo"].is_u64() && promoted_view["lastUsedSecondsAgo"].is_u64(), "each key keeps its history: {promoted_view}");
    assert_eq!(signs_in(&old).await, Ok(u.id.clone()), "an IdP that hasn't refreshed yet");
    assert_eq!(signs_in(&next).await, Ok(u.id.clone()));
    assert!(view(&sp).await["lastUsedSecondsAgo"].is_u64(), "the key in use, too");

    // One rollover at a time: a second promotion waits for the previous key to be retired.
    let (code, e) = sp.key_step("POST", "encryption", "promote").await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("no next"), "{e}");
    assert_eq!(sp.key_step("POST", "encryption", "next").await.0, 200);
    let (code, e) = sp.key_step("POST", "encryption", "promote").await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("retire it first"), "{e}");
    let (code, v) = sp.key_step("DELETE", "encryption", "next").await;
    assert_eq!((code, v["spEncryptionKey"]["next"].clone()), (200, Value::Null));
    assert_eq!(sp.published("encryption").await, vec![next.clone()]);
    let cancelled = &sp.audit("sso.saml_sp_key_retired").await[0];
    assert_eq!(cancelled["details"]["stage"], "next");

    // Retired: the old key is gone for good.
    let (code, v) = sp.key_step("DELETE", "encryption", "previous").await;
    assert_eq!((code, v["spEncryptionKey"]["previous"].clone()), (200, Value::Null));
    let retired = &sp.audit("sso.saml_sp_key_retired").await[0];
    assert_eq!((retired["details"]["stage"].as_str(), retired["details"]["certificate"].as_str()), (Some("previous"), Some(sha_of(&old).as_str())));
    assert!(sp.app.db.setting(&format!("sso_saml_sp_key_{}_encryption_previous", sp.id)).is_none());
    assert_eq!(signs_in(&old).await, Err("/login?error=sso_failed".to_string()));
    assert_eq!(sp.last_failure().await["reason"], "bad_encryption");
    assert_eq!(signs_in(&next).await, Ok(u.id.clone()));
    assert_eq!(sp.key_step("DELETE", "encryption", "previous").await.0, 409, "nothing left to retire");
}

#[tokio::test]
async fn a_signing_key_is_published_first_and_signs_only_once_promoted() {
    let sp = serve_slo(&[("SIGN_REQUESTS", "true")]).await;
    let old = sp.sp_cert().await;
    let (code, v) = sp.key_step("POST", "signing", "next").await;
    assert_eq!(code, 200, "{v}");
    assert!(v["spKey"]["next"]["certificate"]["sha256"].is_string() && v["spKey"].get("previous").is_none(), "{v}");
    let published = sp.published("signing").await;
    assert_eq!((published.len(), sha_of(&published[0])), (2, old.sha256.clone()), "the one in use first");
    let next = crate::sso::xmldsig::Cert::from_base64(&published[1]).unwrap();
    let request = || async {
        let (code, head, _) = crate::tests::call_with(sp.port, "GET", &format!("/api/auth/sso/{}/start", sp.id), "", "", "").await;
        assert_eq!(code, 303);
        let (_, query) = header(&head, "location").unwrap().split_once('?').map(|(a, b)| (a.to_string(), b.to_string())).unwrap();
        crate::sso::saml_sp::from_redirect(&query).unwrap()
    };
    let r = request().await;
    assert_eq!(r.verify(std::slice::from_ref(&old)), Ok(true), "still signed with the old key");
    assert!(r.verify(std::slice::from_ref(&next)).is_err());

    let (code, v) = sp.key_step("POST", "signing", "promote").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["spKey"]["certificate"]["sha256"].as_str(), Some(next.sha256.as_str()));
    assert_eq!(sp.published("signing").await, vec![published[1].clone()]);
    let r = request().await;
    assert_eq!(r.verify(std::slice::from_ref(&next)), Ok(true), "signed with the new key");
    assert!(r.verify(std::slice::from_ref(&old)).is_err());
    assert!(sp.app.db.setting(&format!("sso_saml_sp_key_{}_previous", sp.id)).is_none(), "a replaced signing key isn't kept");
    let promoted = &sp.audit("sso.saml_sp_key_promoted").await[0];
    assert_eq!((promoted["details"]["use"].as_str(), promoted["details"]["previousKept"].as_bool()), (Some("signing"), Some(false)));
    assert_eq!(sp.key_step("DELETE", "signing", "previous").await.0, 409);

    // Logout answers are signed with it too.
    sp.link();
    let (code, to) = sp.slo_get(&Logout::request(&sp.slo(), NAME_ID, None, db::now()).redirect()).await;
    assert_eq!(code, 303, "{to}");
    signed_redirect(&to, &next);
}

#[tokio::test]
async fn rollovers_are_for_admins_and_botds_own_keys_in_use() {
    let off = serve(&[]).await;
    let (code, e) = off.key_step("POST", "encryption", "next").await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("ENCRYPTED_ASSERTIONS is off"), "{e}");
    assert!(off.app.db.setting(&format!("sso_saml_sp_key_{}_encryption_next", off.id)).is_none());
    assert_eq!(off.key_step("POST", "both", "next").await.0, 400);
    assert_eq!(call(off.port, "POST", "/api/sso/nope/saml/keys/signing/next", &off.admin, "").await.0, 400);
    let member = off.app.db.create_user(None, Some("bob@example.com"), "Bob", Role::Member).unwrap();
    let bob = session_for(off.port, &off.admin, &member.id).await;
    for (method, end) in [("POST", "next"), ("POST", "promote"), ("DELETE", "next"), ("DELETE", "previous")] {
        assert_eq!(call(off.port, method, &format!("/api/sso/{}/saml/keys/signing/{end}", off.id), &bob, "").await.0, 403, "{method} {end}");
    }
    assert!(off.audit("sso.saml_sp_key_created").await.iter().all(|e| e["details"]["stage"] == "current"), "nothing made for bob");

    // A configured key is rolled over in .env, never here.
    let dir = std::env::temp_dir().join(format!("saml-roll-{}", random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let (mine, _) = crate::sso::saml_sp::SpKey::generate("mine").unwrap();
    let cert_file = dir.join("sp.pem");
    std::fs::write(&cert_file, format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", mine.cert)).unwrap();
    let configured = serve(&[("SP_CERT_FILE", &cert_file.to_string_lossy())]).await;
    let (code, e) = configured.key_step("POST", "signing", "next").await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("SP_CERT_FILE sets this signing key"), "{e}");
    std::fs::remove_dir_all(dir).ok();
}

// How people signed in at the IdP (ADR 0190)

const MFA: &str = "http://schemas.microsoft.com/claims/multipleauthn";
const AMR: &str = "http://schemas.microsoft.com/claims/authnmethodsreferences";
const PASSWORD: &str = "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password";

impl Sp {
    /// The AuthnRequest a web sign-in sends the IdP, as XML.
    async fn authn_request(&self) -> String {
        let (_, head, _) = crate::tests::call_with(self.port, "GET", &format!("/api/auth/sso/{}/start", self.id), "", "", "").await;
        let to_idp = url::Url::parse(&header(&head, "location").unwrap()).unwrap();
        let q: HashMap<_, _> = to_idp.query_pairs().into_owned().collect();
        String::from_utf8(miniz_oxide::inflate::decompress_to_vec(&STANDARD.decode(&q["SAMLRequest"]).unwrap()).unwrap()).unwrap()
    }

    async fn view(&self) -> Value {
        serde_json::from_str(&call(self.port, "GET", &format!("/api/sso/{}/saml", self.id), &self.admin, "").await.1).unwrap()
    }
}

#[tokio::test]
async fn sign_ins_record_how_the_idp_says_people_signed_in() {
    let sp = serve(&[]).await;
    let u = sp.link();
    assert_eq!(sp.view().await["authnContext"], Value::Null, "nothing required by default");
    assert!(!sp.authn_request().await.contains("RequestedAuthnContext"));
    let (code, _, head) = sp.sign_in(|_| {}).await;
    assert_eq!((code, signed_in_as(sp.port, &head).await), (200, Some(u.id.clone())), "a password-only sign-in, as before");
    let login = &sp.audit("auth.login").await[0];
    assert_eq!(login["details"]["authnContext"], test_idp::PASSWORD_PROTECTED, "the class the IdP sent, as evidence");
}

#[tokio::test]
async fn a_required_authn_context_keeps_out_sign_ins_without_it_before_just_in_time() {
    let sp = serve_with(
        &[("AUTHN_CONTEXT", &format!("{MFA},urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract")), ("AUTHN_METHODS_ATTRIBUTE", AMR), ("ALLOWED_DOMAINS", "example.com"), ("JIT_ROLE", "member")],
        |a| a.limiter = users::Limiter::new(1000, 60_000),
    )
    .await;
    let v = sp.view().await;
    assert_eq!(v["authnContext"], json!({ "required": [MFA, "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"], "methodsAttribute": AMR, "requested": false }));
    assert!(!sp.authn_request().await.contains("RequestedAuthnContext"), "not requested unless asked: Entra ID refuses a mismatch");

    let refused = async |tweak: Box<dyn FnOnce(&mut Response)>| {
        let (code, to, head) = sp.sign_in(tweak).await;
        assert_eq!((code, to.as_str()), (303, "/login?error=sso_mfa_required"));
        assert_eq!(signed_in_as(sp.port, &head).await, None);
        let f = sp.last_failure().await;
        assert_eq!((f["reason"].as_str(), f["subject"].as_str()), (Some("authn_context"), Some(STORED)));
        f
    };
    let f = refused(Box::new(|_| {})).await;
    assert_eq!((&f["authnContexts"], &f["authnMethods"]), (&json!([test_idp::PASSWORD_PROTECTED]), &json!([])), "says what the IdP sent");
    let f = refused(Box::new(|r| r.multi_attributes = vec![(AMR.into(), vec![PASSWORD.into()])])).await;
    assert_eq!(f["authnMethods"], json!([PASSWORD]));
    refused(Box::new(|r| r.multi_attributes = vec![("amr".into(), vec![MFA.into()])])).await;
    refused(Box::new(|r| r.authn_contexts = vec![MFA.to_ascii_uppercase()])).await;
    // Named somewhere other than the signed assertion: changed after signing, or outside it.
    let (request, relay, cookie) = sp.start().await;
    let r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    let forged = r.xml_with(|a| a.replace(test_idp::PASSWORD_PROTECTED, MFA));
    let (_, to, _) = sp.post(Some(&STANDARD.encode(forged)), Some(&relay), &cookie).await;
    assert_eq!((to.as_str(), sp.last_failure().await["reason"].as_str()), ("/login?error=sso_failed", Some("bad_signature")));
    assert!(sp.app.db.identity(IDP, STORED).is_none(), "no account made");

    // The IdP vouches for MFA in the class or in its methods attribute: in.
    let (code, _, head) = sp.sign_in(|r| r.multi_attributes = vec![(AMR.into(), vec![PASSWORD.into(), MFA.into()])]).await;
    assert_eq!(code, 200, "{head}");
    let uid = signed_in_as(sp.port, &head).await.expect("just in time, once the requirement is met");
    assert_eq!(sp.app.db.user(&uid).unwrap().role, Role::Member);
    assert_eq!(sp.audit("auth.login").await[0]["details"]["authnContext"], MFA, "the value that met it");
    let (code, _, _) = sp.sign_in(|r| r.authn_contexts = vec!["urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract".into()]).await;
    assert_eq!(code, 200);
    assert_eq!(sp.audit("auth.login").await[0]["details"]["authnContext"], "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract");
    // Checked on every sign-in, not only the first.
    refused(Box::new(|_| {})).await;
}

#[tokio::test]
async fn a_requested_authn_context_is_asked_for_and_an_idp_that_cant_meet_it_says_so() {
    let sp = serve_with(&[("AUTHN_CONTEXT", MFA), ("REQUEST_AUTHN_CONTEXT", "true"), ("SIGN_REQUESTS", "true")], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    let u = sp.link();
    assert_eq!(sp.view().await["authnContext"]["requested"], true);
    let request = sp.authn_request().await;
    assert!(request.contains(&format!(r#"<samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>{MFA}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>"#)), "{request}");
    // Still a signed request the IdP can check.
    let (code, head, _) = crate::tests::call_with(sp.port, "GET", &format!("/api/auth/sso/{}/start", sp.id), "", "", "").await;
    assert_eq!(code, 303);
    let cert = sp.sp_cert().await;
    let (_, redirected) = signed_redirect(&header(&head, "location").unwrap(), &cert);
    assert!(redirected.xml.contains("RequestedAuthnContext"));

    // ADFS and Entra ID answer NoAuthnContext when they can't: the person is told why.
    let (request, relay, cookie) = sp.start().await;
    let nested = r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"/></samlp:StatusCode>"#;
    let xml = Response::new(&sp.acs(), &sp.entity(), &request, db::now()).xml().replace(r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>"#, nested);
    let (code, to, _) = sp.post(Some(&STANDARD.encode(xml)), Some(&relay), &cookie).await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_mfa_required"));
    let f = sp.last_failure().await;
    assert_eq!((f["reason"].as_str(), f["idpStatus"].as_str()), (Some("idp_error"), Some("Responder/NoAuthnContext")));
    // A class it didn't ask for is still refused; the one it did, signs in.
    sp.sign_in(|_| {}).await;
    assert_eq!(sp.last_failure().await["reason"], "authn_context");
    let (code, _, head) = sp.sign_in(|r| r.authn_contexts = vec![MFA.into()]).await;
    assert_eq!((code, signed_in_as(sp.port, &head).await), (200, Some(u.id)));
}

#[tokio::test]
async fn an_idp_initiated_post_restarts_and_the_restarted_sign_in_is_held_to_the_requirement() {
    let sp = serve_with(&[("IDP_INITIATED", "restart"), ("AUTHN_CONTEXT", MFA)], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    let u = sp.link();
    // The tile's response signs nobody in, so it isn't held to it: it only restarts.
    let (code, to, _) = sp.post(Some(&sp.unsolicited().posted()), None, "").await;
    assert_eq!((code, to.ends_with("/start")), (303, true), "{to}");
    let (request, relay, binder) = sp.start().await;
    let cookie = format!("{binder}; {RESTART}={}", sp.id);
    let (_, to, _) = sp.post(Some(&Response::new(&sp.acs(), &sp.entity(), &request, db::now()).posted()), Some(&relay), &cookie).await;
    assert_eq!(to, "/login?error=sso_mfa_required");
    let (request, relay, binder) = sp.start().await;
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    r.authn_contexts = vec![MFA.into()];
    let (code, _, head) = sp.post(Some(&r.posted()), Some(&relay), &binder).await;
    assert_eq!((code, signed_in_as(sp.port, &head).await), (200, Some(u.id)));
}

// When they signed in, and for how long (ADR 0225)

const HOUR: i64 = 3_600_000;

/// Where an ACS answer sent the browser back to the IdP: its AuthnRequest, RelayState, and the
/// new binder cookie, which the ACS doesn't clear.
fn sent_back(to: &str, head: &str) -> (String, String, String) {
    let to_idp = url::Url::parse(to).unwrap();
    assert_eq!(format!("{}://{}{}", to_idp.scheme(), to_idp.host_str().unwrap(), to_idp.path()), SSO_URL, "{to}");
    let q: HashMap<_, _> = to_idp.query_pairs().into_owned().collect();
    let request = String::from_utf8(miniz_oxide::inflate::decompress_to_vec(&STANDARD.decode(&q["SAMLRequest"]).unwrap()).unwrap()).unwrap();
    let binders: Vec<_> = set_cookies(head).into_iter().filter(|c| c.starts_with("__Host-superbot_saml=")).collect();
    assert_eq!(binders.len(), 1, "one new binder, not cleared: {head}");
    assert!(!binders[0].starts_with("__Host-superbot_saml=;") && binders[0].contains("SameSite=None"), "{}", binders[0]);
    (request, q["RelayState"].clone(), binders[0].split(';').next().unwrap().to_string())
}

fn request_id(request: &str) -> String {
    request.split(" ID=\"").nth(1).unwrap().split('"').next().unwrap().to_string()
}

impl Sp {
    /// `/api/auth/me` for the session `head` set.
    async fn session_of(&self, head: &str) -> Value {
        let session = set_cookies(head).into_iter().find(|c| c.starts_with("__Host-superbot_session=sbs_")).expect("a session cookie");
        let (_, _, me) = crate::tests::call_with(self.port, "GET", "/api/auth/me", "", &format!("Cookie: {}\r\n", session.split(';').next().unwrap()), "").await;
        serde_json::from_str::<Value>(&me).unwrap()["session"].clone()
    }
}

/// Asserts the session lasts the server's own limit, not an IdP's. Its end is set from the
/// sign-in's clock, a moment before the session row is written, so it may come in up to a
/// second short.
fn lasts_the_servers_limit(s: &Value) {
    let (lasts, max) = (s["expiresAt"].as_i64().unwrap() - s["createdAt"].as_i64().unwrap(), users::SessionConfig::default().max_ms);
    assert!((max - 1_000..=max).contains(&lasts), "{lasts} vs {max}");
}

fn max_age(head: &str) -> i64 {
    let session = set_cookies(head).into_iter().find(|c| c.starts_with("__Host-superbot_session=sbs_")).unwrap();
    session.split("Max-Age=").nth(1).unwrap().split(';').next().unwrap().trim().parse().unwrap()
}

#[tokio::test]
async fn the_idps_session_limit_ends_the_session_it_makes() {
    let sp = serve_with(&[], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    let u = sp.link();
    let v = sp.view().await;
    assert_eq!((&v["forceAuthn"], &v["maxAuthnAgeSeconds"], &v["idpSessionLimit"]), (&json!(false), &Value::Null, &json!(true)));
    assert!(!sp.authn_request().await.contains("ForceAuthn"), "not asked for unless set");

    // No limit: the server's own, as before; when they signed in at the IdP is recorded.
    let instant = db::now() - 10 * 60_000;
    let (code, _, head) = sp.sign_in(|r| r.authn_instant = instant).await;
    assert_eq!(code, 200, "{head}");
    lasts_the_servers_limit(&sp.session_of(&head).await);
    let d = &sp.audit("auth.login").await[0]["details"];
    assert_eq!((d["authnInstant"].as_i64(), &d["idpSessionEnds"], &d["forceAuthn"]), (Some(instant / 1000 * 1000), &Value::Null, &Value::Null));

    // SessionNotOnOrAfter in two hours: the session, and its cookie, end then.
    let ends = (db::now() + 2 * HOUR) / 1000 * 1000;
    let (code, _, head) = sp.sign_in(|r| r.session_not_on_or_after = Some(ends)).await;
    assert_eq!((code, signed_in_as(sp.port, &head).await), (200, Some(u.id.clone())));
    assert_eq!(sp.session_of(&head).await["expiresAt"], ends);
    assert!((2 * 3_600 - 10..=2 * 3_600).contains(&max_age(&head)), "{head}");
    assert_eq!(sp.audit("auth.login").await[0]["details"]["idpSessionEnds"], ends);
    // Longer than the server's own limit: the server's holds.
    let (_, _, head) = sp.sign_in(|r| r.session_not_on_or_after = Some(db::now() + 400 * 24 * HOUR)).await;
    lasts_the_servers_limit(&sp.session_of(&head).await);

    // Already over (or about to be): asked once to sign in again, not given a dead session.
    let logins = sp.audit("auth.login").await.len();
    let (request, relay, binder) = sp.start().await;
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    r.session_not_on_or_after = Some(db::now() + 60_000);
    let (code, to, head) = sp.post(Some(&r.posted()), Some(&relay), &binder).await;
    assert_eq!(code, 303);
    assert!(signed_in_as(sp.port, &head).await.is_none());
    let (again, relay, new_binder) = sent_back(&to, &head);
    assert!(again.contains(r#" ForceAuthn="true""#), "{again}");
    assert_ne!(new_binder, binder);
    let asked = &sp.audit("auth.saml_reauthn").await[0];
    let d = &asked["details"];
    assert_eq!((d["reason"].as_str(), d["outcome"].as_str(), d["subject"].as_str(), d["forceAuthn"].as_bool()), (Some("idp_session_ended"), Some("asked_again"), Some(STORED), Some(false)));
    assert_eq!((asked["targetType"].as_str(), asked["targetId"].as_str(), asked["idpProvider"].as_str()), (Some("sso_provider"), Some(sp.id.as_str()), Some(sp.id.as_str())));
    // The old binder doesn't answer the new request: only the browser that was sent back does.
    let fresh = Response::new(&sp.acs(), &sp.entity(), &request_id(&again), db::now());
    let (_, to, _) = sp.post(Some(&fresh.posted()), Some(&relay), &binder).await;
    assert_eq!((to.as_str(), sp.last_failure().await["reason"].as_str()), ("/login?error=sso_expired", Some("binder_mismatch")));

    // An IdP that answers the forced request with its ended session again: refused, and told why.
    let (request, relay, binder) = sp.start().await;
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    r.session_not_on_or_after = Some(db::now() - 60 * 60_000);
    let (_, to, head) = sp.post(Some(&r.posted()), Some(&relay), &binder).await;
    let (again, relay, binder) = sent_back(&to, &head);
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request_id(&again), db::now());
    r.session_not_on_or_after = Some(db::now() - 60 * 60_000);
    let (code, to, head) = sp.post(Some(&r.posted()), Some(&relay), &binder).await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_reauth_required"));
    assert!(signed_in_as(sp.port, &head).await.is_none());
    let f = sp.last_failure().await;
    assert_eq!((f["reason"].as_str(), f["forceAuthn"].as_bool(), f["subject"].as_str()), (Some("idp_session_ended"), Some(true), Some(STORED)));
    assert!(set_cookies(&head).iter().any(|c| c.starts_with("__Host-superbot_saml=;")), "the binder goes once it's answered");

    // One that signs them in again: in, until its new limit.
    let (request, relay, binder) = sp.start().await;
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    r.session_not_on_or_after = Some(db::now());
    let (_, to, head) = sp.post(Some(&r.posted()), Some(&relay), &binder).await;
    let (again, relay, binder) = sent_back(&to, &head);
    let ends = (db::now() + 8 * HOUR) / 1000 * 1000;
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request_id(&again), db::now());
    r.session_not_on_or_after = Some(ends);
    let (code, _, head) = sp.post(Some(&r.posted()), Some(&relay), &binder).await;
    assert_eq!((code, signed_in_as(sp.port, &head).await), (200, Some(u.id.clone())));
    assert_eq!(sp.session_of(&head).await["expiresAt"], ends);
    let d = &sp.audit("auth.login").await[0]["details"];
    assert_eq!((d["idpSessionEnds"].as_i64(), d["forceAuthn"].as_bool()), (Some(ends), Some(true)));
    assert_eq!(sp.audit("auth.login").await.len(), logins + 1, "the refused and redirected answers signed nobody in");
    // The earliest of several statements' limits holds.
    let soon = (db::now() + HOUR) / 1000 * 1000;
    let (_, _, head) = sp
        .sign_in(|r| {
            r.session_not_on_or_after = Some(db::now() + 4 * HOUR);
            r.extra_statements = format!(
                r#"<saml:AuthnStatement AuthnInstant="{}" SessionNotOnOrAfter="{}"><saml:AuthnContext><saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"#,
                crate::sso::saml_sp::test_instant(db::now()),
                crate::sso::saml_sp::test_instant(soon),
                test_idp::PASSWORD_PROTECTED
            );
        })
        .await;
    assert_eq!(sp.session_of(&head).await["expiresAt"], soon);
}

#[tokio::test]
async fn an_app_sign_in_ends_with_the_idps_session_too() {
    let sp = serve(&[]).await;
    let u = sp.link();
    let verifier = "v".repeat(64);
    let start = format!("/api/auth/sso/{}/start?session=token&redirect=superbot%3A%2F%2Fauth&challenge={}&state=st-1&label=Phone", sp.id, s256(&verifier));
    let (_, head, _) = crate::tests::call_with(sp.port, "GET", &start, "", "", "").await;
    let q: HashMap<_, _> = url::Url::parse(&header(&head, "location").unwrap()).unwrap().query_pairs().into_owned().collect();
    let request = String::from_utf8(miniz_oxide::inflate::decompress_to_vec(&STANDARD.decode(&q["SAMLRequest"]).unwrap()).unwrap()).unwrap();

    // Over already: the app's browser goes back to the IdP, with no binder cookie (it has none).
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request_id(&request), db::now());
    r.session_not_on_or_after = Some(db::now() - HOUR);
    let (code, to, head) = sp.post(Some(&r.posted()), Some(&q["RelayState"]), "").await;
    assert_eq!(code, 303, "{to}");
    assert!(to.starts_with(SSO_URL), "{to}");
    assert!(!set_cookies(&head).iter().any(|c| c.starts_with("__Host-superbot_saml=") && !c.starts_with("__Host-superbot_saml=;")), "{head}");
    let q: HashMap<_, _> = url::Url::parse(&to).unwrap().query_pairs().into_owned().collect();
    let again = String::from_utf8(miniz_oxide::inflate::decompress_to_vec(&STANDARD.decode(&q["SAMLRequest"]).unwrap()).unwrap()).unwrap();
    assert!(again.contains(r#" ForceAuthn="true""#), "{again}");

    // Signed in again, for an hour: the app's code becomes a token session ending then.
    let ends = (db::now() + HOUR) / 1000 * 1000;
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request_id(&again), db::now());
    r.session_not_on_or_after = Some(ends);
    let (code, to, _) = sp.post(Some(&r.posted()), Some(&q["RelayState"]), "").await;
    assert_eq!(code, 303, "{to}");
    let back: HashMap<_, _> = url::Url::parse(&to).unwrap().query_pairs().into_owned().collect();
    assert_eq!(back["state"], "st-1", "the app's own state, kept through the second request");
    let (code, res) = call(sp.port, "POST", "/api/auth/login", "", &json!({ "sso": back["code"], "verifier": verifier }).to_string()).await;
    assert_eq!(code, 200, "{res}");
    let res: Value = serde_json::from_str(&res).unwrap();
    assert_eq!((res["user"]["id"].as_str(), &res["session"]["expiresAt"], res["session"]["kind"].as_str()), (Some(u.id.as_str()), &json!(ends), Some("token")));
    let d = &sp.audit("auth.login").await[0]["details"];
    assert_eq!((d["idpSessionEnds"].as_i64(), d["forceAuthn"].as_bool()), (Some(ends), Some(true)));

    // A code taken as a web session: its cookie ends with the session, not at SESSION_MAX_AGE.
    let start = format!("/api/auth/sso/{}/start?session=token&redirect=superbot%3A%2F%2Fauth&challenge={}&state=st-2", sp.id, s256(&verifier));
    let (_, head, _) = crate::tests::call_with(sp.port, "GET", &start, "", "", "").await;
    let q: HashMap<_, _> = url::Url::parse(&header(&head, "location").unwrap()).unwrap().query_pairs().into_owned().collect();
    let request = String::from_utf8(miniz_oxide::inflate::decompress_to_vec(&STANDARD.decode(&q["SAMLRequest"]).unwrap()).unwrap()).unwrap();
    let ends = (db::now() + 2 * HOUR) / 1000 * 1000;
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request_id(&request), db::now());
    r.session_not_on_or_after = Some(ends);
    let (_, to, _) = sp.post(Some(&r.posted()), Some(&q["RelayState"]), "").await;
    let back: HashMap<_, _> = url::Url::parse(&to).unwrap().query_pairs().into_owned().collect();
    let body = json!({ "sso": back["code"], "verifier": verifier, "session": "cookie" }).to_string();
    let (code, head, res) = crate::tests::call_with(sp.port, "POST", "/api/auth/login", "", "", &body).await;
    assert_eq!(code, 200, "{res}");
    assert_eq!(serde_json::from_str::<Value>(&res).unwrap()["session"]["expiresAt"], ends);
    assert!((2 * 3_600 - 10..=2 * 3_600).contains(&max_age(&head)), "{head}");
}

#[tokio::test]
async fn an_idp_session_limit_turned_off_is_ignored() {
    let sp = serve(&[("IDP_SESSION_LIMIT", "off")]).await;
    sp.link();
    assert_eq!(sp.view().await["idpSessionLimit"], false);
    let (code, _, head) = sp.sign_in(|r| r.session_not_on_or_after = Some(db::now() - HOUR)).await;
    assert_eq!(code, 200, "{head}");
    lasts_the_servers_limit(&sp.session_of(&head).await);
    assert_eq!(sp.audit("auth.login").await[0]["details"]["idpSessionEnds"], Value::Null);
    assert!(sp.audit("auth.saml_reauthn").await.is_empty());
}

#[tokio::test]
async fn force_authn_asks_every_time_and_refuses_an_older_sign_in() {
    let sp = serve_with(&[("FORCE_AUTHN", "true"), ("SIGN_REQUESTS", "true")], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    let u = sp.link();
    assert_eq!(sp.view().await["forceAuthn"], true);
    let (code, head, _) = crate::tests::call_with(sp.port, "GET", &format!("/api/auth/sso/{}/start", sp.id), "", "", "").await;
    assert_eq!(code, 303);
    let (_, redirected) = signed_redirect(&header(&head, "location").unwrap(), &sp.sp_cert().await);
    assert!(redirected.xml.contains(r#" ForceAuthn="true""#), "asked for, in the signed request: {}", redirected.xml);

    // An IdP that ignores it and answers from its old session: refused, not asked again.
    let (code, to, head) = sp.sign_in(|r| r.authn_instant = db::now() - 10 * 60_000).await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_reauth_required"));
    assert!(signed_in_as(sp.port, &head).await.is_none());
    let f = sp.last_failure().await;
    assert_eq!((f["reason"].as_str(), f["forceAuthn"].as_bool(), f["subject"].as_str()), (Some("stale_authn"), Some(true), Some(STORED)));
    assert!(f["authnSince"].as_i64().unwrap() > f["authnInstant"].as_i64().unwrap() + crate::sso::saml_sp::SKEW_MS, "{f}");
    assert!(sp.audit("auth.saml_reauthn").await.is_empty());
    // Signed in just now: in.
    let (code, _, head) = sp.sign_in(|_| {}).await;
    assert_eq!((code, signed_in_as(sp.port, &head).await), (200, Some(u.id)));
    assert_eq!(sp.audit("auth.login").await[0]["details"]["forceAuthn"], true);
}

#[tokio::test]
async fn a_sign_in_older_than_max_authn_age_asks_the_idp_once_to_sign_in_again() {
    let sp = serve_with(&[("MAX_AUTHN_AGE", "1h"), ("ALLOWED_DOMAINS", "example.com"), ("JIT_ROLE", "member")], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    assert_eq!(sp.view().await["maxAuthnAgeSeconds"], 3_600);
    assert!(!sp.authn_request().await.contains("ForceAuthn"), "only asked for once a sign-in is too old");

    // Too old, before anyone is made just in time: sent back, and nobody made yet.
    let (request, relay, binder) = sp.start().await;
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    r.authn_instant = db::now() - 2 * HOUR;
    let (code, to, head) = sp.post(Some(&r.posted()), Some(&relay), &binder).await;
    assert_eq!(code, 303);
    assert!(sp.app.db.identity(IDP, STORED).is_none(), "no account made");
    let (again, new_relay, new_binder) = sent_back(&to, &head);
    assert!(again.contains(r#" ForceAuthn="true""#), "{again}");
    assert_ne!((&new_relay, &new_binder), (&relay, &binder));
    let d = &sp.audit("auth.saml_reauthn").await[0]["details"];
    assert_eq!(d["reason"], "stale_authn");
    assert!(d["authnSince"].as_i64().unwrap() > d["authnInstant"].as_i64().unwrap() + HOUR, "{d}");
    // The first request is spent: its RelayState answers nothing now.
    let (_, to, _) = sp.post(Some(&Response::new(&sp.acs(), &sp.entity(), &request, db::now()).posted()), Some(&relay), &binder).await;
    assert_eq!(to, "/login?error=sso_expired");
    // The IdP still answers from its old session: refused this time.
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request_id(&again), db::now());
    r.authn_instant = db::now() - 2 * HOUR;
    let (_, to, _) = sp.post(Some(&r.posted()), Some(&new_relay), &new_binder).await;
    assert_eq!(to, "/login?error=sso_reauth_required");
    assert_eq!(sp.last_failure().await["reason"], "stale_authn");
    assert_eq!(sp.audit("auth.saml_reauthn").await.len(), 1, "asked once per sign-in");

    // Within the hour: in, just in time, without asking again.
    let (code, _, head) = sp.sign_in(|r| r.authn_instant = db::now() - 30 * 60_000).await;
    assert_eq!(code, 200, "{head}");
    assert!(signed_in_as(sp.port, &head).await.is_some());
    assert_eq!(sp.audit("auth.saml_reauthn").await.len(), 1);
    // Too old, then signed in again when asked: in, and the login says it was asked for.
    let (request, relay, binder) = sp.start().await;
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    r.authn_instant = db::now() - 2 * HOUR;
    let (_, to, head) = sp.post(Some(&r.posted()), Some(&relay), &binder).await;
    let (again, relay, binder) = sent_back(&to, &head);
    let (code, _, head) = sp.post(Some(&Response::new(&sp.acs(), &sp.entity(), &request_id(&again), db::now()).posted()), Some(&relay), &binder).await;
    assert_eq!(code, 200, "{head}");
    assert!(signed_in_as(sp.port, &head).await.is_some());
    assert_eq!(sp.audit("auth.login").await[0]["details"]["forceAuthn"], true);
}

#[tokio::test]
async fn an_idp_initiated_post_restarts_and_the_restarted_sign_in_is_held_to_max_authn_age() {
    let sp = serve_with(&[("IDP_INITIATED", "restart"), ("MAX_AUTHN_AGE", "1h")], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    let u = sp.link();
    // The tile's response signs nobody in, so an old sign-in in it only restarts.
    let mut tile = sp.unsolicited();
    tile.authn_instant = db::now() - 2 * HOUR;
    let (code, to, _) = sp.post(Some(&tile.posted()), None, "").await;
    assert_eq!((code, to.ends_with("/start")), (303, true), "{to}");
    assert!(sp.audit("auth.saml_reauthn").await.is_empty());
    // The restarted sign-in is: sent back with ForceAuthn, the restart marker kept for the loop check.
    let (request, relay, binder) = sp.start().await;
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    r.authn_instant = db::now() - 2 * HOUR;
    let (code, to, head) = sp.post(Some(&r.posted()), Some(&relay), &format!("{binder}; {RESTART}={}", sp.id)).await;
    assert_eq!(code, 303);
    assert!(!set_cookies(&head).iter().any(|c| c.starts_with(&format!("{RESTART}="))), "{head}");
    let (again, relay, binder) = sent_back(&to, &head);
    let (code, _, head) = sp.post(Some(&Response::new(&sp.acs(), &sp.entity(), &request_id(&again), db::now()).posted()), Some(&relay), &format!("{binder}; {RESTART}={}", sp.id)).await;
    assert_eq!((code, signed_in_as(sp.port, &head).await), (200, Some(u.id)));
    assert!(set_cookies(&head).iter().any(|c| c.starts_with(&format!("{RESTART}=;"))), "{head}");
}

// Certificates ending (ADR 0198)

/// A PEM certificate for a new RSA key, ending `days` from now, and the key.
fn cert_ending_in(days: i64) -> (String, rcgen::KeyPair) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, "ending");
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
    (params.self_signed(&key).unwrap().pem(), key)
}

fn base64_of(pem: &str) -> String {
    pem.lines().filter(|l| !l.starts_with("-----")).collect()
}

#[tokio::test]
async fn certificates_ending_are_shown_and_audited_once_each() {
    use crate::sso::saml_expiry;
    use crate::sso::xmldsig::test_signer::signers;
    let dir = std::env::temp_dir().join(format!("saml-ending-{}", random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let (sp_pem, sp_key) = cert_ending_in(10);
    let cert_file = dir.join("sp.pem");
    std::fs::write(&cert_file, &sp_pem).unwrap();
    let mut providers = Vec::new();
    let sp = serve_with(&[("SP_CERT_FILE", &cert_file.to_string_lossy())], |a| providers = a.sso.providers.clone()).await;
    crate::secrets::global().put(&format!("SSO_{}_PRIVATE_KEY", sp.id.to_ascii_uppercase()), &sp_key.serialize_pem()).unwrap();
    let http = reqwest::Client::new();
    let check = |at: i64| saml_expiry::check(&sp.app, &providers, &http, std::time::Duration::ZERO, at);

    // The IdP's only certificate ends in 5 days.
    let (idp_pem, _) = cert_ending_in(5);
    let ending = base64_of(&idp_pem);
    let import = |xml: String| {
        let (port, id, admin) = (sp.port, sp.id.clone(), sp.admin.clone());
        async move { call(port, "PUT", &format!("/api/sso/{id}/saml/idp-metadata"), &admin, &json!({ "xml": xml }).to_string()).await }
    };
    assert_eq!(import(test_idp::metadata().replace(&signers()[0].cert, &ending)).await.0, 200);
    let ending_sha = crate::sso::xmldsig::Cert::from_base64(&ending).unwrap().sha256;
    let sp_sha = crate::sso::xmldsig::Cert::from_base64(&base64_of(&sp_pem)).unwrap().sha256;

    let v = sp.view().await;
    assert_eq!((v["spKey"]["certificate"]["expiry"].as_str(), v["spKey"]["certificate"]["daysLeft"].as_i64()), (Some("expiring"), Some(10)), "{v}");
    assert_eq!((v["idp"]["certificates"][0]["expiry"].as_str(), v["idp"]["certificates"][0]["daysLeft"].as_i64()), (Some("expiring"), Some(5)));
    let w = v["certificateWarnings"].as_array().unwrap();
    assert_eq!(w.len(), 2, "{w:?}");
    let (sp_w, idp_w) = (&w[0], &w[1]);
    assert_eq!((sp_w["role"].as_str(), sp_w["from"].as_str(), sp_w["certificate"].as_str(), sp_w["replacement"].clone()), (Some("sp_signing"), Some("secret"), Some(sp_sha.as_str()), Value::Null));
    assert!(sp_w["action"].as_str().unwrap().contains("_SP_CERT_FILE"), "{sp_w}");
    assert_eq!((idp_w["role"].as_str(), idp_w["from"].as_str(), idp_w["state"].as_str(), idp_w["daysLeft"].as_i64()), (Some("idp_signing"), Some("botctl"), Some("expiring"), Some(5)));
    assert!(idp_w["action"].as_str().unwrap().contains(&format!("botctl sso saml {} import", sp.id)), "{idp_w}");

    // Audited once each, however often botd looks.
    let now = db::now();
    assert_eq!(check(now).await, 2);
    assert_eq!(check(now + 60_000).await, 0, "already warned");
    let warned = sp.audit("sso.saml_certificate_expiring").await;
    assert_eq!(warned.len(), 2);
    for e in &warned {
        assert_eq!((e["outcome"].as_str(), e["targetType"].as_str(), e["targetId"].as_str(), e["actorKind"].as_str()), (Some("success"), Some("sso_provider"), Some(sp.id.as_str()), Some("system")), "{e}");
    }
    let idp_e = warned.iter().find(|e| e["details"]["role"] == "idp_signing").unwrap();
    assert_eq!((idp_e["details"]["certificate"].as_str(), idp_e["details"]["daysLeft"].as_i64(), idp_e["details"]["replacement"].clone()), (Some(ending_sha.as_str()), Some(5), Value::Null));

    // Listed twice, it's still one certificate, and one that isn't covered.
    let and_then = |cert: &str| format!(r#"{ending}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}"#);
    assert_eq!(import(test_idp::metadata().replace(&signers()[0].cert, &and_then(&ending))).await.0, 200);
    let w = sp.view().await["certificateWarnings"].clone();
    assert_eq!((w.as_array().unwrap().len(), w[1]["replacement"].clone()), (2, Value::Null), "{w}");

    // The IdP publishes its next certificate: the ending one is covered, and nothing more is audited.
    assert_eq!(import(test_idp::metadata().replace(&signers()[0].cert, &and_then(&signers()[0].cert))).await.0, 200);
    let w = sp.view().await["certificateWarnings"].clone();
    let idp_w = w.as_array().unwrap().iter().find(|w| w["role"] == "idp_signing").unwrap();
    assert_eq!(idp_w["replacement"].as_str(), Some(signers()[0].cert().sha256.as_str()));
    assert!(idp_w["action"].as_str().unwrap().contains("already has a newer certificate"), "{idp_w}");
    assert_eq!(check(now + 120_000).await, 0);

    // Past both ends: botd's own certificate is a failure, the IdP's replaced one isn't.
    let later = now + 11 * 86_400_000;
    assert_eq!(check(later).await, 2);
    assert_eq!(check(later + 60_000).await, 0);
    let expired = sp.audit("sso.saml_certificate_expired").await;
    let outcome = |role: &str| expired.iter().find(|e| e["details"]["role"] == role).map(|e| (e["outcome"].as_str().unwrap().to_string(), e["details"]["daysLeft"].as_i64()));
    assert_eq!(outcome("sp_signing"), Some(("failure".into(), Some(0))));
    assert_eq!(outcome("idp_signing"), Some(("success".into(), Some(0))));
    assert_eq!(sp.audit("sso.saml_certificate_expiring").await.len(), 2, "no warning after the end");
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn generated_keys_and_their_next_keys_are_checked_without_making_any() {
    use crate::sso::saml_expiry;
    let mut providers = Vec::new();
    let sp = serve_with(&[("ENCRYPTED_ASSERTIONS", "allow")], |a| providers = a.sso.providers.clone()).await;
    let http = reqwest::Client::new();
    let now = db::now();
    assert_eq!(saml_expiry::check(&sp.app, &providers, &http, std::time::Duration::ZERO, now).await, 0, "20-year certificates");
    assert_eq!(sp.key_step("POST", "signing", "next").await.0, 200);
    let made = sp.audit("sso.saml_sp_key_created").await.len();
    // Near the end of the generated certificates' 20 years.
    let late = now + (20 * 365 - 10) * 86_400_000;
    let n = saml_expiry::check(&sp.app, &providers, &http, std::time::Duration::ZERO, late).await;
    let warned = sp.audit("sso.saml_certificate_expiring").await;
    let mut got: Vec<(String, String)> = warned.iter().map(|e| (e["details"]["role"].as_str().unwrap().into(), e["details"]["stage"].as_str().unwrap().into())).collect();
    got.sort();
    let want = [("sp_encryption", "current"), ("sp_signing", "current"), ("sp_signing", "next")].map(|(r, s)| (r.to_string(), s.to_string()));
    assert_eq!(got, want, "the import's view made the encryption key");
    assert_eq!(n, want.len(), "the test IdP's certificate lasts past then");
    assert_eq!(sp.audit("sso.saml_sp_key_created").await.len(), made, "checking makes no key");
    assert_eq!(sp.view().await["certificateWarnings"], json!([]), "not yet, today");
}

/// The monthly health check (ADR 0252) looks 60 days ahead, further than the warnings.
#[tokio::test]
async fn the_health_check_sees_certificates_ending_within_60_days() {
    use crate::sso::xmldsig::test_signer::signers;
    let sp = serve(&[]).await;
    let saml = |sp: &Sp| {
        let (port, admin) = (sp.port, sp.admin.clone());
        async move {
            let r: Value = serde_json::from_str(&call(port, "GET", "/api/support/health-check", &admin, "").await.1).unwrap();
            r["items"].as_array().unwrap().iter().find(|i| i["id"] == "saml").unwrap().clone()
        }
    };
    let import = |xml: String| {
        let (port, id, admin) = (sp.port, sp.id.clone(), sp.admin.clone());
        async move { call(port, "PUT", &format!("/api/sso/{id}/saml/idp-metadata"), &admin, &json!({ "xml": xml }).to_string()).await }
    };
    let s = saml(&sp).await;
    assert_eq!(s["status"], "done", "{s}");
    assert!(s["detail"].as_str().unwrap().ends_with("across 1 provider; none ends within 60 days."), "{s}");

    let ending = base64_of(&cert_ending_in(45).0);
    assert_eq!(import(test_idp::metadata().replace(&signers()[0].cert, &ending)).await.0, 200);
    assert_eq!(sp.view().await["certificateWarnings"], json!([]), "45 days is before botd's own warnings start");
    let s = saml(&sp).await;
    assert_eq!(s["status"], "open", "{s}");
    assert_eq!(
        s["detail"],
        format!("Ending within 60 days with nothing to replace it: {}'s the IdP's signing certificate in 45 days. Record who rotates each (botctl sso saml <provider>).", sp.id)
    );

    let and_then = format!(r#"{ending}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}"#, signers()[0].cert);
    assert_eq!(import(test_idp::metadata().replace(&signers()[0].cert, &and_then)).await.0, 200);
    let s = saml(&sp).await;
    assert_eq!(s["status"], "done", "the IdP's next certificate is in its metadata: {s}");
    assert!(s["detail"].as_str().unwrap().contains("each with a newer one already in use"), "{s}");
}

// AuthnRequests over HTTP-POST (ADR 0235)

/// An HTTP-POST binding page: where its form goes, the message it posts (decoded), and its
/// RelayState.
fn posted_form(body: &str) -> (String, String, Option<String>) {
    posted_message(body, "SAMLRequest")
}

/// The same for a page that posts `param` (`SAMLRequest` or `SAMLResponse`).
fn posted_message(body: &str, param: &str) -> (String, String, Option<String>) {
    let value = |name: &str| body.split(&format!(r#"name="{name}" value=""#)).nth(1).map(|v| v.split('"').next().unwrap().to_string());
    let action = body.split(r#"<form method="post" action=""#).nth(1).expect("a form").split('"').next().unwrap().replace("&amp;", "&");
    let xml = String::from_utf8(STANDARD.decode(value(param).unwrap_or_else(|| panic!("a {param}"))).unwrap()).unwrap();
    (action, xml, value("RelayState"))
}

/// What a page that posts an AuthnRequest must be: HTML that runs only its own script, kept
/// nowhere, and sends no Referer.
fn post_page_headers(head: &str) {
    assert_eq!(header(head, "content-type").as_deref(), Some("text/html; charset=utf-8"), "{head}");
    assert_eq!((header(head, "cache-control").as_deref(), header(head, "referrer-policy").as_deref()), (Some("no-store"), Some("no-referrer")), "{head}");
    let csp = header(head, "content-security-policy").expect("a CSP");
    assert!(csp.starts_with("default-src 'none'; script-src 'sha256-") && csp.contains("form-action https:;") && csp.contains("frame-ancestors 'none'"), "{csp}");
}

/// `xml`'s enveloped signature, checked against `cert`. False when it has none.
fn signed_inside(xml: &str, cert: &crate::sso::xmldsig::Cert) -> bool {
    let doc = roxmltree::Document::parse(xml).unwrap();
    crate::sso::xmldsig::verify_enveloped(doc.root_element(), std::slice::from_ref(cert)).unwrap()
}

/// The test IdP's metadata with only its HTTP-POST SingleSignOnService.
fn post_only_metadata() -> String {
    let redirect = format!(r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{SSO_URL}"/>"#);
    let xml = test_idp::metadata();
    assert!(xml.contains(&redirect));
    xml.replace(&redirect, "")
}

impl Sp {
    /// Starts a web sign-in over HTTP-POST: the AuthnRequest, the RelayState, and the binder cookie.
    async fn start_post(&self) -> (String, String, String) {
        let (code, head, body) = crate::tests::call_with(self.port, "GET", &format!("/api/auth/sso/{}/start", self.id), "", "", "").await;
        assert_eq!(code, 200, "{head}\n{body}");
        post_page_headers(&head);
        let (action, request, relay) = posted_form(&body);
        assert_eq!(action, format!("{SSO_URL}/post"));
        assert!(request.contains(&format!(r#"Destination="{SSO_URL}/post""#)) && request.contains(&format!(r#"AssertionConsumerServiceURL="{}""#, self.acs())), "{request}");
        let binder = set_cookies(&head).into_iter().find(|c| c.starts_with("__Host-superbot_saml=")).expect("binder cookie");
        (request, relay.expect("RelayState"), binder.split(';').next().unwrap().to_string())
    }

    async fn import(&self, xml: &str) -> (u16, String) {
        call(self.port, "PUT", &format!("/api/sso/{}/saml/idp-metadata", self.id), &self.admin, &json!({ "xml": xml }).to_string()).await
    }
}

#[tokio::test]
async fn authn_requests_go_over_http_post_signed_inside_when_asked() {
    let sp = serve(&[("REQUEST_BINDING", "post"), ("SIGN_REQUESTS", "true")]).await;
    let u = sp.link();
    let v = sp.view().await;
    assert_eq!((v["requestBinding"].as_str(), v["idp"]["ssoBinding"].as_str(), v["idp"]["ssoUrl"].as_str()), (Some("post"), Some("post"), Some(format!("{SSO_URL}/post").as_str())), "{v}");

    let (request, relay, binder) = sp.start_post().await;
    assert!(signed_inside(&request, &sp.sp_cert().await), "signed by our published key: {request}");
    let r = Response::new(&sp.acs(), &sp.entity(), &request_id(&request), db::now());
    let (code, _, head) = sp.post(Some(&r.posted()), Some(&relay), &binder).await;
    assert_eq!(code, 200, "{head}");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(u.id));

    // The same checks as over redirect: another browser's answer is refused.
    let (request, relay, _) = sp.start_post().await;
    let r = Response::new(&sp.acs(), &sp.entity(), &request_id(&request), db::now());
    assert_eq!(sp.post(Some(&r.posted()), Some(&relay), "").await.1, "/login?error=sso_expired");
    assert_eq!(sp.last_failure().await["reason"], "binder_mismatch");
}

#[tokio::test]
async fn an_idp_that_takes_only_http_post_needs_no_setting() {
    let sp = serve(&[]).await;
    let u = sp.link();
    let (code, view) = sp.import(&post_only_metadata()).await;
    assert_eq!(code, 200, "{view}");
    let v: Value = serde_json::from_str(&view).unwrap();
    assert_eq!((v["requestBinding"].as_str(), v["idp"]["ssoBinding"].as_str()), (Some("auto"), Some("post")), "{v}");
    let imported = sp.audit("sso.saml_metadata_imported").await;
    assert_eq!(imported[0]["details"]["ssoBinding"], "post");

    let (request, relay, binder) = sp.start_post().await;
    assert!(!request.contains("<ds:Signature"), "unsigned without SIGN_REQUESTS: {request}");
    let r = Response::new(&sp.acs(), &sp.entity(), &request_id(&request), db::now());
    let (code, _, head) = sp.post(Some(&r.posted()), Some(&relay), &binder).await;
    assert_eq!((code, signed_in_as(sp.port, &head).await), (200, Some(u.id)));

    // An app sign-in goes the same way, with its own state.
    let path = format!("/api/auth/sso/{}/start?session=token&redirect=superbot%3A%2F%2Fauth&challenge={}&state=app-state", sp.id, s256(&"v".repeat(64)));
    let (code, head, body) = crate::tests::call_with(sp.port, "GET", &path, "", "", "").await;
    assert_eq!(code, 200, "{head}\n{body}");
    post_page_headers(&head);
    assert!(set_cookies(&head).iter().all(|c| !c.starts_with("__Host-superbot_saml=")), "no binder for the app: {head}");
    let (_, request, relay) = posted_form(&body);
    assert!(request.contains(&format!(r#"Destination="{SSO_URL}/post""#)) && relay.is_some_and(|r| r != "app-state"), "RelayState is botd's own state");

    // Back to the redirect binding when the IdP offers it again.
    assert_eq!(sp.import(&test_idp::metadata()).await.0, 200);
    assert!(!sp.start().await.0.is_empty(), "a 303 to the HTTP-Redirect URL");
}

#[tokio::test]
async fn a_binding_the_idp_does_not_offer_is_refused_with_what_to_set() {
    let sp = serve(&[("REQUEST_BINDING", "redirect")]).await;
    let (code, e) = sp.import(&post_only_metadata()).await;
    assert_eq!(code, 400, "{e}");
    assert!(e.contains("no HTTP-Redirect SingleSignOnService: set SSO_<ID>_REQUEST_BINDING=auto or post"), "{e}");
    assert_eq!(sp.view().await["idp"]["ssoBinding"], "redirect", "the metadata in use is kept");
    let sp = serve(&[("REQUEST_BINDING", "post")]).await;
    let redirect_only = test_idp::metadata().replace(&format!(r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{SSO_URL}/post"/>"#), "");
    let (code, e) = sp.import(&redirect_only).await;
    assert_eq!(code, 400, "{e}");
    assert!(e.contains("no HTTP-POST SingleSignOnService"), "{e}");
}

#[tokio::test]
async fn asking_again_for_a_recent_sign_in_posts_too() {
    let sp = serve_with(&[("REQUEST_BINDING", "post"), ("MAX_AUTHN_AGE", "1h")], |a| a.limiter = users::Limiter::new(1000, 60_000)).await;
    let u = sp.link();
    let (request, relay, binder) = sp.start_post().await;
    assert!(!request.contains("ForceAuthn"), "{request}");
    let mut r = Response::new(&sp.acs(), &sp.entity(), &request_id(&request), db::now());
    r.authn_instant = db::now() - 2 * HOUR;
    let res = http().post(sp.acs()).header("cookie", &binder).form(&[("SAMLResponse", r.posted()), ("RelayState", relay.clone())]).send().await.unwrap();
    let head: String = res.headers().iter().map(|(k, v)| format!("{k}: {}\n", v.to_str().unwrap())).collect();
    assert_eq!(res.status().as_u16(), 200, "{head}");
    post_page_headers(&head);
    let binders: Vec<_> = set_cookies(&head).into_iter().filter(|c| c.starts_with("__Host-superbot_saml=")).collect();
    assert!(binders.len() == 1 && !binders[0].starts_with("__Host-superbot_saml=;"), "a new binder, not cleared: {head}");
    let (action, again, new_relay) = posted_form(&res.text().await.unwrap());
    assert_eq!(action, format!("{SSO_URL}/post"));
    assert!(again.contains(r#" ForceAuthn="true""#) && new_relay.as_deref() != Some(relay.as_str()), "{again}");
    assert_eq!(sp.audit("auth.saml_reauthn").await[0]["details"]["reason"], "stale_authn");

    let r = Response::new(&sp.acs(), &sp.entity(), &request_id(&again), db::now());
    let (code, _, head) = sp.post(Some(&r.posted()), new_relay.as_deref(), binders[0].split(';').next().unwrap()).await;
    assert_eq!((code, signed_in_as(sp.port, &head).await), (200, Some(u.id)));
}

// Logout over HTTP-POST to the IdP (ADR 0248)

/// A native provider whose IdP takes logout only over HTTP-POST, at `SLO_URL/post`.
async fn serve_post_slo(extra: &[(&str, &str)]) -> Sp {
    let sp = serve(extra).await;
    let (code, view) = sp.import(&test_idp::with_post_slo(&test_idp::metadata())).await;
    assert_eq!(code, 200, "{view}");
    sp
}

impl Sp {
    /// Signs `cookie`'s session out: the `logoutUrl` botd answers with, as a path on botd.
    async fn sign_out(&self, cookie: &str) -> String {
        let (code, _, body) = crate::tests::call_with(self.port, "POST", "/api/auth/logout", "", cookie, "").await;
        assert_eq!(code, 200, "{body}");
        let url = serde_json::from_str::<Value>(&body).unwrap()["logoutUrl"].as_str().expect("logoutUrl").to_string();
        url.strip_prefix(&format!("http://127.0.0.1:{}", self.port)).unwrap_or_else(|| panic!("a page on botd: {url}")).to_string()
    }
}

#[tokio::test]
async fn signing_out_posts_the_logout_request_to_an_idp_that_takes_only_http_post() {
    let sp = serve_post_slo(&[]).await;
    let u = sp.link();
    let v = sp.view().await;
    assert_eq!((v["singleLogout"].as_bool(), v["idp"]["sloBinding"].as_str(), v["idp"]["sloUrl"].as_str()), (Some(true), Some("post"), Some(format!("{}/post", test_idp::SLO_URL).as_str())), "{v}");

    let cookie = sp.cookie("_s1").await;
    let page = sp.sign_out(&cookie).await;
    assert_eq!(sp.who(&cookie).await, None, "signed out here first");
    assert!(page.starts_with(&format!("/api/auth/sso/{}/logout?h=", sp.id)), "{page}");

    // The page posts our signed LogoutRequest to the IdP, once.
    let (code, head, body) = crate::tests::call_with(sp.port, "GET", &page, "", "", "").await;
    assert_eq!(code, 200, "{head}\n{body}");
    post_page_headers(&head);
    assert!(header(&head, "set-cookie").is_none(), "{head}");
    assert!(body.contains("sign out") && !body.contains("sign-in"), "{body}");
    let (action, request, relay) = posted_message(&body, "SAMLRequest");
    assert_eq!((action, relay), (format!("{}/post", test_idp::SLO_URL), None));
    assert!(signed_inside(&request, &sp.sp_cert().await), "signed inside, with our published key: {request}");
    assert!(request.contains("<samlp:LogoutRequest") && request.contains(&format!(r#"Destination="{}/post""#, test_idp::SLO_URL)), "{request}");
    assert!(request.contains(&format!(">{NAME_ID}</saml:NameID>")) && request.contains("<samlp:SessionIndex>_s1</samlp:SessionIndex>"), "{request}");
    let id = request_id(&request);
    let logout = &sp.audit("auth.logout").await[0];
    assert_eq!((logout["actorId"].as_str(), logout["details"]["slo"].as_str(), logout["details"]["sloBinding"].as_str()), (Some(u.id.as_str()), Some(id.as_str()), Some("post")));
    let (code, head, _) = crate::tests::call_with(sp.port, "GET", &page, "", "", "").await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login")), "spent: {head}");

    // The IdP's answer, posted back: audited against the session, with the binding it came by.
    let (code, to) = sp.slo_post(&Logout::response(&sp.slo(), &id, db::now()).post()).await;
    assert_eq!((code, to.as_str()), (303, "/login"));
    let done = &sp.audit("auth.slo_response").await[0];
    assert_eq!((done["outcome"].as_str(), done["details"]["requestId"].as_str(), done["details"]["binding"].as_str()), (Some("success"), Some(id.as_str()), Some("post")));

    // Handles that are made up, missing, or for another provider show nothing.
    for path in [format!("/api/auth/sso/{}/logout?h=0123", sp.id), format!("/api/auth/sso/{}/logout", sp.id)] {
        let (code, head, body) = crate::tests::call_with(sp.port, "GET", &path, "", "", "").await;
        assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login")), "{path}");
        assert!(!body.contains("SAMLRequest"), "{body}");
    }
    let page = sp.sign_out(&sp.cookie("_s2").await).await;
    let other = page.replacen(&format!("/sso/{}/", sp.id), "/sso/other/", 1);
    assert_eq!(crate::tests::call_with(sp.port, "GET", &other, "", "", "").await.0, 303);
    assert_eq!(crate::tests::call_with(sp.port, "GET", &page, "", "", "").await.0, 303, "one try, whichever provider it named");
}

#[tokio::test]
async fn the_idps_logout_request_is_answered_over_http_post_when_thats_all_it_takes() {
    let sp = serve_post_slo(&[]).await;
    let u = sp.link();
    let (first, second) = (sp.cookie("_s1").await, sp.cookie("_s2").await);
    let cert = sp.sp_cert().await;

    // Over either binding to us, the answer goes over the IdP's.
    let l = Logout::request(&sp.slo(), NAME_ID, Some("_s1"), db::now());
    let res = http().get(format!("{}?{}", sp.slo(), l.redirect())).send().await.unwrap();
    let head: String = res.headers().iter().map(|(k, v)| format!("{k}: {}\n", v.to_str().unwrap())).collect();
    assert_eq!(res.status().as_u16(), 200, "{head}");
    post_page_headers(&head);
    assert!(header(&head, "set-cookie").is_none(), "the browser's own cookie is left alone: {head}");
    let (action, answer, relay) = posted_message(&res.text().await.unwrap(), "SAMLResponse");
    assert_eq!((action, relay.as_deref()), (format!("{}/post", test_idp::SLO_URL), Some("idp-relay")));
    assert!(signed_inside(&answer, &cert), "signed inside: {answer}");
    assert!(answer.contains(&format!(r#"InResponseTo="{}""#, l.id)) && answer.contains(&format!(r#"Destination="{}/post""#, test_idp::SLO_URL)) && answer.contains("status:Success"), "{answer}");
    assert_eq!((sp.who(&first).await, sp.who(&second).await), (None, Some(u.id.clone())));
    assert_eq!(sp.audit("auth.slo").await[0]["details"]["binding"], "redirect");

    let l = Logout::request(&sp.slo(), NAME_ID, None, db::now());
    let res = http().post(sp.slo()).form(&l.post()).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let (_, answer, _) = posted_message(&res.text().await.unwrap(), "SAMLResponse");
    assert!(signed_inside(&answer, &cert) && answer.contains(&format!(r#"InResponseTo="{}""#, l.id)), "{answer}");
    assert_eq!(sp.who(&second).await, None);
    assert_eq!(sp.audit("auth.slo").await[0]["details"]["binding"], "post");

    // Still checked as before: a forged request revokes nothing and gets no answer.
    let mut forged = Logout::request(&sp.slo(), NAME_ID, None, db::now());
    forged.signer = Some(1);
    assert_eq!(sp.slo_post(&forged.post()).await.0, 400);
}

#[tokio::test]
async fn requests_over_http_post_by_choice_take_logout_over_it_too() {
    let sp = serve(&[("REQUEST_BINDING", "post")]).await;
    let (code, view) = sp.import(&test_idp::with_post_slo(&test_idp::with_slo(&test_idp::metadata()))).await;
    assert_eq!(code, 200, "{view}");
    assert_eq!(sp.view().await["idp"]["sloBinding"], "post");
    let plain = serve(&[]).await;
    let (code, view) = plain.import(&test_idp::with_post_slo(&test_idp::with_slo(&test_idp::metadata()))).await;
    assert_eq!(code, 200, "{view}");
    assert_eq!(plain.view().await["idp"]["sloBinding"], "redirect", "HTTP-Redirect first, as before");
    let imported = plain.audit("sso.saml_metadata_imported").await;
    assert_eq!(imported[0]["details"]["sloBinding"], "redirect");
}

// The HTTP-Artifact binding (ADR 0268)

/// A stand-in for the IdP's ArtifactResolutionService: the ArtifactResolves it got, and the
/// response XML it holds for each artifact. An artifact it doesn't hold is answered with none.
/// Its answers name `issuer`, else the test IdP.
#[derive(Clone, Default)]
struct ArtifactIdp {
    got: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    held: Arc<std::sync::Mutex<HashMap<String, String>>>,
    issuer: Option<String>,
}

impl ArtifactIdp {
    async fn start() -> (ArtifactIdp, String) {
        ArtifactIdp::start_for(None).await
    }

    async fn start_for(issuer: Option<&str>) -> (ArtifactIdp, String) {
        let idp = ArtifactIdp { issuer: issuer.map(String::from), ..Default::default() };
        let state = idp.clone();
        let app = axum::Router::new().route(
            "/ars",
            axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
                let state = state.clone();
                async move {
                    let action = headers.get("soapaction").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                    state.got.lock().unwrap().push((action, body.clone()));
                    let id = body.split(" ID=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
                    let artifact = body.split("<samlp:Artifact>").nth(1).unwrap().split('<').next().unwrap();
                    let message = state.held.lock().unwrap().remove(artifact);
                    let mut answer = crate::sso::saml_artifact::test_idp::Answer::new(&id, message, db::now());
                    if let Some(i) = &state.issuer {
                        answer.issuer = Some(i.clone());
                    }
                    answer.soap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}/ars", listener.local_addr().unwrap().port());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (idp, url)
    }
}

/// An ArtifactResolutionService that reads the request, starts its answer and hangs up halfway.
async fn cut_off_ars() -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}/ars", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            while !String::from_utf8_lossy(&got).contains("</soap11:Envelope>") {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 5000\r\n\r\n<soap11:Envelope").await;
        }
    });
    url
}

impl Sp {
    /// The IdP's redirect to our ACS with `artifact`: the status, where it goes next, the head.
    async fn send_artifact(&self, artifact: &str, relay: &str, cookie: &str) -> (u16, String, String) {
        let url = url::Url::parse_with_params(&self.acs(), [("SAMLart", artifact), ("RelayState", relay)]).unwrap();
        let res = http().get(url).header("cookie", cookie).send().await.unwrap();
        let head: String = res.headers().iter().map(|(k, v)| format!("{k}: {}\n", v.to_str().unwrap())).collect();
        let to = res.headers().get("location").map(|l| l.to_str().unwrap().to_string()).unwrap_or_default();
        (res.status().as_u16(), to, head)
    }

    /// A sign-in answered with an artifact `ars` holds a response for: the artifact, and how it went.
    async fn sign_in_by_artifact(&self, ars: &ArtifactIdp, index: u16) -> (String, (u16, String, String)) {
        let (request, relay, cookie) = self.start().await;
        let artifact = crate::sso::saml_artifact::test_idp::artifact(IDP, index);
        ars.held.lock().unwrap().insert(artifact.clone(), Response::new(&self.acs(), &self.entity(), &request, db::now()).xml());
        let went = self.send_artifact(&artifact, &relay, &cookie).await;
        (artifact, went)
    }
}

#[tokio::test]
async fn an_artifact_is_resolved_over_soap_into_a_sign_in_once() {
    let (ars, ars_url) = ArtifactIdp::start().await;
    let md = test_idp::with_artifact_resolution(&test_idp::with_artifact_resolution(&test_idp::metadata(), &ars_url, 1), "http://127.0.0.1:9/ars", 2);
    let sp = serve_importing(&[("RESPONSE_BINDING", "artifact")], |_| {}, &md).await;
    let view = sp.view().await;
    assert_eq!((view["responseBinding"].as_str(), &view["idp"]["artifactResolutionUrls"]), (Some("artifact"), &json!([{ "index": 1, "url": ars_url }, { "index": 2, "url": "http://127.0.0.1:9/ars" }])));
    let ours = http().get(format!("http://127.0.0.1:{}/api/auth/sso/{}/metadata", sp.port, sp.id)).send().await.unwrap().text().await.unwrap();
    assert!(ours.contains(&format!(r#"<md:AssertionConsumerService Binding="{}" Location="{}""#, crate::sso::saml_sp::ARTIFACT, sp.acs())) && ours.matches("<md:AssertionConsumerService").count() == 1, "{ours}");
    let u = sp.link();
    let cert = sp.sp_cert().await;

    let (artifact, (code, to, head)) = sp.sign_in_by_artifact(&ars, 1).await;
    assert_eq!((code, to.as_str()), (200, ""), "{head}");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(u.id.clone()));
    let (action, sent) = ars.got.lock().unwrap()[0].clone();
    assert_eq!(action, crate::sso::saml_slo::SOAP_ACTION);
    let doc = crate::sso::xmldsig::parse(&sent).unwrap();
    let m = doc.descendants().find(|n| crate::sso::xmldsig::is(*n, crate::sso::saml_sp::PROTOCOL, "ArtifactResolve")).expect("an ArtifactResolve");
    assert!(crate::sso::xmldsig::is(m.parent().unwrap(), crate::sso::saml_slo::SOAP11, "Body"));
    assert_eq!(crate::sso::xmldsig::verify_enveloped(m, std::slice::from_ref(&cert)), Ok(true), "signed by our key");
    assert_eq!(m.attribute("Destination"), Some(ars_url.as_str()));
    assert!(sent.contains(&format!("<samlp:Artifact>{artifact}</samlp:Artifact>")) && sent.contains(&format!("<saml:Issuer>{}</saml:Issuer>", sp.entity())), "{sent}");
    let login = &sp.audit("auth.login").await[0];
    assert_eq!((login["actorId"].as_str(), login["details"]["responseBinding"].as_str()), (Some(u.id.as_str()), Some("artifact")));

    // The same artifact again, for a new sign-in: refused without asking the IdP again.
    let (_, relay, cookie) = sp.start().await;
    let (_, to, _) = sp.send_artifact(&artifact, &relay, &cookie).await;
    assert_eq!((to.as_str(), sp.last_failure().await["reason"].as_str()), ("/login?error=sso_failed", Some("replayed")));
    assert_eq!(ars.got.lock().unwrap().len(), 1);

    // Metadata without an ArtifactResolutionService can't be used for it.
    let (code, body) = sp.import(&test_idp::metadata()).await;
    assert!(code == 400 && body.contains("no SOAP ArtifactResolutionService"), "{code} {body}");
    assert_eq!(sp.view().await["idp"]["artifactResolutionUrls"].as_array().map(Vec::len), Some(2), "the last good metadata stays");
}

#[tokio::test]
async fn only_our_idps_artifacts_for_its_endpoints_are_sent_and_posts_are_refused() {
    let (ars, ars_url) = ArtifactIdp::start().await;
    let md = test_idp::with_artifact_resolution(&test_idp::with_artifact_resolution(&test_idp::metadata(), &ars_url, 1), "http://127.0.0.1:9/ars", 2);
    let md = test_idp::with_artifact_resolution(&md, &cut_off_ars().await, 3);
    // Each on a server of its own: refusals nobody vouched for are audited once a minute.
    for (artifact, reason, why, asks) in [
        (crate::sso::saml_artifact::test_idp::artifact("https://evil.example/idp", 1), "wrong_artifact_source", None, false),
        (crate::sso::saml_artifact::test_idp::artifact(IDP, 7), "no_artifact_resolution", Some("7"), false),
        ("AAQ=".to_string(), "bad_artifact", None, false),
        (crate::sso::saml_artifact::test_idp::artifact(IDP, 1), "artifact_unknown", None, true),
        (crate::sso::saml_artifact::test_idp::artifact(IDP, 2), "artifact_unreachable", Some("error sending request"), false),
        // The IdP's answer cut off halfway: its trouble too, so not counted against the browser.
        (crate::sso::saml_artifact::test_idp::artifact(IDP, 3), "artifact_unreachable", Some("error decoding response body"), false),
    ] {
        let sp = serve_importing(&[("RESPONSE_BINDING", "artifact")], |_| {}, &md).await;
        let before = ars.got.lock().unwrap().len();
        let (_, relay, cookie) = sp.start().await;
        let (_, to, _) = sp.send_artifact(&artifact, &relay, &cookie).await;
        let f = sp.last_failure().await;
        assert_eq!((to.as_str(), f["reason"].as_str(), f["idpStatus"].as_str()), ("/login?error=sso_failed", Some(reason), why));
        assert_eq!(ars.got.lock().unwrap().len(), before + usize::from(asks), "{reason}");
    }

    // A posted response, even one signed by the IdP, isn't how this provider takes them.
    let sp = serve_importing(&[("RESPONSE_BINDING", "artifact")], |_| {}, &md).await;
    sp.link();
    let (request, relay, cookie) = sp.start().await;
    let posted = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    let (_, to, _) = sp.post(Some(&posted.posted()), Some(&relay), &cookie).await;
    assert_eq!((to.as_str(), sp.last_failure().await["reason"].as_str()), ("/login?error=sso_failed", Some("wrong_binding")));

    // And the other way round: a provider taking posts refuses an artifact unresolved.
    let sp = serve(&[]).await;
    assert_eq!(sp.view().await["responseBinding"], "post");
    let (_, relay, cookie) = sp.start().await;
    let (_, to, _) = sp.send_artifact(&crate::sso::saml_artifact::test_idp::artifact(IDP, 1), &relay, &cookie).await;
    assert_eq!((to.as_str(), sp.last_failure().await["reason"].as_str()), ("/login?error=sso_failed", Some("wrong_binding")));
    // A response in the query isn't taken: the ACS reads only artifacts there.
    let sp = serve(&[]).await;
    let (request, relay, cookie) = sp.start().await;
    let r = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    let url = url::Url::parse_with_params(&sp.acs(), [("SAMLResponse", r.posted().as_str()), ("RelayState", relay.as_str())]).unwrap();
    let res = http().get(url).header("cookie", cookie).send().await.unwrap();
    assert_eq!(res.headers()["location"], "/login?error=sso_failed");
    assert_eq!(sp.last_failure().await["reason"], "missing_response");
}

// Several IdPs of a federation (ADR 0282)

const IDP_B: &str = "https://login.uni-b.example/saml";

/// A federation's MDQ server for IdP `IDP` (University A, scope example.com, signer 0) and
/// `IDP_B` (Beta Institute, scope uni-b.example, signer `b_signer`), both with SLO URLs, each
/// answer signed by test signer 1; and botd with SCIM on and one provider for both, plus
/// `extra` settings.
async fn serve_federation(extra: &[(&str, &str)], b_signer: usize) -> (Sp, std::path::PathBuf, Vec<Arc<crate::sso::Provider>>) {
    serve_federation_with(extra, b_signer, |_, md| md).await
}

/// `serve_federation`, with each IdP's metadata changed by `edit(entity ID, metadata)` before it's signed.
async fn serve_federation_with(extra: &[(&str, &str)], b_signer: usize, edit: impl Fn(&str, String) -> String) -> (Sp, std::path::PathBuf, Vec<Arc<crate::sso::Provider>>) {
    use crate::sso::saml_sp::{mdq_url, test_instant};
    let signer = |i: usize| crate::sso::xmldsig::test_signer::signer(i);
    let until = test_instant(db::now() + 7 * 86_400_000);
    let entry = |xml: String| test_idp::signed_metadata(&xml.replacen("<md:EntityDescriptor ", &format!(r#"<md:EntityDescriptor validUntil="{until}" "#), 1), signer(1));
    let a = entry(edit(IDP, test_idp::with_slo(&test_idp::with_ui(&test_idp::metadata(), "University A", &["example.com"]))));
    let b = entry(edit(IDP_B, test_idp::with_slo(&test_idp::with_ui(&test_idp::metadata_with(IDP_B, &[signer(b_signer)], ""), "Beta Institute", &["uni-b.example"])).replace("https://idp.example/", "https://login.uni-b.example/")));
    let answers: HashMap<String, String> = HashMap::from([(mdq_url("/mdq", IDP), a), (mdq_url("/mdq", IDP_B), b)]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mdq_port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
        let answer = answers.get(uri.path()).cloned();
        std::future::ready(answer.map_or_else(|| axum::http::StatusCode::NOT_FOUND.into_response(), |a| a.into_response()))
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dir = std::env::temp_dir().join(format!("saml-fed-{}", random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let anchor = dir.join("federation.pem");
    std::fs::write(&anchor, format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", signer(1).cert)).unwrap();
    let id = format!("n{}", random_hex(4));
    let up = id.to_ascii_uppercase();
    let mut vars = HashMap::from([
        ("SSO_PROVIDERS".into(), id.clone()),
        (format!("SSO_{up}_TYPE"), "saml".into()),
        (format!("SSO_{up}_LABEL"), "Uni Federation".into()),
        (format!("SSO_{up}_IDP_ENTITY_IDS"), format!("{IDP},{IDP_B}")),
        (format!("SSO_{up}_IDP_MDQ_URL"), format!("http://127.0.0.1:{mdq_port}/mdq")),
        (format!("SSO_{up}_METADATA_SIGNING_CERT_FILE"), anchor.to_string_lossy().into_owned()),
    ]);
    vars.extend(extra.iter().map(|(k, v)| (format!("SSO_{up}_{k}"), v.to_string())));
    let mut providers = Vec::new();
    let (port, app, admin) = serve_vars_with(vars, |a| {
        a.scim.enabled = true;
        providers = a.sso.providers.clone();
    })
    .await;
    let sp = Sp { port, app, admin, id, sp_entity: None };
    // Loads every IdP's metadata, as the startup expiry check does.
    assert_eq!(call(sp.port, "GET", &format!("/api/sso/{}/saml", sp.id), &sp.admin, "").await.0, 200);
    (sp, dir, providers)
}

impl Sp {
    /// Starts a web sign-in at IdP `idp`: the AuthnRequest's ID, the RelayState, the binder
    /// cookie, and where the AuthnRequest went.
    async fn start_at(&self, idp: &str) -> (String, String, String, String) {
        let path = format!("/api/auth/sso/{}/start?idp={}", self.id, url::form_urlencoded::byte_serialize(idp.as_bytes()).collect::<String>());
        let (code, head, body) = crate::tests::call_with(self.port, "GET", &path, "", "", "").await;
        assert_eq!(code, 303, "{head}\n{body}");
        let to_idp = url::Url::parse(&header(&head, "location").unwrap()).unwrap();
        let q: HashMap<_, _> = to_idp.query_pairs().into_owned().collect();
        let request = String::from_utf8(miniz_oxide::inflate::decompress_to_vec(&STANDARD.decode(&q["SAMLRequest"]).unwrap()).unwrap()).unwrap();
        let id = request.split(" ID=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
        let binder = set_cookies(&head).into_iter().find(|c| c.starts_with("__Host-superbot_saml=")).expect("binder cookie");
        (id, q["RelayState"].clone(), binder.split(';').next().unwrap().to_string(), format!("{}://{}{}", to_idp.scheme(), to_idp.host_str().unwrap(), to_idp.path()))
    }

    /// A whole sign-in started at `idp`, answered with the response `tweak` makes.
    async fn sign_in_at(&self, idp: &str, tweak: impl FnOnce(&mut Response)) -> (u16, String, String) {
        let (request, relay, cookie, _) = self.start_at(idp).await;
        let mut r = Response::new(&self.acs(), &self.entity(), &request, db::now());
        tweak(&mut r);
        self.post(Some(&r.posted()), Some(&relay), &cookie).await
    }
}

/// IdP B's answer: its issuer, signed with its key.
fn from_b(r: &mut Response) {
    r.issuer = IDP_B.into();
    r.signer = 2;
}

#[tokio::test]
async fn a_federation_aggregate_signs_people_in_at_its_listed_idps() {
    use crate::sso::saml_sp::test_idp::{aggregate, signed_aggregate};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let signer = |i: usize| crate::sso::xmldsig::test_signer::signer(i);
    let week = db::now() + 7 * 86_400_000;
    let entity = |id: &str, key: usize, host: &str| test_idp::metadata_with(id, &[signer(key)], "").replace("https://idp.example/", host);
    let mut members: Vec<String> = (0..800).map(|i| entity(&format!("https://idp{i}.member.example/idp"), 0, &format!("https://idp{i}.member.example/"))).collect();
    members.push(entity(IDP, 0, "https://idp.example/"));
    let without_b = members.clone();
    members.push(entity(IDP_B, 2, "https://login.uni-b.example/"));
    let full = signed_aggregate(&aggregate(&members, week), signer(1), "#_agg");
    assert!(full.len() > crate::sso::saml_sp::MAX_METADATA, "{}", full.len());

    // What the federation serves: the aggregate, gzipped or not, and its ETag.
    let served = Arc::new(std::sync::Mutex::new((full, true, "\"v1\"".to_string())));
    let asked = Arc::new(std::sync::Mutex::new(Vec::<(Option<String>, Option<String>)>::new()));
    let slow = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let md_port = listener.local_addr().unwrap().port();
    let (s, a, sl) = (served.clone(), asked.clone(), slow.clone());
    let app = axum::Router::new().fallback(move |headers: axum::http::HeaderMap| {
        let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).map(String::from);
        a.lock().unwrap().push((h("if-none-match"), h("accept-encoding")));
        let (xml, gzip, etag) = s.lock().unwrap().clone();
        let res = if h("if-none-match").as_deref() == Some(etag.as_str()) {
            (StatusCode::NOT_MODIFIED, [("etag", etag)]).into_response()
        } else if gzip {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            std::io::Write::write_all(&mut e, xml.as_bytes()).unwrap();
            ([("etag", etag), ("content-encoding", "gzip".into())], e.finish().unwrap()).into_response()
        } else {
            ([("etag", etag)], xml.into_bytes()).into_response()
        };
        let delay = if sl.load(std::sync::atomic::Ordering::Relaxed) { 3 } else { 0 };
        async move {
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            res
        }
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dir = std::env::temp_dir().join(format!("saml-agg-{}", random_hex(4)));
    std::fs::create_dir_all(&dir).unwrap();
    let anchor = dir.join("federation.pem");
    std::fs::write(&anchor, format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", signer(1).cert)).unwrap();
    let id = format!("n{}", random_hex(4));
    let up = id.to_ascii_uppercase();
    let vars = HashMap::from([
        ("SSO_PROVIDERS".into(), id.clone()),
        (format!("SSO_{up}_TYPE"), "saml".into()),
        (format!("SSO_{up}_IDP_ENTITY_IDS"), format!("{IDP},{IDP_B}")),
        (format!("SSO_{up}_IDP_AGGREGATE_URL"), format!("http://127.0.0.1:{md_port}/federation.xml")),
        (format!("SSO_{up}_METADATA_SIGNING_CERT_FILE"), anchor.to_string_lossy().into_owned()),
    ]);
    let mut provider = None;
    let (port, app, admin) = serve_vars_with(vars, |a| provider = a.sso.providers.first().cloned()).await;
    let (sp, provider) = (Sp { port, app, admin, id, sp_entity: None }, provider.unwrap());
    let downloads = || asked.lock().unwrap().len();

    // One download, gzipped, signs people in at both IdPs, each checked against its own key.
    let bob = sp.app.db.create_user(None, Some("bob@uni-b.example"), "Bob", Role::Member).unwrap();
    sp.app.db.link_identity(&bob.id, &NewIdentity { provider: &sp.id, issuer: IDP_B, subject: STORED, tenant: None, email: None, created_by: Some("test") }).unwrap();
    let (code, _, head) = sp.sign_in_at(IDP_B, from_b).await;
    assert_eq!(code, 200, "{head}");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(bob.id.clone()));
    let ada = sp.link();
    let (code, _, head) = sp.sign_in_at(IDP, |_| {}).await;
    assert_eq!(code, 200, "{head}");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(ada.id.clone()));
    let (code, to, _) = sp.sign_in_at(IDP, |r| r.signer = 2).await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_failed"), "B's key doesn't sign for A");
    assert_eq!(asked.lock().unwrap().clone(), [(None, Some("gzip".to_string()))]);
    let (_, v) = call(sp.port, "GET", &format!("/api/sso/{}/saml", sp.id), &sp.admin, "").await;
    let v: Value = serde_json::from_str(&v).unwrap();
    assert_eq!(v["source"].as_str(), Some("aggregate"));
    assert!(v["from"].as_str().unwrap().ends_with("/federation.xml"), "{}", v["from"]);

    // A day later it hasn't changed: asked with its ETag, and not again until the next day.
    // The sign-in that asks goes on with its good copy meanwhile.
    provider.age_idp(std::time::Duration::from_secs(25 * 3600));
    slow.store(true, std::sync::atomic::Ordering::Relaxed);
    let started = std::time::Instant::now();
    assert_eq!(sp.sign_in_at(IDP, |_| {}).await.0, 200);
    assert!(started.elapsed() < std::time::Duration::from_millis(1_500), "waited {:?} for the download", started.elapsed());
    provider.idp_refreshed().await;
    slow.store(false, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(sp.sign_in_at(IDP_B, from_b).await.0, 200);
    assert_eq!((downloads(), asked.lock().unwrap()[1].0.as_deref()), (2, Some("\"v1\"")));

    // The federation drops B: B's copy goes with it, and A still signs in.
    *served.lock().unwrap() = (signed_aggregate(&aggregate(&without_b, week), signer(1), "#_agg"), false, "\"v2\"".into());
    provider.age_idp(std::time::Duration::from_secs(25 * 3600));
    assert_eq!(sp.sign_in_at(IDP, |_| {}).await.0, 200);
    provider.idp_refreshed().await;
    assert!(provider.idp_loaded_for(IDP_B).is_none());
    let (code, head, _) = crate::tests::call_with(sp.port, "GET", &format!("/api/auth/sso/{}/start?idp={}", sp.id, url::form_urlencoded::byte_serialize(IDP_B.as_bytes()).collect::<String>()), "", "", "").await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login?error=sso_failed")));
    assert_eq!(downloads(), 3, "read today: not again for B");

    // A badly signed aggregate is refused as a whole and audited for no one IdP; A's copy stays.
    *served.lock().unwrap() = (signed_aggregate(&aggregate(&without_b, week), signer(0), "#_agg"), true, "\"v3\"".into());
    provider.age_idp(std::time::Duration::from_secs(25 * 3600));
    assert_eq!(sp.sign_in_at(IDP, |_| {}).await.0, 200, "the last good copy");
    provider.idp_refreshed().await;
    assert_eq!(sp.sign_in_at(IDP, |_| {}).await.0, 200, "audited at the next sign-in");
    let refused = &sp.audit("sso.saml_metadata_refused").await[0];
    assert_eq!(
        (refused["details"]["reason"].as_str(), refused["details"]["source"].as_str(), refused["details"]["kept"].as_bool(), &refused["details"]["entityId"]),
        (Some("bad_signature"), Some("aggregate"), Some(true), &Value::Null)
    );
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn one_provider_signs_people_in_at_each_idp_of_a_federation() {
    let (sp, dir, _) = serve_federation(&[], 2).await;

    // The chooser: both IdPs by name, sorted, each a start at that IdP; no script.
    let (code, head, page) = crate::tests::call_with(sp.port, "GET", &format!("/api/auth/sso/{}/start?session=cookie", sp.id), "", "", "").await;
    assert_eq!(code, 200, "{head}");
    let csp = header(&head, "content-security-policy").unwrap();
    assert!(csp.starts_with("default-src 'none';") && csp.contains("style-src 'sha256-") && !csp.contains("script-src"), "{csp}");
    assert_eq!(header(&head, "cache-control").as_deref(), Some("no-store"));
    assert!(page.contains("Sign in with Uni Federation") && !page.contains("<script"), "{page}");
    let (beta, uni) = (page.find(">Beta Institute<").expect("B's name"), page.find(">University A<").expect("A's name"));
    assert!(beta < uni, "sorted by name");
    let b_link = format!("idp={}", url::form_urlencoded::byte_serialize(IDP_B.as_bytes()).collect::<String>());
    assert!(page.contains(&b_link) && page.contains("session=cookie&amp;idp="), "{page}");

    // Each choice goes to that IdP only.
    assert_eq!(sp.start_at(IDP).await.3, SSO_URL);
    assert_eq!(sp.start_at(IDP_B).await.3, "https://login.uni-b.example/saml/sso");
    let (code, head, _) = crate::tests::call_with(sp.port, "GET", &format!("/api/auth/sso/{}/start?idp=https%3A%2F%2Fidp.other.example", sp.id), "", "", "").await;
    assert_eq!((code, header(&head, "location").as_deref()), (303, Some("/login?error=sso_failed")));
    assert_eq!((sp.last_failure().await["reason"].as_str(), sp.last_failure().await["entityId"].as_str()), (Some("unknown_idp"), Some("https://idp.other.example")));

    // Linking says which IdP's NameID it is.
    let link = |body: Value| {
        let (port, admin) = (sp.port, sp.admin.clone());
        async move { call(port, "POST", "/api/users/bob@uni-b.example/identities", &admin, &body.to_string()).await }
    };
    let bob = sp.app.db.create_user(None, Some("bob@uni-b.example"), "Bob", Role::Member).unwrap();
    let (code, e) = link(json!({ "provider": sp.id, "subject": NAME_ID })).await;
    assert!(code == 400 && e.contains("--idp"), "{code} {e}");
    let (code, e) = link(json!({ "provider": sp.id, "subject": NAME_ID, "idp": "https://idp.other.example" })).await;
    assert!(code == 400 && e.contains("not one of this provider's IdPs"), "{code} {e}");
    let (code, i) = link(json!({ "provider": sp.id, "subject": NAME_ID, "idp": IDP_B })).await;
    assert_eq!(code, 201, "{i}");
    assert_eq!(serde_json::from_str::<Value>(&i).unwrap()["issuer"], IDP_B);

    // Signed in at B: B's person, under B. The email isn't at B's scope, so it's dropped.
    let (code, _, head) = sp.sign_in_at(IDP_B, from_b).await;
    assert_eq!(code, 200, "{head}");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(bob.id.clone()));
    let login = &sp.audit("auth.login").await[0];
    assert_eq!((login["details"]["issuer"].as_str(), login["actorSubject"].as_str()), (Some(IDP_B), Some(format!("{IDP_B}|{STORED}").as_str())));
    assert_eq!(sp.app.db.identity(IDP_B, STORED).unwrap().0.email, None, "ada@example.com isn't B's to vouch for");
    let (code, _, _) = sp.sign_in_at(IDP_B, |r| {
        from_b(r);
        r.attributes[0].1 = "bob@uni-b.example".into();
    })
    .await;
    assert_eq!(code, 200);
    assert_eq!(sp.app.db.identity(IDP_B, STORED).unwrap().0.email.as_deref(), Some("bob@uni-b.example"), "in scope");

    // Started at B, only B's answer counts: not A's, nor one naming B signed by A. (Their
    // audit events are throttled behind the unknown IdP's.)
    for tweak in [(|_: &mut Response| {}) as fn(&mut Response), |r| r.issuer = IDP_B.into()] {
        let (code, to, _) = sp.sign_in_at(IDP_B, tweak).await;
        assert_eq!((code, to.as_str()), (303, "/login?error=sso_failed"));
    }

    // The same NameID at A is someone else, and A vouches for example.com.
    let ada = sp.link();
    let (code, _, head) = sp.sign_in_at(IDP, |r| r.session_index = "_ada".into()).await;
    assert_eq!(code, 200);
    assert_eq!(signed_in_as(sp.port, &head).await, Some(ada.id.clone()));
    assert_eq!(sp.app.db.identity(IDP, STORED).unwrap().0.email.as_deref(), Some("ada@example.com"));
    let ada_cookie = format!("Cookie: {}\r\n", set_cookies(&head).into_iter().find(|c| c.starts_with("__Host-superbot_session=")).unwrap().split(';').next().unwrap());

    // B signs Bob out: checked against B's metadata, answered at B, and only B's sessions end.
    let (code, _, head) = sp.sign_in_at(IDP_B, |r| {
        from_b(r);
        r.session_index = "_bob".into();
    })
    .await;
    assert_eq!(code, 200);
    let bob_cookie = format!("Cookie: {}\r\n", set_cookies(&head).into_iter().find(|c| c.starts_with("__Host-superbot_session=")).unwrap().split(';').next().unwrap());
    let mut l = Logout::request(&sp.slo(), NAME_ID, Some("_bob"), db::now());
    l.issuer = IDP_B.into();
    l.signer = Some(2);
    let (code, to) = sp.slo_get(&l.redirect()).await;
    assert!(code == 303 && to.starts_with("https://login.uni-b.example/saml/slo?SAMLResponse="), "{code} {to}");
    assert_eq!((sp.who(&bob_cookie).await, sp.who(&ada_cookie).await), (None, Some(ada.id.clone())));
    let slo = &sp.audit("auth.slo").await[0];
    assert_eq!((slo["details"]["issuer"].as_str(), slo["details"]["revoked"].as_u64()), (Some(IDP_B), Some(1)));

    // A logout naming an IdP that isn't listed, or naming B but signed by A, is refused.
    let mut l = Logout::request(&sp.slo(), NAME_ID, None, db::now());
    l.issuer = "https://idp.other.example".into();
    assert_eq!(sp.slo_get(&l.redirect()).await.0, 400);
    assert_eq!(sp.audit("auth.slo_failed").await[0]["details"]["reason"], "unknown_idp");
    l.issuer = IDP_B.into();
    assert_eq!(sp.slo_get(&l.redirect()).await.0, 400);
    assert_eq!(sp.who(&ada_cookie).await, Some(ada.id.clone()));

    // botctl's view lists each IdP with its name and email domains.
    let (_, v) = call(sp.port, "GET", &format!("/api/sso/{}/saml", sp.id), &sp.admin, "").await;
    let v: Value = serde_json::from_str(&v).unwrap();
    assert_eq!((v["idpEntityIds"].clone(), v["idpEntityId"].clone(), v["idp"].clone()), (json!([IDP, IDP_B]), Value::Null, Value::Null));
    assert_eq!((v["idps"][1]["name"].as_str(), v["idps"][1]["scopes"].clone(), v["idps"][1]["ssoUrl"].as_str()), (Some("Beta Institute"), json!(["uni-b.example"]), Some("https://login.uni-b.example/saml/sso")));
    assert!(v["from"].as_str().unwrap().ends_with("/mdq") && v["singleLogout"] == true, "{v}");
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn with_allowed_domains_an_email_out_of_the_idps_scope_is_refused() {
    let (sp, dir, _) = serve_federation(&[("ALLOWED_DOMAINS", "example.com,uni-b.example"), ("JIT_ROLE", "member")], 2).await;
    let (code, to, _) = sp.sign_in_at(IDP_B, from_b).await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_wrong_account"), "B can't vouch for example.com");
    assert_eq!(sp.last_failure().await["reason"], "email_out_of_scope");
    assert!(sp.app.db.identity(IDP_B, STORED).is_none(), "nobody made just in time");
    let (code, _, head) = sp.sign_in_at(IDP_B, |r| {
        from_b(r);
        r.attributes[0].1 = "bob@uni-b.example".into();
    })
    .await;
    assert_eq!(code, 200, "{head}");
    assert_eq!(sp.app.db.identity(IDP_B, STORED).unwrap().1.email.as_deref(), Some("bob@uni-b.example"));
    let (code, _, _) = sp.sign_in_at(IDP, |_| {}).await;
    assert_eq!(code, 200, "A vouches for example.com");
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn idps_sharing_a_certificate_are_each_warned_about_it() {
    use crate::sso::saml_expiry;
    let (sp, dir, providers) = serve_federation(&[], 0).await;
    let late = (crate::sso::xmldsig::test_signer::signer(0).cert().not_after - 10 * 86_400) * 1000;
    saml_expiry::check(&sp.app, &providers, &reqwest::Client::new(), std::time::Duration::ZERO, late).await;
    let mut warned: Vec<String> = sp.audit("sso.saml_certificate_expiring").await.iter().filter(|e| e["details"]["role"] == "idp_signing").map(|e| e["details"]["entityId"].as_str().unwrap().to_string()).collect();
    warned.sort();
    assert_eq!(warned, [IDP, IDP_B], "one notice each, not one for both");
    std::fs::remove_dir_all(dir).ok();
}

// Groups with several IdPs of a federation (ADR 0287)

impl Sp {
    /// A user linked at IdP `idp` with NameID `subject`, as stored.
    fn link_at(&self, idp: &str, subject: &str, email: &str, role: Role) -> (User, String) {
        let u = self.app.db.create_user(None, Some(email), email, role).unwrap();
        let i = self.app.db.link_identity(&u.id, &NewIdentity { provider: &self.id, issuer: idp, subject, tenant: None, email: None, created_by: Some("test") }).unwrap();
        (u, i.id)
    }
}

#[tokio::test]
async fn each_idp_of_a_federation_maps_its_own_groups() {
    let (sp, dir, _) = serve_federation(&[("GROUPS_ATTRIBUTE", "groups")], 2).await;
    let (port, admin, id) = (sp.port, sp.admin.clone(), sp.id.clone());
    let auditor = sp.app.db.create_custom_role("Auditor", "", Role::Member, &["audit.view"], None, None).unwrap();
    let map = async |body: Value| {
        let (code, v) = call(port, "POST", "/api/sso/role-mappings", &admin, &body.to_string()).await;
        (code, serde_json::from_str::<Value>(&v).unwrap_or(Value::String(v)))
    };

    // Each mapping says whose group it is.
    let (code, e) = map(json!({ "provider": id, "group": "staff", "role": "Auditor" })).await;
    assert!(code == 400 && e.to_string().contains("--idp"), "{code} {e}");
    let (code, e) = map(json!({ "provider": id, "group": "staff", "role": "Auditor", "idp": "https://idp.other.example" })).await;
    assert!(code == 400 && e.to_string().contains("not one of this provider's IdPs"), "{code} {e}");
    assert_eq!(map(json!({ "provider": id, "group": "staff", "role": "Auditor", "idp": 7 })).await.0, 400);
    let (code, at_a) = map(json!({ "provider": id, "group": "staff", "role": "Auditor", "idp": IDP })).await;
    assert_eq!(code, 201, "{at_a}");
    assert_eq!((at_a["idp"].as_str(), at_a["active"].as_bool()), (Some(IDP), Some(true)));
    assert_eq!(sp.audit("sso.saml_role_mapped").await[0]["details"]["idp"], IDP);
    let (code, e) = map(json!({ "provider": id, "group": "staff", "role": "Auditor", "idp": IDP })).await;
    assert!(code == 409 && e.to_string().contains(&format!("at {IDP}")), "{code} {e}");
    let (_, all) = call(port, "GET", "/api/sso/role-mappings", &admin, "").await;
    assert_eq!(serde_json::from_str::<Value>(&all).unwrap()["providers"][0]["idps"], json!([IDP, IDP_B]));

    let (ada, _) = sp.link_at(IDP, STORED, "ada@example.com", Role::Readonly);
    let (bob, _) = sp.link_at(IDP_B, "00ubob", "bob@uni-b.example", Role::Readonly);
    let role_of = |u: &User| sp.app.db.user(&u.id).unwrap().role_id;
    let at_b = |groups: &'static [&'static str]| {
        move |r: &mut Response| {
            from_b(r);
            r.name_id = "00uBOB".into();
            in_groups(groups)(r);
        }
    };

    // B's "staff" isn't A's.
    let (code, _, _) = sp.sign_in_at(IDP_B, at_b(&["staff"])).await;
    assert_eq!((code, role_of(&bob)), (200, None));
    let (code, _, _) = sp.sign_in_at(IDP, in_groups(&["staff"])).await;
    assert_eq!((code, role_of(&ada)), (200, Some(auditor.id.clone())));
    let given = &sp.audit("role.assigned").await[0]["details"];
    assert_eq!((given["idp"].as_str(), given["user"].as_str()), (Some(IDP), Some(ada.id.as_str())));
    let (code, at_b_map) = map(json!({ "provider": id, "group": "staff", "role": auditor.id, "idp": IDP_B })).await;
    assert_eq!(code, 201, "{at_b_map}");
    sp.sign_in_at(IDP_B, at_b(&["staff"])).await;
    assert_eq!(role_of(&bob), Some(auditor.id.clone()));
    assert_eq!(sp.audit("role.assigned").await[0]["details"]["mapping"], at_b_map["id"]);

    // Someone at both IdPs: only the IdP whose group gave the role can say they left it.
    let (carol, at_a_identity) = sp.link_at(IDP, "00ucarol", "carol@example.com", Role::Readonly);
    let carol_b = sp.app.db.link_identity(&carol.id, &NewIdentity { provider: &id, issuer: IDP_B, subject: "00ucarol", tenant: None, email: None, created_by: Some("test") }).unwrap();
    let carol_at_a = |groups: &'static [&'static str]| {
        move |r: &mut Response| {
            r.name_id = "00uCAROL".into();
            in_groups(groups)(r);
        }
    };
    let carol_at_b = |groups: &'static [&'static str]| {
        move |r: &mut Response| {
            from_b(r);
            r.name_id = "00uCAROL".into();
            in_groups(groups)(r);
        }
    };
    sp.sign_in_at(IDP, carol_at_a(&["staff"])).await;
    assert_eq!(role_of(&carol), Some(auditor.id.clone()));
    sp.sign_in_at(IDP_B, carol_at_b(&[])).await;
    assert_eq!(role_of(&carol), Some(auditor.id.clone()), "B can't say she left A's group");
    let (code, e) = call(port, "DELETE", &format!("/api/users/{}/identities/{}", carol.id, carol_b.id), &admin, "").await;
    assert_eq!(code, 200, "{e}");
    assert_eq!(role_of(&carol), Some(auditor.id.clone()), "unlinked at B, still linked at A");
    sp.sign_in_at(IDP, carol_at_a(&["everyone"])).await;
    assert_eq!(role_of(&carol), None);
    assert_eq!(sp.audit("role.unassigned").await[0]["details"]["reason"], "left_group");
    sp.sign_in_at(IDP, carol_at_a(&["staff"])).await;
    let (code, _) = call(port, "DELETE", &format!("/api/users/{}/identities/{at_a_identity}", carol.id), &admin, "").await;
    assert_eq!((code, role_of(&carol)), (200, None));
    assert_eq!(sp.audit("role.unassigned").await[0]["details"]["reason"], "unlinked");

    // A mapping for an IdP the provider no longer has (made when it had one IdP, or for one
    // taken off the list) gives nothing, and what it gave goes at the next sign-in.
    for (n, stale) in [None, Some("https://idp.gone.example")].into_iter().enumerate() {
        let m = sp.app.db.create_saml_role_mapping(&id, stale, &format!("old-staff-{n}"), &auditor.id, None).unwrap();
        let (_, v) = call(port, "GET", &format!("/api/sso/role-mappings/{}", m.id), &admin, "").await;
        assert_eq!(serde_json::from_str::<Value>(&v).unwrap()["active"], false, "{v}");
        let (dave, _) = sp.link_at(IDP, &format!("00udave{n}"), &format!("dave{n}@example.com"), Role::Readonly);
        assert!(sp.app.db.grant_saml_role(&m, &dave.id));
        let group = m.group.clone();
        sp.sign_in_at(IDP, move |r| {
            r.name_id = format!("00uDAVE{n}");
            r.multi_attributes = vec![("groups".into(), vec![group])];
        })
        .await;
        assert_eq!(role_of(&dave), None, "{stale:?}");
        assert_eq!(sp.audit("role.unassigned").await[0]["details"]["reason"], "idp_not_listed");
    }
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn with_several_idps_a_group_scoped_to_another_idps_domain_never_counts() {
    let (sp, dir, _) = serve_federation(&[("GROUPS_ATTRIBUTE", "groups"), ("REQUIRED_GROUPS", "member@example.com,member@uni-b.example")], 2).await;
    let (bob, _) = sp.link_at(IDP_B, "00ubob", "bob@uni-b.example", Role::Member);
    let at_b = |groups: &'static [&'static str]| {
        move |r: &mut Response| {
            from_b(r);
            r.name_id = "00uBOB".into();
            in_groups(groups)(r);
        }
    };

    // B says Bob is a member at A: dropped, so he's in no required group.
    let (code, to, _) = sp.sign_in_at(IDP_B, at_b(&["member@example.com", "MEMBER@Example.com", "staff"])).await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_not_allowed"));
    let f = sp.last_failure().await;
    assert_eq!((f["reason"].as_str(), f["groupsOutOfScope"].clone()), (Some("not_in_group"), json!(["member@example.com", "MEMBER@Example.com"])));
    let (code, _, head) = sp.sign_in_at(IDP_B, at_b(&["member@uni-b.example"])).await;
    assert_eq!(code, 200);
    assert_eq!(signed_in_as(sp.port, &head).await, Some(bob.id.clone()));

    // A's own scope counts at A, B's doesn't.
    let ada = sp.link();
    let (code, to, _) = sp.sign_in_at(IDP, in_groups(&["member@uni-b.example"])).await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_not_allowed"));
    let (code, _, head) = sp.sign_in_at(IDP, in_groups(&["member@example.com"])).await;
    assert_eq!(code, 200);
    assert_eq!(signed_in_as(sp.port, &head).await, Some(ada.id.clone()));

    // Mappings see the same groups: a scoped value out of the IdP's scope gives nothing.
    let auditor = sp.app.db.create_custom_role("Auditor", "", Role::Member, &["audit.view"], None, None).unwrap();
    sp.app.db.create_saml_role_mapping(&sp.id, Some(IDP_B), "faculty@example.com", &auditor.id, None).unwrap();
    sp.sign_in_at(IDP_B, at_b(&["member@uni-b.example", "faculty@example.com"])).await;
    assert_eq!(sp.app.db.user(&bob.id).unwrap().role_id, None);
    std::fs::remove_dir_all(dir).ok();
}

// IdP-initiated sign-in at each IdP of a federation (ADR 0290)

#[tokio::test]
async fn each_federation_idps_tile_restarts_a_sign_in_at_that_idp() {
    let (sp, dir, _) = serve_federation(&[("IDP_INITIATED", "restart")], 2).await;
    assert_eq!(sp.view().await["idpInitiated"], "restart");
    let (bob, _) = sp.link_at(IDP_B, "00ubob", "bob@uni-b.example", Role::Member);
    sp.link();
    let tile_at = |idp: &str| {
        let mut t = sp.unsolicited();
        if idp == IDP_B {
            from_b(&mut t);
            t.name_id = "00uBOB".into();
        }
        t
    };
    let start_at = |idp: &str| format!("http://127.0.0.1:{}/api/auth/sso/{}/start?idp={}", sp.port, sp.id, url::form_urlencoded::byte_serialize(idp.as_bytes()).collect::<String>());
    let marker_of = |idp: &str| format!("{}.{}", sp.id, &crate::users::hash(idp)[..16]);
    let marker_set = |head: &str| set_cookies(head).into_iter().find(|c| c.starts_with(&format!("{RESTART}="))).map(|c| c.split(';').next().unwrap().to_string());

    // B's tile is checked against B's metadata, then sends the browser to start at B, not the
    // chooser, with a marker naming B.
    let (code, to, head) = sp.post(Some(&tile_at(IDP_B).posted()), Some("https://evil.example/next"), "").await;
    assert_eq!((code, to.as_str()), (303, start_at(IDP_B).as_str()));
    assert!(signed_in_as(sp.port, &head).await.is_none());
    assert_eq!(marker_set(&head), Some(format!("{RESTART}={}", marker_of(IDP_B))));
    let restarted = &sp.audit("auth.saml_idp_initiated").await[0]["details"];
    assert_eq!((restarted["issuer"].as_str(), restarted["subject"].as_str(), restarted["outcome"].as_str()), (Some(IDP_B), Some("00ubob"), Some("restarted")));

    // The browser follows it: the AuthnRequest goes to B, and B's answer signs Bob in.
    let (request, relay, binder, to_idp) = sp.start_at(IDP_B).await;
    assert_eq!(to_idp, "https://login.uni-b.example/saml/sso");
    let mut answer = Response::new(&sp.acs(), &sp.entity(), &request, db::now());
    from_b(&mut answer);
    answer.name_id = "00uBOB".into();
    let (code, _, head) = sp.post(Some(&answer.posted()), Some(&relay), &format!("{binder}; {RESTART}={}", marker_of(IDP_B))).await;
    assert_eq!(code, 200, "{head}");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(bob.id.clone()));
    assert_eq!(marker_set(&head), Some(format!("{RESTART}=")), "the marker is cleared");

    // A's tile goes to A, with A's marker. B's marker doesn't make it a loop: only B answering
    // its own restart unsolicited again is one.
    let (code, to, head) = sp.post(Some(&tile_at(IDP).posted()), None, &format!("{RESTART}={}", marker_of(IDP_B))).await;
    assert_eq!((code, to.as_str()), (303, start_at(IDP).as_str()));
    assert_eq!(marker_set(&head), Some(format!("{RESTART}={}", marker_of(IDP))));
    let (code, to, _) = sp.post(Some(&tile_at(IDP_B).posted()), None, &format!("{RESTART}={}", marker_of(IDP_B))).await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_failed"));
    assert_eq!(sp.last_failure().await["reason"], "idp_initiated_loop");
    let (code, to, _) = sp.post(Some(&tile_at(IDP_B).posted()), None, &format!("{RESTART}={}", sp.id)).await;
    assert_eq!((code, to.as_str()), (303, start_at(IDP_B).as_str()), "a marker without the IdP isn't B's");
    assert_eq!(sp.audit("auth.saml_idp_initiated").await.len(), 3);

    // A tile from an IdP the provider doesn't list is refused before anything is fetched or checked.
    let mut other = sp.unsolicited();
    other.issuer = "https://idp.other.example".into();
    let (code, to, head) = sp.post(Some(&other.posted()), None, "").await;
    assert_eq!((code, to.as_str(), marker_set(&head)), (303, "/login?error=sso_failed", Some(format!("{RESTART}="))), "no restart");
    let f = sp.last_failure().await;
    assert_eq!((f["reason"].as_str(), f["entityId"].as_str(), f["idpInitiated"].as_bool()), (Some("unknown_idp"), Some("https://idp.other.example"), Some(true)));
    // The Issuer only picks whose keys check it: one naming B but signed by A is refused.
    let mut forged = sp.unsolicited();
    forged.issuer = IDP_B.into();
    let (code, to, head) = sp.post(Some(&forged.posted()), None, "").await;
    assert_eq!((code, to.as_str(), marker_set(&head)), (303, "/login?error=sso_failed", Some(format!("{RESTART}="))), "no restart");
    // Nothing to read an IdP from.
    let (code, to, _) = sp.post(Some("not base64 <xml>"), None, "").await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_failed"));
    assert_eq!(sp.audit("auth.saml_idp_initiated").await.len(), 3);
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn a_federation_idps_unsolicited_artifact_is_resolved_at_that_idp_and_restarts_there() {
    use crate::sso::saml_artifact::test_idp::artifact;
    let ((a_ars, a_url), (b_ars, b_url)) = (ArtifactIdp::start().await, ArtifactIdp::start_for(Some(IDP_B)).await);
    let (sp, dir, _) = serve_federation_with(&[("IDP_INITIATED", "restart"), ("RESPONSE_BINDING", "artifact")], 2, |e, md| test_idp::with_artifact_resolution(&md, if e == IDP { &a_url } else { &b_url }, 1)).await;
    let start_at = |idp: &str| format!("http://127.0.0.1:{}/api/auth/sso/{}/start?idp={}", sp.port, sp.id, url::form_urlencoded::byte_serialize(idp.as_bytes()).collect::<String>());
    let asked = || (a_ars.got.lock().unwrap().len(), b_ars.got.lock().unwrap().len());

    // B's tile: its artifact's SourceID picks B, B's resolver alone is asked, and the browser
    // restarts at B.
    let mut tile = sp.unsolicited();
    from_b(&mut tile);
    tile.name_id = "00uBOB".into();
    let b_art = artifact(IDP_B, 1);
    b_ars.held.lock().unwrap().insert(b_art.clone(), tile.xml());
    let (code, to, _) = sp.send_artifact(&b_art, "", "").await;
    assert_eq!((code, to.as_str(), asked()), (303, start_at(IDP_B).as_str(), (0, 1)));
    let restarted = &sp.audit("auth.saml_idp_initiated").await[0]["details"];
    assert_eq!((restarted["issuer"].as_str(), restarted["subject"].as_str()), (Some(IDP_B), Some("00ubob")));

    // A's tile goes to A's resolver, and restarts at A.
    let a_art = artifact(IDP, 1);
    a_ars.held.lock().unwrap().insert(a_art.clone(), sp.unsolicited().xml());
    let (code, to, _) = sp.send_artifact(&a_art, "", "").await;
    assert_eq!((code, to.as_str(), asked()), (303, start_at(IDP).as_str(), (1, 1)));

    // An artifact from an IdP the provider doesn't list is refused, and no resolver is asked.
    let (code, to, _) = sp.send_artifact(&artifact("https://idp.other.example", 1), "", "").await;
    assert_eq!((code, to.as_str(), asked()), (303, "/login?error=sso_failed", (1, 1)));
    let f = sp.last_failure().await;
    assert_eq!((f["reason"].as_str(), f["idpInitiated"].as_bool(), f["entityId"].as_str()), (Some("unknown_idp"), Some(true), None));
    assert_eq!(sp.audit("auth.saml_idp_initiated").await.len(), 2);
    std::fs::remove_dir_all(dir).ok();
}

// SCIM with several IdPs of a federation (ADR 0297)

const SCIM_USERS: &str = "/scim/v2/Users";

impl Sp {
    async fn new_token(&self, body: Value) -> (u16, String) {
        call(self.port, "POST", "/api/scim/tokens", &self.admin, &body.to_string()).await
    }

    /// Each SCIM token's id and the IdP it links.
    async fn token_idps(&self) -> HashMap<String, Value> {
        let (_, v) = call(self.port, "GET", "/api/scim/tokens", &self.admin, "").await;
        let v: Value = serde_json::from_str(&v).unwrap();
        v["tokens"].as_array().unwrap().iter().map(|t| (t["id"].as_str().unwrap().to_string(), t["ssoIdp"].clone())).collect()
    }
}

#[tokio::test]
async fn a_scim_tenant_provisions_people_at_one_idp_of_a_federation() {
    use crate::scim_http_tests::{okta_user, scim, token};
    let (sp, dir, _) = serve_federation(&[], 2).await;

    // The tenant must say which IdP's NameIDs its externalIds are, and it must be listed.
    let (code, e) = sp.new_token(json!({ "tenant": "uni-b", "sso": sp.id })).await;
    assert!(code == 400 && e.contains("--idp"), "{code} {e}");
    let (code, e) = sp.new_token(json!({ "tenant": "uni-b", "sso": sp.id, "idp": "https://idp.other.example" })).await;
    assert!(code == 400 && e.contains("not one of this provider's IdPs"), "{code} {e}");
    let (code, e) = sp.new_token(json!({ "tenant": "uni-b", "idp": IDP_B })).await;
    assert!(code == 400 && e.contains("idp needs sso"), "{code} {e}");
    let (t, first) = token(sp.port, &sp.admin, json!({ "tenant": "uni-b", "sso": sp.id, "idp": IDP_B })).await;
    let created = &sp.audit("scim.token_created").await[0]["details"];
    assert_eq!((created["sso"].as_str(), created["idp"].as_str(), created.get("idpSet")), (Some(sp.id.as_str()), Some(IDP_B), None));

    // Its other tokens link the same IdP; naming another is refused.
    let (_, second) = token(sp.port, &sp.admin, json!({ "tenant": "uni-b", "sso": sp.id })).await;
    let idps = sp.token_idps().await;
    assert_eq!((&idps[&first], &idps[&second]), (&json!(IDP_B), &json!(IDP_B)));
    let (code, e) = sp.new_token(json!({ "tenant": "uni-b", "sso": sp.id, "idp": IDP })).await;
    assert!(code == 409 && e.contains(IDP_B), "{code} {e}");

    // A person it provisions is B's NameID: signed in at B, not at A.
    let (code, _, u) = scim(sp.port, &t, "POST", SCIM_USERS, okta_user("bob@uni-b.example", NAME_ID)).await;
    assert_eq!(code, 201, "{u}");
    let bob = u["id"].as_str().unwrap().to_string();
    assert_eq!(sp.app.db.identity(IDP_B, STORED).map(|(_, u)| u.id), Some(bob.clone()));
    assert!(sp.app.db.identity(IDP, STORED).is_none());
    let linked = &sp.audit("user.identity_linked").await[0]["details"];
    assert_eq!((linked["issuer"].as_str(), linked["subject"].as_str()), (Some(IDP_B), Some(STORED)));
    let (code, _, head) = sp.sign_in_at(IDP_B, |r| {
        from_b(r);
        r.attributes[0].1 = "bob@uni-b.example".into();
    })
    .await;
    assert_eq!(code, 200, "{head}");
    assert_eq!(signed_in_as(sp.port, &head).await, Some(bob.clone()));
    let (code, to, _) = sp.sign_in_at(IDP, |_| {}).await;
    assert_eq!((code, to.as_str()), (303, "/login?error=sso_not_linked"), "the same NameID at A is someone else");

    // B vouches only for its own domains: no one at A's, made or renamed.
    let (code, head, body) = scim(sp.port, &t, "POST", SCIM_USERS, okta_user("eve@example.com", "eve-at-b")).await;
    assert_eq!(code, 400, "{body}");
    crate::scim_http_tests::is_scim_error(&head, &body, 400);
    assert_eq!(body["scimType"], "invalidValue");
    assert!(body["detail"].as_str().unwrap().contains("uni-b.example"), "{body}");
    assert!(sp.app.db.identity(IDP_B, "eve-at-b").is_none(), "nobody made");
    let to_a = json!({ "Operations": [{ "op": "Replace", "path": "emails[type eq \"work\"].value", "value": "bob@example.com" }] });
    let (code, _, body) = scim(sp.port, &t, "PATCH", &format!("{SCIM_USERS}/{bob}"), to_a).await;
    assert_eq!(code, 400, "{body}");
    assert_eq!(sp.app.db.user(&bob).unwrap().email.as_deref(), Some("bob@uni-b.example"));
    let (code, _, body) = scim(sp.port, &t, "PUT", &format!("{SCIM_USERS}/{bob}"), okta_user("bob@example.com", NAME_ID)).await;
    assert_eq!(code, 400, "{body}");

    // Deprovisioning keeps the email, so it never waits on the federation's metadata.
    let off = json!({ "Operations": [{ "op": "Replace", "path": "active", "value": "False" }] });
    assert_eq!(scim(sp.port, &t, "PATCH", &format!("{SCIM_USERS}/{bob}"), off).await.0, 200);
    assert!(!sp.app.db.user(&bob).unwrap().active());
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn a_tenant_made_before_idps_were_recorded_names_one_once_its_provider_lists_several() {
    use crate::scim_http_tests::{okta_user, scim};
    let (sp, dir, _) = serve_federation(&[], 2).await;
    let old = users::new_secret(crate::scim::TOKEN_PREFIX);
    let (made, _) = sp.app.db.create_scim_token("old", None, Some(&sp.id), None, &users::hash(&old), None, db::now() + 86_400_000, Default::default()).unwrap();

    // Without an IdP, botd can't tell whose NameID a person is, and says how to name it.
    let (code, _, body) = scim(sp.port, &old, "POST", SCIM_USERS, okta_user("bob@uni-b.example", NAME_ID)).await;
    assert_eq!(code, 500, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("botctl scim token create old"), "{body}");

    // A new token naming one names it for the tenant's older tokens too.
    let (code, res) = sp.new_token(json!({ "tenant": "old", "sso": sp.id, "idp": IDP_B })).await;
    assert_eq!(code, 201, "{res}");
    let created = &sp.audit("scim.token_created").await[0]["details"];
    assert_eq!((created["idp"].as_str(), created["idpSet"].as_bool()), (Some(IDP_B), Some(true)));
    assert_eq!(sp.token_idps().await[&made.id], json!(IDP_B));
    let (code, _, u) = scim(sp.port, &old, "POST", SCIM_USERS, okta_user("bob@uni-b.example", NAME_ID)).await;
    assert_eq!(code, 201, "{u}");
    assert_eq!(sp.app.db.identity(IDP_B, STORED).map(|(_, u)| u.id), u["id"].as_str().map(String::from));
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn a_tenant_of_a_provider_with_one_idp_records_it() {
    use crate::scim_http_tests::{okta_user, scim, token};
    let sp = serve_with(&[], |a| a.scim.enabled = true).await;
    let (t, id) = token(sp.port, &sp.admin, json!({ "tenant": "okta", "sso": sp.id })).await;
    assert_eq!(sp.token_idps().await[&id], json!(IDP), "so the link holds once the provider lists more");
    let (code, e) = sp.new_token(json!({ "tenant": "okta-2", "sso": sp.id, "idp": IDP_B })).await;
    assert!(code == 400 && e.contains("not one of this provider's IdPs"), "{code} {e}");

    // One IdP's emails aren't checked: its admin chose it, and it may publish no scope.
    let (code, _, u) = scim(sp.port, &t, "POST", SCIM_USERS, okta_user("ada@anywhere.example", NAME_ID)).await;
    assert_eq!(code, 201, "{u}");
    let ada = u["id"].as_str().unwrap().to_string();
    assert_eq!(sp.app.db.identity(IDP, STORED).map(|(_, u)| u.id), Some(ada.clone()));

    // Once the provider stops listing the tenant's IdP (B, dropped from A and B), it sets no
    // email, though one IdP is left; deprovisioning keeps the email, so it still works.
    sp.app.db.with_conn(|c| c.execute("UPDATE scim_tokens SET sso_idp = ? WHERE id = ?", [IDP_B, id.as_str()]).unwrap());
    let moved = json!({ "Operations": [{ "op": "Replace", "path": "emails[type eq \"work\"].value", "value": "ada@elsewhere.example" }] });
    let (code, _, body) = scim(sp.port, &t, "PATCH", &format!("{SCIM_USERS}/{ada}"), moved).await;
    assert_eq!(code, 500, "{body}");
    assert!(body["detail"].as_str().unwrap().contains(IDP_B), "{body}");
    assert_eq!(sp.app.db.user(&ada).unwrap().email.as_deref(), Some("ada@anywhere.example"));
    let off = json!({ "Operations": [{ "op": "Replace", "path": "active", "value": "False" }] });
    assert_eq!(scim(sp.port, &t, "PATCH", &format!("{SCIM_USERS}/{ada}"), off).await.0, 200);
    assert!(!sp.app.db.user(&ada).unwrap().active());
}

#[tokio::test]
async fn an_idps_missing_metadata_blocks_only_new_emails() {
    use crate::scim_http_tests::{okta_user, scim, token};
    // B's MDQ answer is for another entity, so B's metadata is refused and never loaded.
    let (sp, dir, _) = serve_federation_with(&[], 2, |e, md| if e == IDP_B { md.replace(&format!(r#"entityID="{IDP_B}""#), r#"entityID="https://idp.gone.example""#) } else { md }).await;
    let (t, _) = token(sp.port, &sp.admin, json!({ "tenant": "uni-b", "sso": sp.id, "idp": IDP_B })).await;

    // A new email can't be checked against B's domains: 503, and nobody is made.
    let (code, _, body) = scim(sp.port, &t, "POST", SCIM_USERS, okta_user("bob@uni-b.example", NAME_ID)).await;
    assert_eq!(code, 503, "{body}");
    assert!(sp.app.db.identity(IDP_B, STORED).is_none());

    // A person made before the outage keeps being updated and deprovisioned, but not moved.
    let bob = sp.app.db.create_user(None, Some("bob@uni-b.example"), "Bob", Role::Member).unwrap().id;
    let made = "INSERT INTO scim_users (user_id, tenant, user_name, created_at, updated_at) VALUES (?1, 'uni-b', 'bob@uni-b.example', 0, 0)";
    sp.app.db.with_conn(|c| c.execute(made, [bob.as_str()]).unwrap());
    let moved = json!({ "Operations": [{ "op": "Replace", "path": "emails[type eq \"work\"].value", "value": "bob@example.com" }] });
    let (code, _, body) = scim(sp.port, &t, "PATCH", &format!("{SCIM_USERS}/{bob}"), moved).await;
    assert_eq!(code, 503, "{body}");
    assert_eq!(sp.app.db.user(&bob).unwrap().email.as_deref(), Some("bob@uni-b.example"));
    let off = json!({ "Operations": [{ "op": "Replace", "path": "active", "value": "False" }] });
    let (code, _, body) = scim(sp.port, &t, "PATCH", &format!("{SCIM_USERS}/{bob}"), off).await;
    assert_eq!(code, 200, "{body}");
    assert!(!sp.app.db.user(&bob).unwrap().active());
    std::fs::remove_dir_all(dir).ok();
}
