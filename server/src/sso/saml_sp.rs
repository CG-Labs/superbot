//! A native SAML 2.0 service provider (ADR 0127): Web Browser SSO, SP-initiated only, an
//! HTTP-Redirect AuthnRequest out and an HTTP-POST Response back.
//!
//! What a response must be to sign anyone in, checked here in this order:
//!
//! - **Well formed, and one assertion.** No DTD, comment, or processing instruction; the root
//!   is a `samlp:Response`; exactly one `saml:Assertion` in the whole document, a direct child
//!   of it (no `EncryptedAssertion`); every `ID` in the document unique; every `ds:Signature`
//!   a direct child of the response or the assertion.
//! - **Success.** Otherwise the IdP's status is audited and nothing else is read.
//! - **Signed by the IdP.** The assertion carries a valid enveloped signature by one of the
//!   IdP's certificates (`xmldsig`). A signed response must verify too, but doesn't stand in
//!   for the assertion's. Everything below is read from that verified assertion node, so a
//!   wrapped copy elsewhere is never what's read.
//! - **For us, now, and this sign-in.** Issuer is the IdP's entity ID; the response's
//!   `Destination` (if present) and a bearer `SubjectConfirmationData`'s `Recipient` are our
//!   ACS URL; an `AudienceRestriction` names our entity ID; `NotBefore`/`NotOnOrAfter` hold
//!   (with `SKEW_MS`); the response's and the confirmation's `InResponseTo` are the ID of the
//!   AuthnRequest this browser started. Unsolicited (IdP-initiated) responses are refused.
//! - **Someone.** A NameID that isn't transient. The caller then refuses a second use of the
//!   assertion's ID, and keeps the NameID and `SessionIndex` for single logout (`saml_slo`).
//!
//! With a provider's SP key (ADR 0137), AuthnRequests can be signed with the HTTP-Redirect
//! binding's query signature, and our metadata publishes the key's certificate.

use super::jwt::Invalid;
use super::provider::Claims;
use super::xmldsig::{self, Cert, elements, is};
use crate::db::SamlLogin;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::Node;
use zeroize::Zeroizing;

pub const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
pub(super) const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
/// Allowed difference between our clock and the IdP's.
pub const SKEW_MS: i64 = 120_000;
/// The largest posted `SAMLResponse` we decode (base64 characters). Real ones are a few KB.
pub const MAX_RESPONSE: usize = 256 * 1024;
pub const MAX_METADATA: usize = 1024 * 1024;

/// Attributes IdPs commonly put the email in, tried in order when none is configured: Okta
/// and Google's `email`, LDAP's `mail`, Entra and ADFS's claim URI, and the X.500 OID.
pub const EMAIL_ATTRIBUTES: [&str; 4] = ["email", "mail", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3"];
/// The same for a display name. Entra's `.../claims/name` is the UPN, so it isn't one.
pub const NAME_ATTRIBUTES: [&str; 4] = ["displayName", "name", "http://schemas.microsoft.com/identity/claims/displayname", "urn:oid:2.16.840.1.113730.3.1.241"];

/// Which assertion attributes hold the email and name. None: the usual names above.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Attributes {
    pub email: Option<String>,
    pub name: Option<String>,
}

/// What we need from the IdP's metadata.
#[derive(Debug)]
pub struct IdpMetadata {
    pub entity_id: String,
    /// The HTTP-Redirect SingleSignOnService.
    pub sso_url: String,
    pub certs: Vec<Cert>,
    /// The HTTP-Redirect SingleLogoutService on https, if it has one: single logout is on.
    pub slo: Option<Slo>,
}

/// Where the IdP takes logout messages: requests at `location`, our responses at `response`.
#[derive(Clone, Debug, PartialEq)]
pub struct Slo {
    pub location: String,
    pub response: String,
}

/// This service provider, as the IdP knows it.
pub struct Sp<'a> {
    pub entity_id: &'a str,
    pub acs: &'a str,
}

/// What our metadata adds with an SP key: its certificate (base64 DER), our SLO URL, and
/// whether AuthnRequests are signed.
pub struct SpSigning<'a> {
    pub cert: &'a str,
    pub slo: &'a str,
    pub sign_requests: bool,
}

pub(super) fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// The IdP `entity_id` in `xml` (an `EntityDescriptor`, or one inside `EntitiesDescriptor`).
/// `signs_requests`: this provider signs its AuthnRequests (`SIGN_REQUESTS`), so an IdP that
/// wants them signed is fine. The error says what to fix, for the admin who imported it.
pub fn parse_idp_metadata(xml: &str, entity_id: &str, signs_requests: bool) -> Result<IdpMetadata, String> {
    if xml.len() > MAX_METADATA {
        return Err("the metadata is over 1 MB".into());
    }
    let opt = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 100_000, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(xml.trim_start_matches('\u{feff}'), opt).map_err(|e| format!("the metadata isn't XML SuperBot reads (no DTDs): {e}"))?;
    let entity = doc.descendants().find(|n| is(*n, METADATA, "EntityDescriptor") && n.attribute("entityID") == Some(entity_id));
    let Some(entity) = entity else {
        let found: Vec<&str> = doc.descendants().filter(|n| is(*n, METADATA, "EntityDescriptor")).filter_map(|n| n.attribute("entityID")).take(5).collect();
        return Err(if found.is_empty() { "no EntityDescriptor in the metadata".into() } else { format!("the metadata is for {}, not {entity_id}", found.join(", ")) });
    };
    let idp = elements(entity)
        .into_iter()
        .find(|n| is(*n, METADATA, "IDPSSODescriptor") && n.attribute("protocolSupportEnumeration").is_some_and(|p| p.split_ascii_whitespace().any(|p| p == PROTOCOL)))
        .ok_or("the metadata has no SAML 2.0 IDPSSODescriptor")?;
    if idp.attribute("WantAuthnRequestsSigned") == Some("true") && !signs_requests {
        return Err("the IdP wants signed AuthnRequests: set SSO_<ID>_SIGN_REQUESTS=true for this provider, or turn that off for this app at the IdP".into());
    }
    let sso_url = elements(idp)
        .into_iter()
        .find(|n| is(*n, METADATA, "SingleSignOnService") && n.attribute("Binding") == Some(REDIRECT))
        .and_then(|n| n.attribute("Location"))
        .ok_or("the metadata has no HTTP-Redirect SingleSignOnService")?
        .trim()
        .to_string();
    if !super::secure_url(&sso_url) {
        return Err(format!("the SingleSignOnService {sso_url} isn't https"));
    }
    let mut certs = Vec::new();
    for kd in elements(idp).into_iter().filter(|n| is(*n, METADATA, "KeyDescriptor") && n.attribute("use").is_none_or(|u| u == "signing")) {
        for c in kd.descendants().filter(|n| is(*n, xmldsig::DSIG, "X509Certificate")) {
            certs.push(Cert::from_base64(c.text().unwrap_or(""))?);
        }
    }
    if certs.is_empty() {
        return Err("the metadata has no signing certificate".into());
    }
    // Only over HTTP-Redirect and https; without one, sign-out stays local to SuperBot.
    let slo = elements(idp).into_iter().find(|n| is(*n, METADATA, "SingleLogoutService") && n.attribute("Binding") == Some(REDIRECT)).and_then(|n| {
        let location = n.attribute("Location")?.trim().to_string();
        let response = n.attribute("ResponseLocation").map(str::trim).filter(|r| !r.is_empty()).unwrap_or(&location).to_string();
        (super::secure_url(&location) && super::secure_url(&response)).then_some(Slo { location, response })
    });
    Ok(IdpMetadata { entity_id: entity_id.into(), sso_url, certs, slo })
}

/// Our metadata, for the IdP to import: who we are, where to post, and that assertions must
/// be signed; with an SP key, also its certificate and where to send logout messages.
pub fn sp_metadata(sp: &Sp, signing: Option<&SpSigning>) -> String {
    let signed = signing.is_some_and(|s| s.sign_requests);
    let keys = signing.map_or(String::new(), |s| {
        format!(
            r#"
    <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="{}"><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleLogoutService Binding="{REDIRECT}" Location="{slo}"/>
    <md:SingleLogoutService Binding="{POST}" Location="{slo}"/>"#,
            xmldsig::DSIG,
            s.cert,
            slo = escape(s.slo)
        )
    });
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="{METADATA}" entityID="{}">
  <md:SPSSODescriptor AuthnRequestsSigned="{signed}" WantAssertionsSigned="true" protocolSupportEnumeration="{PROTOCOL}">{keys}
    <md:NameIDFormat>{PERSISTENT}</md:NameIDFormat>
    <md:AssertionConsumerService Binding="{POST}" Location="{}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"#,
        escape(sp.entity_id),
        escape(sp.acs)
    )
}

/// botd's signing key for one native SAML provider (ADR 0137). It signs AuthnRequests and
/// logout messages; its certificate is in our metadata. RSA, which every IdP takes.
pub struct SpKey {
    pair: aws_lc_rs::rsa::KeyPair,
    /// The certificate, base64 DER, as metadata carries it.
    pub cert: String,
    pub info: Cert,
}

impl std::fmt::Debug for SpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpKey").field("sha256", &self.info.sha256).finish_non_exhaustive()
    }
}

/// How long a generated certificate is valid. IdPs keep the one they imported, and some
/// refuse an expired one, so it outlives any deployment rather than expire under it.
const SP_CERT_DAYS: i64 = 20 * 365;

impl SpKey {
    /// A new RSA-3072 key and a self-signed certificate for it, and the key as PKCS #8 to keep.
    pub fn generate(subject: &str) -> Result<(SpKey, Zeroizing<Vec<u8>>), String> {
        use aws_lc_rs::encoding::AsDer;
        let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa3072).map_err(|_| "couldn't make an RSA key")?;
        let pkcs8 = Zeroizing::new(pair.as_der().map_err(|_| "couldn't encode the RSA key")?.as_ref().to_vec());
        let signer = rcgen::KeyPair::try_from(pkcs8.as_slice()).map_err(|e| format!("the RSA key: {e}"))?;
        let now = time::OffsetDateTime::now_utc();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
        params.distinguished_name.push(rcgen::DnType::CommonName, subject);
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(SP_CERT_DAYS);
        let cert = params.self_signed(&signer).map_err(|e| format!("the SP certificate: {e}"))?;
        let key = SpKey::from_der(&pkcs8, &STANDARD.encode(cert.der()))?;
        Ok((key, pkcs8))
    }

    /// A kept key (PKCS #8 DER) and its certificate (base64 DER). They must match.
    pub fn from_der(pkcs8: &[u8], cert: &str) -> Result<SpKey, String> {
        let pair = aws_lc_rs::rsa::KeyPair::from_pkcs8(pkcs8).map_err(|_| "the SP key isn't an RSA private key (PKCS #8)")?;
        let info = Cert::from_base64(cert).map_err(|e| format!("the SP certificate: {e}"))?;
        let key = SpKey { pair, cert: cert.chars().filter(|c| !c.is_ascii_whitespace()).collect(), info };
        let probe = b"superbot sp key check";
        xmldsig::verify_raw(xmldsig::RSA_SHA256, probe, &key.sign(probe), std::slice::from_ref(&key.info)).map_err(|_| "the SP certificate isn't for the SP key".to_string())?;
        Ok(key)
    }

    /// A configured key (`SSO_<ID>_PRIVATE_KEY`, PEM) and certificate (`SP_CERT_FILE`, PEM or base64 DER).
    pub fn from_pem(key: &str, cert: &str) -> Result<SpKey, String> {
        let pair = rcgen::KeyPair::from_pem(key).map_err(|_| "the SP key isn't a PEM private key (PKCS #8, BEGIN PRIVATE KEY)")?;
        let der = Zeroizing::new(pair.serialize_der());
        SpKey::from_der(&der, &pem_body(cert))
    }

    /// RSA-SHA256 of `data` (PKCS #1 v1.5, as XML-DSig and the redirect binding use).
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut sig = vec![0; self.pair.public_modulus_len()];
        self.pair.sign(&aws_lc_rs::signature::RSA_PKCS1_SHA256, &aws_lc_rs::rand::SystemRandom::new(), data, &mut sig).expect("RSA signing");
        sig
    }
}

/// The base64 inside a PEM certificate, or the text itself when it has no PEM armour.
pub fn pem_body(pem: &str) -> String {
    let inner = match (pem.find("-----BEGIN CERTIFICATE-----"), pem.find("-----END CERTIFICATE-----")) {
        (Some(b), Some(e)) if b < e => &pem[b + "-----BEGIN CERTIFICATE-----".len()..e],
        _ => pem,
    };
    inner.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

fn form(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// The query string of an HTTP-Redirect message: `param` (`SAMLRequest` or `SAMLResponse`)
/// with `xml` DEFLATEd, RelayState, and with `key` SigAlg and a Signature over exactly those
/// bytes, in that order (SAML Bindings 3.4.4.1).
pub fn redirect_query(param: &str, xml: &str, relay: Option<&str>, key: Option<&SpKey>) -> String {
    let mut q = format!("{param}={}", form(&redirect_encode(xml)));
    if let Some(r) = relay {
        q += &format!("&RelayState={}", form(r));
    }
    if let Some(k) = key {
        q += &format!("&SigAlg={}", form(xmldsig::RSA_SHA256));
        let sig = STANDARD.encode(k.sign(q.as_bytes()));
        q += &format!("&Signature={}", form(&sig));
    }
    q
}

/// `base` with `query` after any query it has.
pub fn with_redirect_query(base: &str, query: &str) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}{query}")
}

/// A message that came over HTTP-Redirect.
#[derive(Debug)]
pub struct Redirected {
    /// `SAMLRequest` or `SAMLResponse`.
    pub param: &'static str,
    pub xml: String,
    pub relay: Option<String>,
    /// SigAlg, the signature, and the bytes it must cover, when it was signed.
    signature: Option<(String, Vec<u8>, String)>,
}

impl Redirected {
    /// Ok(false): unsigned. Err: signed, but not by one of `certs` with an algorithm we take.
    pub fn verify(&self, certs: &[Cert]) -> Result<bool, Refused> {
        match &self.signature {
            None => Ok(false),
            Some((alg, sig, signed)) => xmldsig::verify_raw(alg, signed.as_bytes(), sig, certs).map(|_| true).map_err(Refused::from),
        }
    }
}

/// Reads an HTTP-Redirect message from the raw query string. The signature covers the
/// parameters as they were encoded, so they are taken raw; each may appear only once.
pub fn from_redirect(raw: &str) -> Result<Redirected, Refused> {
    let bad = || Refused("bad_message", None);
    if raw.len() > MAX_RESPONSE {
        return Err(bad());
    }
    let mut found: Vec<(&'static str, &str, String)> = Vec::new();
    for part in raw.split('&').filter(|p| !p.is_empty()) {
        let Some((k, v)) = url::form_urlencoded::parse(part.as_bytes()).next() else { continue };
        let Some(name) = ["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"].into_iter().find(|n| *n == k) else { continue };
        if found.iter().any(|(n, ..)| *n == name) {
            return Err(bad());
        }
        let raw_value = part.split_once('=').map_or("", |(_, v)| v);
        found.push((name, raw_value, v.into_owned()));
    }
    let get = |n: &str| found.iter().find(|(f, ..)| *f == n);
    let (param, raw_message, message) = match (get("SAMLRequest"), get("SAMLResponse")) {
        (Some(m), None) | (None, Some(m)) => m.clone(),
        _ => return Err(bad()),
    };
    // A `+` a sender left unencoded reads as a space; base64 has no spaces.
    let deflated = STANDARD.decode(message.replace(' ', "+")).map_err(|_| bad())?;
    let inflated = miniz_oxide::inflate::decompress_to_vec_with_limit(&deflated, MAX_RESPONSE).map_err(|_| bad())?;
    let xml = String::from_utf8(inflated).map_err(|_| bad())?;
    let relay = get("RelayState").map(|r| r.2.clone());
    let signature = match (get("SigAlg"), get("Signature")) {
        (None, None) => None,
        (Some((_, raw_alg, alg)), Some((.., sig))) => {
            let sig = STANDARD.decode(sig.replace(' ', "+")).map_err(|_| Refused("bad_signature", None))?;
            let mut signed = format!("{param}={raw_message}");
            if let Some((_, raw_relay, _)) = get("RelayState") {
                signed += &format!("&RelayState={raw_relay}");
            }
            signed += &format!("&SigAlg={raw_alg}");
            Some((alg.clone(), sig, signed))
        }
        _ => return Err(Refused("bad_signature", None)),
    };
    Ok(Redirected { param, xml, relay, signature })
}

pub(super) fn instant(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// A new AuthnRequest ID: an NCName, so it starts with `_`.
pub fn request_id() -> String {
    format!("_{}", crate::random_hex(20))
}

/// The AuthnRequest XML. The NameID format is left to the IdP's settings for the app.
pub fn authn_request(sp: &Sp, id: &str, destination: &str, now_ms: i64) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="{POST}"><saml:Issuer>{}</saml:Issuer><samlp:NameIDPolicy AllowCreate="true"/></samlp:AuthnRequest>"#,
        instant(now_ms),
        escape(destination),
        escape(sp.acs),
        escape(sp.entity_id)
    )
}

/// The `SAMLRequest` parameter of the HTTP-Redirect binding: DEFLATE, then base64.
pub fn redirect_encode(xml: &str) -> String {
    STANDARD.encode(miniz_oxide::deflate::compress_to_vec(xml.as_bytes(), 6))
}

/// A response refused: the audit reason, and the IdP's status codes when it said no.
#[derive(Debug, PartialEq)]
pub struct Refused(pub &'static str, pub Option<String>);

impl From<Invalid> for Refused {
    fn from(e: Invalid) -> Refused {
        Refused(e.0, None)
    }
}

/// What a response must match.
pub struct Expect<'a> {
    pub sp: Sp<'a>,
    pub idp: &'a IdpMetadata,
    /// The ID of the AuthnRequest this browser's sign-in sent.
    pub request_id: &'a str,
    pub attributes: &'a Attributes,
    pub now_ms: i64,
}

/// A response that passed: who, and the assertion's ID and how long it must be remembered
/// to refuse it a second time.
#[derive(Debug)]
pub struct Checked {
    pub claims: Claims,
    pub assertion_id: String,
    pub until_ms: i64,
    /// The NameID as sent and the IdP's session, for single logout.
    pub login: SamlLogin,
}

pub(super) fn time(s: &str) -> Result<i64, Refused> {
    chrono::DateTime::parse_from_rfc3339(s.trim()).map(|t| t.timestamp_millis()).map_err(|_| Refused("bad_response", None))
}

/// The one child `{ns}name` of `n`, if there is exactly one.
pub(super) fn only<'a, 'i>(n: Node<'a, 'i>, ns: &str, name: &str) -> Option<Node<'a, 'i>> {
    let mut it = n.children().filter(|c| is(*c, ns, name));
    let first = it.next()?;
    it.next().is_none().then_some(first)
}

/// The text of an element with only text in it.
pub(super) fn text_of<'a>(n: Node<'a, '_>) -> Option<&'a str> {
    if n.children().any(|c| !c.is_text()) {
        return None;
    }
    Some(n.text().unwrap_or(""))
}

/// An optional attribute kept for later, if it's short enough to be real.
fn kept(n: Node, name: &str) -> Option<String> {
    n.attribute(name).filter(|v| !v.is_empty() && v.len() <= 1024).map(String::from)
}

pub(super) fn issuer_is(n: Node, entity_id: &str) -> bool {
    only(n, ASSERTION, "Issuer").and_then(text_of).is_some_and(|i| i.trim() == entity_id)
}

/// The first value of the first attribute in `names` the assertion has.
fn attribute<'a>(assertion: Node<'a, '_>, names: &[&str]) -> Option<&'a str> {
    let attrs: Vec<Node> = assertion.children().filter(|c| is(*c, ASSERTION, "AttributeStatement")).flat_map(|s| s.children().filter(|c| is(*c, ASSERTION, "Attribute"))).collect();
    names.iter().find_map(|name| {
        let a = attrs.iter().find(|a| a.attribute("Name") == Some(*name))?;
        a.children().find(|c| is(*c, ASSERTION, "AttributeValue")).and_then(text_of).map(str::trim).filter(|v| !v.is_empty())
    })
}

/// Checks the base64 `SAMLResponse` an IdP posted, as the module docs list.
pub fn check_response(posted: &str, e: &Expect) -> Result<Checked, Refused> {
    let bad = || Refused("bad_response", None);
    if posted.len() > MAX_RESPONSE {
        return Err(bad());
    }
    let bytes = xmldsig::base64(posted).ok_or_else(bad)?;
    let xml = String::from_utf8(bytes).map_err(|_| bad())?;
    let doc = xmldsig::parse(&xml)?;
    let response = doc.root_element();
    if !is(response, PROTOCOL, "Response") || response.attribute("Version") != Some("2.0") {
        return Err(bad());
    }

    // A failed response usually carries no assertion. Its status is unsigned, but it only ever
    // leads to a refusal, so reading it first is safe and keeps the IdP's reason.
    let status = only(response, PROTOCOL, "Status").and_then(|s| only(s, PROTOCOL, "StatusCode")).ok_or_else(bad)?;
    if status.attribute("Value") != Some(SUCCESS) {
        let codes: Vec<&str> = std::iter::successors(Some(status), |c| only(*c, PROTOCOL, "StatusCode")).filter_map(|c| c.attribute("Value")).map(|v| v.rsplit(':').next().unwrap_or(v)).collect();
        return Err(Refused("idp_error", Some(crate::audit::clip(&codes.join("/"), 128))));
    }

    // Structure first, so nothing below can be pointed at a copy.
    let assertions: Vec<Node> = doc.descendants().filter(|n| n.is_element() && matches!(n.tag_name().name(), "Assertion" | "EncryptedAssertion")).collect();
    let assertion = match assertions.as_slice() {
        [a] if is(*a, ASSERTION, "Assertion") && a.parent() == Some(response) => *a,
        [a] if a.tag_name().name() == "EncryptedAssertion" => {
            return Err(Refused("encrypted_assertion", None));
        }
        [] => return Err(Refused("missing_assertion", None)),
        _ => return Err(Refused("wrapped", None)),
    };
    let mut ids: Vec<&str> = doc.descendants().flat_map(|n| n.attributes()).filter(|a| a.namespace().is_none() && a.name().eq_ignore_ascii_case("id")).map(|a| a.value()).collect();
    let all = ids.len();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != all {
        return Err(Refused("wrapped", None));
    }
    if doc.descendants().filter(|n| is(*n, xmldsig::DSIG, "Signature")).any(|s| s.parent() != Some(response) && s.parent() != Some(assertion)) {
        return Err(Refused("wrapped", None));
    }

    if !xmldsig::verify_enveloped(assertion, &e.idp.certs)? {
        return Err(Refused("unsigned", None));
    }
    xmldsig::verify_enveloped(response, &e.idp.certs)?;

    // From here on, only the verified assertion (and the response that holds it).
    let (now, earliest, latest) = (e.now_ms, e.now_ms - SKEW_MS, e.now_ms + SKEW_MS);
    if response.attribute("Destination").is_some_and(|d| d != e.sp.acs) {
        return Err(Refused("wrong_destination", None));
    }
    if response.children().any(|c| is(c, ASSERTION, "Issuer")) && !issuer_is(response, &e.idp.entity_id) {
        return Err(Refused("wrong_issuer", None));
    }
    if response.attribute("InResponseTo") != Some(e.request_id) {
        return Err(Refused("in_response_to_mismatch", None));
    }
    if assertion.attribute("Version") != Some("2.0") {
        return Err(bad());
    }
    if !issuer_is(assertion, &e.idp.entity_id) {
        return Err(Refused("wrong_issuer", None));
    }
    let assertion_id = assertion.attribute("ID").ok_or_else(bad)?.to_string();

    let conditions = only(assertion, ASSERTION, "Conditions").ok_or(Refused("wrong_audience", None))?;
    let mut until = i64::MAX;
    if let Some(nb) = conditions.attribute("NotBefore")
        && time(nb)? > latest
    {
        return Err(Refused("not_yet_valid", None));
    }
    if let Some(na) = conditions.attribute("NotOnOrAfter") {
        let na = time(na)?;
        if na <= earliest {
            return Err(Refused("expired", None));
        }
        until = until.min(na);
    }
    let restrictions: Vec<Node> = conditions.children().filter(|c| is(*c, ASSERTION, "AudienceRestriction")).collect();
    let ours = |r: &Node| r.children().filter(|c| is(*c, ASSERTION, "Audience")).filter_map(text_of).any(|a| a.trim() == e.sp.entity_id);
    if restrictions.is_empty() || !restrictions.iter().all(ours) {
        return Err(Refused("wrong_audience", None));
    }

    let subject = only(assertion, ASSERTION, "Subject").ok_or(Refused("missing_subject", None))?;
    // A bearer confirmation must hold in full; the first one's failure is the reason given.
    let confirm = |c: Node| -> Result<i64, Refused> {
        let d = only(c, ASSERTION, "SubjectConfirmationData").ok_or_else(bad)?;
        if d.attribute("Recipient") != Some(e.sp.acs) {
            return Err(Refused("wrong_recipient", None));
        }
        let na = time(d.attribute("NotOnOrAfter").ok_or(Refused("expired", None))?)?;
        if na <= earliest {
            return Err(Refused("expired", None));
        }
        if let Some(nb) = d.attribute("NotBefore")
            && time(nb)? > latest
        {
            return Err(Refused("not_yet_valid", None));
        }
        if d.attribute("InResponseTo") != Some(e.request_id) {
            return Err(Refused("in_response_to_mismatch", None));
        }
        Ok(na)
    };
    let bearers: Vec<Node> = subject.children().filter(|c| is(*c, ASSERTION, "SubjectConfirmation") && c.attribute("Method") == Some(BEARER)).collect();
    let mut first_error = None;
    let mut confirmed = None;
    for b in bearers {
        match confirm(b) {
            Ok(na) => {
                confirmed = Some(na);
                break;
            }
            Err(r) => {
                first_error.get_or_insert(r);
            }
        }
    }
    let Some(confirmed) = confirmed else {
        return Err(first_error.unwrap_or_else(bad));
    };
    until = until.min(confirmed);
    let Some(authn) = assertion.children().find(|c| is(*c, ASSERTION, "AuthnStatement")) else {
        return Err(bad());
    };

    let name_id = only(subject, ASSERTION, "NameID").ok_or(Refused("missing_subject", None))?;
    if name_id.attribute("Format") == Some(TRANSIENT) {
        return Err(Refused("transient_subject", None));
    }
    let raw = text_of(name_id).ok_or(Refused("missing_subject", None))?;
    if raw.is_empty() || raw.len() > 255 || raw.trim() != raw {
        return Err(Refused("missing_subject", None));
    }
    let pick = |set: &Option<String>, defaults: &[&str]| match set {
        Some(n) => attribute(assertion, &[n.as_str()]),
        None => attribute(assertion, defaults),
    };
    let email = pick(&e.attributes.email, &EMAIL_ATTRIBUTES).filter(|m| m.len() <= 254 && crate::users::valid_email(m)).map(String::from);
    let name = pick(&e.attributes.name, &NAME_ATTRIBUTES).map(|n| crate::audit::clip(n, 100));
    let claims = Claims { issuer: e.idp.entity_id.clone(), subject: super::saml::subject(raw), tenant: None, email, name, username: None };
    let login = SamlLogin {
        name_id: raw.to_string(),
        format: kept(name_id, "Format"),
        name_qualifier: kept(name_id, "NameQualifier"),
        sp_name_qualifier: kept(name_id, "SPNameQualifier"),
        session_index: kept(authn, "SessionIndex"),
    };
    Ok(Checked { claims, assertion_id, until_ms: until.min(now + 24 * 3600 * 1000), login })
}

#[cfg(test)]
pub mod test_idp {
    //! A SAML IdP for tests: metadata, and signed responses with any part changed.

    use super::*;
    use crate::sso::xmldsig::test_signer::{Signer, signers};

    pub const IDP: &str = "https://idp.example/saml";
    pub const SSO_URL: &str = "https://idp.example/saml/sso";

    pub fn metadata_with(entity: &str, certs: &[&Signer], extra: &str) -> String {
        let keys: String = certs
            .iter()
            .map(|s| format!(r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#, s.cert))
            .collect();
        format!(
            r#"<?xml version="1.0"?><md:EntityDescriptor xmlns:md="{METADATA}" xmlns:ds="{}" entityID="{entity}"><md:IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL}"{extra}>{keys}<md:NameIDFormat>{PERSISTENT}</md:NameIDFormat><md:SingleSignOnService Binding="{POST}" Location="{SSO_URL}/post"/><md:SingleSignOnService Binding="{REDIRECT}" Location="{SSO_URL}"/></md:IDPSSODescriptor></md:EntityDescriptor>"#,
            xmldsig::DSIG
        )
    }

    pub fn metadata() -> String {
        metadata_with(IDP, &[&signers()[0]], "")
    }

    pub const SLO_URL: &str = "https://idp.example/saml/slo";

    /// `xml` with an HTTP-Redirect SingleLogoutService added.
    pub fn with_slo(xml: &str) -> String {
        xml.replacen("<md:NameIDFormat>", &format!(r#"<md:SingleLogoutService Binding="{REDIRECT}" Location="{SLO_URL}"/><md:NameIDFormat>"#), 1)
    }

    /// The parts of a response, each one replaceable before it is signed.
    #[derive(Clone)]
    pub struct Response {
        pub id: String,
        pub assertion_id: String,
        pub destination: Option<String>,
        pub in_response_to: String,
        pub confirm_in_response_to: String,
        pub issuer: String,
        pub recipient: String,
        pub audience: String,
        pub not_before: i64,
        pub not_on_or_after: i64,
        pub confirm_not_on_or_after: i64,
        pub name_id: String,
        pub name_id_format: String,
        pub status: String,
        pub session_index: String,
        pub attributes: Vec<(String, String)>,
        /// More inside Conditions, before signing.
        pub conditions_extra: String,
        /// Sign the assertion, the response, either, or both.
        pub sign_assertion: bool,
        pub sign_response: bool,
        pub signer: usize,
    }

    impl Response {
        pub fn new(acs: &str, sp_entity: &str, request_id: &str, now_ms: i64) -> Response {
            Response {
                id: format!("_r{}", crate::random_hex(8)),
                assertion_id: format!("_a{}", crate::random_hex(8)),
                destination: Some(acs.into()),
                in_response_to: request_id.into(),
                confirm_in_response_to: request_id.into(),
                issuer: IDP.into(),
                recipient: acs.into(),
                audience: sp_entity.into(),
                not_before: now_ms - 60_000,
                not_on_or_after: now_ms + 300_000,
                confirm_not_on_or_after: now_ms + 300_000,
                name_id: "00u1ADA-Persistent".into(),
                name_id_format: PERSISTENT.into(),
                status: SUCCESS.into(),
                session_index: format!("_s{}", crate::random_hex(8)),
                attributes: vec![("email".into(), "ada@example.com".into()), ("displayName".into(), "Ada Lovelace".into())],
                conditions_extra: String::new(),
                sign_assertion: true,
                sign_response: false,
                signer: 0,
            }
        }

        pub fn assertion(&self) -> String {
            let attrs: String =
                self.attributes.iter().map(|(k, v)| format!(r#"<saml:Attribute Name="{k}"><saml:AttributeValue xsi:type="xs:string">{v}</saml:AttributeValue></saml:Attribute>"#)).collect();
            format!(
                r#"<saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{now}"><saml:Issuer>{iss}</saml:Issuer><saml:Subject><saml:NameID Format="{fmt}">{nid}</saml:NameID><saml:SubjectConfirmation Method="{BEARER}"><saml:SubjectConfirmationData InResponseTo="{cirt}" NotOnOrAfter="{cna}" Recipient="{rcp}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction>{extra}</saml:Conditions><saml:AuthnStatement AuthnInstant="{now}" SessionIndex="{si}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>{attrs}</saml:AttributeStatement></saml:Assertion>"#,
                aid = self.assertion_id,
                now = instant(self.not_before + 60_000),
                iss = self.issuer,
                fmt = self.name_id_format,
                nid = self.name_id,
                cirt = self.confirm_in_response_to,
                cna = instant(self.confirm_not_on_or_after),
                rcp = self.recipient,
                nb = instant(self.not_before),
                na = instant(self.not_on_or_after),
                aud = self.audience,
                extra = self.conditions_extra,
                si = self.session_index,
            )
        }

        /// The response XML, signed as asked, with `edit` applied to the assertion first.
        pub fn xml_with(&self, edit: impl Fn(String) -> String) -> String {
            let signer = &signers()[self.signer];
            let mut assertion = self.assertion();
            if self.sign_assertion {
                // Signed in its own document, with the namespaces it will have in place.
                let alone = assertion.replacen(
                    "<saml:Assertion ",
                    &format!(r#"<saml:Assertion xmlns:saml="{ASSERTION}" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" "#),
                    1,
                );
                let signed = signer.sign(&alone, &self.assertion_id);
                assertion = signed.replacen(&format!(r#" xmlns:saml="{ASSERTION}" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance""#), "", 1);
            }
            let assertion = edit(assertion);
            let dest = self.destination.as_ref().map(|d| format!(r#" Destination="{d}""#)).unwrap_or_default();
            let xml = format!(
                r#"<samlp:Response xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="{}" Version="2.0" IssueInstant="{}"{dest} InResponseTo="{}"><saml:Issuer>{}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status>{assertion}</samlp:Response>"#,
                self.id,
                instant(self.not_before + 60_000),
                self.in_response_to,
                self.issuer,
                self.status
            );
            if self.sign_response { signer.sign(&xml, &self.id) } else { xml }
        }

        pub fn xml(&self) -> String {
            self.xml_with(|a| a)
        }

        /// What the browser posts.
        pub fn posted(&self) -> String {
            STANDARD.encode(self.xml())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_idp::*;
    use super::*;
    use crate::sso::xmldsig::test_signer::signers;

    const ACS: &str = "https://bot.example.com/api/auth/sso/okta/acs";
    const SP: &str = "https://bot.example.com/api/auth/sso/okta/metadata";
    const REQ: &str = "_0123456789abcdef";
    const NOW: i64 = 1_800_000_000_000;

    fn idp() -> IdpMetadata {
        parse_idp_metadata(&metadata(), IDP, false).unwrap()
    }

    fn base() -> Response {
        Response::new(ACS, SP, REQ, NOW)
    }

    fn check_at(xml: &str, now_ms: i64) -> Result<Checked, Refused> {
        let idp = idp();
        let attributes = Attributes::default();
        check_response(&STANDARD.encode(xml), &Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp, request_id: REQ, attributes: &attributes, now_ms })
    }

    fn check(xml: &str) -> Result<Checked, Refused> {
        check_at(xml, NOW)
    }

    fn reason(r: Response) -> &'static str {
        check(&r.xml()).err().map_or("ok", |e| e.0)
    }

    #[test]
    fn reads_idp_metadata_and_says_what_is_wrong_with_it() {
        let m = idp();
        assert_eq!((m.entity_id.as_str(), m.sso_url.as_str(), m.certs.len()), (IDP, SSO_URL, 1), "the redirect binding, not the post one");
        let [a, b] = signers();
        assert_eq!(parse_idp_metadata(&metadata_with(IDP, &[a, b], ""), IDP, false).unwrap().certs.len(), 2, "rollover: both certificates");
        let wrapped = format!(
            r#"<md:EntitiesDescriptor xmlns:md="{METADATA}">{}</md:EntitiesDescriptor>"#,
            metadata_with("https://other.example", &[b], "").replace(r#"<?xml version="1.0"?>"#, "") + &metadata().replace(r#"<?xml version="1.0"?>"#, "")
        );
        assert_eq!(parse_idp_metadata(&wrapped, IDP, false).unwrap().certs[0].sha256, a.cert().sha256, "picked by entity ID from an aggregate");
        for (xml, want) in [
            (metadata_with(IDP, &[], ""), "no signing certificate"),
            (metadata_with(IDP, &[a], r#" WantAuthnRequestsSigned="true""#), "signed AuthnRequests"),
            (metadata().replace(&format!(r#"Binding="{REDIRECT}""#), r#"Binding="urn:x""#), "no HTTP-Redirect"),
            (metadata().replace(SSO_URL, "http://idp.example/sso"), "isn't https"),
            (metadata().replace(PROTOCOL, "urn:oasis:names:tc:SAML:1.1:protocol"), "no SAML 2.0"),
            (format!(r#"<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>{}"#, metadata().replace(r#"<?xml version="1.0"?>"#, "")), "no DTDs"),
            ("<html/>".into(), "no EntityDescriptor"),
        ] {
            let err = parse_idp_metadata(&xml, IDP, false).unwrap_err();
            assert!(err.contains(want), "{want}: {err}");
        }
        assert!(parse_idp_metadata(&metadata(), "https://elsewhere.example", false).unwrap_err().contains(IDP), "names the entity it found");

        let wants = metadata_with(IDP, &[a], r#" WantAuthnRequestsSigned="true""#);
        assert!(parse_idp_metadata(&wants, IDP, false).unwrap_err().contains("SIGN_REQUESTS"), "says how to turn signing on");
        assert!(parse_idp_metadata(&wants, IDP, true).is_ok(), "a provider that signs its requests takes it");
        assert_eq!(idp().slo, None, "no SingleLogoutService: sign-out stays local");
        let slo = parse_idp_metadata(&with_slo(&metadata()), IDP, false).unwrap().slo.unwrap();
        assert_eq!((slo.location.as_str(), slo.response.as_str()), (SLO_URL, SLO_URL), "responses go to Location without a ResponseLocation");
        let split = with_slo(&metadata()).replace(&format!(r#"Location="{SLO_URL}""#), &format!(r#"Location="{SLO_URL}" ResponseLocation="{SLO_URL}/done""#));
        assert_eq!(parse_idp_metadata(&split, IDP, false).unwrap().slo.unwrap().response, format!("{SLO_URL}/done"));
        assert_eq!(parse_idp_metadata(&with_slo(&metadata()).replace(SLO_URL, "http://idp.example/slo"), IDP, false).unwrap().slo, None, "not over plain http");
        let post_only = with_slo(&metadata()).replacen(&format!(r#"Binding="{REDIRECT}" Location="{SLO_URL}""#), &format!(r#"Binding="{POST}" Location="{SLO_URL}""#), 1);
        assert_eq!(parse_idp_metadata(&post_only, IDP, false).unwrap().slo, None, "only the redirect binding is sent to");
    }

    #[test]
    fn sp_keys_are_rsa_and_match_their_certificate() {
        let (key, pkcs8) = SpKey::generate("SuperBot okta").unwrap();
        assert_eq!(key.pair.public_modulus_len(), 384, "RSA-3072");
        assert!(key.info.subject.contains("SuperBot okta"));
        assert!(key.info.not_after > chrono::Utc::now().timestamp() + 19 * 365 * 86_400);
        let again = SpKey::from_der(&pkcs8, &key.cert).unwrap();
        assert_eq!(again.info.sha256, key.info.sha256, "the kept key and certificate load back");
        let (other, other_pkcs8) = SpKey::generate("other").unwrap();
        assert!(SpKey::from_der(&other_pkcs8, &key.cert).unwrap_err().contains("isn't for the SP key"));
        assert!(SpKey::from_der(b"nope", &key.cert).is_err());

        let pem = |label: &str, der: &[u8]| format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", STANDARD.encode(der));
        let from_pem = SpKey::from_pem(&pem("PRIVATE KEY", &pkcs8), &pem("CERTIFICATE", &STANDARD.decode(&key.cert).unwrap())).unwrap();
        assert_eq!(from_pem.info.sha256, key.info.sha256, "a configured PEM key and certificate");
        assert_eq!(SpKey::from_pem(&pem("PRIVATE KEY", &pkcs8), &key.cert).unwrap().cert, key.cert, "or the certificate as base64");
        assert!(SpKey::from_pem("not pem", &key.cert).is_err());
        assert!(SpKey::from_pem(&pem("PRIVATE KEY", &pkcs8), &other.cert).is_err());
        let ec = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        assert!(SpKey::from_pem(&ec.serialize_pem(), &key.cert).unwrap_err().contains("RSA"), "ECDSA keys aren't taken yet");
    }

    #[test]
    fn redirect_messages_are_signed_over_the_query_as_sent() {
        let (key, _) = SpKey::generate("sp").unwrap();
        let xml = authn_request(&Sp { entity_id: SP, acs: ACS }, REQ, SSO_URL, NOW);
        let q = redirect_query("SAMLRequest", &xml, Some("state+/="), Some(&key));
        let names: Vec<&str> = q.split('&').map(|p| p.split('=').next().unwrap()).collect();
        assert_eq!(names, ["SAMLRequest", "RelayState", "SigAlg", "Signature"], "in the order the binding signs them");
        let r = from_redirect(&q).unwrap();
        assert_eq!((r.param, r.xml.as_str(), r.relay.as_deref()), ("SAMLRequest", xml.as_str(), Some("state+/=")));
        assert_eq!(r.verify(std::slice::from_ref(&key.info)), Ok(true));
        assert_eq!(r.verify(&[signers()[0].cert()]), Err(Refused("bad_signature", None)), "someone else's key");
        let unsigned = from_redirect(&redirect_query("SAMLRequest", &xml, None, None)).unwrap();
        assert_eq!(unsigned.verify(std::slice::from_ref(&key.info)), Ok(false));

        // Anything changed after signing breaks it: the message, RelayState, or SigAlg.
        let other = redirect_query("SAMLRequest", &xml.replace(REQ, "_other"), Some("state+/="), None);
        let swapped = format!("{}&{}", other.split('&').next().unwrap(), q.split_once('&').unwrap().1);
        assert_eq!(from_redirect(&swapped).unwrap().verify(std::slice::from_ref(&key.info)), Err(Refused("bad_signature", None)));
        let relay = q.replacen("RelayState=state", "RelayState=other", 1);
        assert_eq!(from_redirect(&relay).unwrap().verify(std::slice::from_ref(&key.info)), Err(Refused("bad_signature", None)));
        let dropped = q.split('&').filter(|p| !p.starts_with("RelayState=")).collect::<Vec<_>>().join("&");
        assert_eq!(from_redirect(&dropped).unwrap().verify(std::slice::from_ref(&key.info)), Err(Refused("bad_signature", None)));
        let sha1 = q.replacen(&form(xmldsig::RSA_SHA256), &form("http://www.w3.org/2000/09/xmldsig#rsa-sha1"), 1);
        assert_eq!(from_redirect(&sha1).unwrap().verify(std::slice::from_ref(&key.info)), Err(Refused("weak_algorithm", None)));

        for bad in [
            format!("{q}&SAMLRequest=x"),
            format!("{q}&RelayState=again"),
            q.split('&').filter(|p| !p.starts_with("SigAlg=")).collect::<Vec<_>>().join("&"),
            "RelayState=x".to_string(),
            "SAMLRequest=bm90IGRlZmxhdGVk".to_string(),
            format!("SAMLRequest=a&SAMLResponse=b"),
        ] {
            assert!(from_redirect(&bad).is_err(), "{bad}");
        }
        assert_eq!(with_redirect_query("https://idp.example/sso", "a=1"), "https://idp.example/sso?a=1");
        assert_eq!(with_redirect_query("https://idp.example/sso?app=2", "a=1"), "https://idp.example/sso?app=2&a=1");
    }

    #[test]
    fn sp_metadata_with_a_key_publishes_it_and_the_slo_url() {
        let sp = Sp { entity_id: SP, acs: ACS };
        let (key, _) = SpKey::generate("sp").unwrap();
        let slo = "https://bot.example.com/api/auth/sso/okta/slo";
        for sign_requests in [false, true] {
            let md = sp_metadata(&sp, Some(&SpSigning { cert: &key.cert, slo, sign_requests }));
            let doc = roxmltree::Document::parse(&md).unwrap();
            let spsso = doc.descendants().find(|n| is(*n, METADATA, "SPSSODescriptor")).unwrap();
            assert_eq!(spsso.attribute("AuthnRequestsSigned"), Some(if sign_requests { "true" } else { "false" }));
            let cert = doc.descendants().find(|n| is(*n, xmldsig::DSIG, "X509Certificate")).and_then(|n| n.text());
            assert_eq!(cert, Some(key.cert.as_str()));
            let slos: Vec<_> = doc.descendants().filter(|n| is(*n, METADATA, "SingleLogoutService")).map(|n| (n.attribute("Binding").unwrap(), n.attribute("Location").unwrap())).collect();
            assert_eq!(slos, [(REDIRECT, slo), (POST, slo)]);
            let order: Vec<&str> = elements(spsso).iter().map(|n| n.tag_name().name()).collect();
            assert_eq!(order, ["KeyDescriptor", "SingleLogoutService", "SingleLogoutService", "NameIDFormat", "AssertionConsumerService"], "schema order");
        }
        assert!(!sp_metadata(&sp, None).contains("SingleLogoutService"), "no key, no logout");
    }

    #[test]
    fn writes_sp_metadata_and_a_redirect_authn_request() {
        let sp = Sp { entity_id: SP, acs: ACS };
        let md = sp_metadata(&sp, None);
        let doc = roxmltree::Document::parse(&md).unwrap();
        let root = doc.root_element();
        assert_eq!(root.attribute("entityID"), Some(SP));
        let acs = doc.descendants().find(|n| n.tag_name().name() == "AssertionConsumerService").unwrap();
        assert_eq!((acs.attribute("Binding"), acs.attribute("Location")), (Some(POST), Some(ACS)));
        assert!(md.contains(r#"WantAssertionsSigned="true""#));

        let id = request_id();
        assert!(id.starts_with('_') && id.len() == 41);
        let xml = authn_request(&sp, &id, SSO_URL, NOW);
        let encoded = redirect_encode(&xml);
        let inflated = miniz_oxide::inflate::decompress_to_vec(&STANDARD.decode(encoded).unwrap()).unwrap();
        assert_eq!(String::from_utf8(inflated).unwrap(), xml, "raw DEFLATE, as the binding says");
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let r = doc.root_element();
        assert!(is(r, PROTOCOL, "AuthnRequest"));
        assert_eq!(
            (r.attribute("ID"), r.attribute("Destination"), r.attribute("AssertionConsumerServiceURL"), r.attribute("ProtocolBinding")),
            (Some(id.as_str()), Some(SSO_URL), Some(ACS), Some(POST))
        );
        assert_eq!(r.attribute("IssueInstant"), Some("2027-01-15T08:00:00Z"));
        assert_eq!(doc.descendants().find(|n| is(*n, ASSERTION, "Issuer")).and_then(|n| n.text()), Some(SP));
        let odd = authn_request(&Sp { entity_id: "urn:a&b<c>", acs: ACS }, &id, SSO_URL, NOW);
        assert!(roxmltree::Document::parse(&odd).is_ok(), "escaped");
    }

    #[test]
    fn a_good_response_names_the_person_under_the_idp() {
        let r = base();
        let c = check(&r.xml()).unwrap();
        assert_eq!((c.claims.issuer.as_str(), c.claims.subject.as_str()), (IDP, "00u1ada-persistent"), "lowercased, as the bridge stored it");
        assert_eq!((c.claims.email.as_deref(), c.claims.name.as_deref(), c.claims.tenant.as_deref()), (Some("ada@example.com"), Some("Ada Lovelace"), None));
        assert_eq!(c.assertion_id, r.assertion_id);
        assert_eq!(c.until_ms, NOW + 300_000);
        assert_eq!(
            c.login,
            SamlLogin { name_id: "00u1ADA-Persistent".into(), format: Some(PERSISTENT.into()), name_qualifier: None, sp_name_qualifier: None, session_index: Some(r.session_index.clone()) },
            "the NameID as sent and the IdP's session, for single logout"
        );
        let mut both = base();
        both.sign_response = true;
        assert!(check(&both.xml()).is_ok(), "response and assertion signed");
        let mut entra = base();
        entra.attributes = vec![
            ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".into(), "ada@contoso.example".into()),
            ("http://schemas.microsoft.com/identity/claims/displayname".into(), "Ada".into()),
        ];
        let c = check(&entra.xml()).unwrap();
        assert_eq!((c.claims.email.as_deref(), c.claims.name.as_deref()), (Some("ada@contoso.example"), Some("Ada")));
        let mut no_attrs = base();
        no_attrs.attributes.clear();
        assert_eq!(check(&no_attrs.xml()).unwrap().claims.email, None);
        let idp = idp();
        let mapped = Attributes { email: Some("work_mail".into()), name: None };
        let mut custom = base();
        custom.attributes = vec![("email".into(), "personal@evil.example".into()), ("work_mail".into(), "ada@example.com".into())];
        let c = check_response(&STANDARD.encode(custom.xml()), &Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp, request_id: REQ, attributes: &mapped, now_ms: NOW }).unwrap();
        assert_eq!(c.claims.email.as_deref(), Some("ada@example.com"), "only the configured attribute");
        let mut unspecified = base();
        unspecified.name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".into();
        assert!(check(&unspecified.xml()).is_ok());
    }

    #[test]
    fn unsigned_or_badly_signed_responses_are_refused() {
        let mut r = base();
        r.sign_assertion = false;
        assert_eq!(reason(r.clone()), "unsigned");
        r.sign_response = true;
        assert_eq!(reason(r), "unsigned", "a signed response doesn't stand in for the assertion's signature");
        let mut other = base();
        other.signer = 1;
        assert_eq!(reason(other), "bad_signature", "signed, but not by the IdP");
        let good = base();
        assert_eq!(check(&good.xml_with(|a| a.replace("00u1ADA-Persistent", "00u1EVE-Persistent"))).unwrap_err().0, "bad_signature", "NameID changed after signing");
        assert_eq!(check(&good.xml_with(|a| a.replace("ada@example.com", "eve@example.com"))).unwrap_err().0, "bad_signature");
        let mut bad_resp = base();
        bad_resp.sign_response = true;
        let xml = bad_resp.xml().replacen(&format!("InResponseTo=\"{REQ}\""), &format!("InResponseTo=\"{REQ}\" Consent=\"x\""), 1);
        assert_eq!(check(&xml).unwrap_err().0, "bad_signature", "a response signature, when present, must verify");
    }

    #[test]
    fn signature_wrapping_is_refused() {
        let good = base();
        let signed = good.xml();
        let assertion = &signed[signed.find("<saml:Assertion").unwrap()..signed.find("</samlp:Response>").unwrap()];
        let evil = assertion.replace(&good.assertion_id, "_evil").replace("00u1ADA-Persistent", "eve");
        // XSW: the forged assertion first, the signed one moved into an extension or after it.
        let cases = [
            signed.replace(assertion, &format!("{evil}{assertion}")),
            signed.replace(assertion, &format!("<samlp:Extensions>{assertion}</samlp:Extensions>{evil}")),
            signed.replace(assertion, &evil.replacen("</saml:Subject>", &format!("</saml:Subject><saml:Advice>{assertion}</saml:Advice>"), 1)),
            signed.replace("</samlp:Status>", &format!("</samlp:Status><samlp:Extensions>{}</samlp:Extensions>", assertion.replace(&good.assertion_id, "_copy"))),
            signed.replace(&format!(r#"ID="{}""#, good.id), &format!(r#"ID="{}""#, good.assertion_id)),
        ];
        for (i, xml) in cases.iter().enumerate() {
            assert_eq!(check(xml).unwrap_err().0, "wrapped", "case {i}");
        }
        let moved_sig = signed.replacen("<ds:Signature", "<saml:Subject><ds:Signature", 1);
        assert!(check(&moved_sig).is_err());
        let encrypted = signed.replace(assertion, r#"<saml:EncryptedAssertion><x/></saml:EncryptedAssertion>"#);
        assert_eq!(check(&encrypted).unwrap_err().0, "encrypted_assertion");
        let none = signed.replace(assertion, "");
        assert_eq!(check(&none).unwrap_err().0, "missing_assertion");
        let comment = good.xml_with(|a| a.replace("00u1ADA-Persistent", "00u1ADA<!---->-Persistent"));
        assert_eq!(check(&comment).unwrap_err().0, "bad_response");
        let dtd = format!(r#"<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>{signed}"#);
        assert_eq!(check(&dtd).unwrap_err().0, "bad_response");
    }

    #[test]
    fn responses_for_someone_else_or_another_time_are_refused() {
        let with = |f: fn(&mut Response)| {
            let mut r = base();
            f(&mut r);
            reason(r)
        };
        assert_eq!(with(|r| r.audience = "https://other-sp.example".into()), "wrong_audience");
        assert_eq!(with(|r| r.recipient = "https://bot.example.com/api/auth/sso/other/acs".into()), "wrong_recipient");
        assert_eq!(with(|r| r.destination = Some("https://evil.example/acs".into())), "wrong_destination");
        assert_eq!(with(|r| r.destination = None), "ok", "Destination is optional on an unsigned response");
        assert_eq!(with(|r| r.issuer = "https://evil.example".into()), "wrong_issuer");
        assert_eq!(with(|r| r.in_response_to = "_another".into()), "in_response_to_mismatch");
        assert_eq!(with(|r| r.confirm_in_response_to = "_another".into()), "in_response_to_mismatch", "the signed InResponseTo counts too");
        assert_eq!(with(|r| r.not_on_or_after = NOW - SKEW_MS - 1), "expired");
        assert_eq!(with(|r| r.confirm_not_on_or_after = NOW - SKEW_MS - 1), "expired");
        assert_eq!(with(|r| r.not_on_or_after = NOW - SKEW_MS + 1_000), "ok", "within the clock skew");
        assert_eq!(with(|r| r.not_before = NOW + SKEW_MS + 1_000), "not_yet_valid");
        assert_eq!(with(|r| r.name_id_format = TRANSIENT.into()), "transient_subject");
        assert_eq!(with(|r| r.name_id = " padded".into()), "missing_subject");
        assert_eq!(with(|r| r.status = "urn:oasis:names:tc:SAML:2.0:status:Responder".into()), "idp_error");
        let nested = r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/></samlp:StatusCode>"#;
        let denied = base().xml().replace(&format!(r#"<samlp:StatusCode Value="{SUCCESS}"/>"#), nested);
        assert_eq!(check(&denied).unwrap_err(), Refused("idp_error", Some("Responder/RequestDenied".into())));
        let (start, end) = (denied.find("<saml:Assertion").unwrap(), denied.rfind("</saml:Assertion>").unwrap() + "</saml:Assertion>".len());
        let bare = format!("{}{}", &denied[..start], &denied[end..]);
        assert_eq!(check(&bare).unwrap_err(), Refused("idp_error", Some("Responder/RequestDenied".into())), "a failure without an assertion keeps its reason");
        let mut unsolicited = base();
        unsolicited.in_response_to = String::new();
        let xml = unsolicited.xml().replace(r#" InResponseTo="""#, "");
        assert_eq!(check(&xml).unwrap_err().0, "in_response_to_mismatch", "IdP-initiated");
        assert_eq!(check_at(&base().xml(), NOW + 3_600_000).unwrap_err().0, "expired", "an old response posted later");
        assert_eq!(
            with(|r| { r.conditions_extra = "<saml:AudienceRestriction><saml:Audience>https://other-sp.example</saml:Audience></saml:AudienceRestriction>".into() }),
            "wrong_audience",
            "every restriction must name us"
        );
        assert_eq!(with(|r| r.conditions_extra = "<saml:OneTimeUse/>".into()), "ok");
        assert_eq!(check("not xml").unwrap_err().0, "bad_response");
        assert_eq!(
            check_response(&"A".repeat(MAX_RESPONSE + 4), &Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp(), request_id: REQ, attributes: &Attributes::default(), now_ms: NOW }).unwrap_err().0,
            "bad_response"
        );
    }
}
