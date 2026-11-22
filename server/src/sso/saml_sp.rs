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
//!   assertion's ID.

use super::jwt::Invalid;
use super::provider::Claims;
use super::xmldsig::{self, Cert, elements, is};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::Node;

pub const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
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
}

/// This service provider, as the IdP knows it.
pub struct Sp<'a> {
    pub entity_id: &'a str,
    pub acs: &'a str,
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// The IdP `entity_id` in `xml` (an `EntityDescriptor`, or one inside `EntitiesDescriptor`).
/// The error says what to fix, for the admin who imported it.
pub fn parse_idp_metadata(xml: &str, entity_id: &str) -> Result<IdpMetadata, String> {
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
    if idp.attribute("WantAuthnRequestsSigned") == Some("true") {
        return Err("the IdP wants signed AuthnRequests, which SuperBot doesn't send: turn that off for this app at the IdP".into());
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
    Ok(IdpMetadata { entity_id: entity_id.into(), sso_url, certs })
}

/// Our metadata, for the IdP to import: who we are, where to post, and that assertions must be signed.
pub fn sp_metadata(sp: &Sp) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="{METADATA}" entityID="{}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="{PROTOCOL}">
    <md:NameIDFormat>{PERSISTENT}</md:NameIDFormat>
    <md:AssertionConsumerService Binding="{POST}" Location="{}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"#,
        escape(sp.entity_id),
        escape(sp.acs)
    )
}

fn instant(ms: i64) -> String {
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
}

fn time(s: &str) -> Result<i64, Refused> {
    chrono::DateTime::parse_from_rfc3339(s.trim()).map(|t| t.timestamp_millis()).map_err(|_| Refused("bad_response", None))
}

/// The one child `{ns}name` of `n`, if there is exactly one.
fn only<'a, 'i>(n: Node<'a, 'i>, ns: &str, name: &str) -> Option<Node<'a, 'i>> {
    let mut it = n.children().filter(|c| is(*c, ns, name));
    let first = it.next()?;
    it.next().is_none().then_some(first)
}

/// The text of an element with only text in it.
fn text_of<'a>(n: Node<'a, '_>) -> Option<&'a str> {
    if n.children().any(|c| !c.is_text()) {
        return None;
    }
    Some(n.text().unwrap_or(""))
}

fn issuer_is(n: Node, entity_id: &str) -> bool {
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

    let status = only(response, PROTOCOL, "Status").and_then(|s| only(s, PROTOCOL, "StatusCode")).ok_or_else(bad)?;
    if status.attribute("Value") != Some(SUCCESS) {
        let codes: Vec<&str> = std::iter::successors(Some(status), |c| only(*c, PROTOCOL, "StatusCode")).filter_map(|c| c.attribute("Value")).map(|v| v.rsplit(':').next().unwrap_or(v)).collect();
        return Err(Refused("idp_error", Some(crate::audit::clip(&codes.join("/"), 128))));
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
    if !assertion.children().any(|c| is(c, ASSERTION, "AuthnStatement")) {
        return Err(bad());
    }

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
    Ok(Checked { claims, assertion_id, until_ms: until.min(now + 24 * 3600 * 1000) })
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
                r#"<saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{now}"><saml:Issuer>{iss}</saml:Issuer><saml:Subject><saml:NameID Format="{fmt}">{nid}</saml:NameID><saml:SubjectConfirmation Method="{BEARER}"><saml:SubjectConfirmationData InResponseTo="{cirt}" NotOnOrAfter="{cna}" Recipient="{rcp}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction>{extra}</saml:Conditions><saml:AuthnStatement AuthnInstant="{now}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>{attrs}</saml:AttributeStatement></saml:Assertion>"#,
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
        parse_idp_metadata(&metadata(), IDP).unwrap()
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
        assert_eq!(parse_idp_metadata(&metadata_with(IDP, &[a, b], ""), IDP).unwrap().certs.len(), 2, "rollover: both certificates");
        let wrapped = format!(
            r#"<md:EntitiesDescriptor xmlns:md="{METADATA}">{}</md:EntitiesDescriptor>"#,
            metadata_with("https://other.example", &[b], "").replace(r#"<?xml version="1.0"?>"#, "") + &metadata().replace(r#"<?xml version="1.0"?>"#, "")
        );
        assert_eq!(parse_idp_metadata(&wrapped, IDP).unwrap().certs[0].sha256, a.cert().sha256, "picked by entity ID from an aggregate");
        for (xml, want) in [
            (metadata_with(IDP, &[], ""), "no signing certificate"),
            (metadata_with(IDP, &[a], r#" WantAuthnRequestsSigned="true""#), "signed AuthnRequests"),
            (metadata().replace(&format!(r#"Binding="{REDIRECT}""#), r#"Binding="urn:x""#), "no HTTP-Redirect"),
            (metadata().replace(SSO_URL, "http://idp.example/sso"), "isn't https"),
            (metadata().replace(PROTOCOL, "urn:oasis:names:tc:SAML:1.1:protocol"), "no SAML 2.0"),
            (format!(r#"<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>{}"#, metadata().replace(r#"<?xml version="1.0"?>"#, "")), "no DTDs"),
            ("<html/>".into(), "no EntityDescriptor"),
        ] {
            let err = parse_idp_metadata(&xml, IDP).unwrap_err();
            assert!(err.contains(want), "{want}: {err}");
        }
        assert!(parse_idp_metadata(&metadata(), "https://elsewhere.example").unwrap_err().contains(IDP), "names the entity it found");
    }

    #[test]
    fn writes_sp_metadata_and_a_redirect_authn_request() {
        let sp = Sp { entity_id: SP, acs: ACS };
        let md = sp_metadata(&sp);
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
