//! The HTTP-Artifact binding for native SAML responses (ADR 0268): the IdP sends the browser
//! to our ACS with a short reference (`SAMLart`), and botd fetches the response itself from the
//! IdP's ArtifactResolutionService over SOAP, so the assertion never passes through the browser.
//!
//! - **The artifact** (SAML Bindings 3.6.4) is type `0x0004`: an endpoint index, the SHA-1 of
//!   the IdP's entity ID (its `SourceID`), and a message handle. One from another IdP is
//!   refused before anything is sent, and its index must name a SOAP ArtifactResolutionService
//!   on https in the IdP's metadata. The caller spends each artifact once.
//! - **The ArtifactResolve** names our entity ID and the artifact and carries our enveloped
//!   signature by the provider's SP signing key, which is how the IdP knows it's us: botd sits
//!   behind a proxy and has no TLS client certificate to offer.
//! - **The ArtifactResponse** comes back on the TLS connection botd opened to the URL in the
//!   IdP's metadata, which is what vouches for it; a signature, if the IdP adds one, must still
//!   be the IdP's. It is held to the SOAP rules of single logout (one message in the Body, no
//!   header botd must understand), every `ID` in it unique, a `ds:Signature` only on it or
//!   inside the response it carries, its `Issuer` (if any) the IdP, `InResponseTo` our
//!   ArtifactResolve, `IssueInstant` fresh, and `Success`. Success with no message means the
//!   IdP doesn't know the artifact (`artifact_unknown`).
//! - **The response** inside is then checked exactly as a posted one (`saml_sp`): its assertion
//!   signed by the IdP, for our ACS, audience and request, and so on. Resolution over a TLS
//!   channel lets the SAML spec drop the signature; botd doesn't.

use super::saml_slo::{self, SOAP11};
use super::saml_sp::{ASSERTION, IdpMetadata, MAX_RESPONSE, PROTOCOL, Refused, SKEW_MS, SUCCESS, escape, instant, issuer_is, only, text_of, time};
use super::xmldsig::{self, is};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::Node;

/// The artifact type the Web Browser SSO profile uses.
const TYPE_CODE: [u8; 2] = [0, 4];
/// Type code, endpoint index, SourceID and MessageHandle: 2 + 2 + 20 + 20 bytes.
const LEN: usize = 44;
/// How old the IdP's ArtifactResponse may be: it answers on the same connection, at once.
pub const MAX_AGE_MS: i64 = 5 * 60_000;

/// An artifact from the browser, for the IdP it names.
#[derive(Debug, PartialEq)]
pub struct Artifact {
    /// The ArtifactResolutionService it is resolved at.
    pub index: u16,
    /// As the ArtifactResolve carries it: base64 of the 44 bytes.
    pub value: String,
}

/// The SourceID an IdP puts in its artifacts: the SHA-1 of its entity ID.
pub fn source_id(entity_id: &str) -> [u8; 20] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, entity_id.as_bytes());
    d.as_ref().try_into().expect("SHA-1 is 20 bytes")
}

/// Reads the `SAMLart` the browser brought. It must be a type 4 artifact from `idp_entity_id`.
pub fn parse(raw: &str, idp_entity_id: &str) -> Result<Artifact, Refused> {
    let bad = || Refused("bad_artifact", None);
    let raw = raw.trim();
    if raw.len() > 128 {
        return Err(bad());
    }
    // A `+` a sender left unencoded in the query reads as a space; base64 has no spaces.
    let bytes = STANDARD.decode(raw.replace(' ', "+")).map_err(|_| bad())?;
    if bytes.len() != LEN || bytes[..2] != TYPE_CODE {
        return Err(bad());
    }
    if bytes[4..24] != source_id(idp_entity_id) {
        return Err(Refused("wrong_artifact_source", None));
    }
    Ok(Artifact { index: u16::from_be_bytes([bytes[2], bytes[3]]), value: STANDARD.encode(&bytes) })
}

/// Our ArtifactResolve for `artifact`, to the IdP's ArtifactResolutionService at
/// `destination`. The caller signs it: the signature goes after the Issuer, as the schema has it.
pub fn resolve_request(sp_entity_id: &str, id: &str, destination: &str, artifact: &Artifact, now_ms: i64) -> String {
    format!(
        r#"<samlp:ArtifactResolve xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{}" Destination="{}"><saml:Issuer>{}</saml:Issuer><samlp:Artifact>{}</samlp:Artifact></samlp:ArtifactResolve>"#,
        instant(now_ms),
        escape(destination),
        escape(sp_entity_id),
        artifact.value
    )
}

/// The IdP's SOAP answer to our ArtifactResolve `request_id`, as the module docs list: the
/// `samlp:Response` it carries, as a document of its own, for `saml_sp::check_response_xml`.
pub fn receive(body: &str, idp: &IdpMetadata, request_id: &str, now_ms: i64) -> Result<String, Refused> {
    let bad = || Refused("bad_message", None);
    if body.len() > MAX_RESPONSE {
        return Err(bad());
    }
    let doc = xmldsig::parse(body).map_err(|_| bad())?;
    let m = saml_slo::soap_body(&doc)?;
    if is(m, SOAP11, "Fault") {
        let why = m.children().find(|c| c.tag_name().name() == "faultstring").and_then(text_of).unwrap_or("");
        return Err(Refused("soap_fault", Some(crate::audit::clip(why.trim(), 128))));
    }
    if !is(m, PROTOCOL, "ArtifactResponse") || m.attribute("Version") != Some("2.0") {
        return Err(bad());
    }
    // Issuer, Signature and Extensions, then Status, then the message, if any.
    let kids = xmldsig::elements(m);
    let status_at = kids.iter().position(|k| is(*k, PROTOCOL, "Status")).ok_or_else(bad)?;
    let message = match &kids[status_at + 1..] {
        [] => None,
        [r] if is(*r, PROTOCOL, "Response") => Some(*r),
        _ => return Err(bad()),
    };
    if m.children().any(|c| c.is_text() && c.text().is_some_and(|t| !t.trim().is_empty())) {
        return Err(bad());
    }

    // Structure first, then the signature, then only what was signed or came over TLS is read.
    let mut ids: Vec<&str> = doc.descendants().flat_map(|n| n.attributes()).filter(|a| a.namespace().is_none() && a.name().eq_ignore_ascii_case("id")).map(|a| a.value()).collect();
    let all = ids.len();
    ids.sort_unstable();
    ids.dedup();
    let inside = |s: Node| message.is_some_and(|r| s.ancestors().any(|a| a == r));
    if ids.len() != all || doc.descendants().filter(|n| is(*n, xmldsig::DSIG, "Signature")).any(|s| s.parent() != Some(m) && !inside(s)) {
        return Err(Refused("wrapped", None));
    }
    xmldsig::verify_enveloped(m, &idp.certs)?;
    if m.children().any(|c| is(c, ASSERTION, "Issuer")) && !issuer_is(m, &idp.entity_id) {
        return Err(Refused("wrong_issuer", None));
    }
    if m.attribute("InResponseTo") != Some(request_id) {
        return Err(Refused("artifact_mismatch", None));
    }
    let issued = time(m.attribute("IssueInstant").ok_or_else(bad)?).map_err(|_| bad())?;
    if issued > now_ms + SKEW_MS {
        return Err(Refused("not_yet_valid", None));
    }
    if issued <= now_ms - MAX_AGE_MS - SKEW_MS {
        return Err(Refused("expired", None));
    }
    let code = only(kids[status_at], PROTOCOL, "StatusCode").ok_or_else(bad)?;
    if code.attribute("Value") != Some(SUCCESS) {
        return Err(Refused("idp_error", Some(saml_slo::status_codes(code))));
    }
    standalone(message.ok_or(Refused("artifact_unknown", None))?, body)
}

/// `n` as a document of its own: its text as the IdP sent it, with every namespace it had in
/// scope declared on it, since the IdP may have declared them only on the ArtifactResponse or
/// the envelope. Exclusive C14N, the only kind `xmldsig` takes, renders a prefix where it is
/// used whichever ancestor declared it, so signatures inside verify as they did in place.
fn standalone(n: Node, body: &str) -> Result<String, Refused> {
    let bad = || Refused("bad_message", None);
    let raw = &body[n.range()];
    let declared = start_tag_attributes(raw).ok_or_else(bad)?;
    let name_end = raw.find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>').ok_or_else(bad)?;
    let mut decls = String::new();
    for ns in n.namespaces().filter(|ns| ns.name() != Some("xml")) {
        let attr = ns.name().map_or_else(|| "xmlns".to_string(), |p| format!("xmlns:{p}"));
        if !declared.contains(&attr.as_str()) {
            decls += &format!(r#" {attr}="{}""#, escape(ns.uri()));
        }
    }
    Ok(format!("{}{decls}{}", &raw[..name_end], &raw[name_end..]))
}

/// The attribute names in the start tag `raw` begins with, as written.
fn start_tag_attributes(raw: &str) -> Option<Vec<&str>> {
    let b = raw.as_bytes();
    let mut i = raw.find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')?;
    let mut names = Vec::new();
    loop {
        while b.get(i)?.is_ascii_whitespace() {
            i += 1;
        }
        if matches!(b.get(i)?, b'/' | b'>') {
            return Some(names);
        }
        let start = i;
        while !matches!(b.get(i)?, b'=' | b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        }
        names.push(&raw[start..i]);
        while b.get(i)?.is_ascii_whitespace() {
            i += 1;
        }
        if *b.get(i)? != b'=' {
            return None;
        }
        i += 1;
        while b.get(i)?.is_ascii_whitespace() {
            i += 1;
        }
        let quote = *b.get(i)?;
        if quote != b'"' && quote != b'\'' {
            return None;
        }
        i += 1 + raw[i + 1..].find(quote as char)? + 1;
    }
}

#[cfg(test)]
pub mod test_idp {
    //! The test IdP's artifacts and ArtifactResponses, with any part changed.

    use super::*;
    use crate::sso::saml_sp::test_idp::IDP;
    use crate::sso::xmldsig::test_signer::signer;

    /// An artifact from `entity_id` for its ArtifactResolutionService `index`.
    pub fn artifact(entity_id: &str, index: u16) -> String {
        let mut b = Vec::with_capacity(LEN);
        b.extend_from_slice(&TYPE_CODE);
        b.extend_from_slice(&index.to_be_bytes());
        b.extend_from_slice(&source_id(entity_id));
        b.extend_from_slice(&aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, crate::random_hex(8).as_bytes()).as_ref()[..20]);
        STANDARD.encode(b)
    }

    /// The ArtifactResponse the IdP sends for `in_response_to`, carrying `message` (a
    /// response's XML, or nothing), in a SOAP envelope.
    #[derive(Clone)]
    pub struct Answer {
        pub id: String,
        pub in_response_to: String,
        pub issuer: Option<String>,
        pub issued_ms: i64,
        pub status: String,
        pub message: Option<String>,
        /// Which test key signs it (0 is the IdP's), or none.
        pub signer: Option<usize>,
        /// Take the `samlp`, `saml`, `xs` and `xsi` declarations off the message's root and
        /// declare them on the envelope instead, as some IdPs serialize it.
        pub hoist_namespaces: bool,
    }

    impl Answer {
        pub fn new(in_response_to: &str, message: Option<String>, now_ms: i64) -> Answer {
            Answer { id: format!("_ar{}", crate::random_hex(8)), in_response_to: in_response_to.into(), issuer: Some(IDP.into()), issued_ms: now_ms, status: SUCCESS.into(), message, signer: None, hoist_namespaces: false }
        }

        pub fn soap(&self) -> String {
            const DECLS: [(&str, &str); 4] = [("samlp", PROTOCOL), ("saml", ASSERTION), ("xs", "http://www.w3.org/2001/XMLSchema"), ("xsi", "http://www.w3.org/2001/XMLSchema-instance")];
            let mut message = self.message.clone().unwrap_or_default();
            let mut hoisted = String::new();
            if self.hoist_namespaces {
                for (p, uri) in DECLS {
                    message = message.replacen(&format!(r#" xmlns:{p}="{uri}""#), "", 1);
                    hoisted += &format!(r#" xmlns:{p}="{uri}""#);
                }
            }
            let issuer = self.issuer.as_ref().map(|i| format!("<saml:Issuer>{i}</saml:Issuer>")).unwrap_or_default();
            let declare = if self.hoist_namespaces { String::new() } else { format!(r#" xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}""#) };
            let m = format!(
                r#"<samlp:ArtifactResponse{declare} ID="{}" Version="2.0" IssueInstant="{}" InResponseTo="{}">{issuer}<samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status>{message}</samlp:ArtifactResponse>"#,
                self.id,
                instant(self.issued_ms),
                self.in_response_to,
                self.status
            );
            let envelope = format!(r#"<soap11:Envelope xmlns:soap11="{SOAP11}"{hoisted}><soap11:Body>{m}</soap11:Body></soap11:Envelope>"#);
            match self.signer {
                Some(s) => signer(s).sign(&envelope, &self.id),
                None => envelope,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_idp::*;
    use super::*;
    use crate::sso::saml_sp::test_idp::{IDP, Response, metadata};
    use crate::sso::saml_sp::{AesCbc, Attributes, Expect, Sp, check_response_xml, parse_idp_metadata};

    const ACS: &str = "https://bot.example.com/api/auth/sso/okta/acs";
    const SP: &str = "https://bot.example.com/api/auth/sso/okta/metadata";
    const ARS: &str = "https://idp.example/saml/artifact";
    const REQ: &str = "_0123456789abcdef";
    const RESOLVE: &str = "_resolve0123456789";
    const NOW: i64 = 1_800_000_000_000;

    fn idp() -> IdpMetadata {
        parse_idp_metadata(&metadata(), IDP, false).unwrap()
    }

    fn response() -> Response {
        Response::new(ACS, SP, REQ, NOW)
    }

    fn answer() -> Answer {
        Answer::new(RESOLVE, Some(response().xml()), NOW)
    }

    fn got(a: &Answer) -> Result<String, &'static str> {
        receive(&a.soap(), &idp(), RESOLVE, NOW).map_err(|e| e.0)
    }

    fn check(xml: &str) -> Result<String, &'static str> {
        let attributes = Attributes::default();
        let idp = idp();
        let e = Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp, request_id: Some(REQ), attributes: &attributes, now_ms: NOW, decrypt: &[], require_encrypted: false, aes_cbc: AesCbc::Off };
        check_response_xml(xml, &e).map(|c| c.claims.subject).map_err(|e| e.0)
    }

    #[test]
    fn artifacts_are_type_4_from_our_idp_and_name_an_endpoint() {
        let raw = artifact(IDP, 3);
        let a = parse(&raw, IDP).unwrap();
        assert_eq!((a.index, a.value.as_str()), (3, raw.as_str()));
        assert_eq!(parse(&raw.replace('+', " "), IDP).unwrap().value, raw, "a + the query turned into a space");
        assert_eq!(parse(&artifact("https://evil.example/idp", 0), IDP), Err(Refused("wrong_artifact_source", None)), "refused before anything is sent");
        let mut bytes = STANDARD.decode(&raw).unwrap();
        bytes[1] = 1;
        for bad in [STANDARD.encode(&bytes), STANDARD.encode(&bytes[..40]), "not base64!".into(), "A".repeat(200), String::new()] {
            assert_eq!(parse(&bad, IDP), Err(Refused("bad_artifact", None)), "{bad}");
        }
        assert_eq!(hex(&source_id("https://idp.example.org/idp/shibboleth")), hex(&aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, b"https://idp.example.org/idp/shibboleth").as_ref()[..20]));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn the_artifact_resolve_names_us_and_the_artifact_and_signs_after_the_issuer() {
        let a = parse(&artifact(IDP, 0), IDP).unwrap();
        let xml = resolve_request("urn:a&b", RESOLVE, ARS, &a, NOW);
        let doc = xmldsig::parse(&xml).unwrap();
        let r = doc.root_element();
        assert!(is(r, PROTOCOL, "ArtifactResolve"));
        assert_eq!((r.attribute("ID"), r.attribute("Destination"), r.attribute("Version")), (Some(RESOLVE), Some(ARS), Some("2.0")));
        assert!(issuer_is(r, "urn:a&b"), "escaped");
        assert_eq!(only(r, PROTOCOL, "Artifact").and_then(text_of), Some(a.value.as_str()));
        let (key, _) = crate::sso::saml_sp::SpKey::generate("test").unwrap();
        let signed = key.sign_enveloped(&xml, RESOLVE).unwrap();
        let doc = xmldsig::parse(&signed).unwrap();
        let kids = xmldsig::elements(doc.root_element());
        assert_eq!(kids.iter().map(|k| k.tag_name().name()).collect::<Vec<_>>(), ["Issuer", "Signature", "Artifact"]);
        assert_eq!(xmldsig::verify_enveloped(doc.root_element(), std::slice::from_ref(&key.info)), Ok(true));
    }

    #[test]
    fn an_artifact_response_gives_the_response_inside_checked_as_a_posted_one() {
        let xml = got(&answer()).unwrap();
        assert_eq!(check(&xml), Ok("00u1ada-persistent".into()));
        let mut signed = answer();
        signed.signer = Some(0);
        assert_eq!(check(&got(&signed).unwrap()), Ok("00u1ada-persistent".into()), "signed by the IdP too");
        let mut no_issuer = answer();
        no_issuer.issuer = None;
        assert!(got(&no_issuer).is_ok(), "its Issuer is optional");

        // The response inside is held to everything a posted one is.
        let mut unsigned = response();
        unsigned.sign_assertion = false;
        assert_eq!(check(&got(&Answer::new(RESOLVE, Some(unsigned.xml()), NOW)).unwrap()), Err("unsigned"), "TLS doesn't stand in for the assertion's signature");
        let mut other = response();
        other.audience = "https://other.example/sp".into();
        assert_eq!(check(&got(&Answer::new(RESOLVE, Some(other.xml()), NOW)).unwrap()), Err("wrong_audience"));
        let changed = response().xml().replace("ada@example.com", "eve@example.com");
        assert_eq!(check(&got(&Answer::new(RESOLVE, Some(changed), NOW)).unwrap()), Err("bad_signature"));
    }

    #[test]
    fn namespaces_declared_only_around_the_response_are_carried_onto_it() {
        for sign_response in [false, true] {
            let mut r = response();
            r.sign_response = sign_response;
            let mut a = Answer::new(RESOLVE, Some(r.xml()), NOW);
            a.hoist_namespaces = true;
            let body = a.soap();
            assert!(!body.contains(&format!(r#"<samlp:Response xmlns:samlp="{PROTOCOL}""#)), "{body}");
            let xml = got(&a).unwrap();
            let start = xml.split('>').next().unwrap();
            assert!(start.contains(&format!(r#"xmlns:samlp="{PROTOCOL}""#)) && start.contains(&format!(r#"xmlns:saml="{ASSERTION}""#)), "{start}");
            assert_eq!(check(&xml), Ok("00u1ada-persistent".into()), "signed response: {sign_response}");
        }
        // Declared on it already: not declared twice.
        let xml = got(&answer()).unwrap();
        assert_eq!(xml.matches(&format!(r#"xmlns:samlp="{PROTOCOL}""#)).count(), 1, "{xml}");
    }

    #[test]
    fn artifact_responses_must_answer_our_request_from_our_idp_now() {
        let cases: Vec<(Box<dyn Fn(&mut Answer)>, &str)> = vec![
            (Box::new(|a| a.in_response_to = "_another".into()), "artifact_mismatch"),
            (Box::new(|a| a.issuer = Some("https://evil.example/idp".into())), "wrong_issuer"),
            (Box::new(|a| a.issued_ms = NOW - MAX_AGE_MS - SKEW_MS - 1_000), "expired"),
            (Box::new(|a| a.issued_ms = NOW + SKEW_MS + 1_000), "not_yet_valid"),
            (Box::new(|a| a.signer = Some(1)), "bad_signature"),
            (Box::new(|a| a.message = None), "artifact_unknown"),
            (Box::new(|a| a.status = "urn:oasis:names:tc:SAML:2.0:status:Requester".into()), "idp_error"),
        ];
        for (tweak, want) in cases {
            let mut a = answer();
            tweak(&mut a);
            assert_eq!(got(&a), Err(want));
        }
        let mut denied = answer();
        denied.status = "urn:oasis:names:tc:SAML:2.0:status:Responder".into();
        assert_eq!(receive(&denied.soap(), &idp(), RESOLVE, NOW).unwrap_err().1.as_deref(), Some("Responder"));
    }

    #[test]
    fn artifact_responses_carry_one_response_and_nothing_wrapped() {
        let body = answer().soap();
        let another = response().xml();
        let fault = saml_slo::soap_fault("x");
        let sig = format!(r#"<ds:Signature xmlns:ds="{}"/>"#, xmldsig::DSIG);
        let cases = [
            (body.replacen("</samlp:ArtifactResponse>", &format!("{another}</samlp:ArtifactResponse>"), 1), "bad_message", "two responses"),
            (body.replacen("</samlp:ArtifactResponse>", "<samlp:LogoutRequest/></samlp:ArtifactResponse>", 1), "bad_message", "another message"),
            (body.replacen("<samlp:Status>", "junk<samlp:Status>", 1), "bad_message", "text in it"),
            (body.replace("ArtifactResponse", "Response"), "bad_message", "not an ArtifactResponse"),
            (body.replacen("<soap11:Body>", "<soap11:Header><x:S xmlns:x=\"urn:x\" soap11:mustUnderstand=\"1\"/></soap11:Header><soap11:Body>", 1), "must_understand", "a header to understand"),
            (fault, "soap_fault", "a fault"),
            (body.replacen("</soap11:Body>", &format!("{sig}</soap11:Body>"), 1), "bad_message", "a signature beside it"),
            (body.replacen("<samlp:StatusCode", &format!("{sig}<samlp:StatusCode"), 1), "wrapped", "a signature in the status"),
            (body.replacen("<samlp:Response ", &format!("{sig}<samlp:Response "), 1), "bad_message", "a signature after the status"),
        ];
        for (xml, want, why) in cases {
            assert_eq!(receive(&xml, &idp(), RESOLVE, NOW).err().map_or("ok", |e| e.0), want, "{why}");
        }
        // The response's ID again on the ArtifactResponse: a wrapping attempt.
        let r = response();
        let mut a = Answer::new(RESOLVE, Some(r.xml()), NOW);
        a.id = r.id.clone();
        assert_eq!(got(&a), Err("wrapped"));
        assert_eq!(receive(&"x".repeat(MAX_RESPONSE + 1), &idp(), RESOLVE, NOW), Err(Refused("bad_message", None)));
    }

    #[test]
    fn start_tags_are_read_attribute_by_attribute() {
        assert_eq!(start_tag_attributes(r#"<a:R xmlns:a="u" ID='x>y' b = "1">"#), Some(vec!["xmlns:a", "ID", "b"]));
        assert_eq!(start_tag_attributes("<R/>"), Some(vec![]));
        assert_eq!(start_tag_attributes(r#"<R a="1"#), None);
        assert_eq!(start_tag_attributes(r#"<R a=1>"#), None);
    }
}
