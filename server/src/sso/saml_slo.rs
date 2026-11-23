//! Single logout for native SAML (ADR 0137): the LogoutRequest botd sends the IdP when
//! someone signs out of SuperBot, and the LogoutRequests and LogoutResponses the IdP sends to
//! our SLO URL, over HTTP-Redirect or HTTP-POST.
//!
//! A message to the SLO URL counts only if it is:
//!
//! - **Signed by the IdP.** Over HTTP-Redirect, the binding's signature over the query
//!   (SAML Bindings 3.4.4.1); over HTTP-POST, an enveloped signature on the message itself
//!   (`xmldsig`). Unsigned messages are refused: anyone could otherwise sign anyone out.
//! - **Well formed, and one message.** As for responses: no DTD, comment, or processing
//!   instruction; every `ID` unique; a `ds:Signature` only as a direct child of the message,
//!   so what is read is what was signed.
//! - **From the IdP, for us, and now.** `Issuer` is the IdP's entity ID, `Destination` our SLO
//!   URL, `IssueInstant` within `MAX_AGE_MS` (with the clock skew), and a request's
//!   `NotOnOrAfter` not passed. The caller refuses an ID seen before (replay), and a response
//!   to a request it didn't send.
//!
//! A LogoutRequest names a NameID and maybe `SessionIndex`es; the caller revokes the SuperBot
//! sessions signed in with them, then answers. An `EncryptedID` is decrypted with the
//! provider's encryption key (ADR 0151), after the signature over it is checked, and refused
//! (`encrypted_id`) when the provider has none.

use super::saml_sp::{self, ASSERTION, IdpMetadata, MAX_RESPONSE, PROTOCOL, Refused, SKEW_MS, SUCCESS, SpKey, escape, instant, issuer_is, only, text_of, time};
use super::xmldsig::{self, is};
use crate::db::SamlLogin;
use roxmltree::Node;
use std::collections::HashMap;

/// How old a logout message may be. They are answered at once, so a few minutes is plenty.
pub const MAX_AGE_MS: i64 = 5 * 60_000;
/// More SessionIndexes than any IdP sends.
const MAX_INDEXES: usize = 32;

/// How a message reached the SLO URL.
pub enum Incoming<'a> {
    /// GET, with the raw query string.
    Redirect(&'a str),
    /// POST, with its form.
    Post(&'a HashMap<String, String>),
}

/// What a message must match.
pub struct Expect<'a> {
    pub idp: &'a IdpMetadata,
    /// Our SLO URL: the `Destination`.
    pub slo_url: &'a str,
    pub now_ms: i64,
    /// Our encryption key, when the provider has one (ADR 0150), for an `EncryptedID` (ADR 0151).
    pub decrypt: Option<&'a SpKey>,
}

/// A logout message that passed. `until_ms` is how long to remember its ID to refuse it again.
#[derive(Debug, PartialEq)]
pub enum Received {
    /// The IdP signed this person out: revoke their sessions, then answer.
    /// `issued_ms` is its `IssueInstant`.
    Request { id: String, name_id: String, session_indexes: Vec<String>, relay: Option<String>, issued_ms: i64, until_ms: i64 },
    /// The IdP's answer to our LogoutRequest. `status` is None for success, else its codes.
    Response { id: String, in_response_to: String, status: Option<String>, until_ms: i64 },
}

/// Checks a message the IdP sent to the SLO URL, as the module docs list.
pub fn receive(incoming: &Incoming, e: &Expect) -> Result<Received, Refused> {
    let bad = || Refused("bad_message", None);
    let (param, xml, relay, by_binding) = match incoming {
        Incoming::Redirect(q) => {
            let r = saml_sp::from_redirect(q)?;
            let signed = r.verify(&e.idp.certs)?;
            (r.param, r.xml, r.relay, signed)
        }
        Incoming::Post(f) => {
            let (param, v) = match (f.get("SAMLRequest"), f.get("SAMLResponse")) {
                (Some(v), None) => ("SAMLRequest", v),
                (None, Some(v)) => ("SAMLResponse", v),
                _ => return Err(bad()),
            };
            if v.len() > MAX_RESPONSE {
                return Err(bad());
            }
            let xml = String::from_utf8(xmldsig::base64(v).ok_or_else(bad)?).map_err(|_| bad())?;
            (param, xml, f.get("RelayState").cloned(), false)
        }
    };
    let doc = xmldsig::parse(&xml).map_err(|_| bad())?;
    let root = doc.root_element();
    let request = match param {
        "SAMLRequest" if is(root, PROTOCOL, "LogoutRequest") => true,
        "SAMLResponse" if is(root, PROTOCOL, "LogoutResponse") => false,
        _ => return Err(bad()),
    };
    if root.attribute("Version") != Some("2.0") {
        return Err(bad());
    }

    // Structure first, then the signature, then only the signed message is read.
    let mut ids: Vec<&str> = doc.descendants().flat_map(|n| n.attributes()).filter(|a| a.namespace().is_none() && a.name().eq_ignore_ascii_case("id")).map(|a| a.value()).collect();
    let all = ids.len();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != all || doc.descendants().filter(|n| is(*n, xmldsig::DSIG, "Signature")).any(|s| s.parent() != Some(root)) {
        return Err(Refused("wrapped", None));
    }
    if !by_binding && !xmldsig::verify_enveloped(root, &e.idp.certs)? {
        return Err(Refused("unsigned", None));
    }

    let id = root.attribute("ID").filter(|i| !i.is_empty() && i.len() <= 256).ok_or_else(bad)?.to_string();
    if !issuer_is(root, &e.idp.entity_id) {
        return Err(Refused("wrong_issuer", None));
    }
    if root.attribute("Destination") != Some(e.slo_url) {
        return Err(Refused("wrong_destination", None));
    }
    let issued = time(root.attribute("IssueInstant").ok_or_else(bad)?).map_err(|_| bad())?;
    if issued > e.now_ms + SKEW_MS {
        return Err(Refused("not_yet_valid", None));
    }
    if issued <= e.now_ms - MAX_AGE_MS - SKEW_MS {
        return Err(Refused("expired", None));
    }
    let until_ms = issued + MAX_AGE_MS + 2 * SKEW_MS;

    if !request {
        let in_response_to = root.attribute("InResponseTo").filter(|i| !i.is_empty()).ok_or(Refused("unknown_request", None))?.to_string();
        let code = only(root, PROTOCOL, "Status").and_then(|s| only(s, PROTOCOL, "StatusCode")).ok_or_else(bad)?;
        let status = (code.attribute("Value") != Some(SUCCESS)).then(|| {
            let codes: Vec<&str> = std::iter::successors(Some(code), |c| only(*c, PROTOCOL, "StatusCode")).filter_map(|c| c.attribute("Value")).map(|v| v.rsplit(':').next().unwrap_or(v)).collect();
            crate::audit::clip(&codes.join("/"), 128)
        });
        return Ok(Received::Response { id, in_response_to, status, until_ms });
    }
    if let Some(na) = root.attribute("NotOnOrAfter")
        && time(na).map_err(|_| bad())? <= e.now_ms - SKEW_MS
    {
        return Err(Refused("expired", None));
    }
    let name_id = saml_sp::name_id(root, e.decrypt)?;
    let indexes: Vec<Node> = root.children().filter(|c| is(*c, PROTOCOL, "SessionIndex")).collect();
    if indexes.len() > MAX_INDEXES {
        return Err(bad());
    }
    let session_indexes = indexes.into_iter().map(|n| text_of(n).map(str::trim).filter(|i| !i.is_empty() && i.len() <= 1024).map(String::from)).collect::<Option<Vec<_>>>().ok_or_else(bad)?;
    let relay = relay.filter(|r| r.len() <= 80);
    Ok(Received::Request { id, name_id: name_id.value, session_indexes, relay, issued_ms: issued, until_ms })
}

fn name_id_xml(l: &SamlLogin) -> String {
    let attr = |name: &str, v: &Option<String>| v.as_ref().map_or(String::new(), |v| format!(r#" {name}="{}""#, escape(v)));
    format!(
        "<saml:NameID{}{}{}>{}</saml:NameID>",
        attr("Format", &l.format),
        attr("NameQualifier", &l.name_qualifier),
        attr("SPNameQualifier", &l.sp_name_qualifier),
        escape(&l.name_id)
    )
}

/// Our LogoutRequest for the person and IdP session `login` names, to the IdP's SLO URL.
pub fn logout_request(sp_entity_id: &str, id: &str, destination: &str, login: &SamlLogin, now_ms: i64) -> String {
    let index = login.session_index.as_ref().map_or(String::new(), |i| format!("<samlp:SessionIndex>{}</samlp:SessionIndex>", escape(i)));
    format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{}" Destination="{}" NotOnOrAfter="{}"><saml:Issuer>{}</saml:Issuer>{}{index}</samlp:LogoutRequest>"#,
        instant(now_ms),
        escape(destination),
        instant(now_ms + MAX_AGE_MS),
        escape(sp_entity_id),
        name_id_xml(login),
    )
}

/// Our LogoutResponse to the IdP's LogoutRequest `in_response_to`: done.
pub fn logout_response(sp_entity_id: &str, id: &str, destination: &str, in_response_to: &str, now_ms: i64) -> String {
    format!(
        r#"<samlp:LogoutResponse xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{id}" Version="2.0" IssueInstant="{}" Destination="{}" InResponseTo="{}"><saml:Issuer>{}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{SUCCESS}"/></samlp:Status></samlp:LogoutResponse>"#,
        instant(now_ms),
        escape(destination),
        escape(in_response_to),
        escape(sp_entity_id),
    )
}

#[cfg(test)]
pub mod test_idp {
    //! The test IdP's side of single logout: its LogoutRequests and LogoutResponses, signed
    //! over either binding, with any part changed.

    use super::*;
    use crate::sso::saml_sp::test_idp::IDP;
    use crate::sso::xmldsig::test_signer::signer;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    #[derive(Clone)]
    pub struct Logout {
        pub id: String,
        pub issuer: String,
        pub destination: Option<String>,
        pub issued_ms: i64,
        /// A request's NameID and SessionIndexes; a response's InResponseTo and status.
        pub name_id: String,
        pub session_indexes: Vec<String>,
        pub in_response_to: String,
        pub status: String,
        /// Which test key signs it (0 is the IdP's), or none.
        pub signer: Option<usize>,
        pub relay: Option<String>,
        /// Send the NameID as an `EncryptedID` to this certificate.
        pub encrypt_name_id_to: Option<String>,
    }

    impl Logout {
        pub fn request(slo_url: &str, name_id: &str, session_index: Option<&str>, now_ms: i64) -> Logout {
            Logout {
                id: format!("_l{}", crate::random_hex(8)),
                issuer: IDP.into(),
                destination: Some(slo_url.into()),
                issued_ms: now_ms - 1_000,
                name_id: name_id.into(),
                session_indexes: session_index.into_iter().map(String::from).collect(),
                in_response_to: String::new(),
                status: SUCCESS.into(),
                signer: Some(0),
                relay: Some("idp-relay".into()),
                encrypt_name_id_to: None,
            }
        }

        pub fn response(slo_url: &str, in_response_to: &str, now_ms: i64) -> Logout {
            Logout { in_response_to: in_response_to.into(), relay: None, ..Logout::request(slo_url, "", None, now_ms) }
        }

        fn is_request(&self) -> bool {
            self.in_response_to.is_empty()
        }

        pub fn xml(&self) -> String {
            let dest = self.destination.as_ref().map(|d| format!(r#" Destination="{d}""#)).unwrap_or_default();
            let at = instant(self.issued_ms);
            if self.is_request() {
                let indexes: String = self.session_indexes.iter().map(|i| format!("<samlp:SessionIndex>{i}</samlp:SessionIndex>")).collect();
                let plain = format!(r#"<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{}</saml:NameID>"#, self.name_id);
                let name_id = match &self.encrypt_name_id_to {
                    Some(cert) => crate::sso::xmlenc::test_encrypter::Encrypt::default().encrypt_as("saml:EncryptedID", &plain, cert),
                    None => plain,
                };
                format!(
                    r#"<samlp:LogoutRequest xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{}" Version="2.0" IssueInstant="{at}"{dest}><saml:Issuer>{}</saml:Issuer>{name_id}{indexes}</samlp:LogoutRequest>"#,
                    self.id, self.issuer
                )
            } else {
                format!(
                    r#"<samlp:LogoutResponse xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{}" Version="2.0" IssueInstant="{at}"{dest} InResponseTo="{}"><saml:Issuer>{}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status></samlp:LogoutResponse>"#,
                    self.id, self.in_response_to, self.issuer, self.status
                )
            }
        }

        fn param(&self) -> &'static str {
            if self.is_request() { "SAMLRequest" } else { "SAMLResponse" }
        }

        /// The query string of the HTTP-Redirect binding, signed over the query.
        pub fn redirect(&self) -> String {
            self.redirect_xml(&self.xml())
        }

        pub fn redirect_xml(&self, xml: &str) -> String {
            let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
            let mut q = format!("{}={}", self.param(), enc(&saml_sp::redirect_encode(xml)));
            if let Some(r) = &self.relay {
                q += &format!("&RelayState={}", enc(r));
            }
            if let Some(s) = self.signer {
                q += &format!("&SigAlg={}", enc(signer(s).alg));
                let sig = signer(s).sign_raw(q.as_bytes());
                q += &format!("&Signature={}", enc(&sig));
            }
            q
        }

        /// The form of the HTTP-POST binding, with an enveloped signature.
        pub fn post(&self) -> HashMap<String, String> {
            let xml = self.xml();
            let xml = match self.signer {
                Some(s) => signer(s).sign(&xml, &self.id),
                None => xml,
            };
            let mut f = HashMap::from([(self.param().to_string(), STANDARD.encode(xml))]);
            f.extend(self.relay.clone().map(|r| ("RelayState".to_string(), r)));
            f
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_idp::Logout;
    use super::*;
    use crate::sso::saml_sp::test_idp::{IDP, metadata, with_slo};
    use crate::sso::saml_sp::{SpKey, parse_idp_metadata};
    use crate::sso::xmldsig::test_signer::{signer, signers};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    const SLO: &str = "https://bot.example.com/api/auth/sso/okta/slo";
    const NOW: i64 = 1_800_000_000_000;

    fn idp() -> IdpMetadata {
        parse_idp_metadata(&with_slo(&metadata()), IDP, false).unwrap()
    }

    fn redirect(l: &Logout) -> Result<Received, &'static str> {
        receive(&Incoming::Redirect(&l.redirect()), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).map_err(|e| e.0)
    }

    fn post(l: &Logout) -> Result<Received, &'static str> {
        receive(&Incoming::Post(&l.post()), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).map_err(|e| e.0)
    }

    fn request() -> Logout {
        Logout::request(SLO, "00u1ADA-Persistent", Some("_s1"), NOW)
    }

    #[test]
    fn a_signed_logout_request_names_the_person_and_their_idp_sessions() {
        let l = request();
        let want = Received::Request { id: l.id.clone(), name_id: "00u1ADA-Persistent".into(), session_indexes: vec!["_s1".into()], relay: Some("idp-relay".into()), issued_ms: NOW - 1_000, until_ms: NOW - 1_000 + MAX_AGE_MS + 2 * SKEW_MS };
        assert_eq!(redirect(&l).as_ref(), Ok(&want), "over HTTP-Redirect");
        assert_eq!(post(&l).as_ref(), Ok(&want), "over HTTP-POST, with the enveloped signature");
        let mut all = request();
        all.session_indexes.clear();
        assert!(matches!(redirect(&all), Ok(Received::Request { session_indexes, .. }) if session_indexes.is_empty()), "no SessionIndex: every session");
    }

    #[test]
    fn unsigned_or_badly_signed_logout_requests_are_refused() {
        let mut unsigned = request();
        unsigned.signer = None;
        assert_eq!(redirect(&unsigned), Err("unsigned"));
        assert_eq!(post(&unsigned), Err("unsigned"));
        let mut other = request();
        other.signer = Some(1);
        assert_eq!(redirect(&other), Err("bad_signature"), "signed, but not by the IdP");
        assert_eq!(post(&other), Err("bad_signature"));

        // The person changed after signing, on either binding.
        let l = request();
        let signed = l.redirect();
        let forged = Logout { name_id: "00u1EVE".into(), signer: None, ..l.clone() }.redirect();
        let q = format!("{}&{}", forged.split('&').next().unwrap(), signed.split_once('&').unwrap().1);
        assert_eq!(receive(&Incoming::Redirect(&q), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).unwrap_err().0, "bad_signature");
        let mut form = l.post();
        let xml = String::from_utf8(STANDARD.decode(&form["SAMLRequest"]).unwrap()).unwrap().replace("00u1ADA", "00u1EVE");
        form.insert("SAMLRequest".into(), STANDARD.encode(xml));
        assert_eq!(receive(&Incoming::Post(&form), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).unwrap_err().0, "bad_signature");

        // A signature over another element, or a second message beside the signed one.
        let mut form = l.post();
        let xml = String::from_utf8(STANDARD.decode(&form["SAMLRequest"]).unwrap()).unwrap();
        let moved = xml.replacen("<ds:Signature", "<samlp:Extensions><ds:Signature", 1).replacen("</ds:Signature>", "</ds:Signature></samlp:Extensions>", 1);
        form.insert("SAMLRequest".into(), STANDARD.encode(moved));
        assert_eq!(receive(&Incoming::Post(&form), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).unwrap_err().0, "wrapped");
        let doubled = xml.replacen("<saml:NameID", &format!(r#"<samlp:Extensions><x ID="{}"/></samlp:Extensions><saml:NameID"#, l.id), 1);
        form.insert("SAMLRequest".into(), STANDARD.encode(doubled));
        assert_eq!(receive(&Incoming::Post(&form), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).unwrap_err().0, "wrapped");
        let comment = xml.replace("00u1ADA-Persistent", "00u1ADA<!---->-Persistent");
        form.insert("SAMLRequest".into(), STANDARD.encode(comment));
        assert_eq!(receive(&Incoming::Post(&form), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).unwrap_err().0, "bad_message");
    }

    #[test]
    fn logout_requests_from_elsewhere_for_elsewhere_or_old_are_refused() {
        let with = |f: fn(&mut Logout)| {
            let mut l = request();
            f(&mut l);
            (redirect(&l).err().unwrap_or("ok"), post(&l).err().unwrap_or("ok"))
        };
        assert_eq!(with(|l| l.issuer = "https://evil.example/saml".into()), ("wrong_issuer", "wrong_issuer"));
        assert_eq!(with(|l| l.destination = Some("https://other.example/slo".into())), ("wrong_destination", "wrong_destination"));
        assert_eq!(with(|l| l.destination = None), ("wrong_destination", "wrong_destination"), "a signed message must say where it's for");
        assert_eq!(with(|l| l.issued_ms = NOW - MAX_AGE_MS - SKEW_MS - 1), ("expired", "expired"));
        assert_eq!(with(|l| l.issued_ms = NOW + SKEW_MS + 1_000), ("not_yet_valid", "not_yet_valid"));
        assert_eq!(with(|l| l.issued_ms = NOW - MAX_AGE_MS), ("ok", "ok"), "within the skew");
        assert_eq!(with(|l| l.name_id = String::new()), ("missing_subject", "missing_subject"));

        let l = request();
        let encrypted = l.xml().replacen(r#"<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">00u1ADA-Persistent</saml:NameID>"#, "<saml:EncryptedID><x/></saml:EncryptedID>", 1);
        let q = l.redirect_xml(&encrypted);
        assert_eq!(receive(&Incoming::Redirect(&q), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).unwrap_err().0, "encrypted_id");
        let expired = l.xml().replacen(r#" Version="2.0""#, &format!(r#" Version="2.0" NotOnOrAfter="{}""#, instant(NOW - SKEW_MS - 1)), 1);
        assert_eq!(receive(&Incoming::Redirect(&l.redirect_xml(&expired)), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).unwrap_err().0, "expired");
        let dtd = format!(r#"<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>{}"#, l.xml());
        assert_eq!(receive(&Incoming::Redirect(&l.redirect_xml(&dtd)), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).unwrap_err().0, "bad_message");
        let authn = l.xml().replace("LogoutRequest", "AuthnRequest");
        assert_eq!(receive(&Incoming::Redirect(&l.redirect_xml(&authn)), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).unwrap_err().0, "bad_message");
        let as_response = Logout::response(SLO, "_ours", NOW);
        let swapped = Logout { signer: None, ..l.clone() }.redirect().replacen("SAMLRequest=", "SAMLResponse=", 1);
        assert_eq!(receive(&Incoming::Redirect(&swapped), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: None }).unwrap_err().0, "bad_message", "a request posing as a response");
        assert!(redirect(&as_response).is_ok());
    }

    #[test]
    fn encrypted_name_ids_in_logout_requests_are_decrypted_with_our_key() {
        let (key, _) = SpKey::generate("SuperBot SAML SP encryption (okta)").unwrap();
        let (other, _) = SpKey::generate("someone else").unwrap();
        let mut l = request();
        l.encrypt_name_id_to = Some(key.cert.clone());
        let with = |k: Option<&SpKey>, form: &HashMap<String, String>| receive(&Incoming::Post(form), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: k }).map_err(|e| e.0);
        let form = l.post();
        assert!(matches!(with(Some(&key), &form), Ok(Received::Request { name_id, .. }) if name_id == "00u1ADA-Persistent"), "over HTTP-POST");
        let q = l.redirect();
        let got = receive(&Incoming::Redirect(&q), &Expect { idp: &idp(), slo_url: SLO, now_ms: NOW, decrypt: Some(&key) }).map_err(|e| e.0);
        assert!(matches!(got, Ok(Received::Request { name_id, .. }) if name_id == "00u1ADA-Persistent"), "over HTTP-Redirect");
        assert_eq!(with(None, &form), Err("encrypted_id"), "no encryption key: refused, as before");
        assert_eq!(with(Some(&other), &form), Err("bad_encryption"), "encrypted to another key");

        // Checked after the signature: an EncryptedID added beside the signed NameID is wrapping.
        let mut unsigned = l.clone();
        unsigned.signer = None;
        assert_eq!(with(Some(&key), &unsigned.post()), Err("unsigned"));
        let plain = request().post();
        let xml = String::from_utf8(STANDARD.decode(&plain["SAMLRequest"]).unwrap()).unwrap();
        let extra = crate::sso::xmlenc::test_encrypter::Encrypt::default().encrypt_as("saml:EncryptedID", r#"<saml:NameID>00u1EVE</saml:NameID>"#, &key.cert);
        let both = xml.replacen("<saml:NameID", &format!("{extra}<saml:NameID"), 1);
        let mut form = plain.clone();
        form.insert("SAMLRequest".into(), STANDARD.encode(both));
        assert_eq!(with(Some(&key), &form), Err("bad_signature"), "the signature covers the identifiers");
        let r = request();
        let both = r.xml().replacen("<saml:NameID", &format!("{extra}<saml:NameID"), 1);
        form.insert("SAMLRequest".into(), STANDARD.encode(signer(0).sign(&both, &r.id)));
        assert_eq!(with(Some(&key), &form), Err("wrapped"), "two identifiers, both signed");
    }

    #[test]
    fn ecdsa_signed_logout_requests_verify_against_an_ecdsa_idp_certificate() {
        for s in [2, 3] {
            let md = crate::sso::saml_sp::test_idp::metadata_signed_by(s);
            let idp = parse_idp_metadata(&with_slo(&md), IDP, false).unwrap();
            let mut l = request();
            l.signer = Some(s);
            for incoming in [Incoming::Redirect(&l.redirect()), Incoming::Post(&l.post())] {
                assert!(matches!(receive(&incoming, &Expect { idp: &idp, slo_url: SLO, now_ms: NOW, decrypt: None }), Ok(Received::Request { .. })), "signer {s}");
            }
            l.signer = Some(if s == 2 { 3 } else { 2 });
            assert_eq!(receive(&Incoming::Redirect(&l.redirect()), &Expect { idp: &idp, slo_url: SLO, now_ms: NOW, decrypt: None }).unwrap_err().0, "bad_signature", "the other curve's key");
        }
    }

    #[test]
    fn logout_responses_say_which_request_and_how_it_went() {
        let r = Logout::response(SLO, "_ours", NOW);
        assert_eq!(redirect(&r), Ok(Received::Response { id: r.id.clone(), in_response_to: "_ours".into(), status: None, until_ms: NOW - 1_000 + MAX_AGE_MS + 2 * SKEW_MS }));
        assert!(matches!(post(&r), Ok(Received::Response { status: None, .. })));
        let partial = Logout { status: "urn:oasis:names:tc:SAML:2.0:status:Responder".into(), ..r.clone() };
        assert!(matches!(redirect(&partial), Ok(Received::Response { status: Some(s), .. }) if s == "Responder"));
        let mut unsigned = r.clone();
        unsigned.signer = None;
        assert_eq!(redirect(&unsigned), Err("unsigned"));
        let wrong = Logout { issuer: "https://evil.example".into(), ..r };
        assert_eq!(redirect(&wrong), Err("wrong_issuer"));
    }

    #[test]
    fn our_logout_messages_are_what_the_idp_expects() {
        let login = SamlLogin {
            name_id: "00u1ADA&co".into(),
            format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into()),
            name_qualifier: Some(IDP.into()),
            sp_name_qualifier: None,
            session_index: Some("_s1".into()),
        };
        let xml = logout_request("https://bot.example.com/sp", "_req1", "https://idp.example/saml/slo", &login, NOW);
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let r = doc.root_element();
        assert!(is(r, PROTOCOL, "LogoutRequest"));
        assert_eq!((r.attribute("ID"), r.attribute("Destination"), r.attribute("Version")), (Some("_req1"), Some("https://idp.example/saml/slo"), Some("2.0")));
        let n = doc.descendants().find(|n| is(*n, ASSERTION, "NameID")).unwrap();
        assert_eq!((n.text(), n.attribute("Format"), n.attribute("NameQualifier"), n.attribute("SPNameQualifier")), (Some("00u1ADA&co"), login.format.as_deref(), Some(IDP), None));
        assert_eq!(doc.descendants().find(|n| is(*n, PROTOCOL, "SessionIndex")).and_then(|n| n.text()), Some("_s1"));
        assert_eq!(doc.descendants().find(|n| is(*n, ASSERTION, "Issuer")).and_then(|n| n.text()), Some("https://bot.example.com/sp"));
        let no_index = logout_request("sp:x", "_r", "https://idp.example/slo", &SamlLogin { session_index: None, ..login }, NOW);
        assert!(!no_index.contains("SessionIndex"));

        let xml = logout_response("https://bot.example.com/sp", "_res1", "https://idp.example/saml/slo", "_their<1>", NOW);
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let r = doc.root_element();
        assert!(is(r, PROTOCOL, "LogoutResponse"));
        assert_eq!((r.attribute("InResponseTo"), r.attribute("Destination")), (Some("_their<1>"), Some("https://idp.example/saml/slo")));
        assert!(xml.contains(SUCCESS));

        // Signed over the redirect binding with our key, as the IdP checks it.
        let (key, _) = SpKey::generate("sp").unwrap();
        let q = saml_sp::redirect_query("SAMLResponse", &xml, Some("idp-relay"), Some(&key));
        let back = saml_sp::from_redirect(&q).unwrap();
        assert_eq!((back.param, back.xml.as_str()), ("SAMLResponse", xml.as_str()));
        assert_eq!(back.verify(std::slice::from_ref(&key.info)), Ok(true));
        assert!(back.verify(&[signers()[0].cert()]).is_err());
    }
}
