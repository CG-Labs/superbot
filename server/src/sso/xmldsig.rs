//! XML signatures for native SAML (ADR 0127): a deliberately narrow verifier in Rust, with
//! no C XML stack and nothing that fetches, transforms, or runs anything.
//!
//! It takes only what SAML IdPs send: one enveloped `ds:Signature` per signed element, one
//! `Reference` to that element's own `ID`, the transforms enveloped-signature then Exclusive
//! C14N, RSA with SHA-256 or SHA-512, and keys from the configured IdP certificates (never
//! from `KeyInfo`). Anything else is refused, not interpreted. The HTTP-Redirect binding's
//! detached signature over a query string (ADR 0137) is checked with the same algorithms and keys.
//!
//! Documents are parsed with `roxmltree`, which refuses DTDs (so no entities, external or
//! otherwise). Comments and processing instructions are refused outright: canonicalization
//! drops comments, and a comment inside a NameID is how readers get tricked into a prefix of it.

use super::jwt::Invalid;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::{Document, Node, ParsingOptions};
use sha2::{Digest, Sha256, Sha512};

pub const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
/// A SAML response has a few dozen elements; this bounds what a hostile one costs to parse.
const MAX_NODES: u32 = 10_000;

/// Parses `xml` with no DTD, no comments, and no processing instructions.
pub fn parse(xml: &str) -> Result<Document<'_>, Invalid> {
    let opt = ParsingOptions { allow_dtd: false, nodes_limit: MAX_NODES, ..ParsingOptions::default() };
    let doc = Document::parse_with_options(xml, opt).map_err(|_| Invalid("bad_response"))?;
    if doc.descendants().any(|n| n.is_comment() || n.is_pi()) {
        return Err(Invalid("bad_response"));
    }
    Ok(doc)
}

/// The element is `{ns}name`.
pub fn is(n: Node, ns: &str, name: &str) -> bool {
    n.is_element() && n.tag_name().name() == name && n.tag_name().namespace() == Some(ns)
}

/// The element children of `n`, in order.
pub fn elements<'a, 'i>(n: Node<'a, 'i>) -> Vec<Node<'a, 'i>> {
    n.children().filter(Node::is_element).collect()
}

/// Base64 as XML carries it: wrapped across lines.
pub fn base64(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD.decode(clean).ok()
}

/// The element's name as written, with its prefix: the start tag up to the first space, `/` or `>`.
fn qname<'i>(n: Node<'_, 'i>) -> &'i str {
    let tag = &n.document().input_text()[n.range()];
    let rest = tag.get(1..).unwrap_or("");
    &rest[..rest.find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>').unwrap_or(rest.len())]
}

fn prefix(qname: &str) -> &str {
    qname.split_once(':').map_or("", |(p, _)| p)
}

fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// Exclusive XML Canonicalization 1.0, without comments, of `apex` and everything under it
/// except `skip` (the enveloped signature). `inclusive` is the transform's PrefixList.
pub fn exc_c14n(apex: Node, skip: Option<Node>, inclusive: &[String]) -> Result<String, Invalid> {
    let mut out = String::new();
    c14n_element(apex, skip, inclusive, &[], &mut out)?;
    Ok(out)
}

fn c14n_element(n: Node, skip: Option<Node>, inclusive: &[String], rendered: &[(String, String)], out: &mut String) -> Result<(), Invalid> {
    let text = n.document().input_text();
    let scope: Vec<(&str, &str)> = n.namespaces().map(|ns| (ns.name().unwrap_or(""), ns.uri())).filter(|(p, _)| *p != "xml").collect();
    let bound = |p: &str| scope.iter().find(|(q, _)| *q == p).map(|(_, u)| *u);
    let name = qname(n);
    let own = prefix(name);
    // The prefix as written must name the namespace the parser gave the element.
    if bound(own).unwrap_or("") != n.tag_name().namespace().unwrap_or("") {
        return Err(Invalid("bad_response"));
    }
    let mut used = vec![own];
    let mut attrs = Vec::new();
    for a in n.attributes() {
        let aq = &text[a.range_qname()];
        let ap = prefix(aq);
        if !ap.is_empty() && ap != "xml" {
            if bound(ap) != a.namespace() {
                return Err(Invalid("bad_response"));
            }
            used.push(ap);
        }
        attrs.push((a.namespace().unwrap_or(""), a.name(), aq, a.value()));
    }
    for p in inclusive {
        let p = if p == "#default" { "" } else { p.as_str() };
        if bound(p).is_some() {
            used.push(p);
        }
    }
    used.sort_unstable();
    used.dedup();
    let mut now = rendered.to_vec();
    let mut decls = Vec::new();
    for p in used {
        let uri = bound(p).unwrap_or("");
        let before = rendered.iter().find(|(q, _)| q == p).map_or("", |(_, u)| u.as_str());
        if uri != before {
            decls.push((p, uri));
            now.retain(|(q, _)| q != p);
            now.push((p.to_string(), uri.to_string()));
        }
    }
    attrs.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    out.push('<');
    out.push_str(name);
    for (p, uri) in decls {
        out.push_str(if p.is_empty() { " xmlns" } else { " xmlns:" });
        out.push_str(p);
        out.push_str("=\"");
        escape_attr(uri, out);
        out.push('"');
    }
    for (_, _, aq, v) in attrs {
        out.push(' ');
        out.push_str(aq);
        out.push_str("=\"");
        escape_attr(v, out);
        out.push('"');
    }
    out.push('>');
    for c in n.children() {
        if c.is_element() {
            if Some(c) != skip {
                c14n_element(c, skip, inclusive, &now, out)?;
            }
        } else if let Some(t) = c.text().filter(|_| c.is_text()) {
            escape_text(t, out);
        }
    }
    out.push_str("</");
    out.push_str(name);
    out.push('>');
    Ok(())
}

/// An IdP signing certificate from its metadata: RSA, at least 2048 bits.
#[derive(Clone, Debug)]
pub struct Cert {
    /// The RSAPublicKey (PKCS #1) inside the certificate.
    key: Vec<u8>,
    /// SHA-256 of the certificate, as admins compare it with the IdP's console.
    pub sha256: String,
    pub subject: String,
    /// Unix seconds. Not enforced (IdP certificates are self-signed trust anchors), but shown.
    pub not_after: i64,
}

impl Cert {
    /// Whether two certificates are for the same key, whatever else differs.
    pub fn same_key(&self, other: &Cert) -> bool {
        self.key == other.key
    }

    pub fn from_base64(b64: &str) -> Result<Cert, String> {
        let der = base64(b64).ok_or("a certificate isn't base64")?;
        let (rest, c) = x509_parser::parse_x509_certificate(&der).map_err(|_| "a certificate isn't X.509".to_string())?;
        if !rest.is_empty() {
            return Err("a certificate has trailing bytes".into());
        }
        let spki = c.public_key();
        let bits = match spki.parsed() {
            Ok(x509_parser::public_key::PublicKey::RSA(k)) => k.key_size(),
            _ => return Err("only RSA signing certificates are supported".into()),
        };
        if bits < 2048 {
            return Err(format!("a {bits}-bit RSA key is too short (2048 at least)"));
        }
        let sha256 = Sha256::digest(&der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
        Ok(Cert { key: spki.subject_public_key.data.to_vec(), sha256, subject: c.subject().to_string(), not_after: c.validity().not_after.timestamp() })
    }
}

/// The PrefixList of a c14n transform's `InclusiveNamespaces`, the only child it may have.
fn inclusive_prefixes(method: Node) -> Result<Vec<String>, Invalid> {
    match elements(method).as_slice() {
        [] => Ok(Vec::new()),
        [inc] if is(*inc, EXC_C14N, "InclusiveNamespaces") => Ok(inc.attribute("PrefixList").unwrap_or("").split_ascii_whitespace().map(String::from).collect()),
        _ => Err(Invalid("bad_algorithm")),
    }
}

/// The RSA verification `alg` (a SignatureMethod URI) names: SHA-256 or SHA-512, never SHA-1.
fn rsa_algorithm(alg: &str) -> Result<&'static aws_lc_rs::signature::RsaParameters, Invalid> {
    match alg {
        RSA_SHA256 => Ok(&aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256),
        RSA_SHA512 => Ok(&aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA512),
        RSA_SHA1 => Err(Invalid("weak_algorithm")),
        _ => Err(Invalid("bad_algorithm")),
    }
}

/// A detached signature over `data` by one of `certs`, as the HTTP-Redirect binding signs its
/// query string: the same algorithms and keys as an enveloped signature, and no XML.
pub fn verify_raw(alg: &str, data: &[u8], signature: &[u8], certs: &[Cert]) -> Result<(), Invalid> {
    let rsa = rsa_algorithm(alg)?;
    let ok = certs.iter().any(|c| aws_lc_rs::signature::UnparsedPublicKey::new(rsa, &c.key).verify(data, signature).is_ok());
    if ok { Ok(()) } else { Err(Invalid("bad_signature")) }
}

fn algorithm<'a>(n: Node<'a, '_>, name: &str) -> Result<&'a str, Invalid> {
    if !is(n, DSIG, name) {
        return Err(Invalid("bad_signature"));
    }
    n.attribute("Algorithm").ok_or(Invalid("bad_algorithm"))
}

/// Checks the enveloped signature of `signed` (its direct `ds:Signature` child) with one of
/// `certs`. Ok(false): it has none. Err: it has one that doesn't verify, or isn't one we take.
pub fn verify_enveloped(signed: Node, certs: &[Cert]) -> Result<bool, Invalid> {
    let sigs: Vec<Node> = signed.children().filter(|c| is(*c, DSIG, "Signature")).collect();
    let sig = match sigs.as_slice() {
        [] => return Ok(false),
        [s] => *s,
        _ => return Err(Invalid("wrapped")),
    };
    let id = signed.attribute("ID").ok_or(Invalid("wrapped"))?;
    let (signed_info, value) = match elements(sig).as_slice() {
        [si, sv] => (*si, *sv),
        [si, sv, ki] if is(*ki, DSIG, "KeyInfo") => (*si, *sv),
        _ => return Err(Invalid("bad_signature")),
    };
    if !is(signed_info, DSIG, "SignedInfo") || !is(value, DSIG, "SignatureValue") {
        return Err(Invalid("bad_signature"));
    }
    let [c14n, method, reference] = elements(signed_info)[..] else {
        return Err(Invalid("bad_signature"));
    };
    if algorithm(c14n, "CanonicalizationMethod")? != EXC_C14N {
        return Err(Invalid("bad_algorithm"));
    }
    let signed_info_prefixes = inclusive_prefixes(c14n)?;
    let rsa = rsa_algorithm(algorithm(method, "SignatureMethod")?)?;
    if !is(reference, DSIG, "Reference") {
        return Err(Invalid("bad_signature"));
    }
    // The signature covers the element it sits in, and nothing else.
    if reference.attribute("URI") != Some(format!("#{id}").as_str()) {
        return Err(Invalid("wrapped"));
    }
    let [transforms, digest_method, digest_value] = elements(reference)[..] else {
        return Err(Invalid("bad_signature"));
    };
    if !is(transforms, DSIG, "Transforms") || !is(digest_value, DSIG, "DigestValue") {
        return Err(Invalid("bad_signature"));
    }
    let [enveloped, exc] = elements(transforms)[..] else {
        return Err(Invalid("bad_algorithm"));
    };
    if algorithm(enveloped, "Transform")? != ENVELOPED || !elements(enveloped).is_empty() || algorithm(exc, "Transform")? != EXC_C14N {
        return Err(Invalid("bad_algorithm"));
    }
    let reference_prefixes = inclusive_prefixes(exc)?;
    let canonical = exc_c14n(signed, Some(sig), &reference_prefixes)?;
    let digest = match algorithm(digest_method, "DigestMethod")? {
        SHA256 => Sha256::digest(canonical.as_bytes()).to_vec(),
        SHA512 => Sha512::digest(canonical.as_bytes()).to_vec(),
        SHA1 => return Err(Invalid("weak_algorithm")),
        _ => return Err(Invalid("bad_algorithm")),
    };
    let claimed = base64(digest_value.text().unwrap_or("")).ok_or(Invalid("bad_signature"))?;
    if !crate::same(&digest, &claimed) {
        return Err(Invalid("bad_signature"));
    }
    let info = exc_c14n(signed_info, None, &signed_info_prefixes)?;
    let value = base64(value.text().unwrap_or("")).ok_or(Invalid("bad_signature"))?;
    let ok = certs.iter().any(|c| aws_lc_rs::signature::UnparsedPublicKey::new(rsa, &c.key).verify(info.as_bytes(), &value).is_ok());
    if ok { Ok(true) } else { Err(Invalid("bad_signature")) }
}

#[cfg(test)]
pub mod test_signer {
    //! Signs SAML the way an IdP does, with a fresh RSA key and a self-signed certificate.

    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::KeyPair;
    use std::sync::OnceLock;

    pub struct Signer {
        pair: KeyPair,
        /// The certificate, base64 DER, as metadata carries it.
        pub cert: String,
    }

    impl Signer {
        fn new(cn: &str) -> Signer {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.distinguished_name.push(rcgen::DnType::CommonName, cn);
            let cert = params.self_signed(&key).unwrap();
            let pair = KeyPair::from_pkcs8(&key.serialize_der()).unwrap();
            assert_eq!(pair.public_modulus_len(), 256);
            Signer { pair, cert: STANDARD.encode(cert.der()) }
        }

        pub fn cert(&self) -> Cert {
            Cert::from_base64(&self.cert).unwrap()
        }

        pub fn rsa_sha256(&self, data: &[u8]) -> String {
            let mut sig = vec![0; self.pair.public_modulus_len()];
            self.pair.sign(&aws_lc_rs::signature::RSA_PKCS1_SHA256, &SystemRandom::new(), data, &mut sig).unwrap();
            STANDARD.encode(sig)
        }

        /// `xml` with an enveloped signature added to the element whose ID is `id`, right
        /// after its first child (the Issuer), as IdPs place it.
        pub fn sign(&self, xml: &str, id: &str) -> String {
            let doc = parse(xml).unwrap();
            let el = doc.descendants().find(|n| n.attribute("ID") == Some(id)).unwrap();
            let digest = STANDARD.encode(Sha256::digest(exc_c14n(el, None, &[]).unwrap().as_bytes()));
            let signed_info = format!(
                r##"<ds:SignedInfo xmlns:ds="{DSIG}"><ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/><ds:Transform Algorithm="{EXC_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
            );
            let info = parse(&signed_info).unwrap();
            let value = self.rsa_sha256(exc_c14n(info.root_element(), None, &[]).unwrap().as_bytes());
            let body = signed_info.replacen(&format!(r#"<ds:SignedInfo xmlns:ds="{DSIG}">"#), "<ds:SignedInfo>", 1);
            let sig = format!(
                r#"<ds:Signature xmlns:ds="{DSIG}">{body}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
                self.cert
            );
            let first = el.first_element_child().unwrap();
            let at = first.range().end;
            format!("{}{sig}{}", &xml[..at], &xml[at..])
        }
    }

    /// Two IdP keys, made once per test run (RSA key generation is slow).
    pub fn signers() -> &'static [Signer; 2] {
        static S: OnceLock<[Signer; 2]> = OnceLock::new();
        S.get_or_init(|| [Signer::new("idp.example"), Signer::new("other.example")])
    }
}

#[cfg(test)]
mod tests {
    use super::test_signer::signers;
    use super::*;

    fn c14n(xml: &str, inclusive: &[&str]) -> String {
        let doc = parse(xml).unwrap();
        let incl: Vec<String> = inclusive.iter().map(|s| s.to_string()).collect();
        exc_c14n(doc.root_element().first_element_child().unwrap_or(doc.root_element()), None, &incl).unwrap()
    }

    /// Expected outputs from libxml2's exclusive C14N (lxml `method="c14n", exclusive=True`).
    #[test]
    fn exclusive_c14n_matches_libxml2() {
        let cases: [(&str, &[&str], &str); 7] = [
            (
                r#"<r xmlns:a="urn:a" xmlns:b="urn:b" xmlns="urn:d"><a:e b:z="1" y='2' a:x="3" xmlns:c="urn:c">t &amp; &lt; &gt; "q"</a:e></r>"#,
                &[],
                r#"<a:e xmlns:a="urn:a" xmlns:b="urn:b" y="2" a:x="3" b:z="1">t &amp; &lt; &gt; "q"</a:e>"#,
            ),
            (r#"<r xmlns="urn:d"><e><f/></e></r>"#, &[], r#"<e xmlns="urn:d"><f></f></e>"#),
            (r#"<r xmlns="urn:d"><e xmlns=""><f/></e></r>"#, &[], r#"<e><f></f></e>"#),
            (r#"<r><e xmlns="urn:d"><f xmlns=""/></e></r>"#, &[], r#"<e xmlns="urn:d"><f xmlns=""></f></e>"#),
            (r#"<r xmlns:xs="urn:xs" xmlns:xsi="urn:xsi"><v xsi:type="xs:string">a</v></r>"#, &["xs"], r#"<v xmlns:xs="urn:xs" xmlns:xsi="urn:xsi" xsi:type="xs:string">a</v>"#),
            (r#"<r xmlns:p="urn:p"><p:e><p:f xmlns:p="urn:p"/><p:g xmlns:p="urn:other"/></p:e></r>"#, &[], r#"<p:e xmlns:p="urn:p"><p:f></p:f><p:g xmlns:p="urn:other"></p:g></p:e>"#),
            ("<r><e a=\"x&#9;y&#10;z&#13;\">l1\r\nl2&#13;</e></r>", &[], "<e a=\"x&#x9;y&#xA;z&#xD;\">l1\nl2&#xD;</e>"),
        ];
        for (xml, inc, want) in cases {
            assert_eq!(c14n(xml, inc), want, "{xml}");
        }
    }

    #[test]
    fn parsing_refuses_dtds_comments_and_processing_instructions() {
        assert!(parse(r#"<?xml version="1.0" encoding="UTF-8"?><r/>"#).is_ok(), "the XML declaration is fine");
        for bad in [
            r#"<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#,
            r#"<!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><r>&b;</r>"#,
            "<r><n>ada@example.com<!-- -->.evil.example</n></r>",
            "<r><?pi x?></r>",
            "<r><unclosed></r>",
            "<r>&unknown;</r>",
        ] {
            assert_eq!(parse(bad).err(), Some(Invalid("bad_response")), "{bad}");
        }
    }

    const DOC: &str =
        r#"<p:Response xmlns:p="urn:p" xmlns:a="urn:a" ID="r1"><a:Issuer>idp</a:Issuer><a:Assertion ID="a1"><a:Issuer>idp</a:Issuer><a:Subject>ada</a:Subject></a:Assertion></p:Response>"#;

    fn assertion<'a, 'i>(d: &'a Document<'i>) -> Node<'a, 'i> {
        d.descendants().find(|n| n.attribute("ID") == Some("a1")).unwrap()
    }

    #[test]
    fn verifies_an_enveloped_signature_and_nothing_looser() {
        let [idp, other] = signers();
        let signed = idp.sign(DOC, "a1");
        let doc = parse(&signed).unwrap();
        assert_eq!(verify_enveloped(assertion(&doc), &[idp.cert()]), Ok(true));
        assert_eq!(verify_enveloped(assertion(&doc), &[other.cert(), idp.cert()]), Ok(true), "any configured certificate");
        assert_eq!(verify_enveloped(assertion(&doc), &[other.cert()]), Err(Invalid("bad_signature")), "signed by someone else");
        assert_eq!(verify_enveloped(assertion(&doc), &[]), Err(Invalid("bad_signature")));
        assert_eq!(verify_enveloped(doc.root_element(), &[idp.cert()]), Ok(false), "the response itself is unsigned");

        let swap = |from: &str, to: &str| {
            let s = signed.replacen(from, to, 1);
            assert_ne!(s, signed, "{from}");
            let d = parse(&s).map_err(|e| e.0)?;
            let el = d.descendants().find(|n| n.attribute("ID") == Some("a1")).or_else(|| d.descendants().find(|n| n.tag_name().name() == "Assertion")).unwrap();
            verify_enveloped(el, &[idp.cert()]).map_err(|e| e.0)
        };
        assert_eq!(swap("<a:Subject>ada<", "<a:Subject>eve<"), Err("bad_signature"), "the person changed under a good signature");
        assert_eq!(swap(r##"URI="#a1""##, r##"URI="#r1""##), Err("wrapped"), "a signature over another element");
        assert_eq!(swap(r##"URI="#a1""##, r#"URI="""#), Err("wrapped"), "the whole document");
        assert_eq!(swap(&format!(r#"Algorithm="{RSA_SHA256}""#), &format!(r#"Algorithm="{RSA_SHA1}""#)), Err("weak_algorithm"));
        assert_eq!(swap(&format!(r#"Algorithm="{SHA256}""#), &format!(r#"Algorithm="{SHA1}""#)), Err("weak_algorithm"));
        assert_eq!(
            swap(&format!(r#"<ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/>"#), r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>"#),
            Err("bad_algorithm")
        );
        assert_eq!(swap(&format!(r#"<ds:Transform Algorithm="{ENVELOPED}"/>"#), r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"/>"#), Err("bad_algorithm"), "no XSLT");
        assert_eq!(swap(&format!(r#"<ds:Transform Algorithm="{ENVELOPED}"/>"#), ""), Err("bad_algorithm"));
        assert_eq!(swap("<ds:SignatureValue>", "<ds:SignatureValue>AAAA"), Err("bad_signature"));
        assert_eq!(swap("</ds:Signature>", &format!("</ds:Signature><ds:Signature xmlns:ds=\"{DSIG}\"/>")), Err("wrapped"), "two signatures");
        assert_eq!(swap("<ds:KeyInfo>", "<ds:Object/><ds:KeyInfo>"), Err("bad_signature"));
    }

    /// Signed by xmlsec1 (libxml2's canonicalizer), with an inclusive prefix declared on an
    /// ancestor: an independent check that our canonical form is the one IdPs sign.
    #[test]
    fn verifies_what_xmlsec1_signed() {
        let (xml, cert) = (include_str!("testdata/xmlsec-signed.xml"), Cert::from_base64(include_str!("testdata/xmlsec-cert.b64")).unwrap());
        let check = |xml: &str| {
            let doc = parse(xml).map_err(|e| e.0)?;
            let a = doc.descendants().find(|n| n.tag_name().name() == "Assertion").unwrap();
            verify_enveloped(a, std::slice::from_ref(&cert)).map_err(|e| e.0)
        };
        assert_eq!(check(xml), Ok(true));
        assert_eq!(check(&xml.replace("Ada-1", "Ada-2")), Err("bad_signature"));
        assert_eq!(check(&xml.replace(r#"xsi:type="xs:string""#, r#"xsi:type="xs:token""#)), Err("bad_signature"));
        assert_eq!(check(&xml.replace(r#"PrefixList="xs""#, r#"PrefixList="""#)), Err("bad_signature"), "the prefix list is signed too");
        assert_eq!(check(&xml.replace("<samlp:Response ", "<samlp:Response xmlns:extra=\"urn:x\" ")), Ok(true), "unused ancestor namespaces don't count");
        assert_eq!(check(&xml.replace(">ada@example.com<", ">ada@example.com<!-- -->.evil<")), Err("bad_response"));
    }

    #[test]
    fn verifies_a_detached_signature_with_the_same_rules() {
        let [idp, other] = signers();
        let data = b"SAMLRequest=abc&RelayState=x&SigAlg=y";
        let sig = STANDARD.decode(idp.rsa_sha256(data)).unwrap();
        assert_eq!(verify_raw(RSA_SHA256, data, &sig, &[other.cert(), idp.cert()]), Ok(()));
        assert_eq!(verify_raw(RSA_SHA256, data, &sig, &[other.cert()]), Err(Invalid("bad_signature")));
        assert_eq!(verify_raw(RSA_SHA256, b"SAMLRequest=abd&RelayState=x&SigAlg=y", &sig, &[idp.cert()]), Err(Invalid("bad_signature")));
        assert_eq!(verify_raw(RSA_SHA256, data, &sig, &[]), Err(Invalid("bad_signature")));
        assert_eq!(verify_raw(RSA_SHA1, data, &sig, &[idp.cert()]), Err(Invalid("weak_algorithm")));
        assert_eq!(verify_raw("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", data, &sig, &[idp.cert()]), Err(Invalid("bad_algorithm")));
    }

    #[test]
    fn certificates_must_be_rsa_2048_or_more() {
        let c = signers()[0].cert();
        assert_eq!(c.sha256.len(), 95);
        assert!(c.subject.contains("idp.example") && c.not_after > 0);
        assert!(Cert::from_base64("not base64!").is_err());
        assert!(Cert::from_base64("AAAA").is_err());
        let ec = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ec_cert = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap().self_signed(&ec).unwrap();
        assert!(Cert::from_base64(&STANDARD.encode(ec_cert.der())).unwrap_err().contains("only RSA"));
    }
}
