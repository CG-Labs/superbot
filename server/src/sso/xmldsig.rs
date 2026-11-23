//! XML signatures for native SAML (ADR 0127): a deliberately narrow verifier in Rust, with
//! no C XML stack and nothing that fetches, transforms, or runs anything.
//!
//! It takes only what SAML IdPs send: one enveloped `ds:Signature` per signed element, one
//! `Reference` to that element's own `ID`, the transforms enveloped-signature then Exclusive
//! C14N, RSA with SHA-256 or SHA-512 or ECDSA on P-256 with SHA-256 or P-384 with SHA-384
//! (ADR 0151), and keys from the configured IdP certificates (never from `KeyInfo`). Anything
//! else is refused, not interpreted. The HTTP-Redirect binding's detached signature over a
//! query string (ADR 0137) is checked with the same algorithms and keys.
//!
//! Documents are parsed with `roxmltree`, which refuses DTDs (so no entities, external or
//! otherwise). Comments and processing instructions are refused outright: canonicalization
//! drops comments, and a comment inside a NameID is how readers get tricked into a prefix of it.

use super::jwt::Invalid;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::{Document, Node, ParsingOptions};
use sha2::{Digest, Sha256, Sha384, Sha512};

pub const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
pub const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
const ECDSA_SHA1: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
/// A SAML response has a few dozen elements; this bounds what a hostile one costs to parse.
const MAX_NODES: u32 = 10_000;
/// Deeper than any SAML message or metadata nests; canonicalization recurses this far at most.
const MAX_DEPTH: usize = 128;

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
    c14n_element(apex, skip, inclusive, &[], 0, &mut out)?;
    Ok(out)
}

fn c14n_element(n: Node, skip: Option<Node>, inclusive: &[String], rendered: &[(String, String)], depth: usize, out: &mut String) -> Result<(), Invalid> {
    if depth > MAX_DEPTH {
        return Err(Invalid("bad_response"));
    }
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
                c14n_element(c, skip, inclusive, &now, depth + 1, out)?;
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

/// What a certificate's key is. Each signature algorithm is tried only with keys of its kind.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyKind {
    Rsa,
    P256,
    P384,
}

/// An IdP signing certificate from its metadata: RSA of at least 2048 bits, or ECDSA on
/// P-256 or P-384 (ADR 0151).
#[derive(Clone, Debug)]
pub struct Cert {
    pub kind: KeyKind,
    /// The RSAPublicKey (PKCS #1), or the uncompressed EC point, inside the certificate.
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
        let kind = match spki.parsed() {
            Ok(x509_parser::public_key::PublicKey::RSA(k)) if k.key_size() < 2048 => return Err(format!("a {}-bit RSA key is too short (2048 at least)", k.key_size())),
            Ok(x509_parser::public_key::PublicKey::RSA(_)) => KeyKind::Rsa,
            Ok(x509_parser::public_key::PublicKey::EC(_)) => match spki.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok()).map(|o| o.to_id_string()).as_deref() {
                Some("1.2.840.10045.3.1.7") => KeyKind::P256,
                Some("1.3.132.0.34") => KeyKind::P384,
                _ => return Err("only P-256 and P-384 ECDSA certificates are supported".into()),
            },
            _ => return Err("only RSA and ECDSA (P-256, P-384) signing certificates are supported".into()),
        };
        let sha256 = Sha256::digest(&der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
        Ok(Cert { kind, key: spki.subject_public_key.data.to_vec(), sha256, subject: c.subject().to_string(), not_after: c.validity().not_after.timestamp() })
    }

    /// Whether `signature` over `data` is this key's, by `alg` (which must be for its kind).
    fn verifies(&self, alg: (KeyKind, &'static dyn aws_lc_rs::signature::VerificationAlgorithm), data: &[u8], signature: &[u8]) -> bool {
        self.kind == alg.0 && aws_lc_rs::signature::UnparsedPublicKey::new(alg.1, &self.key).verify(data, signature).is_ok()
    }
}

/// The certificates in a PEM file (or one base64 DER certificate without armour), for a
/// trust anchor that may hold several during a rollover.
pub fn certs_from_pem(pem: &str) -> Result<Vec<Cert>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if !pem.contains(BEGIN) {
        return Ok(vec![Cert::from_base64(pem)?]);
    }
    let mut certs = Vec::new();
    let mut rest = pem;
    while let Some(b) = rest.find(BEGIN) {
        let after = &rest[b + BEGIN.len()..];
        let e = after.find(END).ok_or("a certificate has no END line")?;
        certs.push(Cert::from_base64(&after[..e])?);
        rest = &after[e + END.len()..];
    }
    Ok(certs)
}

/// The PrefixList of a c14n transform's `InclusiveNamespaces`, the only child it may have.
fn inclusive_prefixes(method: Node) -> Result<Vec<String>, Invalid> {
    match elements(method).as_slice() {
        [] => Ok(Vec::new()),
        [inc] if is(*inc, EXC_C14N, "InclusiveNamespaces") => Ok(inc.attribute("PrefixList").unwrap_or("").split_ascii_whitespace().map(String::from).collect()),
        _ => Err(Invalid("bad_algorithm")),
    }
}

/// The key kind and verification `alg` (a SignatureMethod or SigAlg URI) names: RSA with
/// SHA-256 or SHA-512, or ECDSA on P-256 with SHA-256 or P-384 with SHA-384, never SHA-1.
/// ECDSA signatures are `r || s` of the curve's size, as XML-DSig 1.1 has them, not DER.
fn signature_algorithm(alg: &str) -> Result<(KeyKind, &'static dyn aws_lc_rs::signature::VerificationAlgorithm), Invalid> {
    use aws_lc_rs::signature as s;
    match alg {
        RSA_SHA256 => Ok((KeyKind::Rsa, &s::RSA_PKCS1_2048_8192_SHA256)),
        RSA_SHA512 => Ok((KeyKind::Rsa, &s::RSA_PKCS1_2048_8192_SHA512)),
        ECDSA_SHA256 => Ok((KeyKind::P256, &s::ECDSA_P256_SHA256_FIXED)),
        ECDSA_SHA384 => Ok((KeyKind::P384, &s::ECDSA_P384_SHA384_FIXED)),
        RSA_SHA1 | ECDSA_SHA1 => Err(Invalid("weak_algorithm")),
        _ => Err(Invalid("bad_algorithm")),
    }
}

/// A detached signature over `data` by one of `certs`, as the HTTP-Redirect binding signs its
/// query string: the same algorithms and keys as an enveloped signature, and no XML.
pub fn verify_raw(alg: &str, data: &[u8], signature: &[u8], certs: &[Cert]) -> Result<(), Invalid> {
    let alg = signature_algorithm(alg)?;
    if certs.iter().any(|c| c.verifies(alg, data, signature)) { Ok(()) } else { Err(Invalid("bad_signature")) }
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
    let alg = signature_algorithm(algorithm(method, "SignatureMethod")?)?;
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
        SHA384 => Sha384::digest(canonical.as_bytes()).to_vec(),
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
    if certs.iter().any(|c| c.verifies(alg, info.as_bytes(), &value)) { Ok(true) } else { Err(Invalid("bad_signature")) }
}

/// `xml` (one message, whose root has `ID` = `id` and an `Issuer` first) with an enveloped
/// signature after its Issuer, as SAML's schema places it: exactly the shape
/// `verify_enveloped` takes, SHA-256 digest, `sign` making the `alg` signature over the
/// canonical SignedInfo, and `cert` (base64 DER) in its KeyInfo. For the SOAP binding, which
/// has no signature of its own (ADR 0208).
pub fn sign_enveloped(xml: &str, id: &str, alg: &str, cert: &str, sign: impl Fn(&[u8]) -> Vec<u8>) -> Result<String, Invalid> {
    let doc = parse(xml)?;
    let root = doc.root_element();
    if root.attribute("ID") != Some(id) {
        return Err(Invalid("bad_response"));
    }
    let first = root.first_element_child().ok_or(Invalid("bad_response"))?;
    let digest = STANDARD.encode(Sha256::digest(exc_c14n(root, None, &[])?.as_bytes()));
    let signed_info = format!(
        r##"<ds:SignedInfo xmlns:ds="{DSIG}"><ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/><ds:SignatureMethod Algorithm="{alg}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/><ds:Transform Algorithm="{EXC_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="{SHA256}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
    );
    let info = parse(&signed_info)?;
    let value = STANDARD.encode(sign(exc_c14n(info.root_element(), None, &[])?.as_bytes()));
    // Inside the Signature, which declares ds:, the SignedInfo canonicalizes the same.
    let body = signed_info.replacen(&format!(r#"<ds:SignedInfo xmlns:ds="{DSIG}">"#), "<ds:SignedInfo>", 1);
    let sig = format!(r#"<ds:Signature xmlns:ds="{DSIG}">{body}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#);
    let at = first.range().end;
    Ok(format!("{}{sig}{}", &xml[..at], &xml[at..]))
}

#[cfg(test)]
pub mod test_signer {
    //! Signs SAML the way an IdP does, with a fresh key (RSA, or ECDSA on P-256 or P-384) and
    //! a self-signed certificate.

    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::KeyPair;
    use aws_lc_rs::signature::EcdsaKeyPair;
    use std::sync::OnceLock;

    enum Key {
        Rsa(KeyPair),
        Ec(EcdsaKeyPair),
    }

    pub struct Signer {
        key: Key,
        /// The SignatureMethod (and SigAlg) it signs with.
        pub alg: &'static str,
        /// The certificate, base64 DER, as metadata carries it.
        pub cert: String,
    }

    impl Signer {
        fn new(cn: &str, kind: KeyKind) -> Signer {
            let rc = match kind {
                KeyKind::Rsa => &rcgen::PKCS_RSA_SHA256,
                KeyKind::P256 => &rcgen::PKCS_ECDSA_P256_SHA256,
                KeyKind::P384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            };
            let key = rcgen::KeyPair::generate_for(rc).unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.distinguished_name.push(rcgen::DnType::CommonName, cn);
            let cert = params.self_signed(&key).unwrap();
            let der = key.serialize_der();
            let (key, alg) = match kind {
                KeyKind::Rsa => (Key::Rsa(KeyPair::from_pkcs8(&der).unwrap()), RSA_SHA256),
                KeyKind::P256 => (Key::Ec(EcdsaKeyPair::from_pkcs8(&aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &der).unwrap()), ECDSA_SHA256),
                KeyKind::P384 => (Key::Ec(EcdsaKeyPair::from_pkcs8(&aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED_SIGNING, &der).unwrap()), ECDSA_SHA384),
            };
            Signer { key, alg, cert: STANDARD.encode(cert.der()) }
        }

        pub fn cert(&self) -> Cert {
            Cert::from_base64(&self.cert).unwrap()
        }

        /// A signature over `data` with `alg`, base64.
        pub fn sign_raw(&self, data: &[u8]) -> String {
            match &self.key {
                Key::Rsa(pair) => {
                    let mut sig = vec![0; pair.public_modulus_len()];
                    pair.sign(&aws_lc_rs::signature::RSA_PKCS1_SHA256, &SystemRandom::new(), data, &mut sig).unwrap();
                    STANDARD.encode(sig)
                }
                Key::Ec(pair) => STANDARD.encode(pair.sign(&SystemRandom::new(), data).unwrap()),
            }
        }

        /// `xml` with an enveloped signature added to the element whose ID is `id`, right
        /// after its first child (the Issuer), as IdPs place it. P-384 keys digest with SHA-384.
        pub fn sign(&self, xml: &str, id: &str) -> String {
            let doc = parse(xml).unwrap();
            let el = doc.descendants().find(|n| n.attribute("ID") == Some(id)).unwrap();
            let canonical = exc_c14n(el, None, &[]).unwrap();
            let (digest_alg, digest) = match self.alg {
                ECDSA_SHA384 => (SHA384, STANDARD.encode(Sha384::digest(canonical.as_bytes()))),
                _ => (SHA256, STANDARD.encode(Sha256::digest(canonical.as_bytes()))),
            };
            let signed_info = format!(
                r##"<ds:SignedInfo xmlns:ds="{DSIG}"><ds:CanonicalizationMethod Algorithm="{EXC_C14N}"/><ds:SignatureMethod Algorithm="{}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="{ENVELOPED}"/><ds:Transform Algorithm="{EXC_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="{digest_alg}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
                self.alg
            );
            let info = parse(&signed_info).unwrap();
            let value = self.sign_raw(exc_c14n(info.root_element(), None, &[]).unwrap().as_bytes());
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
        S.get_or_init(|| [Signer::new("idp.example", KeyKind::Rsa), Signer::new("other.example", KeyKind::Rsa)])
    }

    /// Two ECDSA IdP keys: P-256 and P-384.
    pub fn ec_signers() -> &'static [Signer; 2] {
        static S: OnceLock<[Signer; 2]> = OnceLock::new();
        S.get_or_init(|| [Signer::new("ec256.idp.example", KeyKind::P256), Signer::new("ec384.idp.example", KeyKind::P384)])
    }

    /// Every test key by number: the two RSA ones, then P-256 and P-384.
    pub fn signer(i: usize) -> &'static Signer {
        if i < 2 { &signers()[i] } else { &ec_signers()[i - 2] }
    }
}

#[cfg(test)]
mod tests {
    use super::test_signer::{ec_signers, signers};
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
        let sig = STANDARD.decode(idp.sign_raw(data)).unwrap();
        assert_eq!(verify_raw(RSA_SHA256, data, &sig, &[other.cert(), idp.cert()]), Ok(()));
        assert_eq!(verify_raw(RSA_SHA256, data, &sig, &[other.cert()]), Err(Invalid("bad_signature")));
        assert_eq!(verify_raw(RSA_SHA256, b"SAMLRequest=abd&RelayState=x&SigAlg=y", &sig, &[idp.cert()]), Err(Invalid("bad_signature")));
        assert_eq!(verify_raw(RSA_SHA256, data, &sig, &[]), Err(Invalid("bad_signature")));
        assert_eq!(verify_raw(RSA_SHA1, data, &sig, &[idp.cert()]), Err(Invalid("weak_algorithm")));
        assert_eq!(verify_raw(ECDSA_SHA256, data, &sig, &[idp.cert()]), Err(Invalid("bad_signature")), "an ECDSA algorithm never tries an RSA key");
        assert_eq!(verify_raw("http://www.w3.org/2001/04/xmldsig-more#rsa-md5", data, &sig, &[idp.cert()]), Err(Invalid("bad_algorithm")));
    }

    #[test]
    fn certificates_must_be_rsa_2048_or_more_or_p256_or_p384() {
        let c = signers()[0].cert();
        assert_eq!((c.sha256.len(), c.kind), (95, KeyKind::Rsa));
        assert!(c.subject.contains("idp.example") && c.not_after > 0);
        assert!(Cert::from_base64("not base64!").is_err());
        assert!(Cert::from_base64("AAAA").is_err());
        let cert_for = |alg: &'static rcgen::SignatureAlgorithm| {
            let k = rcgen::KeyPair::generate_for(alg).unwrap();
            STANDARD.encode(rcgen::CertificateParams::new(Vec::<String>::new()).unwrap().self_signed(&k).unwrap().der())
        };
        assert_eq!(Cert::from_base64(&cert_for(&rcgen::PKCS_ECDSA_P256_SHA256)).unwrap().kind, KeyKind::P256);
        assert_eq!(Cert::from_base64(&cert_for(&rcgen::PKCS_ECDSA_P384_SHA384)).unwrap().kind, KeyKind::P384);
        assert!(Cert::from_base64(&cert_for(&rcgen::PKCS_ED25519)).unwrap_err().contains("only RSA and ECDSA"));
    }

    #[test]
    fn verifies_ecdsa_signatures_with_keys_of_their_curve_only() {
        let [p256, p384] = ec_signers();
        let [rsa, _] = signers();
        for s in [p256, p384] {
            let signed = s.sign(DOC, "a1");
            let doc = parse(&signed).unwrap();
            assert_eq!(verify_enveloped(assertion(&doc), &[rsa.cert(), s.cert()]), Ok(true), "{}", s.alg);
            assert_eq!(verify_enveloped(assertion(&doc), &[rsa.cert()]), Err(Invalid("bad_signature")), "{}", s.alg);
            let changed = signed.replacen("<a:Subject>ada<", "<a:Subject>eve<", 1);
            assert_eq!(verify_enveloped(assertion(&parse(&changed).unwrap()), &[s.cert()]), Err(Invalid("bad_signature")), "{}", s.alg);
        }
        assert!(p384.sign(DOC, "a1").contains(SHA384), "P-384 digests with SHA-384");
        let signed = p256.sign(DOC, "a1");
        let doc = parse(&signed).unwrap();
        assert_eq!(verify_enveloped(assertion(&doc), &[p384.cert()]), Err(Invalid("bad_signature")), "another curve's key");
        // ecdsa-sha384 on a P-256 key, or ecdsa-sha256 named for a P-384 signature: never mixed.
        let swapped = signed.replacen(ECDSA_SHA256, ECDSA_SHA384, 1);
        assert_eq!(verify_enveloped(assertion(&parse(&swapped).unwrap()), &[p256.cert(), p384.cert()]), Err(Invalid("bad_signature")));
        let sha1 = signed.replacen(ECDSA_SHA256, ECDSA_SHA1, 1);
        assert_eq!(verify_enveloped(assertion(&parse(&sha1).unwrap()), &[p256.cert()]), Err(Invalid("weak_algorithm")));

        let data = b"SAMLResponse=abc&SigAlg=y";
        let raw = STANDARD.decode(p256.sign_raw(data)).unwrap();
        assert_eq!(raw.len(), 64, "r || s, not DER");
        assert_eq!(verify_raw(ECDSA_SHA256, data, &raw, &[rsa.cert(), p256.cert()]), Ok(()));
        assert_eq!(verify_raw(RSA_SHA256, data, &raw, &[p256.cert()]), Err(Invalid("bad_signature")), "an RSA algorithm never tries an EC key");
        assert_eq!(verify_raw(ECDSA_SHA384, data, &STANDARD.decode(p384.sign_raw(data)).unwrap(), &[p384.cert()]), Ok(()));
        // The same signature DER-encoded, as some libraries make it: not what XML-DSig sends.
        let der = {
            let int = |b: &[u8]| {
                let b = &b[b.iter().position(|x| *x != 0).unwrap_or(b.len() - 1)..];
                let pad = b[0] & 0x80 != 0;
                [vec![2, (b.len() + pad as usize) as u8], if pad { vec![0] } else { vec![] }, b.to_vec()].concat()
            };
            let body = [int(&raw[..32]), int(&raw[32..])].concat();
            [vec![0x30, body.len() as u8], body].concat()
        };
        assert_eq!(verify_raw(ECDSA_SHA256, data, &der, &[p256.cert()]), Err(Invalid("bad_signature")));
        assert_eq!(verify_raw(ECDSA_SHA1, data, &raw, &[p256.cert()]), Err(Invalid("weak_algorithm")));
    }

    #[test]
    fn reads_every_certificate_in_a_pem_file() {
        let [a, b] = signers();
        let pem = |c: &str| format!("-----BEGIN CERTIFICATE-----\n{c}\n-----END CERTIFICATE-----\n");
        let both = certs_from_pem(&format!("old one\n{}new one\n{}", pem(&a.cert), pem(&b.cert))).unwrap();
        assert_eq!(both.iter().map(|c| c.sha256.clone()).collect::<Vec<_>>(), [a.cert().sha256, b.cert().sha256]);
        assert_eq!(certs_from_pem(&a.cert).unwrap()[0].sha256, a.cert().sha256, "base64 DER without armour");
        assert!(certs_from_pem("-----BEGIN CERTIFICATE-----\nAAAA").is_err());
        assert!(certs_from_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----").is_err());
    }

    #[test]
    fn canonicalization_refuses_absurd_nesting() {
        let deep = format!(r#"<r ID="x">{}{}</r>"#, "<a>".repeat(MAX_DEPTH + 1), "</a>".repeat(MAX_DEPTH + 1));
        let doc = parse(&deep).unwrap();
        assert_eq!(exc_c14n(doc.root_element(), None, &[]).err(), Some(Invalid("bad_response")));
        let fine = format!(r#"<r ID="x">{}{}</r>"#, "<a>".repeat(MAX_DEPTH), "</a>".repeat(MAX_DEPTH));
        assert!(exc_c14n(parse(&fine).unwrap().root_element(), None, &[]).is_ok());
    }
}
