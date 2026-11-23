//! A native SAML 2.0 service provider (ADR 0127): Web Browser SSO, SP-initiated only, an
//! HTTP-Redirect AuthnRequest out and an HTTP-POST Response back.
//!
//! What a response must be to sign anyone in, checked here in this order:
//!
//! - **Well formed, and one assertion.** No DTD, comment, or processing instruction; the root
//!   is a `samlp:Response`; exactly one `saml:Assertion` in the whole document, a direct child
//!   of it; every `ID` in the document unique; every `ds:Signature` a direct child of the
//!   response or the assertion. With an encryption key (ADR 0150), the one assertion may be
//!   an `EncryptedAssertion` instead: the response's signature, if any, is checked first, then
//!   it is decrypted (`xmlenc`) and the assertion inside held to the same rules, its IDs
//!   unique against the response's too. `ENCRYPTED_ASSERTIONS=require` refuses a plain one.
//! - **Success.** Otherwise the IdP's status is audited and nothing else is read.
//! - **Signed by the IdP.** The assertion carries a valid enveloped signature by one of the
//!   IdP's certificates (`xmldsig`). A signed response must verify too, but doesn't stand in
//!   for the assertion's. Everything below is read from that verified assertion node, so a
//!   wrapped copy elsewhere is never what's read.
//! - **For us, now, and this sign-in.** Issuer is the IdP's entity ID; the response's
//!   `Destination` (if present) and a bearer `SubjectConfirmationData`'s `Recipient` are our
//!   ACS URL; an `AudienceRestriction` names our entity ID; `NotBefore`/`NotOnOrAfter` hold
//!   (with `SKEW_MS`); the response's and the confirmation's `InResponseTo` are the ID of the
//!   AuthnRequest this browser started. An unsolicited (IdP-initiated) response must have no
//!   `InResponseTo` on either instead, and only ever restarts a sign-in (ADR 0175).
//! - **Someone.** A NameID that isn't transient. With an encryption key it may be an
//!   `EncryptedID` (ADR 0151), read only from the verified assertion, decrypted like an
//!   assertion and holding exactly one NameID. The caller then refuses a second use of the
//!   assertion's ID, and keeps the NameID and `SessionIndex` for single logout (`saml_slo`).
//! - **Groups**, only when the provider names a groups attribute (ADR 0160): every value of
//!   it in the verified assertion. Entra's overage claim, or more than `MAX_GROUPS` values,
//!   make the groups unknown, which the caller treats as in none.
//!
//! With a provider's SP key (ADR 0137), AuthnRequests can be signed with the HTTP-Redirect
//! binding's query signature, and our metadata publishes the key's certificate. The key may
//! be ECDSA when it's configured (ADR 0151); generated ones are RSA.
//!
//! IdP metadata can be held to a signature by a configured certificate (ADR 0151): see
//! `load_idp_metadata`.

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

/// Entra ID sends this instead of the groups when someone is in more than it puts in a token.
pub const GROUPS_OVERAGE: &str = "http://schemas.microsoft.com/claims/groups.link";
/// More group values than this and the list is taken as unknown, not cut short.
pub const MAX_GROUPS: usize = 500;
/// The longest group value read. Longer ones are left out.
pub const MAX_GROUP_LEN: usize = 256;

/// Which assertion attributes hold the email and name. None: the usual names above.
/// `groups` has no default: groups are read only from the attribute an admin names (ADR 0160).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Attributes {
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Option<String>,
}

/// The groups a signed assertion puts the person in (ADR 0160).
#[derive(Clone, Debug, PartialEq)]
pub enum Groups {
    /// The provider names no groups attribute.
    NotRead,
    /// Every value of the attribute, as sent, without duplicates. Empty when it's missing.
    Listed(Vec<String>),
    /// The IdP left groups out (Entra's overage claim), or sent more than `MAX_GROUPS`:
    /// `overage` or `too_many`.
    Unknown(&'static str),
}

impl Groups {
    /// The groups, when the assertion says which they are.
    pub fn listed(&self) -> Option<&[String]> {
        match self {
            Groups::Listed(g) => Some(g),
            _ => None,
        }
    }
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

/// What our metadata adds with an SP key: its certificate (base64 DER) and, during a rollover,
/// the next key's after it (ADR 0181); our SLO URL; and whether AuthnRequests are signed.
pub struct SpSigning<'a> {
    pub certs: &'a [&'a str],
    pub slo: &'a str,
    pub sign_requests: bool,
}

pub(super) fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// What a provider's IdP metadata must be signed by (ADR 0151): the certificates in
/// `SSO_<ID>_METADATA_SIGNING_CERT_FILE`, and whether unsigned metadata is refused
/// (`SIGNED_METADATA=require`, the default with a certificate) or still taken (`allow`).
#[derive(Clone, Debug)]
pub struct MetadataTrust {
    pub certs: Vec<Cert>,
    pub require: bool,
}

/// IdP metadata that can't be used: `reason` for the audit log, `message` for the admin.
/// `reason` is `bad_metadata` unless its signature or validity is what didn't hold.
#[derive(Debug, PartialEq)]
pub struct MetadataRefused {
    pub reason: &'static str,
    pub message: String,
}

impl MetadataRefused {
    fn bad(message: impl Into<String>) -> MetadataRefused {
        MetadataRefused { reason: "bad_metadata", message: message.into() }
    }

    /// Refused for its signature or validity, not for what it says: worth an audit event.
    pub fn untrusted(&self) -> bool {
        self.reason != "bad_metadata"
    }
}

impl std::fmt::Display for MetadataRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// `load_idp_metadata` without a trust anchor, for tests that don't care about one.
#[cfg(test)]
pub fn parse_idp_metadata(xml: &str, entity_id: &str, signs_requests: bool) -> Result<IdpMetadata, String> {
    load_idp_metadata(xml, entity_id, signs_requests, None, 0).map_err(|e| e.message)
}

/// The text of an element, all of it: a comment inside doesn't cut it short. Exclusive C14N
/// drops comments, so in signed metadata one can be added without breaking the signature.
fn all_text(n: Node) -> String {
    n.descendants().filter(Node::is_text).filter_map(|t| t.text()).collect()
}

/// With `trust`, the signatures that cover `entity`: the document's (`root`) and the entity's
/// own, when it's inside an aggregate. Each one present must verify against the anchor, and
/// one must be present when it's required. Signed metadata past its `validUntil` is refused,
/// so an old signed copy can't be served again once it has expired.
fn check_signed(root: Node, entity: Node, t: &MetadataTrust, now_ms: i64) -> Result<(), MetadataRefused> {
    let path = if root == entity { vec![root] } else { vec![root, entity] };
    let mut signed = false;
    for n in &path {
        match xmldsig::verify_enveloped(*n, &t.certs) {
            Ok(s) => signed |= s,
            Err(Invalid(reason)) => return Err(MetadataRefused { reason, message: format!("its signature isn't by the metadata signing certificate ({reason})") }),
        }
    }
    if !signed {
        return if t.require { Err(MetadataRefused { reason: "unsigned", message: "it isn't signed, and signed metadata is required".into() }) } else { Ok(()) };
    }
    // Every descriptor from the entity up to the root: a signed root covers a nested
    // EntitiesDescriptor's validUntil too.
    for n in entity.ancestors().filter(Node::is_element) {
        if let Some(v) = n.attribute("validUntil") {
            let until = time(v).map_err(|_| MetadataRefused::bad(format!("its validUntil ({v}) isn't a date")))?;
            if until <= now_ms {
                return Err(MetadataRefused { reason: "expired", message: format!("it expired at {v} (validUntil): the IdP must publish a fresh copy") });
            }
        }
    }
    Ok(())
}

/// The IdP `entity_id` in `xml` (an `EntityDescriptor`, or one inside `EntitiesDescriptor`).
/// `signs_requests`: this provider signs its AuthnRequests (`SIGN_REQUESTS`), so an IdP that
/// wants them signed is fine. With `trust` (ADR 0151), only metadata signed by its
/// certificate, and not expired at `now_ms`, is read (`check_signed`). The message says what
/// to fix, for the admin who set it up.
pub fn load_idp_metadata(xml: &str, entity_id: &str, signs_requests: bool, trust: Option<&MetadataTrust>, now_ms: i64) -> Result<IdpMetadata, MetadataRefused> {
    if xml.len() > MAX_METADATA {
        return Err(MetadataRefused::bad("the metadata is over 1 MB"));
    }
    let opt = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 100_000, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(xml.trim_start_matches('\u{feff}'), opt).map_err(|e| MetadataRefused::bad(format!("the metadata isn't XML SuperBot reads (no DTDs): {e}")))?;
    let entity = doc.descendants().find(|n| is(*n, METADATA, "EntityDescriptor") && n.attribute("entityID") == Some(entity_id));
    let Some(entity) = entity else {
        let found: Vec<&str> = doc.descendants().filter(|n| is(*n, METADATA, "EntityDescriptor")).filter_map(|n| n.attribute("entityID")).take(5).collect();
        return Err(MetadataRefused::bad(if found.is_empty() { "no EntityDescriptor in the metadata".into() } else { format!("the metadata is for {}, not {entity_id}", found.join(", ")) }));
    };
    if let Some(t) = trust {
        check_signed(doc.root_element(), entity, t, now_ms).map_err(|e| MetadataRefused { message: format!("the metadata can't be trusted: {}", e.message), ..e })?;
    }
    read_idp(entity, entity_id, signs_requests).map_err(MetadataRefused::bad)
}

/// What we need from the IdP's `EntityDescriptor`.
fn read_idp(entity: Node, entity_id: &str, signs_requests: bool) -> Result<IdpMetadata, String> {
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
            certs.push(Cert::from_base64(&all_text(c))?);
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

/// Whether a native provider takes encrypted assertions (`SSO_<ID>_ENCRYPTED_ASSERTIONS`,
/// ADR 0150). Off: refused, and our metadata has no encryption key. Allow: both. Require:
/// a plain assertion is refused.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Encryption {
    #[default]
    Off,
    Allow,
    Require,
}

impl Encryption {
    pub fn parse(s: &str) -> Option<Encryption> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Some(Encryption::Off),
            "allow" => Some(Encryption::Allow),
            "require" => Some(Encryption::Require),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Encryption::Off => "off",
            Encryption::Allow => "allow",
            Encryption::Require => "require",
        }
    }
}

/// What a native provider does with an unsolicited response, as an IdP's app tile posts
/// (`SSO_<ID>_IDP_INITIATED`, ADR 0175). Off: refused like any post botd didn't ask for.
/// Restart: once it checks out as the IdP's, for us, now, and unused, the browser starts an
/// SP-initiated sign-in. It never signs anyone in itself.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum IdpInitiated {
    #[default]
    Off,
    Restart,
}

impl IdpInitiated {
    pub fn parse(s: &str) -> Option<IdpInitiated> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Some(IdpInitiated::Off),
            "restart" => Some(IdpInitiated::Restart),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            IdpInitiated::Off => "off",
            IdpInitiated::Restart => "restart",
        }
    }
}

/// What our metadata offers IdPs that encrypt: the GCM ciphers, then OAEP with SHA-256 (XML
/// Encryption 1.1) and with SHA-1 (1.0, which most IdPs send). Nothing botd would refuse.
fn encryption_methods() -> String {
    use super::xmlenc::{AES128_GCM, AES256_GCM, MGF1_SHA256, RSA_OAEP, RSA_OAEP_MGF1P, SHA256, XENC11};
    format!(
        r#"<md:EncryptionMethod Algorithm="{AES256_GCM}"/><md:EncryptionMethod Algorithm="{AES128_GCM}"/><md:EncryptionMethod Algorithm="{RSA_OAEP}"><ds:DigestMethod xmlns:ds="{}" Algorithm="{SHA256}"/><xenc11:MGF xmlns:xenc11="{XENC11}" Algorithm="{MGF1_SHA256}"/></md:EncryptionMethod><md:EncryptionMethod Algorithm="{RSA_OAEP_MGF1P}"/>"#,
        xmldsig::DSIG
    )
}

/// Our metadata, for the IdP to import: who we are, where to post, and that assertions must
/// be signed; with an SP key, also its certificates and where to send logout messages; with
/// encryption certificates (`encryption`, base64 DER), the keys to encrypt assertions to. During
/// a rollover each use lists the key in use first, then the next one (ADR 0181).
pub fn sp_metadata(sp: &Sp, signing: Option<&SpSigning>, encryption: &[&str]) -> String {
    let signed = signing.is_some_and(|s| s.sign_requests);
    let key_info = |cert: &str| format!(r#"<ds:KeyInfo xmlns:ds="{}"><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"#, xmldsig::DSIG);
    let mut keys = String::new();
    for cert in signing.map_or(&[][..], |s| s.certs) {
        keys += &format!("\n    <md:KeyDescriptor use=\"signing\">{}</md:KeyDescriptor>", key_info(cert));
    }
    for cert in encryption {
        keys += &format!("\n    <md:KeyDescriptor use=\"encryption\">{}{}</md:KeyDescriptor>", key_info(cert), encryption_methods());
    }
    if let Some(s) = signing {
        keys += &format!("\n    <md:SingleLogoutService Binding=\"{REDIRECT}\" Location=\"{slo}\"/>\n    <md:SingleLogoutService Binding=\"{POST}\" Location=\"{slo}\"/>", slo = escape(s.slo));
    }
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

/// One of botd's keys for a native SAML provider: the signing key (ADR 0137), which signs
/// AuthnRequests and logout messages, or the encryption key (ADR 0150), which IdPs encrypt
/// assertions to. Never one key for both. Its certificate is in our metadata. Generated keys
/// are RSA, which every IdP takes; a configured signing key may be ECDSA on P-256 or P-384
/// (ADR 0151). An encryption key must be RSA (RSA-OAEP).
pub struct SpKey {
    signing: Signing,
    /// None for an ECDSA key, which can't decrypt.
    decrypt: Option<aws_lc_rs::rsa::OaepPrivateDecryptingKey>,
    /// The certificate, base64 DER, as metadata carries it.
    pub cert: String,
    pub info: Cert,
}

enum Signing {
    Rsa(aws_lc_rs::rsa::KeyPair),
    /// The key, and its SignatureMethod (ecdsa-sha256 for P-256, ecdsa-sha384 for P-384).
    Ec(aws_lc_rs::signature::EcdsaKeyPair, &'static str),
}

impl std::fmt::Debug for SpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpKey").field("sha256", &self.info.sha256).finish_non_exhaustive()
    }
}

/// What an SP key is for. Each native provider has one of each, never one key for both.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyUse {
    Signing,
    Encryption,
}

impl KeyUse {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyUse::Signing => "signing",
            KeyUse::Encryption => "encryption",
        }
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
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair};
        const NOT_A_KEY: &str = "the SP key isn't an RSA or ECDSA (P-256, P-384) private key (PKCS #8)";
        let (signing, decrypt) = if let Ok(pair) = aws_lc_rs::rsa::KeyPair::from_pkcs8(pkcs8) {
            let decrypt = aws_lc_rs::rsa::PrivateDecryptingKey::from_pkcs8(pkcs8).ok().and_then(|k| aws_lc_rs::rsa::OaepPrivateDecryptingKey::new(k).ok()).ok_or(NOT_A_KEY)?;
            (Signing::Rsa(pair), Some(decrypt))
        } else if let Ok(pair) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8) {
            (Signing::Ec(pair, xmldsig::ECDSA_SHA256), None)
        } else if let Ok(pair) = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8) {
            (Signing::Ec(pair, xmldsig::ECDSA_SHA384), None)
        } else {
            return Err(NOT_A_KEY.into());
        };
        let info = Cert::from_base64(cert).map_err(|e| format!("the SP certificate: {e}"))?;
        let key = SpKey { signing, decrypt, cert: cert.chars().filter(|c| !c.is_ascii_whitespace()).collect(), info };
        let probe = b"superbot sp key check";
        xmldsig::verify_raw(key.sig_alg(), probe, &key.sign(probe), std::slice::from_ref(&key.info)).map_err(|_| "the SP certificate isn't for the SP key".to_string())?;
        Ok(key)
    }

    /// A configured key (`SSO_<ID>_PRIVATE_KEY`, PEM) and certificate (`SP_CERT_FILE`, PEM or base64 DER).
    pub fn from_pem(key: &str, cert: &str) -> Result<SpKey, String> {
        let pair = rcgen::KeyPair::from_pem(key).map_err(|_| "the SP key isn't a PEM private key (PKCS #8, BEGIN PRIVATE KEY)")?;
        let der = Zeroizing::new(pair.serialize_der());
        SpKey::from_der(&der, &pem_body(cert))
    }

    /// The signature `sign` makes, as a SignatureMethod or SigAlg URI.
    pub fn sig_alg(&self) -> &'static str {
        match &self.signing {
            Signing::Rsa(_) => xmldsig::RSA_SHA256,
            Signing::Ec(_, alg) => alg,
        }
    }

    /// A signature over `data`, as XML-DSig and the redirect binding use: RSA-SHA256 (PKCS #1
    /// v1.5), or ECDSA as `r || s`.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        match &self.signing {
            Signing::Rsa(pair) => {
                let mut sig = vec![0; pair.public_modulus_len()];
                pair.sign(&aws_lc_rs::signature::RSA_PKCS1_SHA256, &rng, data, &mut sig).expect("RSA signing");
                sig
            }
            Signing::Ec(pair, _) => pair.sign(&rng, data).expect("ECDSA signing").as_ref().to_vec(),
        }
    }

    /// The key as RSA-OAEP decrypts with it, for encrypted assertions and NameIDs (`xmlenc`).
    /// None for an ECDSA key.
    pub fn decrypting(&self) -> Option<&aws_lc_rs::rsa::OaepPrivateDecryptingKey> {
        self.decrypt.as_ref()
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
        q += &format!("&SigAlg={}", form(k.sig_alg()));
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
    /// The ID of the AuthnRequest this browser's sign-in sent. None: an unsolicited response
    /// (ADR 0175), which must answer no request at all.
    pub request_id: Option<&'a str>,
    pub attributes: &'a Attributes,
    pub now_ms: i64,
    /// Our encryption keys, when the provider takes encrypted assertions (ADR 0150): the one in
    /// use, then any a rollover holds beside it (ADR 0181). Empty: an `EncryptedAssertion` is refused.
    pub decrypt: &'a [&'a SpKey],
    /// Refuse a plain assertion (`ENCRYPTED_ASSERTIONS=require`).
    pub require_encrypted: bool,
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
    pub groups: Groups,
    /// Which of `Expect::decrypt` opened the assertion or its NameID, if either was encrypted:
    /// what tells an admin which key the IdP encrypts to (ADR 0181).
    pub decrypted_with: Option<usize>,
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

/// Every value of every `name` attribute in the (verified) assertion's attribute statements.
/// Values that aren't plain text, are empty, or are longer than `MAX_GROUP_LEN` are left out:
/// a group never matched only takes access away.
fn groups(assertion: Node, name: &str) -> Groups {
    let attrs: Vec<Node> = assertion.children().filter(|c| is(*c, ASSERTION, "AttributeStatement")).flat_map(|s| s.children().filter(|c| is(*c, ASSERTION, "Attribute"))).collect();
    if attrs.iter().any(|a| a.attribute("Name") == Some(GROUPS_OVERAGE)) {
        return Groups::Unknown("overage");
    }
    let values = attrs.iter().filter(|a| a.attribute("Name") == Some(name)).flat_map(|a| a.children().filter(|c| is(*c, ASSERTION, "AttributeValue")));
    let mut out: Vec<String> = Vec::new();
    for (n, v) in values.enumerate() {
        if n >= MAX_GROUPS {
            return Groups::Unknown("too_many");
        }
        if let Some(v) = text_of(v).map(str::trim).filter(|v| !v.is_empty() && v.len() <= MAX_GROUP_LEN)
            && !out.iter().any(|o| o == v)
        {
            out.push(v.to_string());
        }
    }
    Groups::Listed(out)
}

/// Every `ID`-like attribute at or under `n`.
fn ids_under<'a>(n: Node<'a, '_>) -> impl Iterator<Item = &'a str> {
    n.descendants().flat_map(|n| n.attributes()).filter(|a| a.namespace().is_none() && a.name().eq_ignore_ascii_case("id")).map(|a| a.value())
}

/// A decrypted assertion or NameID, made a document of its own in the namespaces the
/// `EncryptedAssertion` (or `EncryptedID`) had in scope: it was serialized (and usually
/// signed) in that context, so its prefixes may be declared only there. An XML declaration
/// in front is dropped.
fn in_context(encrypted: Node, plaintext: &[u8]) -> Result<Zeroizing<String>, Refused> {
    let bad = || Refused("bad_response", None);
    let text = std::str::from_utf8(plaintext).map_err(|_| bad())?.trim_start_matches('\u{feff}');
    let text = match text.strip_prefix("<?xml") {
        Some(rest) => &rest[rest.find("?>").ok_or_else(bad)? + 2..],
        None => text,
    };
    let mut open = String::from("<decrypted");
    for ns in encrypted.namespaces().filter(|ns| ns.name() != Some("xml")) {
        match ns.name() {
            Some(p) => open += &format!(r#" xmlns:{p}="{}""#, escape(ns.uri())),
            None => open += &format!(r#" xmlns="{}""#, escape(ns.uri())),
        }
    }
    open += ">";
    const CLOSE: &str = "</decrypted>";
    // Sized up front, so the plaintext is never left behind in a reallocated buffer.
    let mut xml = Zeroizing::new(String::with_capacity(open.len() + text.len() + CLOSE.len()));
    xml.push_str(&open);
    xml.push_str(text);
    xml.push_str(CLOSE);
    Ok(xml)
}

/// The one `saml:Assertion` a decrypted document holds, with nothing beside it (but
/// whitespace), no assertion inside it, and its signatures only where it can have one.
fn decrypted_assertion<'a, 'i>(doc: &'a roxmltree::Document<'i>) -> Result<Node<'a, 'i>, Refused> {
    let wrapper = doc.root_element();
    let kids: Vec<Node> = wrapper.children().filter(|c| !(c.is_text() && c.text().is_some_and(|t| t.trim().is_empty()))).collect();
    let [a] = kids.as_slice() else { return Err(Refused("wrapped", None)) };
    if !is(*a, ASSERTION, "Assertion") {
        return Err(Refused("wrapped", None));
    }
    if a.descendants().skip(1).any(|n| n.is_element() && matches!(n.tag_name().name(), "Assertion" | "EncryptedAssertion")) {
        return Err(Refused("wrapped", None));
    }
    if a.descendants().filter(|n| is(*n, xmldsig::DSIG, "Signature")).any(|s| s.parent() != Some(*a)) {
        return Err(Refused("wrapped", None));
    }
    Ok(*a)
}

/// The person a signed message names, as the IdP sent it, or as decrypted from its `EncryptedID`.
#[derive(Debug, PartialEq)]
pub struct NameId {
    pub value: String,
    pub format: Option<String>,
    pub name_qualifier: Option<String>,
    pub sp_name_qualifier: Option<String>,
}

/// A `saml:NameID`: only text, 1 to 255 characters, no surrounding whitespace.
fn read_name_id(n: Node) -> Result<NameId, Refused> {
    let value = text_of(n).filter(|v| !v.is_empty() && v.len() <= 255 && v.trim() == *v).ok_or(Refused("missing_subject", None))?;
    Ok(NameId { value: value.to_string(), format: kept(n, "Format"), name_qualifier: kept(n, "NameQualifier"), sp_name_qualifier: kept(n, "SPNameQualifier") })
}

/// The one identifier `parent` (an assertion's `Subject`, or a `LogoutRequest`) names the
/// person by: a `NameID`, or an `EncryptedID` decrypted with one of `keys` (ADR 0151). `parent`
/// must be verified already: the ciphertext is part of what the IdP signed. Two identifiers are
/// refused as `wrapped`, an `EncryptedID` without a key as `encrypted_id`, and a `BaseID` or
/// none as `missing_subject`.
pub fn name_id(parent: Node, keys: &[&SpKey]) -> Result<NameId, Refused> {
    name_id_with(parent, keys).map(|(n, _)| n)
}

/// `name_id`, and which of `keys` decrypted it, if it was encrypted.
fn name_id_with(parent: Node, keys: &[&SpKey]) -> Result<(NameId, Option<usize>), Refused> {
    let ids: Vec<Node> = parent.children().filter(|c| c.is_element() && c.tag_name().namespace() == Some(ASSERTION) && matches!(c.tag_name().name(), "BaseID" | "NameID" | "EncryptedID")).collect();
    match ids.as_slice() {
        [n] if n.tag_name().name() == "NameID" => Ok((read_name_id(*n)?, None)),
        [n] if n.tag_name().name() == "EncryptedID" && keys.is_empty() => Err(Refused("encrypted_id", None)),
        [n] if n.tag_name().name() == "EncryptedID" => decrypted_name_id(*n, keys).map(|(n, i)| (n, Some(i))),
        [_, _, ..] => Err(Refused("wrapped", None)),
        _ => Err(Refused("missing_subject", None)),
    }
}

/// Decrypts an `EncryptedAssertion` or `EncryptedID` with one of our keys (`xmlenc`), as a document
/// of its own in the namespaces it was encrypted in, and which key opened it. An ECDSA key can't.
fn decrypted(encrypted: Node, keys: &[&SpKey]) -> Result<(Zeroizing<String>, usize), Refused> {
    let ours: Vec<&aws_lc_rs::rsa::OaepPrivateDecryptingKey> = keys.iter().filter_map(|k| k.decrypting()).collect();
    if ours.len() != keys.len() {
        return Err(Refused("no_sp_key", None));
    }
    let (plaintext, i) = super::xmlenc::decrypt(encrypted, &ours)?;
    Ok((in_context(encrypted, &plaintext)?, i))
}

/// An `EncryptedID`'s NameID: decrypted with the same algorithms and single failure as an
/// `EncryptedAssertion` (`xmlenc`), parsed with the same rules in the namespaces it was
/// encrypted in, and holding exactly one `saml:NameID` with nothing beside it.
fn decrypted_name_id(encrypted: Node, keys: &[&SpKey]) -> Result<(NameId, usize), Refused> {
    let (plaintext, i) = decrypted(encrypted, keys)?;
    let doc = xmldsig::parse(&plaintext)?;
    let kids: Vec<Node> = doc.root_element().children().filter(|c| !(c.is_text() && c.text().is_some_and(|t| t.trim().is_empty()))).collect();
    match kids.as_slice() {
        [n] if is(*n, ASSERTION, "NameID") => Ok((read_name_id(*n)?, i)),
        _ => Err(Refused("wrapped", None)),
    }
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
    let (found, key) = match (assertions.as_slice(), e.decrypt) {
        ([a], _) if is(*a, ASSERTION, "Assertion") && a.parent() == Some(response) => (*a, None),
        ([a], []) if a.tag_name().name() == "EncryptedAssertion" => return Err(Refused("encrypted_assertion", None)),
        ([a], k) if is(*a, ASSERTION, "EncryptedAssertion") && a.parent() == Some(response) => (*a, Some(k)),
        ([], _) => return Err(Refused("missing_assertion", None)),
        _ => return Err(Refused("wrapped", None)),
    };
    if key.is_none() && e.require_encrypted {
        return Err(Refused("unencrypted_assertion", None));
    }
    if doc.descendants().filter(|n| is(*n, xmldsig::DSIG, "Signature")).any(|s| s.parent() != Some(response) && (key.is_some() || s.parent() != Some(found))) {
        return Err(Refused("wrapped", None));
    }

    // Encrypted: the response's signature, if any, is checked before anything is decrypted.
    // The assertion inside is read with the same rules as a posted one, and is signed or refused.
    let plaintext: Zeroizing<String>;
    let inner: roxmltree::Document;
    let mut decrypted_with = None;
    let assertion = match key {
        None => found,
        Some(k) => {
            xmldsig::verify_enveloped(response, &e.idp.certs)?;
            let (p, i) = decrypted(found, k)?;
            (plaintext, decrypted_with) = (p, Some(i));
            inner = xmldsig::parse(&plaintext)?;
            decrypted_assertion(&inner)?
        }
    };
    // Every ID unique, the decrypted assertion's against the response's too.
    let mut ids: Vec<&str> = ids_under(doc.root()).collect();
    if key.is_some() {
        ids.extend(ids_under(assertion.document().root()));
    }
    let all = ids.len();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != all {
        return Err(Refused("wrapped", None));
    }

    if !xmldsig::verify_enveloped(assertion, &e.idp.certs)? {
        return Err(Refused("unsigned", None));
    }
    if key.is_none() {
        xmldsig::verify_enveloped(response, &e.idp.certs)?;
    }

    // From here on, only the verified assertion (and the response that holds it).
    let (now, earliest, latest) = (e.now_ms, e.now_ms - SKEW_MS, e.now_ms + SKEW_MS);
    if response.attribute("Destination").is_some_and(|d| d != e.sp.acs) {
        return Err(Refused("wrong_destination", None));
    }
    if response.children().any(|c| is(c, ASSERTION, "Issuer")) && !issuer_is(response, &e.idp.entity_id) {
        return Err(Refused("wrong_issuer", None));
    }
    if response.attribute("InResponseTo") != e.request_id {
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
        if d.attribute("InResponseTo") != e.request_id {
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

    let (nid, id_with) = name_id_with(subject, e.decrypt)?;
    let decrypted_with = decrypted_with.or(id_with);
    if nid.format.as_deref() == Some(TRANSIENT) {
        return Err(Refused("transient_subject", None));
    }
    let raw = nid.value.as_str();
    let pick = |set: &Option<String>, defaults: &[&str]| match set {
        Some(n) => attribute(assertion, &[n.as_str()]),
        None => attribute(assertion, defaults),
    };
    let email = pick(&e.attributes.email, &EMAIL_ATTRIBUTES).filter(|m| m.len() <= 254 && crate::users::valid_email(m)).map(String::from);
    let name = pick(&e.attributes.name, &NAME_ATTRIBUTES).map(|n| crate::audit::clip(n, 100));
    let claims = Claims { issuer: e.idp.entity_id.clone(), subject: super::saml::subject(raw), tenant: None, email, name, username: None };
    let session_index = kept(authn, "SessionIndex");
    let login = SamlLogin { name_id: nid.value, format: nid.format, name_qualifier: nid.name_qualifier, sp_name_qualifier: nid.sp_name_qualifier, session_index };
    let groups = e.attributes.groups.as_deref().map_or(Groups::NotRead, |n| groups(assertion, n));
    Ok(Checked { claims, assertion_id, until_ms: until.min(now + 24 * 3600 * 1000), login, groups, decrypted_with })
}

#[cfg(test)]
pub mod test_idp {
    //! A SAML IdP for tests: metadata, and signed responses with any part changed.

    use super::*;
    use crate::sso::xmldsig::test_signer::{Signer, signer, signers};

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

    /// Metadata whose one signing certificate is test signer `i`'s (2 and 3 are ECDSA).
    pub fn metadata_signed_by(i: usize) -> String {
        metadata_with(IDP, &[signer(i)], "")
    }

    /// `xml` (an EntityDescriptor or EntitiesDescriptor) with an ID on its root, signed by `s`.
    pub fn signed_metadata(xml: &str, s: &Signer) -> String {
        let at = xml.find("Descriptor ").expect("a descriptor") + "Descriptor ".len();
        let with_id = format!(r#"{}ID="_md1" {}"#, &xml[..at], &xml[at..]);
        s.sign(&with_id, "_md1")
    }

    pub const SLO_URL: &str = "https://idp.example/saml/slo";

    /// `xml` with an HTTP-Redirect SingleLogoutService added.
    pub fn with_slo(xml: &str) -> String {
        xml.replacen("<md:NameIDFormat>", &format!(r#"<md:SingleLogoutService Binding="{REDIRECT}" Location="{SLO_URL}"/><md:NameIDFormat>"#), 1)
    }

    /// The parts of a response, each one replaceable before it is signed.
    /// An `InResponseTo` value that is sent, but empty.
    pub const EMPTY_IN_RESPONSE_TO: &str = "(empty)";

    /// An `InResponseTo` attribute, or none for an empty one (an unsolicited response).
    fn in_response_to(id: &str) -> String {
        match id {
            "" => String::new(),
            EMPTY_IN_RESPONSE_TO => r#" InResponseTo="""#.into(),
            _ => format!(r#" InResponseTo="{id}""#),
        }
    }

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
        /// Attributes with several values each (`groups`), after `attributes`.
        pub multi_attributes: Vec<(String, Vec<String>)>,
        /// More inside Conditions, before signing.
        pub conditions_extra: String,
        /// Sign the assertion, the response, either, or both.
        pub sign_assertion: bool,
        pub sign_response: bool,
        pub signer: usize,
        /// Encrypt the (signed) assertion to `encrypt_to`, a certificate from our metadata.
        pub encrypt: Option<crate::sso::xmlenc::test_encrypter::Encrypt>,
        pub encrypt_to: String,
        /// Send the NameID as an `EncryptedID` to this certificate, inside what is signed.
        pub encrypt_name_id_to: Option<String>,
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
                multi_attributes: Vec::new(),
                conditions_extra: String::new(),
                sign_assertion: true,
                sign_response: false,
                signer: 0,
                encrypt: None,
                encrypt_to: String::new(),
                encrypt_name_id_to: None,
            }
        }

        /// The subject's NameID, or its `EncryptedID`.
        pub fn name_id_xml(&self) -> String {
            let plain = format!(r#"<saml:NameID Format="{}">{}</saml:NameID>"#, self.name_id_format, self.name_id);
            match &self.encrypt_name_id_to {
                Some(cert) => crate::sso::xmlenc::test_encrypter::Encrypt::default().encrypt_as("saml:EncryptedID", &plain, cert),
                None => plain,
            }
        }

        pub fn assertion(&self) -> String {
            let value = |v: &String| format!(r#"<saml:AttributeValue xsi:type="xs:string">{v}</saml:AttributeValue>"#);
            let single = self.attributes.iter().map(|(k, v)| format!(r#"<saml:Attribute Name="{k}">{}</saml:Attribute>"#, value(v)));
            let multi = self.multi_attributes.iter().map(|(k, vs)| format!(r#"<saml:Attribute Name="{k}">{}</saml:Attribute>"#, vs.iter().map(value).collect::<String>()));
            let attrs: String = single.chain(multi).collect();
            format!(
                r#"<saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{now}"><saml:Issuer>{iss}</saml:Issuer><saml:Subject>{nid}<saml:SubjectConfirmation Method="{BEARER}"><saml:SubjectConfirmationData{cirt} NotOnOrAfter="{cna}" Recipient="{rcp}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction>{extra}</saml:Conditions><saml:AuthnStatement AuthnInstant="{now}" SessionIndex="{si}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>{attrs}</saml:AttributeStatement></saml:Assertion>"#,
                aid = self.assertion_id,
                now = instant(self.not_before + 60_000),
                iss = self.issuer,
                nid = self.name_id_xml(),
                cirt = in_response_to(&self.confirm_in_response_to),
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
            let signer = signer(self.signer);
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
            let assertion = match &self.encrypt {
                Some(e) => e.encrypt(&assertion, &self.encrypt_to),
                None => assertion,
            };
            let dest = self.destination.as_ref().map(|d| format!(r#" Destination="{d}""#)).unwrap_or_default();
            let xml = format!(
                r#"<samlp:Response xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="{}" Version="2.0" IssueInstant="{}"{dest}{}><saml:Issuer>{}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status>{assertion}</samlp:Response>"#,
                self.id,
                instant(self.not_before + 60_000),
                in_response_to(&self.in_response_to),
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
    use crate::sso::xmldsig::test_signer::{Signer, signers};

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
        check_response(&STANDARD.encode(xml), &Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp, request_id: Some(REQ), attributes: &attributes, now_ms, decrypt: &[], require_encrypted: false })
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
    fn sp_keys_match_their_certificate() {
        let (key, pkcs8) = SpKey::generate("SuperBot okta").unwrap();
        assert!(matches!(&key.signing, Signing::Rsa(p) if p.public_modulus_len() == 384), "generated keys are RSA-3072");
        assert_eq!(key.sig_alg(), xmldsig::RSA_SHA256);
        assert!(key.decrypting().is_some());
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
        assert!(SpKey::from_pem(&ec.serialize_pem(), &key.cert).unwrap_err().contains("isn't for the SP key"), "an ECDSA key with an RSA certificate");
        let ed = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        assert!(SpKey::from_pem(&ed.serialize_pem(), &key.cert).unwrap_err().contains("isn't an RSA or ECDSA"));
    }

    /// A configured ECDSA SP key: its PEM and its certificate's PEM.
    fn ec_sp_key(alg: &'static rcgen::SignatureAlgorithm) -> (String, String) {
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "SuperBot SAML SP (okta)");
        (key.serialize_pem(), params.self_signed(&key).unwrap().pem())
    }

    #[test]
    fn ecdsa_sp_keys_sign_with_their_curve_and_never_decrypt() {
        for (alg, sig_alg) in [(&rcgen::PKCS_ECDSA_P256_SHA256, xmldsig::ECDSA_SHA256), (&rcgen::PKCS_ECDSA_P384_SHA384, xmldsig::ECDSA_SHA384)] {
            let (key_pem, cert_pem) = ec_sp_key(alg);
            let key = SpKey::from_pem(&key_pem, &cert_pem).unwrap();
            assert_eq!(key.sig_alg(), sig_alg);
            assert!(key.decrypting().is_none(), "IdPs encrypt with RSA-OAEP only");
            let xml = authn_request(&Sp { entity_id: SP, acs: ACS }, REQ, SSO_URL, NOW);
            let q = redirect_query("SAMLRequest", &xml, Some("s"), Some(&key));
            assert!(q.contains(&format!("SigAlg={}", form(sig_alg))), "{q}");
            let r = from_redirect(&q).unwrap();
            assert_eq!(r.verify(std::slice::from_ref(&key.info)), Ok(true), "verifies as an IdP would");
            let (other_pem, _) = ec_sp_key(alg);
            assert!(SpKey::from_pem(&other_pem, &cert_pem).unwrap_err().contains("isn't for the SP key"));
        }
        let (p256, _) = ec_sp_key(&rcgen::PKCS_ECDSA_P256_SHA256);
        let (_, p384_cert) = ec_sp_key(&rcgen::PKCS_ECDSA_P384_SHA384);
        assert!(SpKey::from_pem(&p256, &p384_cert).is_err(), "a P-256 key with a P-384 certificate");
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
            "SAMLRequest=a&SAMLResponse=b".to_string(),
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
            let md = sp_metadata(&sp, Some(&SpSigning { certs: &[&key.cert], slo, sign_requests }), &[]);
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
        assert!(!sp_metadata(&sp, None, &[]).contains("SingleLogoutService"), "no key, no logout");
    }

    #[test]
    fn writes_sp_metadata_and_a_redirect_authn_request() {
        let sp = Sp { entity_id: SP, acs: ACS };
        let md = sp_metadata(&sp, None, &[]);
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
        let mapped = Attributes { email: Some("work_mail".into()), name: None, groups: None };
        let mut custom = base();
        custom.attributes = vec![("email".into(), "personal@evil.example".into()), ("work_mail".into(), "ada@example.com".into())];
        let c = check_response(&STANDARD.encode(custom.xml()), &Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp, request_id: Some(REQ), attributes: &mapped, now_ms: NOW, decrypt: &[], require_encrypted: false }).unwrap();
        assert_eq!(c.claims.email.as_deref(), Some("ada@example.com"), "only the configured attribute");
        let mut unspecified = base();
        unspecified.name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".into();
        assert!(check(&unspecified.xml()).is_ok());
        assert_eq!(c.groups, Groups::NotRead, "no groups attribute named, none read");
    }

    fn groups_of(r: &Response, name: &str) -> Groups {
        let idp = idp();
        let attributes = Attributes { groups: Some(name.into()), ..Attributes::default() };
        check_response(&STANDARD.encode(r.xml()), &Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp, request_id: Some(REQ), attributes: &attributes, now_ms: NOW, decrypt: &[], require_encrypted: false }).unwrap().groups
    }

    #[test]
    fn groups_come_only_from_the_named_attribute_of_the_signed_assertion() {
        let s = |v: &[&str]| v.iter().map(|g| g.to_string()).collect::<Vec<_>>();
        let mut r = base();
        r.multi_attributes = vec![("groups".into(), s(&["Engineering", " Auditors ", "Engineering", "", &"x".repeat(MAX_GROUP_LEN + 1)])), ("roles".into(), s(&["Admins"]))];
        // Trimmed, deduplicated, empty and overlong values left out, other attributes ignored.
        assert_eq!(groups_of(&r, "groups"), Groups::Listed(s(&["Engineering", "Auditors"])));
        assert_eq!(groups_of(&r, "roles"), Groups::Listed(s(&["Admins"])));
        assert_eq!(groups_of(&r, "memberOf"), Groups::Listed(vec![]), "missing: in no groups");
        // The same attribute twice: both are signed, so both count.
        r.multi_attributes.push(("groups".into(), s(&["Support"])));
        assert_eq!(groups_of(&r, "groups"), Groups::Listed(s(&["Engineering", "Auditors", "Support"])));
        // Case matters: group names are compared as the IdP sends them.
        assert!(!groups_of(&r, "groups").listed().unwrap().contains(&"engineering".to_string()));

        // Entra's overage claim, or too many values: unknown, never a partial list.
        let mut over = base();
        over.multi_attributes = vec![("groups".into(), s(&["Engineering"])), (GROUPS_OVERAGE.into(), s(&["https://graph.microsoft.com/v1.0/users/x/getMemberObjects"]))];
        assert_eq!(groups_of(&over, "groups"), Groups::Unknown("overage"));
        let mut many = base();
        many.multi_attributes = vec![("groups".into(), (0..=MAX_GROUPS).map(|i| format!("g{i}")).collect())];
        assert_eq!(groups_of(&many, "groups"), Groups::Unknown("too_many"));
        many.multi_attributes[0].1.pop();
        assert_eq!(groups_of(&many, "groups").listed().map(<[String]>::len), Some(MAX_GROUPS));

        // A value with markup inside isn't a group name, even signed.
        let mut marked = base();
        marked.multi_attributes = vec![("groups".into(), s(&["<b>Admins</b>", "Users"]))];
        assert_eq!(groups_of(&marked, "groups"), Groups::Listed(s(&["Users"])));

        // Added to the assertion after it was signed: refused before any group is read.
        let idp = idp();
        let attributes = Attributes { groups: Some("groups".into()), ..Attributes::default() };
        let e = Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp, request_id: Some(REQ), attributes: &attributes, now_ms: NOW, decrypt: &[], require_encrypted: false };
        let added = base().xml_with(|a| a.replace("</saml:AttributeStatement>", r#"<saml:Attribute Name="groups"><saml:AttributeValue>Admins</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>"#));
        assert_eq!(check_response(&STANDARD.encode(added), &e).unwrap_err().0, "bad_signature");

        // Groups outside the signed assertion are never read.
        let mut plain = base();
        plain.multi_attributes = vec![("groups".into(), s(&["Users"]))];
        let wrapped = plain.xml().replace("</samlp:Response>", r#"<saml:AttributeStatement><saml:Attribute Name="groups"><saml:AttributeValue>Admins</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></samlp:Response>"#);
        let c = check_response(&STANDARD.encode(wrapped), &e).unwrap();
        assert_eq!(c.groups, Groups::Listed(s(&["Users"])));
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
        unsolicited.confirm_in_response_to = String::new();
        assert_eq!(check(&unsolicited.xml()).unwrap_err().0, "in_response_to_mismatch", "IdP-initiated");
        assert_eq!(check_at(&base().xml(), NOW + 3_600_000).unwrap_err().0, "expired", "an old response posted later");
        assert_eq!(
            with(|r| { r.conditions_extra = "<saml:AudienceRestriction><saml:Audience>https://other-sp.example</saml:Audience></saml:AudienceRestriction>".into() }),
            "wrong_audience",
            "every restriction must name us"
        );
        assert_eq!(with(|r| r.conditions_extra = "<saml:OneTimeUse/>".into()), "ok");
        assert_eq!(check("not xml").unwrap_err().0, "bad_response");
        assert_eq!(
            check_response(&"A".repeat(MAX_RESPONSE + 4), &Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp(), request_id: Some(REQ), attributes: &Attributes::default(), now_ms: NOW, decrypt: &[], require_encrypted: false }).unwrap_err().0,
            "bad_response"
        );
    }

    /// Checked as an unsolicited response (ADR 0175): no request to answer.
    fn check_unsolicited(xml: &str) -> Result<Checked, Refused> {
        let idp = idp();
        let attributes = Attributes::default();
        check_response(&STANDARD.encode(xml), &Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp, request_id: None, attributes: &attributes, now_ms: NOW, decrypt: &[], require_encrypted: false })
    }

    fn unsolicited() -> Response {
        let mut r = base();
        r.in_response_to = String::new();
        r.confirm_in_response_to = String::new();
        r
    }

    #[test]
    fn unsolicited_responses_answer_no_request_and_are_checked_in_full() {
        let c = check_unsolicited(&unsolicited().xml()).unwrap();
        assert_eq!(c.claims.subject, "00u1ada-persistent");
        // An answer to some request (another browser's, or one that expired) is not unsolicited.
        assert_eq!(check_unsolicited(&base().xml()).unwrap_err().0, "in_response_to_mismatch");
        let mut half = unsolicited();
        half.confirm_in_response_to = REQ.into();
        assert_eq!(check_unsolicited(&half.xml()).unwrap_err().0, "in_response_to_mismatch", "the signed confirmation answers a request");
        let mut half = unsolicited();
        half.in_response_to = REQ.into();
        assert_eq!(check_unsolicited(&half.xml()).unwrap_err().0, "in_response_to_mismatch", "the response answers a request");
        // An empty InResponseTo, signed by the IdP, is not an absent one.
        let mut empty = unsolicited();
        empty.confirm_in_response_to = EMPTY_IN_RESPONSE_TO.into();
        assert!(empty.xml().contains(r#"<saml:SubjectConfirmationData InResponseTo="" "#));
        assert_eq!(check_unsolicited(&empty.xml()).unwrap_err().0, "in_response_to_mismatch", "on the confirmation");
        let mut empty = unsolicited();
        empty.in_response_to = EMPTY_IN_RESPONSE_TO.into();
        assert!(empty.xml().contains(r#" InResponseTo="">"#));
        assert_eq!(check_unsolicited(&empty.xml()).unwrap_err().0, "in_response_to_mismatch", "on the response");
        // Everything else holds as for a solicited one.
        let with = |f: fn(&mut Response)| {
            let mut r = unsolicited();
            f(&mut r);
            check_unsolicited(&r.xml()).err().map_or("ok", |e| e.0)
        };
        assert_eq!(with(|r| r.sign_assertion = false), "unsigned");
        assert_eq!(with(|r| r.signer = 1), "bad_signature");
        assert_eq!(with(|r| r.audience = "https://other.example/sp".into()), "wrong_audience");
        assert_eq!(with(|r| r.recipient = "https://other.example/acs".into()), "wrong_recipient");
        assert_eq!(with(|r| r.destination = Some("https://other.example/acs".into())), "wrong_destination");
        assert_eq!(with(|r| r.issuer = "https://evil.example/saml".into()), "wrong_issuer");
        assert_eq!(with(|r| r.confirm_not_on_or_after = NOW - 300_000), "expired");
        assert_eq!(with(|r| r.name_id_format = TRANSIENT.into()), "transient_subject");
    }

    // Encrypted assertions (ADR 0150)

    use crate::sso::xmlenc::test_encrypter::Encrypt;
    use crate::sso::xmlenc::{AES128_GCM, AES256_CBC, RSA_1_5};

    /// Our encryption key, and another SP's.
    fn enc_keys() -> &'static [SpKey; 2] {
        static K: std::sync::OnceLock<[SpKey; 2]> = std::sync::OnceLock::new();
        K.get_or_init(|| [SpKey::generate("enc").unwrap().0, SpKey::generate("other sp").unwrap().0])
    }

    fn encrypted() -> Response {
        let mut r = base();
        r.encrypt = Some(Encrypt::default());
        r.encrypt_to = enc_keys()[0].cert.clone();
        r
    }

    fn check_enc(xml: &str, require: bool) -> Result<Checked, Refused> {
        let idp = idp();
        let attributes = Attributes::default();
        let e = Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp, request_id: Some(REQ), attributes: &attributes, now_ms: NOW, decrypt: &[&enc_keys()[0]], require_encrypted: require };
        check_response(&STANDARD.encode(xml), &e)
    }

    fn enc_reason(xml: &str) -> &'static str {
        check_enc(xml, false).err().map_or("ok", |e| e.0)
    }

    /// `edit` applied to the decrypted assertion of `r` (signed already), then encrypted again
    /// to our key, as an attacker with only our public certificate can.
    fn reencrypted(r: &Response, edit: impl Fn(String) -> String) -> String {
        let mut plain = r.clone();
        plain.encrypt = None;
        let xml = plain.xml();
        let a = &xml[xml.find("<saml:Assertion").unwrap()..xml.rfind("</saml:Assertion>").unwrap() + "</saml:Assertion>".len()];
        xml.replace(a, &Encrypt::default().encrypt(&edit(a.to_string()), &enc_keys()[0].cert))
    }

    #[test]
    fn an_encrypted_assertion_signs_in_like_a_plain_one() {
        let r = encrypted();
        let xml = r.xml();
        assert!(xml.contains("<saml:EncryptedAssertion>") && !xml.contains("00u1ADA"), "the person is only in the ciphertext");
        let c = check_enc(&xml, true).unwrap();
        assert_eq!((c.claims.subject.as_str(), c.claims.email.as_deref(), c.assertion_id.as_str()), ("00u1ada-persistent", Some("ada@example.com"), r.assertion_id.as_str()));
        assert_eq!(c.login.session_index, Some(r.session_index.clone()));

        let mut variants = Vec::new();
        for (data_alg, key_inside, sign_response) in [(AES128_GCM, false, false), (AES128_GCM, true, true)] {
            let mut v = encrypted();
            v.encrypt = Some(Encrypt { data_alg: data_alg.into(), key_inside, ..Default::default() });
            v.sign_response = sign_response;
            variants.push(v.xml());
        }
        // Serialized with its own namespace declarations (as OpenSAML does), and after an XML declaration.
        let own = r.xml_with(|a| a.replacen("<saml:Assertion ", &format!(r#"<saml:Assertion xmlns:saml="{ASSERTION}" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" "#), 1));
        variants.push(own);
        variants.push(r.xml_with(|a| format!(r#"<?xml version="1.0" encoding="UTF-8"?>{a}"#)));
        for (i, xml) in variants.iter().enumerate() {
            assert_eq!(enc_reason(xml), "ok", "variant {i}");
        }
        // Allowed but not required: a plain assertion still works.
        assert!(check_enc(&base().xml(), false).is_ok());
    }

    #[test]
    fn encryption_settings_are_kept_to() {
        assert_eq!(check(&encrypted().xml()).unwrap_err().0, "encrypted_assertion", "off: no key to decrypt with");
        assert_eq!(check_enc(&base().xml(), true).unwrap_err().0, "unencrypted_assertion", "require: a plain assertion is refused");
        let mut both = base();
        both.sign_response = true;
        assert_eq!(check_enc(&both.xml(), true).unwrap_err().0, "unencrypted_assertion", "however well signed");
        let mut other = encrypted();
        other.encrypt_to = enc_keys()[1].cert.clone();
        assert_eq!(enc_reason(&other.xml()), "bad_encryption", "encrypted for another SP");
    }

    #[test]
    fn weak_encryption_is_refused() {
        let with = |f: fn(&mut Encrypt)| {
            let mut r = encrypted();
            let mut e = Encrypt::default();
            f(&mut e);
            r.encrypt = Some(e);
            enc_reason(&r.xml())
        };
        assert_eq!(with(|e| e.data_alg = AES256_CBC.into()), "weak_algorithm");
        assert_eq!(with(|e| e.key_alg = RSA_1_5.into()), "weak_key_transport");
        assert_eq!(with(|e| e.key_alg = "urn:x:none".into()), "bad_algorithm");
    }

    #[test]
    fn encryption_never_stands_in_for_the_idps_signature() {
        // Anyone can encrypt to our public certificate, so what's inside must still be signed.
        let mut unsigned = encrypted();
        unsigned.sign_assertion = false;
        assert_eq!(enc_reason(&unsigned.xml()), "unsigned");
        unsigned.sign_response = true;
        assert_eq!(enc_reason(&unsigned.xml()), "unsigned", "a signed response around an encrypted, unsigned assertion");
        let r = encrypted();
        assert_eq!(enc_reason(&reencrypted(&r, |a| a)), "ok", "re-encrypting a signed assertion changes nothing");
        assert_eq!(enc_reason(&reencrypted(&r, |a| a.replace("00u1ADA-Persistent", "00u1EVE-Persistent"))), "bad_signature", "changed, then encrypted");
        let mut other = encrypted();
        other.signer = 1;
        assert_eq!(enc_reason(&other.xml()), "bad_signature", "signed by someone else, then encrypted");

        // A bad response signature is refused before anything is decrypted, even with the wrong key.
        let mut signed = encrypted();
        signed.sign_response = true;
        signed.encrypt_to = enc_keys()[1].cert.clone();
        let tampered = signed.xml().replacen(&format!("InResponseTo=\"{REQ}\""), &format!("InResponseTo=\"{REQ}\" Consent=\"x\""), 1);
        assert_eq!(enc_reason(&tampered), "bad_signature");
    }

    #[test]
    fn wrapping_around_or_inside_an_encrypted_assertion_is_refused() {
        let r = encrypted();
        let xml = r.xml();
        let enc = &xml[xml.find("<saml:EncryptedAssertion>").unwrap()..xml.find("</samlp:Response>").unwrap()];
        let mut plain = r.clone();
        plain.encrypt = None;
        let plain_xml = plain.xml();
        let signed = &plain_xml[plain_xml.find("<saml:Assertion").unwrap()..plain_xml.find("</samlp:Response>").unwrap()];
        let outer = [
            ("beside a plain one", xml.replace(enc, &format!("{enc}{signed}"))),
            ("two encrypted", xml.replace(enc, &format!("{enc}{enc}"))),
            ("moved into extensions", xml.replace(enc, &format!("<samlp:Extensions>{enc}</samlp:Extensions>"))),
            ("in another namespace", xml.replace("saml:EncryptedAssertion", "samlp:EncryptedAssertion")),
            ("a signature inside it", xml.replacen("<xenc:EncryptedData", &format!(r#"<ds:Signature xmlns:ds="{}"/><xenc:EncryptedData"#, xmldsig::DSIG), 1)),
        ];
        for (what, xml) in outer {
            assert_eq!(enc_reason(&xml), "wrapped", "{what}");
        }

        let evil = |a: &str| a.replace(&r.assertion_id, "_evil").replace("00u1ADA-Persistent", "admin");
        let inner: [(&str, Box<dyn Fn(String) -> String>); 6] = [
            ("two assertions", Box::new(move |a| format!("{}{a}", evil(&a)))),
            ("the signed one in Advice", Box::new(move |a| evil(&a).replacen("</saml:Subject>", &format!("</saml:Subject><saml:Advice>{a}</saml:Advice>"), 1))),
            ("encrypted again", Box::new(|a| format!("<saml:EncryptedAssertion>{a}</saml:EncryptedAssertion>"))),
            ("text beside it", Box::new(|a| format!("{a}and more"))),
            ("something else", Box::new(|_| "<saml:Issuer>x</saml:Issuer>".into())),
            ("a signature moved into the subject", Box::new(|a| a.replacen("<ds:Signature", "<saml:Subject><ds:Signature", 1).replacen("</ds:Signature>", "</ds:Signature></saml:Subject>", 1))),
        ];
        for (what, edit) in inner {
            assert_eq!(enc_reason(&reencrypted(&r, edit)), "wrapped", "{what}");
        }
        // An ID inside the ciphertext that is also outside it.
        let mut dup = encrypted();
        dup.id = dup.assertion_id.clone();
        assert_eq!(enc_reason(&dup.xml()), "wrapped");

        // Inside, the same parser rules: no DTDs, no comments.
        assert_eq!(enc_reason(&reencrypted(&r, |a| a.replace("00u1ADA-Persistent", "00u1ADA<!---->-Persistent"))), "bad_response");
        assert_eq!(enc_reason(&reencrypted(&r, |a| format!(r#"<!DOCTYPE x [<!ENTITY e "x">]>{a}"#))), "bad_response");
        assert_eq!(enc_reason(&reencrypted(&r, |_| "\u{0}not utf-8 \u{FFFF}".into())), "bad_response");
    }

    #[test]
    fn encrypted_name_ids_are_decrypted_with_our_key() {
        // In a plain assertion, and in an encrypted one.
        for encrypt_assertion in [false, true] {
            let mut r = encrypted();
            r.encrypt_name_id_to = Some(enc_keys()[0].cert.clone());
            if !encrypt_assertion {
                r.encrypt = None;
            }
            let c = check_enc(&r.xml(), false).unwrap();
            assert_eq!(c.claims.subject, crate::sso::saml::subject("00u1ADA-Persistent"));
            assert_eq!((c.login.name_id.as_str(), c.login.format.as_deref()), ("00u1ADA-Persistent", Some(PERSISTENT)), "kept for single logout, decrypted");
        }
        let mut r = base();
        r.encrypt_name_id_to = Some(enc_keys()[0].cert.clone());
        assert_eq!(reason(r.clone()), "encrypted_id", "without ENCRYPTED_ASSERTIONS there is no key to decrypt it with");
        r.encrypt_name_id_to = Some(enc_keys()[1].cert.clone());
        assert_eq!(enc_reason(&r.xml()), "bad_encryption", "encrypted to another key");
        r.encrypt_name_id_to = Some(enc_keys()[0].cert.clone());
        r.name_id_format = TRANSIENT.into();
        assert_eq!(enc_reason(&r.xml()), "transient_subject", "the decrypted format is checked like a plain one");
        let (ec_pem, ec_cert) = ec_sp_key(&rcgen::PKCS_ECDSA_P256_SHA256);
        let ec = SpKey::from_pem(&ec_pem, &ec_cert).unwrap();
        let idp = idp();
        let attributes = Attributes::default();
        let e = Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp, request_id: Some(REQ), attributes: &attributes, now_ms: NOW, decrypt: &[&ec], require_encrypted: false };
        assert_eq!(check_response(&STANDARD.encode(r.xml()), &e).unwrap_err().0, "no_sp_key", "an ECDSA key can't decrypt");
    }

    #[test]
    fn encrypted_name_ids_use_only_strong_algorithms_and_hold_one_name_id() {
        let mut r = base();
        r.encrypt_name_id_to = Some(enc_keys()[0].cert.clone());
        let plain = format!(r#"<saml:NameID Format="{PERSISTENT}">00u1ADA-Persistent</saml:NameID>"#);
        let with_id = |inner: &str, e: &Encrypt| {
            let mut r = r.clone();
            r.encrypt_name_id_to = None;
            let xml = r.xml();
            let id = &xml[xml.find("<saml:NameID").unwrap()..xml.find("</saml:NameID>").unwrap() + "</saml:NameID>".len()];
            // Signed again over the swapped identifier, as the IdP would.
            let mut unsigned = r.clone();
            unsigned.sign_response = false;
            unsigned.sign_assertion = false;
            let swapped = unsigned.xml().replace(id, &e.encrypt_as("saml:EncryptedID", inner, &enc_keys()[0].cert));
            let aid = r.assertion_id.clone();
            crate::sso::xmldsig::test_signer::signer(0).sign(&swapped, &aid)
        };
        assert_eq!(enc_reason(&with_id(&plain, &Encrypt::default())), "ok");
        let cbc = Encrypt { data_alg: crate::sso::xmlenc::AES256_CBC.into(), ..Default::default() };
        assert_eq!(enc_reason(&with_id(&plain, &cbc)), "weak_algorithm", "AES-CBC is refused, as for assertions");
        let v15 = Encrypt { key_alg: crate::sso::xmlenc::RSA_1_5.into(), ..Default::default() };
        assert_eq!(enc_reason(&with_id(&plain, &v15)), "weak_key_transport", "RSA PKCS #1 v1.5 too");
        assert_eq!(enc_reason(&with_id(&format!("{plain}{plain}"), &Encrypt::default())), "wrapped", "two NameIDs inside");
        assert_eq!(enc_reason(&with_id(r#"<saml:BaseID xsi:type="x"/>"#, &Encrypt::default())), "wrapped", "only a NameID");
        assert_eq!(enc_reason(&with_id("<saml:NameID> padded </saml:NameID>", &Encrypt::default())), "missing_subject");
        let dtd = format!(r#"<!DOCTYPE x [<!ENTITY e "x">]>{plain}"#);
        assert_ne!(enc_reason(&with_id(&dtd, &Encrypt::default())), "ok", "no DTDs in the plaintext");
    }

    #[test]
    fn a_subject_names_the_person_once() {
        let mut r = encrypted();
        // Signed by the IdP with an EncryptedID beside the NameID.
        r.name_id = format!(r#"x</saml:NameID><saml:EncryptedID><xenc:EncryptedData xmlns:xenc="{}"/></saml:EncryptedID><saml:NameID>y"#, crate::sso::xmlenc::XENC);
        assert_eq!(enc_reason(&r.xml()), "wrapped");
        r.encrypt = None;
        assert_eq!(check(&r.xml()).unwrap_err().0, "wrapped", "plain too");
        let mut r = base();
        r.name_id = format!(r#"x</saml:NameID><saml:NameID Format="{PERSISTENT}">y"#);
        assert_eq!(reason(r), "wrapped", "two NameIDs");
        let mut r = base();
        r.name_id = "x</saml:NameID><saml:BaseID><x/></saml:BaseID><saml:NameID>y".into();
        assert_eq!(reason(r), "wrapped");
    }

    #[test]
    fn ecdsa_signed_responses_verify_against_ecdsa_idp_certificates() {
        for s in [2, 3] {
            let idp = parse_idp_metadata(&metadata_signed_by(s), IDP, false).unwrap();
            let attributes = Attributes::default();
            let run = |xml: &str| {
                let e = Expect { sp: Sp { entity_id: SP, acs: ACS }, idp: &idp, request_id: Some(REQ), attributes: &attributes, now_ms: NOW, decrypt: &[], require_encrypted: false };
                check_response(&STANDARD.encode(xml), &e).err().map_or("ok", |e| e.0)
            };
            let mut r = base();
            r.signer = s;
            assert_eq!(run(&r.xml()), "ok", "signer {s}");
            r.signer = if s == 2 { 3 } else { 2 };
            assert_eq!(run(&r.xml()), "bad_signature", "the other curve");
            r.signer = 0;
            assert_eq!(run(&r.xml()), "bad_signature", "an RSA key");
            let mut r = base();
            r.signer = s;
            let sha1 = r.xml().replace(xmldsig::ECDSA_SHA256, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1").replace(xmldsig::ECDSA_SHA384, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1");
            assert_eq!(run(&sha1), "weak_algorithm");
        }
    }

    fn trust(signers: &[&Signer], require: bool) -> MetadataTrust {
        MetadataTrust { certs: signers.iter().map(|s| s.cert()).collect(), require }
    }

    fn load(xml: &str, t: &MetadataTrust) -> Result<IdpMetadata, &'static str> {
        load_idp_metadata(xml, IDP, false, Some(t), NOW).map_err(|e| e.reason)
    }

    #[test]
    fn signed_metadata_is_checked_against_its_anchor() {
        let anchor = crate::sso::xmldsig::test_signer::signer(1);
        let required = trust(&[anchor], true);
        let signed = signed_metadata(&metadata(), anchor);
        let m = load(&signed, &required).unwrap();
        assert_eq!(m.certs[0].sha256, signers()[0].cert().sha256, "the IdP's own signing key, from signed metadata");
        assert_eq!(load(&metadata(), &required).unwrap_err(), "unsigned");
        assert!(load(&metadata(), &trust(&[anchor], false)).is_ok(), "allow: unsigned is still taken");
        assert_eq!(load(&signed_metadata(&metadata(), &signers()[0]), &required).unwrap_err(), "bad_signature", "signed by another key");
        assert_eq!(load(&signed_metadata(&metadata(), &signers()[0]), &trust(&[anchor], false)).unwrap_err(), "bad_signature", "allow: a bad signature is still refused");
        assert!(load(&signed_metadata(&metadata(), &signers()[0]), &trust(&[anchor, &signers()[0]], true)).is_ok(), "any of the anchors, for rollover");

        // The signing certificate swapped after signing: refused.
        let swapped = signed.replace(&signers()[0].cert, &signers()[1].cert);
        assert_eq!(load(&swapped, &required).unwrap_err(), "bad_signature");
        let moved = signed.replacen(r#"Location="https://idp.example"#, r#"Location="https://evil.example"#, 1);
        assert_eq!(load(&moved, &required).unwrap_err(), "bad_signature", "the SSO URL changed");
        // Comments don't change what was signed (exclusive C14N), and don't cut a certificate.
        let c = &signers()[0].cert;
        let commented = signed.replacen(c.as_str(), &format!("{}<!-- note -->{}", &c[..10], &c[10..]), 1);
        assert_eq!(load(&commented, &required).unwrap().certs[0].sha256, signers()[0].cert().sha256);
        let sha1 = signed.replace(xmldsig::RSA_SHA256, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        assert_eq!(load(&sha1, &required).unwrap_err(), "weak_algorithm");
        assert_eq!(load_idp_metadata(&metadata(), IDP, false, Some(&required), NOW).unwrap_err().message, "the metadata can't be trusted: it isn't signed, and signed metadata is required");
    }

    #[test]
    fn signed_metadata_may_be_ecdsa_and_expires() {
        for s in [2, 3] {
            let anchor = crate::sso::xmldsig::test_signer::signer(s);
            assert!(load(&signed_metadata(&metadata(), anchor), &trust(&[anchor], true)).is_ok(), "signer {s}");
        }
        let anchor = &signers()[1];
        let t = trust(&[anchor], true);
        let until = |ms: i64| metadata().replacen("<md:EntityDescriptor ", &format!(r#"<md:EntityDescriptor validUntil="{}" "#, instant(ms)), 1);
        assert!(load(&signed_metadata(&until(NOW + 1_000), anchor), &t).is_ok());
        assert_eq!(load(&signed_metadata(&until(NOW), anchor), &t).unwrap_err(), "expired", "an old signed copy, served again");
        assert!(load(&until(NOW - 1_000), &trust(&[anchor], false)).is_ok(), "unsigned metadata's validUntil vouches for nothing");
        assert!(parse_idp_metadata(&until(NOW - 1_000), IDP, false).is_ok(), "nor without an anchor, as before");
    }

    #[test]
    fn aggregates_are_trusted_by_their_own_signature_or_the_entitys() {
        let anchor = &signers()[1];
        let t = trust(&[anchor], true);
        let entity = metadata().replacen(r#"<?xml version="1.0"?>"#, "", 1);
        let other = entity.replace(IDP, "https://other.example/saml");
        let aggregate = |inner: &str| format!(r#"<md:EntitiesDescriptor xmlns:md="{METADATA}">{other}{inner}</md:EntitiesDescriptor>"#);
        assert!(load(&signed_metadata(&aggregate(&entity), anchor), &t).is_ok(), "the whole aggregate signed");
        assert!(load(&aggregate(&signed_metadata(&entity, anchor)), &t).is_ok(), "only our entity signed");
        assert_eq!(load(&aggregate(&signed_metadata(&entity, &signers()[0])), &t).unwrap_err(), "bad_signature");
        let other_signed = format!(r#"<md:EntitiesDescriptor xmlns:md="{METADATA}">{}{entity}</md:EntitiesDescriptor>"#, signed_metadata(&other, anchor));
        assert_eq!(load(&other_signed, &t).unwrap_err(), "unsigned", "another entity's signature vouches not for ours");
        assert_eq!(load(&aggregate(&entity), &t).unwrap_err(), "unsigned");

        // A signed root covers the validUntil of every descriptor between it and our entity.
        let nested = |until: i64| {
            format!(
                r#"<md:EntitiesDescriptor xmlns:md="{METADATA}" validUntil="{}"><md:EntitiesDescriptor validUntil="{}">{entity}</md:EntitiesDescriptor></md:EntitiesDescriptor>"#,
                instant(NOW + 86_400_000),
                instant(until)
            )
        };
        assert!(load(&signed_metadata(&nested(NOW + 1_000), anchor), &t).is_ok());
        assert_eq!(load(&signed_metadata(&nested(NOW - 1_000), anchor), &t).unwrap_err(), "expired", "an expired middle level");
    }

    #[test]
    fn sp_metadata_offers_only_strong_encryption() {
        let sp = Sp { entity_id: SP, acs: ACS };
        let (sign, _) = SpKey::generate("sp").unwrap();
        let enc = &enc_keys()[0];
        let md = sp_metadata(&sp, Some(&SpSigning { certs: &[&sign.cert], slo: "https://bot.example.com/slo", sign_requests: false }), &[&enc.cert]);
        let doc = roxmltree::Document::parse(&md).unwrap();
        let spsso = doc.descendants().find(|n| is(*n, METADATA, "SPSSODescriptor")).unwrap();
        let order: Vec<String> = elements(spsso).iter().map(|n| format!("{}{}", n.tag_name().name(), n.attribute("use").map(|u| format!("/{u}")).unwrap_or_default())).collect();
        assert_eq!(order, ["KeyDescriptor/signing", "KeyDescriptor/encryption", "SingleLogoutService", "SingleLogoutService", "NameIDFormat", "AssertionConsumerService"], "schema order");
        let kd = elements(spsso)[1];
        assert_eq!(kd.descendants().find(|n| is(*n, xmldsig::DSIG, "X509Certificate")).and_then(|n| n.text()), Some(enc.cert.as_str()), "its own key, not the signing one");
        let methods: Vec<&str> = elements(kd).iter().filter(|n| is(**n, METADATA, "EncryptionMethod")).filter_map(|n| n.attribute("Algorithm")).collect();
        assert_eq!(methods.len(), 4);
        assert!(methods.iter().all(|m| m.contains("gcm") || m.contains("rsa-oaep")), "{methods:?}");
        // What the metadata offers, botd takes.
        let ok = Encrypt { key_alg: crate::sso::xmlenc::RSA_OAEP.into(), ..Default::default() };
        let mut r = encrypted();
        r.encrypt = Some(ok);
        assert_eq!(enc_reason(&r.xml()), "ok");
        assert!(!sp_metadata(&sp, None, &[]).contains("encryption"), "off: nothing to encrypt to");
    }
}
