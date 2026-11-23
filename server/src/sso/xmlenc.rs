//! XML Encryption for native SAML (ADR 0150): decrypts the one `EncryptedAssertion` an IdP
//! sends us, or an `EncryptedID` (ADR 0151), with our own SP encryption key, and nothing looser.
//!
//! It takes only what is still sound: AES-GCM for the assertion (XML Encryption 1.1), and
//! RSA-OAEP for the key that encrypts it. AES-CBC and Triple DES are refused (the CBC padding
//! oracle of "How to Break XML Encryption", and the backwards-compatibility attack that turns
//! a GCM key into a CBC oracle), as is RSA PKCS #1 v1.5 key transport (Bleichenbacher's
//! oracle). Every algorithm is checked before anything is decrypted, so a refusal never
//! depends on a secret.
//!
//! Decryption itself fails one way only, `bad_encryption`: a content key that doesn't decrypt,
//! or decrypts to the wrong length, is replaced by a random one, so a bad key and a bad
//! ciphertext both end in the same GCM tag failure. Keys come only from our private key,
//! never from `KeyInfo`, and `CipherReference` (fetching ciphertext from a URI) is refused.
//!
//! The plaintext is as untrusted as a posted response: anyone with our public certificate can
//! encrypt to us. The caller parses it with the same rules and still requires the IdP's
//! signature on the assertion inside.

use super::jwt::Invalid;
use super::xmldsig::{self, DSIG, elements, is};
use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::rsa::{OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512, OaepAlgorithm, OaepPrivateDecryptingKey};
use roxmltree::Node;
use zeroize::Zeroizing;

pub const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
pub const XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
const ELEMENT: &str = "http://www.w3.org/2001/04/xmlenc#Element";
pub const AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
pub const AES192_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
pub const AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
pub const AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
pub const AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const AES192_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
const TRIPLEDES_CBC: &str = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
/// RSA-OAEP with MGF1-SHA1; its digest defaults to SHA-1 (XML Encryption 1.0).
pub const RSA_OAEP_MGF1P: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
/// RSA-OAEP with a digest and MGF of its own (XML Encryption 1.1); both default to SHA-1.
pub const RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
pub const RSA_1_5: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
pub const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const MGF1_SHA1: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha1";
pub const MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
const MGF1_SHA384: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha384";
const MGF1_SHA512: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha512";
/// More than an IdP sends (one per certificate of ours it knows, in a rollover).
const MAX_KEYS: usize = 4;
const GCM_IV: usize = 12;
const GCM_TAG: usize = 16;

fn bad() -> Invalid {
    Invalid("bad_encryption")
}

/// The AES-GCM `EncryptionMethod` of the data. CBC modes are weak, anything else unknown.
fn content_cipher(method: Node) -> Result<&'static aead::Algorithm, Invalid> {
    if !is(method, XENC, "EncryptionMethod") || !elements(method).is_empty() {
        return Err(bad());
    }
    match method.attribute("Algorithm") {
        Some(AES128_GCM) => Ok(&aead::AES_128_GCM),
        Some(AES192_GCM) => Ok(&aead::AES_192_GCM),
        Some(AES256_GCM) => Ok(&aead::AES_256_GCM),
        Some(AES128_CBC | AES192_CBC | AES256_CBC | TRIPLEDES_CBC) => Err(Invalid("weak_algorithm")),
        _ => Err(Invalid("bad_algorithm")),
    }
}

/// The RSA-OAEP parameters of an `EncryptedKey`'s `EncryptionMethod`: a digest and MGF1 hash
/// that are the same (what aws-lc offers), and no OAEP label.
fn key_transport(method: Node) -> Result<&'static OaepAlgorithm, Invalid> {
    if !is(method, XENC, "EncryptionMethod") {
        return Err(bad());
    }
    let alg = method.attribute("Algorithm").unwrap_or("");
    if alg == RSA_1_5 {
        return Err(Invalid("weak_key_transport"));
    }
    if alg != RSA_OAEP_MGF1P && alg != RSA_OAEP {
        return Err(Invalid("bad_algorithm"));
    }
    let (mut digest, mut mgf) = (SHA1, MGF1_SHA1);
    for c in elements(method) {
        match (c.tag_name().namespace(), c.tag_name().name()) {
            (Some(DSIG), "DigestMethod") => digest = c.attribute("Algorithm").unwrap_or(""),
            (Some(XENC11), "MGF") if alg == RSA_OAEP => mgf = c.attribute("Algorithm").unwrap_or(""),
            _ => return Err(Invalid("bad_algorithm")),
        }
    }
    match (digest, mgf) {
        (SHA1, MGF1_SHA1) => Ok(&OAEP_SHA1_MGF1SHA1),
        (SHA256, MGF1_SHA256) => Ok(&OAEP_SHA256_MGF1SHA256),
        (SHA384, MGF1_SHA384) => Ok(&OAEP_SHA384_MGF1SHA384),
        (SHA512, MGF1_SHA512) => Ok(&OAEP_SHA512_MGF1SHA512),
        _ => Err(Invalid("bad_algorithm")),
    }
}

/// The bytes of a `CipherData`'s one `CipherValue`. A `CipherReference` would have us fetch.
fn cipher_value(data: Node) -> Result<Vec<u8>, Invalid> {
    match elements(data).as_slice() {
        [v] if is(*v, XENC, "CipherValue") && elements(*v).is_empty() => xmldsig::base64(v.text().unwrap_or("")).ok_or_else(bad),
        _ => Err(bad()),
    }
}

/// One `EncryptedKey`: how it was encrypted, and the encrypted content key.
fn encrypted_key(k: Node) -> Result<(&'static OaepAlgorithm, Vec<u8>), Invalid> {
    let kids = elements(k);
    let Some((method, rest)) = kids.split_first() else { return Err(bad()) };
    let alg = key_transport(*method)?;
    let mut value = None;
    for c in rest {
        match (c.tag_name().namespace(), c.tag_name().name()) {
            (Some(XENC), "CipherData") if value.is_none() => value = Some(*c),
            // Which of our keys it names, and what it encrypts: our key is the only one, and
            // what it encrypts is the EncryptedData beside it.
            (Some(DSIG), "KeyInfo") | (Some(XENC), "ReferenceList" | "CarriedKeyName") => {}
            _ => return Err(bad()),
        }
    }
    Ok((alg, cipher_value(value.ok_or_else(bad)?)?))
}

/// Decrypts `encrypted` (a `saml:EncryptedAssertion` or `EncryptedID`) with one of `ours` (several
/// during a rollover of our key, ADR 0181). Its children are one `EncryptedData` and, beside it
/// or in its `KeyInfo`, the `EncryptedKey`s that carry its content key. Every key of ours is
/// tried on every `EncryptedKey`, so the work doesn't depend on which one opens. Returns the
/// plaintext (the serialized element, still to be checked) and the index of the key that opened it.
pub fn decrypt(encrypted: Node, ours: &[&OaepPrivateDecryptingKey]) -> Result<(Zeroizing<Vec<u8>>, usize), Invalid> {
    let mut data = None;
    let mut keys = Vec::new();
    for c in elements(encrypted) {
        if is(c, XENC, "EncryptedData") && data.is_none() {
            data = Some(c);
        } else if is(c, XENC, "EncryptedKey") {
            keys.push(c);
        } else {
            return Err(bad());
        }
    }
    let data = data.ok_or_else(bad)?;
    if data.attribute("Type").is_some_and(|t| t != ELEMENT) {
        return Err(bad());
    }
    let (method, key_info, cipher) = match elements(data).as_slice() {
        [m, c] => (*m, None, *c),
        [m, k, c] if is(*k, DSIG, "KeyInfo") => (*m, Some(*k), *c),
        _ => return Err(bad()),
    };
    if !is(cipher, XENC, "CipherData") {
        return Err(bad());
    }
    let cipher_alg = content_cipher(method)?;
    for c in key_info.map(elements).unwrap_or_default() {
        match (c.tag_name().namespace(), c.tag_name().name()) {
            (Some(XENC), "EncryptedKey") => keys.push(c),
            (Some(DSIG), "RetrievalMethod" | "KeyName") => {}
            _ => return Err(bad()),
        }
    }
    if keys.is_empty() || keys.len() > MAX_KEYS || ours.is_empty() {
        return Err(bad());
    }
    let keys: Vec<(&OaepAlgorithm, Vec<u8>)> = keys.into_iter().map(encrypted_key).collect::<Result<_, _>>()?;
    // Opened in place: the plaintext never leaves this zeroizing buffer.
    let mut sealed = Zeroizing::new(cipher_value(cipher)?);
    if sealed.len() < GCM_IV + GCM_TAG {
        return Err(bad());
    }

    let len = cipher_alg.key_len();
    let mut content_key = Zeroizing::new(vec![0u8; len]);
    SystemRandom::new().fill(&mut content_key).map_err(|_| bad())?;
    let mut found = None;
    for (i, key) in ours.iter().enumerate() {
        let mut out = Zeroizing::new(vec![0u8; key.min_output_size()]);
        for (alg, wrapped) in &keys {
            if let Ok(k) = key.decrypt(alg, wrapped, &mut out, None)
                && k.len() == len
                && found.is_none()
            {
                content_key.copy_from_slice(k);
                found = Some(i);
            }
        }
    }
    let opener = LessSafeKey::new(UnboundKey::new(cipher_alg, &content_key).map_err(|_| bad())?);
    let (iv, body) = sealed.split_at_mut(GCM_IV);
    let nonce = Nonce::try_assume_unique_for_key(iv).map_err(|_| bad())?;
    let n = opener.open_in_place(nonce, Aad::empty(), body).map_err(|_| bad())?.len();
    sealed.copy_within(GCM_IV..GCM_IV + n, 0);
    sealed.truncate(n);
    Ok((sealed, found.unwrap_or(0)))
}

#[cfg(test)]
pub mod test_encrypter {
    //! Encrypts an assertion the way an IdP does, to a certificate from our metadata, with any
    //! algorithm named (even ones botd refuses) and any part replaceable.

    use super::*;
    use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    #[derive(Clone)]
    pub struct Encrypt {
        /// The data's `EncryptionMethod`; only the GCM ones really encrypt.
        pub data_alg: String,
        /// The key's `EncryptionMethod` and what goes in it.
        pub key_alg: String,
        pub key_method_extra: String,
        /// The `EncryptedKey` in the `EncryptedData`'s `KeyInfo` (Okta, Entra) or beside it.
        pub key_inside: bool,
        /// Encrypt the content key with SHA-256 OAEP (for `xenc11#rsa-oaep` with SHA-256).
        pub oaep_sha256: bool,
    }

    impl Default for Encrypt {
        fn default() -> Encrypt {
            Encrypt { data_alg: AES256_GCM.into(), key_alg: RSA_OAEP_MGF1P.into(), key_method_extra: String::new(), key_inside: true, oaep_sha256: false }
        }
    }

    fn public_key(cert_b64: &str) -> OaepPublicEncryptingKey {
        let der = STANDARD.decode(cert_b64).unwrap();
        let (_, c) = x509_parser::parse_x509_certificate(&der).unwrap();
        OaepPublicEncryptingKey::new(PublicEncryptingKey::from_der(c.public_key().raw).unwrap()).unwrap()
    }

    /// A content key's RSA-OAEP encryption to `cert`.
    pub fn wrap_key(cert_b64: &str, content_key: &[u8], sha256: bool) -> String {
        let pk = public_key(cert_b64);
        let mut out = vec![0; pk.ciphertext_size()];
        let alg = if sha256 { &OAEP_SHA256_MGF1SHA256 } else { &OAEP_SHA1_MGF1SHA1 };
        STANDARD.encode(pk.encrypt(alg, content_key, &mut out, None).unwrap())
    }

    /// `plaintext` sealed with AES-GCM under `content_key`: IV, ciphertext, tag.
    pub fn seal(content_key: &[u8], plaintext: &[u8]) -> String {
        let alg = match content_key.len() {
            16 => &aead::AES_128_GCM,
            24 => &aead::AES_192_GCM,
            _ => &aead::AES_256_GCM,
        };
        let key = LessSafeKey::new(UnboundKey::new(alg, content_key).unwrap());
        let mut iv = [0u8; GCM_IV];
        SystemRandom::new().fill(&mut iv).unwrap();
        let mut body = plaintext.to_vec();
        key.seal_in_place_append_tag(Nonce::assume_unique_for_key(iv), Aad::empty(), &mut body).unwrap();
        STANDARD.encode([iv.as_slice(), &body].concat())
    }

    pub fn key_len(data_alg: &str) -> usize {
        match data_alg {
            AES128_GCM | AES128_CBC => 16,
            AES192_GCM => 24,
            _ => 32,
        }
    }

    impl Encrypt {
        /// The `EncryptedKey` for `content_key`, to `cert`.
        pub fn encrypted_key(&self, cert_b64: &str, content_key: &[u8]) -> String {
            let wrapped = wrap_key(cert_b64, content_key, self.oaep_sha256);
            format!(
                r#"<xenc:EncryptedKey xmlns:xenc="{XENC}"><xenc:EncryptionMethod Algorithm="{}">{}</xenc:EncryptionMethod><ds:KeyInfo xmlns:ds="{DSIG}"><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{wrapped}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>"#,
                self.key_alg, self.key_method_extra
            )
        }

        /// `assertion` (a serialized `saml:Assertion`) as an `EncryptedAssertion` to `cert`.
        pub fn encrypt(&self, assertion: &str, cert_b64: &str) -> String {
            let mut content_key = vec![0u8; key_len(&self.data_alg)];
            SystemRandom::new().fill(&mut content_key).unwrap();
            self.encrypt_with(assertion, cert_b64, &content_key)
        }

        pub fn encrypt_with(&self, assertion: &str, cert_b64: &str, content_key: &[u8]) -> String {
            self.encrypt_element("saml:EncryptedAssertion", assertion, cert_b64, content_key)
        }

        /// `plaintext` (a serialized element) inside `element` (`saml:EncryptedID`, say), to `cert`.
        pub fn encrypt_as(&self, element: &str, plaintext: &str, cert_b64: &str) -> String {
            let mut content_key = vec![0u8; key_len(&self.data_alg)];
            SystemRandom::new().fill(&mut content_key).unwrap();
            self.encrypt_element(element, plaintext, cert_b64, &content_key)
        }

        fn encrypt_element(&self, element: &str, plaintext: &str, cert_b64: &str, content_key: &[u8]) -> String {
            let ek = self.encrypted_key(cert_b64, content_key);
            let value = seal(content_key, plaintext.as_bytes());
            let (inside, beside) = if self.key_inside { (format!(r#"<ds:KeyInfo xmlns:ds="{DSIG}">{ek}</ds:KeyInfo>"#), String::new()) } else { (String::new(), ek) };
            format!(
                r#"<{element}><xenc:EncryptedData xmlns:xenc="{XENC}" Type="{ELEMENT}"><xenc:EncryptionMethod Algorithm="{}"/>{inside}<xenc:CipherData><xenc:CipherValue>{value}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>{beside}</{element}>"#,
                self.data_alg
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_encrypter::*;
    use super::*;
    use crate::sso::saml_sp::SpKey;
    use std::sync::OnceLock;

    const ASSERTION: &str = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml:Issuer>idp</saml:Issuer></saml:Assertion>"#;
    const WRAP: &str = r#"<r xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">"#;

    /// Two SP encryption keys, made once (RSA key generation is slow).
    fn keys() -> &'static [SpKey; 2] {
        static K: OnceLock<[SpKey; 2]> = OnceLock::new();
        K.get_or_init(|| [SpKey::generate("enc").unwrap().0, SpKey::generate("other").unwrap().0])
    }

    fn open(xml: &str, key: &SpKey) -> Result<String, &'static str> {
        open_with(xml, &[key]).map(|(p, _)| p)
    }

    fn open_with(xml: &str, ours: &[&SpKey]) -> Result<(String, usize), &'static str> {
        let doc = roxmltree::Document::parse(xml).map_err(|_| "xml")?;
        let enc = doc.descendants().find(|n| n.tag_name().name() == "EncryptedAssertion").unwrap();
        let ours: Vec<_> = ours.iter().map(|k| k.decrypting().unwrap()).collect();
        decrypt(enc, &ours).map(|(p, i)| (String::from_utf8(p.to_vec()).unwrap(), i)).map_err(|e| e.0)
    }

    fn sealed(e: &Encrypt) -> String {
        format!("{WRAP}{}</r>", e.encrypt(ASSERTION, &keys()[0].cert))
    }

    #[test]
    fn decrypts_gcm_with_oaep_keys_wherever_the_key_is() {
        let key = &keys()[0];
        for data_alg in [AES128_GCM, AES192_GCM, AES256_GCM] {
            for key_inside in [true, false] {
                let e = Encrypt { data_alg: data_alg.into(), key_inside, ..Default::default() };
                assert_eq!(open(&sealed(&e), key).as_deref(), Ok(ASSERTION), "{data_alg} {key_inside}");
            }
        }
        let sha1_explicit = Encrypt { key_method_extra: format!(r#"<ds:DigestMethod xmlns:ds="{DSIG}" Algorithm="{SHA1}"/>"#), ..Default::default() };
        assert_eq!(open(&sealed(&sha1_explicit), key).as_deref(), Ok(ASSERTION));
        let xenc11_sha1 = Encrypt { key_alg: RSA_OAEP.into(), ..Default::default() };
        assert_eq!(open(&sealed(&xenc11_sha1), key).as_deref(), Ok(ASSERTION), "XML Encryption 1.1 OAEP defaults to SHA-1");
        let xenc11_sha256 = Encrypt {
            key_alg: RSA_OAEP.into(),
            key_method_extra: format!(r#"<ds:DigestMethod xmlns:ds="{DSIG}" Algorithm="{SHA256}"/><xenc11:MGF xmlns:xenc11="{XENC11}" Algorithm="{MGF1_SHA256}"/>"#),
            oaep_sha256: true,
            ..Default::default()
        };
        assert_eq!(open(&sealed(&xenc11_sha256), key).as_deref(), Ok(ASSERTION));
    }

    #[test]
    fn refuses_weak_and_unknown_algorithms_before_decrypting() {
        let key = &keys()[0];
        let with = |f: fn(&mut Encrypt)| {
            let mut e = Encrypt::default();
            f(&mut e);
            open(&sealed(&e), key)
        };
        assert_eq!(with(|e| e.data_alg = AES256_CBC.into()), Err("weak_algorithm"), "the CBC padding oracle");
        assert_eq!(with(|e| e.data_alg = AES128_CBC.into()), Err("weak_algorithm"));
        assert_eq!(with(|e| e.data_alg = TRIPLEDES_CBC.into()), Err("weak_algorithm"));
        assert_eq!(with(|e| e.data_alg = "urn:x:chacha".into()), Err("bad_algorithm"));
        assert_eq!(with(|e| e.key_alg = RSA_1_5.into()), Err("weak_key_transport"), "Bleichenbacher");
        assert_eq!(with(|e| e.key_alg = "http://www.w3.org/2001/04/xmlenc#kw-aes256".into()), Err("bad_algorithm"), "no shared secret to wrap with");
        assert_eq!(with(|e| e.key_method_extra = format!(r#"<ds:DigestMethod xmlns:ds="{DSIG}" Algorithm="{SHA256}"/>"#)), Err("bad_algorithm"), "SHA-256 with MGF1-SHA1: not offered");
        assert_eq!(with(|e| e.key_method_extra = format!(r#"<xenc:OAEPparams xmlns:xenc="{XENC}">AAAA</xenc:OAEPparams>"#)), Err("bad_algorithm"), "no OAEP label");
        assert_eq!(with(|e| e.key_method_extra = format!(r#"<xenc11:MGF xmlns:xenc11="{XENC11}" Algorithm="{MGF1_SHA256}"/>"#)), Err("bad_algorithm"), "MGF only with xenc11 rsa-oaep");
        assert_eq!(
            with(|e| {
                e.key_alg = RSA_OAEP.into();
                e.key_method_extra = format!(r#"<ds:DigestMethod xmlns:ds="{DSIG}" Algorithm="{SHA256}"/><xenc11:MGF xmlns:xenc11="{XENC11}" Algorithm="{MGF1_SHA1}"/>"#);
            }),
            Err("bad_algorithm"),
            "mixed digest and MGF"
        );
        // A weak key beside a good one is still refused: nothing is tried until all pass.
        let e = Encrypt::default();
        let xml = sealed(&e);
        let weak = Encrypt { key_alg: RSA_1_5.into(), ..Default::default() }.encrypted_key(&key.cert, &[0; 32]);
        let two = xml.replacen("</xenc:EncryptedData>", &format!("</xenc:EncryptedData>{weak}"), 1);
        assert_eq!(open(&two, key), Err("weak_key_transport"));
    }

    #[test]
    fn every_decryption_failure_looks_the_same() {
        let [key, other] = keys();
        let e = Encrypt::default();
        let xml = sealed(&e);
        assert_eq!(open(&xml, other), Err("bad_encryption"), "encrypted to someone else");
        // The ciphertext or its tag changed: GCM says no.
        let value = xml.rsplit("<xenc:CipherValue>").next().unwrap().split('<').next().unwrap();
        let mut bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 1;
        let flipped = xml.replace(value, &base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes));
        assert_eq!(open(&flipped, key), Err("bad_encryption"));
        // A content key of the wrong length decrypts fine under OAEP, but is never used.
        let short = e.encrypt_with(ASSERTION, &key.cert, &[7; 16]);
        assert_eq!(open(&format!("{WRAP}{short}</r>"), key), Err("bad_encryption"), "a 128-bit key for AES-256");
        // The key slot holding garbage.
        let garbage = xml.replacen("<xenc:CipherValue>", "<xenc:CipherValue>AAAA", 1);
        assert_eq!(open(&garbage, key), Err("bad_encryption"));
        let truncated = xml.replace(value, "AAAA");
        assert_eq!(open(&truncated, key), Err("bad_encryption"), "shorter than an IV and a tag");
    }

    #[test]
    fn refuses_odd_structures_and_references() {
        let key = &keys()[0];
        let xml = sealed(&Encrypt::default());
        let cases = [
            ("no key", xml.replace(&xml[xml.find(r#"<ds:KeyInfo"#).unwrap()..xml.rfind("</ds:KeyInfo>").unwrap() + 13], "")),
            ("fetch the ciphertext", xml.replacen("<xenc:CipherData><xenc:CipherValue>", r#"<xenc:CipherData><xenc:CipherReference URI="https://evil.example/c"/><xenc:CipherValue>"#, 1)),
            ("two data", xml.replace("</saml:EncryptedAssertion>", r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>"#)),
            ("something else beside it", xml.replace("</saml:EncryptedAssertion>", "<saml:Assertion/></saml:EncryptedAssertion>")),
            ("content, not an element", xml.replace(ELEMENT, "http://www.w3.org/2001/04/xmlenc#Content")),
            ("properties", xml.replacen("<xenc:CipherData>", "<xenc:EncryptionProperties/><xenc:CipherData>", 1)),
            ("a key from the message", xml.replacen("<xenc:EncryptedKey", r#"<ds:KeyValue/><xenc:EncryptedKey"#, 1)),
        ];
        for (what, xml) in cases {
            assert_eq!(open(&xml, key), Err("bad_encryption"), "{what}");
        }
        let five = (0..5).map(|_| Encrypt::default().encrypted_key(&key.cert, &[1; 32])).collect::<String>();
        let many = xml.replace("</saml:EncryptedAssertion>", &format!("{five}</saml:EncryptedAssertion>"));
        assert_eq!(open(&many, key), Err("bad_encryption"), "too many keys to try");
        // One of several keys is ours (a rollover at the IdP): that one is used.
        let theirs = Encrypt::default().encrypted_key(&keys()[1].cert, &[1; 32]);
        let rollover = xml.replace("</saml:EncryptedAssertion>", &format!("{theirs}</saml:EncryptedAssertion>"));
        assert_eq!(open(&rollover, key).as_deref(), Ok(ASSERTION));
    }

    #[test]
    fn opens_with_whichever_of_our_keys_it_was_encrypted_to() {
        let [key, other] = keys();
        let xml = sealed(&Encrypt::default());
        assert_eq!(open_with(&xml, &[key, other]), Ok((ASSERTION.to_string(), 0)));
        assert_eq!(open_with(&xml, &[other, key]), Ok((ASSERTION.to_string(), 1)), "a rollover's other key: says which");
        assert_eq!(open_with(&xml, &[other]), Err("bad_encryption"));
        assert_eq!(open_with(&xml, &[]), Err("bad_encryption"), "no key of ours");
        // Encrypted to both (an IdP that knows our current and next key): the first of ours.
        let both = xml.replace("</saml:EncryptedAssertion>", &format!("{}</saml:EncryptedAssertion>", Encrypt::default().encrypted_key(&other.cert, &[9; 32])));
        assert_eq!(open_with(&both, &[key, other]).map(|(_, i)| i), Ok(0));
    }
}
