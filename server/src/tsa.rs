//! RFC 3161 time-stamping for audit checkpoints (ADR 0149): the request botd sends a
//! time-stamping authority (TSA), and the checks a token must pass before botd keeps it
//! and every time it is read back.
//!
//! A token is a CMS SignedData (RFC 5652) whose content is a TSTInfo: the hash it was
//! asked to stamp, the TSA's time, and the nonce botd sent. It counts only if:
//!
//! - the TSTInfo's hash is SHA-256 of what botd stamped (and, when stamping, the nonce is
//!   the one botd sent);
//! - the signed attributes name a TSTInfo and carry its digest, and their signature
//!   verifies with the signer's certificate, which an ESS signing-certificate attribute
//!   binds to the signature (RFC 2634, RFC 5035);
//! - that certificate is for time-stamping (extended key usage) and was valid at the
//!   token's time;
//! - with `AUDIT_TIMESTAMP_CA_FILE` set, it is one of those certificates or chains to
//!   one, each link checked. Without it, a token is checked as far as it can be, and
//!   reported as `trusted: null`.
//!
//! Only DER is read (RFC 3161 tokens are DER), with a small reader of its own: no CMS
//! library. Signatures: RSA PKCS #1 v1.5, ECDSA P-256 and P-384 with SHA-256, -384 or
//! -512, and Ed25519. Never SHA-1, except for the hash an ESSCertID (v1) names its
//! certificate by, which isn't a signature.

use serde::Serialize;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const SHA384: &str = "2.16.840.1.101.3.4.2.2";
const SHA512: &str = "2.16.840.1.101.3.4.2.3";
const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const SIGNING_CERT: &str = "1.2.840.113549.1.9.16.2.12";
const SIGNING_CERT_V2: &str = "1.2.840.113549.1.9.16.2.47";
const RSA: &str = "1.2.840.113549.1.1.1";
const EC: &str = "1.2.840.10045.2.1";
const ED25519: &str = "1.3.101.112";
const P256: &str = "1.2.840.10045.3.1.7";
const P384: &str = "1.3.132.0.34";

const SEQ: u8 = 0x30;
const SET: u8 = 0x31;
const INT: u8 = 0x02;
const OCTETS: u8 = 0x04;
const OID: u8 = 0x06;
const BOOL: u8 = 0x01;
const BITS: u8 = 0x03;
const GENERALIZED_TIME: u8 = 0x18;
const CTX0: u8 = 0xa0;
const CTX1: u8 = 0xa1;
/// How deep a certificate chain may go.
const MAX_CHAIN: usize = 6;
/// Bigger than any real reply (a few KB with the TSA's chain); a bound on what we read.
pub const MAX_REPLY: usize = 256 * 1024;

/// Why a token doesn't count: a code for the audit log and the API, and a message.
#[derive(Clone, Debug, PartialEq)]
pub struct Invalid {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn bad(code: &'static str, message: impl Into<String>) -> Invalid {
    Invalid { code, message: message.into() }
}

fn malformed(what: &str) -> Invalid {
    bad("malformed", format!("the time-stamp token is malformed: {what}"))
}

// A DER reader: definite lengths, low tag numbers, nothing BER allows that DER doesn't need.

#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub body: &'a [u8],
    /// The whole element, tag and length included.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn reader(&self) -> Reader<'a> {
        Reader(self.body)
    }
}

pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Reader<'a> {
        Reader(b)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    pub fn next(&mut self) -> Result<Tlv<'a>, Invalid> {
        let b = self.0;
        let (&tag, rest) = b.split_first().ok_or_else(|| malformed("it ends early"))?;
        if tag & 0x1f == 0x1f {
            return Err(malformed("a high tag number"));
        }
        let (&first, rest) = rest.split_first().ok_or_else(|| malformed("it ends early"))?;
        let (len, rest) = match first {
            l if l < 0x80 => (l as usize, rest),
            0x81..=0x84 => {
                let n = (first & 0x7f) as usize;
                if rest.len() < n {
                    return Err(malformed("it ends early"));
                }
                (rest[..n].iter().fold(0usize, |l, &x| (l << 8) | x as usize), &rest[n..])
            }
            _ => return Err(malformed("an indefinite or oversized length")),
        };
        if rest.len() < len {
            return Err(malformed("it ends early"));
        }
        let head = b.len() - rest.len();
        let t = Tlv { tag, body: &rest[..len], raw: &b[..head + len] };
        self.0 = &rest[len..];
        Ok(t)
    }

    pub fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, Invalid> {
        let t = self.next()?;
        if t.tag != tag {
            return Err(malformed(&format!("expected tag {tag:#04x}, found {:#04x}", t.tag)));
        }
        Ok(t)
    }

    pub fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, Invalid> {
        if self.peek() == Some(tag) { self.next().map(Some) } else { Ok(None) }
    }
}

/// An OID's dotted form.
pub fn oid_string(body: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    for &b in body {
        v = (v << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let first = (v / 40).min(2);
                parts.extend([first, v - first * 40]);
            } else {
                parts.push(v);
            }
            v = 0;
        }
    }
    parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".")
}

fn read_oid(r: &mut Reader) -> Result<String, Invalid> {
    Ok(oid_string(r.expect(OID)?.body))
}

/// An AlgorithmIdentifier's OID; its parameters aren't needed for any algorithm we take.
fn algorithm(t: Tlv) -> Result<String, Invalid> {
    read_oid(&mut t.reader())
}

/// An INTEGER's magnitude, without the leading zeros DER adds to keep it positive.
fn unsigned(b: &[u8]) -> &[u8] {
    let skip = b.iter().take_while(|x| **x == 0).count().min(b.len().saturating_sub(1));
    &b[skip..]
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// A DER writer, for the request (and the tests' TSA).

pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = n.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend(&bytes[skip..]);
    }
    out.extend(body);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQ, &parts.concat())
}

pub fn uint(b: &[u8]) -> Vec<u8> {
    let b = unsigned(b);
    let mut body = Vec::with_capacity(b.len() + 1);
    if b.first().is_none_or(|x| x & 0x80 != 0) {
        body.push(0);
    }
    body.extend(b);
    tlv(INT, &body)
}

pub fn oid(dotted: &str) -> Vec<u8> {
    let n: Vec<u64> = dotted.split('.').map(|p| p.parse().expect("a dotted OID")).collect();
    let mut body = Vec::new();
    for v in std::iter::once(n[0] * 40 + n[1]).chain(n[2..].iter().copied()) {
        let mut chunk = vec![(v & 0x7f) as u8];
        let mut v = v >> 7;
        while v > 0 {
            chunk.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        body.extend(chunk.iter().rev());
    }
    tlv(OID, &body)
}

/// A TimeStampReq (RFC 3161 2.4.1) for a SHA-256 `imprint`, with `nonce`, asking for the
/// TSA's certificate in the token so it can be checked without anything else.
pub fn request(imprint: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
    let alg = seq(&[&oid(SHA256), &[0x05, 0x00]]);
    let message = seq(&[&alg, &tlv(OCTETS, imprint)]);
    seq(&[&uint(&[1]), &message, &uint(nonce), &[BOOL, 1, 0xff]])
}

/// The token in a TimeStampResp, or why the TSA gave none.
pub fn token_from_reply(der: &[u8]) -> Result<Vec<u8>, Invalid> {
    let mut outer = Reader::new(der);
    let resp = outer.expect(SEQ)?;
    let mut r = resp.reader();
    let mut status = r.expect(SEQ)?.reader();
    let code = unsigned(status.expect(INT)?.body);
    if code.len() != 1 || code[0] > 1 {
        let mut text = Vec::new();
        if let Some(free) = status.optional(SEQ)? {
            let mut f = free.reader();
            while !f.is_empty() {
                text.push(String::from_utf8_lossy(f.next()?.body).into_owned());
            }
        }
        let text = text.join("; ");
        let text = if text.is_empty() { String::new() } else { format!(": {}", crate::audit::clip(&text, 200)) };
        return Err(bad("refused", format!("the TSA refused the request (status {}){text}", code.last().copied().unwrap_or(0))));
    }
    Ok(r.expect(SEQ).map_err(|_| bad("refused", "the TSA granted the request but sent no token"))?.raw.to_vec())
}

/// What a token that checks out says.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stamp {
    /// The TSA's time, unix ms.
    pub time: i64,
    /// The token's serial number, hex.
    pub serial: String,
    pub policy: String,
    /// SHA-256 of the TSA's signing certificate, and its subject.
    pub tsa_cert: String,
    pub tsa_subject: String,
    /// Whether the certificate chains to `AUDIT_TIMESTAMP_CA_FILE`; null when that isn't set.
    pub trusted: Option<bool>,
}

/// The certificates a token's signer must be, or chain to (`AUDIT_TIMESTAMP_CA_FILE`).
#[derive(Clone, Debug, Default)]
pub struct Trust {
    anchors: Vec<Vec<u8>>,
}

impl Trust {
    /// Every `CERTIFICATE` block in PEM text.
    pub fn from_pem(pem: &str) -> Result<Trust, String> {
        use base64::Engine;
        let mut anchors = Vec::new();
        let mut rest = pem;
        while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
            let body = &rest[start + 27..];
            let end = body.find("-----END CERTIFICATE-----").ok_or("a certificate has no END line")?;
            let b64: String = body[..end].split_whitespace().collect();
            let der = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|_| "a certificate isn't base64")?;
            x509_parser::parse_x509_certificate(&der).map_err(|_| "a certificate isn't X.509")?;
            anchors.push(der);
            rest = &body[end..];
        }
        if anchors.is_empty() {
            return Err("no certificates in it (expected PEM, BEGIN CERTIFICATE)".into());
        }
        Ok(Trust { anchors })
    }

    pub fn is_set(&self) -> bool {
        !self.anchors.is_empty()
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }
}

struct TstInfo {
    policy: String,
    imprint_alg: String,
    imprint: Vec<u8>,
    serial: Vec<u8>,
    time: i64,
    nonce: Option<Vec<u8>>,
}

fn tst_info(der: &[u8]) -> Result<TstInfo, Invalid> {
    let mut r = Reader::new(der).expect(SEQ)?.reader();
    r.expect(INT)?;
    let policy = read_oid(&mut r)?;
    let mut m = r.expect(SEQ)?.reader();
    let imprint_alg = algorithm(m.expect(SEQ)?)?;
    let imprint = m.expect(OCTETS)?.body.to_vec();
    let serial = r.expect(INT)?.body.to_vec();
    let time = generalized_time(r.expect(GENERALIZED_TIME)?.body)?;
    r.optional(SEQ)?;
    r.optional(BOOL)?;
    let nonce = r.optional(INT)?.map(|n| unsigned(n.body).to_vec());
    Ok(TstInfo { policy, imprint_alg, imprint, serial, time, nonce })
}

/// `YYYYMMDDHHMMSS[.fff]Z` as unix ms.
fn generalized_time(b: &[u8]) -> Result<i64, Invalid> {
    let s = std::str::from_utf8(b).ok().and_then(|s| s.strip_suffix('Z')).ok_or_else(|| malformed("a time that isn't UTC"))?;
    let (main, frac) = s.split_once('.').unwrap_or((s, ""));
    if main.len() != 14 || !main.bytes().all(|c| c.is_ascii_digit()) || !frac.bytes().all(|c| c.is_ascii_digit()) {
        return Err(malformed("a bad time"));
    }
    let n = |a: usize, b: usize| main[a..b].parse::<u32>().unwrap_or(0);
    let at = chrono::NaiveDate::from_ymd_opt(n(0, 4) as i32, n(4, 6), n(6, 8)).and_then(|d| d.and_hms_opt(n(8, 10), n(10, 12), n(12, 14))).ok_or_else(|| malformed("a bad time"))?;
    let ms: String = frac.chars().chain("000".chars()).take(3).collect();
    Ok(at.and_utc().timestamp_millis() + ms.parse::<i64>().unwrap_or(0))
}

fn digest(alg: &str, data: &[u8]) -> Result<Vec<u8>, Invalid> {
    Ok(match alg {
        SHA256 => Sha256::digest(data).to_vec(),
        SHA384 => Sha384::digest(data).to_vec(),
        SHA512 => Sha512::digest(data).to_vec(),
        other => {
            return Err(bad("signature", format!("the token uses digest {other}, which botd doesn't take")));
        }
    })
}

/// A certificate's key: its algorithm, curve (EC), and the key bytes.
fn spki(raw: &[u8]) -> Result<(String, Option<String>, Vec<u8>), Invalid> {
    let mut r = Reader::new(raw).expect(SEQ)?.reader();
    let mut alg = r.expect(SEQ)?.reader();
    let kind = read_oid(&mut alg)?;
    let curve = alg.optional(OID)?.map(|o| oid_string(o.body));
    let bits = r.expect(BITS)?.body;
    let key = bits.split_first().filter(|(unused, _)| **unused == 0).map(|(_, k)| k.to_vec()).ok_or_else(|| malformed("a bad public key"))?;
    Ok((kind, curve, key))
}

/// Checks `sig` over `msg` with `key` (a SubjectPublicKeyInfo), under signature algorithm
/// `alg`; `hash` is the digest algorithm when `alg` is plain rsaEncryption, as CMS allows.
fn verify_signature(key: &[u8], alg: &str, hash: Option<&str>, msg: &[u8], sig: &[u8]) -> Result<(), Invalid> {
    use aws_lc_rs::signature as s;
    let (kind, curve, key) = spki(key)?;
    let unsupported = || bad("signature", format!("signature algorithm {alg} isn't one botd takes"));
    let v: &'static dyn s::VerificationAlgorithm = match (alg, kind.as_str(), curve.as_deref()) {
        (RSA, RSA, _) => match hash {
            Some(SHA256) => &s::RSA_PKCS1_2048_8192_SHA256,
            Some(SHA384) => &s::RSA_PKCS1_2048_8192_SHA384,
            Some(SHA512) => &s::RSA_PKCS1_2048_8192_SHA512,
            _ => return Err(unsupported()),
        },
        ("1.2.840.113549.1.1.11", RSA, _) => &s::RSA_PKCS1_2048_8192_SHA256,
        ("1.2.840.113549.1.1.12", RSA, _) => &s::RSA_PKCS1_2048_8192_SHA384,
        ("1.2.840.113549.1.1.13", RSA, _) => &s::RSA_PKCS1_2048_8192_SHA512,
        ("1.2.840.10045.4.3.2", EC, Some(P256)) => &s::ECDSA_P256_SHA256_ASN1,
        ("1.2.840.10045.4.3.3", EC, Some(P256)) => &s::ECDSA_P256_SHA384_ASN1,
        ("1.2.840.10045.4.3.4", EC, Some(P256)) => &s::ECDSA_P256_SHA512_ASN1,
        ("1.2.840.10045.4.3.2", EC, Some(P384)) => &s::ECDSA_P384_SHA256_ASN1,
        ("1.2.840.10045.4.3.3", EC, Some(P384)) => &s::ECDSA_P384_SHA384_ASN1,
        ("1.2.840.10045.4.3.4", EC, Some(P384)) => &s::ECDSA_P384_SHA512_ASN1,
        (ED25519, ED25519, _) => &s::ED25519,
        _ => return Err(unsupported()),
    };
    s::UnparsedPublicKey::new(v, &key).verify(msg, sig).map_err(|_| bad("signature", "the signature doesn't verify"))
}

type Cert<'a> = x509_parser::certificate::X509Certificate<'a>;

fn parse_cert(der: &[u8]) -> Result<Cert<'_>, Invalid> {
    x509_parser::parse_x509_certificate(der).map(|(_, c)| c).map_err(|_| bad("certificate", "a certificate in the token isn't X.509"))
}

fn valid_at(c: &Cert, ms: i64) -> bool {
    let s = ms.div_euclid(1000);
    c.validity().not_before.timestamp() <= s && s <= c.validity().not_after.timestamp()
}

fn only_stamping(u: &x509_parser::extensions::ExtendedKeyUsage) -> bool {
    !(u.any || u.server_auth || u.client_auth || u.code_signing || u.email_protection || u.ocsp_signing || !u.other.is_empty())
}

/// `child` was signed by `issuer`'s key.
fn issued_by(child: &Cert, issuer: &Cert) -> bool {
    child.issuer().as_raw() == issuer.subject().as_raw()
        && verify_signature(issuer.public_key().raw, &child.signature_algorithm.algorithm.to_id_string(), None, child.tbs_certificate.as_ref(), &child.signature_value.data).is_ok()
}

fn is_ca(c: &Cert) -> bool {
    matches!(c.basic_constraints(), Ok(Some(b)) if b.value.ca)
}

/// The signer is an anchor, or chains to one through `pool` (the token's certificates),
/// each link signed by the next and valid at `at`, each issuer below the anchor a CA.
fn chains(signer: &[u8], pool: &[&[u8]], trust: &Trust, at: i64) -> Result<(), Invalid> {
    let untrusted = |why: &str| bad("untrusted", format!("the TSA's certificate doesn't chain to AUDIT_TIMESTAMP_CA_FILE: {why}"));
    let mut cur = signer;
    for _ in 0..MAX_CHAIN {
        if trust.anchors.iter().any(|a| a.as_slice() == cur) {
            return Ok(());
        }
        let c = parse_cert(cur)?;
        let anchor = trust.anchors.iter().map(Vec::as_slice).find(|a| parse_cert(a).is_ok_and(|a| issued_by(&c, &a)));
        if let Some(a) = anchor {
            return if parse_cert(a).is_ok_and(|a| valid_at(&a, at)) { Ok(()) } else { Err(untrusted("the CA wasn't valid at the token's time")) };
        }
        let next = pool.iter().copied().filter(|p| *p != cur).find(|p| parse_cert(p).is_ok_and(|p| issued_by(&c, &p)));
        let Some(next) = next else {
            return Err(untrusted("no issuer for it"));
        };
        let n = parse_cert(next)?;
        if !is_ca(&n) || !valid_at(&n, at) {
            return Err(untrusted("an intermediate isn't a CA valid at the token's time"));
        }
        cur = next;
    }
    Err(untrusted("the chain is too long"))
}

/// Checks `token` (a TimeStampToken, DER) against the SHA-256 `imprint` it should stamp,
/// the `nonce` sent with the request when there is one, and `trust`.
pub fn verify(token: &[u8], imprint: &[u8], nonce: Option<&[u8]>, trust: &Trust) -> Result<Stamp, Invalid> {
    let mut ci = Reader::new(token).expect(SEQ)?.reader();
    if read_oid(&mut ci)? != SIGNED_DATA {
        return Err(malformed("it isn't CMS SignedData"));
    }
    let mut sd = ci.expect(CTX0)?.reader().expect(SEQ)?.reader();
    sd.expect(INT)?;
    sd.expect(SET)?;
    let mut encap = sd.expect(SEQ)?.reader();
    if read_oid(&mut encap)? != TST_INFO {
        return Err(malformed("its content isn't a TSTInfo"));
    }
    let content = encap.expect(CTX0)?.reader().expect(OCTETS)?.body;
    let mut certs: Vec<&[u8]> = Vec::new();
    if let Some(set) = sd.optional(CTX0)? {
        let mut r = set.reader();
        while !r.is_empty() {
            let c = r.next()?;
            if c.tag == SEQ {
                certs.push(c.raw);
            }
        }
    }
    sd.optional(CTX1)?;
    let mut signers = sd.expect(SET)?.reader();
    let si = signers.expect(SEQ)?;
    if !signers.is_empty() {
        return Err(malformed("more than one signer"));
    }

    let info = tst_info(content)?;
    if info.imprint_alg != SHA256 || info.imprint != imprint {
        return Err(bad("imprint", "the token stamps something other than this checkpoint"));
    }
    if let Some(n) = nonce {
        if info.nonce.as_deref() != Some(unsigned(n)) {
            return Err(bad("nonce", "the token's nonce isn't the one botd sent"));
        }
    }

    let mut s = si.reader();
    s.expect(INT)?;
    let sid = s.next()?;
    let digest_alg = algorithm(s.expect(SEQ)?)?;
    let attrs = s.expect(CTX0).map_err(|_| malformed("no signed attributes"))?;
    let sig_alg = algorithm(s.expect(SEQ)?)?;
    let sig = s.expect(OCTETS)?.body;

    let mut content_type = None;
    let mut message_digest = None;
    let mut ess: Option<(String, Vec<u8>)> = None;
    let mut a = attrs.reader();
    while !a.is_empty() {
        let mut attr = a.expect(SEQ)?.reader();
        let kind = read_oid(&mut attr)?;
        let mut values = attr.expect(SET)?.reader();
        let v = values.next()?;
        match kind.as_str() {
            CONTENT_TYPE if v.tag == OID => content_type = Some(oid_string(v.body)),
            MESSAGE_DIGEST => message_digest = Some(v.body.to_vec()),
            // SigningCertificateV2: certs SEQUENCE OF ESSCertIDv2 { hashAlgorithm DEFAULT sha256, certHash, ... }.
            SIGNING_CERT_V2 => {
                let mut id = v.reader().expect(SEQ)?.reader().expect(SEQ)?.reader();
                let alg = match id.optional(SEQ)? {
                    Some(a) => algorithm(a)?,
                    None => SHA256.into(),
                };
                ess = Some((alg, id.expect(OCTETS)?.body.to_vec()));
            }
            // SigningCertificate: certs SEQUENCE OF ESSCertID { certHash (SHA-1), ... }.
            SIGNING_CERT if ess.is_none() => {
                let mut id = v.reader().expect(SEQ)?.reader().expect(SEQ)?.reader();
                ess = Some(("sha1".into(), id.expect(OCTETS)?.body.to_vec()));
            }
            _ => {}
        }
    }
    if content_type.as_deref() != Some(TST_INFO) {
        return Err(bad("signature", "the signed attributes don't name a TSTInfo"));
    }
    if message_digest != Some(digest(&digest_alg, content)?) {
        return Err(bad("signature", "the signed digest isn't the TSTInfo's"));
    }

    let signer = match_signer(&certs, sid, &trust.anchors)?;
    let mut signed = attrs.raw.to_vec();
    signed[0] = SET;
    let cert = parse_cert(signer)?;
    verify_signature(cert.public_key().raw, &sig_alg, Some(&digest_alg), &signed, sig)?;
    let (ess_alg, ess_hash) = ess.ok_or_else(|| bad("certificate", "no signing-certificate attribute binds the TSA's certificate"))?;
    let actual = match ess_alg.as_str() {
        "sha1" => aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, signer).as_ref().to_vec(),
        alg => digest(alg, signer)?,
    };
    if actual != ess_hash {
        return Err(bad("certificate", "the signing-certificate attribute names another certificate"));
    }
    // RFC 3161 2.3: time-stamping must be the certificate's only extended key usage, and critical.
    let stamping = matches!(cert.extended_key_usage(), Ok(Some(e)) if e.critical && e.value.time_stamping && only_stamping(e.value));
    if !stamping {
        return Err(bad("certificate", "the TSA's certificate isn't for time-stamping"));
    }
    if !valid_at(&cert, info.time) {
        return Err(bad("certificate", "the TSA's certificate wasn't valid at the token's time"));
    }
    let trusted = if trust.is_set() {
        chains(signer, &certs, trust, info.time)?;
        Some(true)
    } else {
        None
    };
    Ok(Stamp {
        time: info.time,
        serial: hex(unsigned(&info.serial)),
        policy: info.policy,
        tsa_cert: hex(&Sha256::digest(signer)),
        tsa_subject: crate::audit::clip(&cert.subject().to_string(), 200),
        trusted,
    })
}

/// The certificate `sid` (IssuerAndSerialNumber, or `[0]` SubjectKeyIdentifier) names,
/// from the token's own or the anchors.
fn match_signer<'a>(certs: &[&'a [u8]], sid: Tlv, anchors: &'a [Vec<u8>]) -> Result<&'a [u8], Invalid> {
    let pool = certs.iter().copied().chain(anchors.iter().map(Vec::as_slice));
    let wanted = |c: &Cert| -> bool {
        match sid.tag {
            SEQ => {
                let mut r = sid.reader();
                let (Ok(name), Ok(serial)) = (r.expect(SEQ), r.expect(INT)) else {
                    return false;
                };
                c.issuer().as_raw() == name.raw && unsigned(c.raw_serial()) == unsigned(serial.body)
            }
            0x80 => {
                matches!(c.get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER),
                Ok(Some(e)) if matches!(e.parsed_extension(), x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(k) if k.0 == sid.body))
            }
            _ => false,
        }
    };
    for der in pool {
        if parse_cert(der).is_ok_and(|c| wanted(&c)) {
            return Ok(der);
        }
    }
    Err(bad("certificate", "the token doesn't carry the TSA's certificate, and AUDIT_TIMESTAMP_CA_FILE doesn't have it"))
}

/// A TSA for tests: a CA and a time-stamping certificate it issued, with ECDSA P-256
/// keys, answering requests with real tokens.
#[cfg(test)]
pub mod fake {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};

    pub struct FakeTsa {
        pub ca_pem: String,
        pub leaf: Vec<u8>,
        key: EcdsaKeyPair,
    }

    impl FakeTsa {
        pub fn new() -> FakeTsa {
            FakeTsa::with_stamping(true)
        }

        /// `stamping`: whether its certificate says time-stamping, as RFC 3161 asks (critical).
        pub fn with_stamping(stamping: bool) -> FakeTsa {
            FakeTsa::with_usage(stamping.then_some(true))
        }

        /// `critical`: its certificate's time-stamping extended key usage, if any, and whether it's critical.
        pub fn with_usage(critical: Option<bool>) -> FakeTsa {
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            ca.distinguished_name.push(rcgen::DnType::CommonName, "Test TSA Root");
            ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = rcgen::CertifiedIssuer::self_signed(ca, ca_key).unwrap();
            let key = rcgen::KeyPair::generate().unwrap();
            let mut leaf = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            leaf.distinguished_name.push(rcgen::DnType::CommonName, "Test TSA");
            if let Some(critical) = critical {
                // SEQUENCE { id-kp-timeStamping }; rcgen's own never marks it critical.
                let usage = vec![0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
                let mut ext = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 37], usage);
                ext.set_criticality(critical);
                leaf.custom_extensions.push(ext);
            }
            let leaf = leaf.signed_by(&key, &ca).unwrap();
            FakeTsa { ca_pem: ca.pem(), leaf: leaf.der().to_vec(), key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key.serialize_der()).unwrap() }
        }

        /// A TimeStampResp granting `request` (a TimeStampReq), stamped at `time` (unix ms).
        pub fn reply(&self, request: &[u8], time: i64) -> Vec<u8> {
            let mut r = Reader::new(request).expect(SEQ).unwrap().reader();
            r.expect(INT).unwrap();
            let mut m = r.expect(SEQ).unwrap().reader();
            m.expect(SEQ).unwrap();
            let imprint = m.expect(OCTETS).unwrap().body.to_vec();
            let nonce = r.optional(INT).unwrap().map(|n| n.body.to_vec());
            seq(&[&seq(&[&uint(&[0])]), &self.token(&imprint, nonce.as_deref(), time)])
        }

        /// A TimeStampResp refusing the request, as a TSA that's misconfigured would.
        pub fn refusal() -> Vec<u8> {
            seq(&[&seq(&[&uint(&[2]), &seq(&[&tlv(0x0c, b"unsupported policy")])])])
        }

        pub fn token(&self, imprint: &[u8], nonce: Option<&[u8]>, time: i64) -> Vec<u8> {
            let t = chrono::DateTime::from_timestamp_millis(time).unwrap().format("%Y%m%d%H%M%S%.3fZ").to_string();
            let alg = seq(&[&oid(SHA256), &[0x05, 0x00]]);
            let mut tst = vec![uint(&[1]), oid("1.2.3.4.1"), seq(&[&alg, &tlv(OCTETS, imprint)]), uint(&crate::random_bytes(8)), tlv(GENERALIZED_TIME, t.as_bytes())];
            if let Some(n) = nonce {
                tst.push(uint(n));
            }
            let tst = seq(&tst.iter().map(Vec::as_slice).collect::<Vec<_>>());
            let ess = seq(&[&seq(&[&seq(&[&tlv(OCTETS, &Sha256::digest(&self.leaf))])])]);
            let attrs =
                [seq(&[&oid(CONTENT_TYPE), &tlv(SET, &oid(TST_INFO))]), seq(&[&oid(MESSAGE_DIGEST), &tlv(SET, &tlv(OCTETS, &Sha256::digest(&tst)))]), seq(&[&oid(SIGNING_CERT_V2), &tlv(SET, &ess)])]
                    .concat();
            let sig = self.key.sign(&SystemRandom::new(), &tlv(SET, &attrs)).unwrap();
            let (_, leaf) = x509_parser::parse_x509_certificate(&self.leaf).unwrap();
            let sid = seq(&[leaf.issuer().as_raw(), &uint(leaf.raw_serial())]);
            let signer = seq(&[&uint(&[1]), &sid, &alg, &tlv(CTX0, &attrs), &seq(&[&oid("1.2.840.10045.4.3.2")]), &tlv(OCTETS, sig.as_ref())]);
            let encap = seq(&[&oid(TST_INFO), &tlv(CTX0, &tlv(OCTETS, &tst))]);
            let signed = seq(&[&uint(&[3]), &tlv(SET, &alg), &encap, &tlv(CTX0, &self.leaf), &tlv(SET, &signer)]);
            seq(&[&oid(SIGNED_DATA), &tlv(CTX0, &signed)])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeTsa;
    use super::*;

    const DIGICERT: &[u8] = include_bytes!("../tests/fixtures/tsa/digicert.tsr");
    const FREETSA: &[u8] = include_bytes!("../tests/fixtures/tsa/freetsa.tsr");
    const DIGICERT_ROOT: &str = include_str!("../tests/fixtures/tsa/digicert-root-g4.pem");
    const FREETSA_CA: &str = include_str!("../tests/fixtures/tsa/freetsa-ca.pem");
    /// Both fixtures stamp SHA-256("hello") with this nonce.
    const NONCE: [u8; 8] = [0x69, 0x04, 0xa9, 0x9f, 0xdc, 0x9b, 0x99, 0x6f];

    fn hello() -> Vec<u8> {
        Sha256::digest(b"hello").to_vec()
    }

    #[test]
    fn der_round_trips() {
        for o in [SHA256, TST_INFO, "2.999.1", "1.2.840.10045.3.1.7"] {
            let enc = oid(o);
            assert_eq!(oid_string(Reader::new(&enc).expect(OID).unwrap().body), o);
        }
        let long = vec![7u8; 300];
        let t = tlv(OCTETS, &long);
        assert_eq!(&t[..4], &[OCTETS, 0x82, 0x01, 0x2c]);
        assert_eq!(Reader::new(&t).expect(OCTETS).unwrap().body, &long[..]);
        assert_eq!(uint(&[0x80]), vec![INT, 2, 0, 0x80], "kept positive");
        assert_eq!(uint(&[0, 0, 5]), vec![INT, 1, 5], "minimal");
        assert!(Reader::new(&[0x30, 0x80, 0, 0]).next().is_err(), "no indefinite lengths");
        assert!(Reader::new(&[0x30, 0x05, 1]).next().is_err(), "no running past the end");
        assert_eq!(generalized_time(b"20261122222818Z").unwrap(), 1_795_386_498_000);
        assert_eq!(generalized_time(b"20261122222818.5Z").unwrap(), 1_795_386_498_500);
        assert!(generalized_time(b"20261122222818+0100").is_err());
    }

    #[test]
    fn requests_parse_as_rfc_3161() {
        let imprint: [u8; 32] = hello().try_into().unwrap();
        let req = request(&imprint, &NONCE);
        let mut r = Reader::new(&req).expect(SEQ).unwrap().reader();
        assert_eq!(r.expect(INT).unwrap().body, &[1]);
        let mut m = r.expect(SEQ).unwrap().reader();
        assert_eq!(algorithm(m.expect(SEQ).unwrap()).unwrap(), SHA256);
        assert_eq!(m.expect(OCTETS).unwrap().body, &imprint);
        assert_eq!(unsigned(r.expect(INT).unwrap().body), &NONCE);
        assert_eq!(r.expect(BOOL).unwrap().body, &[0xff], "asks for the TSA's certificate");
    }

    #[test]
    fn real_tokens_from_public_tsas_verify() {
        for (reply, ca, subject) in [(DIGICERT, DIGICERT_ROOT, "DigiCert"), (FREETSA, FREETSA_CA, "freetsa")] {
            let token = token_from_reply(reply).unwrap();
            let s = verify(&token, &hello(), Some(&NONCE), &Trust::default()).unwrap();
            assert_eq!((s.trusted, s.time / 1000), (None, 1_795_386_498), "{subject}: {s:?}");
            assert!(s.tsa_subject.contains(subject), "{s:?}");
            let trust = Trust::from_pem(ca).unwrap();
            assert_eq!(verify(&token, &hello(), Some(&NONCE), &trust).unwrap().trusted, Some(true), "{subject}");
            // Someone else's CA doesn't vouch for it.
            let other = if subject == "DigiCert" { FREETSA_CA } else { DIGICERT_ROOT };
            assert_eq!(verify(&token, &hello(), None, &Trust::from_pem(other).unwrap()).unwrap_err().code, "untrusted", "{subject}");
            // Another hash, another nonce.
            assert_eq!(verify(&token, &Sha256::digest(b"hellp"), None, &trust).unwrap_err().code, "imprint");
            assert_eq!(verify(&token, &hello(), Some(&[1, 2, 3]), &trust).unwrap_err().code, "nonce");
        }
    }

    #[test]
    fn a_changed_token_fails() {
        let token = token_from_reply(DIGICERT).unwrap();
        let s = verify(&token, &hello(), None, &Trust::default()).unwrap();
        // Flip one byte of the signed TSTInfo's serial: the signed digest no longer matches.
        let serial = (0..token.len() - 16).find(|&i| hex(&token[i..i + 16]) == s.serial).unwrap();
        let mut changed = token.clone();
        changed[serial] ^= 1;
        assert_eq!(verify(&changed, &hello(), None, &Trust::default()).unwrap_err().code, "signature");
        // And the last byte of the signature itself.
        let mut changed = token.clone();
        let sig = changed.len() - 1;
        changed[sig] ^= 1;
        assert!(verify(&changed, &hello(), None, &Trust::default()).is_err());
        assert!(verify(&token[..token.len() - 1], &hello(), None, &Trust::default()).is_err(), "cut short");
    }

    #[test]
    fn the_fake_tsa_is_a_real_one() {
        let tsa = FakeTsa::new();
        let imprint: [u8; 32] = hello().try_into().unwrap();
        let reply = tsa.reply(&request(&imprint, &NONCE), 1_795_000_000_123);
        let token = token_from_reply(&reply).unwrap();
        let trust = Trust::from_pem(&tsa.ca_pem).unwrap();
        let s = verify(&token, &imprint, Some(&NONCE), &trust).unwrap();
        assert_eq!((s.time, s.trusted, s.policy.as_str()), (1_795_000_000_123, Some(true), "1.2.3.4.1"));
        assert_eq!(verify(&token, &imprint, None, &Trust::from_pem(&FakeTsa::new().ca_pem).unwrap()).unwrap_err().code, "untrusted");
        let plain = FakeTsa::with_stamping(false);
        let t = token_from_reply(&plain.reply(&request(&imprint, &NONCE), 1_795_000_000_000)).unwrap();
        assert_eq!(verify(&t, &imprint, None, &Trust::default()).unwrap_err().code, "certificate", "not a time-stamping certificate");
        let lax = FakeTsa::with_usage(Some(false));
        let t = token_from_reply(&lax.reply(&request(&imprint, &NONCE), 1_795_000_000_000)).unwrap();
        assert_eq!(verify(&t, &imprint, None, &Trust::default()).unwrap_err().code, "certificate", "time-stamping, but not critical");
        let e = token_from_reply(&FakeTsa::refusal()).unwrap_err();
        assert_eq!(e.code, "refused");
        assert!(e.message.contains("status 2") && e.message.contains("unsupported policy"), "{e}");
        assert!(Trust::from_pem("nothing here").is_err());
    }
}
