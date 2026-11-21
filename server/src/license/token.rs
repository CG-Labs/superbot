//! The license token (ADR 0038): a compact JWT signed with Ed25519 (`alg: EdDSA`), checked
//! offline against public keys built into botd. Only EdDSA: one algorithm leaves no `alg`
//! to confuse, and a signature by a key we ship is the only thing that makes a token count.
//!
//! This file has no `crate::` paths: `superbot-license`, the offline tool CG-Labs mints
//! keys with, includes it too, so both sides read and write exactly the same format.

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Every license names this audience, so a token CG-Labs signs for something else with the
/// same key is never a license.
pub const AUDIENCE: &str = "superbot-self-host";
pub const ISSUER: &str = "CG-Labs";
/// Bigger than any real license; a bound on what we parse.
pub const MAX_TOKEN: usize = 8 * 1024;
/// Clock difference we put up with, in seconds.
pub const SKEW: i64 = 300;
const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";

/// What a license grants. Times are unix seconds, as in any JWT.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    /// The licensee, as shown to admins.
    pub sub: String,
    /// The license's id. A renewal gets a new one.
    pub jti: String,
    pub iat: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    pub exp: i64,
    /// Active users the license covers. None: unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seats: Option<u32>,
    /// e.g. "team", "business", "enterprise".
    pub edition: String,
    #[serde(default)]
    pub features: Vec<String>,
}

/// Why a token isn't a license. The code goes in the audit log and the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    Malformed,
    BadAlgorithm,
    UnknownKey,
    BadSignature,
    WrongAudience,
    NotYetValid,
    BadClaims,
}

impl Invalid {
    pub fn code(self) -> &'static str {
        match self {
            Invalid::Malformed => "malformed",
            Invalid::BadAlgorithm => "bad_algorithm",
            Invalid::UnknownKey => "unknown_key",
            Invalid::BadSignature => "bad_signature",
            Invalid::WrongAudience => "wrong_audience",
            Invalid::NotYetValid => "not_yet_valid",
            Invalid::BadClaims => "bad_claims",
        }
    }

    pub fn text(self) -> &'static str {
        match self {
            Invalid::Malformed => "This isn't a SuperBot license key. Paste the whole key, three parts separated by dots.",
            Invalid::BadAlgorithm => "This key isn't signed the way SuperBot licenses are (EdDSA).",
            Invalid::UnknownKey => "This license was signed by a key this version of SuperBot doesn't know. Upgrade SuperBot, or ask CG-Labs for a new key.",
            Invalid::BadSignature => "This license's signature doesn't match: it was changed after it was issued, or wasn't issued by CG-Labs.",
            Invalid::WrongAudience => "This key isn't a SuperBot self-host license.",
            Invalid::NotYetValid => "This license starts later. Check this server's clock, or install it once it starts.",
            Invalid::BadClaims => "This license is missing something it needs (licensee, id, edition, seats, or dates).",
        }
    }
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// A public key botd trusts, by the `kid` licenses name it with.
#[derive(Clone, Debug)]
pub struct Key {
    pub kid: String,
    pub public: Vec<u8>,
}

impl Key {
    /// `public` is the 32-byte Ed25519 key in unpadded base64url, as `superbot-license keygen` prints it.
    pub fn parse(kid: &str, public: &str) -> Result<Key, String> {
        let public = B64.decode(public.trim()).map_err(|e| format!("key {kid}: {e}"))?;
        if public.len() != 32 {
            return Err(format!("key {kid}: an Ed25519 public key is 32 bytes, not {}", public.len()));
        }
        Ok(Key { kid: kid.into(), public })
    }
}

pub fn valid_kid(kid: &str) -> bool {
    slug(kid, 32)
}

fn slug(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.')
}

fn text(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control)
}

impl Claims {
    /// What every license must have, whoever signed it. `superbot-license` checks it
    /// before signing, and botd after verifying.
    pub fn check(&self) -> Result<(), &'static str> {
        if self.aud != AUDIENCE {
            return Err("aud");
        }
        if !text(&self.sub, 200) {
            return Err("the licensee (sub) must be 1 to 200 characters");
        }
        if !slug(&self.jti, 64) {
            return Err("the license id (jti) must be 1 to 64 lowercase letters, digits, or - _ .");
        }
        if !slug(&self.edition, 32) {
            return Err("the edition must be 1 to 32 lowercase letters, digits, or - _ .");
        }
        if self.features.len() > 64 || !self.features.iter().all(|f| slug(f, 32)) {
            return Err("features must be up to 64 names of lowercase letters, digits, or - _ .");
        }
        if self.seats == Some(0) {
            return Err("seats must be at least 1, or left out for unlimited");
        }
        if self.iat <= 0 || self.exp <= self.iat || self.nbf.is_some_and(|n| n >= self.exp) {
            return Err("the license must end (exp) after it is issued (iat) and starts (nbf)");
        }
        Ok(())
    }
}

fn part(s: &str) -> Result<Map<String, Value>, Invalid> {
    let bytes = B64.decode(s).map_err(|_| Invalid::Malformed)?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(Invalid::Malformed),
    }
}

/// The claims of a token signed by one of `keys`, for audience [`AUDIENCE`], that has
/// started by `now` (unix seconds). Expiry is not checked here: an expired license is
/// still a license, and botd decides what that means (a grace period, then no license).
pub fn verify(token: &str, keys: &[Key], now: i64) -> Result<Claims, Invalid> {
    let token = token.trim();
    if token.len() > MAX_TOKEN {
        return Err(Invalid::Malformed);
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(Invalid::Malformed);
    };
    let header = part(h)?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") || header.contains_key("crit") {
        return Err(Invalid::BadAlgorithm);
    }
    let kid = header.get("kid").and_then(Value::as_str).ok_or(Invalid::UnknownKey)?;
    let key = keys.iter().find(|k| k.kid == kid).ok_or(Invalid::UnknownKey)?;
    let sig = B64.decode(s).map_err(|_| Invalid::Malformed)?;
    UnparsedPublicKey::new(&ED25519, &key.public)
        .verify(format!("{h}.{p}").as_bytes(), &sig)
        .map_err(|_| Invalid::BadSignature)?;
    // Only now is the payload ours to read.
    let claims: Claims = serde_json::from_value(Value::Object(part(p)?)).map_err(|_| Invalid::BadClaims)?;
    if claims.aud != AUDIENCE {
        return Err(Invalid::WrongAudience);
    }
    claims.check().map_err(|_| Invalid::BadClaims)?;
    if claims.nbf.unwrap_or(claims.iat) > now + SKEW {
        return Err(Invalid::NotYetValid);
    }
    Ok(claims)
}

/// The `kid` a token's header names, without checking anything else. For error messages.
pub fn kid_of(token: &str) -> Option<String> {
    let h = token.trim().split('.').next()?;
    part(h).ok()?.get("kid")?.as_str().map(String::from)
}

/// Signs `claims` with `key`, named `kid`. Refuses claims [`Claims::check`] refuses.
pub fn sign(key: &Ed25519KeyPair, kid: &str, claims: &Claims) -> Result<String, String> {
    claims.check().map_err(String::from)?;
    if !valid_kid(kid) {
        return Err("the key id must be 1 to 32 lowercase letters, digits, or - _ .".into());
    }
    let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
    let signed = format!("{}.{}", B64.encode(header.to_string()), B64.encode(serde_json::to_string(claims).map_err(|e| e.to_string())?));
    let sig = key.sign(signed.as_bytes());
    Ok(format!("{signed}.{}", B64.encode(sig.as_ref())))
}

/// A new signing key, as PKCS#8 PEM (what `openssl genpkey -algorithm ed25519` writes too).
pub fn generate_pem() -> Result<String, String> {
    let key = Ed25519KeyPair::generate().map_err(|_| "couldn't make a key")?;
    let der = key.to_pkcs8v1().map_err(|_| "couldn't encode the key")?;
    let b64 = STANDARD.encode(der.as_ref());
    let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    Ok(format!("{PEM_BEGIN}\n{}\n{PEM_END}\n", lines.join("\n")))
}

pub fn key_from_pem(pem: &str) -> Result<Ed25519KeyPair, String> {
    let body = pem.trim().strip_prefix(PEM_BEGIN).and_then(|r| r.strip_suffix(PEM_END)).ok_or("expected a PKCS#8 PEM private key (BEGIN PRIVATE KEY)")?;
    let der = STANDARD.decode(body.split_whitespace().collect::<String>()).map_err(|e| format!("bad PEM: {e}"))?;
    Ed25519KeyPair::from_pkcs8(&der).map_err(|e| format!("not an Ed25519 private key: {e}"))
}

/// The public half, in the form [`Key::parse`] reads.
pub fn public_b64(key: &Ed25519KeyPair) -> String {
    B64.encode(key.public_key().as_ref())
}
