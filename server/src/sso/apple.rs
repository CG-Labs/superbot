//! Sign in with Apple (ADR 0018). Apple is OpenID Connect with three differences: the
//! client secret is a short-lived ES256 JWT we sign with the team's key, the result
//! comes back as a form POST, and the person's name arrives once, outside the token.

use super::jwt::Invalid;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};

pub const ISSUER: &str = "https://appleid.apple.com";
/// Hide My Email addresses. They are real and stable per app, but say nothing about
/// where someone works, so this domain can't be an allowed one.
pub const RELAY_DOMAIN: &str = "privaterelay.appleid.com";
/// Apple accepts up to six months; a fresh one per code exchange means none is kept.
const SECRET_TTL_S: i64 = 300;

/// A Team ID or Key ID: ten uppercase letters and digits.
pub fn apple_id(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_uppercase();
    (s.len() == 10 && s.bytes().all(|b| b.is_ascii_alphanumeric())).then_some(s)
}

/// The `.p8` key from Apple's developer site: the PEM file, the PEM with its line breaks
/// written as `\n` (one env line), or just the base64 between the markers.
pub fn signing_key(text: &str) -> Result<EcdsaKeyPair, Invalid> {
    let body: String = text
        .replace("\\n", "\n")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    let der = STANDARD
        .decode(body)
        .map_err(|_| Invalid("bad_private_key"))?;
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der)
        .map_err(|_| Invalid("bad_private_key"))
}

/// The client secret for one token request: `iss` is the team, `sub` the Services ID.
pub fn client_secret(
    key: &EcdsaKeyPair,
    team_id: &str,
    key_id: &str,
    client_id: &str,
    audience: &str,
    now: i64,
) -> Result<String, Invalid> {
    let header = json!({ "alg": "ES256", "kid": key_id, "typ": "JWT" });
    let claims = json!({ "iss": team_id, "sub": client_id, "aud": audience, "iat": now, "exp": now + SECRET_TTL_S });
    let signed = format!(
        "{}.{}",
        B64.encode(header.to_string()),
        B64.encode(claims.to_string())
    );
    let sig = key
        .sign(&SystemRandom::new(), signed.as_bytes())
        .map_err(|_| Invalid("bad_private_key"))?;
    Ok(format!("{signed}.{}", B64.encode(sig.as_ref())))
}

/// The name in the `user` field Apple posts on the first sign-in only:
/// `{"name":{"firstName":…,"lastName":…},"email":…}`. It isn't signed, so it is only
/// ever a display name, never who someone is.
pub fn posted_name(user: &str) -> Option<String> {
    let v: Value = serde_json::from_str(user).ok()?;
    let part = |k: &str| {
        v["name"][k]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    let name = [part("firstName"), part("lastName")]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let name = crate::audit::clip(&name, 100);
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
pub mod test_key {
    use super::*;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, KeyPair, UnparsedPublicKey};

    /// A new P-256 key as Apple's `.p8` file has it, and its public key.
    pub fn p8() -> (String, Vec<u8>) {
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let public = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref())
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
        let b64 = STANDARD.encode(doc.as_ref());
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        (
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                lines.join("\n")
            ),
            public,
        )
    }

    /// The header and claims of a client secret, if `public` signed it.
    pub fn verify(jwt: &str, public: &[u8]) -> Option<(Value, Value)> {
        let mut parts = jwt.split('.');
        let (h, c, s) = (parts.next()?, parts.next()?, parts.next()?);
        let sig = B64.decode(s).ok()?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public)
            .verify(format!("{h}.{c}").as_bytes(), &sig)
            .ok()?;
        let part = |p: &str| serde_json::from_slice::<Value>(&B64.decode(p).ok()?).ok();
        Some((part(h)?, part(c)?))
    }
}

#[cfg(test)]
mod tests {
    use super::test_key::{p8, verify};
    use super::*;

    #[test]
    fn the_client_secret_is_an_es256_jwt_apple_can_check() {
        let (pem, public) = p8();
        let key = signing_key(&pem).unwrap();
        let jwt = client_secret(
            &key,
            "TEAM123456",
            "KEY1234567",
            "com.example.superbot",
            ISSUER,
            1_800_000_000,
        )
        .unwrap();
        let (h, c) = verify(&jwt, &public).expect("signed by the key");
        assert_eq!(
            h,
            json!({ "alg": "ES256", "kid": "KEY1234567", "typ": "JWT" })
        );
        assert_eq!(
            c,
            json!({ "iss": "TEAM123456", "sub": "com.example.superbot", "aud": ISSUER, "iat": 1_800_000_000, "exp": 1_800_000_300 })
        );
        let (_, other) = p8();
        assert!(verify(&jwt, &other).is_none(), "another key's signature");
    }

    #[test]
    fn reads_the_p8_key_however_it_was_pasted() {
        let (pem, _) = p8();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        for text in [
            pem.clone(),
            pem.replace('\n', "\\n"),
            body,
            format!("  {}  ", pem.replace('\n', "\r\n")),
        ] {
            assert!(signing_key(&text).is_ok(), "{text}");
        }
        for bad in [
            "",
            "not a key",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
        ] {
            assert_eq!(
                signing_key(bad).err(),
                Some(Invalid("bad_private_key")),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_posted_name_is_display_text_only() {
        assert_eq!(posted_name(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"x@privaterelay.appleid.com"}"#).as_deref(), Some("Ada Lovelace"));
        assert_eq!(
            posted_name(r#"{"name":{"firstName":" Ada "}}"#).as_deref(),
            Some("Ada")
        );
        assert_eq!(
            posted_name(&format!(
                r#"{{"name":{{"firstName":"{}"}}}}"#,
                "x".repeat(300)
            ))
            .map(|n| n.chars().count()),
            Some(101)
        );
        assert_eq!(
            posted_name(r#"{"name":{"firstName":"A\u0000\u001bda"}}"#).as_deref(),
            Some("Ada"),
            "control characters dropped"
        );
        for none in [
            "",
            "{}",
            "nope",
            r#"{"name":"Ada"}"#,
            r#"{"name":{"firstName":""}}"#,
        ] {
            assert_eq!(posted_name(none), None, "{none}");
        }
    }

    #[test]
    fn team_and_key_ids() {
        assert_eq!(apple_id(" abcde12345 ").as_deref(), Some("ABCDE12345"));
        for bad in ["", "ABCDE1234", "ABCDE123456", "ABCDE-1234"] {
            assert!(apple_id(bad).is_none(), "{bad}");
        }
    }
}
