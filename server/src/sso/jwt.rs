//! ID token checks (ADR 0014): an RS256 signature by a key in the IdP's JWKS, then the
//! standard claims. Only RS256: it's what Entra and most IdPs sign ID tokens with, and
//! accepting one algorithm leaves no `alg` to confuse.

use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Map, Value};

/// Why a token was refused. The text goes in the audit log.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Invalid(pub &'static str);

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Bigger than any real ID token; a bound on what we parse.
const MAX_TOKEN: usize = 16 * 1024;
/// Clock difference we put up with between us and the IdP, in seconds.
pub const SKEW: i64 = 300;

pub struct Jwk {
    pub kid: Option<String>,
    n: Vec<u8>,
    e: Vec<u8>,
}

#[derive(Default)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

fn unsigned(b: &[u8]) -> Vec<u8> {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[start..].to_vec()
}

impl Jwks {
    /// The RSA signing keys of a JWKS document. Others (encryption keys, EC keys) are skipped.
    pub fn parse(v: &Value) -> Result<Jwks, Invalid> {
        let keys = v["keys"].as_array().ok_or(Invalid("bad_jwks"))?;
        let keys = keys
            .iter()
            .filter(|k| {
                k["kty"] == "RSA"
                    && k["use"].as_str().is_none_or(|u| u == "sig")
                    && k["alg"].as_str().is_none_or(|a| a == "RS256")
            })
            .filter_map(|k| {
                let n = unsigned(&B64.decode(k["n"].as_str()?).ok()?);
                let e = unsigned(&B64.decode(k["e"].as_str()?).ok()?);
                (!n.is_empty() && !e.is_empty()).then(|| Jwk {
                    kid: k["kid"].as_str().map(String::from),
                    n,
                    e,
                })
            })
            .collect();
        Ok(Jwks { keys })
    }

    pub fn has(&self, kid: Option<&str>) -> bool {
        kid.is_none_or(|kid| self.keys.iter().any(|k| k.kid.as_deref() == Some(kid)))
    }
}

/// A decoded, not yet trusted, token.
pub struct Token {
    pub kid: Option<String>,
    pub claims: Map<String, Value>,
    signed: String,
    sig: Vec<u8>,
}

fn part(s: &str) -> Result<Map<String, Value>, Invalid> {
    let bytes = B64.decode(s).map_err(|_| Invalid("malformed"))?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(Invalid("malformed")),
    }
}

pub fn decode(token: &str) -> Result<Token, Invalid> {
    if token.len() > MAX_TOKEN {
        return Err(Invalid("malformed"));
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Invalid("malformed"));
    };
    let header = part(h)?;
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err(Invalid("bad_algorithm"));
    }
    // Extensions we don't know must not be ignored (RFC 7515 4.1.11).
    if header.contains_key("crit") {
        return Err(Invalid("bad_algorithm"));
    }
    Ok(Token {
        kid: header.get("kid").and_then(Value::as_str).map(String::from),
        claims: part(p)?,
        signed: format!("{h}.{p}"),
        sig: B64.decode(s).map_err(|_| Invalid("malformed"))?,
    })
}

impl Token {
    /// Signed by the key the header names, or by any key when it names none.
    pub fn verify(&self, jwks: &Jwks) -> Result<(), Invalid> {
        let mut keys = jwks
            .keys
            .iter()
            .filter(|k| self.kid.is_none() || k.kid == self.kid)
            .peekable();
        if keys.peek().is_none() {
            return Err(Invalid("unknown_key"));
        }
        let ok = keys.any(|k| {
            RsaPublicKeyComponents { n: &k.n, e: &k.e }
                .verify(
                    &RSA_PKCS1_2048_8192_SHA256,
                    self.signed.as_bytes(),
                    &self.sig,
                )
                .is_ok()
        });
        if ok {
            Ok(())
        } else {
            Err(Invalid("bad_signature"))
        }
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        self.claims
            .get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    }

    /// The OIDC checks every provider shares: audience, authorized party, times, nonce.
    /// The issuer and subject are the provider's to check.
    pub fn check(&self, client_id: &str, nonce: &str, now: i64) -> Result<(), Invalid> {
        let aud: Vec<&str> = match self.claims.get("aud") {
            Some(Value::String(a)) => vec![a.as_str()],
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
            _ => vec![],
        };
        if !aud.contains(&client_id) {
            return Err(Invalid("wrong_audience"));
        }
        // OIDC Core 3.1.3.7: with other audiences, we must be the party it was issued to.
        let azp = self.str("azp");
        if azp.is_some_and(|a| a != client_id) || (aud.len() > 1 && azp.is_none()) {
            return Err(Invalid("wrong_audience"));
        }
        let time = |name: &str| self.claims.get(name).and_then(Value::as_i64);
        match time("exp") {
            Some(exp) if now < exp + SKEW => {}
            Some(_) => return Err(Invalid("expired")),
            None => return Err(Invalid("malformed")),
        }
        let iat = time("iat").ok_or(Invalid("malformed"))?;
        if iat > now + SKEW || time("nbf").is_some_and(|nbf| nbf > now + SKEW) {
            return Err(Invalid("not_yet_valid"));
        }
        if !self
            .str("nonce")
            .is_some_and(|n| crate::same(n.as_bytes(), nonce.as_bytes()))
        {
            return Err(Invalid("nonce_mismatch"));
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod test_keys {
    //! A local IdP's keys: sign tokens, publish a JWKS.

    use super::B64;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeyPair, KeySize, PublicKeyComponents};
    use aws_lc_rs::signature::{self, KeyPair as _};
    use base64::Engine;
    use serde_json::{Value, json};
    use std::sync::OnceLock;

    pub struct Key {
        pub kid: String,
        pair: KeyPair,
    }

    impl Key {
        fn new(kid: &str) -> Key {
            Key {
                kid: kid.into(),
                pair: KeyPair::generate(KeySize::Rsa2048).unwrap(),
            }
        }

        pub fn jwk(&self) -> Value {
            let p = PublicKeyComponents::<Vec<u8>>::from(self.pair.public_key());
            json!({ "kty": "RSA", "use": "sig", "kid": self.kid, "n": B64.encode(&p.n), "e": B64.encode(&p.e) })
        }

        pub fn sign_with(&self, header: &Value, claims: &Value) -> String {
            let signed = format!(
                "{}.{}",
                B64.encode(header.to_string()),
                B64.encode(claims.to_string())
            );
            let mut sig = vec![0; self.pair.public_modulus_len()];
            self.pair
                .sign(
                    &signature::RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    signed.as_bytes(),
                    &mut sig,
                )
                .unwrap();
            format!("{signed}.{}", B64.encode(sig))
        }

        pub fn sign(&self, claims: &Value) -> String {
            self.sign_with(
                &json!({ "alg": "RS256", "typ": "JWT", "kid": self.kid }),
                claims,
            )
        }
    }

    /// Two keys, made once per test run (RSA key generation is slow).
    pub fn keys() -> &'static [Key; 2] {
        static K: OnceLock<[Key; 2]> = OnceLock::new();
        K.get_or_init(|| [Key::new("k1"), Key::new("k2")])
    }

    pub fn jwks(keys: &[&Key]) -> Value {
        json!({ "keys": keys.iter().map(|k| k.jwk()).collect::<Vec<_>>() })
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::{jwks, keys};
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;

    fn nonce() -> &'static str {
        static N: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        N.get_or_init(|| {
            crate::random_bytes(16)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        })
    }

    fn claims() -> Value {
        json!({ "iss": "https://idp.example/t/v2.0", "aud": "client-1", "sub": "s", "nonce": nonce(), "iat": NOW - 10, "nbf": NOW - 10, "exp": NOW + 3600 })
    }

    fn check(token: &str, set: &Jwks) -> Result<Token, Invalid> {
        let t = decode(token)?;
        t.verify(set)?;
        t.check("client-1", nonce(), NOW)?;
        Ok(t)
    }

    #[test]
    fn accepts_a_good_token_signed_by_any_published_key() {
        let [k1, k2] = keys();
        let set = Jwks::parse(&jwks(&[k1, k2])).unwrap();
        assert_eq!(
            check(&k1.sign(&claims()), &set).unwrap().str("sub"),
            Some("s")
        );
        assert!(check(&k2.sign(&claims()), &set).is_ok());
        let no_kid = k2.sign_with(&json!({ "alg": "RS256" }), &claims());
        assert!(check(&no_kid, &set).is_ok(), "no kid: try each key");
    }

    #[test]
    fn refuses_bad_signatures_and_other_algorithms() {
        let [k1, k2] = keys();
        let only_k1 = Jwks::parse(&jwks(&[k1])).unwrap();
        let forged = k2.sign_with(&json!({ "alg": "RS256", "kid": "k1" }), &claims());
        assert_eq!(
            check(&forged, &only_k1).err(),
            Some(Invalid("bad_signature"))
        );
        assert_eq!(
            check(&k2.sign(&claims()), &only_k1).err(),
            Some(Invalid("unknown_key"))
        );

        let good = k1.sign(&claims());
        let (head, rest) = good.split_once('.').unwrap();
        let (_, sig) = rest.split_once('.').unwrap();
        let mut c = claims();
        c["sub"] = json!("admin");
        let tampered = format!("{head}.{}.{sig}", B64.encode(c.to_string()));
        assert_eq!(
            check(&tampered, &only_k1).err(),
            Some(Invalid("bad_signature"))
        );

        let unsigned = format!(
            "{}.{}.",
            B64.encode(r#"{"alg":"none"}"#),
            B64.encode(claims().to_string())
        );
        assert_eq!(
            check(&unsigned, &only_k1).err(),
            Some(Invalid("bad_algorithm"))
        );
        let hs = format!(
            "{}.{}.{sig}",
            B64.encode(r#"{"alg":"HS256","kid":"k1"}"#),
            B64.encode(claims().to_string())
        );
        assert_eq!(check(&hs, &only_k1).err(), Some(Invalid("bad_algorithm")));
        let crit = k1.sign_with(
            &json!({ "alg": "RS256", "kid": "k1", "crit": ["x"] }),
            &claims(),
        );
        assert_eq!(check(&crit, &only_k1).err(), Some(Invalid("bad_algorithm")));
        for junk in ["", "a.b", "a.b.c.d", "!!.!!.!!", &format!("{good}x")] {
            assert!(check(junk, &only_k1).is_err(), "{junk}");
        }
        assert!(Jwks::parse(&json!({ "nope": [] })).is_err());
        let mut enc = k1.jwk();
        enc["use"] = json!("enc");
        assert!(
            Jwks::parse(&json!({ "keys": [enc] }))
                .unwrap()
                .keys
                .is_empty(),
            "encryption keys are not signing keys"
        );
    }

    #[test]
    fn refuses_tokens_for_someone_else_out_of_time_or_replayed() {
        let [k1, _] = keys();
        let set = Jwks::parse(&jwks(&[k1])).unwrap();
        let with = |f: &dyn Fn(&mut Value)| {
            let mut c = claims();
            f(&mut c);
            check(&k1.sign(&c), &set).err()
        };
        assert_eq!(
            with(&|c| c["aud"] = json!("client-2")),
            Some(Invalid("wrong_audience"))
        );
        assert_eq!(
            with(&|c| c["aud"] = json!(["client-2", "client-1"])),
            Some(Invalid("wrong_audience")),
            "several audiences need azp"
        );
        assert_eq!(
            with(&|c| {
                c["aud"] = json!(["client-2", "client-1"]);
                c["azp"] = json!("client-1");
            }),
            None
        );
        assert_eq!(
            with(&|c| c["azp"] = json!("client-2")),
            Some(Invalid("wrong_audience"))
        );
        assert_eq!(
            with(&|c| c["exp"] = json!(NOW - SKEW - 1)),
            Some(Invalid("expired"))
        );
        assert_eq!(
            with(&|c| c["exp"] = json!(NOW - 60)),
            None,
            "within the clock skew"
        );
        assert_eq!(
            with(&|c| c["nbf"] = json!(NOW + SKEW + 60)),
            Some(Invalid("not_yet_valid"))
        );
        assert_eq!(
            with(&|c| c["iat"] = json!(NOW + SKEW + 60)),
            Some(Invalid("not_yet_valid"))
        );
        assert_eq!(
            with(&|c| {
                c.as_object_mut().unwrap().remove("exp");
            }),
            Some(Invalid("malformed"))
        );
        assert_eq!(
            with(&|c| c["nonce"] = json!("n-2")),
            Some(Invalid("nonce_mismatch"))
        );
        assert_eq!(
            with(&|c| {
                c.as_object_mut().unwrap().remove("nonce");
            }),
            Some(Invalid("nonce_mismatch"))
        );
    }
}
