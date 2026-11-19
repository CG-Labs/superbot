//! The SAML bridge (ADR 0019). botd never parses SAML: an OIDC broker (Keycloak) is the
//! SAML service provider, checks the IdP's signed assertion, and signs people in to
//! botd over OpenID Connect like any other provider. What botd adds on its side:
//!
//! - **Brokered, by that IdP.** The ID token's `identity_provider` claim (Keycloak's user
//!   session note, set only by a brokered login) must name the SAML IdP's alias. A
//!   password login at the broker, or a login through another IdP the broker knows, has
//!   no such claim or another value, and is refused (`not_brokered`).
//! - **The SAML identity is the key.** The subject is the IdP's name for the person
//!   (`identity_provider_identity`: the NameID, by Keycloak's default principal type),
//!   stored under the IdP's entity ID. So identities don't depend on the broker: a new
//!   realm, another broker, or native SAML later (M5) names the same identity.
//! - `kc_idp_hint` goes straight to the SAML IdP, skipping the broker's own login page.

/// The ID token claim that says which IdP the broker used (a Keycloak user session note).
pub const IDP_CLAIM: &str = "identity_provider";
/// The default subject claim: the person's id at the SAML IdP (a Keycloak user session note).
pub const SUBJECT_CLAIM: &str = "identity_provider_identity";
/// Keycloak's authorization parameter that goes straight to one of its IdPs.
pub const HINT_PARAM: &str = "kc_idp_hint";
pub const LABEL: &str = "Company SSO";

/// A SAML subject as identities store it: lowercase. Keycloak lowercases the IdP's name for
/// the person before passing it on, so a link typed from the IdP's own records must match
/// that. Persistent NameIDs are random or directory ids; case never tells two people apart.
pub fn subject(s: &str) -> String {
    s.to_lowercase()
}

/// An IdP alias as Keycloak allows it in URLs: letters, digits, `.`, `_`, `-`.
pub fn alias(s: &str) -> Option<String> {
    let s = s.trim();
    ((1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))).then(|| s.to_string())
}

/// A SAML entity ID: a URI of at most 1024 characters (SAML core 8.3.6), with no spaces.
pub fn entity_id(s: &str) -> Option<String> {
    let s = s.trim();
    let uri = s.split_once(':').is_some_and(|(scheme, rest)| !scheme.is_empty() && !rest.is_empty() && scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)));
    ((1..=1024).contains(&s.len()) && uri && s.bytes().all(|b| b.is_ascii_graphic())).then(|| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_and_entity_ids() {
        assert_eq!(alias(" adfs ").as_deref(), Some("adfs"));
        assert!(alias("okta-saml_2.prod").is_some());
        for bad in ["", "ad fs", "adfs/../x", "a?b", &"a".repeat(65)] {
            assert!(alias(bad).is_none(), "{bad}");
        }
        for good in ["http://adfs.example.com/adfs/services/trust", "http://www.okta.com/exk1abc", "urn:example:idp", "https://idp.example/metadata"] {
            assert_eq!(entity_id(good).as_deref(), Some(good));
        }
        for bad in ["", "adfs", "http://adfs.example.com/a b", ":nope", "x:", &format!("urn:{}", "a".repeat(1024))] {
            assert!(entity_id(bad).is_none(), "{bad}");
        }
    }
}
