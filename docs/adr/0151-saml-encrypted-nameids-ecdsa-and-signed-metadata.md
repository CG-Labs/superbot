# 0151: Encrypted NameIDs, ECDSA keys and signed IdP metadata for SAML

## Status

Accepted. The fourth and last M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (the ACS, metadata, XML-DSig), [ADR 0137](0137-saml-signed-requests-and-single-logout.md) (the SP key, single logout) and [ADR 0150](0150-saml-encrypted-assertions.md) (XML Encryption). Setup guide: [native SAML](../sso/saml-native.md).

## Context

ADR 0150 left three gaps in native SAML:

- **Encrypted NameIDs.** Some IdPs encrypt only the subject (`saml:EncryptedID`), in assertions and in their LogoutRequests. botd refused both as `encrypted_id`.
- **ECDSA keys.** botd verified only RSA signatures and its SP key could only be RSA. IdPs and policies that use P-256 or P-384 couldn't use native SAML.
- **Signed IdP metadata.** Metadata was trusted because it came over https or from an admin. Federations and some IdPs sign it, so a compromised web host, proxy or file can't swap in an attacker's signing certificate.

IdP-initiated sign-in stays off by design (ADR 0127): it has no request to answer, so it can't be bound to the browser.

## Decision

**Encrypted NameIDs use the ADR 0150 decryption.** An `EncryptedID` is an `EncryptedElementType`, like `EncryptedAssertion`, so it goes through the same code: AES-GCM content and RSA-OAEP key transport only, every algorithm checked before decrypting, and one `bad_encryption` for a wrong key, a bad wrapped key or a tampered ciphertext.

- It's decrypted with the provider's encryption key, so it needs `SSO_<ID>_ENCRYPTED_ASSERTIONS=allow` or `require`. With encryption off, there's no key and it's refused as `encrypted_id`, as before. No new setting.
- It's read only after the signature over it is verified (the assertion's, or the LogoutRequest's). Anyone can encrypt to our certificate, so the ciphertext counts only as part of what the IdP signed.
- The plaintext is parsed in the namespaces in scope at the `EncryptedID`, with the same parser rules (no DTD, no comments). It must hold exactly one `saml:NameID` and nothing else.
- A subject or LogoutRequest with more than one identifier (`NameID`, `EncryptedID`, `BaseID`) is refused as `wrapped`. `BaseID` alone is still `missing_subject`.
- The decrypted NameID is used and stored like a plain one. botd's own LogoutRequests send the stored NameID in plain: the IdP knows it, and the request is signed and goes over TLS.

**ECDSA signatures, with strict pairing.**

- IdP certificates may be RSA (2048 bits or more), P-256 or P-384. Other curves and key types are refused when the metadata is read.
- `ecdsa-sha256` verifies only with P-256 keys, `ecdsa-sha384` only with P-384 keys, and the RSA algorithms only with RSA keys. A signature never verifies with a key of another kind, even when the curve library would allow it.
- Signature values are `r || s` (64 bytes for P-256, 96 for P-384), as XML-DSig 1.1 and the redirect binding define them. DER-encoded values are refused.
- SHA-384 digests are taken. `ecdsa-sha1`, like `rsa-sha1`, is refused as `weak_algorithm`.
- The SP signing key (`SP_CERT_FILE` with the provider's `PRIVATE_KEY`) may be P-256 or P-384 PKCS #8. botd then signs with `ecdsa-sha256` or `ecdsa-sha384`. Generated keys stay RSA-3072, which every IdP takes. The encryption key must be RSA, since IdPs encrypt to it with RSA-OAEP: an ECDSA `SP_ENCRYPTION_CERT_FILE` is refused at startup.

**Signed metadata against a trust anchor, per provider.**

- `SSO_<ID>_METADATA_SIGNING_CERT_FILE` names a PEM file with one or more certificates. Several are for the IdP's rollover. `SSO_<ID>_SIGNED_METADATA` is `require` (the default with the file), `allow`, or `off` (the default without it). `allow` or `require` without the file, `off` with it, or anything else is a startup error.
- The anchor is checked on every load: the URL fetch (daily), the file at startup, a botctl import, and the imported copy at startup.
- The signature must be enveloped on the `EntityDescriptor` or on the `EntitiesDescriptor` at the root, and verify against an anchor with the XML-DSig rules above (exclusive C14N, one reference to the signed element, no wrapping, strong algorithms). A signature on another entity in an aggregate doesn't count.
- With `require`, unsigned metadata is refused as `unsigned`. With `allow`, it's taken unchecked. With either, a signature that is present but doesn't verify is refused.
- Signed metadata is refused as `expired` once any descriptor from the root down to the entity is past its `validUntil`, so an old signed copy can't be served again. In unsigned metadata `validUntil` is still ignored, since it proves nothing.
- A refused copy never replaces what is loaded. From a URL, botd keeps the last good copy and tries again after the refresh gap. An import is refused with a 400, and the stored copy stays. A file or a stored copy refused at startup stops the provider: the file stops botd, and the stored copy leaves the provider not offered until it's imported again.
- Refusals for the signature or validity are audited as `sso.saml_metadata_refused`, also when the last good copy is used instead, with the provider, the source, the reason, and whether a good copy is still in use. Metadata that just doesn't parse or is for another entity isn't a trust failure, so it isn't audited that way.
- Comments inside a certificate's text no longer cut it short. Exclusive C14N drops comments, so an attacker could add one to signed metadata without breaking the signature.

**Hardening.** Canonicalization refuses elements nested more than 128 deep, so a crafted document can't exhaust the stack.

## Consequences

- With this slice, native SAML covers what the roadmap asked of #52: signed and encrypted assertions and NameIDs, RSA and ECDSA keys, signed AuthnRequests, single logout, and signed metadata. IdP-initiated sign-in stays off by design.
- An IdP that encrypts NameIDs needs `ENCRYPTED_ASSERTIONS` turned on, even if it doesn't encrypt whole assertions. The setup guide says so.
- With signed metadata required, an IdP that rotates its metadata signing key needs the new certificate in the anchor file first. Until then, URL refreshes are refused and audited, and the last good copy keeps working.
- No new dependency. `aws-lc-rs` does ECDSA, and `x509-parser` reads the curve from the certificate.
- Not tested against an external XML-DSig implementation for ECDSA: the tests sign with our own test signer, and RSA interop fixtures from earlier slices still pass.
