# 0150: Encrypted SAML assertions

## Status

Accepted. The third M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (the ACS and its XML-DSig verifier) and [ADR 0137](0137-saml-signed-requests-and-single-logout.md) (the SP key). Setup guide: [native SAML](../sso/saml-native.md#encrypted-assertions).

## Context

ADRs 0127 and 0137 refuse `EncryptedAssertion` and name it as the next slice. Some customers' policies require encrypted assertions, so the assertion (with the person's identifiers and attributes) is unreadable in the browser, its extensions and its logs. Those customers had to keep the Keycloak bridge.

XML Encryption is easy to get wrong. AES-CBC in XML Encryption 1.0 has a padding oracle that recovers the plaintext from error responses ("How to Break XML Encryption", Jager and Somorovsky, 2011), and a backwards-compatibility attack turns an AES-GCM key into a CBC oracle if both are accepted. RSA PKCS #1 v1.5 key transport has Bleichenbacher's oracle. Decryption also adds new places for signature wrapping: the decrypted assertion is a second document, and an encrypted assertion proves nothing about who wrote it, because anyone can encrypt to our public certificate.

The other item in scope for this slice, IdP metadata refreshed from a URL, already ships: ADR 0127 refreshes metadata from `SSO_<ID>_IDP_METADATA_URL` daily, keeps the last good copy, and takes every certificate listed, so IdP certificate rollovers need nothing. Signed metadata is left for later (below).

## Decision

**Off unless asked, per provider.** `SSO_<ID>_ENCRYPTED_ASSERTIONS` is `off` (the default: `EncryptedAssertion` is refused as `encrypted_assertion`, as before), `allow` (encrypted or plain), or `require` (a plain assertion is refused as `unencrypted_assertion`). Native providers only; the bridge decrypts in Keycloak.

**A separate encryption key.** The ADR 0137 signing key is never used to decrypt. When encryption isn't off, botd makes a second RSA-3072 key and 20-year certificate for the provider the first time it's needed, sealed in the settings `sso_saml_sp_key_<id>_encryption` and `sso_saml_sp_cert_<id>_encryption`. Provider ids have no `_`, so these names can't clash with another provider's, and master-key rotation and `SUPERBOT_FORGET_SEALED` treat them like the signing key. Making it is audited as `sso.saml_sp_key_created` with `use` = `encryption`. Operators can set their own with `SSO_<ID>_SP_ENCRYPTION_CERT_FILE` and the key as the server secret `SSO_<ID>_ENCRYPTION_PRIVATE_KEY`. It must be another certificate than `SP_CERT_FILE`. The provider isn't offered until the key is set and matches. SP metadata publishes the certificate as `<md:KeyDescriptor use="encryption">` with the algorithms we take as `EncryptionMethod`s, and only when encryption isn't off.

**Strong algorithms only, checked before decrypting.** One `xenc:EncryptedData` (type absent or `#Element`), with its keys in its `ds:KeyInfo` or beside it in the `EncryptedAssertion` (at most four, so an IdP rollover that encrypts the key to several certificates works).

- Content: AES-128-GCM, AES-192-GCM or AES-256-GCM (XML Encryption 1.1: a 12-byte IV, then the ciphertext, then a 16-byte tag; no additional data). AES-CBC and Triple DES are refused as `weak_algorithm`, and anything else as `bad_algorithm`.
- Key transport: `rsa-oaep-mgf1p` (its digest only SHA-1, as 1.0 defines it) or 1.1 `rsa-oaep` with a matching SHA-1, SHA-256, SHA-384 or SHA-512 digest and MGF1. RSA PKCS #1 v1.5 is refused as `weak_key_transport`, even when another key beside it is good. `OAEPparams` and `CipherReference` are refused.
- Every algorithm in the message is checked before any decryption, so a refusal never depends on a secret.

**Decryption fails one way.** Keys come only from botd's private key. Names and certificates in `KeyInfo` are ignored, and a `KeyValue` there is refused. Each `EncryptedKey` is tried with our key. If none gives a content key of the right length, botd continues with a random one, so a wrong key, a bad wrapped key and a tampered ciphertext all take the same path to the same GCM tag failure: `bad_encryption`. The content key and plaintext are zeroized after use.

**Signatures and wrapping, as for a plain assertion.** The order:

1. Structure first. The one `saml:EncryptedAssertion` must be a direct child of the `Response`, with no plain `Assertion` anywhere. Outer `ds:Signature`s may only be direct children of the `Response`.
2. A signature on the response is verified before anything is decrypted.
3. Decrypt. The plaintext is parsed with the namespaces in scope at the `EncryptedAssertion`, since IdPs sign and serialize the assertion in place, and with the same parser rules (no DTD, no comments, size limits).
4. The decrypted document must hold exactly one `saml:Assertion`, with nothing else but whitespace beside it, no assertion inside it, and signatures only as its direct children. IDs must be unique across the response and the decrypted assertion together.
5. The assertion inside must be signed by a certificate in the IdP's metadata, whether or not the response was signed. Anyone can encrypt to us, so encryption never stands in for the IdP's signature. Then every ADR 0127 check runs on it unchanged.

`EncryptedID` in the subject is refused with `encrypted_id`. The new refusals that come before a signature is checked are throttled in the audit log like the others.

## Consequences

- Customers who require encrypted assertions can use native SAML with Okta, OneLogin, PingFederate and other IdPs that offer AES-GCM with RSA-OAEP. Entra ID and ADFS only encrypt with AES-256-CBC, so for them encryption stays off. That is safe: assertions travel over TLS and are signed, and accepting CBC would bring back the padding oracle for every provider.
- An IdP that rotates SuperBot's encryption certificate on its own can't, since botd decrypts only with its own key. Changing keys means giving the IdP the new certificate first. Self-supplied keys are read once, so changing one needs a restart, as for the signing key.
- Two more settings per native provider that encrypts. Deleting them makes botd generate a new key, which the IdP must then import.
- `roxmltree` and `aws-lc-rs` (already dependencies) do the parsing, RSA-OAEP and AES-GCM. There is no general XML Encryption library and no new dependency.
- Still not supported: encrypted NameIDs (`EncryptedID`), ECDSA keys, and verifying signed IdP metadata (metadata is trusted from https or an admin, as in ADR 0127). IdP-initiated sign-in stays off by design.
