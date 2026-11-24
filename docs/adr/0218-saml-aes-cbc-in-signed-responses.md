# 0218: SAML AES-CBC assertions, only in signed responses

## Status

Accepted. The eleventh M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Amends [ADR 0150](0150-saml-encrypted-assertions.md) (encrypted assertions, AES-GCM only), which refused AES-CBC and so left Entra ID and ADFS customers without encryption. Setup guide: [native SAML](../sso/saml-native.md#aes-cbc-entra-id-and-adfs).

## Context

ADR 0150 takes encrypted assertions with AES-GCM only. AES-CBC is refused because it isn't authenticated: an attacker who can send changed ciphertext and tell a padding error from other errors can recover the plaintext a block at a time (Jager and Somorovsky, "How to Break XML Encryption", 2011). The same paper's backwards-compatibility attack uses CBC to break even a GCM key, when the same RSA key wraps both.

The two IdPs most enterprise customers run, Microsoft Entra ID and ADFS, encrypt assertions only with AES-256-CBC (with RSA-OAEP). Customers whose policy says assertions must be encrypted therefore can't use native SAML with them. It was the one item left open on #52.

Both IdPs can also sign the whole response, not just the assertion: Entra ID's **Sign SAML response and assertion**, and ADFS's `-SamlResponseSignature MessageAndAssertion`. botd's enveloped signature check (ADR 0127) takes only a reference to the signed element's own ID with the enveloped and exclusive-c14n transforms, so a valid response signature covers every byte of the `EncryptedAssertion`: the `EncryptedKey`, the IV and the ciphertext.

## Decision

A new per-provider setting, `SSO_<ID>_AES_CBC`, default `off`.

- `signed-response` takes AES-128-CBC, AES-192-CBC and AES-256-CBC assertions, but only when the response is signed by a certificate in the IdP's metadata. botd already checks a response signature before decrypting (ADR 0150), so changed ciphertext fails as `bad_signature` and is never decrypted. There is no padding oracle to query, and the backwards-compatibility attack needs changed ciphertext too.
- A CBC assertion in an unsigned response is refused as `cbc_unsigned_response`, before decryption. It is throttled in the audit log like other refusals the IdP never vouched for.
- With `off`, CBC is refused as `weak_algorithm`, as before. Triple DES is refused always.
- The setting needs `ENCRYPTED_ASSERTIONS=allow` or `require`, and is for native SAML only. Other values are refused at startup.
- The inner assertion must still be signed (ADR 0150's rule: anyone can encrypt to our public certificate).
- Encrypted NameIDs (`EncryptedID`, ADR 0151) never take CBC. Entra ID and ADFS encrypt whole assertions, not NameIDs, so nothing needs it, and the LogoutRequest path stays as ADR 0151 left it.
- Decryption uses XML Encryption's ISO 10126 padding (random filler, last byte the length), with the IV the first 16 bytes. botd checks the padding length only, and any failure is `bad_encryption`; with the signature checked first, the difference can't be probed.
- The SP metadata lists AES-256-CBC and AES-128-CBC after the GCM methods, only when the setting is on, so an IdP that picks the first method it supports still picks GCM.
- `auth.login` events (and refusals after decryption) carry `details.assertionEncryption`, such as `aes256-cbc` or `aes256-gcm`. Admins can see which IdPs still use CBC and drop the setting once they move.
- `GET /api/sso/:id/saml` has `aesCbc`, and `botctl sso saml <id>` says when CBC is taken.

## Alternatives considered

- **Keep refusing CBC.** Safe, but leaves Entra ID and ADFS customers with no encryption, which some policies require. Rejected: with the response signature checked first, CBC is as safe here as GCM.
- **Take CBC whenever the assertion is signed.** The assertion's signature is inside the ciphertext, so it can't be checked before decrypting, and the oracle stays open. Rejected.
- **Take CBC without a setting whenever the response is signed.** Fewer settings, but it widens what every existing provider accepts without the admin choosing it, and the metadata would offer CBC to IdPs that do GCM. Rejected; opt-in matches ADR 0150.
- **Hide padding errors and decrypt in constant time instead.** That is what most SAML libraries attempted after 2011, and timing and error side channels kept turning up. Rejected in favour of never decrypting what the IdP didn't sign.
- **A separate decryption key for CBC.** It would stop a cross-algorithm attack on the RSA key, but the signature already does, and IdPs take one encryption certificate. Rejected.

## Consequences

- Entra ID and ADFS can encrypt assertions to SuperBot, with one setting and the IdP signing the response too. The guide and runbook say how.
- An admin who turns the setting on but leaves the IdP signing only the assertion sees `cbc_unsigned_response` with a clear fix.
- Encryption stays per provider: a CBC provider doesn't change what any other provider accepts.
- If an IdP later offers GCM, switching needs no change here; the audit field shows the switch, and the setting can go back to `off`.
