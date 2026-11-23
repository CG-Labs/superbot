# 0181: Rolling over SuperBot's own SAML keys

## Status

Accepted. The seventh M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0137](0137-saml-signed-requests-and-single-logout.md) (the SP signing key) and [ADR 0150](0150-saml-encrypted-assertions.md) (the SP encryption key). Setup guide: [native SAML](../sso/saml-native.md#rolling-over-superbots-keys).

## Context

Each native SAML provider has up to two keys of botd's own: one signs AuthnRequests and logout messages, the other decrypts encrypted assertions and NameIDs. By default botd makes them (RSA-3072, a 20-year certificate) and seals them in its database. IdP certificate rollovers were already handled: metadata may list several certificates, and a metadata URL is refreshed daily. botd's own keys had no rollover at all. The guide said "give the IdP the new certificate first; botd decrypts only with the key it has", but there was no way to make a new key, and nothing to decrypt with two.

Security policies ask for keys to be rotated on a schedule and at once after a suspected leak (a backup copied, a server image shared, an admin leaving). With one key per use, any change breaks sign-in until the IdP has the new certificate:

- **Encryption.** The IdP encrypts each assertion to the certificate it was given. If botd's key changes first, every sign-in fails with `bad_encryption` until the IdP admin uploads the new certificate. If the IdP changes first, botd can't decrypt it at all.
- **Signing.** An IdP that checks AuthnRequest or logout signatures refuses anything signed by a key it doesn't know. Most IdPs take several SP signing certificates, so the new one can be added before botd signs with it.

IdPs that read SuperBot's metadata URL pick up new certificates on their own schedule, which botd can't see.

## Decision

A rollover per provider and per use (signing or encryption), for the keys botd makes. It has three stages, each a sealed setting of its own beside the current one (`sso_saml_sp_key_<id>[_encryption]` plus `_next` or `_previous`, and the same for `sso_saml_sp_cert_`). All are covered by master-key rotation and `SUPERBOT_FORGET_SEALED`, as before.

1. **Next** (`POST /api/sso/:id/saml/keys/:use/next`, `botctl sso saml <id> key next <use>`). botd makes a new key. The SP metadata publishes its certificate after the current one, in a `KeyDescriptor` of the same use. A next encryption key also decrypts at once, so an IdP that takes up the new metadata early keeps working. A next signing key never signs. Only one next key at a time (409).
2. **Promote** (`POST .../promote`). Once the IdP has the new certificate, the next key becomes the current one, in one database transaction. botd then signs with it and publishes it alone. A replaced **encryption** key becomes *previous*: it's no longer published, but it still decrypts, so assertions the IdP encrypted to it (or an IdP slow to refresh) still sign in. A replaced **signing** key is dropped, since nothing botd receives is checked against it. Promoting while a previous key exists is refused (409), so at most three keys decrypt.
3. **Retire** (`DELETE .../previous`) drops the previous encryption key. **Cancel** (`DELETE .../next`) drops a next key that was never promoted.

Every step is admin-only, rebuilds the provider's keys under one lock, returns the provider's view, and is audited. Making a key is `sso.saml_sp_key_created`, now with `stage` (`current` or `next`). Promoting is `sso.saml_sp_key_promoted`, with the new and replaced certificates' SHA-256 and `previousKept`. Retiring or cancelling is `sso.saml_sp_key_retired`, with `stage`. A key is moved by opening it and sealing it again under its new setting's name, because the setting name is part of the sealing context.

**Knowing when to promote and retire.** botd notes, in memory, the last time each encryption key decrypted a sign-in (an assertion or its NameID). `GET /api/sso/:id/saml` and `botctl sso saml <id>` show it for the current, next and previous keys. When the next key has decrypted sign-ins, the IdP has it, so promote. When the previous key hasn't decrypted anything for a while, retire it. These times start over at each restart. They're a hint, not a record, so botd never retires a key on its own.

**What isn't rolled over here.** A key from `SSO_<ID>_SP_CERT_FILE` or `SSO_<ID>_SP_ENCRYPTION_CERT_FILE` belongs to the operator: every step is refused (409, naming the setting), and the guide explains how to roll it over in `.env`. With `ENCRYPTED_ASSERTIONS=off` there is no encryption key to roll over (409).

Decrypting takes a list of keys. The key in use is tried first, then next, then previous, and the first that unwraps an `EncryptedKey` is used. A failure looks the same whichever key was tried, and the algorithm rules and checks of ADR 0150 and 0151 are unchanged.

## Alternatives considered

- **Replace the key in one step.** This is simplest, but every sign-in fails until the IdP admin acts, for every encrypted IdP. A rotation after a leak would become an outage.
- **Rotate on a timer.** botd can't know when an IdP has the new certificate (IdPs that read metadata URLs do it on their own schedule; others need a person), so an automatic promotion could break sign-in. The certificates last 20 years, so expiry doesn't force a rotation either. Admins decide, and botd shows what it sees.
- **Keep every old key.** That needs no retire step, but a leaked key would stay useful forever, which defeats the point of rotating.
- **Keep the replaced signing key too.** Nothing botd receives is signed with its own key, so an old signing key does nothing except add a key to protect.
- **Also roll over configured keys.** Their key lives in the secret store or the environment, which the operator manages and botd may only read (Vault, cloud secret managers). The operator rolls them over there: publish both by putting the new certificate in the IdP first, then switch the file and the secret.

## Consequences

- Admins can rotate botd's SAML keys, on a schedule or after a leak, with no failed sign-ins. The steps are: next, give the IdP the new metadata or certificate, wait for the next key's first decryption, promote, then retire.
- An IdP that reads SuperBot's metadata URL needs nothing from its admin during a rollover. One given the certificate by hand needs it added once.
- The SP metadata may list two certificates of a use during a rollover, which every IdP we document accepts.
- Up to three keys per provider decrypt, each tried in turn on every encrypted sign-in. That's a few milliseconds of RSA, only during a rollover.
- Keys from before this change are the current key of their provider, unchanged, under the same setting names.
- Rolling over configured keys, and warning before an SP certificate expires, are left for later.
