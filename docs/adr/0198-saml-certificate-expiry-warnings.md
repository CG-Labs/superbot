# 0198: Warning before SAML certificates expire

## Status

Accepted. The ninth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (the native SP), [ADR 0137](0137-saml-signed-requests-and-single-logout.md) and [ADR 0150](0150-saml-encrypted-assertions.md) (botd's own keys), [ADR 0151](0151-saml-encrypted-nameids-ecdsa-and-signed-metadata.md) (signed IdP metadata) and [ADR 0181](0181-saml-sp-key-rollover.md) (rolling over botd's keys), which left this for later. Follows [ADR 0196](0196-scim-token-expiry-and-rotation.md)'s expiry notices for SCIM tokens. Setup guide: [native SAML](../sso/saml-native.md#certificates-that-are-ending).

## Context

A native SAML provider depends on four kinds of certificate:

- **botd's signing certificate**, published in its SP metadata. The IdP checks signed AuthnRequests and logout messages with it.
- **botd's encryption certificate**, with encrypted assertions on. The IdP encrypts to it.
- **The IdP's signing certificates**, from its metadata. botd checks every assertion and logout message with them.
- **The metadata signing certificates** in `SSO_<ID>_METADATA_SIGNING_CERT_FILE`, when signed metadata is checked.

botd doesn't refuse a signature for its certificate's dates. In SAML, the metadata names the key to trust, and the certificate is only how the key is carried. That stays as it is. But an expiry still breaks sign-in, at the other end or on a date nobody is watching:

- **The IdP replaces its own certificate when it ends.** Entra ID's SAML signing certificates last three years, ADFS rolls its token-signing certificate over yearly, and Okta's last ten years. With metadata from a URL, botd's daily refresh picks up the new one. With a metadata file or an import, nothing does: on the day the IdP switches, every sign-in fails with `bad_signature` until an admin brings botd new metadata.
- **Some IdPs refuse an expired SP certificate**, for encryption or to check signed requests and logout messages. botd's generated certificates last 20 years for this reason. A configured one (`SP_CERT_FILE`, `SP_ENCRYPTION_CERT_FILE`) often comes from a corporate CA with a one- or two-year life.
- **A federation's metadata signing certificate is replaced at its end.** After that, botd refuses each refresh as `bad_signature` and keeps the last good copy. The next IdP certificate rollover is then missed.

`botctl sso saml <id>` showed each certificate's end date, but nothing said when one was close, and nothing reached the SIEM.

## Decision

botd watches every certificate a native SAML provider uses, and warns before and when it ends.

**Which certificates.** botd's own: the configured certificate, or the generated key's current and next certificates (ADR 0181), as published. A previous encryption key isn't published, so it's left out. These are read as they are kept, so checking never makes a key. The IdP's: the signing certificates in the metadata in use. And the trust anchors in `METADATA_SIGNING_CERT_FILE`. A certificate listed twice is checked once.

**When.** A certificate is `expiring` from 30 days before its `notAfter`, and `expired` from then on. Thirty days leaves time to take a certificate to an IdP admin or a change board, and sits within Entra ID's own 60/30/7-day notices. The window is fixed. A setting would be one more thing that differs between servers, and the audit events can feed any longer reminder a SIEM wants.

**Covered or not.** A certificate is *covered* when another of the same kind isn't ending: the IdP's next certificate is already in its metadata, botd's next key is published, or another trust anchor outlives it. This is reported as `replacement`, the SHA-256 of that certificate. It decides what to do. A covered IdP certificate needs nothing. A covered SP key needs promoting once the IdP has the next one. Anything uncovered needs someone to act.

**Audited once per certificate.** botd checks at startup and then hourly. Before checking a provider whose IdP metadata comes from a URL, it refreshes it if the daily refresh is due. So a certificate the IdP already replaced there isn't reported, and a quiet server's metadata no longer waits for a sign-in to be read. A refused refresh is audited as before (`sso.saml_metadata_refused`). Each certificate gets:

- `sso.saml_certificate_expiring`, once, when it enters the window, with outcome `success`;
- `sso.saml_certificate_expired`, once, after its end, with outcome `failure` when nothing replaces it, else `success`.

Both are system events on the `sso_provider`. Their details are `role` (`sp_signing`, `sp_encryption`, `idp_signing`, `metadata_signing`), `stage` for a generated key, `from` (where the certificate comes from), `certificate`, `subject`, `notAfter`, `daysLeft` and `replacement`. A certificate already ended when botd first sees it gets only `expired`. Which notice was given is kept in a table of its own (`saml_cert_notices`, by provider, role and SHA-256). The notice is claimed with a conditional upsert in the transaction that records the audit event. So a notice that can't be recorded is still owed at the next check, and one already recorded is never repeated, even after a restart. Every one is also logged as a warning naming the provider, the kind of certificate and when it ends. The certificate and what to do stay in the audit event and `botctl`. These are audit events, not emails, for the same reasons as ADR 0196: the audit log is where SAML's other alerts go, and it reaches the customer's SIEM.

**Shown where admins look.** In `GET /api/sso/:id/saml`, every certificate has `expiry` (`ok`, `expiring`, `expired`) and `daysLeft`. `certificateWarnings` lists the ones that need a notice, each with an `action` sentence for its role, source and replacement. For example: roll it over with `botctl sso saml <id> key next signing`, promote the next key, replace `SP_CERT_FILE` and the key in `.env`, renew it at the IdP and import its new metadata, or nothing to do. `botctl sso saml <id>` prints these as **Certificate warnings** below the IdP's entity ID, and adds "(in N days)" or "(expired)" after each ending date.

**What doesn't change.** No signature check, refusal or decryption depends on a certificate's dates. Accepting a signature only from a certificate that hasn't expired would make an IdP's late rollover an outage. It wouldn't stop anyone who has the key. botd never rolls a key over or promotes one by itself either, as ADR 0181 decided, because it can't tell when the IdP has the new certificate.

## Alternatives considered

- **Refuse signatures from expired IdP certificates.** It sounds stricter, but it protects nothing: the key is what's trusted, and an attacker with a leaked key can use it while the certificate is still valid. It also turns a missed rollover into an outage on a fixed date. Most SAML SPs, Shibboleth among them, don't do it either. Rejected.
- **Rotate botd's generated keys automatically near their end.** botd can't see when an IdP takes up new metadata (ADR 0181), and generated certificates last 20 years. Rejected. The warning names the rollover commands.
- **A configurable window (`SSO_SAML_CERT_WARN_DAYS`).** It adds a setting for little gain, since a SIEM can alert earlier on its own clock from `notAfter`. Rejected for now. It's easy to add if asked for.
- **Several warnings (60, 30, 7 days).** That's more events per certificate for the same fact, already in the view every day. One warning and one end, like SCIM tokens, keeps the SIEM rules simple.
- **Keep notices in `settings`.** That needs no migration, but it mixes state about each certificate, which grows with every rollover, into server settings. Rejected for a small table of its own.
- **Email the admins.** As ADR 0196 says, botd's mail isn't set up for server admins' operational alerts. The audit log and SIEM are the existing path.

## Consequences

- An admin, and their SIEM, hear about every SAML certificate 30 days before it ends and again when it does, with whether anything replaces it. "The IdP's certificate rolled over and nobody updated the metadata file" becomes a warning instead of an outage.
- Providers with metadata from a URL are refreshed at least daily, even with no sign-ins.
- One migration adds `saml_cert_notices`. Nothing is backfilled. Certificates already in the window get their notice at the first check after upgrading.
- Signature, decryption and metadata checks are unchanged.
- Still to do for #52: Entra ID and ADFS encrypted assertions (AES-CBC, refused by design) and back-channel (SOAP) logout.
