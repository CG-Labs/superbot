# 0127: Native SAML service provider

## Status

Accepted. The first M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Supersedes the "no SAML in botd" part of [ADR 0020](0020-saml-bridge.md); the bridge stays supported. Keeps account linking, sessions, the app handoff and audit events from [ADR 0014](0014-oidc-sso-entra.md), [ADR 0016](0016-sso-multi-provider.md) and [ADR 0019](0019-audit-actors.md), and the just-in-time allow-list rule from [ADR 0103](0103-sso-jit-needs-an-allow-list.md). Setup guide: [native SAML](../sso/saml-native.md).

## Context

The SAML bridge (ADR 0020) needs a Keycloak run next to SuperBot. Enterprise buyers asked for SAML without it: one service fewer to patch, and the IdP admin enters SuperBot's own URLs. ADR 0020 refused to hand-roll XML-DSig and rejected `samael` because it needs `xmlsec1`, `libxml2` and `libxslt`. That reasoning still holds for a general XML-DSig library. It does not hold for the narrow case a SAML SP needs: one signature over the element that holds it, enveloped, Exclusive C14N, RSA with SHA-256 or SHA-512, and a key we already know.

The known SAML attacks are signature wrapping (the signature covers one element and the code reads another), XML entities and DTDs, comments that truncate a NameID during canonicalization, parser differences between the verifier and the reader, weak algorithms, keys taken from the message, and replay, misdirection or audience confusion of an otherwise valid assertion.

## Decision

botd is a SAML 2.0 service provider itself when a `saml` provider has no `ISSUER` (with `ISSUER` it is still the bridge):

- **SP-initiated only.** `GET /api/auth/sso/{id}/start` sends an AuthnRequest over HTTP-Redirect, with a random ID kept as the sign-in's pending state and a `__Host-` binder cookie (`SameSite=None`, since the IdP posts back cross-site). `POST /api/auth/sso/{id}/acs` takes the HTTP-POST response and must name that pending sign-in in `RelayState`; IdP-initiated posts are refused. `GET /api/auth/sso/{id}/metadata` publishes SP metadata, whose URL is also the default SP entity ID.
- **One parser, one reader.** The response is parsed once with `roxmltree`, which refuses DTDs (so no entities), and every check reads that same tree. Comments and processing instructions anywhere are refused, as are responses over 256 KB or 10,000 nodes.
- **Signature, narrowly.** Exactly one `Assertion`, a direct child of `Response`; no `EncryptedAssertion`; every `ID` unique. Each `ds:Signature` must be a direct child of the Response or the Assertion, its one `Reference` must be `#` plus its parent's `ID`, its transforms exactly enveloped then Exclusive C14N, RSA-SHA256 or RSA-SHA512 with SHA-256 or SHA-512 digests (SHA-1 is refused). The key is only ever a configured IdP certificate (RSA, 2048 bits or more); `KeyInfo` in the message is ignored. The assertion must be signed; a signed response is checked too but never stands in for it. Exclusive C14N is our own, small and tested against `libxml2`'s output and an `xmlsec1`-signed fixture; RSA is `aws-lc-rs`, certificates `x509-parser`.
- **Protocol checks.** Status `Success`; `Destination`, when present, the ACS URL; `InResponseTo` on the response and on the bearer `SubjectConfirmationData` the pending request's ID; `Issuer` the configured IdP entity ID; `NotBefore`/`NotOnOrAfter` on the conditions and the confirmation, with two minutes of clock skew; every `AudienceRestriction` names our entity ID; `Recipient` the ACS URL; an `AuthnStatement`; a NameID that isn't transient. Each assertion ID is accepted once (kept until it expires); after a restart the pending request it answers is gone too, so it still can't be replayed.
- **IdP from metadata.** `SSO_<ID>_IDP_ENTITY_ID` is required. Metadata comes from `IDP_METADATA_URL` (https, refreshed daily, the last good copy kept if a refresh fails), `IDP_METADATA_FILE` (read at startup), or neither: then `botctl sso saml <id> import` stores it in botd's database, audited as `sso.saml_metadata_imported`, and the provider isn't offered until it has some. Metadata must be for the configured entity ID, have an HTTP-Redirect `SingleSignOnService` on https and signing certificates; IdPs that want signed AuthnRequests are refused, since botd doesn't sign them yet.
- **Same users.** Identities are keyed by the IdP's entity ID and the NameID, lowercased, exactly as the bridge stored them, so moving an IdP from the bridge to native keeps every link. The email comes from a configured attribute or the usual ones (`email`, `mail`, the claim URIs), counted as verified because the IdP signed it; `ALLOWED_DOMAINS` checks it, and `JIT_ROLE` needs `ALLOWED_DOMAINS`. Disabled users, by an admin or SCIM, are refused like everywhere else. Audit events are the existing `auth.login` and `auth.login_failed` with `idp` = `saml` and a reason per failed check; failures nobody vouched for (unsigned, bad signature, unknown state, …) are throttled like other unauthenticated failures.

Admins see what to enter at the IdP and the metadata in use with `botctl sso saml <id>` (`GET /api/sso/{id}/saml`); both admin routes fall under the default admin-only rule.

## Consequences

- SAML IdPs (Okta, Entra ID, ADFS, OneLogin, PingFederate) need no broker. The bridge remains for IdPs that need what this slice lacks.
- Not in this slice: encrypted assertions, signed AuthnRequests, single logout, IdP-initiated sign-in, ECDSA keys, and per-provider certificate pinning beyond the metadata. Each is refused with a clear reason rather than half-supported.
- We own a small XML-DSig verifier. It is deliberately narrow, and any change to `server/src/sso/xmldsig.rs` needs its wrapping and canonicalization tests to stay green; it should be in the next external security review's scope.
- New dependencies: `roxmltree` (pure Rust, no unsafe, no DTD support) and `miniz_oxide` (DEFLATE for the redirect binding).
