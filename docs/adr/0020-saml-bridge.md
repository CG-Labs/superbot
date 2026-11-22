# 0020: SAML sign-in through an OIDC broker

## Status

Accepted. An M2 slice ([roadmap](../ROADMAP.md#m2--multi-user--sso)): the SAML bridge, the rest of [#19](https://github.com/CG-Labs/superbot/issues/19). Full native SAML stays in M5 ([#52](https://github.com/CG-Labs/superbot/issues/52)). Extends [ADR 0014](0014-oidc-sso-entra.md) and [ADR 0016](0016-sso-multi-provider.md): the flow, binder cookie, handoff to the app, account linking, and audit events (with per-user actors, [ADR 0019](0019-audit-actors.md)) are unchanged; SAML sign-ins record `idp` = `saml`. Setup guide: [SAML](../sso/saml.md). Amended by [ADR 0103](0103-sso-jit-needs-an-allow-list.md): just in time now needs `ALLOWED_DOMAINS`.

## Context

Some companies' identity providers only speak SAML 2.0: ADFS, older Okta, OneLogin, and PingFederate tenants. They should sign in to SuperBot like everyone else, landing on the same user model: one user per person across providers, the same roles, sessions, bot ACLs, and audit events.

The hard part of SAML is the signature, not the protocol. A SAML response is an XML document signed with XML-DSig, and nearly every serious SAML vulnerability comes from validating that signature: signature wrapping (the signature covers one element, the code reads another), XML external entities, comment and canonicalization tricks, parser differentials, and transforms that run code. After the signature come the protocol checks: audience and recipient, `NotBefore`/`NotOnOrAfter`, `InResponseTo`, and one-time use. That security was the deciding factor. We will not hand-roll XML-DSig.

### Options

1. **A native service provider in Rust.** The only maintained crate with signature checks is [samael](https://github.com/njaremko/samael). It does its XML-DSig with the C libraries xmlsec1, libxml2, and libxslt. In October 2026 Oxide, its main user, published [advisory 20261009-1](https://docs.oxide.computer/security/advisories/20261009-1): an unauthenticated SAML response could crash their control plane and maybe run code (CVE-2025-7424 in libxslt, reached through xmlsec's transforms), or make it send requests to internal addresses (`ds:Reference` URIs fetched by libxml2). An earlier [Trail of Bits audit](https://zoo.dev/blog/security-trail-of-bits) found several weaknesses in samael's response validation (fixed in 0.0.20, still 0.0.x). Taking it would put a C XML stack on botd's unauthenticated sign-in endpoint, add five system libraries and libclang to every build (Docker, the installer, CI), and leave the security of sign-in resting on how those libraries are configured.
2. **Dex as a SAML-to-OIDC broker.** Its own docs mark the [SAML connector](https://dexidp.io/docs/connectors/saml/) as unmaintained and "likely vulnerable to authentication bypass vulnerabilities" ([discussion #1884](https://github.com/dexidp/dex/discussions/1884), after CVE-2020-26290 and CVE-2020-27847). Ruled out.
3. **Keycloak as a SAML-to-OIDC broker.** Keycloak is a mature, widely deployed SAML service provider with a security team and frequent releases. It handles the XML, checks the signature, audience, destination, time window, and `InResponseTo`, and rejects replays. It then signs people in to botd with ordinary OpenID Connect, which botd already verifies (RS256 ID tokens, `state`, PKCE, `nonce`, binder cookie). It runs as its own service in Java, with no XML code in botd.

## Decision

Bridge through **Keycloak** (option 3), with a dedicated provider type `saml`, so the bridge is explicit rather than a generic OIDC provider that happens to point at Keycloak.

### Why its own type, not plain `oidc`

A plain `oidc` provider pointed at Keycloak would trust anyone the broker signs in: a password user created in the broker's realm, another IdP someone adds later, or a person whose Keycloak account was linked to theirs by email. And its identities would be keyed by Keycloak's own user ids, so rebuilding the broker or moving to native SAML later would orphan every link. The `saml` type closes both gaps:

- **Only the SAML IdP vouches.** botd tells Keycloak which IdP to use (`kc_idp_hint=<alias>`) and refuses any ID token whose `identity_provider` claim isn't exactly that alias (`not_brokered`, shown as "That account can't sign in here"). Keycloak sets that claim only on a session the IdP created. So a broker password login, another IdP, or an unbrokered session can't sign in, even through a hand-made request without the hint. Checked on every sign-in, before the identity is looked up.
- **Identities belong to the IdP, not the broker.** The subject is the IdP's name for the person: Keycloak's `identity_provider_identity`, which is the SAML NameID (or the attribute picked as the principal). It is stored under the IdP's **entity ID** (`SSO_<ID>_IDP_ENTITY_ID`), not the broker's issuer. A rebuilt broker, a second broker, or the native SP in M5 maps the same person to the same SuperBot user.
- **Without case.** Keycloak lowercases that identity before passing it on (verified on 26.8.2), so botd stores SAML subjects lowercased and lowercases the subject an admin links. Persistent NameIDs are opaque random or directory ids, so case never tells two people apart and this costs no real entropy. The native SP in M5 will lowercase too.

Everything else is the generic OIDC path: discovery from the broker issuer, `iss` exact, `aud` and `azp` = the client id, RS256 with the broker's JWKS, expiry, and the `nonce` bound to this sign-in. Email counts only when verified, and `ALLOWED_DOMAINS` checks it. Just in time needs a restriction like the other types, and `email`, `preferred_username`, and similar mutable claims can't be the subject. Startup refuses SAML settings on other types and other types' settings on `saml`.

### Who checks what

| Threat | Checked by | How |
|--------|-----------|-----|
| Forged or altered response, signature wrapping | Keycloak | Validate Signatures with the IdP's certificate from its metadata; Want Assertions Signed; the signed element is the one read |
| XXE, DTDs, transforms | Keycloak | DOCTYPE refused; no XSLT on the sign-in path |
| Wrong IdP | Keycloak | Identity Provider Entity ID: the response `Issuer` must match |
| Response meant for another SP (audience, recipient) | Keycloak | Audience and `Destination` must be the broker |
| Expired or early assertion | Keycloak | `NotBefore` / `NotOnOrAfter`, allowed clock skew |
| Replay, unsolicited, or another sign-in's response | Keycloak | `InResponseTo` bound to this browser's broker session; an assertion is accepted once |
| Forged or altered ID token | botd | RS256 against the broker's JWKS (`bad_signature`, `unknown_key`, `bad_algorithm`) |
| Token for another app, expired, replayed | botd | `aud`/`azp`, `exp`/`nbf`, `nonce`, one-time `state`, PKCE, binder cookie |
| Someone the SAML IdP didn't vouch for | botd | `identity_provider` must be the configured alias (`not_brokered`) |

We ran each SAML attack against Keycloak 26.8.2 brokering a second Keycloak realm as the SAML IdP, then signed in to botd through it: a tampered NameID, stripped signatures, an XSW-wrapped assertion, an XXE DOCTYPE, the same response replayed in the same and in another browser, an unused response posted into another browser's sign-in, a response the IdP issued to another SP, and an expired assertion (60 s lifespan, no skew). Keycloak refused all of them, and a broker password login with the hint stripped was refused by botd (`not_brokered`). The genuine flow signed in. botd's half is covered by unit and HTTP tests against a mock broker.

### Keycloak settings that matter

Written out in [the guide](../sso/saml.md): a realm just for the bridge with no local users or self-registration; the SAML IdP set up from its metadata URL, with **Validate Signatures**, **Want Assertions Signed**, signed AuthnRequests, **Principal type** Subject NameID, and a **persistent** NameID policy; **Trust Email** only for an IdP whose emails are verified; a confidential OIDC client with PKCE S256 and only the standard flow; two **User Session Note** mappers (`identity_provider`, `identity_provider_identity`) into the ID token; and short realm SSO sessions. Within that broker session, botd sign-ins reuse it without going back to the IdP, so its length bounds how long someone disabled at the IdP can still sign in.

### No SP metadata endpoint in botd

Keycloak is the SAML service provider, so it publishes the SP metadata (`/realms/<realm>/broker/<alias>/endpoint/descriptor`) that ADFS or Okta imports. botd only adds a provider type, with no XML and no new dependencies.

## Consequences

- SAML-only IdPs can sign in today, with the same users, roles, sessions, bot ACLs, and audit events as every other provider. Each person is one user whatever mix of providers they use.
- Operators run and update one more service (Keycloak, a JVM and a database). Its SAML security becomes part of ours, so it must be kept current. We document a supported setup but don't ship or manage it.
- The button says "Sign in with Company SSO" by default (`LABEL` changes it).
- A broker misconfiguration can only lock people out, not let others in: botd still demands the alias, the signature, and its own checks. A wrong alias or entity ID shows up in the audit log as `not_brokered` or `not_linked` with the subject.
- Moving to native SAML in M5 keeps every link, because identities are already (entity ID, lowercased NameID).
- Keycloak's lowercasing means a NameID that differs only in case from another is the same person to SuperBot. Persistent NameIDs never do that in practice.

## Not in this slice

- A native SAML service provider in botd, IdP-initiated sign-in, single logout, encrypted assertions handled by botd, and per-IdP attribute mapping (M5, [#52](https://github.com/CG-Labs/superbot/issues/52)). Revisit native once a pure-Rust XML-DSig verifier is maintained and audited, or samael's xmlsec backend can be locked down (no transforms beyond the SAML profile, no external references).
- Other brokers (Authentik, Zitadel, …): any broker that puts the IdP's alias and the person's IdP identity in signed ID token claims could work through `SUBJECT_CLAIM`, but only Keycloak is documented and tested.
- Requiring a NameID format in botd. Keycloak keeps the format only in an internal session note, so the IdP's settings (persistent NameID) are the control.
- SCIM provisioning and a linking UI.
