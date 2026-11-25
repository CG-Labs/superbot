# 0290: SAML IdP-initiated sign-in at several IdPs of a federation

## Status

Accepted. The twentieth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0175](0175-saml-idp-initiated-sign-in-restarted.md) (IdP-initiated sign-in, restarted as SP-initiated) and [ADR 0282](0282-saml-several-idps-of-a-federation.md) (several IdPs of a federation on one provider), which refused `IDP_INITIATED=restart` with several IdPs. Setup guide: [native SAML](../sso/saml-native.md#several-idps-of-a-federation).

## Context

ADR 0282 lets one native SAML provider take several IdPs of a federation, with people picking their institution on SuperBot's chooser. It refused `SSO_<ID>_IDP_INITIATED=restart` with several IdPs, because the restarted sign-in has to know which IdP to go to, and an unsolicited response says which IdP it's from only in its `Issuer`, which is unsigned until checked.

In federations, IdP-initiated links are common, not a portal nicety: a university's library pages, its learning platform and its own portal link to a service with Shibboleth's unsolicited endpoint (`/idp/profile/SAML2/Unsolicited/SSO?providerId=<SP>`), which posts an unsolicited response to the ACS. With one provider for several IdPs, every such link showed "That sign-in expired" and the consortium had to teach people to start at SuperBot instead.

Single logout already faced the same question for several IdPs: botd reads a logout message's `Issuer` before anything is checked (`saml_slo::claimed_issuer`), only to pick which listed IdP's metadata to check it against, then checks it in full as from that IdP (ADR 0282). Nothing read before the signature check decides anything but whose keys check it.

## Decision

### Settings

`IDP_INITIATED=restart` is allowed with `IDP_ENTITY_IDS`, and covers every listed IdP. Nothing new to set. A single IdP works exactly as before.

### Which IdP's keys check it

With several IdPs, an unsolicited post to the ACS names its IdP before it is checked:

- **Posted** (`SAMLResponse`): the response's own `Issuer` if it has exactly one, else its one plain assertion's (the Response's `Issuer` is optional in SAML 2.0) (`saml_sp::claimed_issuer`). An encrypted assertion's `Issuer` can't be read without decrypting it, so a response with neither is refused. Real IdPs (Shibboleth, Entra ID, Okta, ADFS) always put one on the response.
- **As an artifact** (`SAMLart`, ADR 0268): the listed IdP whose entity ID's SHA-1 is the artifact's `SourceID` (`saml_artifact::claimed_source`), as the binding defines it. `saml_artifact::parse` then checks it against that IdP again, and only that IdP's ArtifactResolutionService is asked.

An IdP that isn't listed, or nothing to read one from, is refused as `unknown_idp` (`idpInitiated: true`, with `entityId` when one was read), counted against the address and audited like other failures nobody vouched for, before any metadata is fetched or anything is checked. So a post can make botd fetch metadata only for an IdP the admin listed, as the chooser's `idp` can.

Otherwise the response is checked exactly as ADR 0175 says, against that IdP's metadata only: its signature by that IdP's certificates, its `Issuer` (both, again), audience, recipient, destination, time, NameID, encryption, the email and scoped group checks of ADR 0282 and 0287, and that it answers no request. A response naming IdP B but signed by IdP A fails B's signature check, so the claim can't make one IdP's signature count for another.

### Restarting at that IdP

Its assertion is spent, `auth.saml_idp_initiated` is audited with the issuer and subject, and the browser goes to `/api/auth/sso/<id>/start?idp=<entity ID>` instead of the plain start URL, so the AuthnRequest goes straight to the IdP that signed the tile, without the chooser. The restarted sign-in is an ordinary SP-initiated one at that IdP (ADR 0282): bound to the browser's binder cookie, and only that IdP's answer to it counts. So ADR 0175's argument holds per IdP: whoever the IdP signs in for this browser is who gets a session, never the tile's subject.

### Loops

ADR 0175's marker cookie named the provider. With several IdPs it names the provider and the IdP: `<provider>.<first 16 hex of SHA-256 of the entity ID>`, in the cookie's character set whatever the entity ID holds. A loop is an IdP answering its own restart unsolicited (`idp_initiated_loop`). Another listed IdP's tile within the marker's two minutes, after someone gave up at the first IdP's login page, restarts as usual. With one IdP the marker is the provider id, as before.

## Alternatives considered

- **Send every tile to the chooser.** No claim is read at all, but people who clicked their own university's link would be asked which university they're from, and a federation's IdP may be one of a hundred. The response already proves which IdP it is once checked.
- **Check the response against every listed IdP until one verifies.** Up to 100 signature checks (and MDQ fetches) per anonymous post, and an IdP whose keys another IdP shares (ADR 0282's certificate warnings allow that) would be picked by order. Reading the claim picks one, and refuses the rest at no cost.
- **Trust the `Issuer` to pick the restart's IdP without checking the response.** The restart is safe either way (ADR 0175), but botd would then bounce people to any listed IdP on unsigned input, audit subjects nobody vouched for, and hide a misconfigured IdP until the restart. ADR 0175 checks first; so does this.
- **Keep the provider-only marker.** Simpler, but someone who opens one institution's link, leaves at its login page, and opens another's within two minutes would be refused as a loop.
- **Bind the IdP into the start URL's state instead of the cookie.** The loop shows on the *next* post to the ACS, which comes from the IdP with nothing of ours in it (ADR 0175), so the browser still has to carry it.

## Consequences

- With `IDP_INITIATED=restart`, each listed IdP's portal and library links work on a provider with several IdPs, at one extra round trip to that IdP.
- An unsolicited post from an IdP that isn't listed is refused before botd fetches anything for it.
- The restart marker's value changes for providers with several IdPs only; nothing changes for one IdP, the SAML bridge or OIDC.
- One new failure context (`unknown_idp` with `idpInitiated: true`); no new settings, tables, routes or audit actions.
- SCIM linking stays refused with several IdPs (ADR 0282). Still open on #52, only if a customer needs it: whole federation aggregates over 1 MB, every IdP of a federation without a list, and SCIM linking with several IdPs.
