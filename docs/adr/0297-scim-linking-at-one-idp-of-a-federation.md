# 0297: SCIM linking at one IdP of a federation

## Status

Accepted. The twenty-first M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0023](0023-scim.md) (SCIM, with a tenant linking an SSO provider) and [ADR 0282](0282-saml-several-idps-of-a-federation.md) (several IdPs of a federation on one provider), which refused SCIM linking with several IdPs. Setup guides: [native SAML](../sso/saml-native.md#several-idps-of-a-federation) and [SCIM](../sso/scim.md).

## Context

A SCIM tenant can link an SSO provider (`botctl scim token create <tenant> --sso <provider>`). Each `externalId` it sends is then the person's subject at that provider, and botd links the SSO identity when it provisions them, so they sign in as the user SCIM made and SCIM's deprovisioning reaches their SSO sign-ins.

ADR 0282 stores the identities of a provider with several IdPs under the IdP that signed them in, `(entity ID, NameID)`. A tenant's `externalId` says nothing about which IdP, so ADR 0282 refused such a link, and ADR 0290 left it open. A consortium whose member institutions provision their own people (one on Entra ID, another through a Shibboleth-side SCIM connector) had to link people by hand or rely on just-in-time sign-up, and lost the deprovisioning that SCIM gives.

Two things need deciding: which IdP a tenant's people are at, and what else a tenant tied to one IdP may say about them. ADR 0282 holds each IdP to the domains the federation lists for it (`shibmd:Scope`) for emails in assertions, because emails are unique on SuperBot: an IdP that could set another institution's address could take it before its owner signs in (`email_taken` for them), and the address shows on the account and is where notifications go.

## Decision

### A tenant links one IdP

`POST /api/scim/tokens` takes `idp`, an IdP's entity ID (`botctl scim token create <tenant> --sso <provider> --idp <entity ID>`, and a field in the console's SCIM form). It is stored on the token (`scim_tokens.sso_idp`, shown as `ssoIdp`), and it is part of the tenant's link: like the provider, a tenant's first token sets it for good.

- `idp` needs `sso`, and only a native SAML provider takes one (`issuer_at`); it must be one of the IdPs the provider lists.
- A provider with several IdPs needs one named; without it the token is refused with how to name it.
- A native SAML provider with one IdP records that IdP when the tenant's first token is made, without being asked, so the tenant's link holds when the provider lists more later.
- A later token of the tenant takes the tenant's IdP when it names none, and is refused (409, naming the tenant's link) when it names another. Rotation copies it.
- A tenant made before this has none. With a single IdP it works as before. Once the provider lists several, provisioning a new person fails (500, so the IdP retries) with the command to run; the first token that names an IdP then sets it on all the tenant's tokens, audited with `idpSet: true`. Its people already provisioned were linked under the provider's one IdP, which the admin names.

Other providers record nothing: an Entra provider's tenant, Google, Apple, GitHub, generic OIDC and the SAML bridge link as before.

### Provisioning

A person the tenant provisions gets the identity `(that IdP's entity ID, externalId as a NameID)`, and a person an admin already linked there is taken on, both exactly as for any linked tenant. The IdP must still be listed: if the provider stops listing it, provisioning someone new or changing an email fails (500) saying so, while other updates and deprovisioning still work, since they don't touch identities or emails. Sessions, single logout and back-channel logout on deprovisioning already go to the session's own IdP (ADR 0282, 0258).

### Emails at the IdP's domains

With several IdPs, an email the tenant sets must be at one of its IdP's `shibmd:Scope`s, exactly, as at sign-in. Otherwise the request is refused, 400 `invalidValue`, naming the IdP's domains, and nothing is saved. Only a new email is checked: a create, or an update that changes it. An update that keeps it, a deactivation and a `DELETE` read no metadata, so deprovisioning never waits on the federation's MDQ server. When a new email has to be checked and the IdP's metadata can't be loaded, the answer is 503, which IdPs retry.

A single IdP isn't checked, as at sign-in: its admin chose it, and many IdPs outside federations publish no scope.

### Audit

`scim.token_created` gains `idp` (and `idpSet` when it named the tenant's IdP for its older tokens). `user.identity_linked` from SCIM already records the issuer, now the tenant's IdP. No new actions, routes or settings.

## Alternatives considered

- **The IdP in each SCIM request** (an extension attribute, or the `externalId` as `<entity ID>|<NameID>`). Every IdP's provisioning mappings would have to be changed to send it, and any member's connector could then provision people at any other member. One tenant per IdP keeps the token the boundary: whoever holds it speaks for one IdP.
- **Several IdPs per tenant.** The same objection: a tenant is one connection, and one connection is one institution. A consortium gives each member its own tenant.
- **Drop an out-of-scope email instead of refusing.** Sign-in drops one when the email decides nothing, but a SCIM email is what the IdP says the address is, and silently dropping it would leave accounts without addresses nobody notices. A refusal shows in the IdP's provisioning log, with the domains to use.
- **Check every email, deactivations included.** Deprovisioning would fail while the MDQ server is down, the opposite of what SCIM is for. An email that isn't changing was checked when it was set.
- **Leave single-IdP tenants unrecorded.** Simpler, but a provider that grows from one IdP to several would break its tenants until each named an IdP. Recording it at creation costs nothing; a tenant made before still gets a one-time way to name it.
- **Link Entra tenants the same way.** An Entra provider allowing several tenants has the same gap (SCIM can't say which tenant). It isn't SAML, and Entra provisioning is per tenant anyway; left for its own change if someone needs it.

## Consequences

- Each member institution of a federation can provision its own people on a provider with several IdPs, with their SAML identities linked and SCIM's deactivation and deletion ending their SuperBot and IdP sessions.
- A tenant tied to one IdP can't give anyone an address at another member's domains.
- New native SAML tenants record their IdP; tenants of other providers don't change. One new column (`scim_tokens.sso_idp`), no new settings.
- Still open on #52, only if a customer needs it: whole federation aggregates over 1 MB, and every IdP of a federation without a list.
