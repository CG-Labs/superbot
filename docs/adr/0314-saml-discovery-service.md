# 0314: A federation's discovery service picks the SAML IdP

## Status

Accepted. The twenty-fourth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0282](0282-saml-several-idps-of-a-federation.md) (several IdPs of a federation and the chooser) and [ADR 0308](0308-saml-every-idp-of-a-federation.md) (every IdP, and the chooser as a search box). Setup guide: [native SAML](../sso/saml-native.md#a-federations-discovery-service).

## Context

With several IdPs, botd asks people which organization they're from on a page of its own. ADR 0308 left a discovery service as a later option. Research and education federations run or recommend one: SeamlessAccess, used across eduGAIN, and national WAYFs (SWITCHwayf, DFN's, Shibboleth's embedded one). People know them. They remember the choice across every service that uses them, and they show each member's logo and names in many languages. Some federations expect their SPs to use one.

The OASIS Identity Provider Discovery Service Protocol and Profile (2008) defines how. The SP sends the browser to the service with its `entityID` and a `return` URL. The service sends the browser back to `return` with the IdP picked in a query parameter, `entityID` by default (`returnIDParam` renames it). The service only sends people to a `return` URL listed in the SP's metadata as an `idpdisc:DiscoveryResponse`. With no `return`, it uses that endpoint.

That opens some questions. What may the service decide? Where does it send people back to? How does that not loop back to it? What does it get to see?

## Decision

### `SSO_<ID>_DISCOVERY_URL`

This is the service's URL, https, with no fragment. It may have a query of its own (`?lang=en`), but not the protocol's `entityID`, `return`, `returnIDParam`, `policy` or `isPassive`, which botd sets. It's only for `IDP_ENTITY_IDS`, a list or `all`. It's refused with one IdP, where there is nothing to choose.

When a start has no `idp`, botd sends the browser to the service. This comes after the start's own checks (the app's redirect, PKCE and state, the public host, the rate limit), so a bad start fails at once and not after a detour. The request is `entityID=<SP entity ID>&return=<SSO_PUBLIC_URL>/api/auth/sso/<id>/discovery?<the start's own parameters>`. There is no `isPassive`, so people always pick, and no `returnIDParam`. No cookie is set yet: the binder is set only by the start that sends the AuthnRequest. A start with `idp` (a chooser link, a portal's link, an IdP-initiated restart) skips the service.

### A discovery response endpoint of its own

`GET /api/auth/sso/<id>/discovery` takes the service's answer, `entityID`. It does nothing but pass the pick on. It sends the browser to `/api/auth/sso/<id>/start?<the same parameters>&idp=<entityID>`, so every check stays in one place: an IdP not listed, or with `all` not in the aggregate, fails as `unknown_idp`. A provider that isn't ready, one IdP, or too many tries also go to the start, which refuses or signs in as it would anyway. A provider id nobody configured is not found (404): the redirect is only ever made from a configured provider's id, never from what the path says.

With no pick (the person gave up at the service, or it sent no answer), the endpoint shows botd's own chooser. That chooser's links go to the start with `idp`. With every IdP, its search box comes back to `/discovery`, not to `/start`, which would send the browser to the service again. So a service that never answers can't make a loop, and the person still gets in.

It's a separate endpoint and not `/start` with a marker. With no `return`, a service answers with `entityID` at the metadata's endpoint. A path of its own takes that answer, and a start without `idp` always means "not picked yet".

### The service only picks

The service never sees a SAML message, and its answer is no more trusted than a chooser link's or a URL someone types. The AuthnRequest goes to the endpoint in the picked IdP's signed metadata, and only that IdP's signed answer to that request counts. A rogue or compromised service can send people to the wrong organization's login page or to no page at all, which is the same as a phishing link. It can't sign anyone in. Login CSRF is no worse than with `start?idp=`, which anyone can already link to.

### In the SP metadata

With several IdPs, our metadata has `<md:Extensions><idpdisc:DiscoveryResponse Binding="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol" Location="…/discovery" index="0" isDefault="true"/></md:Extensions>`, first in the `SPSSODescriptor` as the schema says. It's there with or without `DISCOVERY_URL`, so a federation's own service can send people to it unasked. It's not there with one IdP. `botctl sso saml <id>` and its API show `discoveryUrl` and `discoveryResponseUrl`.

### What the service sees

The `return` URL carries the start's own parameters: `session`, and for apps `redirect`, the PKCE `challenge`, `state` and `label`. None of them signs anyone in. The challenge only matters with its verifier, which never leaves the app, and the redirect must be one of `SSO_APP_REDIRECTS`. They're sorted, so the same start always makes the same URL.

## Alternatives considered

- **Hold the parameters in botd and send the service a handle.** That hides nothing that matters and adds state that must expire, be shared by every botd, and be cleaned up. A lost handle would also strand the person.
- **`returnIDParam=idp` back to `/start`.** That needs a marker on `/start` to stop a loop, and it can't take an unasked answer at the metadata's default endpoint, which comes back as `entityID`.
- **Ask passively first (`isPassive=true`), then actively.** That's two round trips to a third party on every sign-in. Services that remember the choice already make the second visit one click.
- **Embed the service's JavaScript on botd's chooser (SeamlessAccess's "persistence" service and button).** That adds a third-party script to botd's sign-in pages, against their no-script CSP. Linking out keeps the service on its own origin.
- **On an unknown pick, show the chooser instead of failing.** The pick came from the person, as a typed `idp` does. Failing with `unknown_idp`, audited, says plainly that this provider doesn't take that organization, rather than silently offering others.

## Consequences

- Federation members can use the discovery service they know, and their choice carries over from other services.
- Admins give the federation updated SP metadata (or enter the `/discovery` URL at its registry) once, when they turn it on.
- Sign-in reaches a third party before the IdP. If the service is down, people can't pick there. Removing the setting brings back botd's chooser with no other change.
- The chooser stays as the fallback, and as the default.
- `botctl offline-check` and the console's offline report list the service as a sign-in destination, so an air-gapped install learns that people must reach it.
