# 0268: SAML responses over the HTTP-Artifact binding

## Status

Accepted. The sixteenth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (native SAML SP) and [ADR 0208](0208-saml-back-channel-soap-logout.md) (SOAP). Setup guide: [native SAML](../sso/saml-native.md#responses-over-http-artifact).

## Context

botd took the IdP's answer to a sign-in one way only: the browser posts the signed response to the ACS (HTTP-POST). SAML's Web Browser SSO profile has a second way, HTTP-Artifact: the IdP sends the browser back with only an artifact, a 44-byte reference, and the SP fetches the response from the IdP's ArtifactResolutionService over SOAP. The assertion then never passes through the browser, where extensions, proxies or a stolen page could read it. Some government and higher-education IdPs (Shibboleth, mostly) require it, and full SP conformance needs it. AuthnRequests over Redirect and POST, and logout over Redirect, POST and SOAP, were done; this was the last Web SSO binding missing. The roadmap listed it, with federation metadata, as the optional work left on #52.

## Decision

A native SAML provider takes responses over one binding, set by `SSO_<ID>_RESPONSE_BINDING`: `post` (the default, as before) or `artifact`.

- **Asking for it.** With `artifact`, AuthnRequests set `ProtocolBinding` to HTTP-Artifact, and SP metadata lists one ACS, HTTP-Artifact, at the same URL. One, so an IdP can't fall back to posting.
- **The IdP's metadata** must list a SOAP `ArtifactResolutionService` on https (http only on loopback), each by its `index`; the first one for an index wins. Metadata without one is refused when the provider is set to `artifact` (the last good one stays), with a message that says what to change.
- **At the ACS.** `GET /api/auth/sso/{id}/acs` now takes `SAMLart` and `RelayState` (redirect), and the POST form takes `SAMLart` too. The RelayState, binder cookie and limiter checks come first, as for a post. A message with both `SAMLResponse` and `SAMLart`, or neither, is `missing_response`. One that came over the binding the provider doesn't take is `wrong_binding`, before anything is fetched.
- **The artifact** must be type 0x0004, 44 bytes, with the SourceID of the provider's IdP (SHA-1 of its entity ID, SAML Bindings 3.6.4), and name an endpoint index the metadata lists. Anything else is refused before botd sends anything: `bad_artifact`, `wrong_artifact_source`, `no_artifact_resolution`. Each artifact is sent at most once per provider (`replayed`).
- **Resolving.** botd sends a `samlp:ArtifactResolve` in a SOAP 1.1 envelope, signed with an enveloped signature by the SP signing key (as ADR 0208's LogoutRequest), to that endpoint, over the SSO HTTP client (10 seconds, no redirects, body read up to `MAX_RESPONSE`).
- **The ArtifactResponse** is checked like ADR 0208's SOAP answers. It must be:
  - the only element in the Body, with no `mustUnderstand` header;
  - unique IDs and no signature anywhere but on it or inside the Response (`wrapped`);
  - its signature valid when it has one (TLS carries it otherwise), and its Issuer the IdP when present;
  - `InResponseTo` our request (`artifact_mismatch`), and under five minutes old with the usual skew;
  - status Success with exactly one `samlp:Response` (Success with nothing is `artifact_unknown`; other statuses are `idp_error`, a SOAP fault `soap_fault`).
- **The Response inside** is taken out as a document of its own, with the namespaces it had in scope declared on its root, and goes through the same checks as a posted one (`check_response_xml`): the assertion signature, audience, recipient, InResponseTo, times, encryption. Exclusive C14N, the only kind botd verifies, renders namespaces where they are used, so signatures verify the same out of place.
- **Counting.** Refusals the browser can cause count against its address, and those before a signature is checked are logged sparingly, as before. `artifact_unreachable` and `artifact_http_error` (the IdP is down) don't count.
- **Audit.** `auth.login` carries `responseBinding` (`post` or `artifact`). `GET /api/sso/{id}/saml` and `botctl sso saml` show the setting and the IdP's artifact resolution URLs, and `botd offline check` (ADR 0257) lists them among the addresses botd reaches.

## Alternatives considered

- **Take both bindings.** Then a provider set to artifact for confidentiality would still take a response that went through the browser. Rejected: one binding per provider, as `REQUEST_BINDING=redirect|post` does for requests.
- **Pick the endpoint by order, ignoring the artifact's index.** Simpler with one endpoint, but the index is how the IdP says which one holds the message. Rejected: an index the metadata doesn't list is refused.
- **Require a signed ArtifactResponse.** SAML Bindings leaves it to TLS, most IdPs don't sign it, and the assertion inside is signed and checked anyway. Rejected: checked when signed, not required.
- **Mutual TLS to the ArtifactResolutionService instead of a signed request.** Few IdPs set it up, and it would need a client certificate in the HTTP client. The SP signing key already identifies botd, as for SOAP logout. Left for when an IdP asks.
- **Artifacts for logout messages.** No IdP in our users' list sends them. Left out.

## Consequences

- An IdP that wants HTTP-Artifact works with one setting and a metadata re-import on both sides, and the assertion never reaches the browser.
- A sign-in now waits on one extra request from botd to the IdP. An IdP that is down shows `artifact_unreachable` in the audit log instead of a failed post.
- Nothing changes for providers left on `post`, the default, the SAML bridge or OIDC.
- Still open on #52, only if a customer needs it: multi-IdP federation metadata (InCommon, eduGAIN): large signed aggregates or MDQ, and choosing an IdP among many.
