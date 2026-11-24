# 0235: SAML AuthnRequests over HTTP-POST

## Status

Accepted. The thirteenth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (native SP), [ADR 0137](0137-saml-signed-requests-and-single-logout.md) (signed AuthnRequests) and [ADR 0225](0225-saml-session-lifetime-and-reauthentication.md) (asking again with `ForceAuthn`). Setup guide: [native SAML](../sso/saml-native.md#authnrequests-over-http-post).

## Context

botd sent AuthnRequests only over HTTP-Redirect, and refused IdP metadata without an HTTP-Redirect `SingleSignOnService` ("the metadata has no HTTP-Redirect SingleSignOnService"). Most IdPs list both bindings, but some list only HTTP-POST: some Shibboleth and PingFederate deployments, and government and eID IdPs that want signed requests carried in the message itself. Those customers couldn't use native SAML at all, and the roadmap lists AuthnRequests over HTTP-POST as the first optional extra still open on #52.

## Decision

One per-provider setting, native SAML only (refused on bridge and OIDC providers, like the other native settings): `SSO_<ID>_REQUEST_BINDING`, `auto` (default), `redirect` or `post`.

- **Picked when the metadata is loaded.** `auto` takes the HTTP-Redirect `SingleSignOnService` when the metadata has one, else the HTTP-POST one. `redirect` and `post` take only that binding, and metadata without it is refused at import, at startup and on each URL refresh, with a message naming the setting. The chosen URL must be https (or loopback http), as before. The metadata keeps the URL and binding together, so a sign-in always uses both from the same copy, even if a refresh lands mid-request.
- **Redirect first under `auto`.** Every provider that works today keeps sending exactly what it sent before. Only metadata that botd used to refuse now loads.
- **The POST binding page.** `start` (and the `ForceAuthn` retry from the ACS) answers with a small HTML page whose form posts `SAMLRequest` (base64, not DEFLATEd, per SAML Bindings 3.5.4) and `RelayState` to the IdP. A fixed inline script submits it on load; without script, a **Continue** button does. The binder cookie for web sign-ins, the app flow's state, the request ID and everything checked at the ACS are unchanged.
- **Locked down.** The page has its own Content-Security-Policy: `default-src 'none'`, the one script allowed by its SHA-256 hash, `form-action https:` (plus `http:` only for a loopback IdP), `base-uri 'none'` and `frame-ancestors 'none'`. It's `no-store` with `Referrer-Policy: no-referrer`, so the IdP never sees botd's start URL. Every value in it is escaped.
- **Signed inside the message.** HTTP-POST has no query signature, so with `SIGN_REQUESTS=true` the AuthnRequest carries an enveloped XML signature after its `Issuer`, as the schema places it. It's made by the same code that signs SOAP logout messages (ADR 0208): exclusive C14N, SHA-256, the SP signing key's algorithm (RSA-SHA256 or the configured ECDSA curve) and its certificate in `KeyInfo`. `ForceAuthn` and `RequestedAuthnContext` are inside the signature. Nothing changes in the SP metadata: `AuthnRequestsSigned` and the signing certificate already cover both bindings.
- **Evidence.** `GET /api/sso/:id/saml` has `requestBinding` and `idp.ssoBinding`, `sso.saml_metadata_imported` records `ssoBinding`, and `botctl sso saml <id>` shows "AuthnRequests over: HTTP-POST (REQUEST_BINDING=auto)".

## Alternatives considered

- **Prefer HTTP-POST under `auto`.** It avoids URL length limits and keeps the request out of IdP access logs, but it changes what every working deployment sends. Rejected; `post` is one setting away.
- **`form-action` limited to the IdP's origin.** Tighter, but browsers apply `form-action` to the redirects after the post too, and IdPs send the browser on to login pages on other hosts. Rejected; the target is fixed by the metadata and the page runs no other script, so https-only is the useful part.
- **No script, only a button.** Works everywhere, but adds a click to every sign-in. Rejected; the button stays for browsers without script.
- **Logout messages over HTTP-POST as well.** IdPs with only an HTTP-POST `SingleLogoutService` would get front-channel logout. But signing out answers the web client with a `logoutUrl` to open, which a POST can't be, so it needs a new endpoint and a client change. Out of scope here; SOAP logout (ADR 0208) already covers sign-out without a browser.

## Consequences

- IdPs that offer only HTTP-POST for sign-in now work with native SAML and no new setting. Nothing changes for IdPs that offer HTTP-Redirect.
- Admins who want signed requests inside the message, or long requests out of URLs, set `REQUEST_BINDING=post`.
- Still open on #52, only if a customer needs them: logout requests and responses over HTTP-POST to the IdP, the Artifact binding, and multi-IdP federation metadata (InCommon, eduGAIN).
