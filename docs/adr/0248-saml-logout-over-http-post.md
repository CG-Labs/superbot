# 0248: SAML logout over HTTP-POST

## Status

Accepted. The fourteenth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0137](0137-saml-signed-requests-and-single-logout.md) (single logout over the browser), [ADR 0208](0208-saml-back-channel-soap-logout.md) (enveloped signatures on logout messages) and [ADR 0235](0235-saml-authn-requests-over-http-post.md) (the page that posts a message to the IdP). Setup guide: [native SAML](../sso/saml-native.md#logout-over-http-post).

## Context

botd took logout messages from the IdP over HTTP-Redirect and HTTP-POST, but it sent its own only over HTTP-Redirect: our LogoutRequest when someone signs out, and our LogoutResponse to the IdP's LogoutRequest. It used an IdP's `SingleLogoutService` only when it was HTTP-Redirect. If an IdP listed only HTTP-POST (some Shibboleth, PingFederate and government IdPs), signing out of SuperBot left the IdP session alive. Its signed LogoutRequests were also refused (`no_slo`), because botd had nowhere to answer them. ADR 0235 left this out: signing out answers the client with a `logoutUrl` to open, and a POST can't be a URL. It was the first optional extra still open on #52.

## Decision

botd uses an IdP's HTTP-POST `SingleLogoutService` with no new setting.

- **Picked when the metadata is loaded.** The IdP's browser logout endpoint is the HTTP-Redirect one, else the HTTP-POST one, each only on https (http only on loopback, as before), with its `ResponseLocation`. Under `SSO_<ID>_REQUEST_BINDING=post` the order flips, so an admin who wants messages signed inside them gets that for logout too. Logout never makes metadata be refused: without either endpoint, sign-out stays local (or uses SOAP), as before. `GET /api/sso/:id/saml` shows `idp.sloBinding`, `sso.saml_metadata_imported` records it, and `botctl sso saml <id>` says `Single logout: yes, over HTTP-POST`.
- **Signing out: a one-time page on botd.** For a browser session whose IdP takes logout only over HTTP-POST, botd signs the LogoutRequest with an enveloped signature (after `Issuer`, the SP signing key, as ADR 0208). It keeps the request in memory under a random 128-bit handle and answers `POST /api/auth/logout` with `logoutUrl` = `<public URL>/api/auth/sso/<id>/logout?h=<handle>`. Opening it returns ADR 0235's page, which posts the request to the IdP: it loads nothing, runs only its hashed script, posts only to https, is `no-store` and sends no Referer. The handle is spent on the first try, even with the wrong provider in the path. It lasts five minutes, the request's own `NotOnOrAfter`. A spent, unknown or expired handle just goes to `/login`. The route is public, like the other SSO steps: the session has already been revoked when the link is made, and the handle is the only thing that opens it. The request ID is kept for the IdP's answer exactly as over HTTP-Redirect, and `auth.logout` records `sloBinding` = `post`.
- **Answering the IdP: over its own binding.** When the IdP's endpoint is HTTP-POST, botd answers the IdP's LogoutRequest with a page that posts the LogoutResponse to its `ResponseLocation`. The response has an enveloped signature, a `Destination` and the IdP's RelayState. This holds whichever binding the request came by. Its checks and the sessions it revokes are unchanged.
- **The IdP's answer to ours** already came in over either binding. `auth.slo_response` now records the binding it actually came by; before, it always said `redirect`.

## Alternatives considered

- **Return the form in the logout answer and change the clients.** The web console, the Expo web app and any other client would each need code to build and submit a form. Only http(s) links are followed today, which keeps an odd `logoutUrl` from doing anything. Rejected: a same-origin https link needs no client change.
- **Build the LogoutRequest when the page is opened.** That would mean keeping the session's NameID and session index under the handle until then, and signing for a session already gone. Rejected: the signed request is made at sign-out, as over HTTP-Redirect, and only waits for the browser.
- **Tie the page to the browser with a cookie.** The handle is unguessable, used once and short-lived. Anyone who has it can do no more than the HTTP-Redirect `logoutUrl` already lets them: end an IdP session that SuperBot has already ended. Sign-out clears the session cookie, so a binder would be one more cookie for no gain. Rejected.
- **A setting (`SSO_<ID>_LOGOUT_BINDING`).** Every IdP that works today keeps sending and receiving exactly what it did, and an IdP with only HTTP-POST now just works. Following `REQUEST_BINDING=post` covers admins who want signed-in-message logout. Rejected until someone needs logout and sign-in on different bindings.
- **Keep refusing the IdP's LogoutRequests when botd can't answer over HTTP-Redirect.** The IdP would show logout failing at SuperBot and the sessions would live on. Rejected.

## Consequences

- IdPs that list only HTTP-POST for logout now get single logout both ways, with no setting. Nothing changes for IdPs that list HTTP-Redirect, unless `REQUEST_BINDING=post`.
- A sign-out's link to the IdP is now sometimes a page on botd. Clients open it as before; it works once, within five minutes, and after a restart it is gone (the SuperBot session is ended regardless).
- Still open on #52, only if a customer needs them: the Artifact binding, multi-IdP federation metadata (InCommon, eduGAIN), and sending back-channel logout when an admin revokes a session or deprovisions someone (ADR 0208).
