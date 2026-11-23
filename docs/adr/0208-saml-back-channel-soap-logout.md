# 0208: SAML back-channel (SOAP) logout

## Status

Accepted. The tenth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (the native SP) and [ADR 0137](0137-saml-signed-requests-and-single-logout.md) (single logout over the browser), which left the SOAP binding out. Uses the encrypted NameIDs and ECDSA keys of [ADR 0151](0151-saml-encrypted-nameids-ecdsa-and-signed-metadata.md). Setup guide: [native SAML](../sso/saml-native.md#back-channel-soap-logout).

## Context

ADR 0137 did single logout over the browser only (HTTP-Redirect and HTTP-POST). That leaves two gaps:

- **Sessions with no browser.** The phone app and `botctl` sign in through the IdP too, but signing out of them ended only the SuperBot session, so the person stayed signed in at the IdP. There is no browser to send there.
- **IdPs that end sessions server to server.** Shibboleth, PingFederate and some ADFS setups send logout over the SAML SOAP binding, from their server to ours, so it works when the browser is gone or the SP's page is closed. Some IdPs offer only that. To them, SuperBot had no logout endpoint at all.

The SOAP binding (SAML 2.0 bindings, section 3.2) is a synchronous POST of a SOAP 1.1 envelope whose body is the SAML message, answered in the same HTTP response. Shibboleth IdP's documentation adds what matters in practice: it signs back-channel requests only when the SP's endpoint is on port 443 (it expects TLS client authentication otherwise), it assumes logout messages are signed, and older versions pick the first logout binding the SP's metadata lists.

## Decision

botd does SOAP logout both ways, with no new setting.

**From the IdP: `POST /api/auth/sso/{id}/slo/soap`.** The SP metadata lists a SOAP `SingleLogoutService` there, after the HTTP-Redirect and HTTP-POST ones, so an IdP that picks by order keeps using the browser as before. The body is read up to the same 256 KiB cap as the browser bindings and must be:

- a SOAP 1.1 envelope (`http://schemas.xmlsoap.org/soap/envelope/`), with an optional `Header` and a `Body` holding exactly one element, a LogoutRequest. SOAP 1.2 isn't in the SAML binding and is refused.
- free of headers marked `mustUnderstand="1"`: botd understands none, so it refuses them (`must_understand`, SOAP's `MustUnderstand` fault) as SOAP requires.
- signed: an enveloped XML signature on the LogoutRequest by a certificate in the IdP's metadata. The SOAP binding lets a peer authenticate with TLS client certificates instead, but botd sits behind a TLS proxy and never sees them, so a signature is the only proof. An unsigned request is refused as `unsigned`.
- addressed to the SOAP SLO URL. `Destination` is optional over SOAP, but ADR 0137 already requires it for logout, and Shibboleth and ADFS send it. Keeping the rule means one check for every binding.

Everything else is the browser path's: issuer, five-minute freshness, replay, wrapping and duplicate IDs, signatures only directly on the message, encrypted NameIDs, and which sessions are revoked. A request that passes revokes the sessions, audits `auth.slo` with `binding` = `soap`, and gets 200 `text/xml` with a LogoutResponse in an envelope. botd signs it with an enveloped signature, since the IdP checks SOAP answers that way, and gives it no `Destination`, because a SOAP answer has none. A refusal gets HTTP 500 with an unsigned SOAP fault (`soap11:Client`, or `soap11:MustUnderstand`) whose fault string is the reason, and is audited as `auth.slo_failed` with `binding` = `soap`. Refusals before the signature check are throttled per address like the browser's.

**To the IdP: signing out without a browser.** When a session an IdP vouched for is signed out (`POST /api/auth/logout`):

- a browser session whose IdP has a browser logout URL is sent there, as before;
- otherwise, if the IdP's metadata has a SOAP `SingleLogoutService` on https (http only on loopback, for tests), botd signs a LogoutRequest for that session's NameID and session index and POSTs it there itself, with `SOAPAction: http://www.oasis-open.org/committees/security`.

The sign-out answers at once. botd sends the request in the background, so a slow IdP never holds up signing out, and the SuperBot session is already revoked either way. The answer is read up to 256 KiB, redirects aren't followed, and it must be a SOAP envelope holding a LogoutResponse from the IdP's entity ID, in response to that request, and fresh. If it's signed, the signature must be the IdP's. An unsigned answer is accepted, because botd reached the IdP over https at the address its metadata names and the answer grants nothing: at worst, a forged one hides that the IdP session lives on. The result is audited as `auth.slo_response` against the session, a system event with `binding` = `soap`, `status`, and a `reason` when the IdP didn't confirm (`unreachable`, `http_error`, `soap_fault`, or a refusal reason for its answer). `auth.logout` records `sloBinding` (`redirect` or `soap`) next to the request ID in `slo`.

**Signing.** The SOAP binding can't carry the redirect binding's query-string signature, so botd now makes enveloped XML signatures: exclusive canonicalization, SHA-256 digests, RSA-SHA256 or the key's ECDSA algorithm, the signature right after `Issuer`, and the certificate in `KeyInfo`. botd checks its own output with the same narrow verifier it uses for the IdP.

**Shown where admins look.** `GET /api/sso/:id/saml` gives `sloSoapUrl`, `backChannelLogout` (botd can send logout to the IdP over SOAP) and the IdP's `idp.sloSoapUrl`. `botctl sso saml <id>` prints a **Back-channel logout** line ("from the IdP, and to it", or "from the IdP only") with the SOAP SLO URL, and the IdP's SOAP logout URL.

## Alternatives considered

- **A setting to turn SOAP logout on.** The endpoint takes only signed requests from the IdP the provider already trusts, and the outbound request goes only where that IdP's metadata says. Off by default would mean most servers never had it, for no security gain. Rejected.
- **Accept unsigned requests over TLS client certificates.** That's how the binding expects peers to authenticate, and Shibboleth's default off port 443. botd is deployed behind a proxy that ends TLS, and trusting a header from that proxy would make a forged header revoke anyone's sessions. Rejected: the guide says to use port 443 or have the IdP sign.
- **Drop the `Destination` requirement over SOAP.** The binding doesn't require it, but every IdP we looked at sends it, and keeping ADR 0137's rule keeps one checker for all bindings. Kept strict. It's easy to relax if an IdP turns up without it.
- **List SOAP first in the metadata.** It would make back-channel logout the default for IdPs that pick by order, but it would change how existing IdPs log out the moment SuperBot's metadata is refreshed. Rejected: it's last.
- **Wait for the IdP's answer before answering sign-out.** Clients give logout about five seconds, and an IdP that's down would make signing out look broken when the SuperBot session is already gone. Rejected for a background request with an audited answer.
- **Require the IdP's answer to be signed.** Shibboleth and ADFS don't always sign SOAP answers, relying on TLS, and nothing is granted by one. Rejected: accepted unsigned, but a signature must still be the IdP's.
- **Also send SOAP logout when an admin revokes a session or disables someone.** It's useful, but it changes the session and deprovisioning paths other work is changing now. Left for later.

## Consequences

- Signing out of the phone app or `botctl` now also ends the IdP session when the IdP supports SOAP logout, and IdPs that end sessions server to server can reach SuperBot.
- IdPs that only knew the browser bindings see one more `SingleLogoutService` in SuperBot's metadata, last, and change nothing.
- Shibboleth installations on a port other than 443 must set `signRequests` for SuperBot, or back-channel requests are refused as `unsigned`.
- A failed back-channel request leaves the IdP session alive, visible only in `auth.slo_response`. The SuperBot session is ended regardless.
- Admin revocation and deprovisioning don't send back-channel logout yet.
- Still to do for #52: Entra ID and ADFS encrypted assertions (AES-CBC, refused by design).
