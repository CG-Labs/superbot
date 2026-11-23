# 0175: SAML IdP-initiated sign-in, restarted as SP-initiated

## Status

Accepted. The sixth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (the native SP), which refused IdP-initiated sign-in, and keeps its reason. Setup guide: [native SAML](../sso/saml-native.md#idp-initiated-sign-in-app-tiles).

## Context

Native SAML signs people in only when they start at SuperBot (SP-initiated). The ACS takes a response only if its `RelayState` names a sign-in this server holds, its `InResponseTo` is that sign-in's AuthnRequest ID, and the browser has the binder cookie that sign-in set. Everything else, including IdP-initiated posts, is refused as `unknown_state` ([ADR 0127](0127-native-saml-service-provider.md)).

Enterprises launch apps from their IdP's portal: the Okta dashboard, Microsoft My Apps, the OneLogin portal. For a SAML app, Okta's and OneLogin's tiles post an *unsolicited* response straight to the ACS (Entra's does too, unless a Sign on URL is set). Today that tile shows "That sign-in expired", which is the most common SAML support question we expect after a rollout. ADR 0127, 0137, 0151 and 0160 left IdP-initiated sign-in off "by design": an unsolicited assertion answers no request, so nothing ties it to the browser it arrives in.

Accepting it as a sign-in would bring back exactly what the request binding prevents:

- **Login CSRF.** An attacker who has an account at the IdP takes a valid unsolicited response for themselves and has a victim's browser post it (an auto-submitting form on any site). The victim is now signed in to SuperBot as the attacker, and whatever they type, upload or connect goes to the attacker's account.
- **Stolen or leaked assertions.** A bearer assertion that answers no request can be replayed from anywhere within its validity window; only the one-use check stands in the way.

## Decision

A per-provider policy, `SSO_<ID>_IDP_INITIATED`, `off` (the default) or `restart`. With `restart`, an unsolicited response never signs anyone in. It starts an SP-initiated sign-in instead:

1. A post to the ACS whose `RelayState` (if any) names no sign-in botd holds goes down a separate path. With `off`, or with no `SAMLResponse`, it's refused as before (`unknown_state`, "That sign-in expired").
2. The response is checked exactly as a solicited one: signature by a certificate in the IdP's metadata, the issuer, audience, recipient, destination, validity window, a non-transient NameID, encryption as the provider requires, and every structural check. The only difference is the request it answers: it must answer **none**. `InResponseTo` must be absent on the response and on the bearer confirmation (an empty value doesn't count as absent).
3. A response that answers *some* request (it carries `InResponseTo`) isn't unsolicited: it's a sign-in that expired, or another browser's. It's refused as `unknown_state`, as before.
4. Its assertion ID is spent, so it can't be posted again, and it can't be used for a sign-in later either.
5. botd audits `auth.saml_idp_initiated` (the IdP's issuer and subject, the assertion ID, `outcome` = `restarted`) and sends the browser (303) to `/api/auth/sso/<id>/start`, the same URL as the sign-in button. It sets a short-lived marker cookie naming the provider, `__Host-superbot_saml_restart` (2 minutes, `SameSite=None` because the IdP's post is cross-site, `HttpOnly`, `Secure`).
6. The start sends an AuthnRequest. The user already has an IdP session, so the IdP answers at once with a solicited response, which signs in whoever *this browser* is at the IdP. Every rule of a normal sign-in applies: binder cookie, `InResponseTo`, the allow-list, required groups, group roles, disabled users.
7. **Loops.** If an unsolicited response arrives while the marker names this provider, the IdP answered our AuthnRequest unsolicited again (it ignores AuthnRequests, or always posts to the ACS from the tile URL). Restarting again would go round forever, so it's refused as `idp_initiated_loop`. Any post to the ACS that doesn't restart clears the marker.

What the IdP posted is never used for the session: not its NameID, email, groups or `RelayState`. `RelayState` from an IdP-initiated post is ignored (people land where any sign-in lands), so it can't become an open redirect.

Failures on this path are audited as `auth.login_failed` with `idpInitiated: true` and the usual reason. Failures before the signature check are throttled per address as before, and every refusal after it counts against the address like a solicited one.

`botctl sso saml <id>` and `GET /api/sso/<id>/saml` (`idpInitiated`) show the setting. It's refused on the SAML bridge (Keycloak handles that path there) and on non-SAML providers.

### Why this is safe

Login CSRF needs the attacker's identity to end up in the victim's browser. Here, the attacker's response only makes the victim's browser *start* a sign-in. The identity of the session comes from the IdP's answer to an AuthnRequest bound to that browser's own binder cookie, which is the victim's own IdP session (or a password prompt). The worst an attacker can do with a forged or stolen post is make someone sign in as themselves, which the sign-in button already lets any page do with a link. Only a response the IdP really signed, for us, unused and in date, gets this far. Other posts are refused before any redirect, so the ACS is no general-purpose "start a sign-in" trigger for forged data.

## Alternatives considered

- **Accept unsolicited assertions as sign-ins**, as many SPs do. Login CSRF and replay within the validity window, as above. Refused.
- **Accept them, but bind the subject**: restart, then require the solicited answer to name the same NameID. That adds no safety, since the solicited answer is already bound to the browser, and it breaks the case where a shared computer's IdP session changed between the tile and the restart.
- **Redirect without checking the post.** Simpler, but then anyone could bounce people through sign-in with junk, the audit log would hold nothing useful, and a misdirected IdP (wrong audience or ACS) would look like it works until the restart. Checking first means a tile only works when the app is set up right.
- **Honour IdP `RelayState` as a deep link.** Okta and Entra let admins set a default RelayState. Taking it, even only for same-origin paths, needs its own validation and gains little: SuperBot's landing already sends admins to the console and everyone else to the app. Left out.
- **A marker in the start URL instead of a cookie** (`/start?restart=1`). The loop happens on the *next* post to the ACS, which arrives from the IdP with no trace of our URL, so the browser has to carry it. A cookie it is.
- **Document only the IdP-side fixes** (Entra's Sign on URL; an Okta bookmark app). The guide gives these, and they need no setting. But not every IdP has one, and admins often can't change how a portal launches apps. The setting covers the rest.

## Consequences

- IdP portal tiles work for SAML providers with `SSO_<ID>_IDP_INITIATED=restart`, at the cost of one extra round trip to the IdP. With Entra, a Sign on URL set to the start URL makes the tile SP-initiated without the setting. With Okta, a bookmark app does the same.
- An IdP that ignores AuthnRequests can't use tiles: people see "sign-in failed" and the audit log says `idp_initiated_loop`.
- One new audit action (`auth.saml_idp_initiated`), one new failure reason (`idp_initiated_loop`), one cookie, and one setting. No new tables or routes.
- `Expect.request_id` in the SAML checker is now optional: `None` means "answers no request", so there is one checker for both paths and no second set of rules to keep in step.
