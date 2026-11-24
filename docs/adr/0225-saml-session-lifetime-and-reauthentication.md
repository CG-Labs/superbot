# 0225: SAML sign-in age, the IdP's session limit, and ForceAuthn

## Status

Accepted. The twelfth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (native SP), [ADR 0175](0175-saml-idp-initiated-sign-in-restarted.md) (restarted IdP-initiated sign-ins) and [ADR 0190](0190-saml-required-authn-context.md) (required authentication context). Setup guide: [native SAML](../sso/saml-native.md#sign-in-age-and-the-idps-session-limit).

## Context

A signed SAML assertion says two things about time that botd ignored until now:

- `AuthnInstant` on each `AuthnStatement`: when the IdP actually signed the person in. An IdP with a live session answers a new AuthnRequest from that session, so the instant can be hours or days old.
- `SessionNotOnOrAfter`: when the IdP's own session for the person ends. The Web Browser SSO profile (SAML 2.0 Profiles, 4.1.4.2) says the SP SHOULD end its security context then. botd gave every native SAML session the full `SESSION_MAX_AGE` (30 days by default), so someone whose IdP session the customer limited to 8 hours kept SuperBot for a month.

Customers ask for the OIDC `max_age` and `prompt=login` equivalents: "SuperBot needs a sign-in at the IdP from today", or "always ask for the password". SAML's tool for that is `ForceAuthn="true"` on the AuthnRequest. Without a check on `AuthnInstant`, though, `ForceAuthn` is only a request: an IdP that ignores it (Okta with **Honor Force Authentication** off, say) silently answers from its old session.

## Decision

Three per-provider settings, native SAML only (refused on bridge and OIDC providers, like the other native settings):

- `SSO_<ID>_IDP_SESSION_LIMIT`, `on` (default) or `off`. With `on`, a session made from an assertion with `SessionNotOnOrAfter` ends then, or at `SESSION_MAX_AGE` if that's sooner. Web sessions get the shorter cookie `Max-Age` too. App sign-ins carry the limit through the one-time code to the token session, and a code whose limit has passed can't be exchanged.
- `SSO_<ID>_FORCE_AUTHN`, `false` (default) or `true`. Every AuthnRequest carries `ForceAuthn="true"` (inside the signature, with signed requests), and the answer's `AuthnInstant` must be no earlier than when botd sent the request.
- `SSO_<ID>_MAX_AUTHN_AGE`, a duration from 5 minutes to 365 days, unset by default. An answer whose `AuthnInstant` is older than that is sent back to the IdP once, with `ForceAuthn`. Setting it with `FORCE_AUTHN` is refused at startup: one already implies the other.

How it is checked:

- **Protocol in the parser, policy at the ACS.** `check_response` reads `AuthnInstant` and `SessionNotOnOrAfter` only from the `AuthnStatement`s of the signed assertion, so moving or adding them after signing fails as `bad_signature`, and copies outside the assertion are never read. Malformed timestamps are `bad_response`. With several statements the latest instant and the earliest end count, which is the strictest reading. The policy runs in `finish_saml`, after the signature, replay, email, required groups and authentication context checks, and before the account is looked up. Just in time never makes an account from a stale sign-in.
- **Fresh means within the clock skew.** A sign-in is recent enough when `AuthnInstant + 2 minutes` is at or after the required time (the request time when `ForceAuthn` was asked, else now minus `MAX_AUTHN_AGE`), and isn't more than 2 minutes in the future. The skew is botd's existing `SKEW_MS` for every SAML time check. An assertion without `AuthnInstant` can't show it's recent, so it fails when a recent sign-in is required. Without either setting, the instant is only recorded.
- **An IdP session that has ended**, or ends within the skew, would make a session that is already over. That is treated like a stale sign-in.
- **One automatic retry.** A stale or ended answer to a request that didn't ask for `ForceAuthn` doesn't fail. botd records `auth.saml_reauthn` and sends the browser back to the IdP with a new AuthnRequest that does. The retry has a new request ID, a new RelayState and, for web sign-ins, a new binder cookie. The ACS keeps that cookie and the IdP-initiated restart marker instead of clearing them. App sign-ins keep their PKCE challenge and state, so the app's flow is unchanged. The first assertion is already spent by the replay check.
- **Then a clear refusal.** An answer to a `ForceAuthn` request that is still stale or ended is refused as `stale_authn` or `idp_session_ended` in `auth.login_failed`, with `authnInstant`, `authnSince`, `idpSessionEnds` and `forceAuthn`. It counts against the client's address. The person sees a new message, `sso_reauth_required`. botd never asks twice, so an IdP that ignores `ForceAuthn` can't loop.
- **IdP-initiated posts** (ADR 0175) aren't held to it, because they never sign anyone in. The sign-in they restart is.
- **Evidence.** `auth.login` gains `authnInstant`, `idpSessionEnds` (when it limited the session) and `forceAuthn` (when botd asked). `GET /api/sso/:id/saml` has `forceAuthn`, `maxAuthnAgeSeconds` and `idpSessionLimit`, and `botctl sso saml <id>` shows them. Support triage counts `auth.saml_reauthn` as SAML, and the new reasons point to the SAML runbook.

## Alternatives considered

- **Refuse stale answers without a retry.** Simpler, but every person whose IdP session is older than `MAX_AUTHN_AGE` would hit an error and have to sign out of the IdP by hand. Rejected: one `ForceAuthn` round trip is what the person expects.
- **Always send `ForceAuthn` when `MAX_AUTHN_AGE` is set.** Then everyone types a password on every sign-in, which is what `FORCE_AUTHN` is for. Rejected; asking only when needed keeps SSO single.
- **Keep ignoring `SessionNotOnOrAfter` by default (opt in).** The profile says SHOULD, and an IdP that sends it is stating the customer's policy. Rejected; the default is on, with `off` as the escape hatch for an IdP that sets it far too short.
- **Recheck the IdP's limit at every request.** The limit is fixed when the session is made, so storing it as the session's `expires_at` gives the same result with no new column and no new check. The existing session check already honours `expires_at`.
- **A per-provider session length.** A separate feature, and the IdP's own limit already covers the common case. Out of scope.
- **Treat a missing `AuthnInstant` as fresh.** The schema requires it, so an IdP that leaves it out is broken or tampered with. Rejected; it fails only when freshness is required.

## Consequences

- Sessions from IdPs that send `SessionNotOnOrAfter` now end with the IdP's session, from the next sign-in after upgrading. This is a behaviour change for those customers, noted in the changelog. Sessions people already have aren't changed. `IDP_SESSION_LIMIT=off` restores the old behaviour.
- Customers get a SAML equivalent of OIDC's `max_age`/`prompt=login` that is enforced, not just requested.
- An IdP that ignores `ForceAuthn` fails with `stale_authn` and a fix in the guide and runbook, instead of silently letting an old session through.
- Single logout is unchanged; a session ended by the IdP's limit simply expires like any other.
