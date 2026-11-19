# 0026: SCIM hardening from the SCIM auth review

## Status

Accepted. From the SCIM addendum to the M2 auth review ([report](../security/auth-review-2026-11-scim.md)). Changes parts of [ADR 0023](0023-scim.md) (the bad-token limit, when SCIM writes a user's status, and what `scim.auth_failed` records). Follows [ADR 0024](0024-auth-review-hardening.md), which reviewed everything but SCIM.

## Context

The review found no way past the SCIM guard and no way to set a role or link an identity by email. It found two places where the design worked against deprovisioning:

1. After 20 bad tokens from an IP in 10 minutes, the guard refused every request from that IP, valid tokens included. Entra ID and Okta send provisioning traffic from addresses they share with all their customers. Anyone can point their own Entra or Okta app at a server's `/scim/v2` with a junk token and keep the real tenant's traffic blocked, so leavers stay in.
2. Every SCIM update wrote back the `active` it had read. An admin's disable that landed between a SCIM update's read and its write was silently undone.

It also found that a SCIM token sent to `/api`, or a revoked one still in use, was logged in a way that hid it.

## Decision

- **A valid token is never refused for its IP.** The guard looks the token up first. A live token goes on to the per-tenant limit (600 a minute). Only bad tokens count against, and are refused by, the per-IP limit (20 in 10 minutes, then 429). Tokens are 256 random bits, so the IP limit never protected against guessing; it keeps junk from filling the database and the audit log. Sessions were already exempt from the sign-in limiter for the same reason ([ADR 0024](0024-auth-review-hardening.md)). Only values shaped like a token (`sbp_` and 64 hex digits) are looked up.
- **SCIM writes the status only when it changes it.** If the request's `active` matches the user as read, the status column is left as it is when the write runs, and no `user.enabled` or `user.disabled` is recorded. The IdP still owns `active`: a request that sets it is applied, as before.
- **Failures say what they were.** `scim.auth_failed` has `reason` `missing`, `unknown`, or `revoked`; a revoked token is the event's target, with its tenant. A SCIM token sent to `/api` is `auth.login_failed` with method `scim_token`, reason `not_for_api`, actor `system` `scim`.

## Consequences

- An attacker can still fill the audit log's throttle for an IP and get 429s for their own junk; the real tenant's requests carry on.
- Requests with bad tokens cost one indexed lookup each, even from a blocked IP.
- Admins can find an IdP still using a revoked token (`botctl audit --action scim.auth_failed`), and spot a leaked SCIM token being tried on the API (`--method scim_token`).
- `auth_review_http_tests` now walks `/scim/v2` too: every SCIM route takes a live SCIM token and nothing else, no other route takes one, and with `SCIM=off` every SCIM route is a 404 that never reads the token.
