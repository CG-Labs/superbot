# Auth review, November 2026 (M2)

A pen-test style review of authentication and authorization in `botd` and the Expo client, before M2 exit ([#25](https://github.com/CG-Labs/superbot/issues/25)). Design changes are in [ADR 0024](../adr/0024-auth-review-hardening.md).

**Result:** no Critical or High findings. Nothing let a caller skip sign-in or a role or Bot ACL check. Four Medium and two Low findings are fixed, each with a regression test; seven Low or informational items are accepted.

## Findings

| ID | Severity | Where | Finding | Status |
|----|----------|-------|---------|--------|
| AUTH-01 | Medium | `main.rs` `auth` | **CSRF on ambient credentials.** Only cookie sessions had the same-origin check. A browser holding a cached break-glass password, or any browser under `ALLOW_NO_AUTH`, could be made to write by another site: a form or `text/plain` fetch to routes that read raw bodies (`POST /api/users/{key}/login-codes`, `/api/approvals/{id}/approve`, `/api/signups/{id}/approve`, `/api/bots/{id}/stop`) or opening a screen. | **Fixed.** Every request without `Authorization: Bearer` needs the same-origin check beyond plain reads. Tests: `a_cached_break_glass_password_cannot_be_ridden_cross_site`, `allow_no_auth_writes_must_come_from_our_own_pages`. |
| AUTH-02 | Medium | `main.rs` `authenticate` | **Break-glass password guessing.** HTTP Basic on any API route was not rate-limited (ADR 0012), so the always-admin password could be guessed without limit. | **Fixed.** Basic failures count against the per-IP sign-in limiter; a blocked IP gets 429 even with the right password. Sessions are not blocked. Tests: `break_glass_password_guesses_on_any_route_are_rate_limited`, `failed_sign_ins_are_rate_limited_per_client_ip`. |
| AUTH-03 | Medium | `sso/provider.rs` (Entra) | **Unverified Entra email adopted (nOAuth).** Entra's `email` is whatever the account's tenant set. Just-in-time sign-up saved it as the user's email, and admins act by email (grants, codes, ownership, audit filters, the signup queue), so an account from an allowed tenant could pose as a colleague or block their address. | **Fixed.** The email counts only when `xms_edov` is true; setup guide updated. Tests: `entra_email_counts_only_when_its_domain_is_verified`, `an_entra_email_its_tenant_did_not_verify_is_not_taken`. |
| AUTH-04 | Medium | `users.rs`, `sso/mod.rs` | **Cookie tossing.** `superbot_session` and `superbot_sso` could be set by a sibling subdomain for the parent domain: session fixation (the victim works in the attacker's account) or a planted SSO binder. | **Fixed.** `__Host-superbot_session` and `__Host-superbot_sso` (`Path=/`). Tests: `cookies_and_origins`, the SSO cookie attribute checks. |
| AUTH-05 | Low | `users.rs` `revoke_user_sessions` | **Revoke left live grants.** "Sign out everywhere" ended sessions but an unredeemed SSO app code (2 minutes) could still become a session, and open screen links kept working. | **Fixed.** Revoking drops the user's app codes and rotates screen links. Test: `signing_out_everywhere_spends_app_codes_not_yet_redeemed`. |
| AUTH-06 | Low | `main.rs` `same` | **Length leak.** The constant-time compare returned early on a length mismatch, showing the break-glass password's and Bot token's length. | **Fixed.** Both sides are hashed before comparing. Test: `secrets_compare_without_showing_their_length`. |
| AUTH-07 | Low | `main.rs`, ADR 0017 | One Bot token is shared by every Bot run, and `X-SuperBot-Bot` is self-reported, so one Bot can act as another within the Bot role. | Accepted. By design until per-Bot tokens (ADR 0017); the Bot role can't approve, review, or administer. |
| AUTH-08 | Low | `signups.rs` | Signup emails are not verified, so anyone can ask for access as someone else's address. | Accepted. Signups do nothing until an admin approves, and the code goes to that address by hand. Revisit with the M3 mailer. |
| AUTH-09 | Low | `apps/client` (web) | On Expo web the session token sits in browser storage, readable by any XSS on that origin. | Accepted. Native apps use SecureStore; a browser has no script-proof storage for a bearer token. Sessions expire and admins can revoke them. |
| AUTH-10 | Low | `users.rs` `Limiter` | The limiter is per IP and in memory: many IPs, or a restart, get more guesses. | Accepted. Sessions, codes, and handoffs are 256-bit; the installer's password is long and random. |
| AUTH-11 | Info | `main.rs` `request_source` | Behind a CDN plus a proxy, `X-Forwarded-For`'s last entry is the CDN, so the limiter and audit see the CDN's IP. | Accepted. Documented deployments put one trusted proxy in front. |
| AUTH-12 | Info | `sso/mod.rs` | Pending SSO sign-ins are in memory, capped at 20 per IP and 10,000 total; many IPs can fill the cap and stall new sign-ins for 10 minutes. | Accepted. Break-glass and existing sessions are unaffected. |
| AUTH-13 | Info | ADR 0020 | With the SAML bridge, disabling someone at the SAML IdP doesn't end their Keycloak session; until it ends they can still start a botd sign-in. | Accepted. Short Keycloak sessions bound it ([SAML guide](../sso/saml.md)); disable the user in SuperBot too. |

## Method

Code review of every route in `router()` and the auth middleware, then attacks against the real router in tests (`*_http_tests.rs`, with mock Entra, OIDC, GitHub, Apple, and Keycloak IdPs).

Checked and holding:

- **Sessions:** 256-bit random tokens, stored as SHA-256; idle and absolute lifetimes checked on every request; logout, admin revoke, revoke-all, and disable end them at once (the live stream rechecks every 5 seconds); a new token on every sign-in, so no fixation from the server side; cookie `HttpOnly; Secure; SameSite=Strict`.
- **Codes and break-glass:** one-time codes are single use (atomic update), expire, are refused for disabled users, and are dropped on revoke-all; failed sign-ins are rate limited per IP; the right password is refused while blocked; `AUTH_BREAK_GLASS=0` ignores the password everywhere.
- **SSO:** state single use and bound to the browser (binder cookie) or to a PKCE challenge (app); PKCE S256 at the IdP; RS256 only, no `crit`; `aud`, `azp`, `exp`, `iat`, `nbf`, `nonce`; issuer per provider type; Entra `tid` and issuer match; Google `hd`; GitHub numeric id, verified primary email, org membership on GitHub's API; Apple form post; the SAML broker alias; app redirects only from `SSO_APP_REDIRECTS` (no open redirect); fixed error codes in redirects; identities never matched by email; JIT refuses an email that belongs to someone else.
- **RBAC and ACLs:** default deny (unclassified routes need admin; odd paths like `//`, `..`, `%75` fail closed); read-only callers can't write; members can't reach users, sessions, audit, secrets, policy, or signups; admins can't demote or disable the owner or themselves into lock-out; Bot ACLs on every Bot, chat, routine, screen, approval, and rule route and in `?bot=` filters, with 404 for Bots you can't see; screen links rotate when access narrows.
- **Router walk:** `auth_review_http_tests` reads `router()` and calls every route. Each one that isn't public must answer 401 to no credentials, a forged token, and a forged cookie, and 403 to every role `rbac::classify` doesn't allow. A new route can't ship open by mistake.

## Out of scope

- The computer daemon, voxl screen streaming internals, and harness sandboxes (ADR 0003, ADR 0008).
- Network and host hardening: TLS, proxy, firewall, Docker, the installer's systemd units.
- Third-party IdP configuration mistakes, and the IdPs themselves.
- SCIM (design stub, PR [#75](https://github.com/CG-Labs/superbot/pull/75)).
- Denial of service beyond the sign-in limiter.
- An external pen test, still planned before M3 GA.
