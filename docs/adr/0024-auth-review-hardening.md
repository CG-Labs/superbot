# 0024: Auth hardening from the M2 review

## Status

Accepted. From the M2 auth pen-test review ([report](../security/auth-review-2026-11.md), [#25](https://github.com/CG-Labs/superbot/issues/25)). Changes parts of [ADR 0012](0012-users-sessions-rbac.md) (Basic rate limit, CSRF scope, cookie name), [ADR 0014](0014-oidc-sso-entra.md) (binder cookie), and how Entra email is read.

## Context

The review found no way to skip authentication or a role check on any route. It did find four places where the design trusted the browser or the IdP more than it should:

1. Only cookie sessions had the same-origin check on writes. A browser that cached the break-glass password, or any caller under `ALLOW_NO_AUTH`, could be made to write by another site with a form or a `text/plain` fetch, which needs no CORS preflight.
2. Basic auth on API routes was not rate-limited (ADR 0012 chose this so a shared NAT can't lock the owner out). That leaves unlimited guesses at the one password that is always admin.
3. Cookies were named `superbot_session` and `superbot_sso`. Any sibling subdomain (`*.example.com` on a shared parent) can set a cookie with that name for the parent domain, planting its own session or binder.
4. Entra's `email` claim is set by the account's tenant and isn't verified ("nOAuth"). Just-in-time sign-up saved it as the user's email. Admins act by email (grants, codes, ownership, audit filters), so an outsider could take a colleague's address.

## Decision

- **CSRF check on all ambient credentials.** Any request not carrying `Authorization: Bearer` (cookie, Basic, or nothing with `ALLOW_NO_AUTH`) must pass the same-origin check on anything beyond plain reads. Bearer tokens are only sent on purpose, so the client app may still run on another origin (Expo web). Tools that send no browser headers (`botctl`, `curl`) pass, as before.
- **Basic shares the sign-in limiter.** A wrong Basic password counts as a failed sign-in for that client IP. After 10 in 10 minutes, Basic from that IP gets 429 with `Retry-After`, even with the right password. Sessions are not affected, so people already signed in from that NAT keep working; `botctl` should use `SUPERBOT_TOKEN`. `ALLOW_NO_AUTH` skips the limiter (there is no password to guess).
- **`__Host-` cookies.** The session cookie is `__Host-superbot_session`; the SSO binder is `__Host-superbot_sso` with `Path=/` (the prefix requires it; still `SameSite=Lax`, 10 minutes). Browsers refuse `__Host-` cookies from any other host. Web sessions made before the upgrade sign in once more; the old cookie is ignored.
- **Entra email needs `xms_edov`.** The email counts only when the optional claim `xms_edov` is true (Microsoft: the user's tenant verified the email's domain). Otherwise the JIT user has no email until an admin adds one. The setup guide asks for the claim.
- **Small ones.** Revoking a user's sessions also drops their unredeemed SSO app codes and rotates screen links. Secret comparisons hash both sides first, so timing doesn't show a secret's length.

## Consequences

- Upgrading signs web console users out once.
- An attacker on the owner's NAT can block break-glass Basic for 10 minutes, but not sessions or SSO. Accepted: guessing the admin password had no limit at all.
- Entra tenants that skip the optional claim get JIT users without email; sign-in still works (identity is `tid` + `oid`).
- `tests::auth_review_http_tests` walks `router()` and fails if a new route is reachable without credentials or by a role that `rbac::classify` doesn't allow.
