# 0014: OIDC single sign-on, starting with Microsoft Entra ID

## Status

Accepted. Second slice of M2 ([roadmap](../ROADMAP.md#m2--multi-user--sso), [#17](https://github.com/CG-Labs/superbot/issues/17)). Builds on the users and sessions of [ADR 0012](0012-users-sessions-rbac.md). Google ([#18](https://github.com/CG-Labs/superbot/issues/18)) and generic OIDC ([#19](https://github.com/CG-Labs/superbot/issues/19)) reuse this layer: see [ADR 0016](0016-sso-multi-provider.md) for their claim rules, several providers at once, and account linking.

## Context

People should sign in with the identity they already have. ADR 0012 gave botd users, roles, and revocable sessions, but the only ways in were an admin's one-time code and the owner's break-glass password. Entra ID comes first because it is what most of our target teams use. The work must not fork the user model, must leave break-glass alone, and must make the next IdPs mostly configuration.

## Decision

### One generic OIDC layer, with presets

`server/src/sso/` implements the OpenID Connect authorization code flow once. A provider is a `Kind` plus settings:

- **Entra** (`SSO_<ID>_TYPE=entra`, the default for id `entra`): issuer per tenant, `oid` as the subject (below).
- **Generic OIDC** (`type=oidc`): one issuer from `SSO_<ID>_ISSUER`, `sub` as the subject, email only when `email_verified` is true.

Google will be a preset of the generic kind. Providers are listed in `SSO_PROVIDERS` (`entra`, or several, comma separated), and everything else is `SSO_<ID>_*` env vars. There is no database or UI configuration: providers are rare, security-sensitive changes, and env keeps them reviewable and the same in Docker and the installer.

### The flow

1. `GET /api/auth/sso/{id}/start` makes a random `state`, `nonce`, and PKCE verifier (S256), remembers them in memory for 10 minutes keyed by the state's hash, and redirects to the IdP's authorization endpoint (`response_mode=query`, `prompt=select_account` for Entra).
2. The IdP sends the browser to `{SSO_PUBLIC_URL}/api/auth/sso/{id}/callback?code&state`. botd removes the pending sign-in (so a replayed callback finds nothing), exchanges the code with the verifier and client secret at the token endpoint, and checks the ID token.
3. The identity becomes a user (below), and botd calls ADR 0012's `start_session` with method `sso`. From here it is an ordinary session: same TTLs, revoke, roles.

All three endpoints are open (they are how you sign in) but Host-checked, and failures share the sign-in rate limit (10 per 10 minutes per IP).

**Web app**: `start` also sets a binder cookie (`superbot_sso`, HttpOnly, Secure, `SameSite=Lax`, path `/api/auth/sso`, 10 minutes) whose hash is stored with the state. The callback must carry it, so a sign-in can't be finished in someone else's browser (login CSRF). Lax is needed because the callback is a top-level navigation from the IdP. On success the callback sets the session cookie and returns a tiny page that moves to `/` itself: a 303 would keep the navigation cross-site, and the `SameSite=Strict` session cookie would not be sent. If the request reached botd on another host than `SSO_PUBLIC_URL`, `start` first redirects there, so both cookies live on the host the IdP returns to.

**Client app** (`?session=token`): the app makes its own PKCE pair and a state, and passes the challenge, state, and its redirect URL. The redirect must be listed in `SSO_APP_REDIRECTS` (default `superbot://auth` and the bundled web client's `{SSO_PUBLIC_URL}/app/auth`); http(s) redirects must be https or loopback. The callback sends a one-time code (`sbh_` + 256 bits, 2 minutes, held in memory, hashed) to that redirect, and the app trades it with its verifier at `POST /api/auth/login {sso, verifier}` for a bearer token. Another app that registered the same URL scheme could catch the code, but without the verifier it is useless; a wrong verifier spends the code. On redemption botd looks the identity up again, so one unlinked or disabled in the meantime gets no session. This is RFC 8252's pattern with botd as the authorization server.

Errors come back as one of a fixed set of codes (`sso_not_linked`, `sso_failed`, `sso_expired`, …) in `/login?error=` or the app redirect, never text from the IdP or the request.

### Token checks

Hand-written on `aws-lc-rs` rather than a JWT crate, because the checks are few and we want each one visible and tested:

- **Signature**: RS256 only. `alg` other than RS256, `none`, or a `crit` header is refused, so no algorithm confusion. The key is the JWKS entry with the token's `kid` (RSA, `use` absent or `sig`).
- **Keys and metadata**: discovery document cached 24 hours, JWKS 1 hour. A token with an unknown `kid` refetches the JWKS (at most once a minute), so IdP key rotation needs no restart. If the IdP is down, the cached copies keep working, and a failed fetch is retried at most once a minute rather than on every sign-in. All IdP URLs must be https (or loopback, for tests); responses are capped at 1 MB, redirects aren't followed, and requests time out after 10 seconds.
- **Claims**: `aud` contains our client id, and `azp` is ours when present or when there are several audiences; `exp` in the future and `iat`/`nbf` not in the future, with 5 minutes of clock skew; `nonce` equal to ours.
- **Issuer**: generic providers compare to the configured issuer and the discovery document's. Entra is below.

### Entra choices

- **Tenant-scoped issuer.** The token's `tid` must be the configured tenant (`SSO_ENTRA_TENANT=<tenant id>`), and `iss` must be exactly `{authority}/{tid}/v2.0`. Entra's multi-tenant metadata has a `{tenantid}` placeholder issuer, which libraries often accept for anyone; we don't.
- **Multi-tenant only with an allow-list.** `TENANT=organizations` or `common` is refused at startup unless `SSO_ENTRA_ALLOWED_TENANTS` lists the tenant ids to accept. `consumers` (personal accounts) is refused. A tenant id plus an allow-list is refused too, as unclear.
- **Subject is `oid` within `tid`.** The stored identity is `(issuer, oid)`, and the issuer names the tenant. `sub` is pairwise per app and `email`/`preferred_username` can be changed by a tenant admin or a user, so neither identifies a person.
- **Never matched by email.** A token's email never finds or merges an existing user (the "nOAuth" class of account takeover). It is saved on the identity for display only.
- `SSO_ENTRA_AUTHORITY` (default `https://login.microsoftonline.com`) exists for sovereign clouds and tests.

### Identities and provisioning

Migration 4 adds `user_identities (id, user_id, provider, issuer, subject, tenant, email, created_at, created_by, last_login_at)`, unique on `(issuer, subject)`, and copies any `users.idp_*` pair into it. The user's first identity is mirrored in `users.idp_issuer/idp_subject` (kept in step on link and unlink). Sessions record which identity signed them in (`sessions.idp_subject`), and the audit actor's subject comes from the session.

Two ways an identity gets a user:

- **Admin links it** (default): `POST /api/users/{user}/identities {provider, subject, tenant?}` or `botctl user link <user> entra <object-id>`. For Entra the subject is the user's object id; the tenant defaults to the configured one. `GET` lists, `DELETE .../identities/{id}` unlinks (sessions stay; revoke them separately). Admin only.
- **Just in time**, when `SSO_<ID>_JIT_ROLE` is `readonly`, `member`, or `admin` (default off): an unknown identity that passed every check becomes a new user with that role, its `name`, and its email if valid. If another user already has that email, sign-in is refused (`sso_email_taken`), and an admin links the identity instead.

A disabled user can't sign in with SSO either.

### Secrets

The client secret is `SSO_<ID>_CLIENT_SECRET`: from env, `_FILE`, or sealed in SQLite with `botctl secret set SSO_ENTRA_CLIENT_SECRET` ([ADR 0010](0010-secrets.md)), read when used so a rotation needs no restart. `SSO_*` names were already reserved from Bots; botd's secrets store now accepts exactly `SSO_<ID>_CLIENT_SECRET` as botd's own (`forBots: false` in `GET /api/secrets`), never adds it to a harness environment, and strips every `SSO_*` env var from harness and screen processes. The value is registered for redaction. A provider without its secret isn't offered.

### Audit

- `auth.login` with method `sso`, provider, issuer, subject, tenant, kind, label; the actor subject is `issuer|subject`.
- `auth.login_failed` with method `sso`, provider, and reason (`not_linked`, `wrong_tenant`, `wrong_issuer`, `wrong_audience`, `expired`, `nonce_mismatch`, `bad_signature`, `unknown_key`, `email_taken`, `user_disabled`, `binder_mismatch`, `unknown_state`, `idp_error`, …), plus issuer and subject once the token named someone. Failures anyone can cause by opening a callback URL are throttled like other failed sign-ins; failures after the IdP vouched are always recorded.
- `user.created` by `system:sso` for JIT, and `user.identity_linked` / `user.identity_unlinked` by the admin.

## Consequences

- Teams can sign in with Entra and admins can turn off break-glass once every admin can. Break-glass, sign-in codes, and Basic auth are unchanged.
- Pending sign-ins and app handoffs live in memory: a restart in the middle of a sign-in means trying again. With several botd instances (M3) they move to the shared store.
- Adding Google or a company IdP is configuration plus, at most, a small preset for its subject and email rules.
- `SSO_PUBLIC_URL` must be in `ALLOWED_HOSTS` (or be the server's own address) and match the redirect URI registered at the IdP exactly.

## Not in this slice

- Desktop (Electron) SSO: the app loads from `file://`, which no IdP can return to. It keeps codes and the password; a loopback redirect is the likely fix.
- Group or app-role to SuperBot role mapping, IdP logout, `prompt=login` re-authentication for sensitive actions, and certificate (`private_key_jwt`) client auth instead of a secret.
- A web or client UI for linking identities (API and `botctl` only).
- Apple, GitHub, SAML, SCIM. (Google and generic OIDC rules came next, in [ADR 0016](0016-sso-multi-provider.md); Apple and GitHub in [ADR 0018](0018-sso-github-apple.md).)
