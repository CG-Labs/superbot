# 0094: A second factor for code and password sign-in

## Status

Accepted (21 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes CC6.1-1 in the [readiness checklist](../security/soc2-readiness-checklist.md) and the MFA part of the CC6.1 gap in the [SOC 2 control mapping](../security/soc2-control-mapping.md).

Numbering: `main` has up to 0092, and open PR #153 takes 0093. Renumber this if a collision appears at merge.

## Context

botd signs people in three ways ([ADR 0012](0012-users-sessions-rbac.md)): single sign-on through an IdP ([ADR 0014](0014-oidc-sso-entra.md), [ADR 0016](0016-sso-multi-provider.md)), a one-time sign-in code an admin makes, and the owner's break-glass `AUTH_PASSWORD`, at `/login` or over HTTP Basic on any request. SSO can carry the IdP's MFA. The other two were one factor: whoever had the code or the password got an admin session, and the password never expires.

A SOC 2 auditor expects MFA on administrative access. Customers can enforce it at their IdP, but that never covers codes or the break-glass password, which is exactly the admin way in.

## Decision

**TOTP (RFC 6238) with one-time recovery codes, for code and password sign-ins.** SSO sign-ins are unchanged: they rely on the IdP's MFA, a complementary user entity control the IdP guides now state ([`docs/sso/`](../sso/)). TOTP needs no SMS provider or email delivery, works offline with any authenticator app, and fits in a few hundred lines of Rust on the HMAC botd already links ([`server/src/mfa.rs`](../../server/src/mfa.rs)). WebAuthn is stronger and can be added later behind the same challenge step.

- **Codes**: HMAC-SHA1, 30-second steps, 6 digits, the standard every app reads from an `otpauth://` link; one step of clock drift either way. Every candidate is compared in constant time. Each sign-in saves the step it used, and a code at or before it is refused, so a code works once.
- **Secrets**: 20 random bytes, sealed with the secrets master key under a per-user context (`user_mfa.secret/<user id>`, XChaCha20-Poly1305, [ADR 0010](0010-secrets.md)). Losing the key drops them with the other sealed values; a person the policy covers then sets theirs up again at their next sign-in.
- **Recovery codes**: ten per person, `xxxxx-xxxxx` (50 random bits each), shown once, stored as HMAC-SHA256 under a key derived from the master key, each usable once. New ones replace the old.
- **Policy**: `off` (default), `admins` (admins, which includes the owner) or `all`, set by an admin in the console, the app or `PUT /api/auth/mfa/policy`, and audited. `AUTH_MFA=off|admins|all` in `.env` fixes it, so the API can't change it. Anyone can turn theirs on whatever the policy; once on, every code or password sign-in asks for it.
- **Sign-in**: a good code or password from someone who needs the second factor gets 401 `{mfa: "totp", challenge}` instead of a session; the client sends `{challenge, totp | recoveryCode}` to the same endpoint. If the policy requires one and they have none, the reply is `{mfa: "enroll", challenge, secret, otpauthUrl, qrSvg}`: the new secret lives only in memory with the challenge until a code from it proves the app has it, then it is saved and the recovery codes come back with the session. A first factor and a code can also go in one request (`botctl login --totp`). Challenges are random 256-bit tokens (`sbm_`), held in memory for 5 minutes and 5 tries; a restart ends them.
- **HTTP Basic**: the password can't carry a code. Once the owner needs a second factor, Basic is refused (and audited as `auth.login_failed`, reason `mfa_required`), browsers go to `/login`, and `botctl` uses `botctl login --totp`. Sessions are unaffected.
- **Limits**: wrong second factors count against the per-IP sign-in limit (10 in 10 minutes) and a per-user limit of 5 in 15 minutes, so an attacker with the password can't try codes from many addresses. Each is audited with the person as actor, never the code: `auth.login_failed` at sign-in, `access.denied` on settings calls.
- **Management**: `GET /api/auth/mfa`, `POST /api/auth/mfa/{enroll,confirm,recovery-codes,disable}` for your own (people only, not Bots, any role), with a current code or recovery code to make new recovery codes or turn it off; turning it off is refused while the policy requires it. An admin resets someone else's with `DELETE /api/users/<id>/mfa` (not their own). Audit events: `user.mfa_enabled`, `user.mfa_disabled`, `user.mfa_recovery_codes_created`, `auth.mfa_policy_updated`; `auth.login` records `mfa: "totp" | "recovery_code"`, as does the session.

## Consequences

- With `AUTH_MFA=admins` or the policy set, every admin session from a code or the password passed a second factor, and the evidence is the audit log and the session's `mfa` field. CC6.1-1 is done; enforcing MFA at each IdP stays the customer's (CC6.1-2).
- HTTP Basic with `AUTH_PASSWORD` stops working for scripts once the owner has a second factor. They sign in with `botctl login --totp` and use the session token.
- A lost phone with no recovery codes needs another admin's reset. If the owner is the only admin, someone with a shell on the server deletes its row (`sqlite3 <DATA_DIR>/app.sqlite "DELETE FROM user_mfa WHERE user_id = 'operator'"`) and sets `AUTH_MFA=off` until it is set up again: whoever runs the server can always get in, as with the password today.
- Challenges and the per-user limit live in one botd's memory, like the sign-in limiter. Not covered: WebAuthn, remembering a device, and MFA for SSO sign-ins inside botd.
