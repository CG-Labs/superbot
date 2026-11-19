# 0012: Users, sessions, and RBAC v1

## Status

Accepted. First slice of M2 ([roadmap](../ROADMAP.md#m2--multi-user--sso)). OIDC providers sign people in to the users and sessions described here: Entra ID first, in [ADR 0014](0014-oidc-sso-entra.md), which also adds `user_identities`.

## Context

Until now botd had one shared `AUTH_PASSWORD`, sent as HTTP Basic on every request by the browser, the Expo client (which kept it in SecureStore), and `botctl`. Every person was the same "operator", with every permission. M2 needs real people with roles, sessions an admin can end, and a login that OIDC (Entra ID, Google, and others) can plug into, without breaking the live single-owner installs that rely on the password.

## Decision

### Users

`users` table (migration 3, `PRAGMA user_version`):

| Column | Meaning |
|--------|---------|
| `id` | `operator` for the owner; `u` + 8 hex for everyone else. |
| `email` | Unique, case-insensitive, optional (the owner may not have one yet). |
| `display_name` | Shown in the UI and the audit log. |
| `role` | `admin`, `member`, or `readonly` (CHECK). |
| `status` | `active` or `disabled` (CHECK). Disabled users can't sign in and lose their sessions. |
| `idp_issuer`, `idp_subject` | Empty until OIDC. Both set or both empty (CHECK); unique together. The audit `actor_subject` is `issuer\|subject`. |
| `created_at`, `updated_at` | Unix ms. |

Users are never deleted, only disabled, so audit rows keep pointing at someone. Account linking (several IdPs per user) will add a `user_identities` table in the OIDC PR; these two columns are then that user's first identity.

**The owner** is created on first start (and on the first start after upgrading): id `operator`, role admin, name from `USER_NAME`, email from `OWNER_EMAIL` if set. It keeps the id the audit log has used since [ADR 0009](0009-audit-events.md), so history before and after the upgrade is one actor. It can't be demoted or disabled through the API (409): it is the way back in. To turn it off, turn off break-glass.

### Sessions: opaque tokens in SQLite, not JWTs

`POST /api/auth/login` makes a session and returns `sbs_` + 256 random bits as hex. Only its SHA-256 is stored (`sessions.token_hash`), next to the user, kind (`cookie` or `token`), sign-in method, label, IP, user agent, created, last seen, expiry, and who revoked it and why.

- **Why not JWTs**: botd is one process with one database, so a lookup per request is cheap, and every request already needs the database. A server-side row can be revoked at once (logout, admin revoke, user disabled, role changed); a JWT stays valid until it expires unless we add a deny list, which is a session table again. Roles are read from the user row on every request, so a demotion applies to the next request, not the next token. JWTs would also add key management and algorithm pitfalls for no gain. When there are several servers (M3), they can share the session store or call the control plane.
- **Why SHA-256 and not bcrypt/argon2**: the tokens are 256-bit random, so there is nothing to guess; a slow hash only protects low-entropy secrets like passwords. A plain hash means a leaked database (or backup) holds no usable tokens, and lookup is by an index on the hash, so there is no timing leak from string comparison.
- **Prefixes** (`sbs_` sessions, `sbc_` sign-in codes) make leaked tokens easy to spot. The audit scrubber redacts both, and so does the redaction of saved chats, approvals, and live events ([ADR 0010](0010-secrets.md)), by shape, since only their hashes are kept.

**Two ways to carry the token**:

- **Web app (`web/`)**: `Set-Cookie: superbot_session=...; HttpOnly; Secure; SameSite=Strict; Path=/`. Scripts can't read it, it never goes over plain http (browsers allow `Secure` on `http://localhost`), and other sites can't make the browser send it. On top of SameSite (which still lets sibling subdomains through), every cookie-authenticated write, meaning any request that needs more than `read` or `review`, including `GET /api/bots/:id/screen` (it starts a screen), must come from our own origin (`Origin` equal to the Host, or `Sec-Fetch-Site: same-origin`), else 403, and the cookie sign-in itself checks the same. Requests with neither header aren't from a browser page.
- **Expo client and `botctl`**: `Authorization: Bearer sbs_...`. Not sent automatically, so no CSRF. The client keeps the token in SecureStore (browser storage on web) instead of the password. A password for a server from before sign-in stays in SecureStore on phones and is never written to browser storage.

**Lifetimes** (`.env`): `SESSION_IDLE_TIMEOUT` (default `7d`) since the last request, and `SESSION_MAX_AGE` (default `30d`) since sign-in, however active. Values like `30m`, `12h`, `7d`, from 5 minutes to 365 days. Both are checked on every request against the current settings, so shortening them applies to existing sessions. Last-seen is written at most once a minute. The SSE stream rechecks its session every few seconds and closes when it ends. Ended sessions and codes are deleted 30 days later.

**Ending a session**: `POST /api/auth/logout` (also clears the cookie); admins: `DELETE /api/sessions/:id`, or `DELETE /api/users/:id/sessions` for all of a user's sessions and unused codes. Disabling a user revokes their sessions too. All are audited.

### Signing in, before OIDC

- **Break-glass password**: `{password}` with `AUTH_PASSWORD` signs in as the owner. HTTP Basic with the password keeps working on every request, as before, so old clients, scripts, and `botctl` with `SUPERBOT_PASSWORD` don't break.
- **One-time sign-in codes**: an admin makes one for a user (`POST /api/users/:id/login-codes`, `botctl user code <email>`); the person enters it in the web app or client, which trades it for a session. Codes are `sbc_` + 256 bits, stored hashed, single use (spent atomically), expire (default 60 minutes, up to 7 days), and die with the user's sessions. This lets teams try multi-user now without botd storing per-user passwords. OIDC will replace codes as the normal way in; codes stay for bootstrap and recovery.

Failed sign-ins are rate-limited per client IP (10 per 10 minutes, then 429 with `Retry-After`). The IP is the last `X-Forwarded-For` entry behind a loopback proxy, which a client can't forge. Basic auth on API calls is not rate-limited, to avoid locking the owner out behind a shared NAT; it is the password's job to be strong (the installer generates it).

### Break-glass: `AUTH_BREAK_GLASS`

On by default (unset, `1`, `true`, `on`, `yes`), so an upgraded server keeps working with no config change. Set `AUTH_BREAK_GLASS=0` once admins sign in another way: `AUTH_PASSWORD` is then ignored everywhere (Basic and the login endpoint), botd starts without one, and no Basic challenge is sent. A Basic header the browser still has cached is skipped so the session cookie decides, and pages redirect to `/login`. Getting back in: set it to `1` and restart, which needs shell access to the server. That is the point of break-glass: whoever can edit `.env` already owns the box.

`ALLOW_NO_AUTH=1` (loopback dev) is unchanged: requests without credentials act as the owner.

### RBAC v1

Three roles. One function, `rbac::classify(method, path)`, maps each API route to the permission it needs; the auth middleware checks it before any handler runs and answers 403 (audited as `access.denied` with the role, route, and needed permission).

| Permission | Covers | admin | member | readonly | Bot token |
|------------|--------|:-----:|:------:|:--------:|:---------:|
| `account` | `/api/auth/me`, logout | ✓ | ✓ | ✓ | ✓ |
| `read` | state, events, Bots, messages, routines, models, policy (view) | ✓ | ✓ | ✓ | ✓ |
| `review` | approvals list | ✓ | ✓ | ✓ | |
| `write` | create/edit/delete Bots and routines, send messages, mark read, stop, screen, ask, handoff, approval check | ✓ | ✓ | | ✓ |
| `approve` | approve or deny a pending approval once (remembering it as a rule is a policy change: admin) | ✓ | ✓ | | |
| `admin` | policy and rules changes, audit log and export, users, sign-in codes, sessions, saved secrets ([ADR 0010](0010-secrets.md)) | ✓ | | | |

- **Default deny**: a route the table doesn't name needs `admin`. So does any path with an empty segment, a trailing slash, or unexpected case, so a path that dodges the table can't land on a weaker permission. New routes are admin-only until someone classifies them, and `rbac.rs`'s tests list every route with the permission it should need.
- **Readonly** can see everything a member sees but change nothing, including read markers and starting a Bot's screen.
- **Bots** keep exactly what they had: everything except approvals and admin. Handlers still call `need_user` for decisions as a second lock.
- **Members** decide approvals but can't change the policy or rules that decide which calls ask.
- Bot ACLs (private vs shared Bots) are not in this slice: every signed-in person sees every Bot. Added in [ADR 0017](0017-bot-acls.md).

### Audit events

New actions (ADR 0009 table, same scrubbing): `auth.login` (method `password`, `code`, or `none`; kind `cookie` or `token`), `auth.login_failed` (method and reason, never what was sent), `auth.logout`, `session.revoked`, `session.revoked_all`, `user.created`, `user.updated`, `user.role_changed`, `user.disabled`, `user.enabled`, `user.login_code_created`, and `access.denied` for people as well as Bots. The actor is the signed-in user (id, display name, IdP subject when there is one). The owner's first creation is logged by `system:bootstrap`.

### API

- `POST /api/auth/login` `{password | code, session?: "cookie" | "token", label?}` → `{user, session, token}` (token null for cookies). Open, but Host-checked. `Cache-Control: no-store`
- `POST /api/auth/logout`, `GET /api/auth/me` → `{user, role, permissions, method, session, breakGlass}`
- `GET|POST /api/users` `{email, name?, role?}`, `GET|PATCH /api/users/:id-or-email` `{name?, email?, role?, status?}`
- `POST /api/users/:id/login-codes` `{ttlMinutes?}` → `{code, expiresAt}` (the code is shown once)
- `GET /api/sessions?user=`, `DELETE /api/sessions/:id`, `DELETE /api/users/:id/sessions`
- `/api/state` `me` gains `id`, `email`, `role`, `permissions`, `session`.

`botctl login [<code>|-]`, `logout`, `whoami`, `users`, `user add|role|disable|enable|code`, `sessions`, `session revoke|revoke-all`. botctl prefers `SUPERBOT_TOKEN` (from `botctl login`) over `SUPERBOT_PASSWORD`, sends either only to loopback, and Bots never see either (removed from their environment).

## Consequences

- Upgrading changes nothing for existing users: the password works, the owner appears as an admin user, and the audit actor stays `operator`. The Expo client swaps a saved password for a session token on its next start; the web app gets a sign-in page instead of the browser's password box for new visits.
- A shared password is still possible and is still the weakest link while break-glass is on. Turning it off is a deliberate step once OIDC or codes cover every admin.
- Every request reads SQLite for the session and user. That is one indexed lookup; it can be cached later if it shows up in profiles.
- Unclassified routes are admin-only, which is safe but means new endpoints must be added to `rbac::classify` and its route list test, or members and Bots get 403.

## Not in this slice (next steps)

- **OIDC** (next PR): Entra ID and Google Workspace first, then Apple, GitHub, and generic OIDC. Login callback finds or creates the user by `(issuer, subject)`, maps email domain or groups to a role, and calls the same `start_session`. Refresh with the IdP is not needed for our own session; IdP logout and `prompt=login` are.
- **SAML** bridge, **SCIM** design stub, **bot ACLs** (owner, shared with users or groups), custom roles and service accounts (M5).
- Admin UI for users and sessions in the client and `web/` (the API and `botctl` cover it today).
- Per-user Bot tokens, so a Bot's actions can be tied to the person who started it.
