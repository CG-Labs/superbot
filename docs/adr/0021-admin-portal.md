# 0021: Admin portal for user onboarding

## Status

Accepted. An M2 slice ([roadmap](../ROADMAP.md#m2--multi-user--sso)): a place for admins to add people, hand them a sign-in code, and manage their access without `botctl`. Builds on users, sessions, and roles ([ADR 0012](0012-users-sessions-rbac.md)), the web client at `/app/` ([ADR 0013](0013-serve-web-client.md)), SSO identities ([ADR 0014](0014-oidc-sso-entra.md), [ADR 0016](0016-sso-multi-provider.md)), Bot ACLs ([ADR 0017](0017-bot-acls.md)), and per-user audit actors ([ADR 0019](0019-audit-actors.md)).

## Context

Onboarding someone today means `botctl user add`, `botctl user code`, and pasting the code into a chat with the server URL typed out by hand. Admins want to see who is on the server, how they last signed in, whether a code is still waiting, and what each person can reach, in the app they already use.

The API already covers most of it (ADR 0012). What's missing:

- **When and how a user last signed in.** Sessions are pruned 30 days after they end, so they can't answer it for long.
- **What a user can reach.** Bot access is computed per request (ADR 0017); there's no way to ask "what can Alex see?".
- **Replacing a code.** Making a new code left the old one working.
- **One list call.** The list didn't carry identities or waiting codes, so a portal would call once per user.

## Decision

### Where

A **Users** screen in the Expo client (`apps/client`, served at `/app/`), opened from the sidebar for admins. It is wide (list and detail side by side) on desktop browsers and stacked on phones. The legacy `web/` admin page keeps `botctl`-level parity only; adding the portal there too would duplicate the UI for little gain, so it is deferred.

Access is enforced by the server, not by hiding the button: every `/api/users*` and `/api/sessions*` route is admin-only in `rbac.rs`, and tests check that members, read-only users, and the Bot token get 403.

### API

Existing routes stay; additions are small and backward compatible:

| Change | Why |
|--------|-----|
| `users.last_login_at`, `last_login_method`, `last_login_idp_provider` (migration 8, after ADR 0022's `signups`), set when any session starts, backfilled from the newest kept session | Last sign-in survives session pruning. Method and provider use ADR 0019's terms. |
| Users carry `lastLoginAt` and, in the admin list and `GET /api/users/:id`, `lastLogin: {at, authMethod, idpProvider, idp}`, `identities: [{id, provider, idp, subject, email, createdAt, lastLoginAt}]`, and `pendingCodes: {count, expiresAt} \| null` | One call fills the list. Never a code or its hash. |
| `GET /api/users/:id-or-email/bots` → `{user, active, bots: [{bot, owner, visibility, access, grant}]}` | What ADR 0017 grants this user now, computed with the same rules as their own requests (admins see every Bot). |
| `POST /api/users/:id/login-codes` takes `replace: true` to drop the user's unused codes first; the response is `Cache-Control: no-store` | "Regenerate" really revokes the old code, and no cache keeps the new one. |
| `PATCH /api/users/:id` refuses an admin's own demotion or disabling (409) | An admin can't lock themselves out by mistake. Another admin can still do it. The owner rule stays. |

Every change is audited with the existing `user.*` actions (`user.created`, `user.updated`, `user.role_changed`, `user.disabled`, `user.enabled`, `user.login_code_created` with `{ttlMinutes, replaced?}`, `user.identity_linked`, `user.identity_unlinked`, `session.revoked`, `session.revoked_all`), and ADR 0019 puts the admin's role, sign-in method, IdP, and session on each.

### Sign-in codes

The admin picks 1 hour, 24 hours, or 7 days when adding someone or later. The code is shown once, with **Copy code**, **Copy link**, and **Copy invite**: a short message with the app URL, the server URL, the code, and when it expires. On native, copy opens the share sheet (no new native dependency). Closing the panel forgets the code; the server only has its hash, so it can't be shown again. The list shows "Code waiting" until it's used or expires.

### Invite link

`https://<server>/app/#code=sbc_…` opens the sign-in page with the server URL and code filled in. The person checks the server and presses **Connect**.

Why this is safe enough to ship:

- **Not sent anywhere.** Browsers don't send the fragment to servers or put it in `Referer`, so it never reaches Caddy's or botd's logs.
- **Removed on arrival.** The client reads it once, then replaces the address bar and history entry without it (`history.replaceState`, and Expo Router's `#` param), so it isn't left in history, bookmarks, or a screenshot of the URL bar. Back doesn't return to it.
- **Nothing is spent by opening it.** The link only fills a form. Mail and chat link scanners that fetch or open it don't use the code up; only pressing Connect does.
- **Same exposure as the code.** Anyone with the message already has the code; the link adds nothing an attacker could use that the code alone wouldn't give. Codes stay single use, short lived, and hashed.

## Consequences

- Admins can onboard a person from the app in one step and see whether they have signed in, how, and what they can reach.
- One extra list query per page load for identities and waiting codes; fine at team sizes.
- Old databases get last sign-ins from sessions still kept; users whose sessions were pruned show "Never" until they sign in again.
- Deferred: the portal in legacy `web/`, an audit view in the Expo client (each user's recent sign-ins from `/api/audit`), bulk invites, and email delivery of invites.

## Alternatives considered

- **Invite link with the code in the query string.** Rejected: it lands in proxy and server access logs and in `Referer`.
- **Link that signs in on open.** Rejected: link scanners would spend the code before the person clicks.
- **Derive last sign-in from sessions or the audit log on each request.** Sessions are pruned and audit retention is configurable, so the answer would drift; a column is one write per sign-in.
- **Let a regenerated code coexist with the old one.** Simpler, but "regenerate" after a code leaked would leave the leaked one working.
