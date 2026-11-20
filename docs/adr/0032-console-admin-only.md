# 0032: The console is a minimal admin page

## Status

Accepted (20 Nov 2026). Closes [#82](https://github.com/CG-Labs/superbot/issues/82) (M3). Follows [ADR 0027](0027-expo-primary-hermes-default.md), which made the Expo client the interface for everyone, and [ADR 0028](0028-client-admin-console-link-and-audit.md), which gave admins the audit log and a console link in the client.

0031 is taken by the machine enrollment and mTLS ADR in [PR #87](https://github.com/CG-Labs/superbot/pull/87), so this is 0032.

## Context

After ADR 0027 the console at `/console/` was admin-only, but it was still the old end-user page: chat, the Bot list, New Bot, Bot details and routines, the model picker, the live screen, approvals of Bot actions, and a live event stream. The client has all of that now, for admins too: the Users portal ([ADR 0021](0021-admin-portal.md)), sign-up approvals, and the audit log (ADR 0028). Keeping two chat UIs meant every chat fix had to be made twice or left out of one.

Meanwhile some admin tools had no web page at all: per-user machines from the control plane ([ADR 0025](0025-control-plane-linode.md)), server-wide secrets, and SCIM tokens were API and `botctl` only.

## Decision

The console is a minimal admin and break-glass page. It has five tabs:

| Tab | What it does | API |
|-----|--------------|-----|
| Users | Add people, change role, disable or enable, a one-time sign-in code with an invite link (replacing older unused codes), sign out everywhere, last sign-in and any code waiting | `/api/users*` |
| Requests | Sign-up requests ([ADR 0022](0022-landing-and-signups.md)): approve with a role and a code, or reject with a reason | `/api/signups*` |
| Machines | Every user's machine; give one, suspend, resume, resize, retry, destroy, reconcile now. Says the control plane is off when it is | `/api/machines*`, `/api/users/{id}/machine*` |
| Audit log | The same filters and CSV export as before | `/api/audit*` |
| Settings | Approval mode for all Bots, how people can sign in (break-glass, SSO providers), server secrets (names only), SCIM tokens | `/api/policy`, `/api/auth/sso`, `/api/secrets*`, `/api/scim/tokens*` |

Removed from the console: chat, Bots (list, create, details, delete, routines, models), Bot policy overrides, approvals of Bot actions, screens, and `/api/state` and `/api/events`. A note at the top and **Open the app ↗** in the header send admins to `/app/` for those. SSO account links and per-user Bot access stay in the client's Users portal, not duplicated here.

Unchanged:

- **Routing** ([ADR 0027](0027-expo-primary-hermes-default.md#routing)). Only admins (including break-glass) get `/console/`; members and read-only users get a 303 to `/app/`, signed-out visitors go to `/login`. If someone's role changes while the page is open, the page sends them to `/app/` on its next refused call.
- **The API.** No route was removed or changed; the client still uses all of them. RBAC in `rbac.rs` stays the boundary; the page only shows tools.
- `/login`, web SSO callbacks, `/healthz`, and `/app/` serving.

The page stays plain HTML, CSS and one script with no build step, per the repo's Rust-first rule. It now runs no inline script or style, so botd serves it with a strict Content-Security-Policy (`script-src 'self'`, `style-src 'self'`, `connect-src 'self'`, `frame-ancestors 'none'`), plus `nosniff` and `Referrer-Policy: same-origin`. The page shows sign-in codes and SCIM tokens, so it must not be framed.

### Tests

`server/src/interface_http_tests.rs`:

- The console has the admin tabs, a link to the app, the CSP, and no chat, Bot, screen, approval, or event-stream calls.
- Every `/api` call in `web/app.js` is routed for its method and refuses a member (except the caller's own `/api/auth/*` and reading the approval mode).
- Every `/api` call in `apps/client/src/api.ts` is still routed for its method, so slimming the console can't drop a route the client needs.

The last two read the scripts at build time and check each call against the live router, so they follow both files as they change.

## Consequences

- One chat UI. End-user features go only to the client.
- Admins can manage machines, server secrets, and SCIM tokens from a browser without `botctl`.
- Admins on an install without the web client (`--no-client`) lose browser chat; they use the desktop or mobile app, as members already did.

## Alternatives considered

- **Redirect the console to the client entirely.** Rejected: break-glass sign-in gives a cookie session, and the client needs a working web build at `/app/`; installs without one would have no admin page. The console also covers machines, secrets, and SCIM, which the client doesn't.
- **Move machines, secrets, and SCIM into the client too.** Possible later; the console needed a replacement for what it lost, and these are rare admin tasks that fit a plain page.
