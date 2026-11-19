# 0027: Expo client is the primary interface; Hermes Agent is the managed default

## Status

Accepted (19 Nov 2026). Decided by the product owner, David Kennedy, on 19 Nov 2026. Closes [#28](https://github.com/CG-Labs/superbot/issues/28). Accepts [ADR 0011](0011-hermes-agent-backend.md). Updates [ADR 0013](0013-serve-web-client.md) and [ADR 0022](0022-landing-and-signups.md) on where people land.

ADR 0025 (Linode control plane, [PR #77](https://github.com/CG-Labs/superbot/pull/77)) and ADR 0026 (SCIM review, [PR #78](https://github.com/CG-Labs/superbot/pull/78)) are taken by open PRs, so this is 0027.

## Context

SuperBot had two interfaces for the same people:

- the Expo client in `apps/client` (web at `/app/`, iOS, Android, Electron);
- the server-rendered console in `web/` (at `/console/`, with `/login`).

Both had chat, Bots, approvals and screens, so each feature was built twice or only once. The roadmap proposed making the client primary (decision 5), and asked the owner to accept ADR 0011 on Hermes Agent (decision 6) and to name the harness behind the Enterprise SLA (open question 3).

## Decisions (19 Nov 2026)

1. **The Expo client is the single primary interface for end users.** That is the web build at `/app/` and the native and desktop builds. The server-rendered pages stay only as an **admin fallback**: the console (admin portal, sign-up approvals, audit log), break-glass sign-in at `/login`, and `/healthz`.
2. **Hermes Agent is the default harness for managed tiers, and the harness that carries the Enterprise SLA.** ADR 0011 moves from proposed to accepted. Claude Code, Codex, Pi and other harnesses stay available as **best-effort**: supported in code and tests, not covered by the SLA.

Related, from the same day ([#29](https://github.com/CG-Labs/superbot/issues/29), ADR 0025 in [PR #77](https://github.com/CG-Labs/superbot/pull/77)): managed hosting is **one computer per user**, or **one container per user** on a virtualised server. Hermes's single-tenant design fits that ([ADR 0011](0011-hermes-agent-backend.md#b-hermes-as-the-primary-harness-and-default-engine)).

## How decision 1 is built

### Routing

| Path | Admin (incl. break-glass) | Member or read-only | Signed out |
|------|---------------------------|---------------------|------------|
| `/`, `/get-started`, `/site/*` | public site | public site | public site |
| `/login` | sign-in page | sign-in page | sign-in page |
| `/healthz` | open | open | open |
| `/console/*` | console | **303 to `/app/`** | 303 to `/login` |
| `/app/*` (Caddy serves the client) | client | client | client |
| `/app/*` reaching botd (no client installed) | 303 to `/console/` | 404 page: "web app isn't installed" | 303 to `/login` |

- botd decides by the caller's role (`landing()` in `server/src/main.rs`). Only `admin` gets the console.
- When no client is installed, botd answers `/app/` with a plain page instead of the console. Sending members to the console would loop (`/console/` sends them back to `/app/`). Such installs (`--no-client`, or no `--domain`) can use the desktop or mobile app.
- The API is unchanged. RBAC still decides what each role may do ([ADR 0012](0012-users-sessions-rbac.md)). The redirect is about which interface people see, not a security boundary.

### Landing after sign-in

- `GET /api/auth/me` returns `landing`: `/console/` for admins, `/app/` for everyone else.
- `/login` sends people there after a password or code sign-in, and when they are already signed in.
- A web SSO sign-in (the cookie flow started from `/login`) ends on a page that redirects by the same rule. The client's own SSO (PKCE, `session=token`) is unchanged; it already returns to `/app/auth` or `superbot://auth` ([ADR 0014](0014-oidc-sso-entra.md)).

### The client picks up a sign-in from `/login`

`/login` and the web SSO flow set the session cookie (`__Host-superbot_session`, `HttpOnly`, `SameSite=Strict`). The client normally signs in with a bearer token, so without more work a member would sign in twice.

- On the web build that the server hosts (same origin, not dev), with nothing saved, the client asks `GET /api/auth/me`. If the answer has a session, it uses the cookie: requests carry no `Authorization` header, and the browser sends the cookie.
- The cookie stays unreadable to scripts and is never written to storage. Signing out calls `/api/auth/logout`, which ends the session and clears the cookie.
- Writes on a cookie still need a same-origin request ([ADR 0024](0024-auth-review-hardening.md)). The client is same-origin, so this changes nothing on the server.
- A saved token still wins. Native, desktop and dev builds never look for a cookie.

### Closing small gaps in the client

The console had a few things for end users that the client lacked. These are now in the client:

- changing the harness a Bot runs on (Bot details, for those who manage the Bot);
- a confirmation before deleting a Bot;
- "From Ada" / "Reply from Ada" labels on Bot-to-Bot messages;
- Copy (Share on phones) on a Bot's messages.

Larger gaps are follow-ups, not blockers. They are admin features that stay in the console until then:

- **Audit log viewer in the client**, with filters and CSV export ([ADR 0009](0009-audit-events.md), [ADR 0019](0019-audit-actors.md)). M3, [#81](https://github.com/CG-Labs/superbot/issues/81).
- **Link from the client to the admin console** for admins on the web, and a client-side check of `landing`. M2, [#80](https://github.com/CG-Labs/superbot/issues/80).
- **Retire console end-user features** (chat, Bots, screens) once the client covers admins too, leaving a minimal admin page. M3, [#82](https://github.com/CG-Labs/superbot/issues/82).
- **"Suggested" prompts** in Bot details (create a routine, give it a job). Small; M3 polish, [#83](https://github.com/CG-Labs/superbot/issues/83).

## How decision 2 applies

- **Managed tiers (M3)**: new Bots run on Hermes Agent by default. The control plane sets `DEFAULT_HARNESS=hermes` and installs the pinned Hermes in each user's computer or container. Tier-to-model routing goes through Hermes's providers.
- **Self-host**: unchanged. Hermes stays opt-in in the installer and image (`--with-hermes`, [ADR 0015](0015-hermes-adapter.md)); `DEFAULT_HARNESS` keeps its current default.
- **Readiness**: the owner has decided *whether*. ADR 0011's gate items become the release checklist for managed tiers: the end-to-end approval test on the pinned stable version (including fail-closed on hook timeout and the unguarded-run canary), per-Bot memory and CPU measured on the smallest managed size, one upstream upgrade through the test suite, and tier routing with at least two providers.
- **Support matrix**: Hermes Agent, pinned stable release only, carries the Enterprise SLA. Claude Code, Codex, Pi and others are best-effort: bugs fixed as capacity allows, no response-time commitment.

## Consequences

- One interface to build features in. New end-user features go to the client only; the console gets admin features only.
- Members who bookmarked `/console/` land on `/app/`. Admins see no change.
- Installs without the web client lose the browser interface for members; admins keep the console.
- Hermes's upstream pace becomes an SLA risk we own. We pin stable tags and upgrade only through the test suite ([ADR 0011](0011-hermes-agent-backend.md#recommendation)).
- The roadmap's decisions 5 and 6 and open question 3 are closed.
