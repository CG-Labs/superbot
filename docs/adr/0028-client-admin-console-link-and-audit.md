# 0028: Admin console link and audit log in the client

## Status

Accepted (19 Nov 2026). Follows [ADR 0027](0027-expo-primary-hermes-default.md), which made the Expo client the primary interface and the console an admin fallback. Closes [#80](https://github.com/CG-Labs/superbot/issues/80) (M2) and [#81](https://github.com/CG-Labs/superbot/issues/81) (M3). Builds on the audit log ([ADR 0009](0009-audit-events.md)) and its per-user actors ([ADR 0019](0019-audit-actors.md)).

## Context

After ADR 0027, admins use the client like everyone else but still need the console for a few things, and had no way to get there from the client. The audit log was only in the console.

The client usually signs in with a bearer token (ADR 0012). The console signs in with a browser cookie. The audit API (`GET /api/audit`, `GET /api/audit/export.csv`) already does everything the console's view does.

## Decisions

### Who sees it

Admins only, from `me.permissions` in `/api/state` (the server lists `admin` only for the admin role, the same rule as `landing()` in ADR 0027). The client hides the entries from everyone else. The server is the boundary: `rbac.rs` maps both audit routes to `Admin`, and the router walk test checks members, read-only users and Bots get 403 on them. No server change was needed.

### Console link

**Admin console ↗** in the sidebar opens `<server>/console/`:

- web build served at `/app/`: the same origin, in a new tab;
- phones: the system browser;
- desktop (Electron): a new window.

We don't hand the client's session to the browser. A bearer token can't become a cookie without a new token-to-cookie exchange, which would be a sign-in path of its own to secure and review. So on phones and desktop, the admin signs in once at `/login`. On the web build with a cookie session from `/login`, they are signed in already.

### Audit log

An **Audit log** screen (`/audit`) with the console's filters (action, who, person by email or id, sign-in method, date range) plus outcome, which the API already had. It pages with `nextBefore`, as the console does. Dates are whole days in the device's time zone, sent as unix ms. A bad date or a range that runs backwards shows an error and sends nothing.

### CSV export

The console exports with a plain link, which carries the cookie. A link can't carry a bearer token, so the client fetches the CSV with its own credentials, then saves it:

- **Web and Electron:** a Blob download, named as the server names it (`superbot-audit-<UTC time>.csv`).
- **Phones:** the file is written to the app's cache and opened in the share sheet (Save to Files, Mail, Drive, …). This adds `expo-file-system` and `expo-sharing`, which are Expo SDK modules in Expo Go, so no new native build is needed for development. Their config plugins aren't added: `expo-sharing`'s only sets up receiving shares, which we don't use. Where file sharing isn't available, the CSV goes to the system share sheet as text.

The export is the whole filtered log in memory, not streamed to disk. That is fine for admin-sized exports. `botctl audit export` stays the tool for very large ones.

## Consequences

- The client now has the console's audit view as well as its admin portal, which moves [#82](https://github.com/CG-Labs/superbot/issues/82) (retiring the console's end-user features) closer.
- Admins on phones sign in to the console in the browser once. A token-to-cookie handoff can come later if that hurts.
- Two Expo modules added to the client.
