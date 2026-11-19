# 0017: Bot ACLs (shared and private Bots)

## Status

Accepted. M2 slice for [#20](https://github.com/CG-Labs/superbot/issues/20) ([roadmap](../ROADMAP.md#m2--multi-user--sso)). Builds on the users, sessions, and roles of [ADR 0012](0012-users-sessions-rbac.md).

## Context

ADR 0012 gave people roles, but every signed-in person saw and could run every Bot. A team needs Bots that belong to someone: a personal assistant with its owner's mail and repos shouldn't be readable, let alone runnable, by the whole org. Upgrading must not take anything away from the single-owner installs running today.

## Decision

### The model

Each Bot has an **owner** (a user) and a **visibility**: `shared` (the whole org) or `private` (owner, admins, and grants only). The owner can add per-user **grants**: `viewer` or `operator`.

Access to one Bot is one of four ordered levels. Each includes the ones below it.

| Access | Allows |
|--------|--------|
| `none` | Nothing. The Bot is left out of lists and the live stream, and its routes answer 404, the same as a Bot that doesn't exist. |
| `view` | Its chat, routines, per-Bot policy and rules, and approvals. |
| `operate` | Make it act: chat, stop, mark read, open its screen, routines (create, edit, pause, delete), answer its approvals and handoff cards, `ask` it. |
| `manage` | Its settings (name, model, harness, hidden), delete it, and who can see it (visibility, grants). |

`acl::access(user, role, owner, visibility, grant)` is the whole rule:

- **Admins** manage every Bot.
- **The owner** manages their Bot.
- **Shared** Bots: everyone else operates them.
- **Grants** add their level: `viewer` → view, `operator` → operate. The higher of shared and grant wins.
- **Read-only** users are capped at view, whatever they own or were granted.

Roles still apply first: the auth middleware checks the route's permission (`rbac::classify`) before any handler runs, so a read-only user's write is a 403 by role. Handlers then call `need_bot_access(bot, level)`. A Bot the caller can't see is a 404, so private Bots don't leak their existence; one they can see but not use is a 403. Both are audited as `access.denied` with reason `bot_acl`, the level needed, and the level held.

Why owner + visibility + grants, not groups or roles per Bot: it covers "mine", "the team's", and "share this one with Ana" with one table and one function, and every check reads two columns and at most one grant row. Groups (from SCIM or the IdP) can become another grant target later without changing the levels.

### What each endpoint needs

| Endpoint | Needs |
|----------|-------|
| `GET /api/state`, `GET /api/bots`, `GET /api/approvals` | Lists keep only Bots (and their approvals) with at least view. Each Bot carries the caller's `access`. |
| `GET /api/bots/:id/messages`, `/routines`, `/policy`, `/access`; `GET /api/policy/rules?bot=` | view |
| `POST /api/bots/:id/messages`, `/read`, `/stop`, `/routines`; `GET /api/bots/:id/screen`; `PATCH`/`DELETE /api/routines/:id` (on the routine's Bot) | operate |
| `POST /api/approvals/:id/approve` and `/deny` (on the approval's Bot) | operate, plus the `approve` permission |
| `POST /api/ask`, `/api/handoff`, `/api/approvals/check` from a person | operate on the asking Bot (and on the target, for `ask`) |
| `PATCH`/`DELETE /api/bots/:id`, `PATCH /api/bots/:id/access`, `PUT`/`DELETE /api/bots/:id/grants/:user` | manage |
| Changing the owner | admin role |
| Per-Bot policy changes, the audit log | admin role, as before (admins see every Bot) |

**The live stream** (`/api/events`) goes through a per-subscriber filter: events about a Bot the subscriber can't see are dropped, and Bot views get the subscriber's `access`. Access is cached per Bot and forgotten on `resync`, which every ACL change sends first, so the update that follows reaches exactly who can now see the Bot. A session's stream re-reads the user's role every few seconds (it already rechecked the session); when it changes, the cache resets and the client gets a `resync`.

### Bots act with their owner's access

A Bot's requests (shared bot token, `X-SuperBot-Bot` header from `botctl`) are checked as its owner: `botctl bots`, `ask`, and the "Other Bots" list in its system prompt only show Bots its owner can see, and `ask` only reaches Bots its owner can operate. A Bot made by a Bot belongs to that Bot's owner. Bot requests that don't name a Bot keep full access, as before.

This is a guardrail, not a boundary: every Bot holds the same token, so a Bot that lies about its id is not stopped. Per-Bot tokens (ADR 0012 next steps) will make it one.

### Data and migration

Migration 5: `bots.owner_id` (default `operator`) and `bots.visibility` (`private`/`shared`, CHECK, default `shared`), and `bot_grants (bot_id, user_id, level, created_at, created_by)` with one row per user and Bot, deleted with either (foreign keys, cascade). `owner_id` has no foreign key: the owner account is created after migrations run, and users are never deleted, only disabled.

Existing Bots go to the owner account (`operator`, the break-glass admin) and stay **shared**, so every person keeps the Bots they had and a single-owner install sees no change. The migration records one `bot.acl_initialized` audit event (actor `system:migration`) with the count. New Bots belong to whoever creates them and are shared unless the request says `"visibility": "private"`; changing the default is a one-line follow-up if teams want private-first.

### API and CLI

- `GET /api/bots/:id/access` → `{botId, owner: {id, name, email}, visibility, access, grants?}`. Grants only for callers who manage the Bot.
- `PATCH /api/bots/:id/access` `{visibility?, owner?}`. Owner is a user id or email; admins only; the user must be active. A grant the new owner had is dropped.
- `PUT /api/bots/:id/grants/:user` `{level: "viewer" | "operator"}`, `DELETE /api/bots/:id/grants/:user`. Granting the owner is a 409.
- `POST /api/bots` takes `visibility`. Bot views gain `owner: {id, name}`, `visibility`, and (per caller) `access`.
- `botctl bot access <bot>`, `bot share <bot>`, `bot private <bot>`, `bot owner <bot> <user>`, `bot grant <bot> <user> <viewer|operator>`, `bot revoke <bot> <user>`.

### Audit events

`bot.visibility_changed` `{from, to}`, `bot.owner_changed` `{from, to}`, `bot.access_granted` `{user, level, from}` (`from` is the earlier level, or null), `bot.access_revoked` `{user, level}`, `bot.acl_initialized` (migration). `bot.created` now records `owner` and `visibility`. Denials: `access.denied` with `reason: "bot_acl"`.

### Client

The Expo client shows each Bot's owner and whether it is shared or private in its details panel, with a "Shared with everyone" switch for its owner and admins. It hides what the caller's access would refuse: the composer, stop, screen, routine changes, and approval buttons need operate; renaming, hiding, the model bar, and delete need manage. A server from before ACLs sends no `access`; the client then falls back to the role, as before.

## Consequences

- Single-owner installs and teams that upgrade see no change until someone makes a Bot private.
- A member can no longer rename, re-model, or delete a shared Bot they don't own; they ask its owner or an admin. Running it is unchanged.
- Each Bot check is one indexed lookup (the grant); lists read the caller's grants once. The live stream adds one lookup per Bot per subscriber until the next resync.
- Approvals lists filter in the query (by the caller's visible Bot ids), so others' private Bots never crowd a member's page.
- The proxy sends screen traffic straight to voxl, so `botd` can't check access per connection. When someone may lose access (made private, a grant removed or cut to viewer, a new owner), the Bot's screen (every screen, when a user is demoted or disabled) gets a new token and its viewer restarts: earlier links and open views stop working, and everyone still allowed fetches a new link. The display and the Bot's apps keep running.
- `botDeleted` events still go to every subscriber; they carry only the id of a Bot that no longer exists.

## Not in this slice

- Group grants (IdP groups or SCIM), and a members-only default visibility.
- A grants editor in the client and `web/`; the API and `botctl` cover it. `web/` still shows every action and relies on the server's 403s.
- Per-Bot tokens, so a Bot's identity (and its owner's access) can't be claimed by another Bot.
