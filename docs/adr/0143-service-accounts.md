# 0143: Service accounts

## Status

Accepted (22 Nov 2026). Third slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0123](0123-custom-roles.md) (custom roles) and [ADR 0132](0132-custom-roles-in-the-apps.md) (custom roles in the apps). Follows [ADR 0009](0009-audit-events.md) (the audit log) and [ADR 0012](0012-users-sessions-rbac.md) (users, sessions and roles).

## Context

Scripts and integrations (CI jobs, an HR sync, a reporting export) call the API today with a person's session token or the break-glass password. That ties them to someone who may leave, gives them everything that person can do, and puts the person's name on what the script did. Bot tokens (`sbb_`) are for one Bot's run and can't manage anything. Teams need a non-human caller that holds only the access it needs, can't sign in, and shows in the audit log as itself.

## Decision

### What a service account is

A **service account** is a `users` row with `kind = 'service'` and a `service_accounts` row beside it: name, description, **owner**, and optionally a **team**. It has no email, password, sign-in code, SSO identity, session or second factor, so it can't sign in. It holds a role like a person:

- across the server: `member`, `readonly` (the default), or a custom role (ADR 0123);
- or within one team: a custom role that applies only there (its team permissions, as for a person given the role with `--team`), on its base role across the server.

It can **never be an admin**. The API refuses it (400), and SQLite triggers refuse a service row with role `admin`, an email, or any change of `kind`, whatever writes it. Authentication checks a third time.

Service accounts aren't people. `GET /api/users`, `/api/users/{id}`, role assignment, team membership, Bot grants, seat counts and SCIM don't see them, so none of those routes can make one an admin or a teammate. A team's service account acts in its team as a plain member with its team role, without a `team_members` row or a seat. For Bot sharing it is one of its team: it reaches the team's shared Bots and no one else's, as a person in that team would. One across the server is in no team, like a person in none.

### Tokens

A service account acts only through **API tokens** (`sbsa_` and 64 hex characters):

- **Shown once.** The reply to create or rotate (201, `Cache-Control: no-store`) has the secret. The server keeps its SHA-256 hash and last four characters (`preview`), never the secret. The audit log never has it.
- **Scoped.** `scopes` is a list of permission names the account holds (`read`, `users.manage`, ...). Left out, the token has all the account holds. A token always has `account`, so it can call `GET /api/auth/me`. Unknown names and `admin` grant nothing.
- **Expiring.** Every token expires: `expiresInDays`, 1 to 365, default 90. There are no tokens that never expire.
- **Rotatable.** `POST .../tokens/{id}/rotate` makes a new token with the same name and scopes. The old one stops at once, or after `keepOldMinutes` (at most a day) so callers can switch over. A token rotates once; an expired or revoked one can't.
- **Revocable.** `DELETE .../tokens/{id}` stops it at once. Disabling the account stops all its tokens until it's enabled. Deleting it revokes them for good.

Each request reads the token, account and owner afresh, so revoking, disabling, or the owner losing access takes effect on the next request. A live event stream (`GET /api/events`) rechecks them every few seconds and closes once the token would be refused or may no longer read. Checks inside a route (such as the pending approvals in `GET /api/state`) use the same scoped permissions as the route itself, and a token's stream gets approval events only while it may `review`. Disabling or deleting an account also stops its live and queued runs and pauses its routines; a routine it wrote is refused at start once its owner is disabled or gone, or it may no longer `write` within what its owner holds now, as its tokens are. Disabling the owner stops the runs and queued messages their service accounts asked for, with their own. Use is noted (`lastUsedAt`, `lastUsedIp`) at most once a minute.

### Never more than the owner

The **owner** is whoever made the account. An admin can hand it to another active person. Two limits apply:

- **When it's made or changed**, its roles must fit within what the owner holds: their role and custom role across the server, plus their team permissions in its team (all of them for the team's owners and admins). Otherwise 403, logged as `access.denied` with `limit: "service_account_escalation"` and the `missing` permissions.
- **On every request**, the token gets its scopes, within the account's role, within what the owner holds **now**. An owner who is demoted, loses a custom role, or whose role is narrowed takes the account down with them. A disabled or erased owner lends nothing, and the token is refused (401). The account's views show `effective`, what its tokens can use today.

Admins manage every service account. Someone with `users.manage` (a delegate, ADR 0123) manages only those they own, and can't change the owner. A service account can't manage service accounts, so it can't mint itself new tokens.

Whatever its role, a service account can't use a person's routes: sign-in, sessions and second factor (but `GET /api/auth/me`), `/api/me/*`, a machine, billing, leaving a team, making Bots, screens, or deciding approvals. These are refused (403, `reason: "service_account"`). A delegate's limits from ADR 0123 still apply to what it does (it can't make an admin, for example).

### Audit

Requests by a service account are logged with the account as the actor: `actorKind: "user"`, `actorId` and `actorName` the account's, `actorRole` its role, `authMethod: "service_token"`, and `sessionId` the token's id. A refused token is logged as `auth.login_failed` with `method: "service_token"` and a `reason` (`unknown_token`, `revoked`, `expired`, `account_disabled`, `account_deleted`, `owner_inactive`), throttled like other failed sign-ins. A token outside its scope or its owner's permissions is `access.denied` with `reason: "token_scope"`.

Managing them is logged too: `service_account.created`, `.updated` (with each change), `.enabled`, `.disabled`, `.deleted`, and `service_token.created`, `.rotated`, `.revoked`. A deleted account's row is kept, disabled, so the log keeps naming it.

### API and botctl

| Route | |
|---|---|
| `GET /api/service-accounts` | Admins: all. Others with `users.manage`: their own. With the scope names and day limits |
| `POST /api/service-accounts` | `{name, description?, role?, team?}` |
| `GET` / `PATCH` / `DELETE /api/service-accounts/{id}` | `PATCH`: `{name?, description?, role?, team?, status?, owner?}` |
| `GET` / `POST /api/service-accounts/{id}/tokens` | `POST`: `{name?, scopes?, expiresInDays?}` |
| `POST /api/service-accounts/{id}/tokens/{token}/rotate` | `{expiresInDays?, keepOldMinutes?}` |
| `DELETE /api/service-accounts/{id}/tokens/{token}` | Revoke |

All need `users.manage`. `botctl service-accounts` and `botctl service-account show | add | edit | disable | enable | rm | token list | token add | token rotate | token revoke` call them. A token works with `botctl` as `SUPERBOT_TOKEN`.

## Alternatives considered

- **A separate principal beside users and Bots.** Every route, audit row and role check would need a third case. As a `users` row of another kind, the role checks, custom roles, delegate limits and audit actor work unchanged, and the people routes are kept away from it by one filter.
- **Team service accounts as `team_members` rows.** They would take a seat, show on the team's list and billing, and be reachable by team role changes. A synthetic member, read from the service account, gives the team routes what they need without that.
- **Capping only at creation.** A service account made by someone who is later demoted would keep their old access. Checking the owner on every request is one extra read and closes that.
- **Tokens that never expire.** They outlive the person who made them and are the usual leaked credential. Every token expires, at most in a year, and rotating is one command.
- **A new audit actor kind.** The audit table's `actor_kind` is fixed (`user`, `bot`, `system`). `authMethod: "service_token"` and the account's id tell service accounts apart without a migration of the log.

## Consequences

- Scripts and integrations get their own identity, with only the access they need, that a person leaving doesn't break and a person's demotion caps.
- Service accounts take no seats.
- A role held by a team's service account can't be deleted, as for people.
- Next slice: managing service accounts in the app and the console; letting a service account own Bots or be granted one; listing them in access reviews; and per-account refusal counts.
