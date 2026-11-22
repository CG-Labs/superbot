# 0123: Custom roles from fixed, fine-grained permissions

## Status

Accepted (22 Nov 2026). First slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"). Builds on [ADR 0012](0012-users-sessions-rbac.md) (users, sessions and RBAC v1), [ADR 0017](0017-bot-acls.md) (Bot ACLs) and [ADR 0087](0087-team-accounts-and-machines.md) (team accounts). SCIM is unchanged ([ADR 0023](0023-scim.md), [ADR 0095](0095-scim-groups-as-teams.md)).

0119 to 0122 are taken by open pull requests; this is the next free number.

## Context

RBAC v1 has three built-in roles: **admin** (everything), **member** (use Bots, decide approvals) and **read-only** (see, change nothing). Each API route needs one coarse permission (`account`, `read`, `review`, `write`, `approve`, `admin`), and `rbac::classify` gives every route it doesn't name to `admin`.

So everything an organisation delegates is all of admin or nothing. A helpdesk that resets sign-ins, an auditor who reads the log, a finance person who watches usage, or a site lead who restarts machines each needs the admin role, which also opens secrets, policy, SSO, SCIM, backups, the license and every Bot. Enterprise buyers ask for least privilege here first.

Teams (ADR 0087) have their own roles (owner, admin, member), and only team owners and admins manage the team. A team can't hand one person invites, or machines, without the rest.

## Decision

### Permissions

The permission set is fixed in the code (`rbac::PERMS`): the six coarse ones above plus six that an admin can give away (`rbac::DELEGABLE`):

| Permission | Opens | In a team |
|--|--|--|
| `users.manage` | `GET`/`POST /api/users`, `GET`/`PATCH /api/users/:id`, sign-in codes, signing people out, `GET /api/sessions`, `DELETE /api/sessions/:id` | Invite and withdraw member invites, remove plain members, preview their offboarding |
| `bots.manage` | A user's Bots and routines lists, resuming their routines, `POST /api/tiers/:name/move-bots` | No |
| `audit.view` | `GET /api/audit`, its CSV, `GET /api/access-review`, its CSV | No |
| `billing.manage` | `GET /api/usage`, `GET /api/tiers`, a user's usage; with `users.manage`, a user's tier | The team's plan and billing |
| `signups.approve` | `GET /api/signups`, a sign-up, approve, reject | No |
| `machines.manage` | Machine lifecycle: a user's machine (make, destroy), suspend, resume, enrollment, harness install, resize, rebuild, backups, restore, certificates, the machine agent, placement, region, and the fleet views (`/api/machines/*` reads, reconcile, host drain and recover, `/api/regions`) | Give a member a machine, step it |

A route a delegable permission opens is named exactly, by method and path shape, in `rbac::classify`. Anything else, including paths with odd shapes, still needs `admin`. What stays with admins, deliberately: machine screens, harness logins, folder sync, teammates on a machine, a machine's Bot user, deleting a destroyed machine's backups, linked identities, second-factor resets, erasure, Bot handover, secrets, policy, SSO, SCIM, retention, server backups, the license, setup, status incidents, signing off an access review, and custom roles themselves.

The built-in roles are presets of the same permissions, and behave exactly as before:

| Role | Permissions |
|--|--|
| admin | all twelve |
| member | `account`, `read`, `review`, `write`, `approve` |
| read-only | `account`, `read`, `review` |

`GET /api/auth/me` and `/api/state` list the caller's effective permissions. An admin's list now has the six new names; clients check for `admin`, so nothing changes for them.

### Custom roles

A custom role is a **base** (`member` or `readonly`, never `admin`) plus any of the delegable permissions. Its holder can do what the base does, and what its permissions open. A role can't be based on admin, and `admin` or a coarse permission can't be one of its permissions, so a role never adds up to admin.

- **Across the server**: `users.role_id` points at the role, and `users.role` is kept equal to its base. Every check that reads the built-in role (Bot ACLs, approvals, notifications, MFA policy, SCIM, the access review) keeps working as before, unchanged. Giving someone a role sets their built-in role to its base, so an admin given a role is an admin no longer.
- **Within a team**: `team_members.role_id` points at the role. Only its team permissions (`users.manage`, `billing.manage`, `machines.manage`) apply, only in that team, and only while they stay on it: the row goes when they leave. It never changes their role across the server, nor opens server-wide routes. Changing team roles (owner, admin, member) stays with team owners and admins. Team actions still need write access, as they do for team owners and admins, so a read-only person can't be given a team role (409), and one they hold does nothing while they're read-only: read-only people change nothing, anywhere.

**Deny by default.** A role is saved only with names from the fixed list (400 otherwise, naming the allowed ones). A name the server doesn't know in a stored role, as a newer version or a hand edit might leave, grants nothing: `GET /api/roles/:id` lists it as `unknown`. A custom role's name can't be a built-in one's (`admin`, `member`, `readonly`, `read-only`, `owner`, `bot`, `none`).

### Limits on delegates

Someone with a delegable permission but not the admin role (a delegate) may not:

- change, sign in as (a sign-in code), or sign out an admin, the owner account, or anyone with a custom role across the server, including other delegates and themselves;
- make anyone an admin, by creating them, changing them, or approving their sign-up;
- change a tier without `billing.manage`;
- in a team: invite as owner or admin, withdraw or replace such an invite (inviting the same email again replaces it), or remove an owner, an admin, or anyone with a team role; nor, though a plain member of the team, a server admin, the owner account, or anyone with a custom role across the server (ADR 0138).

Each refusal is a 403 and an `access.denied` event with `reason: "delegate_limit"` and the limit (`protected_user`, `admin_role`, `tier`, `team_role`).

So `users.manage` is real power over everyone else: a delegate can give a plain member a sign-in code, and so act as them. That is what the permission is for (a helpdesk), and every code is audited (`user.login_code_created`).

### Admin API

Admin only (`/api/roles` is never delegable). Every change is audited.

- `GET /api/roles` → `{permissions: [{name, description, team}], builtIn: [{id, name, permissions}], roles: [role]}`
- `POST /api/roles` `{name, description?, base?: "member" | "readonly", permissions: [name]}` → 201 role (`role.created`). 409 for a name in use (names ignore case).
- `GET /api/roles/:id-or-name` → role, with `holders: {users, teams}`
- `PATCH /api/roles/:id` `{name?, description?, base?, permissions?}` → role (`role.updated` with `changes` and `usersMoved`). A new base applies at once, in one transaction, to everyone who holds the role across the server; each is a `user.role_changed` (`reason: "role_updated"`) and is handled as any other change of role (screen links change, offboarding from teammates' machines).
- `DELETE /api/roles/:id` (`role.deleted`). 409 while anyone holds it; the foreign keys refuse it too.
- `PUT|DELETE /api/roles/:id/users/:id-or-email`: give or take away across the server (`role.assigned` and `role.unassigned`, `scope: "org"`; `user.role_changed` when the built-in role changes). 409 for the owner account, which stays an admin, and for yourself. Taking a role away leaves its base as their built-in role. Setting a built-in role with `PATCH /api/users/:id` takes the custom role away too (`role.unassigned`, `reason: "role_set"`).
- `PUT|DELETE /api/roles/:id/teams/:team/users/:id-or-email`: give or take away within a team (`scope: "team"`, with the team and the permissions that apply there). 404 when they're not on that team.

A role is `{id, name, description, base, builtIn: false, permissions, unknown, effective, users, teamMembers, createdAt, createdBy, updatedAt}`.

Users carry `roleId` and, in admin views, `customRole: {id, name}`; `GET /api/auth/me` has `customRole`; `GET /api/team` has the caller's `customRole` and `permissions` in the team, and each member's `customRole`. The access review shows each person's custom role and team role with their permissions (in the CSV's role cells as `member; Name: perms`), and its digest changes when they do. The digest of a report with no custom roles is the same as before.

### Data

One migration adds a `roles` table (`id`, `name` unique ignoring case, `description`, `base` checked as member or readonly, `permissions` as a JSON list, `created_at`, `created_by`, `updated_at`) and a nullable `role_id` referencing it on `users` and `team_members`. Existing databases get no roles and no `role_id`s, so everyone keeps exactly the access they had. A `role_id` is read on every request, so a change applies to existing sessions at once. Erasing someone ([ADR 0102](0102-erasing-a-users-data.md)) clears their `role_id` and takes them off their team, so a role they held can be deleted.

## Alternatives considered

- **Roles as free sets of every permission, admin included, with the built-in roles stored as rows.** Every check that reads `users.role` (Bot ACLs, approvals, notifications, MFA, SCIM, the access review) would have had to change, and a role could quietly add up to admin. A base plus delegable permissions keeps those checks as they are.
- **Permissions per route, or wildcards.** Too many and too unstable to document or review; a new route would silently fall into someone's role. Six named permissions, each opening an exact list of routes, are reviewable, and a new route stays admin-only until it is named.
- **Separate role tables for the server and for teams.** One role definition, applied with its team permissions only in a team, is simpler for admins and for the access review.
- **Letting delegates manage each other.** It turns any `users.manage` holder into a way to spread or keep their own access. Only admins change people with custom roles.

## Consequences

- Admins can delegate user support, auditing, billing, sign-up approval and machine operations without the admin role, and a team can hand out invites, billing or machines to one person.
- The six permissions are part of the API: renaming one is a breaking change. New ones append.
- `rbac::classify` gets more arms; its tests check every route the table names, odd shapes, and that every route still `admin` refuses someone holding every delegable permission.
- Read-only plus `audit.view` is the auditor role SOC 2 reviewers ask for.

## Not in this slice

SCIM group-to-role mapping; service accounts (non-human callers with roles); a client or console editor for roles (the API and the access review show them); `botctl role` commands; Bot handover under `bots.manage`; team owners giving team roles themselves.
