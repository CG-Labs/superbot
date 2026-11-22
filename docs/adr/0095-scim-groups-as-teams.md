# 0095: SCIM groups as teams

## Status

Accepted (21 Nov 2026). The last item on per-user isolation ([#30](https://github.com/CG-Labs/superbot/issues/30), [roadmap](../ROADMAP.md)). Builds on SCIM provisioning ([ADR 0023](0023-scim.md), hardened in [ADR 0026](0026-scim-review-hardening.md)), team accounts and machines ([ADR 0087](0087-team-accounts-and-machines.md)), team screens ([ADR 0088](0088-team-screens-in-the-apps.md)), team billing ([ADR 0093](0093-team-billing.md)), and teammate offboarding ([ADR 0052](0052-teammate-offboarding-on-machines.md), [ADR 0066](0066-removing-teammate-accounts-on-one-server.md)).

Numbering: `main` has up to 0093; 0094 is taken by the open TOTP pull request and 0096 by the open master key rotation one, so this is 0095.

## Context

SCIM provisions people, but not teams. ADR 0023 deferred groups because SuperBot had nothing safe to map them to: roles are per user, and mapping groups to roles is where admin escalation hides. Teams (ADR 0087) are now that thing. A team is a set of people who share Bots and get machines, and with ADR 0093 one bill. That is what an IdP group means to most companies.

Entra ID and Okta push groups the same way: create the group, then add and remove members. Entra uses `PATCH` with `Add` and `Remove` on `members`, and expects 204. Okta uses `PATCH`, and its integration-wizard apps use `PUT` with the whole member list. Both look a group up by `displayName` first. Both must be able to remove people within minutes, and nothing they send may give anyone more than they had.

## Decisions

### A group is a team

- **Off unless `SCIM_GROUPS=on`**, on top of `SCIM=on`. Groups change who shares Bots, who gets machines, and who is billed, which is more than user provisioning does, so an operator turns them on separately. Off, `/scim/v2/Groups` behaves as before: an empty list for connection tests, 404 for one group, and 501 for writes.
- **Each group is one team in one tenant**, stored in `scim_groups` (team id, tenant, `externalId`, `displayName`, origin, when the IdP took it on). The group's SCIM `id` is the team's id. A team is in at most one group. A team's deletion takes the row with it.
- **Two ways in.** `POST /Groups` makes a new team (origin `scim`). An admin can also link a team made by hand (`botctl scim group link <tenant> <team> [--external-id X] [--name N]`, origin `admin`). The IdP takes on a linked team when it creates a group with that `externalId`, or, when the link has none, that `displayName` (any ASCII case; the team's name by default). Okta sends no `externalId`; Entra sends its object id. The IdP may also find the link by name and patch it directly. A second `POST` for a group the tenant has is a 409 `uniqueness`. Joins can still lose a race after the checks pass (a team admin puts someone on another team meanwhile); the `POST` then answers 409 with what was done kept, and the group waits to be taken on again, like a link, so the IdP's retry of that `POST` finishes it (`scim.group_resumed`).
- **`displayName` is unique per tenant**, in any ASCII case, as Entra requires. Uniqueness, taking on a link, and filters all fold case the same way (SQLite's `NOCASE`), so `Équipe` and `éQUIPE` are two groups, each found only by its own spelling. A rename renames the team (the first 100 characters). **`externalId` is set once**: changing it is a 400 `mutability`, since it is what pairs the group with the IdP's.
- **A new team has no owner and no machines.** A server admin gives it an owner (`PUT /api/teams/{id}/members/{user}`) and turns on machines (`PATCH /api/teams/{id}`). Until then its members share Bots with each other as any team does.

### Tenants and teams made by hand stay apart

- A token sees only its tenant's groups: another tenant's group, and a team nobody linked, are 404 to every route and missing from lists and filters.
- **A group holds only its tenant's people.** Adding someone the tenant didn't provision (a user made by hand, another tenant's, or one the tenant deleted) is a 400 `invalidValue`, and nothing changes. On a linked team, people the tenant doesn't manage are never shown in `members` and never removed: a `PUT` replaces the tenant's people only.
- **A person is on one team at most** (ADR 0087). Adding someone who is on another team is a 409 `uniqueness`, audited as `scim.group_member_refused` (reason `other_team`). SCIM never moves people between teams; remove them from the other group, or the other team, first.

### Joining and leaving are the team's own

Every membership change goes through the same `join` and `leave` as an invite or a team admin's add and remove:

- Joining gives the team's machine (when it has `machines` on), moves the person onto a paying team's plan, and wakes the seat sync (ADR 0093). It also ends sharing with people outside the team.
- Leaving revokes grants between them and their teammates (`bot.access_revoked`, reason `left_team`), runs the teammate offboarding on machines and on the server (ADR 0052, 0066), suspends the team's machine and releases it for destruction after `TEAM_MACHINE_DAYS`, moves them back to their own plan, and wakes the seat sync.
- Audited as `team.member_joined` (via `scim`) and `team.member_left` (reason `scim`), plus one `scim.group_updated` per request with what was added and removed. Everything has the token as its actor (`system`, `scim:<token id>`, method `scim_token`).
- **Idempotent.** Adding a member, removing a non-member, or sending the same `PUT` twice changes nothing and logs nothing. One request's changes are worked out first, checked (400 or 409 before anything changes), and then made. Group writes run one at a time, so what a request checked still holds when it writes.
- **Disabled people join.** The IdP may put someone in a group before it enables them, or while they're disabled. They join with no machine. When they're enabled (by the IdP or a server admin), a member of a team that gives machines gets what joining would have given them: the team's machine if they have none (`team.machine_requested`), or the machine a former team released, taken back before the sweep destroys it (`team.machine_kept`). Leaving and taking back both check membership under the machine lock, so a machine is never taken back for someone who has just left. A team admin still can't add a disabled person by hand.
- **A SCIM `DELETE` of a user** takes them off a team their tenant's group put them on, as removing them from the group would, and is logged the same way (`scim.group_updated` with `removed`, and `ownerless` if they were its last owner). Deactivation (`active: false`) keeps them on the team, disabled, as a server admin's disable does, so reactivating gives back the same access.

### Roles: none, ever

SCIM never grants an org role, and never a team role. Members join as `member`. The IdP can't name owners or admins: no attribute or operation sets a team role, and `roles` in a request is ignored. Owners and admins are set by a server admin, or by the team's owners on the Team screen, as for any team.

Deprovisioning can't wait for an owner, though. The IdP removing someone takes them off even if they are the team's last owner, which a team admin can't do. A team left with members but no owner is flagged `ownerless: true` on `scim.group_updated` or `scim.group_deleted`, for a server admin to name a new one. Until then, server admins manage it as before.

### Deleting a group never destroys what the IdP didn't make

`DELETE /Groups/{id}` removes the tenant's people from the team, each as one leave (so everything above happens), and ends the link. Then:

- A team the IdP made (origin `scim`) that is now empty is deleted, unless it pays for a plan. A paying team can't vanish (ADR 0093), so it stays, empty and unlinked, until the plan is cancelled (`team.delete_refused`, reason `team_pays`, via `scim`).
- A team an admin linked, or one that still has people the IdP doesn't manage, stays as it was otherwise, managed by hand again.
- Audited as `scim.group_deleted`, with `teamFate` set to `deleted`, `kept`, or `kept_paying`.

We considered only unlinking (soft delete), leaving everyone on the team. IdPs delete a group to take away the access it gave. Leaving people on a team that no IdP manages would quietly keep the sharing and machines the company meant to end. The people go, the team's data (its Bots belong to people, not teams) is untouched, and only an empty team that the IdP itself made is removed.

An admin can end a link without removing anyone: `botctl scim group unlink <team>` (`scim.group_unlinked`). The IdP's group is then 404 to it.

### Protocol

- `GET /Groups` with `filter` on `displayName` (any ASCII case), `externalId` and `id` (exact), and membership (`members eq`, `members.value eq`, `members[value eq "…"]`), joined with `and`. That covers Entra's lookups and its membership check (`id eq "…" and members eq "…"`), and Okta's. Pages are 1-based, oldest first, at most 200 a page. `excludedAttributes=members` (Entra) and `attributes` leave members out.
- `GET /Groups/{id}` includes `members` (`value`, `display`, `type: User`, `$ref`), as Okta needs.
- `POST` returns 201 with `Location`. `PUT` returns 200 with the group. A `PUT` without `members` leaves them; an `externalId` left out is kept. `PATCH` returns 204.
- `PATCH` takes `add`, `replace`, and `remove` in any case, on `members`, `displayName`, and `externalId`. `remove` on `members` with a list removes those people; with no value it removes all of them. `members[value eq "…"]` can only be removed. With no path, the value is an object of attributes; Okta's rename sends one with the `id`, which is ignored. Groups in groups are refused.
- Bodies to `/Groups` may be up to 1 MiB, since a `PUT` carries every member. Users stay at 64 KiB.
- Discovery adds the `Group` resource type and schema while groups are on.

### Admins

- `GET /api/scim/groups` lists every tenant's groups, with their teams and how many people each tenant manages there. `POST /api/scim/groups` links and `DELETE /api/scim/groups/{team}` unlinks. All are admin-only (RBAC's default for `/api`), and SCIM tokens never reach them.
- `GET /api/teams` and `GET /api/teams/{id}` show server admins a team's `scimGroup` (tenant, name, `externalId`, origin, whether the IdP took it on). Team members never see it.
- `botctl scim groups`, `botctl scim group link`, `botctl scim group unlink`.

## Consequences

- An IdP can now give and take away team membership, machines, and team-billed plans for the people it provisions, within one sync. It can't give anyone a role, reach people it didn't provision, move anyone off a team, or touch a team nobody linked to it.
- Turning `SCIM_GROUPS` off later leaves teams and members as they are. The links stay, and they work again when it's turned back on.
- A team the IdP makes needs a server admin to give it an owner and machines. That's deliberate, and the cost is one step per new team.
- Deleting a group removes its people at once, with all the offboarding that brings. The IdP's audit log and SuperBot's (`scim.group_deleted`) say who did it.

## Not done

- Mapping groups to org roles, or to team roles. Both need their own design if ever wanted.
- Groups in groups, more than one team per person, and Bulk.
- A console screen for links. `botctl` and the API cover it; the console's Teams tab shows `scimGroup`.
