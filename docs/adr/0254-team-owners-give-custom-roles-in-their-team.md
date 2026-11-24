# 0254: Team owners and admins give custom roles in their own team

## Status

Accepted (24 Nov 2026). Fifteenth slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0123](0123-custom-roles.md) (custom roles), [ADR 0132](0132-custom-roles-in-the-apps.md) (custom roles in the apps), [ADR 0197](0197-time-bound-custom-roles.md) (time-bound roles) and [ADR 0206](0206-scim-team-role-groups.md) (SCIM role groups within a team).

0254 was set aside for this change; other open pull requests hold 0251, 0253 and 0255 to 0257.

## Context

ADR 0123 lets a custom role be given within a team, where only its team permissions apply: `users.manage` (invites, removing plain members), `billing.manage` (the team's plan) and `machines.manage` (giving members machines, suspending and resuming them). But only server admins could give one, through `PUT /api/roles/{id}/teams/{team}/users/{user}`. ADR 0123 left "team owners giving team roles themselves" for later, and no slice since built it.

So a team owner who wanted one person to handle invites, or the team's billing, had two choices: make them a team admin, which hands over all three and the team's roles too, or ask a server admin. On a server with many teams, server admins become the help desk for every team's delegation, and owners over-grant to avoid asking.

## Decision

### Who gives, and what

A team's **owners and admins** may give a custom role to someone on their team, within that team, and take one away:

- `PUT /api/team/members/{user}/custom-role` `{role, expiresAt?, reason?}`. `role` is the role's id or name. `expiresAt` and `reason` work as for an admin (ADR 0197): at most 365 days ahead, and a time-bound role needs an end within its own limit. Unknown fields are 400.
- `DELETE /api/team/members/{user}/custom-role` takes away whatever custom role they hold in the team, whoever gave it.

They may give any custom role that adds something in a team, that is, one holding at least one of the three team permissions. A role with none is refused with 409, since it would do nothing there. Server admins still build the roles; team owners only choose among them.

Only the team permissions of the role apply, only in that team, and only while the person is on it (ADR 0123). Their role across the server doesn't change, so nothing here reaches server-wide routes.

### Why no admin opt-in

Owners and admins already hold every team permission, and can make any member a team admin, which grants all three with no end. Giving one narrower role is always less than that. So a separate "teams may give this role" switch on each role would guard nothing that isn't already in the owner's hands, and would be one more setting for admins to keep in step.

### Whom

- **Plain members only.** Giving a role to the team's owners or admins is 409: they can already do all of it. Taking one away from them is allowed, since it only narrows.
- **Not yourself** (409), for giving or taking. Ask another of the team's owners or admins.
- **Not read-only people** (409), as for an admin: read-only people change nothing, anywhere.
- **Not a role from the identity provider** (409). When a SCIM mapping or team role group gave the person their role in the team (ADR 0138, ADR 0206), the IdP owns it. A team owner can't replace or remove it; a server admin changes the mapping. The check is made again inside the write's transaction, so a SCIM grant that lands between the route's check and the write still wins. Server admins' own route still overrides it, as before.
- Someone on another team, or no one, is 404, so a team owner learns nothing about people outside their team.

### Who doesn't

- **Team-role holders** with `users.manage` in the team can't give or take roles (403). Letting delegates hand out access would let it spread without an owner's say, as ADR 0123 decided for server-wide delegates.
- **Service accounts and Bots** never do: a service account's place in a team is a plain member's, and the routes need a person.
- **Read-only owners and admins** are refused by RBAC: the routes are classified `write`, like the team's other changes.

### Audit

Both routes write the usual `role.assigned` and `role.unassigned` with `scope: "team"`, the team, what applies, the end and the reason, with the team owner or admin as the actor. They add `via: "team"`, so the access history shows which grants came from a team rather than a server admin. A server admin's grant has no `via`, as before. The end is cleared by the existing sweep as `role.expired`.

### Where it shows

- `GET /api/team` adds `roleChoices` for the team's owners and admins who can write: each role that adds something in a team, with its `id`, `name`, `description`, `applies` (its team permissions) and `maxDays`. Members, read-only managers and service accounts get none.
- A member's `customRole` in the team view adds `fromIdp: true` when their identity provider gave it.
- **App.** On the Team screen, each teammate's role shows under their name, with when it ends or that it comes from the IdP. Owners and admins get **Give a team role** (or **Change team role**, which starts on the role they hold and the end nearest theirs) on plain members: pick a role, see what it adds in the team, pick an end (only those within a time-bound role's limit), and give it. **Take away role** asks first. Nothing is offered on yourself, on owners and admins (except taking away), or on a role from the IdP.
- `botctl` has no team commands for owners; server admins keep `botctl role assign --team`. The console stays admin-only.

## Alternatives considered

- **A per-role switch for which roles teams may give.** See above: owners can already grant more by making someone an admin. It may still be worth it if roles gain team permissions owners don't hold; not today.
- **Team-defined roles.** Teams building their own roles from the team permissions would duplicate the role catalogue per team, and split the access review. One catalogue, built by server admins, chosen from by teams, keeps it reviewable.
- **Let owners override the IdP.** It makes the IdP and SuperBot disagree, and the next SCIM push wouldn't restore the mapping's role until the hand-given one is cleared. Refusing keeps the IdP the source of truth for what it manages.
- **Reuse `PATCH /api/team/members/{user}` with a `customRole` field.** It mixes the team's built-in roles, with their owner rules, and custom roles, with ends and reasons, in one body. A separate route keeps each set of checks simple.

## Consequences

- Team owners delegate one part of running their team, for a set time if they like, without a server admin and without making someone a team admin.
- The access review already lists team roles and their ends (ADR 0123, ADR 0197); grants from teams show there the same way, and `via` in the audit log tells them apart.
- `GET /api/team` for owners and admins reads the role catalogue once more.
- Still to do for #53: nothing from its scope. Follow-ups could be team owners approving requests for team roles (ADR 0209 sends them to server admins), handing several Bots to a service account in one request, or `botctl` team commands.
