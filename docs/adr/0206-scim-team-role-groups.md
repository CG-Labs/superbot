# 0206: SCIM team role groups

## Status

Accepted (23 Nov 2026). Part of [#51](https://github.com/CG-Labs/superbot/issues/51) (SCIM provisioning: group → role mapping). Builds on [ADR 0180](0180-scim-role-groups.md) (role groups), [ADR 0138](0138-scim-group-role-mapping.md) (groups mapped to roles, within a team or across the server) and [ADR 0123](0123-custom-roles.md) (custom roles within a team). 0202 to 0205 are held by other open pull requests.

## Context

A role group (ADR 0180) gives a custom role across the server, so cross-team groups like "Auditors" can sit beside team groups. ADR 0180 left out the same thing within a team. Directories hold that too: "Support Leads", or one "Team Leads" group across the company, whose people should manage their own team's members and billing, not everyone's. A team group's mapping (ADR 0138) gives a team role to the whole team, and a subset can't be its own team group, since a person is on one team at most. So the only way was to give those team roles by hand.

## Decision

### A team role group

A role group has a **scope**, fixed when it's declared: `org` (across the server, as before, the default) or `team`. `botctl scim role-group add <tenant> <group> <role> --team`, or `POST /api/scim/role-groups` with `"scope": "team"`. Everything else about a role group is unchanged: it waits for the IdP, is no team, shares names and `externalId`s with the tenant's team groups, any number per person, and an IdP delete puts it back to waiting.

A team role group gives its role **within the team each member is on**, when that team is one of the same tenant's team groups (pushed, or linked by an admin). Not one team named in the declaration: a person is on one team, so "their team" is unambiguous, and one "Team Leads" group serves every team. A tenant's group never gives a role in a team the tenant doesn't provision, so one IdP can't reach another's teams or a team run by hand.

### The rules

A team role group follows a team mapping's rules (ADR 0138):

- only the role's team permissions apply (`users.manage`, `billing.manage`), stored as the person's team role (`team_members.role_id`), never across the server and never their built-in role;
- refused (400, `scim.role_map_refused` with `kind: "role_group"`, `scope: "team"`): admin, a built-in role, or a role that reaches admins in a team (`machines.manage`, `rbac::REACHES_ADMINS_IN_TEAM`). `bots.manage` does nothing in a team, so it isn't refused there. A role a team role group gives can't later gain `machines.manage` (409), checked by the group's scope;
- never to read-only people (`readonly`), nor over a team role held already, by hand, a mapping or another team role group (`has_role`), nor to someone on no team of the tenant (`not_on_team`), each audited as `scim.role_skipped`;
- one team role each: the oldest team role group they're in that can give one does, and the next in line is offered when it stops. Org and team role groups queue apart, so a person can hold one of each;
- each grant is a row (`scim_role_group_team_grants`, one per person, with the team and the role it gave); taking it away clears only that role in that team, and a hand change of their team role deletes the row, as for mappings.

### Following the person

- **Onto a team.** When SCIM puts someone on a team (after the team group's mappings), the team role groups they're in are offered, without auditing skips again. When an admin links a team to the tenant, its members are offered them. A join is saved before the machine work it waits on, so a restart there leaves the person on the team without those offers; the IdP's retry names them again, and a PATCH or PUT naming someone already on the team offers them the team group's mappings and their team role groups again, quietly (this also closes the same gap for ADR 0138's mappings).
- **Off a team.** Leaving a team, by any path, takes the team role with the membership; the grant goes with it (`left_team`). Moving to another of the tenant's teams offers it there.
- **Team unlinked.** An admin unlinking the team takes back the team roles the tenant's team role groups gave in it (`team_unlinked`): the team isn't the tenant's any more.

### Mappings and role groups

A team group's mapping gives its role to everyone on the team when they join, so a team role group's members on that team are skipped (`has_role`). Neither overrides the other: an admin's mapping and an admin's role group are both decisions, and ADR 0138 never replaces a role it didn't give.

When a mapping's role is taken from someone, the role groups they're in are now offered, which closes the first gap ADR 0180 left: an admin removing the mapping offers the role groups of its scope; SCIM taking someone off a mapped team (the IdP removing them, or deleting the group) and an admin unlinking the team offer the org role groups to those who lost a role across the server. A team role is offered again only on removing a team mapping, since an unlinked team is no longer the tenant's and someone off the team holds no team role.

### Audit

As for role groups, with `scope` on every event and `team` on each grant and removal; new reasons `left_team` and `team_unlinked`. `GET /api/scim/role-groups` and `/{id}` show `scope`, `applies` (the team permissions for a team role group) and each holder's team; `GET /api/roles/{id}` names the role group as a team holder's `scimMapping`.

## Consequences

- Team leads, team billing and team helpdesks can follow IdP groups, alongside team groups and org role groups.
- One migration adds `scope` to `scim_role_groups` (existing ones are `org`) and the `scim_role_group_team_grants` table. Nothing is backfilled; existing role groups behave exactly as before.
- The Google Workspace sync needs no change: a declared group in `GOOGLE_DIRECTORY_ROLE_GROUPS` is a team role group if it was declared with `--team`.
- The console shows a role group's scope; declaring and changing them is still `botctl` or the API.

## Alternatives considered

- **Name one team in the declaration.** Tighter, but needs one declaration per team for "Team Leads", and a person moved to another team would hold nothing until an admin declared again. The tenant check keeps the same boundary: only the tenant's own teams.
- **Let a team role group override a team mapping.** The more specific group would win, but it would take away a role an admin's mapping gave, which ADR 0138 never does, and a mapping removed later couldn't tell what to give back.
- **Re-offer on every path a mapping's grant goes, including an admin taking someone off a team by hand.** That path runs in the team code, which doesn't hold the SCIM settings that say whether group roles are on; only SCIM requests and the SCIM admin API re-offer. The role across the server is offered on the next change to a role group they're in.

## Not done

- Re-offering a role group's role across the server when someone leaves a mapped team outside SCIM (an admin removing them).
- A mapping is not re-offered when a role group's role is taken; only role groups are queued.
- Declaring and changing role groups in the console.
