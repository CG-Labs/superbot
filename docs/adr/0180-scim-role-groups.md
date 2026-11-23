# 0180: SCIM role groups

## Status

Accepted (23 Nov 2026). Part of [#51](https://github.com/CG-Labs/superbot/issues/51) (SCIM provisioning: group → role mapping). Builds on [ADR 0095](0095-scim-groups-as-teams.md) (groups as teams), [ADR 0138](0138-scim-group-role-mapping.md) (groups mapped to custom roles) and [ADR 0162](0162-google-workspace-directory-sync.md) (Google Workspace sync).

## Context

Every group an IdP pushes becomes a team (ADR 0095), and a person is on one team at most, so a group can only be mapped to a role (ADR 0138) if it is also the team its people work in. That fits "Support Leads manage the Support team", but not how most directories hold roles: "SuperBot Auditors" or "Billing admins" cut across teams. Pushing such a group fails with 409 for everyone already on a team, and assigning it in Entra or Okta breaks provisioning for those people. The only way round it was to give those roles by hand, which is what group-driven access is meant to end.

## Decision

### A role group

An admin declares, per tenant, that the group with a given `externalId` (or, with none, `displayName`, any ASCII case) is a **role group** giving one custom role across the server: `botctl scim role-group add <tenant> <group> <role> [--external-id ID]`, or `POST /api/scim/role-groups`. Needs `SCIM_GROUP_ROLES=on` (409 otherwise).

A declaration waits, unseen by the IdP (`GET /Groups` doesn't list it), until the IdP sends a `POST /Groups` that matches it. That request takes it on (`scim.role_group_adopted`) instead of making a team. From then on the IdP reads and writes it like any group: `GET`, `PUT`, `PATCH`, `DELETE`, filters and Bulk, through the same `/Groups` handlers, which pass role groups to `scim::role_groups`.

A role group is not a team. Its members are any live users the tenant provisioned, in any number of role groups and on any team. Only the role follows membership: no team, machines or seats.

Names and `externalId`s are shared between a tenant's team groups and role groups, as an IdP expects of one `/Groups` collection: neither can take one the other has (409), and a group that is a team already can't be declared. Making an existing team group a role group means deleting it in the IdP and pushing it again once declared, so its people leave the team as with any group delete.

### One custom role each

A person holds one custom role across the server (ADR 0123), and can be in several role groups. The oldest role group they're in (by declaration) that can give them a role does. When a role group's role is taken from them (they leave it, it's removed, or its role changes), the next role group they're in is offered, in the same order. Skips are audited only when someone joins a group or its role changes, not on each re-offer.

### The rules of a mapping

A role group follows ADR 0138's org-scope rules, unchanged:

- never `admin`, a built-in role, or a role holding `rbac::REACHES_ADMINS` permissions across the server (400, `scim.role_map_refused` with `kind: "role_group"`); a role a role group gives can't gain them (409), nor be deleted (409);
- never over an admin, the owner account, or anyone with a custom role already (by hand, a mapping, or another role group), each skip audited as `scim.role_skipped`;
- each grant is a row (`scim_role_group_grants`, one per person, with the role it gave and the built-in role it replaced), and taking it away clears the role it gave, even if the group names another by then; any change of that person's role by hand deletes it, so only untouched grants are taken back, and losing one puts back the built-in role;
- `SCIM_GROUP_ROLES=off` gives nothing and declares nothing, but taking away still runs, and a declared group the IdP pushes is still a role group, never a team.

### When it goes

- **The IdP deletes it**: its members leave it and lose its role (reason `group_removed`), and the declaration goes back to waiting with the name and `externalId` the admin declared (each unless another role group or a team group took it after the IdP changed this one; then it keeps the IdP's), so pushing it again makes it a role group again, never a team.
- **An admin removes the declaration**: the role goes from everyone it gave it to (`role_group_removed`); the answer's `wasPushed` warns that an IdP still pushing the group will make it a team on its next `POST`.
- **An admin changes its role**: `PATCH /api/scim/role-groups/{id}` saves and checks the new role first, so a refused change leaves every grant as it was, then takes the old role (`role_changed`) and offers the new one to every member. If the server stops part way, the same change again takes away the grants still on another role and finishes it.
- **A SCIM `DELETE` of the user**: they leave every role group, losing its role (`user_deleted`).

### Google Workspace

`GOOGLE_DIRECTORY_ROLE_GROUPS` names group emails (needs `SCIM_GROUPS=on` and `SCIM_GROUP_ROLES=on`, none also a team group, at most 50 groups across the three lists). Being in one gives no account; only the people the other two lists bring in are members. The admin declares each one in the sync's tenant by its email. Each pass pushes a declared group (`displayName` the email, `externalId` the Directory id), updates it when its members change, and deletes a pushed one no longer listed. A listed group nobody declared is never pushed, since it would become a team; the pass's summary names it in `roleGroups.undeclared`. A push takes on only the declaration the pass read, checked again under the group write lock, so one removed during the pass is skipped rather than made a team.

### Audit

`scim.role_group_declared`, `scim.role_group_adopted`, `scim.role_group_changed`, `scim.role_group_removed`, `scim.group_updated` and `scim.group_deleted` with `kind: "role"`; each grant is `role.assigned` / `role.unassigned` with `via: "scim"`, `roleGroup` and `tenant`, plus `user.role_changed` (reason `scim_group`) when the built-in role changes. Target type `scim_role_group`.

## Consequences

- Entra, Okta and Google directories can drive cross-team roles from the groups they already have, alongside team groups.
- An admin still decides every role; the IdP only says who is in a group the admin chose.
- A role group must be declared before the IdP first pushes it. Pushed first, it becomes a team, and fixing that means deleting and pushing it again.
- The console lists role groups beside mappings and removes them; declaring and changing them is `botctl` or the API.

## Alternatives considered

- **Let a team group's mapping cover people on other teams.** A team group's members are the team; letting it hold others would break ADR 0095's model and the team's seats and machines.
- **A setting that makes every undeclared group a role group.** Simple for a server with no team groups, but one setting can't tell an IdP's team groups from its role groups, and an IdP's group names would decide who becomes a team member.
- **Read roles from the IdP (`roles` on users or groups).** Rejected in ADR 0138: whoever edits the IdP would decide roles.
- **Several custom roles per person.** ADR 0123 keeps one per scope so a person's access is one role to read; a queue of role groups keeps that.

## Not done

- When a mapping's server-wide role (ADR 0138) is taken from someone, the role groups they're in aren't offered at once: only when they rejoin one, its role changes, or another role group's role is taken from them.
- Role groups within a team (team scope).
- Declaring and changing role groups in the console.
