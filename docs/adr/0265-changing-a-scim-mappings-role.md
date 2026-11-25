# 0265: Changing a SCIM mapping's role

## Status

Accepted (25 Nov 2026). Part of [#51](https://github.com/CG-Labs/superbot/issues/51) (SCIM provisioning: group → role mapping). Closes the "Not done" of [ADR 0253](0253-scim-group-roles-in-the-console.md) (changing a mapping's role in place), on top of [ADR 0138](0138-scim-group-role-mapping.md) (groups mapped to roles). Role groups could already change their role ([ADR 0180](0180-scim-role-groups.md), `PATCH /api/scim/role-groups/{id}`).

Numbering: this number was reserved for this work.

## Context

A mapping ties a team's SCIM group to one custom role, in the team or across the server. Organisations change what a group should give: "Support Leads" moves from a lead role to a narrower one, or an auditor role is split in two. Until now the only way was to remove the mapping and map the group again. That has three costs:

- **Everyone loses access in between.** Removing takes the role from every holder, audited as `role.unassigned`, and across the server puts back their old built-in role and runs offboarding (`users::lost_access`). Mapping again gives it back a moment later.
- **Role groups step in.** When a mapping's role goes across the server, the role groups each holder is in are offered at once (ADR 0206). Someone in an "Auditors" role group gets that role in the gap, and keeps it, so the new mapping then skips them as `has_role`.
- **The audit trail reads as two unrelated events.** A reviewer sees every holder losing a role and gaining one, with nothing saying it was one decision.

Role groups have a `PATCH` that takes the old role away and offers the new one to their members. Mapping grants don't record which role they gave (`scim_role_grants` has no `role_id`; revocation cleared whatever role the mapping named), so that design would need a migration, and it still leaves the gap.

## Decision

### `PATCH /api/scim/role-mappings/{id} {role}`

The mapping gives another custom role, in the same scope (a mapping's group and scope are fixed; `scope` in the body is refused). `botctl scim role remap <id> <role>` sends it. Admins only, like the other mapping routes, and only while `SCIM_GROUP_ROLES=on` (409 otherwise).

The new role is held to a new mapping's rules, with the same refusals: admin or a built-in role (400), a role reaching admins in that scope (400), each audited as `scim.role_map_refused` with the mapping's id; a time-bound role (409). The database checks again as it saves, so a role edited meanwhile can't slip through.

### One swap, in one transaction

`Db::set_scim_role_mapping_role` updates the mapping and, in the same transaction, every person holding the old role from it:

- Across the server: their custom role becomes the new one and their built-in role its base, only while they still hold the old one and aren't an admin. The built-in role they had before the mapping (kept in the grant) stays, so leaving later gives that back, not the old role's base.
- In the team: their team role becomes the new one, only while they still hold the old one there.
- A grant whose holder no longer holds the old role is forgotten (`dropped`), never written over.

So nobody holds neither role at any point, no role group is offered in between, and the swap either happens for everyone or no one. The same role again changes nothing and audits nothing.

### Nobody else is given it

Only holders swap. People the mapping skipped (admins, the owner, anyone holding a custom role in that scope, read-only people in a team) stay skipped: changing the role changes none of those reasons, since the old role was givable too. People whose role an admin took away aren't given the new one: ADR 0138 says a role an admin took away isn't given back until they join the group again, and the new role is the mapping's role now.

This is where mappings and role groups differ. A role group's `PATCH` offers the new role to members without one, because its members are whoever the IdP says and its own grant rules decide. Doing the same for a mapping would undo admins' removals.

### Stale copies of the mapping can't act on the old role

Grant and revoke took the mapping's role from the copy their caller read. Most callers hold the SCIM group write lock, as the `PATCH` does, but someone leaving a team by an admin's hand runs without it. So:

- `grant_scim_role` gives nothing (`changed`) unless the mapping still gives the role the copy names, read in its transaction.
- `revoke_scim_role` clears the role the mapping gives now, read in its transaction, and returns it, so `role.unassigned` names the role actually taken.

Either order of a swap and a leave ends with the leaver holding nothing from the mapping.

### Audit and answer

Each holder's swap is `role.assigned` on the new role with `from` (the old role), `via: "scim"`, the mapping, tenant and scope, `reason: "mapping_changed"`, and for a team role the team and what it applies there, like an admin changing someone's role by hand. A change of built-in role is `user.role_changed` (reason `scim_group`) with the same offboarding as any other. The change itself is `scim.role_remapped` on the team: the group, `from`, the new `role`, what it applies, `swapped` and `dropped`.

The answer is the mapping as `GET` shows it, with `from`, `swapped` and `dropped`.

### In the console

Each mapping's row in the SCIM section has the role picker role groups have (ADR 0253), listing only the roles `choices` offers for its scope. Choosing one asks first (its holders get the new role instead; nobody else is given it), then sends `PATCH`. The ADR 0253 test that requires the routes to accept exactly the offered roles now covers `PATCH` too.

## Consequences

- Admins can change what a group gives without anyone losing access in between, and the audit log shows it as one decision.
- The old role is no longer mapped, so it can be edited or deleted; the new one can't gain permissions reaching admins while mapped, as before.
- One route, one `botctl` command, one audit event, a picker in the console. No migration, no new setting.
- Grant and revoke read the mapping's role in their own transaction: one more indexed read each.

## Alternatives considered

- **Revoke then grant, like role groups.** Needs a `role_id` on mapping grants (a migration), leaves holders with neither role in between, and lets role groups take them in the gap. Rejected.
- **Offer the new role to every member, like role groups.** Would give the role back to people an admin took it from. Rejected; joining the group again still does.
- **Allow changing the scope too.** A different scope is a different mapping, with its own uniqueness (one per group and scope) and different holders' checks; remove and map again for that.
- **Keep remove and map again.** Simple, but costs the gap, the role-group race and the split audit trail above.

## Not done

- Changing a mapping's group: remove it and map the other group.
- These screens in the Expo client: SCIM stays in the admin-only console (ADR 0032).
