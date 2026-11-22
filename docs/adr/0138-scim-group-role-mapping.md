# 0138: SCIM groups mapped to custom roles

## Status

Accepted (22 Nov 2026). Closes the item open on both [#51](https://github.com/CG-Labs/superbot/issues/51) (SCIM provisioning) and [#53](https://github.com/CG-Labs/superbot/issues/53) (Advanced RBAC). Builds on [ADR 0023](0023-scim.md) (SCIM), [ADR 0095](0095-scim-groups-as-teams.md) (groups as teams), [ADR 0123](0123-custom-roles.md) (custom roles) and [ADR 0132](0132-custom-roles-in-the-apps.md) (roles in the apps and `botctl`). [ADR 0124](0124-deprovisioning-stops-bots-and-machines.md) asked for its own design: never admin, per tenant, opt-in, and what happens to a role when a group goes.

## Context

SCIM creates users with `SCIM_DEFAULT_ROLE` (member or read-only) and puts them on teams as plain members. Every role above that is given by hand. Organisations that run access from their IdP want "everyone in the Support Leads group can manage the Support team's people" or "everyone in Auditors can read the audit log" to follow group membership, so access ends when someone leaves the group.

Letting the IdP name roles is where admin escalation hides: whoever can edit a group in the IdP would become an admin in SuperBot, and a mistyped mapping could make a whole department admins. A group's role must stay an admin's decision in SuperBot, and must never add up to admin.

## Decision

### A mapping

An admin maps one tenant's group to one custom role (ADR 0123), in one scope:

- **team** (the default): the role within the team the group is (ADR 0095). Only its team permissions apply, as for any team role.
- **org**: the role across the server. Its base becomes the person's built-in role, as when an admin gives it.

A group has at most one mapping per scope (`UNIQUE(team_id, scope)`), since a person holds one custom role per scope. Mappings are per tenant: a group belongs to one tenant, and the mapping records it.

`SCIM_GROUP_ROLES=on` turns it on; it needs `SCIM_GROUPS=on` (botd refuses to start otherwise). Off, no mapping can be made and nobody is given a role, but leaving still takes away what mappings gave, so turning it off never strands access.

Admins manage mappings with `botctl scim role-mappings | role map <team> <role> [--org] | role show <id> | role unmap <id>`, or `GET`/`POST /api/scim/role-mappings` and `GET`/`DELETE /api/scim/role-mappings/{id}`. The console's SCIM section lists them and removes them. The IdP's SCIM API has no say: a group's `roles`, or a user's, are still ignored.

### Never admin

A mapping is refused (400, audited as `scim.role_map_refused`) when the role is:

- `admin`, or any built-in role (mappings give custom roles only);
- a custom role whose permissions act on admins in that scope (`rbac::REACHES_ADMINS`): across the server, `bots.manage` (anyone's Bots and routines, admins' included) and `machines.manage` (anyone's machine); within a team, `machines.manage` (the team's machines, its owners' and any admin's on it too).

The other delegable permissions keep holders away from admins by ADR 0123's limits on delegates (`users.manage` can't touch an admin, the owner or a custom-role holder, nor make an admin; `audit.view`, `billing.manage` and `signups.approve` act on no one's account, and approving a sign-up can't make an admin). So a mapped role, held by anyone the IdP puts in the group, can never reach an admin or make one.

A role that is mapped can't later gain such a permission (`PATCH /api/roles/{id}` is 409, naming the mapping), and can't be deleted (409) until its mappings are removed. The database checks the role's permissions as they are at the moment of each write: saving a mapping, saving a role's permissions (against the mappings saved by then), and each grant. A role edit racing a new mapping therefore can't slip such a permission through. Refusals give `reason` `admin`, `built_in` or `reaches_admins`.

### Who gets it

When SCIM adds someone to the group, and when a mapping is made (for the group's members then), each person gets the role unless they are:

- an admin, or the owner account (org scope; an admin is never demoted by a group);
- holding a custom role in that scope already, whether given by hand or by the group's other mapping;
- read-only (team scope: a team role does nothing for them, ADR 0123);
- no longer on the team, or the role now reaches admins.

Each skip is audited as `scim.role_skipped` with its reason. The grant is one SQL update whose conditions repeat these checks, so a race with an admin's change can't overwrite it.

### Only what it gave

Each grant is a row in `scim_role_grants` (mapping, user, scope, and across the server the built-in role it replaced). Taking it away clears the person's role only if it is still the mapping's, and deletes the row.

Any change of that person's role by hand ends the mapping's claim on it: an admin giving them a role (the same one included), taking it away, setting their built-in role, or erasing them deletes the grant row in the same transaction. So taking away never removes a role an admin gave or confirmed, and a role an admin took away isn't given back until the person joins the group again.

Across the server, losing the role puts back the built-in role from before it was given: a read-only person a member-based role made a member is read-only again. That and any other change of built-in role is audited as `user.role_changed` and runs the same offboarding as an admin's change (`users::lost_access`).

### When it's taken away

- They leave the group's team, by any path: SCIM removing them, a SCIM `DELETE` of the user, a team admin's or server admin's removal (`teams::leave`, right after the membership row goes, before the rest of offboarding). If SCIM puts them back on the team before that revoke runs, the revoke takes nothing, so the rejoin keeps the role.
- The mapping is removed (`DELETE /api/scim/role-mappings/{id}`): everyone it gave the role to loses it.
- The group goes: the IdP deletes it (members leave first, then remaining mappings go) or an admin unlinks it (mappings go, people stay on the team). Deleting the team deletes its mappings.

Mapping writes and SCIM group writes take the same lock (`group_writes`), so a mapping can't be made or removed in the middle of a membership change.

### Audit

`scim.role_mapped`, `scim.role_unmapped` (reason `mapping_removed` or `group_removed`, with who lost the role), `scim.role_map_refused`, `scim.role_skipped`, and every grant and removal as the existing `role.assigned` and `role.unassigned` with `via: "scim"`, the mapping, the tenant, the team (team scope), and a reason (`left_group`, `mapping_removed`, `group_removed`). A grant made when SCIM adds someone has the SCIM token as its actor; one made when an admin creates a mapping has the admin. A hand change that takes over a SCIM grant records `takenFromScim` or `scimMapping`. `GET /api/roles/{id}` shows each holder's `scimMapping`, and each role's `scimMappings` count.

## Alternatives considered

- **Let the IdP send roles** (a `roles` attribute, or group names like `superbot-admin`). Whoever edits the IdP's groups becomes an admin. Refused; the IdP only says who is in a group.
- **Map groups to built-in roles.** Member and read-only are already what SCIM gives (`SCIM_DEFAULT_ROLE`), and admin is exactly what must never follow a group. Custom roles carry what organisations want to delegate.
- **Refuse every permission at org scope except `audit.view`.** Safer on paper, but `users.manage`, `billing.manage` and `signups.approve` are bounded by ADR 0123's delegate limits already; refusing them would push admins back to giving them by hand, with no group to take them away.
- **Override a role given by hand.** A group would then silently replace an admin's decision, and removing the group would remove a role the admin meant to keep. Skipping, and audited skips, keep the two apart.
- **Recompute roles from group membership on every request.** Simpler state, but it can't tell a hand grant from a group's, and a role's holders would no longer be what the database says.

## Consequences

- Organisations can delegate team management and read-only admin duties through their IdP's groups, and access ends when people leave the group.
- Two tables (`scim_role_mappings`, `scim_role_grants`), a setting, four admin routes, four `botctl` commands, and a 409 on editing or deleting a mapped role.
- The console's SCIM section lists mappings and removes them; admins make them with `botctl` or the API. The app has no mappings screen yet. Holders show their `scimMapping` in a role's details.
