# 0095: SCIM groups as teams

## Status

Accepted (21 Nov 2026). The last item on per-user isolation ([#30](https://github.com/CG-Labs/superbot/issues/30), M3): SCIM groups map to teams. It extends the SCIM stub ([ADR 0023](0023-scim.md)) and its hardening ([ADR 0026](0026-scim-review-hardening.md)) with the Group resource, onto team accounts and machines ([ADR 0087](0087-team-accounts-and-machines.md)), team screens ([ADR 0088](0088-team-screens-in-the-apps.md)) and team billing ([ADR 0093](0093-team-billing.md)). Offboarding ([ADR 0052](0052-teammate-offboarding-on-machines.md), [ADR 0066](0066-removing-teammate-accounts-on-one-server.md)) doesn't change.

Numbering: `main` has up to 0093, and open PR [#154](https://github.com/CG-Labs/superbot/pull/154) claims 0094, so this is 0095.

## Context

Before this change:

- SCIM provisioned users only. `GET /scim/v2/Groups` answered an empty list so IdPs' connection tests pass, and every other group request got 501. ADR 0023 deferred groups because there was nothing to map them to, and because mapping groups to roles is where admin escalation hides.
- Teams (ADR 0087) now exist: one team per user, with roles (`owner`, `admin`, `member`), a machine per member, sharing that stops at the team, and offboarding when someone leaves. But team admins or server admins added each member by hand. Nothing took a leaver off a team when the IdP did.

Companies already keep "who is on which team" in Entra ID or Okta groups. When someone moves teams or leaves, they want SuperBot to follow within one provisioning cycle, with no admin step.

## Decision

### Off by default: `SCIM_GROUPS=on`

Groups as teams is a separate switch from `SCIM`. Off, groups behave exactly as before (empty list, 501 with a hint), so an IdP that was left pushing groups doesn't start making teams on upgrade. On, `ResourceTypes` and `Schemas` list Group too.

### A group is a team

- Each group a tenant `POST`s is a new team. The SCIM group `id` is the team's id. `displayName` is the team's name (its first 100 characters; the group keeps up to 256). The team gives members machines (`machines` on), as any new team.
- `scim_groups` links the team to the tenant, with the group's `displayName` and `externalId`. A team goes, so does its row.
- A tenant sees and changes only its own groups; another tenant's are not found (404). `displayName` is unique in a tenant in any case, `externalId` exactly. Two tenants can use the same name.
- Filters: `displayName eq "…"` and `externalId eq "…"`, which are what Entra and Okta send. `excludedAttributes=members` (Entra) and `attributes` leave `members` out. Anything else is 400 `invalidFilter`.

### Members are the tenant's own users

- A member's `value` is the SCIM id of a user **the same tenant** provisioned and hasn't deleted. Anyone else (a hand-made user, another tenant's) is 400 `invalidValue`. Email or `display` never identifies a member.
- One team per user still holds. Adding someone who is on another team, SCIM or not, is 409 `uniqueness`, with a hint to assign SuperBot only the groups that are teams. Overlapping groups (say, "All staff" and "Engineering") would otherwise make the second one win at random.
- A request is checked whole before anything changes: one bad member and nobody is added, removed or renamed.

### Adding and removing reuse joining and leaving

- **Adding** joins the person as ADR 0087 does: they're a `member`, offboarding runs with reason `joined_team` (people outside the team lose access both ways), runs that now cross teams stop, they get a machine, and a paying team's seats follow (ADR 0093). Audited as `team.member_joined` with `via: scim` and the token as the actor.
- **Removing** is leaving: grants between them and teammates are revoked, runs between them stop, ADR 0052 and 0066 offboarding runs with reason `left_team` (their OS users and accounts on teammates' machines go), the team's machine is released and destroyed after `TEAM_MACHINE_DAYS`, and seats follow. `team.member_left` has reason `scim_removed`.
- **The IdP wins over "a team keeps an owner".** ADR 0087 won't let a team's last owner leave while others are on it. For SCIM that rule would keep a leaver in, so a SCIM removal goes through regardless. The team may be left with no owner; server admins name one.
- **Someone disabled** can be added (Entra provisions disabled people and their groups). They join without a machine, and get it when the IdP enables them.
- **Deleting a user** (`DELETE /Users/{id}`) also takes them off their team if it is that tenant's group (reason `scim_user_deleted`). Disabling (`active: false`) doesn't: they stay listed, so the IdP can reactivate them, and they already lose access as any disabled user does.

### Idempotent by shape

IdPs retry. Every change is computed as "the members the group should have" and applied as the difference:

- `POST` with a `displayName` or `externalId` the tenant has already is 409, never a second team. Entra and Okta then look the group up by name and update it.
- `PATCH` adding someone already on it, or removing someone who isn't, changes nothing and records nothing. `PUT` replaces the members with the list sent.
- `externalId` can be set once, then never changes (400 `mutability`), as for users.
- `DELETE` twice is 404 the second time.
- Group writes run one at a time per server (a lock in the SCIM state), so a change's members are checked against the team it changes.

PATCH takes what Entra and Okta send: `add`, `replace` and `remove` (any case) of `members` (a list; `remove` with no value empties the group), `remove` of `members[value eq "<id>"]`, `add` or `replace` of `displayName` and `externalId`, and Okta's object of attributes with no path. Other attributes are ignored.

### SCIM never sets roles in a team either

Members join as `member`. SCIM sends no team role, and `roles` on users stays ignored (ADR 0023). A new SCIM team has no owner; a server admin makes one (`PUT /api/teams/{id}/members/{user} {"role":"owner"}`), and owners then choose admins as before. Owners and admins of a SCIM team manage its members' machines and roles, and its billing. Granting team admin is never an IdP attribute away, for the same reason granting server admin isn't.

### Only the IdP changes who's on its teams

The IdP's next sync would undo any other change, so `/api` refuses them on a SCIM tenant's team with 409 and "Change them in the identity provider": invites, accepting one, a team admin's remove, leaving, a server admin's add or remove, deleting the team, and renaming it. Role changes and the team's `machines` switch still work. Team views carry `scimTenant`, and the offboarding preview says `blocked: "scim"`, so the apps can say why.

### Deleting a group

Everyone leaves, as above (reason `scim_group_deleted`), then the team goes. A team that pays for a plan (ADR 0093) can't be deleted while its subscription runs. Its people still lose access at once: they're all removed, the team stays empty, and it is no longer the tenant's (`team.delete_refused` with `via: scim`, and `teamDeleted: false`). A server admin ends the plan, then deletes it. Seats drop to the minimum of one.

### Auth, limits and audit

- Same guard as users (ADR 0023, 0026): a live tenant token only, nothing else, and a SCIM token works nowhere else. Same rate limits and 64 KiB body cap (about 900 members in one request; Entra and Okta send member changes in smaller batches).
- New events, all with `targetType` `team`, the tenant, and the token as the actor: `scim.group_created`, `scim.group_updated` (with `changes`), `scim.group_deleted` (`membersRemoved`, `teamDeleted`). Joining, leaving and machines are the existing `team.*` events, with `via: scim` or the reasons above. Filter with `botctl audit --method scim_token`.

## Alternatives considered

- **Groups as roles.** Rejected again, as in ADR 0023: an IdP group shouldn't be able to make server or team admins. Teams carry no privilege beyond sharing within them.
- **Ignore members SuperBot doesn't know, or who are on another team.** Quieter for the IdP, but SuperBot would say "done" while the group and the team disagree, and the IdP wouldn't retry. A clear 400 or 409 shows up in the IdP's provisioning log.
- **Let the last group win** when someone is in two team groups. One team per user is what keeps sharing and machines simple; silently moving people between teams on every sync would churn their machines and grants.
- **Let admins edit SCIM teams by hand.** The IdP would undo it on the next sync, as it does an admin's disable (ADR 0023). Refusing up front is clearer.
- **Keep the last-owner rule for SCIM.** That would keep a leaver on the team, with their access, until a human stepped in. Deprovisioning wins.
- **Block deleting a paying team's group.** The IdP would retry forever while the people in it kept access. Removing them and keeping the empty team stops access and leaves billing to a person.

## Consequences

- With `SCIM_GROUPS=on`, a person added to a team group in Entra or Okta gets the team and a machine on the next sync; removed, they lose the team's Bots, their OS users on teammates' machines, and the team's machine, with no admin step.
- SCIM teams start without an owner until a server admin names one.
- Admins can't fix a SCIM team's members in SuperBot; they fix the group.
- One new table (`scim_groups`), in migration 39.

## Limits and follow-ups

- Nested groups aren't followed (Entra and Okta don't send them in SCIM).
- Google Workspace still needs Entra, Okta or a SCIM connector in front of it (ADR 0023).
- The client and console show `scimTenant` only through the refusals' messages; a "managed by your IdP" badge and hiding the invite and remove buttons on SCIM teams are follow-ups.
- No team role from the IdP (for example, a second "Engineering admins" group). If customers need it, it should map to team admin only, never owner or server admin, and get its own review.
