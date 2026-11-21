# 0087: Team accounts, each teammate on a machine of their own

## Status

Accepted (21 Nov 2026). The last item on [#30](https://github.com/CG-Labs/superbot/issues/30) (M3, per-user isolation): team accounts and machines. It builds on the one-machine-per-user control plane of [ADR 0025](0025-control-plane-linode.md), its Incus containers ([ADR 0065](0065-incus-container-machines.md)) and placement ([ADR 0081](0081-placing-machines-by-host-load.md)). It narrows sharing as decided in [ADR 0046](0046-shared-bots-under-isolation.md) and reuses the offboarding of [ADR 0052](0052-teammate-offboarding-on-machines.md) and [ADR 0066](0066-removing-teammate-accounts-on-one-server.md). Teammates' OS users, logins, accounts and run tokens ([ADR 0048](0048-teammates-own-os-user-on-machines.md), [0062](0062-teammate-harness-logins.md), [0064](0064-teammate-accounts-on-one-server.md), [0083](0083-per-run-tokens.md)) don't change.

Numbering: `main` has up to 0084, and open PR [#145](https://github.com/CG-Labs/superbot/pull/145) uses 0085. Other open work may take 0086, so this is 0087. Renumber it if a collision appears at merge.

## Context

Before this change:

- One botd was one org. "Shared" meant everyone on the server, and a grant could name anyone on it.
- Each user could have one machine (ADR 0025, decision 1). Only server admins could request, suspend or resume one, and those routes also show addresses, provider errors, screens, logins and folder sync.
- There was no team entity. ADR 0052 listed "leaving a team" as one more event its offboarding should handle.

On the managed tiers, one server holds several customers' teams. Teams need their own admins, who manage their people's machines. They must not see into those people's data. And nothing may cross from one team to another.

## Decision

### Each teammate keeps a machine of their own

A team member gets their own machine, not an OS user on a shared team machine. The existing ADRs all point this way:

- **One computer per user** is ADR 0025's first decision, and the roadmap's M3 goal. The machine is the isolation boundary. Billing (ADR 0040), backups and RPO (ADR 0074), resize and placement (ADR 0081) are all per user and per machine.
- **The agent is root and serves one owner.** Each machine's certificate names one user (ADR 0031). The agent runs that owner's Bots as the Bots' OS user (ADR 0043). If one machine held several owners, every team member's Bots would be at the mercy of one agent and one root.
- **OS users are a weaker wall.** ADR 0048 gives teammates their own OS user on an owner's machine, but only for runs of that owner's shared Bots, and it lists what they still share: the kernel, `/tmp` limits, the network, and the screen server. That is fine for a teammate borrowing a Bot. It isn't fine as the only wall between people's whole workspaces, logins and secrets.
- **Leaving stays clean.** A leaver's machine is theirs alone: suspend it, then destroy it, with no files to pick out of a shared disk.

A shared team machine would be cheaper on idle hosts. Incus containers (ADR 0065) already make a machine per user cheap, and placement (ADR 0081) packs them by load. So the saving isn't worth the weaker wall.

### Teams live in the control plane

Teams are control-plane data in botd's database, next to users, roles and billing:

- `teams` holds a name and `machines` (whether joining gives a machine; on by default).
- `team_members` holds the user, the team and the role in it: `owner`, `admin` or `member`. A user is on one team at most, and deleting a user removes them.
- `team_invites` holds an email and a role, and expires after 7 days.
- `team_machines` records which machines a team gave which members, and when a released one is due to go.

None of it is stored on machines. A machine and its agent still know only their owner.

### Sharing reaches only the team

`acl::access` takes whether the Bot's owner and the user are on the same team:

- Off the team, a non-admin gets nothing: not a shared Bot, and not a grant, even one already in the database.
- `PUT /api/bots/{id}/grants/{user}` refuses a user on another team. A server admin gets 409; anyone else gets 404, as if the user weren't there. Both are audited as `bot.access_refused` with reason `other_team`.
- Server admins keep full access, as before.

People in no team are handled by `TEAMS`:

- **`TEAMS=off`** (default): they share with each other as before. A self-hosted server with no teams behaves exactly as it did.
- **`TEAMS=on`**: no team is a team of one, so their shared Bots reach nobody. Managed servers should set this.

Because every check goes through the ACL, everything ADR 0046, 0048, 0062, 0064 and 0083 built on it follows: Bot lists, chats, routines, screens, asks between Bots, teammates' OS users, teammates' harness logins and accounts, and run tokens.

### Team admins manage machines, not data

A team's owners and admins (`/api/team`) can:

- see each member's machine: state, tier, region, enrollment, last agent heartbeat, whether it's placed, backups and the last backup, and when a released one goes;
- give a member a machine (`POST /api/team/members/{user}/machine`), and suspend or resume one the team gave (`.../suspend`, `.../resume`);
- invite people, change roles, and take members off the team.

They never see a machine's address, provider ids, errors, files, logins or screens, and they don't get a teammate's Bots, chats, secrets or folder sync. Those stay behind the ACL and the server admins' `/api/users/...` routes.

A machine a member already has of their own stays theirs: team admins get 403 on it. Anyone off the team is not found (404), so one team's admins learn nothing about another team's people.

Machine actions run through the same code as the server admins' routes (`machines::request_as`, `act`), audited with the team admin as actor and the member as `onBehalfOf`. Every team route refuses Bot tokens and needs `write` (or `account` to read). Read-only users can see their team but change nothing.

Server admins manage every team under `/api/teams`, as `rbac::classify` already leaves anything unlisted to admins.

### Joining provisions; leaving offboards and releases

**Joining** (an accepted invite, or `PUT /api/teams/{id}/members/{user}`):

1. adds the member;
2. runs ADR 0052 and 0066 offboarding with reason `joined_team`, since people outside the team lose access both ways;
3. stops runs that now cross teams;
4. gives them a machine, if the team has `machines` on and they have none. This uses the same request path as admins, at the default tier. A machine they kept from a team they left is resumed and taken back, not replaced.

Once that machine is running and enrolled, the reconciler places it (`placement.assigned` with reason `team`) when `MACHINE_ROUTING` isn't off, so their Bots move there with no admin step.

**Leaving** (`POST /api/team/leave`, a team admin's remove, an admin's remove, or deleting the team), in order:

1. Grants between the leaver and their former teammates are revoked (`bot.access_revoked`, reason `left_team`), and runs between them stop.
2. ADR 0052 and 0066 offboarding runs with reason `left_team`. The leaver's user goes from teammates' machines and accounts, and teammates' users go from theirs. Their work is archived to the owner as before.
3. The machine the team gave them is suspended at once and destroyed after `TEAM_MACHINE_DAYS` (default 7, 0 to 365; 0 destroys it at once). The reconciler does the destroying. Joining a team again before then keeps it.

A team always keeps an owner. Its last owner can't leave or be demoted while others are on it. Only owners make or remove owners. A team whose last member leaves is deleted.

### Audit

Every change is audited with `targetType` `team`:

- `team.created`, `team.updated`, `team.deleted`;
- `team.invited`, `team.invite_cancelled`, `team.invite_declined`;
- `team.member_joined`, `team.role_changed`, `team.member_left`;
- `team.machine_requested`, `team.machine_kept`, `team.machine_failed`, `team.machine_released`, `team.machine_destroyed`.

## Alternatives considered

- **One shared machine per team, an OS user per member.** Rejected for the reasons above: one root and one agent for everyone, a weaker wall (ADR 0048's limits), and per-user billing, backups and offboarding would have to be split up.
- **A botd per team.** It isolates fully, but costs a server per customer and leaves the control plane split across many databases. Teams in one control plane, with machines per user, keep one place for billing and placement.
- **Teams only as a label, with sharing still server-wide.** That's simpler, but one customer's shared Bot would reach another's people. Sharing has to stop at the team.
- **Team admins with server-admin machine routes.** Those routes show addresses, provider errors, screens and logins. A separate, data-free view is safer than filtering the admin one.

## Consequences

- Managed servers can host several customers' teams: nothing is shared across them, and each team has its own admins.
- Self-hosted servers with no teams see no change. With `TEAMS=on`, people in no team share with nobody.
- Joining a team cuts sharing with people outside it, and offboarding cleans up after that as it does for any lost access.
- The control plane provisions and releases team machines on its own. A released machine costs money while it's suspended, for up to `TEAM_MACHINE_DAYS`.

## Limits and follow-ups

- No console or client screens yet: the API is ready, with `GET /api/team` and `GET /api/me/team-invites` for the apps.
- Billing is still per user (ADR 0040). A team-level plan that pays for members' machines is future work.
- Invites match a user's email. Someone with no account yet signs up first (or is provisioned by SCIM), then accepts.
- SCIM groups don't map to teams yet.
- Team machines use the default tier and region. Team admins can't resize; server admins can.
