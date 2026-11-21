# 0088: Team screens in the client and the console

## Status

Accepted (21 Nov 2026). A follow-up on [#30](https://github.com/CG-Labs/superbot/issues/30) (M3, per-user isolation), on top of [ADR 0087](0087-team-accounts-and-machines.md) (team accounts and machines). The Expo client is the main interface ([ADR 0027](0027-expo-primary-hermes-default.md)); the console is a minimal admin fallback ([ADR 0032](0032-console-admin-only.md)). Offboarding is [ADR 0052](0052-teammate-offboarding-on-machines.md) and [ADR 0066](0066-removing-teammate-accounts-on-one-server.md); sharing under isolation is [ADR 0046](0046-shared-bots-under-isolation.md); teammates' accounts on one server are [ADR 0064](0064-teammate-accounts-on-one-server.md).

Numbering: open PR [#145](https://github.com/CG-Labs/superbot/pull/145) uses 0085, and 0086 is left for other open work, so this is 0088.

## Context

ADR 0087 shipped the team API with no screens. Team owners and admins need to see their people, roles and machine states; invite people; change roles; and take people off the team. Taking someone off a team does a lot: it revokes grants, stops runs, removes the leaver's OS users and accounts from teammates' machines, and suspends and later deletes their team machine. So the confirmation has to say exactly what will happen. Most of that depends on server settings (`TEAM_MACHINE_DAYS`, the teammate-files setting) and on the person (does the team own their machine?), which the apps couldn't see.

## Decision

### The client has a Team screen

- **Where it is.** `/team`, linked from the sidebar. The link only shows if you're on a team or have an invite, so self-hosted servers without teams look the same as before.
- **What members see.** The team, its people and their roles. This view is read-only. Read-only users ([ADR 0012](0012-users-sessions-rbac.md)) get the same view even when they're a team admin, because the server refuses their changes anyway.
- **What owners and admins see.** Each teammate's machine state (running, setting up, suspended, being built, couldn't be built, released). They can also:
  - invite people by email as member or admin;
  - cancel invites;
  - change roles (owners can give any role; admins can't make or unmake owners);
  - take a teammate off the team.
- **Confirmations.** Making someone an owner, changing your own role, leaving and joining all ask first.
- **Invites to you.** Someone on no team sees the invites waiting for them, and can join or decline.
- **Where the rules live.** The screen's rules are in `src/team.ts` and copy the server's, so it only offers what the server allows. The server still decides every change and the screen shows its refusals as they come.

### The apps ask the server what offboarding removes

There is a new route, `GET /api/team/members/{user}/offboarding`. It changes nothing, and it's for the team's owners and admins (`Account`, the same as reading the team). It answers:

- `allowed` and `blocked`: `self` (use leave) or `owner` (only owners remove owners);
- `grants`: how many grants between them and teammates end;
- `machine.fate`: `suspend` (with `days`), `destroy`, `kept` (a machine of their own) or `none`;
- `work`: what becomes of their work on teammates' machines and accounts (`archive` or `delete`, with grace days), or null when neither is on.

The client calls it when you press Remove, and builds the confirmation from the answer. Like the rest of `/api/team`, someone on another team gets 404, and so does anyone who isn't on the caller's team. The answer holds counts and settings only: no Bot names or ids, emails, addresses, files or logins. A grant count was the one thing considered and kept. Team admins can already see who is on the team, and the count is what makes "N grants are revoked" true rather than vague.

### The console has a Teams tab

Server admins get a minimal Teams tab on the existing `/api/teams` routes. It shows each team's people, roles and machine states. From it they can make a team, add someone (no invite needed), change a role, take someone off the team, and delete a team. The removal confirmation spells out the same offboarding from the server's settings. Team owners and admins use the client; the console is for server admins only, as before.

## Alternatives considered

- **Building the confirmation from `GET /api/team` alone.** That covers the machine's fate, but not the teammate-files setting or the grants. It would also leave the client to repeat the server's offboarding rules, and they would drift.
- **A per-member `can` block in `GET /api/team`.** That is more server truth on every read, but more data on every read too. The preview asks only when someone is about to act, and the server enforces on the action anyway.
- **Machine actions (give, suspend, resume) on the Team screen now.** The API has them. They were left for a later slice to keep this one focused on people and offboarding.

## Consequences

- Team owners and admins manage their team from the app without a server admin.
- People see what offboarding removes before it happens, worded from the server's own settings.
- The console keeps a fallback for server admins with no team-admin features, as ADR 0032 wants.

## Follow-ups

- Give, suspend and resume teammates' team machines from the Team screen.
- Team names set by the team's owners (today only server admins rename teams).
- Notifying people when they're invited or removed.
