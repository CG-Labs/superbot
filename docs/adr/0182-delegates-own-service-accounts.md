# 0182: A delegate's own service accounts, in the app and within their team

## Status

Accepted (23 Nov 2026). Eighth slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0143](0143-service-accounts.md) (service accounts), [ADR 0152](0152-service-accounts-in-the-apps.md) (service accounts in the apps) and [ADR 0170](0170-service-accounts-granted-bots.md) (service accounts granted Bots). Follows [ADR 0123](0123-custom-roles.md) (custom roles and their delegates) and [ADR 0087](0087-team-accounts-and-machines.md) (teams).

0182 was set aside for this change; other open pull requests hold 0172, 0174, 0177, 0179, 0180, 0181, 0183 and 0184.

## Context

ADR 0143 lets anyone whose role holds `users.manage` (a delegate) manage the service accounts they own, through the API and `botctl`. ADR 0152 kept them out of the app: the screen sat with the admin screens, and a delegate's list would look like everyone's. Its form also read every role (`GET /api/roles`) and team (`GET /api/teams`), both admin-only, so a delegate couldn't have filled it in. They had to use a shell.

There was also a gap. A delegate could put a service account in any team, even one they weren't on. The account then reached none of that team's Bots (ADR 0170 caps Bots by its owner), but team routes treat a team's service account as one of the team. Its token could read that team's page (`GET /api/team`: name, members, their roles) even though its owner couldn't. That breaks ADR 0143's rule: never more than its owner.

## Decision

### Within its owner's team

- **When it's made or moved**, a delegate can put a service account only in the team they're on. Anything else is refused: 403, logged as `access.denied` with `reason: "delegate_limit"`, `limit: "service_account_team"` and the team. An admin can put one in any team. A delegate can still rename an account whose team they've since left. They just can't move it into another team.
- **On every request**, a team's service account counts as one of the team only while its owner is an admin or on that team. Otherwise it acts in no team, so team routes answer 404, as they do for a person in none. An owner who leaves the team takes this with them at once, as ADR 0170 already does for Bots. An admin handing one to someone off its team is allowed, and capped this way.
- Each account's views get `ownerOnTeam`: whether its owner is an admin or on its team, or `null` when it's in none.

### What a caller may give

`GET /api/service-accounts` gets two fields:

- `view`: `all` for admins, `own` for a delegate, so the app can say whose list it is.
- `choices`: what the caller may give a service account they own, worked out by the same check `POST` makes, without logging anything:

```json
{
  "roles": [{ "id": "readonly", "name": "Read-only", "base": "readonly", "builtIn": true, "permissions": [] },
            { "id": "r1", "name": "Help desk", "base": "member", "builtIn": false, "permissions": ["users.manage"] }],
  "server": ["readonly", "member", "r1"],
  "teams": [{ "id": "t1", "name": "Ops", "roles": ["readonly", "member", "r1"] }]
}
```

`server` lists the roles allowed across the server. `teams` lists the teams the caller may use: every team for an admin, their own for anyone else. Each team comes with the roles allowed there, never a read-only custom role, since `POST` refuses that in a team. `roles` names only the custom roles that appear somewhere in those lists, with their base and permissions. A delegate learns the roles they could give, not every role on the server. Admins get every role but admin, and every team.

### In the app

- The **Service accounts** screen is open to admins and to anyone whose permissions include `users.manage`. For a delegate the sidebar entry and the screen are titled **Your service accounts**, and the list is the ones they own, as the server sends it.
- The forms offer only what `choices` holds: the roles allowed where the account goes, and the teams the caller may use. Changing the team changes the roles offered. An account's own role and team stay in the pickers when they're no longer offered, so it can still be renamed. Saving a role or team that isn't offered is blocked with the reason. The server checks everything again.
- Only admins see the owner field. A delegate whose account's owner is inactive is told to ask an admin.
- An account whose owner isn't on its team is flagged ("owner off its team"), and its page says it acts in no team until they are.
- A server from before this change sends no `choices`. An admin's form then reads every role and team as before; a delegate gets the built-in roles across the server.

The console stays admin-only (ADR 0032), and `botctl` is unchanged.

## Alternatives considered

- **Open `GET /api/roles` and `GET /api/teams` to delegates.** They'd see every role and team, including ones they can't give, and the app would have to copy the server's rules to filter them. `choices` comes from the same check as `POST`, so the two can't drift.
- **A separate screen for delegates.** It would duplicate the token, rotate and revoke flows, which must behave the same for both. One screen with the server's list and choices keeps one code path.
- **Refuse admins too when the owner isn't on the team.** ADR 0170 lets an admin hand an account to anyone and caps what it reaches instead. Doing the same for team membership keeps that rule, and `ownerOnTeam` shows the result.
- **Leave the team check to the runtime cap.** A delegate could still make accounts that do nothing, and wouldn't learn why. Refusing at the time says so, and the cap still covers later changes.

## Consequences

- Delegates manage their own service accounts and tokens in the app, without a shell. Admins' screen is unchanged except that it uses `choices` too.
- A team's service account never sees a team its owner can't. One case reaches less than before: a team's account whose owner isn't an admin and isn't on the team no longer gets `GET /api/team` or other team routes. Accounts made by admins, and by people on their own team, are unchanged.
- Each `GET /api/service-accounts` works out `choices` from the custom roles and the caller's team: one read each, and an in-memory check per role.
- Still to do for #53: service accounts owning Bots. That needs a rule for whose machine, plan, keys and memory a service account's Bot uses, and touches the machine code throughout. The access review could also flag an account whose owner is off its team.
