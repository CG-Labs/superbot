# 0311: `botctl team` commands for team owners and admins

## Status

Accepted (26 Nov 2026). Part of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"): the second follow-up [ADR 0272](0272-advanced-rbac-delivered.md) ranked, on top of [ADR 0254](0254-team-owners-give-custom-roles-in-their-team.md) (team owners give custom roles in their team) and [ADR 0263](0263-team-owners-decide-requests-for-team-roles.md) (they decide their team's requests for roles).

0311 was set aside for this change; other open pull requests hold 0306 and 0310.

## Context

Since ADR 0254 and ADR 0263, a team's owners and admins give and take custom roles in their team, and decide its requests for them, without a server admin. But only the app's Team screen and raw API calls do it. `botctl role assign|unassign --team` and `botctl role requests|approve|deny` call the server admins' routes (`/api/roles/...`, `/api/role-requests/...`), which refuse a team owner with a bare 403. So the scripted path ADR 0254 and ADR 0263 deferred is missing, and the error doesn't say what to use instead.

The routes exist, with every check in the server: `PUT|DELETE /api/team/members/{user}/custom-role`, `GET /api/team/role-requests`, and `POST /api/team/role-requests/{id}/approve|deny`. `GET /api/team` already gives owners and admins `roleChoices` (what they may give) and `roleRequests` (how many wait).

## Options

1. **New `botctl team` commands** on the team routes, beside the admins' `botctl role` ones.
2. **A flag on `botctl role`** (`--as-team`, or reading `--team` as "use the team route" for non-admins).
3. **Fall back on 403**: `botctl role` tries the admin route and, when refused, retries the team route.

We chose option 1. The team routes take different arguments from the admin ones: no team (it's always the caller's own), a teammate rather than a role and a team for taking one away (a teammate holds at most one team role), and no scope for requests. One command with two meanings would need rules about which flags apply when. Option 3 sends a write twice, hides which authority acted (the audit says `via: "team"` either way, but the person at the shell wouldn't know which rules applied), and turns every typo in an admin command into a second request. Instead, when a `botctl role` command a team owner would reach for is refused with 403, `botctl` says which `botctl team` command does it in their own team.

## Decision

`botctl` gains, for anyone signed in with `botctl login` (the server decides who may):

| Command | Route |
|---|---|
| `botctl team` | `GET /api/team` |
| `botctl team roles` | `GET /api/team`, printing `roleChoices` and `roleRequests` |
| `botctl team role assign <role> <user> [--for <n>h\|<n>d] [--reason TEXT]` | `PUT /api/team/members/{user}/custom-role` `{role, expiresAt?, reason?}` |
| `botctl team role unassign <user>` | `DELETE /api/team/members/{user}/custom-role` |
| `botctl team requests [pending\|approved\|denied\|cancelled\|lapsed\|all]` | `GET /api/team/role-requests[?status=]` |
| `botctl team approve <request> [--for <n>h\|<n>d] [--note TEXT]` | `POST /api/team/role-requests/{id}/approve` `{hours?, note?}` |
| `botctl team deny <request> [--note TEXT]` | `POST /api/team/role-requests/{id}/deny` `{note?}` |

- **The same words as `botctl role`.** `assign <role> <user>`, `--for` (1 hour to 365 days, as hours or days), `--reason` and `--note` read as they do there, and print the same lines ("ada@example.com has Team helpdesk in Ops. There it gives: users.manage.", "Approved. ... until ..."). Unknown flags, and flags without a value, are refused before anything is sent.
- **`botctl team roles`** lists the roles the caller may give, each with what it adds in a team and a time-bound role's day limit, and how many requests wait. People who can't give roles are told to ask an owner or admin, or to request one. It reads `GET /api/team`, so no new route.
- **A pointer on refusal.** When `botctl role assign|unassign ... --team`, `role requests`, `role approve` or `role deny` is refused with 403, the error adds the `botctl team` command that does it in the caller's own team. Other failures, and other `role` commands, are unchanged.
- **Nothing in the server changes.** No route, check, setting or audit event is added. The team routes keep every rule of ADR 0254 and ADR 0263: plain members only, never yourself, never over a role from the IdP, rechecked in one transaction on approval, audited with `via: "team"`.
- `botctl team region|residency <team>`, the server admins' commands, are untouched.

## Alternatives considered

- **`botctl team role assign <user> <role>`**, matching the route's shape. Rejected: one order for both `role assign` and `team role assign` is easier to remember than one per route.
- **`botctl team role unassign <role> <user>`**, as `role unassign` takes. The route takes no role, since a teammate holds at most one in the team; asking for one would only add a way to be wrong.
- **A text summary for `botctl team requests`.** `botctl role requests` prints JSON, which scripts read; the team one does the same. `botctl team roles` is the summary for people.
- **Team member and invite commands** (`botctl team invite|remove|set-role`). Useful, but not RBAC, and ADR 0272 didn't propose them. They'd follow the same shape.

## Consequences

- A team's owners and admins give, change and take away roles in their team, and decide its requests, from a shell or a script, with the token `botctl login` prints.
- As with every `botctl` command that sends a token, it goes only to `botd` on the same machine, or through an SSH tunnel on 127.0.0.1. Team owners without shell access to the server keep using the app's Team screen; lifting that limit for all of `botctl` is a separate choice.
- A team owner who reaches for `botctl role` learns which command to use instead, rather than only seeing 403.
- No upgrade steps: an older `botd` has the same routes since ADR 0263.
- ADR 0272's remaining follow-ups are unchanged and not started: Bot handover under `bots.manage`, two approvers for chosen roles, handing several Bots to a service account at once, and a per-role switch for what teams may give.

## Tests

- `botctl` unit tests: `team_commands_use_the_team_screens_routes` (every command's method, path and body, `--for` in hours and days, and the refusals: a missing user, a stray `--team`, `--for` without a unit or of zero, a flag with no value, a role on `unassign`, unknown flags); `team_roles_lists_what_an_owner_may_give` (roles with what they add and a day limit, one or several requests waiting, none to give, and someone who can't give roles); `a_refused_admin_role_command_points_team_owners_at_botctl_team` (only a 403, only on the commands a team owner would reach for).
- `server/tests/botctl_team_roles.rs`, end to end with the real `botd` and `botctl` binaries: a team owner signs in with `botctl login` and a one-time code; `botctl team roles` lists only roles that add something in a team; `team role assign` gives one with a reason (audited with `via: "team"` and the owner as actor) and `team role unassign` takes it away; giving one to themselves, one with no team permission, or past a time-bound role's limit is refused; `botctl role assign --team` and `role requests` are refused with the pointer; two teammates request a role in the team, the owner sees both, approves one for fewer hours with a note and denies the other, and a decided one can't be decided again; a plain member is refused `team requests` and `team deny`; the audit log records both decisions with `via: "team"` and the owner as actor.
