# 0320: Two approvers for chosen roles

## Status

Accepted (26 Nov 2026). Part of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"): the fourth follow-up [ADR 0272](0272-advanced-rbac-delivered.md) ranked, deferred by [ADR 0209](0209-requests-for-time-bound-roles.md). Builds on ADR 0209 (requests for time-bound roles), [ADR 0263](0263-team-owners-decide-requests-for-team-roles.md) (team owners decide their team's requests) and [ADR 0302](0302-team-owners-hear-of-requests-for-team-roles.md) (who hears about a request). The third follow-up was [ADR 0315](0315-bot-handover-under-bots-manage.md).

0320 was set aside for this change.

## Context

A request for a time-bound role (ADR 0209) is given by one approver who isn't the asker: a server admin, or, for a team request, the team's owner or admin (ADR 0263). That meets the usual control, and ADR 0209 kept it at one because most self-hosted teams have one or two admins.

Some roles reach much further than others. `machines.manage` runs commands on every computer; `users.manage` across the server resets other people's sign-in. Security teams often want two people to agree before anyone gets those, even for a few hours (four-eyes, or "two-person rule"). With one approver, a single compromised or careless admin account can give them. ADR 0272 ranked this as the next follow-up of #53 after Bot handover, and sketched the shape: a per-role `approvals: 2` on the same requests, the second approval giving the role, both approvers in `role.request_approved`.

Of #53's three remaining follow-ups, this is the one that closes a control gap auditors ask about (SOC 2 CC6.2/CC6.3, ISO 27001 A.5.18: privileged access approved by more than one person). The other two (handing several Bots to a service account at once, a per-role switch for what teams may give) are conveniences or narrowings of what's already safe.

## Options

1. **A per-role `approvals` of 1 or 2, on the existing requests.** One new field, one new state inside `pending`, no new routes.
2. **Any quorum (`approvals: N`), or named approver groups.** More general, but every extra step needs more admins than most installs have, and a list of approvals is harder to audit and explain than "first" and "second".
3. **A server-wide switch: every request needs two.** Simpler to explain, but it forces two approvers on low-risk roles (a read-only auditor for a day), which is what ADR 0209 warned would stall small teams.
4. **Two approvers on hand-given roles too** (`POST /api/roles/:id/users`). An admin can already make themselves or anyone admin; a two-person rule on direct grants needs a pending-grant flow of its own. Out of scope: requests are where a role is given to someone who asked for it, and where the control is expected.

We chose option 1.

## Decision

**Per role.** A custom role has `approvals`, 1 (the default, as before) or 2, set by an admin on create or edit (`POST`/`PATCH /api/roles`, the roles editors in the console and the app, `botctl role add|edit --approvals 1|2`). It's stored on the role (`roles.approvals`, `CHECK (approvals IN (1, 2))`), written in the same transaction as the role's other fields on edit and before the role becomes requestable on create, so no request is approved under new permissions with the old count. Only requests read it: giving the role by hand, SCIM and SAML group rules are unchanged. `role.created` and `role.updated` record it.

**Only when it can be met.** Setting `approvals: 2` is refused (409) while fewer than two active admins who aren't service accounts exist, as no request for it could then be given across the server. The operator's break-glass account counts: it's an admin who can approve. Lowering it is always allowed.

**The first approval.** On a role needing two, the first approval (`POST /api/role-requests/:id/approve` or `/api/team/role-requests/:id/approve`) is saved on the request (`first_by`, `first_at`, `first_hours`, `first_note`) and the request stays `pending`. Nothing is given. The reply is `{request, role: null, applies: [], approvals: {needed: 2, given: 1}}`, and the request's views (`GET /api/role-requests`, `/api/team/role-requests`, `/api/me/role-requests`) show `approvals` and `firstApproval: {by, at, hours, note, counts}`. It's audited as `role.request_first_approved` (`request`, `name`, `user`, `scope`, `team`, `hours`, `requestedHours`, `note`, `approvals`, and `via: "team"` for a team owner's or admin's). The approver may pick fewer hours than asked, as before.

**The second approval** gives the role, as one approval did before, with these rules on top:

| Rule | Answer | Why |
|---|---|---|
| A different person | 409 for the first approver | Two approvals by one person are one. |
| For the first approval's hours or fewer | 400 above them | Both people agreed to the shorter time; the longer was never agreed by two. Omitting `hours` gives the first's. |
| By anyone who may decide it | | An admin, or for a team request the team's owner or admin, as ADR 0263. Mixed is fine: a team owner first, an admin second, or the other way round. |

`role.request_approved` and `role.assigned` gain `approvers: [first, second]`, and `role.request_approved` carries `firstApproval` (`by`, `at`, `hours`, `note`). The reply's `approvals` is `{needed: 2, given: 2}`.

**A first approval counts only while its approver could still give it.** Between the two approvals, the first approver may be disabled, lose admin, leave the team, become the team's plain member, or be erased. Each approval re-reads the first approver, in the same transaction that decides, and counts the first approval only if that person could approve the request now: active, not a service account, not the asker, and an admin, or for a team request one of the team's owners or admins whose team role isn't managed by the IdP and whose asker is a plain member (`role_requests::first_counts`, the same checks as approving). A first approval that no longer counts is replaced by the current one, which becomes the new first: the request stays pending, and `role.request_first_approved` carries `replaced: {by, at, hours}`. So a role is never given on the say-so of someone who has since lost the right to give it. The views say so ahead of time: `firstApproval.counts` is the same check on what an approval now would read (`Db::first_approval_counts`), so clients offer the asked hours again and call the next approval the first.

**Read at each approval.** `approvals` is read when each approval is made, not when the request was asked. Raised to 2 while a request waits, its next approval is the first. Lowered to 1 after a first approval, the next approval gives the role on its own (within the asked hours, as before); the first approval stays in the audit log. Lowering doesn't give anything by itself.

**Denying, lapsing, withdrawing are unchanged.** Any decider may deny a request at any point, the first approver too; one denial ends it. A request still lapses 7 days after it was asked, first approval or not, and the asker can withdraw it.

**Who hears.** A first approval notifies those who could give the second, through ADR 0302's channels: the server's request list and webhook, and, for a team request, the team's other deciders by email and push. The first approver isn't told. The push reads "A request on {team} needs a second approver." The asker sees "Approved once, waiting for a second approver" in their requests.

**Erasure** pseudonymises `first_by` with the rest of a person's audit trail ([ADR 0102](0102-erasing-a-users-data.md)); an erased first approver no longer counts.

**Clients.** The roles editors have "Needs two approvers", only for a requestable role (and cleared when a role stops being requestable). Request rows show the first approval and offer the first approval's hours or fewer, or, when it no longer counts, say so and treat the next approval as the first; the first approver sees "You gave the first approval. Someone else gives the second." instead of Approve, and can still deny. "Approve (1 of 2)" and its confirmation say nothing is given yet. The asker's card says a role needs two approvers before they ask. `botctl role approve` says when it gave the first approval.

## Alternatives considered

- **Count a first approval as given, whatever happens to its approver.** Simpler, but a disabled admin's approval would still give a role a week later, which is the gap two approvers exist to close.
- **Cancel the request when the first approver can no longer approve.** Makes the asker start over for something they didn't do. Replacing the first approval keeps the request and still needs two current approvers.
- **Leave out the break-glass account when checking for two admins.** It's often the second admin on a small install; leaving it out would refuse the setting there. It approves with full audit like any admin.
- **Let the second approver pick more hours than the first.** Then only one person agreed to the longer time.
- **Give the role at once when `approvals` is lowered with a first approval waiting.** A role change would grant access without anyone approving at that moment. The next approval gives it instead.
- **Ask for two on team requests only from the team.** A team with one owner and no admin would be stuck; admins already decide team requests (ADR 0263).

## Consequences

- An admin can require two people to agree before `machines.manage`, `users.manage` or any other requestable role is given, without a new route, permission or setting.
- Roles with `approvals: 1` (all existing ones) behave exactly as before.
- A small install with one admin can't use it until it has two. The setting says why.
- New migration (`roles.approvals`, four `role_requests` columns), new event `role.request_first_approved`, new optional fields in requests' views and in `role.request_approved`, `role.assigned`, `role.created` and `role.updated`. `GET /api/compliance/evidence` lists each custom role's `approvals`.
- ADR 0272's remaining follow-ups are unchanged and not started: handing several Bots to a service account at once, and a per-role switch for what teams may give.

## Tests

- `role_request_approvals_http_tests.rs`, on the real router:
  - `a_role_needing_two_approvals_is_given_only_by_a_second_approver`: `approvals: 2` is refused with one admin; the first approval keeps the request pending, gives nothing, is audited and shown to the asker; the same approver can't give the second (409), nor can anyone approve above the first's hours (400); the second gives the role for the first's hours and records both approvers; one-approver roles are unchanged.
  - `a_first_approval_counts_only_while_its_approver_could_still_approve`: an approver who lost admin no longer counts and is replaced (audited `replaced`); the first approver may deny; lowering to one lets the next approval give it; raising to two with one admin left is refused.
  - `team_owners_and_admins_give_either_approval_within_their_team`: a team owner first and an admin second, or the other way round; not both by one person; a team admin who has since become the team's plain member no longer counts and is replaced.
  - unit `a_first_approval_counts_for_admins_and_the_teams_deciders_only`: `first_counts` across roles, team roles, IdP-managed team roles, disabled, service and asker.
- `team_role_requests_http_tests.rs`: `a_first_approval_tells_the_others_who_may_give_the_second` (the team's other deciders are told by email and push, the first approver isn't).
- `db` unit tests: `a_first_approval_is_saved_and_its_erased_approver_no_longer_counts`, and `a_roles_approvals_are_saved_with_its_other_fields_or_not_at_all`.
- `evidence_http_tests.rs`: custom roles carry `approvals`.
- `botctl` unit tests: `--approvals` on `role add|edit`, and the first-approval message.
- Client: `roles.test.ts` (draft, cap, labels), `RolesAdmin.test.tsx` (the checkbox, first and second approval, the first approver can't give the second, the picked hours capped again when a reload brings a shorter first approval), `RoleRequestsCard.test.tsx` (the asker sees two approvers are needed and where a request is).
