# 0315: Bot handover under `bots.manage`

## Status

Accepted (26 Nov 2026). Part of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"): the third follow-up [ADR 0272](0272-advanced-rbac-delivered.md) ranked, deferred by [ADR 0123](0123-custom-roles.md). Builds on [ADR 0047](0047-disabled-users-routines.md) (a disabled user's routines, and handing their Bots over) and [ADR 0017](0017-bot-acls.md) (giving a Bot away). The second follow-up was [ADR 0311](0311-botctl-team-commands-for-owners.md).

0315 was set aside for this change.

## Context

When someone leaves, their Bots and routines need a new home. ADR 0047 gave that one route, `POST /api/users/{user}/handover {to, resumeRoutines?}` (`botctl user handover`): every Bot a disabled person owns goes to `to`, within `to`'s plan, and the routines they wrote move to `to` wherever `to` can run them. Only a server admin can call it.

`bots.manage` (ADR 0123) already covers the rest of that chore: a holder lists anyone's Bots and routines (`GET /api/users/{user}/bots|routines`) and resumes paused routines. So a helpdesk or IT lead given `bots.manage` can see what a leaver left and restart it, but has to ask an admin for the one step in between. Offboarding is the main delegated chore still left to admins. ADR 0123 deferred it because the handover needs a rule for what it may not reach.

What a handover moves is more than Bot settings: the Bot's chats and memory follow it to the new owner (ADR 0017), and it runs on the new owner's machine with their keys. So the question isn't only "may this person act on that person's Bots" but "may they decide who reads them next".

## Options

1. **Open the route to `bots.manage` as it is.** Simple, but a holder could take an admin's Bots, and their memory, for themselves or a friend, which no other delegable permission allows on admins' accounts.
2. **Open it to `bots.manage` with delegate limits**, as `users.manage` has (ADR 0123's `users::Delegate`).
3. **A new delegable permission, `bots.handover`.** Finer, but a seventh permission changes every roles editor, SCIM and SAML mapping rule, and the access review, for one route whose natural holders are exactly those who already list and resume the same Bots and routines.
4. **Leave it with admins.** Keeps offboarding with a server admin, which is what #53's custom roles exist to avoid.

We chose option 2.

## Decision

`POST /api/users/{user}/handover` moves from `admin` to `bots.manage` in `rbac::classify` (exact shape only; `GET` and longer paths stay admin). Admins are unchanged. Someone holding `bots.manage` but not the admin role hands over with every rule of ADR 0047 (from a disabled person only, 409 while active; to an active person who isn't read-only; within `to`'s Bot limit; routines only where `to` can run the Bot; paused unless `resumeRoutines`), and these limits on top, each a 403 audited as `access.denied` with `reason: "delegate_limit"`, the `limit`, and the person whose Bots they were (`user`):

| Limit | Refused when | Why |
|---|---|---|
| `service_account` | The caller is a service account's token | Deciding who reads a leaver's chats is a person's call. Service accounts never owned, gave or claimed Bots (ADR 0222, ADR 0229), and couldn't hand over before (it was admin-only, and they're never admin). |
| `protected_user` | The disabled person is an admin, the owner account, or holds a custom role across the server | The same people `users.manage` may not change (`Delegate::may_manage`). An admin's Bots may hold an admin's work; a delegate's may hold a delegate's. Taking them is an admin's call. |
| `primary_bot` | The disabled person owns the primary Bot | It's the Bot the server starts with and its owner's main point of contact, can't be deleted, and erasure refuses its owner too ([ADR 0102](0102-erasing-a-users-data.md)). Who holds it is an admin's call. The whole handover is refused, not the rest moved: a partial offboarding is easy to miss. |
| `self` | `to` is the caller | The person who picks who reads a leaver's Bots isn't the one who gets them, as team owners never give themselves roles (ADR 0254) or approve their own requests (ADR 0263). An admin, or another `bots.manage` holder, can hand them to them. |

The limits are checked after ADR 0047's own rules and before the plan check, so the answer to "is this person active" or "can `to` run Bots" is the same for everyone.

**Only from the person decided about.** The limits are checked once, before the Bots move one by one, and moving one can wait on its screen. If someone gives one of the remaining Bots to someone else meanwhile (an admin, to an admin), the handover must not take it from them on checks made about the leaver. So each Bot moves only while it still has the owner the caller read (`Db::move_bot`, one conditional `UPDATE`, inside the same stop that ends its work). A Bot that changed hands is left with its new owner, listed in `ownerChanged` in the reply and in `user.handed_over`, and the rest move as usual. This holds for admins too, and for giving one Bot away (`PATCH /api/bots/{id}/access {owner}`), which now answers 409 rather than take a Bot from an owner the admin didn't see.

A delegate's handover is audited as before (`user.handed_over`, `bot.owner_changed`, `routine.handed_over`, `routine.resumed`, `user.handover_refused`), with the delegate as actor, and `user.handed_over` and `user.handover_refused` carry `via: "bots.manage"`, so an auditor can tell a delegated handover from an admin's without reading the actor's role at the time. An admin's events don't carry `via`.

`bots.manage` stays in `rbac::REACHES_ADMINS`: listing admins' Bots and resuming routines on them still reach admins, so SCIM and SAML groups still can't give it. The handover itself doesn't reach admins.

`botctl user handover` already calls this route with the caller's token, so a holder signed in with `botctl login` uses it as is; its help says what a delegate may not hand over. `bots.manage`'s description in the roles editor says the same. The console and the app have no handover screen yet; that's unchanged.

## Alternatives considered

- **Skip the primary Bot and move the rest.** Leaves the leaver half offboarded, with a 200 that's easy to read as done. One refusal, naming the Bot, says what to ask an admin for.
- **Allow handing to yourself.** Common in small teams ("I'll take Ada's Bots"), but it's the one case where the person deciding also gains the leaver's chats and memory. The admin path is unchanged for that, and two delegates can hand to each other.
- **Refuse routines on admins' Bots.** A routine the leaver wrote on an admin's shared Bot moves to `to` only when `to` can already run that Bot, so `to` could have written it themselves; nothing new is reached. Left as ADR 0047 has it.
- **Let team owners hand over their team's leavers' Bots.** `bots.manage` isn't a team permission (ADR 0123), and Bots aren't owned by teams. That's a separate choice, with ADR 0272's per-role switch for what teams may give.

## Consequences

- A helpdesk, IT or offboarding role (`member` + `bots.manage`, or a time-bound one asked for and approved, ADR 0209) offboards a leaver's Bots and routines end to end without a server admin: list, hand over, resume.
- An admin's, the owner's, a custom-role holder's and the primary Bot's handovers stay with admins, as does handing to yourself.
- No migration, setting or new event. Clients that read `user.handed_over` see a new optional field, `via`, and a new list, `ownerChanged` (empty unless a Bot changed hands during the handover), which the reply carries too.
- Giving one Bot away answers 409 when its owner changed since the request read it.
- ADR 0272's remaining follow-ups are unchanged and not started: two approvers for chosen roles, handing several Bots to a service account at once, and a per-role switch for what teams may give.

## Tests

- `rbac` unit tests: `every_route_is_classified` (`POST /api/users/{user}/handover` is `bots.manage`, by id or email; `GET` and a longer path stay admin).
- `handover_http_tests.rs`, on the real router:
  - `someone_with_bots_manage_hands_a_disabled_persons_bots_on_without_an_admin`: a plain member is refused; a holder can't hand to themselves (audited `self`, nothing moved) and gets ADR 0047's 409 for an active person; a handover to someone else with `resumeRoutines` moves the Bot, makes the routine theirs and running, and is audited with the holder as actor and `via: "bots.manage"`; an admin's handover carries no `via`.
  - `bots_manage_never_hands_over_an_admins_a_custom_role_holders_or_the_primary_bot`: each refused with its limit and nothing moved, not even the primary Bot's owner's other Bots; an admin then hands each over.
  - `a_service_account_with_bots_manage_hands_nothing_over`: its token lists the leaver's routines but is refused the handover (`service_account`, naming the leaver).
  - `a_bot_that_changed_hands_meanwhile_stays_with_its_new_owner`: moving a Bot on a stale read of its owner is a 409 and leaves it with its new owner, with no plan refusal recorded.
- `db` unit test: `move_bot` does nothing when the Bot's owner isn't the one given, and still keeps the plan's cap.
- ADR 0047's tests are unchanged and pass: a plain member is still refused, admins' handovers are as before.
