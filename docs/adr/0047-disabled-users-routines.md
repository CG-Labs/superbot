# 0047: A disabled user's routines: pause, refuse, hand over

## Status

Accepted (20 Nov 2026). Fixes SCIM-05 in the [SCIM review](../security/auth-review-2026-11-scim.md) (Low, accepted for M2), the follow-up named in [ADR 0029](0029-per-user-isolation.md) and [ADR 0046](0046-shared-bots-under-isolation.md). Builds on [ADR 0012](0012-users-sessions-rbac.md) (users, disabling), [ADR 0017](0017-bot-acls.md) (Bot owners, giving a Bot away), [ADR 0023](0023-scim.md) / [ADR 0026](0026-scim-review-hardening.md) (SCIM deprovisioning) and ADR 0046 (a routine runs for whoever wrote it). 0046 was the highest number on `main`; no open branch uses 0047.

## Context

Disabling a user (admin API or portal, `botctl user disable`, SCIM `active: false` or `DELETE`) ended their sessions, but the scheduler didn't look at people at all. What we found in the code:

- **`SHARED_BOTS=open`** (the self-host default): a disabled owner's routines fired and ran on schedule, attributed to them (`onBehalfOf`), with their keys and facts. So did a routine a disabled user wrote on someone else's Bot.
- **`SHARED_BOTS=isolated`**: the runner refused each run (`bot.run_refused`, `owner_disabled` or `asker_lost_access`), but the routine kept firing every time: a `routine.fired` event, a routine run taken from the owner's daily limit and given back, and a queued message each time.

A leaver's scheduled instructions shouldn't keep running in their name. But a leaver's Bots often serve a team, so the routines shouldn't just be deleted.

## Decision

### Disabling pauses, with a reason

When a user is disabled, by any path, botd pauses every **enabled** routine that runs on their behalf:

| Routine | Reason |
|---|---|
| On a Bot they own | `owner_disabled` |
| Written by them (`author_id`, ADR 0046) on someone else's Bot | `author_disabled` |

Pausing turns the routine off (`enabled = false`) and records `paused_reason`, `paused_for` (the disabled user) and `paused_at` (migration 19). A routine that was already off stays as it was, unmarked, so it's never turned on by a later resume. Turning a routine on or off by hand clears the marks.

One path does it: `handover::user_disabled`, called from the admin `PATCH /api/users/:id` (which `botctl` and the portal use), SCIM's `active: false`, and SCIM's `DELETE`. At every start botd also runs it for each user who is disabled, so routines of people disabled before this change (an upgrade) are paused before anyone can re-enable them; the actor is `system` `bootstrap`, and it does nothing once they are paused.

### Refused at fire and run time (defence in depth)

The scheduler skips disabled routines, but a routine can be on anyway (a race with the disable, a database edit, a restore). So:

- **When it fires** (`cron::fire`): if the Bot's owner or the routine's author is disabled (or gone), nothing is queued, no routine run is taken, `routine.run_refused` is audited (reason `owner_disabled` or `author_disabled`), and the routine is paused for that person.
- **When it runs** (`runner::run_one`): a routine message queued before the disable is refused (`bot.run_refused`, same reasons), whatever `SHARED_BOTS` says, and its routine run is given back.
- **Turning one on**: creating an enabled routine, or `PATCH {enabled: true}`, while the Bot's owner or the routine's author is disabled is a 409 that points at hand-over.

This covers routines only. Chat runs on a disabled owner's Bot under `SHARED_BOTS=open` still run for whoever sends them; on a self-hosted server that's often a team's Bot, and an admin hands it over (below). Isolated servers already refuse them (ADR 0046).

### Resume only when an admin asks

Re-enabling a user leaves their routines paused. An admin resumes them with `POST /api/users/:id/routines/resume` (`botctl user resume-routines <user>`), which needs the user active. `ROUTINES_ON_ENABLE=resume` resumes them as part of re-enabling instead (default `paused`). SCIM can re-enable a user, but with the default it can't restart their routines; that stays an admin's decision.

Resuming re-checks each routine: one whose owner or author is still disabled stays paused, now marked for that person, so resuming it is their re-enable's job.

### Hand over to someone else

`POST /api/users/:id/handover {to, resumeRoutines?}` (`botctl user handover <user> <to> [--resume]`), admins only:

- **From** a disabled user only (409 if active: give one Bot away from its access settings instead). **To** an active user who isn't them and isn't read-only (400).
- **Bots**: every Bot they own goes to `to`, the same way an admin gives one Bot away (ADR 0017): work in progress stops, its memory follows, `to`'s grant on it is dropped, `bot.owner_changed`. The whole set must fit `to`'s plan's Bot limit, checked first (403, `user.handover_refused`).
- **Routines**: those they wrote become `to`'s (`author_id`), and pauses held for them move to `to`, on every Bot `to` can operate. A routine on a Bot `to` can't operate (someone else's private Bot) is left as it was, paused for the disabled user, and listed in `skipped`, so nobody's routine starts running on a Bot they can't use.
- If a Bot can't be given midway (someone took one of `to`'s slots meanwhile), the hand-over stops there with a 403, but the routines are still moved for the Bots already given, so none is left with `to` but held for the disabled user. `user.handed_over` records what moved. Running it again moves the rest.
- They **stay paused** unless `resumeRoutines: true`, which resumes the ones just handed over. Otherwise resume them later for `to`.

### Audit

| Event | When | Details |
|---|---|---|
| `routine.paused` (new) | Disabling, or a refused firing | `reason`, `forUser`, `name` |
| `routine.run_refused` | A firing refused | New reasons `owner_disabled`, `author_disabled`; `owner`, `author`, `forUser` |
| `bot.run_refused` | A queued routine refused | New reason `author_disabled` (and `owner_disabled` on open servers); `forUser` |
| `routine.resumed` (new) | Resumed | `reason`: `admin`, `user_enabled` or `handover`; `pausedFor`, `pausedReason` |
| `routine.handed_over` (new) | Moved to `to` | `from`, `to`, `paused` |
| `user.handed_over` (new) | A hand-over | `to`, `bots`, `routines`, `skipped`, `resumed` |
| `user.handover_refused` (new) | Over `to`'s Bot limit | `reason: tier_bot_limit`, counts |
| `user.disabled`, `scim.user_deleted` | | `routinesPaused` |
| `user.enabled` | | `routinesResumed` |

The actor is whoever disabled, resumed or handed over (an admin, or the SCIM token), or `system` `scheduler` for a refused firing.

## Alternatives considered

- **Only refuse at fire time, change nothing stored.** Simple, but every schedule would log a refusal forever, and an admin couldn't tell which routines botd stopped from ones people turned off. Pausing once, with a reason, is quieter and resumable.
- **Delete a leaver's routines.** Loses a team's schedules. No.
- **Hand over automatically** (say, to whoever disabled them). The right owner is a person decision; the admin who clicks disable often isn't it.
- **Resume on re-enable by default.** A user re-enabled by an IdP sync (or by mistake) would restart scheduled work nobody looked at. Opt-in with `ROUTINES_ON_ENABLE=resume`.
- **Refuse every run of a disabled owner's Bot on open servers too.** It would stop team Bots on self-hosted servers the moment their maker leaves, before anyone hands them over. Routines are what run unattended in someone's name; chat runs have a person asking.

## Consequences

- Migration 19 adds `routines.paused_reason`, `paused_for`, `paused_at`. Routine JSON carries them (`null` when not paused).
- New admin routes: `GET /api/users/:id/routines`, `POST /api/users/:id/routines/resume`, `POST /api/users/:id/handover`; `botctl user routines | resume-routines | handover`.
- ADR 0046's "a firing routine says so once" no longer happens for disabled owners: the routine is paused instead, and nothing reaches the chat. Chat runs still say why.
- Tests: `handover_http_tests.rs` (pausing, fire- and run-time refusal on an open server, the 409 on turning one on, resume by an admin and by `ROUTINES_ON_ENABLE`, a routine held for a second disabled person, hand-over with skipped routines and the plan check), `scim_http_tests::deprovisioning_pauses_the_users_routines`, and ADR 0046's disabled-owner test updated.

## Limits and follow-ups

- The client doesn't show why a routine is paused yet; `botctl user routines`, `GET /api/users/:id/routines` and the audit log do.
- Hand-over is all of a user's Bots to one person. Splitting them between people is giving Bots away one by one (`PATCH /api/bots/:id/access`), then handing over the rest.
- A disabled user's grants on other Bots stay (they can't use them while disabled).
