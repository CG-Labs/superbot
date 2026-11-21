# 0052: Removing teammates' users from machines when they leave

## Status

Accepted (20 Nov 2026). A follow-up on [#30](https://github.com/CG-Labs/superbot/issues/30) (M3, per-user isolation). It closes the "teammate users are never removed" limit of [ADR 0048](0048-teammates-own-os-user-on-machines.md) (teammates' own OS user on machines). Numbered 0052 because 0051 is taken by a parallel change.

## Context

What ADR 0048 does today, checked in the code before this change:

- A run of Ada's shared Bot for Bea makes Bea a user on Ada's machine, `superbot-t-<12 hex>`, with a home under `<state>/teammates/`. The agent records it in `teammates.json`.
- Nothing ever removes it. Disable Bea, deprovision her through SCIM, revoke her grant, make the Bot private, give it away or delete it: her user, home, working files and any processes stay on Ada's machine.
- botd closes Bea's screen when she loses access (ADR 0048), but not her jobs or anything else she left running there.
- botd doesn't know which teammates have a user on a machine, except from the `machine.teammate_user_created` audit events.

## Decision

### When a teammate leaves, their user goes

A teammate keeps a user on the owner's machine only while they're active and can still operate one of the owner's Bots. botd checks this when any of these happens:

| Event | Reason recorded |
|---|---|
| An admin disables them (`PATCH /api/users/{id}`) | `disabled` |
| An admin lowers their role so they lose Operate | `access_lost` |
| SCIM sets `active: false`, or deletes them | `deprovisioned` |
| A grant is revoked or narrowed to viewer, a Bot is made private, given away, or deleted | `access_lost` |
| The reconciler finds a teammate who shouldn't be there | `disabled`, `deleted` or `access_lost`, as botd can tell |
| An admin asks (`POST .../teammates/{teammate}/remove`) | `admin` (even if they still have access) |

botd then queues one removal per machine where that person has a user (the `teammate_cleanups` table) and asks the agent at once. Only one removal is pending per machine and teammate, so repeated events add nothing.

### botd knows who's on each machine

Heartbeats now carry `teammates`: the ids in the agent's `teammates.json`. botd keeps them with the rest of the machine's upkeep, and adds a teammate as soon as it makes their user, so a leave before the next heartbeat still finds them. After every round of heartbeats, the reconciler queues removals for any listed teammate who shouldn't be there. This also catches users made before this change, and leaves that happened while botd was down.

### The agent removes the user, and only that user

`POST /v1/teammates/{user}/remove` (mTLS, `owner_id` and a `cleanup_id` in the body) on the agent:

1. Refuses the machine's own user, names that aren't plain, and a body for another owner.
2. Marks the teammate as leaving, so no new job or screen starts for them meanwhile.
3. Stops their jobs and screens, then kills every process of their uid (SIGKILL, until none are left). Each is signalled through a pidfd opened before its owner is checked, so a pid reused by someone else's process is never hit. A kernel without pidfds (before Linux 5.3) fails the removal rather than guess.
4. Moves their `work/` aside, deletes their home, and clears their files in `/tmp`, `/var/tmp` and `/dev/shm`.
5. Deletes the OS user (`userdel`).
6. Deals with their work (below), drops them from `teammates.json` last, and answers what it did.

The steps never follow links, and the user is touched only if it's the uid and gid the agent recorded: a different user by that name is left alone. The machine's own user, the Bots' user, and other teammates are never touched. Each step can be re-run: a removal that stopped halfway finishes on the next try. One that's done is kept by its cleanup id (`teammates-removed.json`, the last 1000), so asking again repeats its answer with `alreadyGone` and never touches a user made for the teammate since. A run or screen that was waiting while a removal ran checks again once it has the lock, so it can't make the user again halfway through. A recorded user that's gone with no home left (a removal that stopped just before dropping the record) is made afresh on the teammate's next run.

Credentials: a teammate's harness state and anything else they kept on the machine live in their home, so deleting it drops them. ADR 0048 gives teammates no machine logins of their own; [ADR 0062](0062-teammate-harness-logins.md) adds them, in that same home, so they go too, and a login still running is stopped. botd holds no per-teammate credentials for machines; their sessions and tokens are already ended by disabling them, and a teammate token stops working once someone else runs the Bot (ADR 0048).

### Their work goes to the owner, or is deleted after a grace period

Before ADR 0048, teammates' runs worked in the owner's own `work/`. So by default their work stays with the owner:

- **`MACHINE_TEAMMATE_FILES=archive`** (default): the teammate's `work/` moves to the owner's `work/from-teammates/<email name>-<date>/`, owned by the Bots' user, so the owner's Bots can use it. The move never replaces an existing folder. A file of theirs with another hard link gets a copy of its own first, so it's handed over too; a link to someone else's file is never read and stays theirs. If the owner's home is on another filesystem, the work is copied as the Bots' user (folders, files and links; never devices, pipes or files it can't read), then the original is deleted.
- **`MACHINE_TEAMMATE_FILES=delete`**: their `work/` is held aside, root's alone (`<state>/teammates/.left/<cleanup id>`), and deleted after `MACHINE_TEAMMATE_FILES_DAYS` (default 7, 0 to 365; 0 deletes at once). botd asks the agent to delete it once the days are up (`POST /v1/teammates/{user}/purge`).

The rest of the home (dotfiles, caches, harness state) is always deleted.

### Retries

An agent that's offline, outdated, or doesn't answer leaves the removal pending. botd asks again after every round of heartbeats until it's done. Removals run in the background, four at a time, so a slow agent never holds up heartbeats; one pass runs at a time, and an event during it runs another after. An agent that says nothing of `teammate_removal` in its heartbeat isn't asked: the removal waits until it's upgraded (ADR 0039).

A removal is cancelled if the machine is destroyed. It's also cancelled if the teammate gets access back before the agent was ever asked (and an admin didn't ask for it). An admin who asks for a removal that's already waiting for another reason makes it theirs, so it's never cancelled that way. Once the agent has been asked, it may have done part of it, such as deleting the user but not yet moving the work, so botd finishes it instead; the teammate's next run makes them a new user.

### Admin view

| Where | What |
|---|---|
| `GET /api/machines/teammate-removals?state=` | Every removal (`pending`, `held`, `done`, `cancelled`, `open` or all), newest first, and open ones per machine |
| `GET /api/users/{key}/machine/teammates` | The teammates with a user on that machine, whether each still should, and its removals |
| `POST /api/users/{key}/machine/teammates/{teammate}/remove` | Remove one now. 200 when done, 202 with why when it's still pending |
| `botctl machine removals [state]`, `botctl machine teammates <user> [remove <teammate>]` | The same |

All admin only.

### Audit

| Event | When |
|---|---|
| `machine.teammate_removal_queued` | A removal was queued: `forUser`, `user`, `reason`, `files`, `cleanupId` |
| `machine.teammate_removed` | The agent removed them: what it stopped, `userRemoved`, `alreadyGone`, `work` (`archived`, `held`, `deleted` or `none`), `archivedTo`, `purgeAt`, `attempts` |
| `machine.teammate_removal_failed` | A try failed or is waiting. Logged once per new reason, not on every retry |
| `machine.teammate_removal_cancelled` | `why`: `access_back` or `machine_gone` |
| `machine.teammate_removal_forced` | An admin asked for a removal already waiting for another reason: `was` |
| `machine.teammate_files_purged`, `machine.teammate_files_purge_failed` | Held work deleted, or not yet |
| `machine.screen_closed` | Reason `teammate_left` |

## Alternatives considered

- **Remove only on SCIM deprovisioning.** Simplest, but a revoked grant or a deleted Bot would leave the user and its processes. Access loss is the same risk.
- **Remove on the teammate's next run being refused.** There may never be a next run.
- **Always delete their work.** Teammates' work used to land in the owner's `work/`, and the Bots they ran are the owner's. Deleting it at once would surprise owners, so it's opt-in, with a grace period.
- **Archive to the teammate.** They may be gone from the server, and the machine is the owner's.
- **Lock the user instead of deleting it.** A locked user still holds files and a uid. Removing it leaves nothing to forget, and a later run makes a new one.

## Consequences

- A teammate who leaves loses their user, home, processes and temp files on every machine they had one on, with no admin step, and botd retries until each machine has done it.
- The owner keeps their work by default. With `delete`, it's held for the grace period, then gone.
- Removal runs whenever machines are on (`MACHINE_CONTROL_URL`), whether or not `MACHINE_TEAMMATE_USERS` is still on, so users made before it was turned off are removed too.
- New code:
  - Agent: `Teammates::remove` and `purge` in `machines/teammates.rs`, `runas::move_into`, and `POST /v1/teammates/{user}/remove` and `/purge` in `machines/agent.rs`. Heartbeats say `can: teammate_removal` and list `teammates`.
  - botd: `machines/offboard.rs`, the `teammate_cleanups` table, hooks in `users.rs`, `scim.rs` and the Bot ACL paths in `main.rs`, and a step after every round of heartbeats.
  - All wire fields are optional, so older agents and botds still talk.
- Tests:
  - The agent's removal with fake accounts: only the leaving user is removed, their processes stopped, their work archived, and nothing of the owner's or other teammates' touched (`machines::teammates`).
  - Moves that never follow links or replace, hard links copied only when they're the teammate's own, and a move to another filesystem copied then deleted (`runas`).
  - A retry of a finished removal after the teammate came back leaves their new home alone, and a stale record doesn't block their next run (`machines::teammates`).
  - End to end over mTLS with the real agent (`machines_offboard_tests.rs`): disable, SCIM deactivate and delete, a revoked grant and a deleted Bot each remove the user; asking again changes nothing; an offline machine is retried and logged once; access coming back finishes a removal the agent was asked for, and cancels one it wasn't (an outdated agent) unless an admin asked for it; delete mode holds then purges; the admin API.
  - As root in CI's isolation job: a real user, its processes and temp files are removed, the archive (including a hard-linked file of theirs) goes to the Bots' user while a hard link to root's file stays root's, and the other teammate and the Bots' user are untouched.

## Limits and follow-ups

- **Disk space.** Archived work counts against the owner's disk, as the teammate's home did.
- **Someone still on the server, but gone from the team.** Done in [ADR 0087](0087-team-accounts-and-machines.md): leaving a team is one more event here, with reason `left_team` (and joining one, `joined_team`, for people outside it).
- **A machine that never comes back** keeps its removals pending until it's destroyed. They're visible in `botctl machine removals`.
