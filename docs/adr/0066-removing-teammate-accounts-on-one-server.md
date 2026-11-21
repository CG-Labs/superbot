# 0066: Removing teammates' accounts on one server when they leave

## Status

Accepted (21 Nov 2026). A follow-up on [#30](https://github.com/CG-Labs/superbot/issues/30) (M3, per-user isolation). It closes the limit [ADR 0064](0064-teammate-accounts-on-one-server.md) left open ("removing pair accounts when a teammate leaves"). It is the one-server side of [ADR 0052](0052-teammate-offboarding-on-machines.md), which does the same on machines.

## Context

What the code did before this change:

- With `ISOLATION_TEAMMATES` (ADR 0064), Bea's run of Ada's shared Bot runs as an account made for that pair, `sb-t-<hash>`, in `ISOLATION_DIR/<ada>-<bea>/`, with Bea's own harness login in its home.
- When Bea left (disabled, deprovisioned by SCIM, deleted) or lost Ada's Bots (a grant revoked, a Bot made private, given away or deleted), she could no longer ask for runs or log in. But the account, its processes, its folder, its work and her login stayed. `superbot-userctl` could only `ensure`.
- On machines, ADR 0052 already removes a leaver's OS user: queued, retried, audited, work archived to the owner.

## Decision

### The same triggers as on machines

`machines::offboard::left` and `check_owner` are where ADR 0052's hooks land: a user disabled or their role changed (`PATCH /api/users/{id}`), SCIM deprovisioning or deletion, and every Bot access change (grant revoked, visibility changed, Bot given away or deleted). Both now call `teammate_removals::left` and `check_owner` first, so one server and machines follow the same rule: a teammate keeps their account for an owner's Bots only while `offboard::wanted` says so (active, not the owner, can still operate one of the owner's Bots). Here the owner must be active too (`teammate_removals::wanted`): none of a disabled owner's Bots run, so their teammates' accounts, logins and processes here go. Their work goes to the owner as usual, and once the owner is back, teammates get new accounts as they run.

- `left(user)` queues the user's accounts for every owner's Bots. It also queues teammates' accounts for the user's own Bots that no one may use now.
- `check_owner(owner)` queues teammates' accounts for the owner's Bots that aren't wanted now.
- A sweep at startup and every 5 minutes does the same for every pair, so leaves while botd was down, accounts from before this change, and missed ones are found. Pairs come from the password file (each `sb-t-` entry whose home is `ISOLATION_DIR/<owner>-<teammate>/home` and whose name is the one those two ids give) and from `teammate_spaces` in botd's database, where botd notes each pair it sets up and forgets it once removed. A recreated container starts with a fresh password file but keeps the `users` volume and botd's data, so its old folders are still found. Pairs made before this table are added to it once, from the `isolation.account_created` events (with `forUser`) in the audit log, when it's made. botd can't list `ISOLATION_DIR` (root's, 0711), so it never guesses pairs from folder names.

### Queued, retried, audited, like ADR 0052

Each removal is a row in `account_removals` (owner, teammate, account, reason, files, state). Only one may be pending per pair.

- **States**: `pending` until the helper has done it, then `done`, or `held` while the work waits to be purged. A pending one is cancelled (`access_back`) if the teammate is wanted again, but only if the helper never started for it and no admin asked. `attempts` is counted before the helper starts, so a try botd never heard back from (it stopped mid-way) still counts. Once the helper has started, it may have done part of the job, so the removal is finished, and a later run makes the teammate a new account.
- **Held stays held**: if a retry finds work an earlier try held, it stays held for at least as long as a new hold would be (30 days in `archive` mode, the grace days in `delete` mode), never due at once.
- **Retries**: botd runs pending removals at once, in the background, and again on every sweep. A failure is audited once per new reason, not every time it's tried.
- **Admins** can force one, even if the teammate still has access: `POST /api/users/{owner}/teammate-accounts/{teammate}/remove` (200 when done, 202 with the reason when still pending). The removal is then the admin's, so it's never cancelled. `GET /api/users/{key}/teammate-accounts` lists the pairs around a user, whether each is wanted, and their removals. `GET /api/isolation/teammate-removals?state=` lists them all. `botctl user teammates <user> [remove <teammate>]` and `botctl user teammate-removals [state]` wrap these, and the console's user detail shows them with a Remove button. All admin-only (`rbac::classify`).
- **Audit**, against the owner with `forUser`, `account`, `reason`, `files` and `cleanupId`: `isolation.teammate_removal_queued`, `teammate_removed` (with `accountRemoved`, `processesStopped`, `tempRemoved`, `runsStopped`, `loginsStopped`, `work`, `archivedTo`, `purgeAt`), `teammate_removal_failed`, `teammate_removal_cancelled`, `teammate_removal_forced`, `teammate_files_purged` and `teammate_files_purge_failed`.

### The root helper does the removal

`superbot-userctl remove <owner> <teammate> <cleanup id> archive <name> | hold | delete`, and `purge <cleanup id>`. The sudoers rule now allows `ensure`, `remove` and `purge`, and nothing else. Re-run `deploy/install.sh --isolation` to get it. botd's error says so when sudo refuses.

- **Only a pair account.** It takes two different valid ids and derives the `sb-t-` name and folder itself, as `ensure` does. An account with that name but another home, or uid or gid 0, is refused. A user's own `sb-u-` account, the owner's, root, system users and every other account are never touched. The owner's own account is only ever read, to hand work to.
- **Processes**: it locks the password, then kills every process of the account, **as the account itself** (`setpriv` to its uid, `kill -9 -1`). So a reused pid of anyone else's is never hit, and it works where root has no `CAP_KILL` (Docker). It repeats until none is left, reaped too, for up to 10 s, then fails so the removal is retried.
- **Work** (the `workspace` folder), unless an earlier try already moved it:
  - Prepared first, while still in the pair's folder where no one else can reach: memory copies botd set aside (`*.md.unsaved`, ADR 0064), and any a run left unsaved (`<bot id>.md`, not the teammate's `USER.md`), go in with it under `unsaved-memory/`, never over a file already there (the second `b1.md` becomes `b1-2.md`), a hard link to someone else's file goes, a file of the account's with other links gets a copy of its own, and set-id bits go.
  - `archive` (the default, `ISOLATION_TEAMMATE_FILES=archive`): chowned to the owner's account, moved into the owner's workspace (`rename(2)`, never over anything), then moved by the owner's account itself into `workspace/from-teammates/<name>-<date>`. The owner's Bots can read it. botd makes the owner's account first if they never ran a Bot here.
  - `hold`: moved to `ISOLATION_DIR/.left/<cleanup id>` (root's, 0700), and deleted by `purge` after `ISOLATION_TEAMMATE_FILES_DAYS` (`delete` mode, default 7). With `ISOLATION_TEAMMATE_FILES_DAYS=0`, `delete` deletes it at once.
  - If the owner is gone or their account can't be made, archived work is held for 30 days instead (`notArchived` in the audit event says why). The account still goes now.
- **The rest**: the pair's folder (home with the login, Bot state, settings, memory copies), its entries in `/tmp`, `/var/tmp` and `/dev/shm` (only if the uid is still unclaimed or still the account's), its crontab, `at` jobs and lingering, then the account and its group.
- **Safe to retry**: each step checks what's there. Work found already moved is reported, not moved again: still staged as `.superbot-from-teammate-<id>` in the owner's workspace (then tidied into `from-teammates/`), already in `from-teammates/` (where `.left/<id>.to`, root's, records it went), or held in `.left/<id>`. A removal of an account that's already gone says `account=absent`. It prints what it did as `key=value` lines, which botd parses strictly.

### Running things and shared Bots

- A gate keeps runs and removals of a pair apart (`teammate_removals::Gate`). A teammate's run, and a login while it starts, holds the pair's account open. A removal closes it: no new run or login starts there while it's being removed or a removal is pending (the run is refused, `account_being_removed`, and the login gets a 409), and once let in, a run checks the teammate's access again, so one that passed its check just before access was revoked doesn't make a new account.
- The removal stops the teammate's runs of the owner's Bots in that account (`bot.run_finished` with `account_removed`); their runs on the owner's machine go on. It waits up to 60 s for them to end, so each saves its memory copy back to botd first, and stops them again while it waits, so a run let in just before the gate closed is stopped once it starts. A run that doesn't end in time fails the try, which is retried. Then it stops their harness logins (`teammate_logins::stop_for`), and the helper kills whatever is left.
- Shared Bots keep working for everyone else: their state, memory and settings live in `DATA_DIR` and in other accounts' folders, never in the leaver's pair folder.

## Alternatives considered

- **Leave the accounts, as before.** A leaver's login and work stay on the server, used by no one. Rejected: it's what #30 asks to close.
- **Let botd delete the folder itself.** botd can't enter a pair's folder, and shouldn't be able to. Only the root helper can, with a narrow sudoers rule.
- **Kill processes as root, or with `pkill -u`.** Docker drops `CAP_KILL`, and a pid can be reused between finding and killing. Killing from the account's own uid avoids both.
- **Archive to a folder botd owns.** Work would leave every owner's isolation. Handing it to the owner's account keeps it with the owner, like ADR 0052.
- **Delete work by default.** Losing a teammate's work by accident is worse than keeping it. `ISOLATION_TEAMMATE_FILES=delete` is there for those who need it.

## Consequences

- When a teammate leaves, or loses an owner's Bots, their account for those Bots goes within seconds, or at the next sweep if something failed. Their processes stop, their login is deleted, and their work goes to the owner (or is held and deleted, if set up so).
- Existing installs must re-run `deploy/install.sh --isolation` to update the sudoers rule. Until then removals fail, are audited once and retried. The Docker image updates itself.
- Someone given access again gets a new, empty account and must log in again. Their old work is the owner's now.
- The tests: unit tests for argument building, strict parsing and held deadlines; HTTP tests with a fake helper for disabling, a revoked grant, retries, admin removal, cancellation (never once the helper started), holding, purging, a recreated container's folders, the gate (runs and logins kept out, the removal waiting for a run) and the audit trail; and in CI's as-root `isolation` job (`deploy/test-isolation.sh`), the real helper: bad arguments and a forged account are refused, and a real removal kills a lingering process, hands the work and an unsaved memory copy (not `USER.md`) to the owner without set-id bits, deletes the temp file and the account, and leaves the owner's and other accounts and their processes alone. Then it re-runs and still reports where the work went, tidies away work an interrupted try left staged, holds and purges. botd's OS test removes a teammate whose run is going and checks the run is stopped first, the work is the owner's, the login is gone, a folder whose account a recreated container lost is cleaned up, and the shared Bot keeps working for the owner and another teammate.

## Limits and follow-ups

- botd's own per-user secrets (`/api/me/secrets`) and sessions are handled as before (ADR 0047): disabling ends sessions. Removing an account doesn't delete a user's stored keys in botd's database.
- Work held for a gone owner is deleted after 30 days. An admin who wants it must copy it from `ISOLATION_DIR/.left/<cleanup id>` first.
- A user's own `sb-u-` account is never removed by this. Deleting a user's own account and folder stays a manual step.
- **Team accounts and team machines** remain open on #30.
