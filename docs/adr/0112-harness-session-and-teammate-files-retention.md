# 0112: Retention for harness session files and teammates' archived work

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row C1.2-1 in the [readiness checklist](../security/soc2-readiness-checklist.md), which [ADR 0098](0098-chat-retention.md) left Partial. Builds on chat retention's job, holds and admin view; corrects where ADR 0098 said harness session files are.

## Context

ADR 0098 gave chat history a retention setting and left two things kept forever: each harness's own session files, and a leaving teammate's work archived into the owner's `from-teammates/` folder ([ADR 0052](0052-teammate-offboarding-on-machines.md), [ADR 0066](0066-removing-teammate-accounts-on-one-server.md)).

ADR 0098 said session files are "in the Bot's folder". Reading the adapters shows most aren't:

| Harness | Where its sessions are | Per Bot? |
|---------|------------------------|----------|
| Claude Code | `$HOME/.claude/projects/<project>/<session>.jsonl`, with `<session>/` (subagents, tool results) beside it; per-session `file-history/<session>/`, `session-env/`, `debug/`, `todos/`. Auto memory is `projects/<project>/memory/`. | No: one HOME, shared |
| Codex | `$HOME/.codex/sessions/YYYY/MM/DD/rollout-<time>-<session>.jsonl[.zst]` and `archived_sessions/`; indexes `history.jsonl`, `session_index.jsonl`, `state_*.sqlite`. SuperBot sets no `CODEX_HOME`. | No: one HOME, shared |
| Pi | `--session-dir <Bot's folder>/pi-sessions`, `<time>_<session>.jsonl` | Yes |
| Hermes Agent | `HERMES_HOME=<Bot's folder>/hermes`, transcripts in its `state.db` (SQLite) | Yes, but in a database |

The HOME is botd's own on a server without per-user accounts (shared by every Bot there), the user's account's HOME with per-user accounts ([ADR 0037](0037-per-user-unix-accounts.md)) or a teammate's account for an owner's Bots ([ADR 0064](0064-teammate-accounts-on-one-server.md)), and on a user's machine the Bots' HOME or a teammate's home there ([ADR 0048](0048-teammates-own-os-user-on-machines.md)). botd can't read into per-user accounts' folders, and only the agent reaches a machine's.

Claude Code also deletes its own sessions older than `cleanupPeriodDays` (30 by default) when it starts, whatever SuperBot's holds say.

## Decision

**Two settings, applied by the retention pass, deleting by age wherever the files are, never under a hold or from under a run.**

- **Settings.** `HARNESS_SESSION_RETENTION_DAYS` and `TEAMMATE_FILES_RETENTION_DAYS`, like `CHAT_RETENTION_DAYS`: unset or `0` keeps forever (the default), `1` to `36500` days, a bad value stops botd. Saved in `settings`, changes audited as `harness_sessions.retention_changed` and `teammate_files.retention_changed`, and in `server.started`'s details. The chat retention worker runs all three passes at start and every 6 hours (`retention::start`, `server/src/file_retention.rs`).
- **Where each harness keeps sessions is the adapter's** (`Adapter::sessions`: folders under the HOME and under the Bot's folder, each with how deep a session sits), so nothing harness-specific is outside adapters. Hermes keeps them in a database it alone may change, so its adapter gives the command instead (`Adapter::prune_sessions`, with `has_session_db` saying whether a Bot folder has one): `hermes sessions prune --older-than <days> --include-archived --yes`, run as a job in each place the Bot's runs keep a database (the owner's Bot folder, and each teammate's own on this server or on the machine), and only where that database is there (botd looks on this server; on a machine the agent says, answering `probe` in the same `/v1/retention` request), its gateway stopped first as around a run. Machines with an older agent aren't asked, so their databases wait too.
- **A session goes whole or not at all.** At a session's depth, every name holding the same UUID is one session (a Claude transcript and its folder; a Codex rollout and its `.zst`). It goes only when everything in it, folders included, last changed before the cutoff. A name with no UUID (Claude's `memory/`, Codex's indexes) is never touched. Each folder says whether it holds transcripts; a Bot's saved session is cleared only when its transcript went, not when an old side file (a Claude debug log) went while the transcript stays. The shared sweeper (`server/src/sweep.rs`) opens each folder from its already-open parent refusing links and removes each name relative to it, so a folder swapped for a link can't lead it elsewhere, and a link is removed, never followed. It looks at 500,000 entries per pass at most.
- **Where it sweeps.** botd's own HOME and `DATA_DIR/bots/<id>`; each per-user and teammate account's HOME and Bot folders, as the account, through `superbot-run --sweep` (reads the sweep as JSON, refuses any folder outside the account's own); each running, enrolled machine whose agent says `retention`, through a new agent route, `POST /v1/retention`, which sweeps the Bots' HOME, each teammate's home there, and the named Bots' folders in each, taking only plain relative paths.
- **Holds.** Holds are read again before each place a pass deletes in (this server, each account, each machine, each Hermes prune, each archive), each after taking a lock that placing a hold also takes, so a hold placed while a pass runs protects everything it hasn't reached; placing it waits for the place in progress (seconds on a server, up to a Hermes prune's 5 minutes). A held Bot's own folder is never swept, and a HOME where a held Bot runs (any Bot on a server without accounts; the owner's Bots in an account or on a machine) isn't swept at all, since sessions there can't be told apart by Bot. Runs in such a HOME tell Claude Code to keep its sessions for 36,500 days (`--settings` `cleanupPeriodDays`); with retention on, they tell it the retention instead, so its own sweep agrees.
- **Running Bots.** Each Bot holds a per-Bot lock while it runs (taken before the run starts, released when it ends); a pass takes every idle Bot's lock first, so no run starts while files are deleted, and a running Bot's folder and saved session stay. A Bot whose saved session went has it cleared, so its next run starts a new one instead of failing to resume.
- **Teammates' archived work.** A removal that archived work (`teammate_cleanups`, `account_removals`) records where; once that's older than the setting, the pass deletes `from-teammates/<name>`: on the machine through the same agent route, on this server as the owner's account through `superbot-run --sweep`. A destroyed machine, or an account whose folder is gone, has nothing left, so the row is marked done. Skipped while any of the owner's Bots is held; a machine that's down, an account not ready, or a server where per-user accounts were turned off (their folders may still be there) waits, so a row is marked done only when the archive is deleted or known gone. Each row is done once (`archive_pruned_at`).
- **Evidence.** Each pass is saved (`harness_sessions_last_pass`, `teammate_files_last_pass`) and shown in `GET /api/retention` and `botctl retention` as `harnessSessions` and `teammateFiles`. A pass that deletes anything records `harness_sessions.pruned` (sessions, files, bytes, Hermes Bots pruned, places swept, sessions cleared, held and running Bots, HOMEs left for a hold, errors) or `teammate_files.pruned` (deleted, already gone, held, waiting, errors); a pass with errors records it with outcome `failure`. Empty passes are saved, not audited.

## Alternatives considered

- **Pointing each harness's HOME at the Bot's folder** (`CLAUDE_CONFIG_DIR`, `CODEX_HOME` per Bot), so every session is per Bot. Logins live in the same folders, so each Bot would need its own login, which breaks how logins work on servers and machines today. A larger change than retention.
- **Only Claude Code's own `cleanupPeriodDays`.** It covers one harness, runs only when a Bot starts, and ignores holds. Set it to agree with the pass instead.
- **A per-session record in the database** to attribute every file to a Bot. Teammates' runs start fresh sessions that aren't saved, and files from before the record would be orphans; skipping HOMEs under a hold is simpler and never deletes held data.
- **A root helper for per-user accounts.** The account owns its files; running as it through `superbot-run` needs no new privilege.
- **Deleting a teammate's archive by the folder's age** rather than the removal's. The archive keeps the work's own times; the removal's time is when it became the owner's.

## Consequences

- Checklist row C1.2-1 is Done: chat history, harness session files and teammates' archived work have settings, deletion jobs, holds, audit events and tests ([`server/src/file_retention_http_tests.rs`](../../server/src/file_retention_http_tests.rs), the machine end to end in [`server/src/machines_offboard_tests.rs`](../../server/src/machines_offboard_tests.rs), the sweeper's unit tests in [`server/src/sweep.rs`](../../server/src/sweep.rs), and the account sweep as root in [`deploy/test-isolation.sh`](../../deploy/test-isolation.sh)).
- New settings: `HARNESS_SESSION_RETENTION_DAYS`, `TEAMMATE_FILES_RETENTION_DAYS`. New column `archive_pruned_at` on `teammate_cleanups` and `account_removals`. New agent route `POST /v1/retention` and capability `retention`. New `superbot-run --sweep`. New audit actions: `harness_sessions.retention_changed`, `harness_sessions.pruned`, `teammate_files.retention_changed`, `teammate_files.pruned`.
- A Bot whose run is queued while a pass runs waits for it, seconds on a server, longer with a slow machine.
- A HOME with a held Bot keeps every session in it, other Bots' included, until the hold is released.
- Machines with an older agent are skipped until upgraded; their files stay. A Codex `CODEX_HOME` set by the operator moves sessions out of reach.
- Backups keep deleted files for their own retention, as with chat.
