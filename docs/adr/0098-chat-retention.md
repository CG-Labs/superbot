# 0098: Chat history retention

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); moves checklist row C1.2-1 from Gap to Partial in the [readiness checklist](../security/soc2-readiness-checklist.md). Follows the audit log's retention setting ([ADR 0009](0009-audit-events.md)); leaves teammates' archived work as [ADR 0052](0052-teammate-offboarding-on-machines.md) and [ADR 0066](0066-removing-teammate-accounts-on-one-server.md) set it.

## Context

botd keeps every Bot's chat in the `messages` table of `app.sqlite`: what people wrote, the Bot's replies, routine prompts, and Bot-to-Bot messages. Nothing deleted it except deleting the Bot. The audit log (`AUDIT_RETENTION_DAYS`), sessions and backups all have retention settings; chat had none, and it is the most sensitive thing botd stores in clear text ([data flows](../security/data-flows.md#at-rest)). SOC 2 C1.2 asks that confidential information is disposed of when it is no longer needed, which needs a setting, a job that applies it, and evidence that it ran.

Deleting chat is irreversible, so it must:

- change nothing for existing installs until an operator opts in;
- never take a message a run still needs, or chat someone has a duty to preserve (a legal hold);
- not stall runs or requests while it works through a large table;
- leave a record of what it did, without recording what it deleted.

## Decision

**`CHAT_RETENTION_DAYS`, a periodic batched deletion job in botd, and per-Bot holds.**

- **Setting.** `CHAT_RETENTION_DAYS` in `.env`: unset or `0` keeps chat forever (the default), `1` to `36500` keeps that many days. Parsed by the same function as `AUDIT_RETENTION_DAYS` (`retention::days`), and a bad value stops botd at start. botd saves it in `settings` (`chat_retention_days`) and audits a change as `chat.retention_changed` with `before` and `after`, as the audit log does. It is in `server.started`'s details as `chatRetentionDays`.
- **Job** (`server/src/retention.rs`). While the setting is on, botd runs a pass at start and every 6 hours. A pass deletes messages written before `now − days`, oldest first, **500 per batch** (one short transaction each), with a short pause between batches, so the database lock is held for milliseconds at a time and runs and requests interleave. A new index on `messages(created_at)` finds old messages by age, and each batch starts after the `(created_at, id)` the previous one ended on, so rows a pass skips (a held Bot's, a running message) are looked at once per pass, not once per batch. The pass runs until a batch comes back short. A failed batch, or a failure to save the pass, is logged and audited where it can be, and the worker carries on to its next pass.
- **What a pass never deletes.**
  - A message whose run is `queued` or `running`: the runner still needs it, and restarts resume from it.
  - Anything in a held Bot's chat, or written into another Bot's chat by a held Bot (`from_bot`), since that is the held Bot's conversation too.
- **Holds** (the admin override, usable as a legal hold). An admin holds a Bot with a reason (`PUT /api/retention/holds/{bot}`, `botctl retention hold <bot> "<reason>"`) and releases it (`DELETE`, `botctl retention release <bot>`). A held Bot **can't be deleted** (409), by its owner or an admin, because deleting a Bot deletes its chat; nor can a Bot whose chat has messages from a held Bot, for the same reason; the hold must be released first. The delete itself is one statement that skips a held Bot, so a hold placed while a delete is under way (its run stopping, its screen closing) still wins; placing a hold on a Bot deleted a moment before is a 404. Holds live in a new `retention_holds` table (Bot, reason, who, when); changing the reason keeps the original time. Placing, changing and releasing are audited (`chat.hold_placed`, `chat.hold_changed`, `chat.hold_released`). The routes are admin-only: RBAC's default for anything unclassified, and the auth review's router walk checks `/api/retention` stays that way.
- **Evidence.** Each pass is saved in `settings` (`chat_retention_last_pass`: when, how many deleted, batches, the cutoff, the setting, how many Bots are held, any error). A pass that deletes anything records `chat.pruned` with those counts and nothing from the messages; a pass that fails records it with outcome `failure`. Empty passes are saved but not audited, so a quiet server doesn't fill the log every 6 hours.
- **Admin view.** `GET /api/retention` and `botctl retention`: the chat and audit settings, the last pass, and each hold with its Bot, owner, reason, who placed it and when.

## What it doesn't cover

- **Backups.** A deleted message stays in server backups for `SUPERBOT_BACKUP_RETENTION_DAYS` (default 14), as deleted audit events do. Operators who must be sure it's gone shorten that too.
- **Harness session files.** Each harness keeps its own transcript of a Bot's sessions in the Bot's folder (`DATA_DIR/bots/<id>/`, or the Bot's folder on the owner's machine). They are the harness's files, in its own formats, and on machines only the agent can reach them; deleting them by age needs a job per harness and, for machines, a new agent job. Left as the remaining chat item on C1.2-1. Most aren't in the Bot's folder: Claude Code and Codex keep them in the HOME their runs use; [ADR 0112](0112-harness-session-and-teammate-files-retention.md) found where each harness keeps them and covers them.
- **Bots' memory and users' facts.** These are what a Bot has been asked to remember, not a log, and people edit them.
- **Teammates' archived work.** With `MACHINE_TEAMMATE_FILES=archive` or `ISOLATION_TEAMMATE_FILES=archive` (the defaults), a leaving teammate's work is moved into the owner's `from-teammates/` folder and from then on is the owner's files, in the owner's folder or on the owner's machine. botd can reach those only through the machine agent or the root helper (`superbot-userctl`), so an age-based sweep would need a new agent job and a new privileged command, each with its own tests as root and over mutual TLS. That doesn't fit this slice. Operators who don't want the archive kept set `*_TEAMMATE_FILES=delete`, which deletes it after `*_TEAMMATE_FILES_DAYS` instead. An age-based sweep of `from-teammates/` is the other remaining item on C1.2-1, done in [ADR 0112](0112-harness-session-and-teammate-files-retention.md) (through the agent, and as the owner's account, who owns the archive, so no privileged command).
- **Erasing a person's data** on request is a different control (CC6.5-1).

## Alternatives considered

- **Retention per plan (a `chatRetentionDays` in the tiers file).** Managed plans may want different retention, but a message belongs to a Bot, whose owner has a plan, which can change; the cutoff would be per owner and move when they change plans, and a shared Bot's chat would follow its owner's plan, not the writer's. One setting per server is what customers' contracts name today. Per-plan retention can be added on top of the same job: a cutoff per tier instead of one.
- **Holds per person** (a custodian, as legal holds usually name). Messages aren't stored per author (a person's messages in a shared Bot are in that Bot's chat), so holding a person would either miss their messages in others' Bots or hold whole chats of people not under hold. Holding the Bot is exact and simple; an admin holds every Bot a custodian used.
- **One `DELETE` per pass.** On a large table the first pass after turning retention on would hold SQLite's write lock for seconds or minutes and stall every run and request.
- **Deleting by `id` instead of `created_at`.** Ids are in write order, but a cutoff by time is what the setting means, and the index makes it as cheap.
- **Retention on by default** (say, a year). Existing installs would lose chat on upgrade, which can't be undone. Off by default matches `AUDIT_RETENTION_DAYS`; the managed operator sets it to what customers' contracts say.
- **Auditing every pass.** Four events a day per server whether anything happened or not; the last pass is shown to admins instead, and passes that delete are audited.

## Consequences

- Checklist row C1.2-1 is Partial: chat history has a setting, a deletion job and tests ([`server/src/retention_http_tests.rs`](../../server/src/retention_http_tests.rs): off by default, batches, spared running and held messages, holds admin-only and audited, a held Bot not deletable; plus unit tests in [`server/src/retention.rs`](../../server/src/retention.rs) and `server/src/db.rs`). Left: harness session files and teammates' archived work.
- New setting: `CHAT_RETENTION_DAYS`. New table: `retention_holds`; new index: `messages_created`. New routes: `GET /api/retention`, `PUT`/`DELETE /api/retention/holds/{bot}`. New audit actions: `chat.retention_changed`, `chat.pruned`, `chat.hold_placed`, `chat.hold_changed`, `chat.hold_released`. New `botctl retention` commands.
- Deleting a Bot can now fail with 409 while it is held.
- Clients that have an old chat open keep showing deleted messages until they reload it; nothing is pushed when a pass deletes.
