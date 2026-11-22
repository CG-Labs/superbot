# 0009: Audit events

## Status

Accepted

## Context

M1 asks for a structured, append-only record of admin actions with CSV export, and M2 (multi-user, Entra/Google SSO) needs it to say *which* person did something. Approvals ([ADR 0007](0007-approvals.md)) added a first `audit_events` table, but it only covered approvals and policy, had no actor identity beyond "user" or "bot", no source IP, and no export.

## Decision

**One SQLite table, written by one function, append-only in code and in the database.**

### Schema

`audit_events` in `app.sqlite`, created by migration 2 (`PRAGMA user_version`), which also copies the rows of the approvals-era table:

| Column | Meaning |
|--------|---------|
| `id` | Increasing integer. Paging cursor. |
| `at` | UTC time, unix milliseconds. The API also returns it as RFC 3339 (`time`). |
| `actor_kind` | `user`, `bot`, or `system` (CHECK constraint). |
| `actor_id` | Who: `operator` for the shared password today, a Bot id, or the system part (`scheduler`, `policy`, `approvals`, `retention`, ...). |
| `actor_name` | Display name when known. |
| `actor_subject` | IdP subject. Empty until M2. |
| `action` | `<noun>.<verb>`, e.g. `bot.created`, `approval.denied`. |
| `target_type`, `target_id` | What it acted on (`bot`, `routine`, `approval`, `rule`, `policy`, `handoff`, ...). |
| `bot_id` | The Bot the event is about, for filtering. |
| `outcome` | `success`, `failure`, or `denied` (CHECK constraint). |
| `ip`, `user_agent` | Request source. Empty for system events. |
| `details` | Small JSON object, scrubbed (below). |

Indexes on `at`, `(action, id)`, and `(actor_kind, actor_id, id)` keep filters fast.

### Append-only

- **Code**: `Db::record` is the only writer. There is no update or delete API, and the only `DELETE` is retention pruning.
- **Database**: a trigger aborts every `UPDATE`, except the narrow rewrite erasing a user makes inside its own transaction: their id to a pseudonym, their identifying fields cleared, nothing else ([ADR 0102](0102-erasing-a-users-data.md)). Another aborts every `DELETE`, unless retention is on (the `audit_retention_days` setting) and the row is older than the window. So even a bug, or a stray query through `botd`, can't rewrite history or delete recent rows.
- **Limits**: anyone with write access to `app.sqlite` (the service user, root) can drop the triggers. This guards against mistakes and API misuse, not a server compromise. Tamper evidence (hash chain, write-once storage, shipping events off the box) is M5 work.

### What is logged

| Area | Actions |
|------|---------|
| Login | `auth.login` (first good request per IP and user agent, again after 30 idle minutes, since Basic auth sends the password on every request), `auth.login_failed` (bad password or token; throttled to one per IP and method per minute, with a count of the ones skipped) |
| Bots | `bot.created`, `bot.updated` (each changed field, old and new), `bot.deleted`, `bot.stopped`, `bot.asked` (Bot to Bot) |
| Routines | `routine.created`, `routine.updated`, `routine.enabled`, `routine.disabled`, `routine.deleted`, `routine.fired` |
| Policy and approvals | `policy.initialized`, `policy.updated`, `policy.reset`, `rule.added`, `rule.removed`, `approval.requested`, `approval.approved`, `approval.denied`, `approval.expired`, `policy.allowed`, `policy.denied` |
| Handoffs | `handoff.requested`, `handoff.answered`, `handoff.timed_out` |
| Runs ([ADR 0019](0019-audit-actors.md)) | `harness.invoked` (each harness start: harness, model, policy mode, attempt, trigger), `bot.run_finished` (result, duration, replies), attributed to whoever queued the task |
| Bot token | Admin calls a Bot makes with `BOT_TOKEN` through `botctl` (routines, Bot to Bot, handoffs, approval checks) are the events above with the Bot as actor; `access.denied` when it calls a person-only endpoint (403) |
| Server and audit | `server.started` (version and the settings that matter: harness, policy mode, auth kind, retention), `audit.exported` (with its filter), `audit.retention_changed`, `audit.pruned`, `audit.schema_upgraded` (an upgrade added columns; rows before it leave them empty) |
| Chat retention ([ADR 0098](0098-chat-retention.md)) | `chat.retention_changed`, `chat.pruned` (counts only), `chat.hold_placed`, `chat.hold_changed`, `chat.hold_released` |
| Access reviews ([ADR 0099](0099-access-review-report.md)) | `access_review.exported` (the report's digest and summary), `access_review.completed` (an admin's sign-off: digest, summary, notes) |
| Erasure ([ADR 0102](0102-erasing-a-users-data.md)) | `user.erased` (the pseudonym and counts of what went), `user.erase_refused` (outcome `denied`, with the reason) |

**Never logged**: passwords, tokens, API keys, `Authorization` headers, message bodies, routine instructions, handoff and ask text. Approval and policy events do carry the call's subject (the command, path, or URL a person decided on), scrubbed and clipped; the full tool input stays in the approvals table. Each event lists the fields it records; `details` are scrubbed before they are written anyway: keys that look secret (`password`, `token`, `secret`, `api_key`, `authorization`, `cookie`, `credential`, ...) become `[redacted]`, and free text has bearer and basic credentials, `--password` style flags, `key=value` secrets, URL user info and secret query parameters, `curl -u user:pass`, and known token prefixes (`sk-`, `ghp_`, ...) masked. Strings are clipped to 500 characters.

### Who

The auth middleware tags each request with an actor and a source:

- **People**: `user:operator` (one shared password today).
- **Bots**: all Bots share one `BOT_TOKEN`, so `botctl` names the calling Bot in an `X-SuperBot-Bot` header from its `BOT_ID`. That name is self-reported until per-Bot tokens ([approvals follow-up 3](../approvals-followups.md)).
- **Source IP**: the peer address, or the last `X-Forwarded-For` entry when the peer is a proxy on loopback (bash installer, Caddy on the same host) or `TRUST_FORWARDED_FOR=1` (Compose, where Caddy is a separate container and the only way in).

### Reading and export

- `GET /api/audit`: newest first, paged by `before=<id>` (returns `nextBefore`), filters `from`, `to` (unix ms, RFC 3339, or `YYYY-MM-DD`), `action` (exact or `prefix.*`, comma-separated), `actor` (`user`, `bot`, `system`, optionally `:id`), `outcome`, `bot`, `limit` (default 100, max 1000).
- `GET /api/audit/export.csv`: same filters, oldest first, streamed in batches, RFC 4180 (quoted where needed, CRLF). Cells starting with `=`, `+`, `-`, `@`, tab, or CR get a leading `'` so spreadsheets don't run them as formulas.
- `botctl audit [opts]` and `botctl audit export [opts] > audit.csv`, and an Audit log window in the web app.
- People only: the Bot token gets 403, unauthenticated requests 401.

### Retention

`AUDIT_RETENTION_DAYS`, default unset (keep forever); 1 to 36500 deletes older rows every 6 hours and records `audit.pruned`.

Why forever by default: events are small and few (an active install writes a few thousand a day, megabytes a year), deletion is irreversible, and compliance regimes ask for anything from 1 to 7 years, so the safe default is to keep everything and let owners choose a window. The setting is saved in the database, so the delete trigger enforces the same window the server uses, and changing it is itself an event.

Backups: the daily backup (bash timer and Compose `backup` service) takes an online SQLite `.backup` of `app.sqlite`, which includes `audit_events`. Archives are kept for `SUPERBOT_BACKUP_RETENTION_DAYS` (default 14), so a pruned row survives in backups for that long.

## How M2 slots in

Users and SSO fill columns that already exist; no migration of old rows is needed:

- `actor_id` becomes the SuperBot user id (`operator` stays for break-glass Basic auth).
- `actor_name` gets the display name, `actor_subject` the IdP identity as `<issuer>|<sub>` (Entra or Google).
- Filters by person already work (`actor=user:<id>`). RBAC decides who may read the log; today any person can.
- Per-Bot tokens turn the self-reported Bot id into a verified one.

Done in [ADR 0019](0019-audit-actors.md), which also adds the email, role, sign-in method, IdP, session, and on-behalf-of columns, and audits Bot runs and harness invocations.

## Later (M5)

SIEM export: stream events as JSON lines (syslog, HTTPS webhook, or S3) in the same shape, using `id` as the resume cursor. Tamper evidence (a hash chain over rows or write-once storage) belongs with it.

## Alternatives considered

- **Append-only file (JSON lines)**: simpler to ship, but filtering and paging need an index anyway, backups already cover SQLite, and triggers give stronger guarantees than file modes for the same OS user.
- **Log every request**: noisy and likely to capture message bodies. We log named actions with chosen fields instead.
- **Deleting with a plain query, no trigger**: one bug away from losing the log. The trigger reads the same retention setting, so pruning works and nothing else can delete.

## Consequences

- The log is only as trustworthy as the host. Off-box export is the real guarantee and is planned for M5.
- Login events are per session, not per request; a burst of failures shows as one event with a count.
- Bot attribution is honest about its limits: a Bot could claim another's id until per-Bot tokens land.
- The database grows without bound by default; owners who care set `AUDIT_RETENTION_DAYS`.
