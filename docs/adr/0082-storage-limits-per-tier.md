# 0082: Storage limits per tier

## Status

Accepted (21 Nov 2026). Fourth slice of billing v0 ([#31](https://github.com/CG-Labs/superbot/issues/31), [roadmap](../ROADMAP.md)). Builds on tiers ([ADR 0033](0033-tiers-model-routing.md)), tier limits ([ADR 0040](0040-billing-v0-tier-limits.md)), the Plan screen ([ADR 0042](0042-billing-checkout-portal-customers.md)) and billing-period usage ([ADR 0050](0050-billing-period-token-usage.md)). Machine resizing on a tier change and billing emails stay on #31.

## Context

Managed tiers already cap Bots, runs, routine runs, tokens and machine size. Nothing capped disk: one user filling the shared workspace could fill the server for everyone, and the pricing table promises storage as a tier feature. A cap must be optional (self-hosters keep "no limit"), measured per user without leaking one user's files to another, cheap enough to check before every run, and explained in plain words before it bites.

## Decisions

### An optional cap per tier

- A tier's limits may set `maxStorageMb`: whole MB, decimal (1 MB = 10^6 bytes, as disks and the client show it), 1 to 10^9. Unset means no cap. `TIERS_FILE` rejects 0 and anything larger at start.
- The example tiers set Starter 5,000, Pro 25,000 and Max 100,000. Without `TIERS_FILE` the open `self-host` tier has no cap, so nothing changes.

### What counts

- **The user's files:** their workspace folder, `WORKSPACE_DIR/users/<id>`, or their isolation folder under `ISOLATION=users` ([ADR 0029](0029-per-user-isolation.md)).
- **botd's data for them:** `DATA_DIR/users/<id>` and the data folder of each Bot they own (harness sessions, logs, screens).
- **Not counted:** chat history (people can't delete messages, only Bots, so counting it would leave no way back under the cap); teammates' shared spaces; the database itself.
- The walk never follows links (a link counts as itself), counts each file once across both folders (hard links and overlapping roots included), and stops after 500,000 entries.
- A folder botd can't read (for example another OS user's under isolation), or a walk that hit the entry cap, marks the number **partial**: a lower bound, shown as "at least". Enforcement uses it as is.

### Machines: a known gap

- Users whose Bots run on their own machine ([ADR 0025](0025-control-plane-linode.md), [ADR 0065](0065-incus-container-machines.md)) have most files on that machine's disk. Heartbeats don't report disk use yet, so botd counts only what it holds for them, and the view says `onMachine: true`. The tier's `machineType` already bounds that disk. Reporting it from the machine is follow-up work.

### Warning and refusal

- **Warning from 90%.** The first run of each UTC day past 90% still runs; the Bot says "Storage is N% full: X used of the Plan's Y…" in the chat, and `usage.storage_warning` is audited (actor `billing`, on behalf of the owner). The Plan screen shows the same warning whenever it applies.
- **Refused at 100%.** Sending a message to a Bot whose owner is full answers `403` with "Storage is full: X used of the Plan's Y. Delete files from the workspace, or move to a bigger plan, before sending more." and audits `bot.message_refused` (reason `storage_limit`). Runs that start any other way (routines, handoffs, queued messages) are refused like other tier limits: `bot.run_refused` with reason `storage_limit` and one chat bubble. The limit follows the Bot's owner, so teammates using a shared Bot are refused when its owner is full.
- Texts name the plan, the sizes and what to do. They never name a model, a path or another user.
- There is no upload route yet; when one lands it should use the same check.

### Cost of measuring

- Measurements are cached per user: up to 10 seconds old for enforcement, 60 seconds for views, and dropped after each run so the next check sees what the run wrote. Walking happens off the async runtime.
- A run can still write past the cap: the check is before a run, not during it. The next one is refused.

### Where it shows

- `GET /api/me/tier`, `GET /api/me/usage`, `GET /api/billing`, `GET /api/users`, `GET /api/users/{key}`, `GET /api/users/{key}/usage` and `GET /api/usage` carry `storage`: `{used, files, data, limit, limitMb, percent, state: ok|warning|over, warnAt, partial, measuredAt, onMachine}`. Byte counts only; no folder names.
- `GET /api/usage` lists `maxStorageMb` among a user's `over` limits when full.
- `botctl usage` prints storage against the plan.
- The client's Plan screen shows the storage line and warning; admins see each user's in the user view, and plan cards list the tier's storage.

## Consequences

- Managed tiers can sell storage, and one user can no longer fill the server unnoticed.
- Full users can still read their chats and delete files or Bots; they just can't start new work until under the cap.
- Machine users' numbers are low until machines report disk use.
- Deleting chat history to free space isn't possible, so it isn't counted; if it grows large, it needs its own limit.
