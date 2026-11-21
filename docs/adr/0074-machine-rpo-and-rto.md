# 0074: RPO and RTO for managed machines

## Status

Accepted. Builds on [ADR 0071](0071-off-host-machine-backups.md) (off-host backups and restore), [ADR 0069](0069-validating-incus-containers-on-a-real-host.md) (the real-host test), [ADR 0061](0061-approval-notifications.md) (notifications) and [ADR 0030](0030-backup-restore-drill.md) (the self-host drill and its targets). The control plane's next step on [#29](https://github.com/CG-Labs/superbot/issues/29), and the contractual RPO and RTO in [#40](https://github.com/CG-Labs/superbot/issues/40).

## Context

ADR 0071 backs each Incus container up off the host on one schedule for every tier, and restores it with fresh enrollment. Nothing said how old a machine's newest off-host copy may get, how long a restore may take, or noticed when either target was missed. A contract (an SLA, or a DPA's availability clause) needs numbers the system keeps and can show it kept.

## Decision

### Targets per tier

Each tier has three numbers, set beside the backup settings. Each takes the same form as `MACHINE_BACKUP_RETENTION`: one number for every tier (`24`), or a default and per-tier values (`24,pro=12,max=6`).

| Setting | Meaning | Default |
|---|---|---|
| `MACHINE_BACKUP_INTERVAL_HOURS` (1 to 720) | How often each machine is backed up. | `24,pro=12,max=6` |
| `MACHINE_BACKUP_RPO_HOURS` (2 to 744) | The most a running machine's newest off-host backup may lag. A tier not named: its interval plus 2. | interval + 2 |
| `MACHINE_RESTORE_RTO_MINUTES` (5 to 1440) | The most a restore may take, from the admin's request to the machine's agent enrolling again. | 60 |

With the default tiers (ADR 0065's `starter`, `pro`, `max`), that is:

| Tier | Backed up every | RPO | RTO | Copies kept at 14 days' retention |
|---|---|---|---|---|
| starter (and any other tier) | 24 h | 26 h | 60 min | 14 |
| pro | 12 h | 14 h | 60 min | 28 |
| max | 6 h | 8 h | 60 min | 56 |

A set `MACHINE_BACKUP_INTERVAL_HOURS` replaces the default schedule entirely, so `24` means every tier daily. botd refuses to start if any tier's RPO is less than its interval plus one hour, or if a setting names a tier that isn't in `MACHINE_TIERS`. The default schedule's tier names needn't exist.

### Why these numbers

**RPO.** The schedule starts a machine's backup once its newest is an interval old. The backup is a point-in-time export taken when it starts, so the oldest data at risk just before the next backup lands is the interval, plus the wait for the next pass (one reconcile interval, 60 seconds by default), plus that backup's export and upload. If that attempt fails, it is retried after an hour (ADR 0071). Two hours of headroom covers one failed attempt, its retry, and two exports of up to half an hour each. Thirty minutes is enough for the default tiers' largest disk (80 GB) at about 50 MB/s to the store, and exports are only the used, compressed blocks. One hour is the least botd allows: the retry alone.

The default schedule tightens with the tier because the tiers sell more resources, not a different service. It is still a full export each time (ADR 0071), so storage grows with copies kept. At the default retention, max keeps 56 copies; `MACHINE_BACKUP_RETENTION=14,max=7` halves that. Incremental backups would change this trade (Later on the roadmap).

**RTO.** A restore downloads, checks and decrypts the backup while importing it, swaps it in, starts it, and waits for its agent to enroll. The import is proportional to the backup's size. The rest is seconds: [ADR 0069](0069-validating-incus-containers-on-a-real-host.md) measured enrollment at about 6 seconds with a cached image, and the real-host test measures the whole restore on every run (below). Sixty minutes is the same as the self-host server's RTO (ADR 0030). It covers an 80 GB backup at about 25 MB/s with room for the boot. A restore that hasn't enrolled within the enrollment timeout plus ten minutes fails anyway (ADR 0071).

### What botd tracks

**RPO.** A machine is held to its RPO while it is running, or in error after it once enrolled, on this server's provider, with no restore underway. A suspended machine's disk doesn't change, so it isn't. A restore is held to the RTO instead.

A machine is *covered since* the latest of: when its newest finished backup was taken, when its newest finished restore ended (what's on it then came from a backup), and when it was made (nothing on it yet). It breaches its RPO when now minus that is more than the RPO.

Every reconcile interval, in the loop that follows restores (not the one that runs backups, which can take hours), botd checks every machine:

- A machine newly past its RPO opens a breach in `machine_rpo_breaches`: when it began (covered since plus the RPO), when botd saw it, the tier and the RPO. It is audited once as `machine.rpo_breached` (outcome `failure`), with the newest backup, the last failed attempt's error, and why it can't be backed up now, if it can't.
- An open breach ends when the machine is covered again (`backed_up`), when its tier's RPO grows past its age (`objective_changed`), or when it stops counting (`suspended`, `destroyed`, `restoring`, ...). It is audited as `machine.rpo_recovered`, with how long it lasted.

The schedule backs up the machines nearest their RPO first, so a long round spends its time where it's needed.

**RTO.** A restore records its machine's tier and RTO when it is asked for. When it is done, botd records `duration_ms`: from the request to the moment the agent enrolled, not to when botd next looked. `machine.restored` carries `durationMs`, `rtoMs` and `withinRto`. A restore that took longer, or is still underway past its RTO, is audited once as `machine.restore_rto_exceeded` (outcome `failure`, `underway` true or false).

### Alerts

Breaches, recoveries from them, restores past their RTO and failed restores are alerted through ADR 0061's channels, to the global email list and global webhook only. Never to a Bot's deciders or its own webhook: these are for operators. The alert is a new notice kind, `alert`: email and Slack-style text with what happened and a link to the console's Machines page, and in the JSON format `{type: <audit action>, alert: {event, title, lines, targetType, targetId, link}, text, sentAt}`. It is audited as `notification.sent` or `notification.failed`, with the machine as the target. Nothing is sent unless an admin turned on a channel.

### Where admins see it

- `GET /api/machines/recovery`: each tier's targets, every live machine against them, the newest 100 breaches and the newest 50 restores with their timing. `botctl machine recovery` shows it.
- Each machine's admin view has `recovery`; `GET /api/machines/backups` shows the targets.
- The console's Machines page has an off-host backup column (age, RPO, RTO, late) and a line naming every machine past its RPO.

No Prometheus endpoint: botd has no metrics endpoint, and adding one is more than this needs. The recovery API is the thing to poll, and the audit events are the record.

### Drills

- **On a real Incus host in CI.** The `incus-e2e` job (ADR 0069) already backs a real container up, changes it and restores it. It now also reads the restore's recorded duration and fails if it is over the tier's RTO. It checks that the recovery API shows the machine tracked and within its RPO, writes the timing to the job summary, and uploads it as an artifact (`restore-drill-<incus>`). It runs on machine changes, weekly, and by hand.
- **Against stand-ins**, in `machines_backup_tests`: a machine past its RPO is audited once, alerted by email, shown in the API, the console's view and the machine's view, and cleared by a backup. Each tier is due and breaches on its own schedule. A destroyed machine's breach ends. Restores are timed until enrollment. A restore still underway past its RTO is audited and alerted once, and recorded as late when it finishes. A failed restore is alerted.
- **By hand on a managed server**: `deploy/machine-restore-drill.sh <drill user> [--fresh] --yes` restores a machine kept for drills from its newest (or a fresh) backup, waits for it, and fails if botd's recorded time is over the RTO ([guide](../ops/machine-recovery.md)). It is meant for a monthly drill. Never point it at a customer's machine: everything since the backup is lost.

### Customer-facing text

[docs/security/machine-recovery-objectives.md](../security/machine-recovery-objectives.md) states the targets in contract terms. It says only what botd enforces and measures, and what it doesn't.

## Consequences

- Each tier's RPO and RTO are checked, not just written down. A missed backup becomes an audited, alerted breach within a reconcile interval, and every restore's time is on record against its target.
- pro and max machines are backed up two and four times a day by default, so they use two and four times the storage of a daily schedule at the same retention.
- Backups still run one at a time per botd. If the machines due in a day take longer to export than a day has, some will breach; the alerts say so. The rule of thumb: machines × backups a day × minutes each must stay well under 1,440.
- The RTO counts from the restore request. It doesn't count noticing the loss, deciding to restore, or bringing back botd itself (ADR 0030's 1 hour, when botd is lost too).
- Not covered: Linode machines (Linode's own backups, no RPO tracking), restoring to a different host than the one the machine is on (ADR 0071), automatic restores, incremental backups, and export to customer-owned storage beyond pointing the bucket at it. The last three stay Later on the roadmap.
