# 0110: Recovery objectives for Linode machines

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row A1.2-2 in the [readiness checklist](../security/soc2-readiness-checklist.md). Builds on the Linode control plane ([ADR 0025](0025-control-plane-linode.md)), machine enrollment ([ADR 0031](0031-machine-enrollment-mtls.md)), machine RPO and RTO ([ADR 0074](0074-machine-rpo-and-rto.md)), alerts ([ADR 0061](0061-approval-notifications.md)) and metrics ([ADR 0089](0089-metrics-and-structured-logs.md)).

0108 is the highest number on `main`. Open PR [#171](https://github.com/CG-Labs/superbot/pull/171) holds 0109.

## Context

Incus machines have off-host backups with an RPO per tier and an RTO, checked by botd, audited and alerted (ADR 0071, ADR 0074). Linode machines had only `MACHINE_BACKUPS=on`: botd turned on Linode Backups once a machine enrolled and re-tried when they were off (ADR 0025). Nothing said how old a machine's newest backup was, nobody heard when a backup stopped happening, and [machine-recovery-objectives.md](../security/machine-recovery-objectives.md) left Linode machines out. A1.2 asks for backups that are monitored against objectives.

What Linode offers:

- One backup a day per Linode, in a two-hour window Linode picks (an operator can pick it per Linode), plus a weekly and a fortnightly one. No schedule of our own.
- `GET /v4/linode/instances/{id}` includes `backups.enabled` and `backups.last_successful` (UTC, no zone). botd's reconciler already calls it for every machine each `MACHINE_RECONCILE_SECONDS`.
- Restores are a Cloud Manager or API action that overwrites the Linode's disks (or makes a new Linode).

## Decision

### Linode's own backups, held to an RPO

- `ProviderMachine` gains `last_backup_at`, and `MachineProvider` gains `reports_backups()` (false by default; true for Linode and the fake provider). The Linode client reads `backups.last_successful`. No new Linode call: it comes with the `get` reconciling already makes.
- The machine record keeps it as `provider_backup_at` (migration 44), shown to admins as `providerBackupAt`.
- With `MACHINE_BACKUPS=on` and a provider that reports backups, botd holds every running machine to **`MACHINE_BACKUPS_RPO_HOURS`**: 26 by default (a day and Linode's window), 25 to 168. One number for every tier: Linode backs every plan up daily, so per-tier RPOs would only be different alarm thresholds for the same schedule. The setting is refused unless backups are on and the provider reports them, and is a different name from Incus's per-tier `MACHINE_BACKUP_RPO_HOURS` so neither silently reads the other's.
- A machine is covered since its newest Linode backup or its creation, whichever is later. A running machine past the RPO is a breach. Suspended, provisioning and destroyed machines aren't tracked, as for off-host backups. Nor is a machine with no backup time saved until the provider has described it since botd started (`not_checked_yet`), so the first start after upgrading doesn't alert on every old machine before reconciling has read its backups.
- Breaches reuse ADR 0074's machinery as is: the `machine_rpo_breaches` table, `machine.rpo_breached` (failure) and `machine.rpo_recovered` audit events, and the email and webhook alerts. They're checked every minute against the saved times on a timer of their own, not after each reconcile, so slow Linode calls or a long `MACHINE_RECONCILE_SECONDS` can't delay an alert. The details say `backups: provider`, the provider, whether backups are on, and the last backup. The alert says when the last backup was, or that there's none, and whether Linode Backups are off. A machine's view gains `recovery` like an Incus machine's.
- Off-host backups win: with `MACHINE_BACKUP_S3_BUCKET` set (Incus only), nothing changes.

### Metrics

Only with `/metrics` on, from botd's records (the scrape never calls Linode), for running machines of the provider, labelled `provider` and `tier` only:

| Metric | Meaning |
|---|---|
| `superbot_machines_provider_backups{backups="on\|off"}` | Machines with the provider's backups on or off. Written even with `MACHINE_BACKUPS=off`, so that is alertable. |
| `superbot_machines_past_provider_backup_rpo` | Machines past the RPO now |
| `superbot_machine_provider_backup_age_max_seconds` | Age of the oldest newest-backup (or creation) |
| `superbot_machine_provider_backup_rpo_seconds` | The RPO |

`superbot_machine_rpo_breaches_open` is written for these too. The age is the maximum by tier, not one series per machine, to keep ADR 0089's bounded labels; the breach audit names the machine.

[`deploy/prometheus/superbot-backups.rules.yml`](../../deploy/prometheus/superbot-backups.rules.yml), tested with `promtool` in CI: `SuperBotMachineBackupsStale` (the oldest is past the RPO for 15 minutes) and `SuperBotMachineBackupsOff` (any running machine with backups off for an hour), both tickets. A test fails if the rules use a metric botd doesn't write.

### No measured RTO

botd neither restores Linode machines nor sees a restore start or finish, so it can't time one. The [recovery objectives](../security/machine-recovery-objectives.md#linode-machines) state a restore time target of 4 hours as the Provider's own, drill-backed, not a measured objective, and the [operator guide](../ops/machine-recovery.md#restoring-a-linode-machine) gives the procedure: suspend through botd, restore onto the same Linode in Cloud Manager, revoke its certificates, resume, and enroll it with a token. A restored disk may hold a certificate that was rotated or revoked since, so it always enrolls anew, as a restored Incus machine does. `botctl machine revoke <user> --yes` and `botctl machine enroll <user>` wrap the existing admin endpoints for this.

### Tests

- **Linode stand-in** (no real Linode): `last_successful` is read into `last_backup_at`; Linode's zone-less times are UTC.
- **Settings**: the default, a value, out of range, and set with backups off or with Incus.
- **HTTP with the fake provider** (`machines_provider_backup_tests`): backups are turned on and the last backup stored; a backup older than the RPO opens one audited, mailed breach shown in the view and in `/metrics` without ids; a newer one recovers it; backups turned off and failing to turn on breach again, say so in the alert and in the `off` metric; suspending ends the breach; with `MACHINE_BACKUPS=off` nothing is held.
- **promtool**: both alerts fire and stay quiet as they should.

## Consequences

- Linode machines have a measured RPO, alerts and a documented restore, so A1.2-2 is done.
- No extra Linode API calls or cost; the age is as fresh as the reconcile interval.
- Machines enrolled while `MACHINE_BACKUPS` was off breach at once when it's turned on, if older than the RPO, and recover at their first backup.
- Not covered: botd-driven Linode restores and a measured RTO for them, restore drills of Linode machines, an admin list of Linode machines' recovery like `GET /api/machines/recovery` (it stays off-host only; each machine's view has it), and losing the Linode data centre that holds both a machine and its backups.
