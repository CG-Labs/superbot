# Runbook: backups failing or late

The server's own backups or users' machines' backups stop, fail, stay on the host or fall behind their RPO. Nothing is lost yet: this is the time to fix it, before a restore needs a backup that isn't there. Severity: [2](severity.md#severities) when server backups are past their RPO or a whole tier of machines is, since the next lost host loses more than the customer was promised; 3 for one machine's backups, or server backups that work but stay on the host; 1 only when data is already lost beyond the RPO, which is a [server restore](runbook-server-restore.md) or a [machine restore](runbook-machine-down.md#restore-one-machine).

The procedures are in [backup and restore](../ops/backup-restore.md) and [machine recovery](../ops/machine-recovery.md); this page is the order to work in.

## First five minutes

1. **Which backups.** The server's own (botd's database, Bot memory and users' files, archived by `superbot-backup` and copied off the host by botd), or users' machines (Incus containers' off-host backups, or Linode's own)? The [health score](health-score.md#backups)'s `backups` signal and its summary say which, and so does the alert the customer got.
2. **Where things stand**, as an admin on the server:

   ```sh
   botctl backups                     # server backups: the store, the newest copies, their errors, the RPO, encryption
   botctl machine recovery            # machines: each tier's RPO and RTO, and those past their RPO
   botctl audit 50 --action 'server.backup_*'
   botctl audit 50 --action machine.backup_failed
   ```

   With botd down, `botd support check` reads the local archives and botd's record of copies without it ([support check](support-check.md#the-checks)). A support bundle has the week's failures in `audit-summary.json`, and [bundle triage](triage.md) lists them as `audit.backups`.
3. **Did anything change?** The store's keys rotated or its bucket policy changed, the bucket was moved or filled its quota, `SERVER_BACKUP_*` or `MACHINE_BACKUP_*` settings edited, the timer or the Compose `backup` service stopped, the disk filled, an upgrade, or a residency pin.

## Server backups

| What botd says | Usually | Fix |
|---|---|---|
| Server backups aren't set up; they stay on this host | No store: `SERVER_BACKUP_S3_*` unset, and no machine backup store to share | Give botd a store of its own ([off-site copies](../ops/backup-restore.md#off-site-copies)). If the customer copies archives off the host themselves, `SERVER_BACKUP_OFF_HOST=off`, and they check their own copies |
| No server backup has been copied off the host yet | A store was just set, or every copy so far failed | `botctl backups copy` copies the newest archive now and says why if it can't |
| `server.backup_copy_failed` | The store refused the upload: wrong keys, a bucket or endpoint that moved, a policy without the multipart actions, a full quota; `interrupted` means botd stopped mid-copy | The event's `error` says which. Fix the keys or the policy, then `botctl backups copy`. botd retries a failed copy after 30 minutes by itself |
| `server.backup_rpo_breached` | The newest copy off the host is older than `SERVER_BACKUP_RPO_HOURS` (26 by default): copies fail, or `superbot-backup` writes no new archive | The alert names the last copy error, or that no newer archive exists. No archive: `journalctl -u superbot-backup` (Compose: `docker compose logs backup`) says why: the timer stopped, the disk is full, `age` or the master key missing. Then back up now: `sudo systemctl start superbot-backup.service` (Compose: `docker compose exec botd superbot-backup`) |
| No archives, or the newest is more than a day old (`botd support check`) | The timer or the Compose service hasn't run | As above, from `journalctl -u superbot-backup`; check `systemctl list-timers superbot-backup.timer` shows the next run |
| Backups aren't encrypted | No age recipients for that target | Set them ([encryption](../ops/backup-restore.md#encryption)), and copy the identity off the host |

A breach ends by itself, audited as `server.backup_rpo_recovered`, when a copy lands within the RPO. Check one does: `botctl backups` shows the newest copy's time.

## Machine backups

| What botd says | Usually | Fix |
|---|---|---|
| `machine.backup_failed` | One machine's off-host backup failed: not enrolled yet, a restore underway, the store refused it; `interrupted` means botd stopped mid-backup | The event's `error` says which. Fix it, then `botctl machine backup <user>` takes one now |
| `machine.rpo_breached` | A running machine's newest backup is older than its tier's RPO | The alert names the last error and why a backup can't run now ([machine recovery](../ops/machine-recovery.md#alerts)). Many machines at once point at the store, not the machines |
| `machine.backups_failed` | Linode backups couldn't be turned on for a machine | The event's `error` is Linode's. Check the Linode account allows backups, then let the reconcile retry ([Linode machines](../ops/machine-recovery.md#linode-machines)) |
| `machine.backups_delete_failed`, `machine.backups_delete_refused` | Deleting a destroyed machine's backups stopped part way, or was refused (the machine still exists, a backup or restore is running, no store set) | Ask again to finish (`botctl machine delete-backups <machine-id> --yes`); what went stays gone ([ADR 0108](../adr/0108-deleting-a-destroyed-machines-backups.md)) |

A pinned customer's machine backups refused for residency (`machine.residency_refused`) are the [residency runbook](runbook-residency.md#refusals-and-fixes)'s.

## Before telling the customer it's fixed

1. A new copy has landed: `botctl backups` (server) or `botctl machine recovery` (machines) shows it within the RPO, and `botctl health-score` no longer says it's past its RPO (failed machine backups stay in its 30-day window, as watch).
2. For server backups, check that copy is whole: download it, compare its SHA-256 with its manifest, and run `superbot-restore --check` on it ([check an archive](../ops/backup-restore.md#check-an-archive)).
3. Tell the customer how long backups were late, from the breach's start to the copy, and so what a lost host in that time would have cost.

## Escalate when

- Copies fail with an error the store doesn't explain, or every new archive fails `superbot-restore --check`.
- botd shows copies landing but the store doesn't have them, or the manifests' SHA-256 don't match the objects.
- Backups were past the RPO when a restore was needed: data is lost beyond the RPO, [Severity 1](runbook-major-incident.md).

## Afterwards

Note the cause in the ticket. If keys or a store changed, put who holds them and when they rotate in the customer's onboarding record ([onboarding](onboarding.md#4-backups-and-recovery)). Book a restore drill from the new copies if the last one is more than a quarter old ([drills](../ops/backup-restore.md#drills), [TAM cadence](tam.md#cadence)).
