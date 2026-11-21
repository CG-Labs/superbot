# Machine recovery: RPO, RTO and drills

How botd holds users' Incus containers to a recovery point objective (RPO) and a recovery time objective (RTO) per tier, how it tells you when one is missed, and how to drill a restore. Design: [ADR 0074](../adr/0074-machine-rpo-and-rto.md). Backups and restores themselves: [ADR 0071](../adr/0071-off-host-machine-backups.md) and [setup](incus-containers.md#7-off-host-backups-optional). The text for customers is in [machine recovery objectives](../security/machine-recovery-objectives.md).

This needs off-host backups on (`MACHINE_BACKUP_S3_BUCKET` set). Linode machines use Linode's own backups and aren't tracked.

## Settings

Each takes one number for every tier, or a default and per-tier values, like `MACHINE_BACKUP_RETENTION`. A setting naming a tier that isn't in `MACHINE_TIERS` stops botd from starting.

| Setting | Default | Meaning |
|---|---|---|
| `MACHINE_BACKUP_INTERVAL_HOURS` | `24,pro=12,max=6` | How often each machine is backed up. Setting it replaces the whole default. |
| `MACHINE_BACKUP_RPO_HOURS` | interval + 2 | The most a machine's newest off-host backup may lag. At least the interval plus 1, or botd won't start. |
| `MACHINE_RESTORE_RTO_MINUTES` | `60` | The most a restore may take, from the request to the agent enrolling again. |

botd logs each tier's numbers at start. Keep the RPO you put in a contract no tighter than these: the defaults allow one failed attempt and its retry an hour later.

Mind the storage: every backup is a full export. At 14 days' retention, a machine backed up every 6 hours keeps 56 copies. `MACHINE_BACKUP_RETENTION=14,max=7` keeps 28.

Mind the time: botd runs one backup at a time, machines nearest their RPO first. Machines × backups a day × minutes each must stay well under 1,440. If it doesn't, machines breach their RPO and you are told.

## Alerts

botd checks every machine each reconcile interval (`MACHINE_RECONCILE_SECONDS`, 60 by default). It alerts through the notification email list and webhook in the console's Settings ([ADR 0061](../adr/0061-approval-notifications.md)); nothing is sent until one is set.

| Event | Audit action | When |
|---|---|---|
| Past its RPO | `machine.rpo_breached` (failure) | A running machine's newest backup, newest restore and creation are all older than its RPO. Once per breach. |
| Back within its RPO | `machine.rpo_recovered` | A backup lands. The breach also ends, silently, when the RPO is raised past its age or the machine stops counting (suspended, destroyed, restoring). |
| Restore past its RTO | `machine.restore_rto_exceeded` (failure) | A restore still underway past the RTO (`underway: true`), or one that took longer (`underway: false`). Once per restore. |
| Restore failed | `machine.restore_failed` (failure) | As before (ADR 0071); now alerted too. |
| Incus host down | `machine.host_down` (failure, target type `host`) | A host hasn't answered for `INCUS_HOST_DOWN_MINUTES` (10). Once each time ([ADR 0076](../adr/0076-restoring-onto-another-incus-host.md)). |
| Incus host up again | `machine.host_up` | A down host answers again. |
| No room for a machine | `machine.placement_failed` (failure, target type `user` or `machine`) | No open Incus host has room for a new or waiting machine's plan ([ADR 0081](../adr/0081-placing-machines-by-host-load.md)). Each refused request, and once per waiting machine. |
| Incus host declared lost | `machine.host_lost` (failure) | An admin recovered it (below). Once. |

`machine.restored` carries `durationMs`, `rtoMs` and `withinRto`.

Webhooks in the JSON format get `{"type": "<audit action>", "alert": {...}, "text": ..., "sentAt": ...}`.

On a breach: look at the machine's backups (`botctl machine backups <user>`). The alert names the last error and why a backup can't run now, if it can't (not enrolled, enrollment token still on it, a restore underway). Fix that, then `botctl machine backup <user>` takes one now.

## Seeing where things stand

```bash
botctl machine recovery
```

Or `GET /api/machines/recovery` (admins): each tier's targets, each machine's newest backup, its age against its RPO, any open breach, and its last restore against its RTO; then the newest 100 breaches and newest 50 restores with their timing. Poll it from your monitoring; `breaching` is the number of machines past their RPO right now.

The console's Machines page shows an off-host backup column (age, the tier's RPO and RTO, late) and a line naming each machine past its RPO.

## Restore drill

### In CI, on a real Incus host

The `incus-e2e` workflow ([ADR 0069](../adr/0069-validating-incus-containers-on-a-real-host.md)) backs a real container up, changes it, restores it, and fails if the restore took longer than the tier's RTO. The timing is in the job summary and in the `restore-drill-<incus>` artifact (`durationMs`, `rtoMs`, `backupBytes`). It runs on changes to the machine code, weekly, and by hand. It drills losing a whole host too: one Incus with a second project stands in for a second host, the first "host" stops answering and its container is deleted, and the test declares it lost, restores the container into the second project and fails past the RTO (artifact `host-drill-<incus>`, with `fromHost` and `toHost`). The CI container's disk is small, so this proves the path and the clock, not how long a full 80 GB disk takes. On the runner a 253 MB backup restores in about a minute, roughly 5 MB/s of import; drill a large machine on your own hardware before you promise 60 minutes for one.

### By hand, on your server

Once a month, restore a machine kept for drills, on the tier and host your customers use, with real data on it:

```bash
botctl login                      # as an admin
deploy/machine-restore-drill.sh drill@<your-domain> --fresh --yes
```

It shows the objectives, takes a backup with `--fresh` (otherwise uses the newest), restores from it, waits, and prints how long botd recorded against the RTO. It exits non-zero if the restore failed or ran past the RTO. It stops waiting 3 minutes after the RTO (`SUPERBOT_DRILL_GRACE_SECONDS`), time for botd to record a restore that finished just in time; botd carries on with one that didn't. Pass or fail is from the time botd recorded. Add `--identity <age key file>` when the server doesn't hold the backups' age identity. Needs `botctl` and `jq`.

Never point it at a customer's machine: everything on it since the backup is lost.

Keep each run's last line (the JSON with `durationMs` and `rtoMs`) with your drill records. The audit log has the same as `machine.restored`.

## What the RTO doesn't count

- Noticing the loss and deciding to restore.
- Bringing back botd itself, if it was lost too ([backup and restore](backup-restore.md), RTO 1 hour).
- Noticing that a whole Incus host is gone: up to `INCUS_HOST_DOWN_MINUTES` before it is down and you are alerted, and then your decision that it isn't coming back.
- Setting up a replacement host, if you had no spare one in `INCUS_HOSTS`.

## Losing a whole Incus host

With more than one host in `INCUS_HOSTS` ([setup](incus-containers.md#several-hosts), [ADR 0076](../adr/0076-restoring-onto-another-incus-host.md)), a host that is gone can have its machines made again on another, from their newest off-host backups.

1. botd alerts **Incus host `<name>` isn't answering** after `INCUS_HOST_DOWN_MINUTES`. Its machines are left as they are, and new ones go elsewhere. `botctl machine hosts check` shows every host.
2. Find out whether it is coming back. If it might, wait: restoring elsewhere first would leave two copies of each machine. botd never decides this for you.
3. If it isn't, power it off at your hosting provider if you can, then:

```bash
botctl machine host recover <name> --yes                       # onto the first other host that is up
botctl machine host recover <name> --to <host> --identity backup-identity.txt --yes
```

It declares the host lost (for good; a replacement gets a new name), revokes its machines' certificates and tokens, and restores each from its newest off-host backup onto another host, two at a time. Without `--to`, each goes where placement puts it ([ADR 0081](../adr/0081-placing-machines-by-host-load.md)): an open host with room for it, counting the ones placed before it; one with nowhere to go is skipped, to retry once there is room. Each enrolls anew. A machine with no backup goes to error: destroy it and request a new one for that user. The answer lists what is restoring, what can't be, and what was skipped; run it again to retry the skipped ones. `botctl machine recovery` shows each restore's time against the RTO.

The data lost is everything on each machine since its newest backup. A whole host's restores take about machines ÷ 2 × one restore's time.

To empty a host that still works (to retire it), move its machines one at a time: `botctl machine restore <user> <backup-id> --host <other> --yes`. That deletes the old container once the new one is ready.
