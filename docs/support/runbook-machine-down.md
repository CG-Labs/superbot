# Runbook: machine down or restore

A user's machine doesn't answer, a whole Incus host is down, or the SuperBot server itself is. Severity: [1](severity.md#severities) for the server, 2 for a host (many users), 3 for one machine. The full procedures are in [machine recovery](../ops/machine-recovery.md) and [backup and restore](../ops/backup-restore.md); this page is the order to work in.

## First five minutes

1. **Which one.** Ask which user, and what they see: Bots failing because their machine isn't ready, the screen not loading, or the app not loading at all.
2. **Server or machine.** If `/status.json` or the app doesn't answer, it's the server: [below](#the-server-itself). Otherwise the status page's machines component shows whether a host is down.
3. **The machine's state**, as an admin on the server:

   ```sh
   botctl machine show <user>        # provider, plan, state, address, enrollment, last error
   botctl machine list error
   botctl machine hosts check        # Incus hosts: up, down or lost
   botctl machine recovery           # backups against RPO, restores against RTO
   ```

   A support bundle has the same counts in `health.json` (`machines`), plus recent `machine.*` failures in `audit-summary.json`.

## One machine

| State or symptom | Do |
|---|---|
| `suspended` | Suspended by an admin, a disabled user, or billing. `botctl machine resume <user>` if it should run; check why first (`botctl audit --action 'machine.*'`). |
| `pending`, not enrolling | `botctl machine show <user>` names the enrollment step. Waiting for room: `machine.placement_failed` in the audit log means no host has room for its plan ([ADR 0081](../adr/0081-placing-machines-by-host-load.md)). |
| `error` | The last error is on `botctl machine show <user>`. `botctl machine reconcile` retries what can be retried. |
| Running but Bots fail | The agent may be down or its certificate rotated. Run `botctl machine reconcile`, then check the user's harness logins (`botctl machine harness-logins <user>`). |
| Broken beyond repair, or the user lost data | Restore from a backup (below). |

### Restore one machine

Everything on it since the backup is lost, so the user agrees first, in the ticket.

- **Incus:** `botctl machine backups <user>` lists backups; `botctl machine restore <user> <backup-id> --yes` makes it again from one, and it enrolls anew. Add `--identity <age-key-file>` if the server doesn't hold the backups' age identity, and `--host <name>` to put it on another host. Follow it with `botctl machine restore <user> status`. ([Machine recovery](../ops/machine-recovery.md), [ADR 0071](../adr/0071-off-host-machine-backups.md).)
- **Linode:** botd doesn't restore Linode machines; follow [restoring a Linode machine](../ops/machine-recovery.md#restoring-a-linode-machine) step by step, and note the time against the RTO.

The plan's RPO and RTO are the commitment ([recovery objectives](../security/machine-recovery-objectives.md)); `machine.restored` records the time taken and whether it was within the RTO. Tell the user what was lost (since the backup's time) when it's back.

## A whole Incus host

botd alerts "Incus host `<name>` isn't answering" after `INCUS_HOST_DOWN_MINUTES` (`machine.host_down`); every machine on it is down. Post a partial outage of machines on the status page.

1. Find out from the hosting provider whether it's coming back. If it might, wait: restoring elsewhere too early leaves two copies of each machine. botd never decides this.
2. If it isn't: power it off at the provider if you can, then `botctl machine host recover <name> --yes` restores each of its machines from its newest backup onto other hosts ([losing a whole Incus host](../ops/machine-recovery.md#losing-a-whole-incus-host), [ADR 0076](../adr/0076-restoring-onto-another-incus-host.md)).
3. Machines with no backup go to `error`: destroy and request a new one for that user, and tell them.
4. Run the recover command again for any it skipped for lack of room once there is room.

## The server itself

The service is down for everyone: Severity 1, page the on-call engineer, post an incident within 15 minutes of confirming it ([SLO](../slo.md#status-page-and-incidents)).

1. **Is botd running?** `systemctl status superbot` and `journalctl -u superbot -n 200` (installer), or `docker compose ps` and `docker compose logs --tail 200 botd` (Compose). A botd that refuses to start says why in its last lines: usually a setting it rejects, a full disk, or the database key.
2. **The host.** Disk (`df -h`), memory, and the hosting provider's status. Caddy in front of it (`systemctl status caddy`, or the `caddy` container) if botd answers on `127.0.0.1:3000` but not outside.
3. **Restore**, if the server or its data is lost: [backup and restore](../ops/backup-restore.md#restore), installer or Compose, same host or new. The server's RTO is 1 hour; you need the newest off-host backup ([ADR 0109](../adr/0109-server-backups-off-the-host.md)), the age identity that decrypts it ([ADR 0114](../adr/0114-backups-encrypted-by-default.md)), and the master key ([master key rotation](../ops/master-key-rotation.md)). Machines keep running meanwhile and enroll back once it's up.
4. When it's back: a support bundle (`botctl support-bundle`), to check health and the start-up lines, and the status page incident resolved with a note.

## Escalate when

- A restore fails (`machine.restore_failed`) or runs past its RTO (`machine.restore_rto_exceeded`).
- A machine's backups are past their RPO and the cause isn't obvious ([alerts](../ops/machine-recovery.md#alerts)).
- The server can't be restored within its RTO, or a backup won't decrypt.
- More than one host is down at once.

## Afterwards

Record restore times against the RTO with the drill records. A Severity 1 gets a written review ([escalation](escalation.md#after-a-severity-1)).
