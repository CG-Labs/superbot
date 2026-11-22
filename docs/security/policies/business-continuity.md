# Business continuity and disaster recovery plan

How a managed SuperBot service keeps running, or comes back within its objectives, when a server, a host, a store, a vendor, a key or a person is lost. Part of the [policy set](README.md). The procedures it relies on are the operator guides for [backup and restore](../../ops/backup-restore.md) and [machine recovery](../../ops/machine-recovery.md). **Draft, not adopted. SuperBot is not SOC 2 certified.**

| Field | Value |
|-------|-------|
| Owner | Management |
| Approver | Management |
| Review | Yearly, and after every test or real recovery |
| Status | Draft, not yet approved |
| Controls | A1.1-3, A1.2-1, A1.2-2, A1.3-1, CC6.7-2, CC9.1-1, CC9.1-2 |

## Objectives

| What | RPO (most data lost) | RTO (longest to restore) | Where it's set and checked |
|------|----------------------|--------------------------|----------------------------|
| The botd server (database, sealed secrets, Bots' folders) | 26 hours with the daily archive: the interval plus 2 hours (`SERVER_BACKUP_RPO_HOURS`) | 1 hour | [ADR 0030](../../adr/0030-backup-restore-drill.md), [ADR 0109](../../adr/0109-server-backups-off-the-host.md); `botctl backups` |
| Incus machines | By plan: 26 hours (Starter), 14 (Pro), 8 (Max) | 60 minutes | [Machine recovery objectives](../machine-recovery-objectives.md#objectives), [ADR 0074](../../adr/0074-machine-rpo-and-rto.md); `botctl machine recovery` |
| Linode machines | 26 hours by default (`MACHINE_BACKUPS_RPO_HOURS`) | The operator's drilled restore time target | [Machine recovery objectives](../machine-recovery-objectives.md#linode-machines), [ADR 0110](../../adr/0110-linode-machine-recovery-objectives.md) |
| Uptime | Per plan in the [SLO](../../slo.md) | | `/status`, the burn-rate alert rules |

botd checks the RPOs itself every minute and audits and alerts each breach (`machine.rpo_breached`, `server.backup_rpo_breached`); restores past their RTO are audited as `machine.restore_rto_exceeded`. A contract states objectives no stricter than these, and the SLO explains why an SLA should sit below its objective.

Backups are encrypted with age by default on new installs and copied off the host ([ADR 0114](../../adr/0114-backups-encrypted-by-default.md), [ADR 0071](../../adr/0071-off-host-machine-backups.md)). The managed service runs with `SUPERBOT_BACKUP_ENCRYPTION=required` and `SERVER_BACKUP_OFF_HOST=on` ([configuration baseline](information-security.md#configuration-baseline)), and keeps its backup store with a different provider, or at least in a different region, from the hosts it backs up, within each customer's data region ([ADR 0117](../../adr/0117-uk-eu-data-regions.md)).

## Keys and people needed to recover

- **Keys.** A restore needs the master key and the backup age identity. Both are kept off the host in the provider's password manager, with at least two people able to reach them ([access control policy](access-control.md#secrets-and-keys)). Without them, backups can't be read: every drill fetches them from there, not from the server.
- **People.** The private policy register names a deputy for the operator and the security owner. This plan and the operator guides are written so the deputy can follow them alone.

## Scenarios

The incident commander declares a disaster and picks the scenario ([incident response plan](incident-response.md)); the status page says so within 15 minutes.

| Scenario | Recover by |
|----------|------------|
| The botd server is lost or its data is damaged | Build a new host and restore the newest off-host archive with its key: [installer, new host](../../ops/backup-restore.md#installer-new-host) or [Compose, new host](../../ops/backup-restore.md#compose-new-host). Never run the restored copy beside the old server. |
| An Incus host is lost | botd alerts when it stops answering. Once it's known not to be coming back (botd never decides this), power it off if possible and run `botctl machine host recover <name> --yes`, which declares it lost, revokes its machines' certificates and restores each onto another host from its newest off-host backup ([losing a whole Incus host](../../ops/machine-recovery.md#losing-a-whole-incus-host), [ADR 0076](../../adr/0076-restoring-onto-another-incus-host.md)). |
| One machine is lost or damaged | `botctl machine restore <user> <backup-id> --yes` from the newest good backup; for a Linode, [restoring a Linode machine](../../ops/machine-recovery.md#restoring-a-linode-machine). |
| The backup store is lost or unreachable | Alerts fire as copies fail and RPOs pass. Point backups at a new store, then copy at once (`botctl backups copy`, `botctl machine backup <user>`); botd restarts the RPO clock for the new store ([ADR 0109](../../adr/0109-server-backups-off-the-host.md)). |
| A model provider is down | Tiers with a second provider fall back to it ([ADR 0077](../../adr/0077-two-providers-through-tier-routing.md)); for others, change the tier's route in the tiers file as a production change. |
| A hosting provider or region is lost | Restore the server and machines with another provider, or in another region of the customer's data region, from the off-host backups, using the scenarios above. |
| GitHub or the image registry is down | Running servers carry on. Upgrades and new installs wait, or use an image already verified and kept by the operator. |
| A key person is unavailable | Their deputy takes the role from the register and follows the same guides. |

botd is one process with one database: there is no failover, so losing the server is an outage of up to its RTO. That is a risk management accepts in the register until a high-availability control plane exists (checklist CC9.1-1).

## Tests

| Test | How often | Evidence |
|------|-----------|----------|
| Backup and restore drills in CI: the installer drill, the Compose drill and the scripts' tests, each within a 5-minute restore budget ([drills](../../ops/backup-restore.md#drills)) | Every change to the server, installer or image | Workflow runs of `server.yml` and `docker.yml` |
| Incus container restore and host-loss drill in CI, against the RTO ([`incus-e2e.yml`](../../../.github/workflows/incus-e2e.yml)) | Changes to machine code, and weekly | The workflow's `restore-drill-*` and `host-drill-*` artifacts |
| Restore of the newest off-site server archive onto a scratch server, timed to `/healthz` | Quarterly, and after a big upgrade | Date, the archive's newest audit time, time taken |
| Restore of a drill machine on the production tier and host ([`deploy/machine-restore-drill.sh`](../../../deploy/machine-restore-drill.sh)) | Monthly | The script's last line (`durationMs`, `rtoMs`) and the `machine.restored` audit event |
| The host-loss drill on production hardware, full size | Yearly | Drill record with timings against the RTO |
| A tabletop of this plan with every role | Yearly | Record and actions, as an incident review |

A failed test is an incident at SEV-3 or higher, reviewed like one, and its actions tracked.
