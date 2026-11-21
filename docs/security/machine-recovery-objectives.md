# Machine recovery objectives

Text for an SLA, a DPA's availability and resilience clause, or a security questionnaire, describing how a SuperBot operator protects customers' managed machines. It states only what SuperBot enforces and measures ([ADR 0074](../adr/0074-machine-rpo-and-rto.md)). The numbers are SuperBot's defaults; an operator who changes them (see [machine recovery](../ops/machine-recovery.md)) must change them here too, and should not promise tighter numbers than the server is set to, nor an RTO their own drill hasn't shown for the plan's largest disk. The encryption statement holds only with `MACHINE_BACKUP_AGE_RECIPIENTS` set.

"Provider" below is whoever runs the SuperBot server. "Machine" is a customer's managed computer running as an Incus container on the Provider's infrastructure.

---

## Scope

This covers machines that run as Incus containers with off-host backups turned on. It does not cover machines on other hosting providers, files the customer keeps elsewhere, or data in third-party services the customer's Bots use.

## Backups

1. Each machine is backed up on a fixed schedule according to its plan (below). A backup is a full, point-in-time copy of the machine's disk, taken while it runs.
2. Backups are stored off the machine's host, in object storage the Provider controls, and encrypted with the Provider's age (X25519) public keys as they leave the host. The server that makes them holds only the public keys, so neither it nor the storage provider can read them.
3. Each backup is kept for the plan's retention period (14 days unless the agreement says otherwise), then deleted. The newest backup of a live machine is never deleted for age. When a machine is destroyed, its backups are deleted at the end of their retention period, not at once.

## Objectives

| Plan | Backed up every | Recovery point objective (RPO) | Recovery time objective (RTO) |
|---|---|---|---|
| Starter | 24 hours | 26 hours | 60 minutes |
| Pro | 12 hours | 14 hours | 60 minutes |
| Max | 6 hours | 8 hours | 60 minutes |

**RPO** is the most data, measured in time, that a restore from backup may lose. A machine meets it while it has a completed off-host backup taken within the RPO, or was created or restored within it.

**RTO** is the most time a restore may take, measured from the Provider starting the restore to the restored machine being back online and connected to SuperBot.

## Measurement and monitoring

1. The server checks every running machine against its RPO at least once a minute. A machine without a backup within its RPO is recorded as a breach, with the time it began and ended, and the Provider's operators are alerted.
2. Every restore records when it was requested, when the machine was back online, and its plan's RTO. A restore that runs past the RTO is recorded and the Provider's operators are alerted.
3. These records are kept in the server's audit log and are available to the Provider on request of the customer, for the customer's machines.
4. The Provider tests restores: automatically, on real container infrastructure, whenever the machine software changes and at least weekly, failing the test if a restore exceeds the RTO; and by hand on its own infrastructure. The automatic test uses a small machine, so it proves the restore works within the RTO but not how long a full-size disk takes; the manual drill covers that.

## What the objectives don't cover

1. **Time before a restore starts.** The RTO starts when the Provider starts the restore, not when a problem happens or is reported. Restores are started by the Provider's operators, not automatically.
2. **Loss of the SuperBot server itself.** If the server that manages machines must be restored too, that time (target: 1 hour) comes before a machine restore can start.
3. **Loss of a machine's host.** Restores are made onto the host the machine runs on. If that host is lost, the Provider must first replace it; that time is not part of the RTO.
4. **Suspended machines.** A suspended machine isn't backed up or held to the RPO, since its disk doesn't change. It is held to it again once resumed.
5. **Changes since the last backup.** A restore brings back the machine as of a backup. Anything written after that backup is lost.
6. **Credentials.** A restored machine connects to SuperBot afresh. Its previous connection is revoked, and the customer's Bots may need to sign in to outside services again.
7. **Failures outside the Provider's control**, including the object storage provider being unavailable. A breach caused by one is still recorded.

The objectives are targets the system measures and alerts on. Any credits or remedies for missing them are set in the customer's agreement, not here.
