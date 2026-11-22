# 0071: Off-host backups of per-user containers

## Status

Accepted. Builds on [ADR 0065](0065-incus-container-machines.md) (Incus containers), [ADR 0067](0067-clearing-enrollment-data-from-containers.md) (clearing enrollment data), [ADR 0069](0069-validating-incus-containers-on-a-real-host.md) (the real-host test) and [ADR 0030](0030-backup-restore-drill.md) (server backups). Covers the backup part of [#29](https://github.com/CG-Labs/superbot/issues/29) together with [#40](https://github.com/CG-Labs/superbot/issues/40).

Per-tier schedules, RPO and RTO targets, breach alerts and timed restore drills: [ADR 0074](0074-machine-rpo-and-rto.md). Deleting a destroyed machine's backups on request: [ADR 0108](0108-deleting-a-destroyed-machines-backups.md).

## Context

A container's daily snapshots stay on the Incus host's pool. They don't survive losing that host, and a user's machine may be the only copy of their work. Managed hosting needs backups off the host, a way to bring a machine back from one, and a record of both.

A restore is also a security event. A backup holds the agent's identity (its mTLS key and certificate) and the disk as it was. Bringing those back must not trust anything that was enrolled from that disk: not its certificate, not any token, not settings that have changed since.

## Decision

### Off unless set

`MACHINE_BACKUP_S3_BUCKET` turns it on. It also needs `MACHINE_BACKUP_S3_ENDPOINT` and the keys `MACHINE_BACKUP_S3_ACCESS_KEY_ID` and `MACHINE_BACKUP_S3_SECRET_ACCESS_KEY` (secrets, `_FILE` allowed, redacted from logs). These are optional:

- `MACHINE_BACKUP_S3_REGION` (default `us-east-1`).
- `MACHINE_BACKUP_S3_PREFIX` (default `superbot/`).
- `MACHINE_BACKUP_AGE_RECIPIENTS` or `_FILE`.
- `MACHINE_BACKUP_INTERVAL_HOURS` (default 24, from 1 to 720).
- `MACHINE_BACKUP_RETENTION`: days, either for every tier (`14`, the default) or per tier (`7,pro=30`).

botd refuses to start if any of these is set without the bucket, if the control plane is off, or if the provider can't export machines. Linode can't export, and has its own `MACHINE_BACKUPS`. The endpoint must be HTTPS. Plain HTTP is allowed only to loopback, which the tests use.

Any S3-compatible store works: AWS S3, Cloudflare R2, Backblaze B2, MinIO, or a customer's own bucket. botd signs requests with SigV4 itself, using path-style addresses, with no SDK. The signing code is checked against AWS's published test vector.

### What a backup is

A backup is an Incus instance backup of the container:

- `instance_only`, so no snapshots, which hold older states of the disk;
- not storage-optimized, so it imports into any pool driver;
- expiring on the host after 24 hours, in case botd stops before it deletes it.

botd streams the export to the store in 16 MiB parts, so a large disk never sits in memory or on botd's disk. It then deletes the host's copy. With age recipients set, the stream is age-encrypted on the way, as server archives are (ADR 0030). botd holds only the public keys, so neither botd nor the store can read old backups.

Each backup is two objects:

- `<prefix>machines/<machine-id>/<backup-id>.incus[.age]`
- a JSON manifest beside it (format `superbot-machine-backup/1`), with the machine, user, tier, plan, size, SHA-256 and recipients.

The manifest is how someone who still has the bucket but no database can tell what each object is. If the manifest can't be written, the backup fails and its data object is deleted.

A `machine_backups` table records each backup: `running`, then `done` or `failed`, and `deleted` once past its retention. The table allows one running backup per machine.

### Only when the provider holds no token

A machine is backed up only when all of these hold:

- it is running and this server's provider owns it;
- its agent has enrolled with its latest token (`enroll_by` is clear);
- no rebuild or restore is underway;
- Incus reports no `cloud-init.user-data`.

This means the provider's config holds no enrollment token, so no backup holds one (ADR 0067). The first-boot scrub (ADR 0069) means none is left on the disk either.

### Schedule and retention

A loop runs every reconcile interval, and at least every minute. It:

- deletes backups past their retention from the store;
- finishes restores whose machine has enrolled;
- backs up each eligible machine whose newest backup is older than the interval, one machine at a time.

A failed backup is tried again after an hour, or after the interval if that is shorter.

A backup expires its tier's retention after it was taken. The newest finished backup of a machine that isn't destroyed is never deleted, however old it is, so a machine that stopped being eligible keeps its last good copy. When a machine is destroyed, its backups expire as usual. They are kept for the retention period, not deleted with the machine, so a mistaken destroy can still be undone by hand.

If botd stops mid-backup, the backup is marked failed at startup. A restore that hadn't yet put its copy in place is also marked failed, and its imported copy is deleted, with retries. The copy is kept if the old container is already gone, since then the copy is all that is left. An upload that fails, even at its last step, is aborted, so no parts are left in the bucket.

### Restore

`POST /api/users/{key}/machine/restore {backupId, identity?}`, or `botctl machine restore <user> <backup-id> [--identity FILE] --yes`.

The backup must be one of this machine's own, finished. The machine must be running, suspended or in error, with no rebuild, restore or backup running. An encrypted backup needs its age identity. The identity is used for this restore only, never stored, logged or echoed. botd answers 202, and the work runs in the background:

1. **Import.** botd downloads the object and checks its size and SHA-256 against the record as it streams. It decrypts if needed and imports the result as a stopped container beside the machine (`<label>-restore`). A wrong key or a damaged object fails here, and the user's machine is untouched.
2. **Replace.** This step holds the control-plane lock. botd revokes the machine's tokens and mints a fresh one. It then sets up the copy:
   - today's hardened security keys, size, tags, root disk and NIC behind today's firewall, never the backup's;
   - no user data;
   - no snapshots until it enrolls;
   - today's CA, agent unit, guard, `machine.env` and the fresh token pushed into it as files, with the old identity file deleted.

   botd then deletes the old container and renames the copy into its place. Before starting it:
   - all the machine's old certificates are revoked (`machine.cert_revoked`, reason `restored`);
   - what the old agent reported is forgotten, as after a rebuild (ADR 0056);
   - its folder-sync state and the owner's sessions on it are dropped;
   - the time enrollment must come after is recorded.

   Enrollment doesn't take the lock, so all of this happens first. Otherwise the new agent's certificate could be revoked, or its enrollment missed. If the swap fails while the old container is still in place, the machine's earlier enrollment deadline is put back, so its backups go on.
3. **Enroll.** Finding no identity, the agent enrolls with the token file and deletes it, as on first boot. Routing refuses the user's Bots (`machine_restoring`) until it has enrolled. Off-host backups, provider snapshots, rebuilds and another restore all wait too. Once it enrolls, the restore is done. If it doesn't enroll within the enrollment timeout plus ten minutes, the restore fails and the token is revoked.

So nothing enrolled from the backup's disk is trusted again. The token lives only in a root-only file on the disk, never in the provider's config, and is spent on first use. The control-plane lock keeps the reconciler and other admin actions out while the copy is swapped in.

The restore keeps the machine's id, label, address and firewall. Teammates' OS users on the restored disk heal themselves: after the reset, the offboarding sweep removes any user the agent reports who shouldn't be there (ADR 0052).

### Audit and views

- Backups audit `machine.backup_created`, `machine.backup_failed` and `machine.backup_deleted` (reason `retention`).
- Restores audit `machine.restore_requested`, `machine.enroll_token_issued` (via `restore`), `machine.cert_revoked`, `machine.restored` and `machine.restore_failed`.

Admins see the machine's `lastBackup` in its view. The owner sees `lastBackupAt` in `GET /api/machine`. Admins also have:

- `GET`/`POST /api/users/{key}/machine/backups`;
- `GET /api/users/{key}/machine/restore`;
- `GET /api/machines/backups`, which shows the settings without credentials;
- `botctl machine backups|backup|restore`.

### Tests

- **Unit tests** cover the signing vector, settings, retention, key handling and streaming encryption.
- **End to end against stand-ins** for the Incus API and an S3 store (the stand-in checks every signature). These cover:
  - a backup, then a restore that brings back the backup's files, removes the old identity, writes a fresh token only to the disk, and revokes the old certificates;
  - re-enrollment with a new certificate;
  - encrypted backups needing the right identity;
  - a failed restore leaving the machine untouched;
  - refusals while busy;
  - the schedule skipping machines whose token is still in their config;
  - retries after a store failure;
  - retention keeping the newest backup.
- **On a real host.** The `incus-e2e` job (ADR 0069) also runs an S3-compatible store on loopback (versitygw). It backs up a real container encrypted, changes it, and restores it. It checks that the backup's files are back, the agent enrolled with a new identity, no token is left, and the container is still isolated from its neighbour. MinIO no longer publishes public images, so CI installs versitygw's pinned release package, checked against its SHA-256.

## Consequences

- A container can be brought back after its host is lost, from a store the customer can own, encrypted to keys botd never holds.
- A restore can't bring back old trust. The machine enrolls anew, and its old certificates and tokens are revoked.
- Everything on the machine since the backup is lost on restore, and the API and botctl say so. Restore takes the machine offline from the swap until it enrolls.
- Between deleting the old container and renaming the copy, a crash leaves the machine without a container. The restore then fails, and the backup is still in the store to try again.
- A backup can only be restored to the same machine, on a host that runs this provider. Restoring onto another Incus host, when a host is lost or to move a machine, came with [ADR 0076](0076-restoring-onto-another-incus-host.md); moving between substrates is still to come (ADR 0065).
- The restricted project must allow backups (`restricted.backups=allow`); Incus blocks them otherwise. This lets a client of the project export its containers, which botd's certificate can do anyway. It loosens none of the isolation in ADR 0065, and botd's checks before each create still refuse every setting that would. botd reports the command to run if backups are blocked.
- Exports are full each time, with no deduplication or incrementals. Storage costs scale with disk size times retention.
- Linode machines keep Linode's own backups (`MACHINE_BACKUPS`). Exporting them is out of scope.
