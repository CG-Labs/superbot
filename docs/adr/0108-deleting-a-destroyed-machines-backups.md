# 0108: Deleting a destroyed machine's backups on request

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row CC6.5-2 in the [readiness checklist](../security/soc2-readiness-checklist.md). Builds on off-host machine backups ([ADR 0071](0071-off-host-machine-backups.md)), restoring onto another host ([ADR 0076](0076-restoring-onto-another-incus-host.md)), erasing a user's data ([ADR 0102](0102-erasing-a-users-data.md)) and the audit log ([ADR 0009](0009-audit-events.md)).

## Context

A machine's off-host backups are whole copies of its disk: the user's files, harness logins and work. ADR 0071 keeps them after the machine is destroyed, until their tier's retention ends (14 days by default, up to ten years if set), so a mistaken destroy can still be undone by hand. That is the right default, but it leaves no way to dispose of them sooner when someone asks: a customer leaving and asking for their data to go, a GDPR erasure (ADR 0102 left them out), or a contract that ends. SOC 2 CC6.5 asks for a disposal path that is tested and leaves evidence.

Where a machine's copies live once it is destroyed:

- **The off-host store.** Each backup's data object and manifest under `<prefix>machines/<machine-id>/`, recorded in `machine_backups`. Objects can also be there with no record: a database restored from an older server backup, or one a botd stopped writing.
- **The provider.** Incus deletes a container's snapshots and its export copies (`superbot-<backup-id>`, which also expire within 24 hours) with the container. A restore that stopped part way can leave its imported copy (`<label>-restore`) beside the container, on the host the restore went to; destroying the machine doesn't delete it. Linode deletes a Linode's own backups (`MACHINE_BACKUPS`) when the Linode is deleted.

## Decision

**`DELETE /api/machines/{id}/backups` (`botctl machine delete-backups <machine-id> --yes`): admin-only, only for a destroyed machine, deleting every copy botd knows of, audited.**

- **Who.** Admins: the route is under `/api/machines`, which RBAC classifies as admin (`rbac::classify`), and the auth review's router walk checks that members, read-only users and Bots get 403. `botctl` refuses without `--yes`. Admins find destroyed machines with `botctl machine list destroyed` and their backups with `botctl machine backups`.
- **Only destroyed machines (409 otherwise).** A machine that still exists, in any state, keeps its backups: they are how it comes back, and a live machine's go when their retention ends (ADR 0071). Destroy it first. Also refused while a backup of it is still running (one that began before the destroy) or a restore is underway; ask again once it ends. With off-host backups off on this server, it answers 409 as every backup route does: botd can't reach the store, so it doesn't mark anything deleted. Each refusal is audited as `machine.backups_delete_refused` (outcome `denied`) with a `reason`: `not_destroyed`, `backup_running`, `restoring` or `store_off`.
- **What goes, in order.**
  1. Each recorded backup not yet deleted (`done` or `failed`): its data object and manifest are deleted from the store, then it is marked `deleted` and audited as `machine.backup_deleted` with reason `requested`, as retention does with reason `retention`.
  2. Anything else under the machine's prefix in the store (listed page by page), counted as `strays`. The prefix is today's `MACHINE_BACKUP_S3_PREFIX`; recorded backups are deleted by the key they were written to, whatever the prefix was then.
  - **Versioned buckets.** In a bucket that keeps old versions (versioning on, or suspended after it was on), a plain delete only hides the bytes behind a delete marker, and a listing doesn't show them. botd asks the bucket first (`GetBucketVersioning`); if it keeps versions, every version and delete marker under each backup's keys, then under the machine's prefix, is deleted by its version id, counted as `versions`. A store with no versioning at all (it answers that it doesn't implement it) is treated as unversioned. So the key always needs `s3:GetBucketVersioning`, and for a versioned bucket `s3:ListBucketVersions` and `s3:DeleteObjectVersion` too; without them the request fails (502) and marks nothing it didn't delete.
  3. Any restore copy at the provider: for each restore of the machine, `<label>-restore` on the host that restore went to is deleted (a no-op when it's gone). Hosts declared lost are skipped, since nothing on them is reached again. A machine another provider made (after `MACHINE_PROVIDER` changed) is skipped too.
- **Evidence.** `machine.backups_deleted`, naming the admin and the machine, with the backups deleted, `strays`, `versions`, `restoreCopies` and the `reason`. Every event names the machine's user, so an erasure later pseudonymises them like the rest.
- **Failures.** The first error from the store or the provider stops it: 502, audited as `machine.backups_delete_failed` (outcome `failure`) with the error and how many backups are left. What went stays gone and stays marked; asking again carries on. Deletes are idempotent (S3 and Incus answer success for what's already gone), so twice is once: the second answers 200 with nothing deleted.
- **Concurrency.** A destroyed machine never becomes live again, so no new backup or restore of it can start, and the request needn't hold the control-plane lock. Retention may delete the same backup meanwhile; the state change is conditional, so each backup is marked and audited once.

### With erasure

Erasing a user (ADR 0102) leaves their personal data in their machines' backups. Erasure now takes `deleteBackups: true` (`botctl user erase <user> --delete-backups --yes`):

- **Refused unless asked.** When any machine of theirs (destroyed, or the one `destroyMachine` is about to destroy) has backups not yet deleted, erasure is refused with reason `machine_backups` and the count, before anything is destroyed. Asking makes the choice explicit, as `destroyMachine` does: a backup may be the last copy of work an owner or a court still wants, and deleting it can't be undone.
- **Refused if botd can't.** With `deleteBackups` but off-host backups off on this server (records left from when they were on), it is refused with `store: off`: turn them back on and erase again. botd never marks a backup deleted that it couldn't delete.
- **A backup begun meanwhile.** Backups start under the control-plane lock and only for a running machine, so once the machine is destroyed none can begin. A backup begun between the first check and the destroy is counted again after it: without `deleteBackups` the erasure is refused then (`machine_backups`), with the machine destroyed and the user not yet erased, as when a destroy doesn't finish.
- **When.** After their machine is destroyed and before anything else changes, every machine of theirs is swept as above, with reason `user_erased`: all of them, not only those with backups still recorded, so an erasure asked again finishes the strays, old versions and restore copies one that stopped part way left. A failure stops the erasure (409 or 502) before the user is marked erased; erasing again with `deleteBackups` carries on. `user.erased` counts the backups as `machineBackups`.

Server backups (`SUPERBOT_BACKUP_RETENTION_DAYS`) are archives of the whole database and data folder, not per user. They still keep erased data until their retention ends.

## Alternatives considered

- **Deleting backups when the machine is destroyed.** Removes the only way back from a mistaken destroy, which ADR 0071 keeps on purpose. A separate request is a decision someone makes.
- **Deleting a live machine's backups.** Leaves a running machine with no way back; retention already bounds them. Refusing is simpler and safer.
- **Erasure deleting backups without asking.** Erasure would destroy the last copy of a disk on a request that may only have meant the person's account. Refusing until asked keeps ADR 0102's rule that destructive steps are chosen.
- **Erasure ignoring backups.** Leaves personal data behind with no signal. The refusal names it.
- **Only the recorded objects.** Misses what a lost record or an old database left in the bucket. Sweeping the machine's prefix covers it; the trailing `/` keeps one machine's sweep off another's.

## Consequences

- Checklist row CC6.5-2 is Done: an admin API and `botctl` command, tested ([`server/src/backup_deletion_http_tests.rs`](../../server/src/backup_deletion_http_tests.rs): refusals (the store off too), RBAC, a store and a provider failing part way, strays, a versioned bucket's old versions and markers, another machine's backups and versions untouched, twice is once, erasure with and without `deleteBackups`, an erasure asked again finishing a restore copy, and a backup begun while the machine is destroyed; [`server/src/machines_backup_tests.rs`](../../server/src/machines_backup_tests.rs): real backups and a restore copy on the Incus stand-in; unit tests in [`server/src/machines/backup.rs`](../../server/src/machines/backup.rs) and [`server/src/machines/s3_standin.rs`](../../server/src/machines/s3_standin.rs)), with audit events.
- New route `DELETE /api/machines/{id}/backups`; new `botctl machine delete-backups`; erasure's `deleteBackups` and `--delete-backups`, and its new refusal `machine_backups`. The S3 client lists and deletes object versions. New audit actions `machine.backups_deleted`, `machine.backups_delete_refused` and `machine.backups_delete_failed`; `machine.backup_deleted` gains reasons `requested` and `user_erased`.
- Erasing a user whose machines have backups now needs `deleteBackups: true`.
- If the bucket itself changed (`MACHINE_BACKUP_S3_BUCKET`), objects in the old one are out of botd's reach; S3 answers success for a missing key, so they are marked deleted. Removing an old bucket is the operator's step.
