# 0114: Backups encrypted by default

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row CC6.7-2 in the [readiness checklist](../security/soc2-readiness-checklist.md). Builds on the server's backups ([ADR 0030](0030-backup-restore-drill.md)), off-host machine backups ([ADR 0071](0071-off-host-machine-backups.md)) and server backups copied off the host ([ADR 0109](0109-server-backups-off-the-host.md)).

0113 is the highest number on `main` (0112 from [#175](https://github.com/CG-Labs/superbot/pull/175), 0113 from [#174](https://github.com/CG-Labs/superbot/pull/174)).

## Context

SuperBot can age-encrypt every backup it writes: `superbot-backup`'s archives (`SUPERBOT_BACKUP_AGE_RECIPIENTS`), botd's off-host copies of them (`SERVER_BACKUP_AGE_RECIPIENTS`), and Incus machines' off-host backups (`MACHINE_BACKUP_AGE_RECIPIENTS`). All three were off until the operator set recipients, and nothing said so. A server installed with the defaults kept every chat, Bot memory and the audit log in plain archives, and copied them plain to S3 when off-host copies were on.

## Decision

Backups are encrypted by default on new installs; plaintext is an explicit, visible and audited choice.

### New installs get a key

When the installer creates the `.env` (a fresh install) and no recipients are set, it runs `age-keygen` and writes the identity to `BACKUP_IDENTITY_FILE` (default `/root/superbot-backup-identity.txt`, root, `0600`), outside the service user's home and outside the backups, and sets `SUPERBOT_BACKUP_AGE_RECIPIENTS` to its public key. Compose's `init.sh` does the same with the host's `age-keygen` when it creates `deploy/docker/.env` (identity at `deploy/docker/backup-identity.txt`, gitignored). Both say, in the summary, to copy the key off the host and delete it there; each later run says so again while the file is still on the host. botd and the backup sidecar only ever see the public key.

Without `age-keygen` on the host the install still finishes, with backups plain and a warning saying how to fix it.

### Upgrades keep working

`install.sh --upgrade` and re-running `init.sh` never make a key on their own. A key made silently on a running server would leave the only identity for every new off-host copy on the host those copies protect against losing. Old servers keep writing what they wrote, plain ones now with a warning; `--backup-age-generate` makes the key on request, refused when recipients are already set.

### `SUPERBOT_BACKUP_ENCRYPTION`

One setting, read by botd and `superbot-backup` (installer `.env`, Compose `.env`, set with `--backup-encryption` on either):

- `auto` (the default): plain backups work, with a warning everywhere below.
- `required`: botd refuses to start when a configured target would be plain; `superbot-backup` refuses to write a plain archive; botd refuses to copy a plain archive off the host when it has no recipients of its own. A refused copy fails like any other ([ADR 0109](0109-server-backups-off-the-host.md)): audited, alerted, nothing uploaded.
- `off`: plain by choice. No warning, but every surface below still shows each plain target, and the choice is audited.

`off` with `--backup-age-generate` is refused, and so is `required` with nothing to encrypt to.

### What botd shows

botd works out three targets from what it is configured with; it reads only whether the recipients settings are set, never their keys ([ADR 0109](0109-server-backups-off-the-host.md)):

| Target | Encrypted when |
|--------|----------------|
| `server_archives` | The newest archive in `BACKUP_DIR` ends in `.age`; with none yet, `SUPERBOT_BACKUP_AGE_RECIPIENTS` is set |
| `server_copies` (with an off-host store) | The archives are encrypted, or botd has recipients to encrypt plain ones on the way |
| `machines` (with Incus off-host backups) | `MACHINE_BACKUP_AGE_RECIPIENTS` is set |

- **Startup**: one log line with the policy and the targets, and a `WARNING` per plain target unless `off`. `server.started` records the policy and the plain targets.
- **Setup checklist**: a "Backups encrypted" item, done when every target is encrypted.
- **`/api/backups` and `botctl backups`**: an `encryption` block with the policy and each target.
- **Metrics**: `superbot_backup_encrypted{target}` and `superbot_backup_plaintext_allowed`. [`superbot-backup-encryption.rules.yml`](../../deploy/prometheus/superbot-backup-encryption.rules.yml) raises a ticket when a target stays plain for an hour, unless plain by choice.
- **Audit**: `server.backup_encryption_changed` (actor `system`, `backup-encryption`) the first time botd sees a policy and set of plain targets, and whenever either changes, checked at start and every minute. It records the policy, the encrypted and plain targets, whether plaintext was chosen, and what it was before. The state is kept in settings, so restarts with nothing changed record nothing.

### Restore

Unchanged: `superbot-restore --identity FILE` ([ADR 0030](0030-backup-restore-drill.md)). The installer and `init.sh` tests restore an archive with the key each made, and refuse it without.

## Tests

- [`server/src/backup_encryption_http_tests.rs`](../../server/src/backup_encryption_http_tests.rs): the policy and targets for each configuration; `required` refusing to start; plain targets shown in metrics, the checklist and `/api/backups` and audited once, then again when they change; plain by choice shown and audited without warnings; `required` never copying a plain archive off the host, and an encrypted one copied as is and opened with the identity.
- [`deploy/test-install.sh`](../../deploy/test-install.sh): a fresh install makes a private key and encrypts to it, and its archive restores with it and not without; an upgrade keeps the key and `.env`; an old `.env` gets no key and a warning, `required` refuses it, `--backup-age-generate` fixes it; `off`; no `age-keygen`; bad flags.
- [`deploy/test-backup.sh`](../../deploy/test-backup.sh): `superbot-backup` with `required` refusing plaintext, from the environment and `.env`; `init.sh` making, keeping and restoring with its key, and `off`.
- [`deploy/docker/smoke-test.sh`](../../deploy/docker/smoke-test.sh): `init.sh` makes a key when the host has `age-keygen`.
- `promtool test rules` for the alert.

## Consequences

- New installs encrypt every server archive, and every copy off the host, from the first backup.
- The new key starts on the host. Until the operator copies it off and deletes it, someone with root on the host can read the archives, as they can read the live database. Losing the host and the key together loses the backups; the installer, `init.sh`, the checklist detail and the docs all say to copy it off.
- Machine backups aren't given a key: `MACHINE_BACKUP_AGE_RECIPIENTS` stays the operator's to set; until they do, botd warns, and `required` refuses to start.
- Existing servers change only in being told, unless the operator opts in.
- Linode Backups of Linode machines are encrypted by Linode, not by SuperBot, and aren't a target here.
