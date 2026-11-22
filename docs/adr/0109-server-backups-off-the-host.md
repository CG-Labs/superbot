# 0109: Server backups copied off the host

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row A1.2-1 in the [readiness checklist](../security/soc2-readiness-checklist.md). Builds on the server's backups and restore drill ([ADR 0030](0030-backup-restore-drill.md)), off-host machine backups ([ADR 0071](0071-off-host-machine-backups.md)), machine recovery objectives ([ADR 0074](0074-machine-rpo-and-rto.md)) and metrics ([ADR 0089](0089-metrics-and-structured-logs.md)).

0107 is the highest number on `main`. Open PR [#170](https://github.com/CG-Labs/superbot/pull/170) holds 0108.

## Context

`superbot-backup` (ADR 0030) archives botd's `DATA_DIR`, the SQLite database with it, into `BACKUP_DIR` on the same host: daily from the installer's systemd timer, or every `SUPERBOT_BACKUP_INTERVAL` seconds from the Compose sidecar. Copying the archives anywhere else was the operator's job, and nothing said whether they did. A lost disk or host lost the server and its backups together.

Machines already back up off the host (ADR 0071): botd streams each export to S3-compatible storage, age-encrypted, with a manifest, retention and RPO alerts (ADR 0074). The server's own data, the one thing every machine depends on, had none of that.

SOC 2's A1.2 asks for backups, and their recovery, to be designed for the loss of the system's infrastructure. The checklist row asks for server backups to leave the host by default.

The live servers upgrade with `install.sh --upgrade` non-interactively, so nothing may need a new answer, a store, or a key to keep working.

## Decision

### botd copies the archives

botd checks `BACKUP_DIR` every minute and copies the newest finished archive to an S3-compatible store with ADR 0071's client: SigV4, multipart, streaming. `superbot-backup` is unchanged: it still writes `superbot-<UTC stamp>.tar.gz[.age]` and deletes local archives after `SUPERBOT_BACKUP_RETENTION_DAYS`. botd needs no root, no new package, and no change to either schedule.

Copying from botd, not from the shell script, gives the copy everything botd already has: the S3 client and its stand-in for tests, age encryption, the audit log, the notifier, `/metrics`, the admin API and the setup checklist. The script runs as the same `superbot` user and writes an archive under a `.partial-*` name before renaming it, so a name botd sees is a finished archive. botd copies only names that look like the script's, and only regular files, never links.

`BACKUP_DIR` defaults to `backups` beside `DATA_DIR`, where both the installer (`~/superbot/backups`) and the Compose file (`/backups`, now also set for botd) put it.

### Where copies go

- `SERVER_BACKUP_S3_BUCKET`, with `_ENDPOINT`, `_REGION` (us-east-1), `_PREFIX` (`superbot/`), `_ACCESS_KEY_ID` and `_SECRET_ACCESS_KEY` (or `_FILE`): a store of the server's own. Using a different account or bucket from the machines' keeps one leaked key from reaching both.
- Without it, the machine backups' store (`MACHINE_BACKUP_S3_*`, ADR 0071), when set. A managed server with machine backups on copies its own backups off the host with no new setting.
- Neither: nothing is copied (below).

Copies go to `<prefix>server/<archive>`, beside the machines' `<prefix>machines/`, with a manifest `<prefix>server/<stem>.json` (format `superbot-server-backup/1`): the archive, when it was made and copied, size, SHA-256, whether and by whom it is encrypted, the recipients, and botd's version. A copy whose manifest couldn't be written is deleted and counts as failed.

`SERVER_BACKUP_OFF_HOST` is `auto` (the default: copy when a store is set), `on` (refuse to start without a store, for servers that must never keep backups only on the host), or `off`.

Each copy records its destination (endpoint, bucket and folder). Only copies to the store set now count: after a change of bucket, endpoint or prefix, the newest archive is due at once, the RPO clock starts again, and botd neither trusts nor deletes the old store's copies.

### Encryption

An archive the script encrypted (`.age`, to `SUPERBOT_BACKUP_AGE_RECIPIENTS`) is copied as it is, so the copy is encrypted at rest on both sides and botd never holds a key that opens it. A plain archive is encrypted on the way to `SERVER_BACKUP_AGE_RECIPIENTS` (or `_FILE`; with the machines' store, `MACHINE_BACKUP_AGE_RECIPIENTS` when unset) and stored as `<archive>.age`. With neither, it is copied plain and the startup log says so; the store's own encryption at rest is then all there is.

botd never reads `SUPERBOT_BACKUP_AGE_RECIPIENTS`: it is the script's, may hold SSH keys age accepts, and a typo in it must not stop botd.

### Retention

`SERVER_BACKUP_RETENTION_DAYS` (30 by default) deletes a copy and its manifest that many days after its archive was made, every pass, counting by the setting as it is now. The newest copy is never deleted, however old, so a server whose archives stopped still has its last one off the host. `off` leaves deleting to the bucket's own lifecycle rules, so its keys need no delete right; botd then deletes nothing, not even copies made while retention was on.

### Failures, the RPO and alerts

Each copy is a row in a new `server_backups` table (running, done, failed, deleted) and an audit event: `server.backup_copied`, `server.backup_copy_failed` (outcome failure, with the error) and `server.backup_deleted`, all by the system actor `server-backups`. One copy runs at a time (a partial unique index). A failed archive is tried again after 30 minutes. A copy cut off by a restart ends as failed when botd starts; its upload was never completed, so the store holds nothing of it.

The RPO is `SERVER_BACKUP_RPO_HOURS`, by default the archive interval plus ADR 0074's two hours of headroom: 26 hours for the daily timer, or `SUPERBOT_BACKUP_INTERVAL` rounded up to hours plus two under Compose. The age measured is that of the newest archive copied off the host, by the time in its name; before the first copy, the time since copies were turned on. Past the RPO botd opens a breach once (`server.backup_rpo_breached`, failure), sends it through the notifier like a machine's (ADR 0074), and closes it when a newer copy lands (`server.backup_rpo_recovered`, reason `backed_up`). The alert names the last copy's error, or that no newer archive reached `BACKUP_DIR`, so a stopped timer or sidecar is caught too. The RPO is checked every minute on its own timer, so a long upload can't hold back the alert.

`/metrics` gains `superbot_server_backup_off_host` (1 or 0, always shown) and, with a store, `superbot_server_backup_rpo_seconds`, `superbot_server_backup_age_seconds`, `superbot_server_backup_past_rpo`, `superbot_server_backup_last_copy_timestamp_seconds` and `superbot_server_backup_last_copy_size_bytes`. The five audit actions are counted in `superbot_events_total`. [`deploy/prometheus/superbot-backup.rules.yml`](../../deploy/prometheus/superbot-backup.rules.yml) alerts, per instance, when backups stay on the host for an hour, are past the RPO, or fail twice in two hours, tested with `promtool` in CI.

### Without a store, the gap is shown

Existing installs have no store, and an upgrade must not make them stop. With none, botd copies nothing, starts as before, and says so where admins look:

- a `WARNING:` line at every start, and `serverBackups.offHost: false` in `server.started`;
- the setup checklist's new item, "Server backups copied off this host", open until a store is set, an archive has reached it, and the newest copy is within the RPO;
- `GET /api/backups` (`botctl backups`): the store without its keys, the RPO, the newest archive and copies, and the warning;
- `superbot_server_backup_off_host 0` and its alert.

`/healthz` and the public `/status` page stay as they are: they are open to anyone and say nothing about the server's setup (ADR 0090), and a warning there would tell strangers where its backups are weakest.

### The admin API

`GET /api/backups` and `POST /api/backups` (copy the newest archive now if it isn't copied; 409 without a store) are admin-only, as every route `rbac::classify` doesn't list is. The copy a request makes records who asked. `botctl backups` and `botctl backups copy` call them.

### Keys

`SERVER_BACKUP_S3_SECRET_ACCESS_KEY` and, now also, `MACHINE_BACKUP_S3_SECRET_ACCESS_KEY` join `secrets::SERVER_SECRETS`: botd's own, never in a Bot's environment. Both are registered for redaction when read.

### The installer

`deploy/install.sh` takes `--backup-s3-endpoint`, `--backup-s3-bucket`, `--backup-s3-region`, `--backup-s3-prefix`, `--backup-age-recipients` (the script's `SUPERBOT_BACKUP_AGE_RECIPIENTS`) and `--backup-off-host`. The keys come from its environment (`SERVER_BACKUP_S3_ACCESS_KEY_ID`, `SERVER_BACKUP_S3_SECRET_ACCESS_KEY`), never flags, which other accounts could see in `ps`. Flags' shapes are checked before the long build; a bucket without keys, given or already in `.env`, stops it before botd restarts. Given nothing, it writes nothing, so `--upgrade` keeps the server as it was; the summary then has a `Backups:` line and a warning that backups stay on the host.

## Tests

- **Settings** (`server_backups_http_tests`): nothing set is on-host with the warning; the server's own store, the machines' store and its recipients, `off` and `on`, Compose's `BACKUP_DIR` and interval; settings that can't work stop botd: `on` without a store, an endpoint or RPO without a bucket, bad hours, days, recipients, endpoint or a missing key. `SUPERBOT_BACKUP_AGE_RECIPIENTS` is never read.
- **Against the S3 stand-in**: only the newest finished archive is copied (partials, links, folders and odd names ignored), encrypted on the way and decrypted back to the same bytes, with its manifest, row and audit event; nothing new copies nothing; an `.age` archive is copied byte for byte; a failed upload leaves nothing in the store, is audited and counted, isn't retried for 30 minutes, then is; a copy cut off by a restart ends failed; retention deletes old copies but never the newest, by the setting as it is now, and `off` deletes nothing; a new store starts empty and leaves the old one's copies alone; the checklist stays open until the first copy; past the RPO is audited once, alerted, shown in the checklist and gauges, and recovered by a newer copy. Admins see the store without its keys; members get 403. Without a store: nothing copied, the warning in the API and checklist, 409 for copy now, `superbot_server_backup_off_host 0`.
- **Installer** (`deploy/test-install.sh`): no flags write nothing and the summary warns; bad flags are refused; the flags write the store and recipients, keys only from the environment, and a later flagless upgrade keeps them.
- **Alert rules**: `promtool test rules` for each alert firing and not, and one server that copies not hiding another that doesn't.

## Consequences

- A server with a store, its own or the machines', has its database off the host within a minute of each archive, encrypted when it has recipients, with an RPO alerted and graphed. A managed server with machine backups needs no new setting.
- A server without one keeps working as before, but every admin surface says its backups can be lost with the host.
- The worst-case data loss is the archive interval plus the copy: up to a day with the installer's daily timer. A shorter RPO needs a shorter interval (`superbot-backup.timer` or `SUPERBOT_BACKUP_INTERVAL`).
- With plain archives and botd's recipients, the archive is read and encrypted by botd; the copy on the host stays plain. Encrypting with `SUPERBOT_BACKUP_AGE_RECIPIENTS` covers both.
- Restoring from the store is by hand: download the copy, check its SHA-256 against the manifest, decrypt with the age identity, then `superbot-restore` as before ([backup and restore](../ops/backup-restore.md)).
- Not covered: the master key (kept out of archives by design, ADR 0010), copies to more than one store, and object lock or immutability, which are the bucket's settings.
