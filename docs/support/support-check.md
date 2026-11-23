# Support check and the offline bundle

`botd support check` and `botd support bundle` run on the server **without botd**: when it won't start, before an upgrade, and after a restore, the times the [support bundle](support-bundle.md) can't be had because botd makes it. They only read: the database is opened read-only, botd's data lock is looked up, never taken, and nothing is written to `DATA_DIR`. Design: [ADR 0187](../adr/0187-offline-support-check-and-bundle.md).

## Run it

As root (or the user botd runs as), with botd up or down:

```sh
# installer: settings from ~superbot/superbot/.env, the key from ~superbot/.config/superbot/master.key
sudo botd support check --home /home/superbot
sudo botd support check --home /home/superbot --before-upgrade
sudo botd support bundle --home /home/superbot          # saves superbot-support-offline-<time>.tar here

# Compose, from deploy/docker: in the running botd container while it runs...
docker compose exec botd botd support check
# ...and in a new one, with the same settings and volumes, while it's stopped
docker compose run --rm --no-deps botd botd support check
docker compose logs --no-color --tail 2000 botd > botd.log
docker compose run --rm --no-deps -T -v "$PWD/botd.log:/tmp/botd.log:ro" botd botd support bundle --logs /tmp/botd.log -o - > support.tar
```

| Option | What it does |
|---|---|
| `--home <dir>` | The installer's layout: settings from `<dir>/superbot/.env` (if it's there), `DATA_DIR` and `BACKUP_DIR` defaulting to `<dir>/superbot/data` and `<dir>/superbot/backups`, the master key to `<dir>/.config/superbot/master.key`. Relative paths in `.env` are taken from `<dir>/superbot`, where the service runs botd |
| `--env-file <file>` | Settings from this file, over botd's environment (Compose's container already has them) |
| `--before-upgrade` | `check` only: stricter about backups (none, or none in the last hour, is a failure or a warning) and disk space (room for a backup and the upgrade) |
| `--json` | `check` only: the findings as JSON, for scripts |
| `-o <file>` | `bundle` only: where to save it. Never over an existing file; readable only by you. `-o -` writes the tar to standard output |
| `--logs <file>` | `bundle` only: log lines from this file instead of the journal (the newest 2,000) |
| `--no-logs` | `bundle` only: no log lines |

`check` exits 0 when nothing failed (warnings included) and 1 when something did, so an upgrade script can stop on it: `botd support check --home /home/superbot --before-upgrade || exit 1`. A usage error exits 2.

It prints one line per check, then what to do about anything that isn't ok:

```text
SuperBot support check: botd 0.1.0 (schema 61), 2026-11-23 08:00 UTC, before an upgrade
DATA_DIR /home/superbot/superbot/data (settings from /home/superbot/superbot/.env)

ok    botd        running (pid 812); /healthz answers on 127.0.0.1:3000
ok    data_dir    /home/superbot/superbot/data: 9 entries
ok    disk        31.2 GiB free of 49.1 GiB (64%) where DATA_DIR is
ok    database    encrypted, 48.0 MiB (WAL 4.0 MiB), schema 61 of 61, integrity ok; last started by botd 0.1.0 at 2026-11-20 09:12 UTC
ok    master_key  found, from /home/superbot/.config/superbot/master.key
warn  backups     14 archives in /home/superbot/superbot/backups; the newest, superbot-20261123-031512.tar.gz.age, is 4.8 hours old and encrypted; botd copied the newest off this host
                  Take one just before the upgrade, so undoing it loses nothing. Back up now: ...
ok    license     Licensed to <licensee> (enterprise, 250 seats) until 2027-06-30.

1 warning, no failures. What each check means and what to do: docs/support/support-check.md
```

## The checks

Each finding is `ok`, `info` (worth knowing, nothing to do), `warn` (look at it) or `fail` (botd won't work, or an upgrade or restore isn't safe, until it's fixed).

### botd

Whether botd is running on this `DATA_DIR`: the process holding its data lock (from `/proc/locks`) and whether `GET /healthz` answers on `HOST`:`PORT` (a wildcard `HOST` is checked on `127.0.0.1`). Not running is a warning: it's why you're here, or expected while you restore. Running without answering usually means it's still starting (schema changes on a large database take a while); if it stays like that, read its log lines. `/healthz` answering with nothing holding the lock means that botd uses another `DATA_DIR`: point the check at its settings. In a container of its own (`docker compose run`), it can't see the botd container's process or loopback port, so it says so (info) instead of guessing: `docker compose ps` says whether botd runs, and while it does, run the check in it with `docker compose exec`.

### data_dir

`DATA_DIR` exists and can be read. Missing after a lost host or a bad restore: [restore it](runbook-server-restore.md).

### disk

Free space where `DATA_DIR` is. A failure under 512 MiB or 2% free, a warning under 2 GiB or 10%, and before an upgrade under twice the database plus 1 GiB. SQLite stops writing on a full disk, and botd with it.

### database

`DATA_DIR/app.sqlite`: plain or [encrypted](../ops/database-encryption.md), its size and its write-ahead log's, SQLite's `quick_check`, its schema against this botd's, and the version of botd that last started on it (from the audit log's `server.started`).

- **Integrity failed** or **can't be read**: restore the newest good backup ([server restore](runbook-server-restore.md)). Never edit `app.sqlite` by hand.
- **Encrypted, and no key opens it**: the master key is missing or wrong ([master_key](#master_key)).
- **Made by a newer botd** (its schema is past this botd's): a failure. Starting an older botd on it isn't safe. Install the version it was on, or restore a backup made on this one ([going back](runbook-upgrade.md#going-back)).
- **Schema changes run at the next start**: info. Run with the new botd before it starts, it says how many; back up first.
- **Last started by a newer botd**: a warning, for the same reason.
- **Plain copies beside it**: left by encrypting it; delete them once botd runs well.
- **No database**: a warning. A new install makes one at first start; after a restore, the archive didn't land in this `DATA_DIR`.

### master_key

Where the master key is, as botd finds it: `SUPERBOT_MASTER_KEY`, `SUPERBOT_MASTER_KEY_FILE`, or the default file, and the previous key during a [rotation](../ops/master-key-rotation.md). Never its value. A failure when a setting is wrong (both set, a file others can read, a key inside `DATA_DIR`) or when the database is encrypted and there's no key; a warning when there's none at all, because botd would make a new one and the secrets saved under the old one couldn't be read. After a restore or a move, put the old key back before botd starts.

### backups

The archives `superbot-backup` left in `BACKUP_DIR` ([backup and restore](../ops/backup-restore.md)): how many, the newest's age, whether it's encrypted, and whether they leave the host. With a store (`SERVER_BACKUP_S3_*` or the machine backups'), it reads botd's record of the copies it made (`botctl backups`): ok only when a finished copy is of the newest archive, a warning when the newest copy is older, there's none, or the record can't be read (then it says the copies are unconfirmed), with how many failed since. `SERVER_BACKUP_OFF_HOST=off` turns botd's copies off even with a store; copies you make yourself can't be seen here, so that's info, never ok. A warning past 26 hours (the daily timer missed) or when they stay on the host, a failure past 7 days; before an upgrade, none is a failure and none in the last hour a warning. Without `BACKUP_DIR` (no `--home` or `--env-file`), it says it didn't look.

### license

The [license](../../deploy/README.md#license) as botd would load it (`LICENSE_KEY`, `LICENSE_KEY_FILE` or `DATA_DIR/license.key`), checked offline. A failure with none or an invalid or ended one (SuperBot has no free tier: Bots don't run), a warning in its grace period or within 14 days of its end, info in testing mode.

## The offline bundle

`botd support bundle` saves the same findings, with what support needs to read them, as a tar for a ticket. Read it before you send it, as with the [support bundle](support-bundle.md#read-it-before-you-send-it).

| File | What's in it |
|---|---|
| `README.txt` | What the bundle is and what's never in it |
| `version.json` | This botd's version and schema, the OS, kernel and architecture, and whether it's in a container |
| `check.json` | Every check's status, summary, fix and details (sizes, schema, ages, the lock's process id) |
| `config.json` | botd's settings with secrets redacted, as in the support bundle, and where they came from |
| `logs.txt` | The service's newest 2,000 log lines: from `journalctl -u superbot` on an installer host (as root), or the file given with `--logs` |
| `manifest.json` | The files and their sizes, and how many settings and log lines went in |

It never holds secret values, chats, files, emails, IP addresses or the licensee's name, by the [same rules](support-bundle.md#whats-never-in-it) as the support bundle; values of secret-named settings and the master key are also taken out of every log line wherever they show. It doesn't hold the audit summary, health or metrics: those come from botd, so make a [support bundle](support-bundle.md) as well once botd is back.
