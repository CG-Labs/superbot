# 0187: An offline support check and bundle, for upgrades and restores

## Status

Accepted (23 Nov 2026). Fifth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the support bundle ([ADR 0131](0131-support-bundle.md)), the TAM programme and health score ([ADR 0144](0144-tam-programme-and-health-score.md)), the score's history ([ADR 0157](0157-health-score-history-and-console.md)) and the support report ([ADR 0167](0167-support-report-from-ticket-exports.md)).

Numbering: this number was reserved for this work.

## Context

The support bundle is made by botd, through its API, so it needs botd up and an admin's credentials. The incidents where support most needs facts are the ones where botd isn't up: it won't start after an upgrade, its database is damaged, or the server was just restored and nobody knows yet whether botd will start on it. The bundle's own page said so ("Anything from a server that isn't running"), and the playbooks had runbooks for sign-in, machines and harnesses but none for upgrades or for restoring the server itself, the two changes an operator makes to botd's data on purpose.

What goes wrong there is mostly the same few things: the master key missing or wrong for an encrypted database, a database a newer botd changed being started by an older one (going back by reinstalling, not restoring), a damaged database, a full disk, backups that stopped or never left the host, and the license. Each can be read from the host without botd, but by hand it takes `sqlite3` (which can't open an encrypted database), `df`, `ls` of the backups folder and the right reading of each.

Constraints: Rust first, no new dependencies; nothing personal or secret in anything meant for a ticket; and touch no other subsystem's behaviour, since several other M5 tracks (SSO, SCIM, RBAC, isolation, secrets, audit, SOC 2, residency, air-gapped) are changing at the same time.

## Decision

### In botd, as `botd support check` and `botd support bundle`

They are subcommands of the `botd` binary, as `botd database` is, not of `botctl`. The check needs to open an encrypted database with the master key, read the license as botd would and reuse the support bundle's redaction, and all of that lives in botd's crate; `botctl` is a thin HTTP client built from a few files. `botctl support-bundle` points at them when botd doesn't answer.

They read botd's settings from its environment, or from an env file: `--home <dir>` uses the installer's layout (`<dir>/superbot/.env`, `data`, `backups` and `~/.config/superbot/master.key`, as `superbot-backup --home` does), `--env-file` names a file. In Compose the container already has its settings, so `docker compose exec botd botd support check` runs it in botd's container while botd runs, and `docker compose run --rm --no-deps botd botd support check` in a new one while it's stopped. A separate container can't see botd's process or loopback port, so there it says it couldn't see botd (info) rather than that botd is down.

### Read only, and never in botd's way

The database is opened read-only (SQLCipher with the key when encrypted). botd's data lock is looked up in `/proc/locks` rather than tried: taking it, even for a moment, could turn away a botd starting at that instant. Nothing is created in `DATA_DIR`, and no master key is made when there's none. So the check is safe on a live server, before and after an upgrade, and on restored data before botd first starts on it.

### Seven checks, each with what to do

`botd` (the lock's holder and `/healthz`), `data_dir`, `disk`, `database` (format, size, write-ahead log, `PRAGMA quick_check`, schema against this botd's, the version that last started on it, plain copies), `master_key` (where, never what), `backups` (age of the newest archive, encryption, and whether botd's `server_backups` record shows a finished off-host copy of it: a store set is only a setting, so without that record the copies are unconfirmed, a warning) and `license`. Each is ok, info, warn or fail, with a fix and an anchor in [the support check page](../support/support-check.md). `--before-upgrade` is stricter about backups and disk. The command exits 1 on any failure so an upgrade script can stop on it, 0 otherwise, warnings included.

A database whose schema is past this botd's is a failure. botd itself runs its migrations forward only and would start on it; this is the check that says going back means restoring a backup, not reinstalling. `db::schema_version()` gives the count from botd's own migrations list, so the check can't drift from it.

### The offline bundle

`botd support bundle` saves the findings, the redacted settings (the support bundle's rules, from the same functions) and the service's newest 2,000 log lines (from `journalctl -u superbot` on a systemd host, or the last 8 MiB of a file given with `--logs`, since a container's logs belong to its runtime). Each line is redacted whole, then cut to 2,000 characters, so a secret across the cut is still found as a tar, readable only by its owner, never over an existing file, or to standard output with `-o -`. Values of secret-named settings and the master key are registered with botd's redaction first, so they're taken out of log lines wherever they show; emails, IP addresses and the licensee are masked as in the support bundle. It has no audit summary, health or metrics: those need botd, and the runbooks ask for a support bundle as well once it's back.

### Two runbooks on top

[Upgrades](../support/runbook-upgrade.md): check and back up just before, check after, fix forward from a table of known causes, or go back by restoring the backup with the version it was made on. [Server restore](../support/runbook-server-restore.md): confirm a restore is the fix (not a missing key or a full disk), gather the archive, age identity, master key and `.env`, check the archive, restore, check before starting, then what's lost and what to tell the customer.

## Alternatives

- **The support bundle with a fallback when botd is down.** `botctl` can't read an encrypted database or the license, and would need much of botd's crate.
- **A shell script beside `superbot-backup`.** It can't open an encrypted database, and redaction would be a second, weaker copy of the bundle's.
- **Taking the data lock to see whether botd runs.** Simpler, but it could stop a botd starting at that moment. `/proc/locks` answers without taking it, with the process id; off Linux the check relies on `/healthz` alone.
- **A full `PRAGMA integrity_check`.** Thorough but slow on a large database and holding a read transaction meanwhile; `quick_check` finds the damage a restore fixes. A suspect database can still be checked by hand on a copy.
- **Refusing to start botd on a newer database.** Worth doing, but it changes botd's start-up, shared by every other track; the check reports it without changing behaviour.

## Tests

`support_check`'s unit tests: env files read like systemd and Compose read them, the env file over the environment and `--home`'s paths; a healthy server passes with a plain database; an encrypted one opens with its key and the previous key mid-rotation, and fails with the wrong key or none; a database from a newer botd, with pending schema changes, a damaged file and none at all; backups by age, before an upgrade and not, and off-host copies by botd's record of them (a copy of the newest archive, an older one, only failures, no record, and `SERVER_BACKUP_OFF_HOST=off` with a store set); a missing `DATA_DIR`, no license and testing mode; a running botd seen by its lock and a stand-in `/healthz`, and `/proc/locks` parsing; the offline bundle carries no API key, password, email, IP address or licensee, with long log lines cut after redaction (a secret across the cut) and only the newest kept, and only a large log file's end read; and the command line saves once, `0600`, never over a file, exits 1 on failure and 2 on bad options. `botctl`'s test checks the hint when botd can't be reached. `tests/support_docs.rs` checks the new runbooks keep the runbooks' shape and that the check page documents every check and option.
