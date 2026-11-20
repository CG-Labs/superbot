# 0030: Backup format, restore drill, and RPO/RTO targets

## Status

Accepted. Part of [#40](https://github.com/CG-Labs/superbot/issues/40) (M3).

## Context

M3's exit criteria ask for a documented restore drill and a tested RPO target. Before this change:

- The installer's timer copied `app.sqlite` (online `.backup`), `bots/`, and `USER.md` into a dated folder. Anything else in `DATA_DIR` (per-user folders, Hermes data) was missed, there was no restore tool, and nothing tested it.
- The Docker image had its own `superbot-backup` (a `.tar.gz` of all of `DATA_DIR`) and `superbot-restore`, and the Compose smoke test restored into the same volumes it backed up.
- Neither install encrypted archives, said how much data a failure could lose, or how long a restore takes.

## Decision

**One backup tool, one archive format, and one restore tool for both installs, with optional public-key encryption, drills in CI, and stated targets.** Operator guide: [docs/ops/backup-restore.md](../ops/backup-restore.md).

- **One format.** `deploy/superbot-backup.sh` and `deploy/superbot-restore.sh` are installed as `/usr/local/bin/superbot-{backup,restore}` by the installer and copied into the image. An archive is `superbot-<UTC stamp>.tar.gz`: an online SQLite `.backup` of `app.sqlite`, all of `DATA_DIR` except the live database files, per-run screen state, and restore leftovers, plus `.superbot-backup` (`format=1`, creation time). Whole-folder by default, so new data under `DATA_DIR` is backed up without changing the script. Archives move between the two installs.
- **Consistency.** SQLite's online `.backup` gives a consistent database while Bots run; no downtime. Files beside it (Bot memory) are copied as they are, which is the same guarantee the old scripts gave.
- **Installer layout.** `superbot-backup --home <home>` reads `DATA_DIR` and the backup settings from `<home>/superbot/.env` without running it as shell; the systemd unit now calls that (the old `superbot-backup <home>` still works). Old dated folders are pruned by the same retention.
- **Encryption: age, public key, optional.** With `SUPERBOT_BACKUP_AGE_RECIPIENTS` (or `_FILE`), archives are piped through `age` and end in `.age`. The server holds only the public key, so a stolen server, disk image, or bucket can't read old archives. If recipients are set and `age` is missing, the backup fails rather than writing plaintext. Chosen over GPG (heavier, keyring state) and a symmetric `openssl` passphrase (the passphrase would sit on the server). `age` is in Debian and Ubuntu; the installer installs it best-effort and the image includes it.
- **Master key stays out.** Archives never hold the master key or `.env` ([ADR 0010](0010-secrets.md)); operators keep those off-host separately. Restoring therefore needs three things: the archive, the master key (and `.env`), and the age identity if encrypted. The docs and drills say so.
- **Restore.** `superbot-restore` refuses while botd answers `/healthz` (or `superbot.service` is active), unpacks into a staging folder in `DATA_DIR`, decrypts if needed, runs `PRAGMA integrity_check`, refuses unknown newer formats, and only then swaps `DATA_DIR` with two `mv`s, keeping the old contents in `.pre-restore-<stamp>/`. Run as root on a non-root `DATA_DIR`, it refuses (it would leave files botd can't write). `--check` does everything except the swap and prints a summary, including the newest audit event, so operators can check off-site copies and see what a restore would lose.
- **Storage target.** Local folder or volume only; off-site copying is the operator's tool of choice (rclone, S3, restic). A built-in uploader would mean cloud credentials on the server and per-provider code; customer S3 for managed hosting is a follow-up.
- **Targets.** Self-host default RPO 24 hours (daily, 03:15 ± 15 minutes, `Persistent=true`; Compose every 86400 seconds). Recommended for teams and the managed tier: RPO 1 hour (hourly timer drop-in, or `SUPERBOT_BACKUP_INTERVAL=3600`) with off-site copies. RTO 1 hour on a new host, of which the restore step is budgeted at 5 minutes. RPO only counts archives off the host.
- **Drills in CI.** `deploy/backup-drill.sh` (installer: real units, encrypted archive via `superbot-backup.service`, the service user deleted and reinstalled, the wrong key refused, data back, restore within `SUPERBOT_DRILL_RTO_SECONDS`, timer within the RPO), the Compose smoke test (sidecar writes an encrypted archive; all volumes deleted; fresh stack; restore within `SMOKE_RTO_SECONDS`), and `deploy/test-backup.sh` (edge cases without botd). The installer drill refuses to run without `SUPERBOT_DRILL_THROWAWAY=1` because it deletes the service user.
- **No side-by-side test restores.** A restored copy started beside the live server would run the same routines. Drills use throwaway hosts; `--check` covers day-to-day verification without starting botd.

## Consequences

- Both installs back up and restore the same way; the installer gains a restore tool, whole-`DATA_DIR` coverage, and encryption. Archive names on installer hosts change from folders to `superbot-<stamp>.tar.gz`.
- An upgrade re-renders `superbot-backup.service` with `--home`; old units keep working until then.
- The image grows by the `age` package (a few MB).
- CI gains two short jobs (`backup-scripts`, `backup-drill`) and about a minute in `compose-smoke`.
- Not covered: the workspace, harness logins, point-in-time recovery between archives, and managed per-user backups to customer S3 with a contractual RPO/RTO (the rest of #40).
