# 0096: Rotating the secrets master key

## Status

Accepted (21 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row CC6.1-3 in the [readiness checklist](../security/soc2-readiness-checklist.md). Builds on [ADR 0010](0010-secrets.md) (the master key and sealed values) and [ADR 0094](0094-totp-second-factor.md) (second factors sealed under it), and amends [ADR 0031](0031-machine-enrollment-mtls.md) (the machine CA derived from the master key).

Numbering: 0095 is held for the SCIM groups work.

## Context

botd seals saved secrets, each user's own secrets, approvals' tool input, push tokens and TOTP secrets ([ADR 0094](0094-totp-second-factor.md)) with XChaCha20-Poly1305 under one 32-byte master key ([ADR 0010](0010-secrets.md)). The key comes from `SUPERBOT_MASTER_KEY`, `SUPERBOT_MASTER_KEY_FILE`, or `~/.config/superbot/master.key`, and a sealed known value in `settings` (`secrets_key_check`) tells a wrong key from a right one. The same key is also the root of derived keys: the machine CA's Ed25519 key is `HMAC(HMAC(master, "superbot/derive"), "machine-ca/v1")` ([ADR 0031](0031-machine-enrollment-mtls.md)).

There was no way to change the key. An operator who suspects the key leaked, loses a person who held it, or rotates keys on a schedule (a common SOC 2 expectation) had only one option: `SUPERBOT_FORGET_SEALED=1`, which throws the sealed values away. A rotation must:

- never lose a sealed value, even if botd stops part-way;
- keep the old key working until the new one has taken over;
- leave a record in the audit log;
- work the same for the installer (key file) and Docker Compose (key in `.env`), with no tool the operator doesn't already have.

## Decision

**botd re-seals at start, when the operator names the old key as the previous one.**

- **Configuration.** The old key goes in `SUPERBOT_MASTER_KEY_PREVIOUS`, or a file named by `SUPERBOT_MASTER_KEY_PREVIOUS_FILE` (same rules as the key file: owner-only, outside `DATA_DIR`, no `..`; both set is an error). The new key goes where the key always goes. There is no default path for the previous key: it exists only during a rotation. Both names are stripped from harness and screen environments with the other server secrets, and the previous key file is closed to other accounts with per-user isolation.
- **What start does** (`server/src/secrets/sealed.rs`, `bootstrap`):
  - The current key opens the database: nothing to do. If a previous key is set, botd logs that it is no longer needed. Leaving it set is harmless.
  - The current key doesn't, the previous key does: **rotate**, then carry on starting with the new key.
  - Neither opens it: refuse to start, as with a wrong key today, and change nothing.
  - A previous key with no current key: refuse. botd never makes a key during a rotation, so the operator always holds the key the data ends up under.
- **One transaction.** The rotation opens a write transaction (`BEGIN IMMEDIATE`), opens every sealed value with the old key and seals it again under the new one (`secrets`, `user_secrets`, sealed `approvals.input`, sealed `push_devices.token`, `user_mfa.secret`), re-seals the key check, and writes the audit event, then commits. A crash, a full disk or any SQL error rolls everything back: the database is still wholly under the old key, so restarting with both keys set tries again. There is no half-rotated state, so no per-value key ids or versioned envelopes are needed; the `sb1:` format is unchanged. Afterwards botd runs `VACUUM` and truncates the WAL (as after sealing plaintext), so values under the old key don't linger in free pages.
- **Idempotent.** A value the new key already opens is left alone and counted as `current`. Once the rotation commits, the key check opens with the new key, so later starts with the previous key still set do nothing and write no second event.
- **Values neither key opens** (already unreadable, for example after a key file was swapped without `SUPERBOT_FORGET_SEALED`) are left exactly as they were and counted as `unreadable`; botd warns. Refusing to rotate over them would block rotation forever, and dropping them would lose data someone might still hold a key for.
- **Derived keys are kept.** The first rotation stores the derived-key root (`HMAC(old master, "superbot/derive")`) in `settings` as `secrets_derive_root`, sealed under the new key, and every later start derives from it. So the machine CA, and every enrolled machine's certificate, survive a routine rotation, and later rotations carry the same root forward. The root is sealed like any other value, so a database or backup still reveals nothing without the master key. **`SUPERBOT_ROTATE_DERIVED_KEYS=1`** during the rotation drops the stored root instead: derived keys come from the new master key, and every machine must enroll again ([ADR 0031](0031-machine-enrollment-mtls.md)). Use it when the old key may have leaked, since the old key gives the old CA key. MFA recovery codes are stored as HMACs under a derived key ([ADR 0094](0094-totp-second-factor.md)), so this also deletes them in the same transaction: each user keeps their authenticator app and makes new codes. A routine rotation keeps them.
- **Audit event.** `secret.master_key_rotated`, actor `system`/`secrets`, target `secret`/`master-key`, details `resealed`, `current`, `unreadable`, `derivedKeysKept`, `recoveryCodesDropped`. It is written in the rotation's transaction, so it exists exactly when the rotation does. A refused or rolled-back rotation is in botd's log, not the audit log: botd hasn't started, and the database is unchanged by design.
- **Operator steps** ([master key rotation](../ops/master-key-rotation.md)): Compose has `./init.sh --rotate-master-key`, which moves the current key to `SUPERBOT_MASTER_KEY_PREVIOUS` (first, so a crash between writes leaves the old key in both) and writes a new one, and refuses while a rotation is pending so the original key can't be overwritten. The installer's key file is rotated with `cp -p`, `openssl rand` and one `.env` line. Then restart, check the log, remove the previous key, restart.

## What is not rotated

- **Backup encryption**: archives are encrypted to age recipients ([ADR 0030](0030-backup-restore-drill.md), [ADR 0071](0071-off-host-machine-backups.md)), not the master key. Rotating those is in the [backup guide](../ops/backup-restore.md).
- **Backups taken before the rotation** stay sealed under the old key. To restore one, set the old key as the previous key and the current key as usual: botd rotates the restored database on start. So keep the old key, apart from the archives, for as long as you keep backups sealed under it.
- **The secrets themselves**: if the old key leaked with a copy of the database, the values in it are exposed whatever happens next. Rotate the API keys and tokens at their providers too.
- `AUTH_PASSWORD`, SSO client secrets, the license key and other settings in `.env` are not sealed and not touched.

## Alternatives considered

- **A `botd rotate-master-key` subcommand** run while botd is stopped. It needs the same environment as the service (systemd `EnvironmentFile`, Compose `env_file`), so it is easy to run with the wrong settings, and run against a live botd it would re-seal under a key the running server doesn't have, leaving new writes under the old key. Rotating at start runs in the service's own environment, with nothing else writing yet.
- **Online rotation through the API.** The cipher is shared by every store and connection; swapping it under live traffic needs a lock around every seal and open, and the new key would still have to reach the service's configuration before the next restart. Not worth it for a yearly or incident-driven operation that costs one restart.
- **Key ids in every value** (`sb2:<kid>:...`) and lazy re-sealing over time. It allows rotation with no downtime, but the database would be under several keys for an unknown time, every key would have to be kept until a sweep proves none are left, and the format change would need a migration of its own. A single transaction is simpler, and the data set is small (secrets, approval inputs, push tokens, TOTP secrets).
- **Re-deriving the CA on every rotation**, as ADR 0031 assumed. Every routine rotation would take every managed machine offline until it re-enrolled. Keeping the root is the safe default; replacing it is one setting away.

## Consequences

- Checklist row CC6.1-3 is done: a rotation, tested ([`server/src/secrets/sealed.rs`](../../server/src/secrets/sealed.rs) unit tests for rotation, a crash part-way, wrong keys, idempotency, unreadable values and derived keys; [`server/tests/master_key_rotation.rs`](../../server/tests/master_key_rotation.rs) end to end with the real `botd` and key files; the Compose smoke test with `init.sh --rotate-master-key`), and its audit event.
- A rotation costs one restart, plus a second to drop the previous key. Large databases hold the write lock for the rotation's length; sealed values are small, so this is seconds.
- New settings: `SUPERBOT_MASTER_KEY_PREVIOUS`, `SUPERBOT_MASTER_KEY_PREVIOUS_FILE`, `SUPERBOT_ROTATE_DERIVED_KEYS`. New audit action: `secret.master_key_rotated`. New `settings` row: `secrets_derive_root` (after the first rotation).
- ADR 0031's "a new master key means a new CA", and ADR 0094's recovery-code key, now change only with `SUPERBOT_ROTATE_DERIVED_KEYS=1` or after `SUPERBOT_FORGET_SEALED=1` drops a root the key can't open.
- An older botd can't use a database after a rotation if it lacks this ADR: it would derive a different CA from the new key (sealed values still open). Downgrading across a rotation means restoring a backup from before it, with the old key.
