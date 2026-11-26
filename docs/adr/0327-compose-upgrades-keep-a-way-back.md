# 0327: Compose upgrades keep a way back

## Status

Accepted (26 Nov 2026). Twenty-first slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Brings the way back that `install.sh --offline` keeps ([ADR 0300](0300-offline-upgrades-keep-a-way-back.md)) to Docker Compose stacks, and the downgrade refusal ([ADR 0128](0128-air-gapped-self-host.md)) to `check-compose` ([ADR 0317](0317-compose-upgrades-checked-first.md)). ADR 0300 and ADR 0317 listed both as not covered.

0327 was reserved for this work.

## Context

ADR 0317 checks a release before a Compose stack switches to it. A release can still go wrong after it starts. Going back on Compose meant: find a backup taken on the old release, stop the stack, restore it with the old image's `superbot-restore`, set the old tag in `.env`, and start again. Nothing checked that the backup was of that release, that it was unchanged, or that the old botd would start with today's `.env`.

Setting the old tag and running `docker compose up -d` without the restore is worse than it looks. botd runs its migrations at start and doesn't refuse a database whose `PRAGMA user_version` is past the ones it knows: an older botd starts on a database a newer one changed, and may misbehave on it. ADR 0317 said botd refuses such a database at start; it doesn't. `botd support check` does see it ("made by a newer botd", or "botd X ran on it last"), but nothing asked it before a Compose switch.

## Decision

### `offline-bundle.sh backup-compose`

`backup-compose [--dir DIR] [-- COMPOSE_OPTION...]`, run where the operator runs Compose, before the switch, takes a rollback point from the running stack:

- **The archive** is the running release's own `superbot-backup -`, run in botd's container with `docker compose exec`. It is a consistent copy of the database (`botd database backup` for an encrypted one), encrypted to the stack's `SUPERBOT_BACKUP_AGE_RECIPIENTS` when it has them, as the backup service's are. The release being left made it, so its own `superbot-restore` reads it.
- **The record** holds the Compose project, the image botd's container runs (its reference and its image ID), when, the archive's name and SHA-256, and the SHA-256 of the database's key check (`key_check`): the `secrets_key_check` setting, a known value sealed under the master key that each rotation seals again ([ADR 0096](0096-master-key-rotation.md)), read with the running botd's `botd database query`. It is `none` before botd sealed anything, and `unknown` for a botd without that command.

Both go in `DIR` (default `./superbot-rollback`), a folder of the operator's that only they can open (0700, files 0600). The archive is written to a uniquely named partial file and the record replaced last, so a failed run keeps the last rollback point. `backup-compose` and `rollback-compose` hold a `flock` on `DIR/.lock`, so two runs on one folder can't interleave. One is kept: the next one replaces it. botd must be running, as the backup needs it. A stream that isn't an archive (gzip or age) is refused.

It doesn't copy `.env`: on Compose that is the operator's file, and going back means editing it anyway (below). The record names the image, which is what `.env` must name again.

`check-compose` and `load` end by naming the rollback point when there is one for the image botd runs now, or by saying to take one.

### `offline-bundle.sh rollback-compose`

`rollback-compose [--dir DIR] [--identity FILE] [-- COMPOSE_OPTION...]` takes the stack back to the rollback point, losing everything since. The operator first sets `SUPERBOT_VERSION` (or `SUPERBOT_IMAGE`) in `.env` back to the record's image, so that the stack starts the release that made the data, now and on every later `up -d`. Editing `.env` stays the operator's, as in ADR 0317.

Before anything changes it checks:

- the record is one `backup-compose` wrote (format 1, every field well formed), and the archive is there with the record's SHA-256;
- the stack is the record's Compose project (the container's `com.docker.compose.project` label), and has run botd;
- Compose would start botd from the record's image (`docker compose config --images botd`), so `.env` was changed back;
- that image is on the host with the record's image ID: a tag can be loaded again with another build;
- the old botd would start with the stack's settings, with its own `botd settings check` (ADR 0317's step, as Compose would start it);
- botd will be given the master key that sealed the archive's values: the record's key check is compared with the stack's database's now, read by the botd release the stack ran last. If they differ, the key was rotated since, and the restored secrets open only with the key from before, so it refuses unless `SUPERBOT_MASTER_KEY_PREVIOUS` is set. For a plain database `superbot-restore --check` can't tell this: it checks the database, not whether the key opens its sealed values;
- the old image's `superbot-restore --check` reads the archive. An encrypted one needs `--identity`, the backup key, mounted read-only for the container's user.

Then it stops the stack, restores the archive with the old image's `superbot-restore` (`docker compose run --rm --no-deps`), which keeps what it replaces in `.pre-restore-<stamp>/` in the data volume, and runs `docker compose up -d --wait`, which recreates the containers from the image `.env` names. It removes the rollback point only once the stack is healthy, so a botd that won't start on the restored data can be fixed and the rollback run again.

If the restore fails, the number of `.pre-restore-*` folders says whether it had started swapping the data. If it hadn't, `docker compose start` starts the stopped containers as they were, on the newer image, and the rollback point is kept. If it had, the stack stays stopped and the output says where the data from before is.

### The downgrade refusal

`check-compose`, and `load` in a stack's folder, first ask the image's own `botd support check` ([ADR 0187](0187-offline-support-check-and-bundle.md)), read-only, through `docker compose run` as ADR 0317 runs its checks. If its database line says the database was made by a newer botd, or that a newer botd ran on it last, they stop before the settings check: nothing changed, keep the stack on its image, and go back with `rollback-compose` or a backup made on that release. This is the Compose form of `install.sh`'s refusal of an older bundle. A check that exits with more than 1 stops too; an image without `botd support check`, or a check that says nothing about the database, is let through with a warning, as ADR 0317 lets older images through.

`rollback-compose` isn't refused: going back with the data from before is what the refusal asks for.

## Considered

- **Taking the rollback point inside `check-compose`.** That would make the check change things, and a check is often run several times while `.env` is fixed. A separate command keeps `check-compose` read-only, and the check's output says to run it.
- **Writing it into the `backups` volume with the daily ones.** Retention would prune it, off-host copies would ship it, and botd could change it. A folder of the operator's keeps the record and archive as they were made.
- **Rolling back the image too, with `SUPERBOT_IMAGE` set only for that `up -d`.** The next `up -d` would read `.env`, start the newer release on the restored data, and migrate it again. Requiring `.env` to name the old image first makes the way back stick.
- **Copying the volumes with `docker run -v ... tar`.** That copies a live SQLite file and ignores database encryption. The image's own backup and restore already handle both and are the documented Compose path.
- **Checking the archive's sealed values against the keys in Rust.** The old image's botd would have to know how, and an older release doesn't. Comparing the key check needs only `botd database query`, which releases since database encryption ([ADR 0116](0116-database-encrypted-at-rest.md)) have, and catches a rotation since the point, the case where the key botd has stops opening the old values. Whether `SUPERBOT_MASTER_KEY_PREVIOUS` is the right old key is left to botd, which refuses to start with a wrong one; the rollback point is kept until then.
- **A downgrade guard on versions alone.** The images have no version label, and the version a stack last ran is in its database. `botd support check` reads both the schema and the last release that started.

## Consequences

- A Compose upgrade that goes wrong is undone with one command, after the operator sets the old tag in `.env` again, as long as `backup-compose` ran before the switch. Everything saved since is lost, and it says so.
- A Compose stack no longer starts an older release on a database a newer one changed, when the operator runs `check-compose` or `load` before the switch.
- `check-compose` and `load` run one more short-lived container from the image, with the stack's volumes, as botd's user. `botd support check` changes nothing.
- The rollback point needs room for one more backup in the stack's folder, and takes as long as a backup.
- The online installer (`install.sh --upgrade`) and `install.sh --offline` are unchanged.
- Tested:
  - `deploy/test-offline.sh`, with a stand-in `docker`: `check-compose` asks the image's `botd support check` as Compose starts botd and passes when no newer release ran; it stops on "made by a newer botd" and "ran on it last", before the settings, and on a check that doesn't finish; it warns when the check says nothing of the database; it names the rollback point, or says to take one. `backup-compose` streams the running botd's `superbot-backup -` into a private folder with a record of the image, its ID and project and the key check, replaces the last point, says when it isn't encrypted, keeps the last point when the backup fails or isn't an archive, or botd is stopped, and refuses while another run holds the folder. `rollback-compose` checks the old image's settings, the master key against the live database's key check, and the archive with its `superbot-restore --check` (the key mounted read-only), then stops, restores, starts on the old image and removes the point, in that order; it refuses, changing nothing, without a point or its key, while `.env` names another image, for a changed archive or damaged record, another build or project, settings or an archive the old release refuses, a master key rotated since without `SUPERBOT_MASTER_KEY_PREVIOUS`, and while another run holds the folder; it goes on with the previous key given, and warns for a record without a key check; a restore that fails first starts the stack again as it was, and one that fails while swapping leaves it stopped; a stack that doesn't come up is said, and the point kept.
  - `deploy/docker/smoke-test.sh` (the `docker.yml` workflow), against the real image and stack with encrypted backups: `check-compose` says no newer release ran on the database; `backup-compose` takes an encrypted rollback point with a key check; `rollback-compose` finds the same master key; a Bot created after it is gone after `rollback-compose --identity`, a Bot and a secret from before are there, botd is healthy, and the point is removed.
- Not covered:
  - Going back more than one upgrade: the next `backup-compose` replaces the point.
  - The Hermes volume and other volumes (workspace, users' homes): only botd's data volume is restored. The Hermes volume for the old pin is still there unless the operator removed it ([ADR 0275](0275-hermes-agent-bundle-for-docker-compose.md)).
  - A stack whose botd is stopped: `backup-compose` needs it running. `docker compose run --rm --no-deps -T botd superbot-backup - > file` on the old image is the manual way.
  - Users' machines, which keep what the newer release gave them, as in ADR 0300.
  - Whether `SUPERBOT_MASTER_KEY_PREVIOUS` is the key from before: botd says so at start, and the point is kept.
