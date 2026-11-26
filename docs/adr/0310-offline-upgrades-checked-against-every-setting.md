# 0310: Offline upgrades checked against every setting first

## Status

Accepted (26 Nov 2026). Nineteenth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on upgrades checked against machines' settings ([ADR 0294](0294-offline-upgrades-checked-against-machines-settings.md)), the backup `--rollback` goes back with ([ADR 0300](0300-offline-upgrades-keep-a-way-back.md)) and the license through upgrades ([ADR 0305](0305-the-license-through-offline-upgrades.md)).

0310 was reserved for this work.

## Context

botd reads about fifty areas of settings at start (SSO, SCIM, sign-ups, sessions, billing, notifications, audit export, retention, backups and their encryption, residency, isolation, machines and more) and refuses to start on any it can't use. That is right: a half-understood setting must not run.

ADR 0294 made `install.sh --offline` ask the new release whether it would start with machines' settings before changing anything. The rest weren't asked. A release that tightens any other setting, say a value it used to take loosely, or a second setting it now needs beside one the server has, still replaced the binaries, restarted botd and left the server down after reporting success. The way back is then `--rollback`, which loses nothing only if nobody used the server in between, and needs the previous bundle. ADR 0294 listed this as not covered.

## Decision

### `botd settings check`

`botd settings check [--home <dir> | --env-file <file>] [--set NAME=VALUE]...` judges each setting botd's start reads and refuses before it opens the database. It takes its options from `botd machines check` and reads settings the same way: the file's values set in the process environment, over botd's, `--set` over both, secrets from the environment and the secrets manager `SECRETS_BACKEND` names, and `--home` working in `<dir>/superbot`, as the unit does.

It calls the same parsers start calls, with the same values and in start's order, and words each refusal as start logs it (`SSO: …`, `Server backups: …`, or a bare `STATUS_PAGE must be on or off`). Unlike start, it goes on after a refusal, so the operator sees everything to fix at once. An area that reads one refused before it (Google Workspace sync reads SCIM and SSO; billing emails read billing and notifications) is `skipped`, not judged on a guess. Machines are judged by `botd machines check`'s own code, which it calls, so the two can't disagree.

It prints a line per area (`ok`, `refused` with the error, or `skipped` with why), what machines get, and what it leaves to other checks; then `botd would start with these settings.` and exits 0, or one `botd wouldn't start with these settings: <error>` line per refusal, the first being what start would stop with, and exits 1.

It leaves to others what needs more than settings:

- the database and master key, which the running botd holds: `botd support check` reads them read-only;
- the license, which ADR 0305's `botd license check` judges with the seats in use;
- screens' ports, which exist only when Xvfb is on botd's PATH, and listening ports, which the running botd holds.

It starts nothing and changes no file. As start does, it may make `DATA_DIR`, `WORKSPACE_DIR` and regional chat stores' folders and keep those last botd's alone (0700): start's own code does that while it reads them, and running as botd's user it can do no more than botd's next start would. It reaches no network but the secrets manager, as start; a test guards its source against network code.

### It can't fall behind start

A test reads `main.rs`, from the first setting read to the end of `main`, and finds every statement that stops start (`exit(`). Each one's first call into this crate must be one `botd settings check` makes, or be on a short list of what it leaves to other checks, with why. A new setting at start therefore fails the build until it is judged here or listed. The test also fails if it finds fewer than forty such statements, so it can't pass by reading nothing.

### The installer runs it over the `.env` the upgrade leaves

`install.sh --offline` over an install with a `.env` runs the bundle's botd as botd's user, from `/`, with only `PATH` and `HOME`, as in ADR 0294. When that botd has `botd settings check` (its usage text is in the file), it runs that; otherwise `botd machines check` as before (a rollback to a release from before this one); otherwise it warns and goes on.

The upgrade writes some settings into `.env` after the check, so the check is given them with `--set`, judging the `.env` the upgrade leaves rather than the one it found:

- what every install writes: `HOST`, `PORT`, `DATA_DIR`, `WORKSPACE_DIR`;
- what this run's flags write: `ALLOWED_HOSTS` and `CORS_ORIGINS` for `--domain`, `TESTING_MODE=on`, the S3 backup target, backup recipients, off-host mode, backup and database encryption, `ISOLATION=off` for `--no-isolation`, and `--machine-hermes-bundle` and `--machine-harness-bundle`;
- stand-ins for what the installer makes later or holds as a secret: `AUTH_PASSWORD` when `.env` has none, a backup recipient when `--backup-age-generate` will make the key, and S3 keys from the installer's environment. botd only checks these are there, and a stand-in keeps the real key off every command line.

Per-user accounts this run turns on (`--isolation` on a server without them) are set up after the check, so `Isolation:` refusals then don't stop the upgrade: the installer makes what they ask for. Any other refusal still does.

If the bundle's botd would start, the upgrade goes on and says so. If not, it stops before the backup, the license check and every change, prints the first refusal and each other one on an `and:` line, says "Nothing has changed", and says to change `.env` (or bring this release's machines' bundles) and check with the bundle's `botd settings check`. A dry run says it would stop and goes on. A rollback judges the `.env` it puts back, from a copy botd's user owns, over what the install then writes, as ADR 0300 did for machines' settings.

## Considered

- **Running the new botd for real, on another port, and seeing whether it starts.** Start opens and migrates the database, makes the master key if there's none, and starts timers and listeners. A trial start on the live data is the change the check is there to avoid.
- **Refactoring start into one function both share.** That would guarantee they match, but it touches the most-changed code in the repository, which several streams of work edit at once. Calling start's parsers and holding the list to start's with a test gets the same guarantee with no change to start.
- **Stopping at the first refusal, as start does.** An operator on an air-gapped network would then fix one setting, carry the result back, and find the next. Listing them all costs nothing.
- **Building the next `.env` in a file and checking that.** It would mean running `configure_env`'s writes twice, or splitting it, which the online install also runs. `--set` reaches the same settings without touching the online path.
- **Checking only settings that changed between releases.** Neither release knows what the other refuses; only the new botd can say.

## Consequences

- An offline upgrade or rollback no longer leaves the server down because the new release refuses a setting at start, for any setting start reads before the database. It stops before anything changes and lists everything to fix.
- Operators check a server against a release before carrying the upgrade out, with the bundle's `botd settings check --home`.
- A new startup setting must be judged by the check (or listed as left to another) before the build passes.
- Online upgrades (`install.sh --upgrade` without `--offline`) are unchanged: they build from source, and the operator runs `botd settings check` by hand if they want.
- Tested:
  - `cargo test`: a plain install starts; SSO, the status page, server backups, database encryption, testing mode, runs at once, the default harness, the port, isolation, SCIM and tiers are each refused as start words them; several refusals are all said, first as start would, and what reads a refused area is skipped; break-glass sign-in needs a password off loopback; machines are judged with the rest, and a refused control plane skips what reads it; the options; no network code; and every refusal in `main` is judged or listed.
  - `deploy/test-offline.sh`, with stand-in botds: the check runs as botd's user, from `/`, with no environment, given what every install writes and what each flag writes; stand-ins for a missing password, a key `--backup-age-generate` will make and S3 keys from the installer's environment, whose value never reaches the command line; a refusal stops the upgrade, saying each one; a dry run goes on; isolation this run sets up doesn't stop it, but a refusal beside it does; a rollback judges the old `.env` from a copy, over what the install writes; and a bundle's botd with only `botd machines check`, or neither, is handled as before.
  - `offline.yml`, with no network: `botd settings check` as botd's user passes on the installed server, judging backups, their encryption, isolation and machines, and refuses SSO with no public URL; the upgrade and the rollback each say the bundle's botd would start; and an upgrade stops, changing nothing and not restarting botd, on `SERVER_BACKUP_OFF_HOST=sometimes` in `.env`.
- Not covered:
  - Docker Compose: its `.env` and volumes are the operator's. `botd settings check --env-file` runs in the image the same way.
  - Settings start judges only with the database open: residency pins at startup, Incus hosts, regional chat stores' contents and destinations, and secrets saved in botd's database.
  - Screens' ports, which overlap `MACHINE_SCREEN_PORTS` only when Xvfb is installed.
