# 0305: The license through offline upgrades

## Status

Accepted (26 Nov 2026). Eighteenth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on the self-host license key ([ADR 0038](0038-self-host-license-key.md)), `install.sh --offline` ([ADR 0128](0128-air-gapped-self-host.md)), upgrades checked against machines' settings ([ADR 0294](0294-offline-upgrades-checked-against-machines-settings.md)) and the backup `--rollback` goes back with ([ADR 0300](0300-offline-upgrades-keep-a-way-back.md)).

0305 was reserved for this work.

## Context

An air-gapped server's license is a signed token, checked offline against the public keys built into botd. Three things can turn a license that runs Bots today into one that doesn't, and an offline upgrade is where they meet:

- **A release can stop trusting a signing key.** When CG-Labs retires a key, the next release drops it, and a license signed with it stops verifying the moment that release starts.
- **`--license-file` installs a key during the upgrade** that may not verify with the new release, or may be for fewer seats than the people active now.
- **`--rollback` puts back DATA_DIR from before the upgrade**, and the license with it. A renewal installed since is lost, and the older release may not take the one that comes back.

In each case the installer finished, botd started, and Bots stopped running. On a connected server the console says why and CG-Labs is an email away; on an air-gapped one the fix is a key file carried in by hand, and nothing said it was needed until after the upgrade. Nothing else checked a key before installing it either: `botctl license install` needs a running botd that takes it, and the console only shows the key installed now.

## Decision

### `botd license check`

`botd license check [--home <dir> | --env-file <file>] [--key-file <file> | -] [--json]` says what this botd makes of an install's license, read as its start reads it:

- the settings from `.env` (or the file given) over botd's environment, as `botd machines check` and `botd support check` read them;
- `LICENSE_KEY`, else `LICENSE_KEY_FILE`, else `DATA_DIR/license.key`, with `--key-file` judged in the file's place, so `LICENSE_KEY` still wins over it, as at start;
- `TESTING_MODE`, which runs Bots with no license, and which botd refuses to start with when it isn't `on` or `off`;
- the seats in use, counted in botd's database opened read-only, with the master key when it's encrypted, against the seats the license allows.

It prints where the license comes from, its mode (`active`, `grace`, `expired`, `invalid`, `unlicensed` or `testing`) and detail, what's wrong with an invalid one, the seats, each warning (an end close, more people active than seats), and last whether Bots would run. It exits 0 when they would and 1 when they wouldn't. It installs nothing and opens no connection; the test that guards licensing against the network scans it too. An operator uses it to check a renewal before installing it, with the bundle's botd or the installed one.

### An offline upgrade checks the license first

`install.sh --offline` runs `offline_license_check` once the bundle, machines' settings and the rollback's backup have been checked, before anything changes:

- **Now:** the running release's botd judges the server's license, as botd's user with only `PATH` and `HOME`, as for `botd machines check`.
- **After:** the bundle's botd judges the license the upgrade leaves: the server's own, or the key in `--license-file`, given on stdin so botd's user never reads root's file. A key is given with its whitespace dropped, as the installer installs it, so a key wrapped across lines is judged as it will be.
- If Bots run now but wouldn't after, the upgrade stops, says why, and says that nothing has changed: re-run with `--license-file` naming a key the release takes, checked first with the bundle's `botd license check`. A dry run says it would stop, and goes on.
- If Bots don't run now either, or the running release can't say, it warns and goes on. Stopping would only keep a server that runs no Bots on the old release.
- Otherwise it logs what the new release makes of the license, and warns on each warning.

With `--testing-mode`, which writes `TESTING_MODE=on`, Bots run with or without a license, so nothing is stopped; a rollback still chooses the license it leaves, as below. A botd is run with `license check` only when its file holds `botd license check`'s usage text, since an older botd would take the unknown subcommand as a start. Without it, the check is skipped with a warning. A new install with `--license-file` says whether the bundle's botd takes the key, and goes on either way, since no Bots run yet.

### A rollback keeps a renewal

On `--rollback`, the older release's botd judges the license over the `.env` it puts back, read from a copy botd's user owns in botd's working directory, as in ADR 0300. Which license that is:

- the key in `--license-file`, when given, which the install then installs as usual;
- else the license installed now, when it differs from the backup's and the older release takes it. It is read as botd's user, since DATA_DIR is theirs, and kept by root in a 0700 folder. Once the backup is restored, it is written back as `DATA_DIR/license.key`, as botd's user, 0600, so a renewal installed since the upgrade outlives the rollback. The backup's license wasn't judged then, so if that write fails, the rollback stops with botd still stopped, and says where the key is: a root-only copy in the rollback folder, and the restore's `.pre-restore-*` copy of DATA_DIR;
- else the backup's, which root reads from the archive, decrypting it with the backup key when it's encrypted.

The same stop applies: if Bots run now but the older release wouldn't run them with that license, the rollback changes nothing and asks for `--license-file`.

## Considered

- **Checking the license key's signature in the installer.** The keys botd trusts are compiled into it, and which release trusts which key is the point. Only that release's botd can say, and it can also count seats, read `TESTING_MODE` and apply the grace period.
- **Stopping whenever the new release wouldn't run Bots.** A server that runs no Bots now loses nothing by upgrading, and the upgrade may be how its operator gets a release that takes their key. It warns.
- **Always putting back the backup's license on a rollback.** That's what restoring DATA_DIR does, but a renewal installed since would be lost, and a license that ended since the upgrade would come back. Keeping the newer key when the older release takes it is what the operator would do by hand.
- **Letting botd's user read root's `--license-file`, or the backup.** botd's user can't read either. Root hands the key over on stdin, and reads the user's own DATA_DIR only as that user, so a link there can't make root read its files.

## Consequences

- An offline upgrade or rollback no longer leaves a licensed server running no Bots without saying so first. When it would, it stops before anything changes, and the fix is a key file and the same command.
- Operators check a renewal, or what the next release makes of their license, with `botd license check --key-file` before they install it.
- The seats check reads botd's database read-only, while botd runs. A database it can't open is reported as seats not counted, not as a failure.
- Release builds trust no key in CI, so the stop and the renewal kept on a rollback are tested with stand-in botds; the real command is tested in CI in testing mode.
- Tested:
  - `cargo test`: the server's license and a key given are judged as at start, `LICENSE_KEY` winning over the key; a key this botd doesn't trust, an ended license, the grace period, testing mode, a `TESTING_MODE` botd refuses and an empty key; seats in an encrypted database with the master key, and without it, and a count that fails reported as not counted; the options and exit codes; and no connection from the new code.
  - `deploy/test-offline.sh`, with stand-in botds:
    - an upgrade runs both botds as botd's user with no environment and stops, changing nothing, when Bots run now but wouldn't after;
    - a dry run, a license neither release takes, a running release or a bundle's botd from before the check, and an online install go on;
    - `--license-file` is judged on stdin in the license's place;
    - a new install's `--license-file` is judged, and goes on either way;
    - a key wrapped across lines is judged without its whitespace, and `--testing-mode` goes on, a rollback with it still keeping a renewal;
    - a rollback keeps a renewal the older release takes, 0600, stops with botd stopped and the key kept when it can't write it, else judges and puts back the backup's license (plain and encrypted), judges with the old `.env` from a copy botd's user owns and removes, stops when Bots run now but wouldn't after, and installs `--license-file` over the backup's.
  - `offline.yml`, with no network and an encrypted database: `botd license check` as botd's user counts seats with the master key, judges a key given as invalid without installing it, and with no testing mode and no license says Bots wouldn't run. The upgrade and the rollback each log what the bundle's botd makes of the license.
- Not covered:
  - Docker Compose: its `.env` and volumes are the operator's. `botd license check --env-file` runs in the image the same way.
  - Online upgrades (`install.sh --upgrade` without `--offline`), which build from source: the operator checks a key with `botd license check` by hand.
