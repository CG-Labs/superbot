# 0294: Offline upgrades checked against machines' settings first

## Status

Accepted (25 Nov 2026). Sixteenth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on Hermes Agent and the harness CLIs on users' machines from botd's bundles ([ADR 0210](0210-hermes-agent-on-air-gapped-machines.md), [ADR 0242](0242-harness-bundle-on-air-gapped-machines.md)) and on the settings check `install.sh --offline` runs ([ADR 0257](0257-checking-settings-for-air-gapped-networks.md)).

0294 was reserved for this work.

## Context

On an air-gapped server, users' machines get Hermes Agent and Claude Code, Codex and Pi from bundles botd serves: `MACHINE_HERMES_BUNDLE` and `MACHINE_HARNESS_BUNDLE` in `.env`. At start, botd checks each bundle in full and refuses to start unless it holds exactly what machines' plan pins. That is right: a bundle can't change what machines run.

But each release pins its own harness versions, and often a new Hermes commit. `install.sh --offline --upgrade` replaced the binaries and restarted botd, and the new botd then refused the last release's bundles still named in `.env`. The server was down after an upgrade that had reported success. The database might already have been migrated, so going back meant restoring a backup. The guide said "after an upgrade, name that release's bundles", which was easy to miss.

Editing `.env` before the upgrade didn't help either. The running, older botd would refuse the new bundles if it restarted for any reason before the upgrade ran.

## Decision

### `botd machines check`

A new subcommand of botd: `botd machines check [--home DIR | --env-file FILE] [--set NAME=VALUE]...`. It runs the same startup code botd runs for machines, in the same order and with the same error prefixes: the tiers, the control plane, machine enrollment, machines' upkeep defaulted to the managed tiers' harnesses, then enrollment into the control plane. That last step reads and checks each Hermes and harness bundle in full against machines' plan. It prints what machines get: the provider and enrollment URL, their upkeep, each bundle and what it holds, and which harnesses come from the bundles. Then it exits 0, or 1 with the error botd would stop with. It starts, serves and writes nothing.

It runs botd's own code, not a copy, so it can't drift from what botd does at start. `hermes_serve` gained two small helpers (`Bundles::holdings`, `from_where`) that `botd harness check-bundles` (ADR 0247) and this check share.

It reads settings as the systemd unit gives them to botd:

- `--home DIR` reads `DIR/superbot/.env` and works in `DIR/superbot`, as `EnvironmentFile` and `WorkingDirectory` do.
- A line ending in `\` goes on in the next, as systemd joins them, so a bundle list split over lines reads as botd gets it. A comment line never takes the next with it, as from systemd 254. `botd offline check` reads `.env` the same way.
- The file's values are set in the process environment, over what botd was started with, so settings read by prefix (named backup stores, for example) are seen too.
- `--set` puts values over both, as the next `.env` will have them.
- Secrets come from the process environment and the external secrets manager `SECRETS_BACKEND` names, as at start. The secrets saved in botd's database aren't part of startup's store, so they aren't read here either.

The machine CA comes from a throwaway cipher: nothing here signs or keeps a certificate.

### The installer runs it before anything changes

`install.sh --offline` over an install that has a `.env` now runs the bundle's botd: `sudo -u superbot env -i PATH=... HOME=... botd machines check --home <home>`, from `/`. It runs as botd's user, so a bundle that user can't read fails here rather than at start. It runs right after the bundle and its Hermes and harness bundles are checked, before the release is recorded, binaries are replaced or botd is stopped.

- Exit 0: the upgrade goes on, and the log shows what machines get.
- Exit 1: the upgrade stops with the reason and "Nothing has changed", and says to carry in this release's bundles or fix `.env`. A dry run reports it and goes on.
- Anything else: a warning, and the upgrade goes on, as before this check.

A bundle's botd from before this subcommand would take `machines check` as a normal start and run as the server. So the installer runs it only when the binary holds its usage text (`grep -qaF "Usage: botd machines check"`), and warns otherwise.

### `--machine-hermes-bundle` and `--machine-harness-bundle`

They name this release's bundles for users' machines. The check takes them with `--set`. The upgrade writes them to `.env`, after the database encryption step, only once it goes ahead. So the new values reach `.env` together with the botd that wants them, and the old botd never sees them. They need `--offline --upgrade`. Online upgrades say to edit `.env`, since an online server can fetch harnesses itself.

Machine bundles without `MACHINE_CONTROL_URL` are ignored by botd, so the check passes them too.

## Considered

- **Starting the new botd and rolling back if it fails.** By then it may have migrated the database, and the old botd may not open it. Checking first changes nothing.
- **A general `botd config check` running all of `main`'s startup.** It would catch more, but `main.rs` is long and other work is changing it in parallel. Machine bundles are what releases break. Other areas can follow with the same pattern.
- **A capability flag in the bundle's `MANIFEST` for the check.** It would need a bundle format change, and the binary's usage text answers the same question for every bundle already made.
- **Installing the new bundles' paths in `.env` before the upgrade.** That leaves a window in which a restart of the old botd fails, as above.

## Consequences

- An offline upgrade no longer leaves botd down because `.env` names the last release's machine bundles. It stops first, names the file and the pin, and says what to carry in.
- Operators can run `botd machines check` by hand, with `--set`, before changing `.env`.
- Online upgrades (`install.sh --upgrade`) are unchanged, and so are fresh offline installs, which have no `.env` yet.
- Tested:
  - `machines::settings_check::tests`: the lines for no control plane, a provider without enrollment, and enrollment with bundles; a Hermes bundle at another commit refused as at start, with the plan from `MACHINE_HARNESSES` and defaulted from the tiers; `MACHINE_APT_MIRROR`, `MACHINE_REGIONS` and `MACHINE_CONTROL_URL` refused with their area's prefix; the options, including `--set` names and `--home` with `--env-file`.
  - `support_check::tests`: `.env` lines ending in `\` are joined to the next, as systemd does, and an escaped `\` or a comment isn't; a two-arch bundle list split over two lines passes the check.
  - `deploy/test-offline.sh`, with a stand-in botd: the check runs as botd's user with only `PATH` and `HOME`, from `/`, with `--set` for the new flags; a refusal stops the upgrade with its reason, or warns in a dry run; an older botd is never run; a check that fails to run warns; nothing runs online or without a `.env`. The flags need `--offline --upgrade`, and write and replace their `.env` lines.
  - `offline.yml`, with no network: the installed botd passes the real harness bundle as botd's user and refuses it against another claude pin. An upgrade with `--machine-harness-bundle` checks and writes it. An upgrade over a `.env` botd would refuse stops with "Nothing has changed", and botd isn't restarted.
- Not covered:
  - Docker Compose (`offline-bundle.sh load`): Compose's `.env` and volumes are the operator's, and the container shows the refusal at start.
  - Settings outside machines, such as SSO or storage, which botd also checks at start.
  - Secrets saved in botd's database, which startup's machine settings don't read.
