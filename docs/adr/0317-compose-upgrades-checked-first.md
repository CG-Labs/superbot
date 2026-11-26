# 0317: Compose upgrades checked first

## Status

Accepted (26 Nov 2026). Twentieth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Brings what offline upgrades check with `install.sh --offline` (settings in [ADR 0310](0310-offline-upgrades-checked-against-every-setting.md), machines' settings in [ADR 0294](0294-offline-upgrades-checked-against-machines-settings.md), the license in [ADR 0305](0305-the-license-through-offline-upgrades.md)) to Docker Compose stacks, which ADRs 0294, 0305 and 0310 each listed as not covered.

0317 was reserved for this work.

## Context

On a Compose stack an upgrade is `offline-bundle.sh load` for the new images, a new `SUPERBOT_VERSION` (or `SUPERBOT_IMAGE`) in `.env`, then `docker compose up -d`. Compose stops the old container and starts botd from the new image. If that botd refuses a setting in `.env`, or wouldn't run Bots with the license the stack has, the stack is down (botd restarts in a loop) or its Bots stop, and the way back is the old tag in `.env` and another `up -d`, by an operator who has to read the log to know why.

`install.sh --offline` asks the bundle's botd first, so a server installed with it never gets there. The image holds the same botd with the same checks (`botd settings check`, `botd machines check`, `botd license check`), but nothing ran them for a Compose stack. The hard part isn't the check, it's botd's environment: Compose builds it from `.env`, `env_file`, `environment:`, overrides, extra `-f` files and the shell, and mounts the data volume, which holds the license and the sealed secrets.

## Decision

### `offline-bundle.sh check-compose`

`deploy/offline-bundle.sh check-compose [--image REF] [--key-file FILE] [-- COMPOSE_OPTION...]`, run where the operator runs Compose, asks botd from `REF` whether it would start with the stack's settings and run Bots with its license. Without `--image` it checks the image Compose would now run botd from, for an operator who has already changed `.env`. Compose's own options (`-f`, `-p`, `--env-file`, `--project-directory`) go after `--`.

It runs the new botd through Compose itself: `docker compose run --rm --no-deps -T --entrypoint botd botd <check>`, with `SUPERBOT_IMAGE=REF` in Compose's environment, which wins over `.env` when Compose reads the file. botd so gets the stack's own environment, volumes, user and network, whatever files and overrides make them, and nothing is rebuilt by hand that could differ from what `up -d` would run. `--no-deps` starts no other service; `--rm` leaves no container.

Before it runs anything it checks:

- that `REF` is a plain image reference (no `$`, no space, not an option);
- that Compose can read the stack, and that the image it would run botd from, with `SUPERBOT_IMAGE=REF`, is `REF`: a Compose file that names botd's image without `SUPERBOT_IMAGE` would otherwise have the old image checked and reported as the new;
- that the stack has run botd before (`docker compose ps -a` lists its container), so the data volume exists and the check makes no volume or network the stack doesn't have;
- that the image is on this host. It never pulls: an air-gapped host has nothing to pull from, and a pull would change what the tag means.

### What it asks

The image's botd is asked only what it can answer. As in ADR 0310, it looks for each check's usage text in the binary (here with `grep` in the image, no network), because a botd that doesn't know a subcommand would start as the server.

1. **Settings**: `botd settings check`, or `botd machines check` for an image from before ADR 0310, or a warning that it can't be checked. A refusal stops: it prints the first, then each other on an `and:` line, says nothing in the stack has changed, and says to change `.env` and check again. botd reads `.env` again only when Compose recreates it, so the running botd is untouched.
2. **License**: `botd license check`, which reads the license from the data volume and seats from the database, as ADR 0305. `--key-file` gives a key for the new release, sent on stdin (`--key-file -`), so it reaches no command line. If the new botd wouldn't run Bots, it asks the running botd the same, with `docker compose exec`. If Bots run now, it stops and says to get a key from CG-Labs and check with it. If they don't run now either, or the running botd can't say (stopped, or from before ADR 0305), it warns and goes on: the upgrade doesn't make it worse.

It ends with how to switch: `SUPERBOT_VERSION` or `SUPERBOT_IMAGE` in `.env`, then `docker compose up -d`. It never switches the stack itself.

### `load` runs it

`offline-bundle.sh load`, run in a Compose stack's folder (Compose is there and `ps -a` lists botd), runs the same check on the loaded image after `docker load`, and stops the same way. Compose options for it go after `--`. Elsewhere (no stack, or a host that only pushes to a mirror) it prints the `check-compose` line to run from the stack's folder.

## Considered

- **Running the new image's botd with `docker run` and the stack's `.env`.** That skips `environment:`, `env_file`, overrides, the shell's variables and the volume names a project prefix gives. The check would judge a botd the stack doesn't run.
- **Checking inside `up -d`, with a healthcheck or an entrypoint that refuses.** By then Compose has stopped the old container; the stack is down either way.
- **Switching the stack too (`--switch`).** Editing the operator's `.env` and recreating their containers is theirs to do, at a time they pick. Printing what to do keeps the tool read-only.
- **Asking the running botd only, with `docker compose exec`.** It knows today's settings, not what the new release refuses. Only the new botd can say.
- **Checking a stack that has never started.** `run` would create its volumes and network for a check. There is nothing to upgrade yet; a first start says the same in its log.

## Consequences

- A Compose upgrade no longer leaves the stack down because the new release refuses a setting at start, nor stops Bots because it takes the license differently, when the operator runs `load` or `check-compose` first. Nothing changes until they switch.
- `load` in a stack's folder now needs Compose to read the stack and refuses a bad image there; it fails where the old `load` only loaded. Elsewhere it is unchanged.
- The check runs a short-lived container from the new image, with the stack's volumes, as botd's user. It writes nothing botd's own start wouldn't (ADR 0310), and reaches no network but the secrets manager.
- Tested:
  - `deploy/test-offline.sh`, with a stand-in `docker`: settings and license pass and Compose's options reach every call; a refusal lists each refused setting; an image with only `machines check`, or no check, is said and its botd never run; with no `license check` it is said; the license stops when Bots run now, warns when they don't run now either, when the running botd can't say and when botd is stopped, and `--key-file` sends the key on stdin with whitespace dropped; with no `--image` the configured image is checked; an override naming another image, an image not on the host, a bad reference, an unknown option, an unreadable key, a stack that never ran botd, and a stack Compose can't read are refused; `load` checks the loaded image in a stack's folder, says how to switch, stops on a refusal, and prints the `check-compose` line elsewhere.
  - `deploy/docker/smoke-test.sh` (the `docker.yml` workflow), against the real image and stack: `check-compose` says the settings pass and gives the license's outcome; with `SERVER_BACKUP_OFF_HOST=sometimes` in `.env` it stops, naming the setting; and botd is the same container, healthy, after both.
- Not covered:
  - A downgrade guard: `check-compose` checks an older image like any other. botd refuses a database migrated past it at start, after the switch.
  - A backup before a Compose upgrade, as `install.sh --offline` takes for `--rollback` (ADR 0300). The operator backs up first with `docker compose exec botd superbot-backup`.
  - The Hermes volume: `load` already says whether the volume for the new image's pin is there ([ADR 0275](0275-hermes-agent-bundle-for-docker-compose.md)); `check-compose` doesn't.
  - Stacks that pull from a mirror: the image must be pulled (`docker compose pull botd` with the new tag, or `docker pull`) before it is checked.
  - Settings botd judges only with the database open, as in ADR 0310.
