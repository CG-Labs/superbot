# 0275: Hermes Agent with Docker Compose from the Hermes bundle

## Status

Accepted (25 Nov 2026). Fourteenth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on the Hermes bundle ([ADR 0200](0200-hermes-agent-bundle-for-air-gapped-installs.md)) and its place in the release check ([ADR 0247](0247-hermes-and-harness-bundles-in-the-release-check.md)).

0275 was reserved for this work.

## Context

Hermes Agent is the default harness on every shipped plan ([ADR 0079](0079-hermes-default-for-managed-tiers.md)). The bash install takes it from the signed Hermes bundle with no network (ADR 0200), and users' machines take it from botd's copy (ADR 0210). The published image has no Hermes Agent, because it adds about 2.5 GB.

So an air-gapped Compose deployment had one way to run Hermes. The operator built an image of their own on the connected side, with `HARNESSES="... hermes"`, bundled it with `--allow-unsigned` and set `SUPERBOT_IMAGE`. That throws away what the rest of #59 gives: the image is unsigned, has no SBOM or provenance from the release, and isn't the one the release check checked. Hermes's installer ran on the operator's builder, from the internet, at whatever it fetched that day. Every release meant building it again.

## Decision

### `offline-bundle.sh load-hermes`

```sh
deploy/offline-bundle.sh load-hermes HERMES_BUNDLE [--sha256 HEX] [--image REF] [--env-file FILE] [--volume NAME]
```

Run from the Compose folder, after `load`. Before it changes anything, it checks:

- the Hermes bundle, with `install.sh`'s own checks: its SHA-256 or signature, `SHA256SUMS`, a `MANIFEST` for this arch and `/opt/hermes`, and every tree entry staying inside `/opt/hermes`, with none setuid;
- the image Compose runs botd from, found as Compose finds it (`SUPERBOT_IMAGE`, else the published image at `SUPERBOT_VERSION`, else `main`, from the environment, then the env file), or `--image`. The image must be there, since nothing is pulled, and be for this arch;
- that the bundle holds exactly the Hermes commit that image's botd pins, from `botd harness pins` run in the image with no network. The bundle's own commit isn't trusted on its own: a Hermes for another release would run, but with a CLI that release's adapter wasn't tested with.

Then it copies the checked tree into a new Docker volume, `superbot-hermes-<first 12 of the commit>`, labelled with the commit. In a root container with no network, it runs `hermes-share.sh` as `install.sh` does, so the wrapper and shared environment match. It makes the tree root's, not writable by anyone else, and readable only where runs need it (the same list `install.sh` uses). Then it runs `hermes --version` from the volume, mounted read-only in the image with no network, as the image's user and as another account (per-user accounts run it as theirs). Only then does it write a marker into the volume. A volume without the marker is from a failed load, and the next run removes it and starts again. A volume with the marker for that commit is left and checked again.

It prints the two `.env` settings Compose needs.

### `docker-compose.hermes.yml` and the image

`docker-compose.hermes.yml` adds one thing to `botd`: the named volume, external and read-only, at `/opt/hermes`. `SUPERBOT_HERMES_VOLUME` must be set, or Compose stops and says so. It's opted in with `COMPOSE_FILE` in `.env`, so `docker compose` commands need no `-f`.

The image now links `/usr/local/bin/hermes` to `/opt/hermes/.hermes/superbot/hermes` always, and has `libatomic1` (Hermes's Node.js tools need it) in every build. Without the volume, the link dangles and `command -v hermes` doesn't find it, so botd sees no Hermes, as before. An image built with Hermes baked in has the same link, to its own tree in the image.

`load` reads the release botd's Hermes pin and says whether that pin's volume is there, or which Hermes bundle to load.

### Considered

- **Hermes in the published image.** Every pull would be 2.5 GB larger for an opt-in harness. A second published image (`superbot-hermes`) would double what is signed, mirrored, bundled and checked for every release, and still carry a copy of the Hermes bundle's contents.
- **Load the bundle at botd's start, inside the container.** botd would need to write `/opt/hermes`, run as root or hold the tree writable, and do a 2.7 GB unpack on each new container. A volume keeps the tree root's and read-only to botd, and is made once per commit.
- **A bind mount of a host folder.** It needs a root-owned host path the operator keeps in step, and the tree's owners and permissions depend on the host. A named volume lives with Compose's other volumes and needs no host path.
- **Overwrite one volume in place.** A failed upgrade would leave botd with half a tree. A volume per commit is made beside the old one, and the old one stays until the operator switches.
- **Trust the bundle's `MANIFEST` commit.** The bundle is signed, but the release it came from isn't necessarily the image's. Asking the image's botd ties the two together.

## Consequences

- An air-gapped Compose deployment runs the release's signed images and its signed Hermes bundle, both checked by the release check, with no build of its own.
- The bash install, the machines and Compose take Hermes from the same bundle, shared the same way.
- Moving the Hermes pin means carrying in the new bundle, as for the bash install. `load` says so.
- Tested:
  - `deploy/test-offline.sh`, with a stand-in `docker`: `load-hermes` refuses no bundle, an offline bundle, a wrong SHA-256, a changed tree, another arch's bundle, a bad volume name, a missing image (including the image named by `.env`'s `SUPERBOT_VERSION`, a quoted `SUPERBOT_IMAGE` digest, and the environment over `.env`), an image for another arch, an image with no pins, and an image at another pin. None of those touch a volume. The bundle carries `docker-compose.hermes.yml`.
  - `deploy/docker/smoke-test.sh`, with the stack's real image: a stand-in Hermes tree at the image's pin is bundled, loaded and mounted with `docker-compose.hermes.yml`. botd finds `hermes` on PATH and runs it, root can't write the volume, and a second load says it is already there. Without the volume, `hermes` isn't found.
  - The `offline` workflow: the real Hermes bundle, built and checked with no network, loaded into a volume for an image with that run's botd, runs there with no network, root-owned and `755`, and loads again as already there.
- Not covered:
  - Removing the old volume after an upgrade, which is left to the operator so a rollback still has it.
  - Hermes Agent for Compose with the internet: building from source with `SUPERBOT_HARNESSES=... hermes` is still the way.
  - A volume driver other than Docker's local one, and Docker rootless or Podman, which aren't tested.
