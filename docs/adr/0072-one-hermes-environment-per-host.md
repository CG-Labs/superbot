# 0072: One Hermes environment per host, shared by every Bot

## Status

Accepted (21 Nov 2026). Meets the first condition [ADR 0070](0070-hermes-per-bot-footprint.md) set on the footprint item of the [ADR 0011 checklist](0011-hermes-agent-backend.md#recommendation), and fixes the D-Bus/keyring leftovers it found. Part of [#33](https://github.com/CG-Labs/superbot/issues/33) (M3).

## Context

ADR 0070 measured 487 MiB of disk and about 20 CPU-seconds for each new Hermes Bot, and made "share one dependency environment across a machine's Bots" a condition for making Hermes the managed default. Three facts from Hermes v0.23.2's source explain the cost:

- **Dependency state lives per data root.** Each Bot has its own `HERMES_HOME` (Hermes's isolation unit, and SuperBot's: [ADR 0015](0015-hermes-adapter.md)). Hermes keeps its Python environments in `HERMES_HOME/installs/<hash of the checkout path>/environments/<generation>/`. A launch under a data root other than the installer's "borrows" the checkout and runs `uv sync` into its own root (`hermes_cli/venv_sync.py`). That is the 470 MiB and 20 CPU-seconds per Bot.
- **A Bot running as another OS user can't start at all.** The borrow refuses an environment another user owns, then finds none committed in its own root. So Hermes failed outright for per-user accounts ([ADR 0064](0064-teammate-accounts-on-one-server.md)), for harnesses as their own OS user ([ADR 0058](0058-harness-os-user-by-default.md)), and for Bots on machines as their own user ([ADR 0043](0043-bots-own-os-user-on-machines.md), [ADR 0048](0048-teammates-own-os-user-on-machines.md)), whatever the disk cost.
- **The update check runs per data root.** Once a day per Bot, Hermes runs `git ls-remote` and `gh auth token`. On a desktop host, `gh` starts a `dbus-daemon` and `gnome-keyring-daemon` that never exit (12 MiB per Bot).

Hermes has two supported ways to run from a prepared environment. A **sealed payload**: a `manifest.json` beside the checkout naming a venv makes `pm/environments.py` load that venv, read-only, for any data root without its own dependency state. A **steward-owned install**: `updateMechanism: external` in the install's `install-stamp.json` tells Hermes a package manager owns it, so it skips the per-root sync and reports updates as the steward's job, with no network check.

## Options

1. **Point every Bot at the installer's data root.** Breaks isolation: config, memory, sessions and logins live in the data root, so Bots would share them.
2. **A prepared template home, copied for each new Bot.** Still one environment per Bot on disk (hard links help on one filesystem only), still per-user ownership trouble, and the copy must track every upgrade.
3. **Seal the one install** (chosen). Every Bot keeps its own `HERMES_HOME`; only the program and its environment are shared, read-only.

## Decision

1. **One sealed Hermes install per host.** `deploy/hermes-seal.sh <home>` runs after Hermes's own installer and:
   - writes `manifest.json` naming the environment the installer committed (it must sit inside the install and be a real venv);
   - removes the environment's lease markers (`.lease-managed`, `.leases`), so no run writes into it (other OS users would get EACCES, and the owner would change what everyone shares);
   - sets `updateMechanism: external` in `install-stamp.json` (git-ignored, Hermes's own field);
   - then checks a fresh data root twice, as Hermes is launched in production (`env -i`), and fails if it grew its own environment or leases.

   Each Bot's `HERMES_HOME` then holds only its own state: config, sessions, memory files, logins, and Hermes's small boot record. botd's managed config ([ADR 0015](0015-hermes-adapter.md)) adds `security.allow_lazy_installs: false` and `plugins.auto_update_check_hours: 0`, so a run can't install packages into the shared environment or check for plugin updates. (The `HERMES_DISABLE_LAZY_INSTALLS` variable is not used: it also skips Hermes's launch preparation, which an unsealed install needs.)
2. **Versioned folders and one atomic switch.** Hermes's launcher and environment name their own absolute paths, so a version can't be moved after install. Each version goes in its own folder, and `current` is a symlink switched with one `rename`:
   - **Servers and the image**: `deploy/hermes-shared.sh <dir> <commit>` installs into `/opt/hermes/<commit>`, as root, seals it, and switches `/opt/hermes/current`. `/usr/local/bin/hermes` points at `current`. A run that started on the old version keeps its own paths and finishes on it; the next run starts on the new one. The previous version is kept (for runs still on it) and older ones are removed. A version already installed and sealed is reused; one cut short starts again. `deploy/install.sh --with-hermes` now always installs this way, whatever the isolation mode, and re-points the old per-service-user launcher at the shared one. Every account may run it, none may change it.
   - **Machines** ([ADR 0039](0039-machine-harnesses-and-agent-upgrades.md)): an installer-script recipe installs into `scripts/<name>/<version>-<recipe hash>/`, runs the recipe's new optional `after` step (Hermes's is `hermes-seal.sh`, sent by the control plane), and relinks `bin/<name>` in one rename. Installing a new version no longer waits for running jobs; removing the old folders does: it runs under the agent's replace gate, once no job is running.
   - **CI** (`deploy/install-harness-clis.sh`): the same `hermes-shared.sh`, with the pinned installer checksum.
3. **The `after` step is a capability.** Older agents reject unknown recipe fields, so agents now report `script_after`, and the control plane strips `after` from plans for agents that don't. Those agents install Hermes as before until they upgrade, which the control plane already pushes ([ADR 0039](0039-machine-harnesses-and-agent-upgrades.md)). `after` is at most 64 KiB, runs as the installer does (same env, HOME, timeout), and must succeed before the link moves.

## Results

Same 4-vCPU, 16 GiB VM and pinned Hermes v0.23.2 as ADR 0070; `deploy/harness-footprint.sh --harness hermes`, fake model at 1.5 s per call. "Per Bot" is the unsealed install (ADR 0070's layout), "shared" is this ADR's.

| | Per Bot (before) | Shared (this ADR) |
|---|---|---|
| Install | 2,604 MiB | 2,602 MiB |
| Disk per new Bot | **482.5 MiB** | **4.8 MiB** |
| Cold start (new Bot) | 19.0 s | 7.9 s |
| Warm start | 5.1 s | 4.1 s |
| CPU per typical run | 6.7 s | 4.1 s |
| Peak PSS per run | 333 MiB | 330 MiB |
| 4 new Bots at once | 1,280 MiB PSS, **80.5 CPU s**, 27.8 s | 1,227 MiB PSS, **18.9 CPU s**, 11.6 s |
| The same 4 again | 26.5 CPU s, 12.9 s | 16.3 CPU s, 11.0 s |
| Left running when idle | 10 processes, 59 MiB (D-Bus and keyring, 5 Bots) | **0** |

Pinned to one CPU (`--cpus 1`, 3 Bots at once), as on a Starter:

| | Per Bot (before) | Shared (this ADR) |
|---|---|---|
| Cold start | 22.1 s | 5.5 s |
| 3 new Bots at once | 56.9 CPU s, **67.1 s** | 14.0 CPU s, **20.9 s** |
| The same 3 again | 18.9 CPU s, 25.8 s | 12.8 CPU s, 19.9 s |

A new Bot now costs what a repeat run does. Memory per run doesn't change: that is Python itself, not the environment. Per run, Hermes no longer runs `uv pip check`, `git ls-remote` or `gh`. By disk, a Starter's 20 GiB now holds thousands of Hermes Bots instead of 28.

The `harness-e2e` workflow's Footprint job now fails if a Hermes Bot's state passes 128 MiB, and its Hermes job runs the sealed install as `nobody` with a fresh data root and checks that no environment appears.

## Consequences

- Hermes works for Bots running as their own OS user, on servers and machines, which it didn't before.
- Hermes's own update check is off for every install SuperBot makes; upgrades are SuperBot's (`HERMES_COMMIT`, the machine pins), as ADR 0070 asked.
- An upgrade briefly holds two versions on disk (about 5.2 GiB), then drops back to one or two.
- Existing installs move on their next install or upgrade: the checkout's path changes, so every Bot then uses the shared environment. Each existing Bot's old environment (`DATA_DIR/bots/<id>/hermes/installs/`, about 480 MiB) is left in place, unused.
- Servers keep the previous version until the next upgrade; machines remove it as soon as no job runs. The unversioned `/opt/hermes` layout (per-user installs before this ADR) goes after the second upgrade.
- `deploy/test-hermes-shared.sh` (CI) tests install, seal, the switch with a run still on the old version, reuse, an install cut short, a bad checksum and pruning, with a fake installer. Rust tests cover versioned folders, the `after` step, pruning held by a running job, and plans for older agents.
- Follow-ups on [#33](https://github.com/CG-Labs/superbot/issues/33): remove old per-Bot environments once no run uses them; the per-machine concurrent-run cap by tier (ADR 0070's second condition) is still open.
