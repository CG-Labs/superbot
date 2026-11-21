# 0072: One Hermes Agent environment per computer

## Status

Accepted (21 Nov 2026). Meets the first condition [ADR 0070](0070-hermes-per-bot-footprint.md) set on Hermes Agent becoming the managed default: share one dependency environment across a machine's Bots. Part of [#33](https://github.com/CG-Labs/superbot/issues/33) (M3), item 2 of the [ADR 0011 checklist](0011-hermes-agent-backend.md#recommendation).

Since [ADR 0077](0077-two-providers-through-tier-routing.md), `deploy/hermes-share.sh` also adds Hermes's `anthropic` extra to the shared environment, since Bots can't install it. Its wrapper also gives a Bot with no `config.yaml` an empty one, since Hermes reads the fallback chain only from a data root that has one.

## Context

Each Bot runs Hermes with its own `HERMES_HOME` (the Bot's state folder, [ADR 0015](0015-hermes-adapter.md)), and that is how one Bot's config, memory, sessions and logins stay apart from another's. Hermes keeps its Python dependency environment per data root, in `<HERMES_HOME>/installs/<key>/environments/` (`<key>` is the start of the SHA-256 of the checkout's real path). So every new Bot's first run built a 470 MiB environment of its own: [ADR 0070](0070-hermes-per-bot-footprint.md) measured 487 MiB of disk and about 20 CPU-seconds per new Bot, and 90 CPU-seconds when four new Bots start at once.

The isolation must not get weaker. A Bot must not read another Bot's state, and a run under one OS user must not read or change another's files: the machine's Bots' own user ([ADR 0043](0043-bots-own-os-user-on-machines.md)), teammates' own users there ([ADR 0048](0048-teammates-own-os-user-on-machines.md)), and per-user accounts on one server ([ADR 0037](0037-per-user-unix-accounts.md), [ADR 0058](0058-harness-os-user-by-default.md), [ADR 0064](0064-teammate-accounts-on-one-server.md)).

What Hermes (v0.23.2, the pin) offers, and why it doesn't fit as is:

- **Profiles** (one data root, several profiles) share the root's `auth.json`, plugins and lease sweeps between profiles, so Bots would share logins.
- **One writable install state for every Bot** works only under one OS user: each launch takes a lock and writes a lease file in the install's state.
- **Running the environment's Python directly** skips Hermes's launcher, but Hermes starts its own children (the gateway) through the launcher again.

A launch reads `installs/<key>/facts.json`, which names the committed environment, and accepts it only if it sits under that data root's `installs/<key>/environments/` once links are resolved. It then takes `installs/<key>/.install.lock` and, if the generation has a `.lease-managed` marker, a lease in it. `HERMES_DISABLE_LAZY_INSTALLS=1` stops a launch from installing anything.

## Decision

1. **One environment per install, read-only to Bots.** After Hermes's installer runs, `deploy/hermes-share.sh` runs as the install's owner, with the HOME the installer had. It finds the committed environment from `facts.json`, removes its lease marker and leases (so no Bot takes a lease, and Hermes never collects it: generations without the marker are kept), removes environments left from earlier installs, and writes a copy of itself with the install's paths filled in to `<install>/.hermes/superbot/hermes`. That copy is the `hermes` Bots run.
2. **Each Bot keeps its own record of the install, in its own `HERMES_HOME`.** Run with a Bot's `HERMES_HOME`, the copy makes `HERMES_HOME/installs/<key>/` (owned by whoever runs it, closed to other accounts): a copy of `facts.json` and of the input stamps, and a link to the shared `environments/`. Hermes accepts that record (the link resolves inside it), and takes its lock in the Bot's folder. The copy sets `HERMES_DISABLE_LAZY_INSTALLS=1`, so a Bot never installs or changes dependencies; only the installer does. Without a `HERMES_HOME`, or with the install's own, it just runs Hermes. A Bot from before this has an environment of its own there; it goes on the Bot's next run.
3. **Isolation is unchanged.** Each Bot still has its own `HERMES_HOME`, so config, memory, sessions and logins stay per Bot, and each run's files belong to its own OS user. What Bots share is the program and its environment, which only the install's owner can change (the machine agent's user, root, or botd's service user in a single-user install), as they already shared the checkout. `deploy/test-isolation.sh` checks it on a real host: two per-user accounts run the shared Hermes, each gets its own record owned by itself, neither can write the shared environment or `facts.json`, and one can't read or use the other's.
4. **Everywhere Hermes is installed.**
   - **Machines**: the install recipe botd sends gains an `after` script (`InstallSource::Script`), run like the installer, in its HOME, once it succeeds; its `bin` is the copy. Only an agent that says `install_after` is sent it; an older agent gets the recipe it always did (no `after`, Hermes's own launcher, the same plan id), since plans deny unknown fields.
   - **One server** (`deploy/install.sh --with-hermes`): the script is staged with the other root-owned deploy files and run after the installer. Without per-user accounts, botd's `.env` PATH gains `~/.hermes/superbot`; with them, `/usr/local/bin/hermes` links to `/opt/hermes/.hermes/superbot/hermes`, and a `nobody` run checks it.
   - **Docker image** (`HARNESSES` with `hermes`): the same, in `/opt/hermes`, with a `nobody` run as the check.
   - **Tests**: `deploy/install-harness-clis.sh` runs it, so the hook tests and the footprint run Hermes the way Bots do.
5. **Upgrades stay safe for running Bots.** A new pin builds a new environment and removes the old one, so a running Bot must not be using it:
   - Machines already replace an installed harness only once no job of it is running, and hold new jobs meanwhile.
   - `install.sh` stops botd before it reinstalls Hermes at a new commit (`install_systemd` starts it again); at the same commit it only reruns the script, which keeps the committed environment. It installs packages and downloads the installer before stopping botd, and starts botd again if the install fails after that.
   - A new Docker image is a new container.
   - Each Bot's record follows the install: when the shared `facts.json` changes, the next run copies it again.
6. **The footprint test watches it.** It reports a new Bot's state on disk and how much more CPU a new Bot's first run takes than its next, and fails if a new Bot's state passes 64 MiB, which a Bot building its own environment (about 470 MiB) would.

## Results

The `harness-e2e` workflow's Footprint job, on the same runner type (4 vCPUs, Intel Xeon 6975P-C, 15.3 GiB) before and after. Before is `main` at `9362ce5` (the ADR 0070 measurement run in CI); after is this change at `4cb1080`. Hermes Agent v0.23.2, fake model, 4 Bots at once.

| Hermes Agent | Before | After |
|---|---|---|
| A new Bot's state on disk | 488 MiB | **4.7 MiB** |
| Extra CPU of a new Bot's first run, over its next (per Bot) | 23.4 s | **0.66 s** |
| A new Bot's first run, CPU (per Bot, 4 at once) | 31.6 s | 7.8 s |
| 4 new Bots at once | 126 CPU s, 41.1 s | 31.2 CPU s, 15.0 s |
| The same 4 again | 32.6 CPU s, 15.0 s | 28.6 CPU s, 14.2 s |
| Cold start (a new Bot's first one-turn run) | 19.5 s, 29.6 CPU s | 9.2 s, 10.3 CPU s |
| Warm start | 5.5 s | 4.4 s |
| Typical run: peak PSS, CPU | 346 MiB, 6.2 s | 341 MiB, 5.2 s |
| Install | 2,602 MiB | 2,604 MiB |

A new Bot now costs about what a Bot's next run costs: 4.7 MiB of its own state (sessions, config, the skills Hermes copies in), and well under a CPU-second more on its first run. The cold start is still about 5 s longer than a warm one. That is the once-a-day update check Hermes runs per `HERMES_HOME` (ADR 0070, point 5), not the environment. Per-run memory and CPU don't change; the environment was never part of a run's cost. By disk, a Starter's 20 GiB now holds about 2,900 Hermes Bots, not 28.

## Consequences

- Hermes's environment costs disk once per computer, not once per Bot, and a new Bot's first run costs about what its next ones do.
- Bots can't install Python packages into Hermes's environment at run time (Hermes's lazy installs). A feature that needs one needs the installer to add it.
- `deploy/hermes-share.sh` depends on Hermes internals (`installs/<key>`, `facts.json`, the lease marker). A pin bump runs the hook tests and the footprint, which run through it; if Hermes changes those, the script fails at install time rather than at a Bot's run.
- Not changed: the install itself (2.6 GiB), per-run memory and CPU, and the other ADR 0070 follow-ups (a concurrent-run cap per tier, a pin bump, two providers, a hook-timeout test).
