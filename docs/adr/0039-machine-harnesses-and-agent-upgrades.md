# 0039: Harness CLIs and agent upgrades on users' machines

## Status

Accepted. Next slice of [#29](https://github.com/CG-Labs/superbot/issues/29) (M3). Builds on [ADR 0031](0031-machine-enrollment-mtls.md) (enrollment, mutual TLS, the agent), [ADR 0035](0035-machine-firewall-auto-enroll.md) (cloud-init enrollment) and [ADR 0036](0036-bots-on-the-users-machine.md) (Bots on their owner's machine).

## Context

After ADR 0036, a freshly enrolled machine refuses every run with `harness_missing`: cloud-init installs the agent and botctl, but not Claude Code, Codex, Pi or Hermes. Its agent also stays at whatever build it booted with. botd refuses an outdated one (`agent_outdated`), but nothing ever upgrades it.

We want a new machine to run Bots without manual steps, and its agent to keep up with botd. Both must stay off unless asked for, and must not break machines enrolled before this change.

## Decision

### Harness CLIs: botd plans, the agent installs

`MACHINE_HARNESSES` lists the CLIs every machine gets, for example `claude,codex,pi`. It needs `MACHINE_CONTROL_URL`. Unset (the default), botd installs nothing and nothing changes.

The recipes live in botd, in `adapters/install.rs`, next to the adapters. Each is pinned to an exact version:

| Harness | Source | Checked against |
|---------|--------|-----------------|
| `claude` | npm `@anthropic-ai/claude-code` | the tarball's pinned SHA-512 (npm integrity) |
| `codex` | npm `@openai/codex` | same |
| `pi` | npm `@earendil-works/pi-coding-agent` | same |
| `hermes` | Hermes Agent's `scripts/install.sh` at a pinned commit (v0.23.2), as the Dockerfile and install.sh use | the script's pinned SHA-256 |

npm harnesses get Node.js 22, from nodejs.org's tarball for the machine's architecture, checked against its pinned SHA-256. npm checks each dependency (including Claude Code's and Codex's native builds) against the registry's own hashes. `name@version` picks another exact version, without a pinned hash unless one is given (`name@version=sha512-...`). Ranges and tags like `latest` are refused. A different Hermes commit needs its installer's SHA-256 (`hermes@<commit>=<sha256>`).

botd sends the whole plan: `PUT /v1/harnesses` with a `HarnessPlan`, which lists Node.js downloads and each harness's source. The agent knows npm packages and installer scripts, not harnesses, so harness-specific code stays in botd. The agent checks the plan (known harness names, exact versions, HTTPS URLs, well-formed hashes, relative paths). It answers 202 and installs in the background, one harness at a time, under its tools folder (`SUPERBOT_TOOLS`, default `<state dir>/tools`):

- `node-<version>/`, plus links `bin/node`, `bin/npm`, `bin/npx`;
- npm harnesses: `npm pack`, then a SHA-512 check of the tarball against the pin, then `npm install -g --prefix <tools>` of that very file, then a check that the installed version is the one asked for;
- scripts: download, SHA-256 check, run with its own HOME (`scripts/<name>`), then a link in `bin/`.

Nothing that fails a check is kept. `<tools>/bin` comes first on the default harness PATH, and the tools folder counts as a place programs may run from, so the existing `harness_missing` check simply clears. What is installed, and each harness's state, live in `state.json`. A restart picks up where it stopped and doesn't install again. Harnesses that leave the plan stay installed, because a Bot may still be using one.

Heartbeats now also report `can` (`harnesses`, `upgrade`), the agent's `build` (the SHA-256 of its own binary), the plan id it has, and each harness's `version`, `wanted`, `state` (`queued`, `installing`, `installed`, `failed`), `error` and `at`. After each periodic heartbeat, botd sends the plan to an agent that doesn't have it yet (at most every 10 minutes). It sends it again when a harness failed more than 30 minutes ago. A run whose harness is still being installed is refused with a new reason, `harness_installing` ("still being installed on your computer. Try again in a few minutes."). One that failed stays `harness_missing`.

### Agent upgrades

`MACHINE_AGENT_UPGRADES` is `manual` (default) or `auto`:

- `manual`: nothing upgrades an agent by itself. An admin asks: `POST /api/users/{user}/machine/agent/upgrade` (`botctl machine upgrade <user>`).
- `auto`: after each periodic heartbeat, botd also upgrades every idle agent whose build isn't botd's. It does this once per build: a build that failed on a machine isn't tried there again by itself.

Either way, an admin can hold a machine at its build: `PUT|DELETE /api/users/{user}/machine/agent/hold` (`botctl machine upgrade <user> hold|release`). `GET /api/users/{user}/machine/agent` (`botctl machine agent <user>`) shows the agent's build, harnesses and upgrade against botd's. All of these are admin only.

Since botd and the agent share one crate version, the build means the SHA-256 of `superbot-machine` as botd serves it at `/v1/agent`. botd asks only when:
- it ships an agent;
- the agent's build differs;
- the agent says it `can` upgrade;
- the agent isn't held;
- the agent runs no jobs;
- the agent's version isn't newer than botd's. botd never downgrades.

The request is `POST /v1/upgrade` with an `UpgradeRequest`: an id, the version, the SHA-256 of the agent and of botctl, and a trial length. The agent then:

1. refuses if it's busy, on trial, already that build, or can't read its own binary. Once it accepts, it refuses new jobs (503) until it restarts.
2. downloads `/v1/agent` (and `/v1/botctl`, if it has one) from botd's machine port over the CA-pinned mutual-TLS channel, capped at 256 MiB, and checks each SHA-256.
3. writes each as `<file>.new`, and checks the new agent answers `--version` with the version botd named.
4. writes `upgrade-trial.json` in its state dir. Then it swaps each file in one rename, keeping the old one as `<file>.prev`. botctl goes first, then the agent.
5. returns from `run`, so systemd starts the new binary.

The new agent is on trial. The first heartbeat from botd (only the control plane's certificate gets through) commits it: the `.prev` files go and the report says `done`. If no heartbeat comes within the trial (3 heartbeat intervals, at least 5 minutes), the agent puts the old files back and restarts. A new agent that can't even start is caught by the unit's guard, `ExecStartPre=-/usr/local/lib/superbot/agent-guard`. While a trial is open it counts starts, and on the fourth it puts the `.prev` files back. The old agent then reports the upgrade `rolled_back`. botd treats an upgrade it hasn't heard the end of by the trial plus 10 minutes as failed (`timeout`).

Cloud-init now installs the agent and botctl in `/usr/local/lib/superbot/`, with links from `/usr/local/bin`. The unit allows writes there (`ReadWritePaths=/etc/superbot /usr/local/lib/superbot`) and runs `ExecStart=/usr/local/lib/superbot/superbot-machine run`. The agent finds its binary through `SUPERBOT_AGENT_BIN`, which defaults to that path. An agent that can't read its binary there says it can't upgrade, and is left alone.

### Audit

| Event | Meaning |
|-------|---------|
| `machine.harnesses_requested` | botd (or an admin) sent the plan. Includes `planId` and `harnesses` (`name@version`); outcome `failure` with `error` if the agent didn't take it. |
| `machine.harness_installed` | A heartbeat showed a harness newly installed, with its version. |
| `machine.harness_install_failed` | A heartbeat showed an install failed, with the version and error. Outcome `failure`. |
| `machine.agent_upgrade_requested` | An upgrade was sent. Includes `by` (`auto` or the admin), `upgradeId`, `fromVersion`, `fromBuild`, `toVersion`, `toBuild`. |
| `machine.agent_upgraded` | botd reached the new agent, which kept it. |
| `machine.agent_upgrade_failed` | Outcome `failure`, with `reason`: `refused` (the agent turned it down), `failed` (a download, hash or `--version` check failed; nothing was replaced), `rolled_back` (the new agent was replaced by the old one) or `timeout`. |
| `machine.agent_upgrade_held`, `machine.agent_upgrade_released` | An admin held or released a machine. |

Each change is recorded once: botd stores the last heartbeat's report (`agent_upkeep`) and records only what changed, even when several heartbeats overlap.

### Data

Migration 15 adds to `machines`:
- `agent_upkeep` (JSON);
- `harnesses_sent_at`, `harnesses_sent_plan`;
- `upgrade_hold_at`, `upgrade_hold_by`;
- `upgrade_id`, `upgrade_build`, `upgrade_sent_at`, `upgrade_by`;
- `upgrade_failed_build`.

An upgrade is claimed in one conditional update, so an admin's request and an automatic one can't both go out.

## Consequences

- Self-hosting doesn't change. Without `MACHINE_CONTROL_URL` none of this runs. With it, nothing is installed or upgraded unless `MACHINE_HARNESSES` or `MACHINE_AGENT_UPGRADES=auto` is set, or an admin asks. Both settings without `MACHINE_CONTROL_URL` are a startup error.
- A machine created with `MACHINE_HARNESSES=claude,codex,pi` runs Bots a few minutes after it enrolls, with no manual steps. Until then its runs are refused with `harness_installing`, then go through.
- Everything installed is pinned, and checked by hash before use: Node.js and Hermes's installer by SHA-256, npm tarballs by SHA-512, and the agent and botctl by the SHA-256 botd computed when it started. npm dependencies are checked against the registry's hashes, not ours.
- Installs run as the agent, which is root (ADR 0036), and npm runs the packages' install scripts. That trusts what is pinned: the same packages a server install runs.
- Claude Code updates itself by default, so a machine may drift ahead of its pin. Its heartbeat then reports the pinned version (what was installed), not what's on disk. Turning off the auto-updater belongs with harness logins and settings on the machine.
- Tests run the real agent over real mutual TLS on loopback (as ADR 0036's do). A local HTTPS server stands in for nodejs.org, with a stand-in npm. They cover installing a planned harness, running a Bot with it, refusing a package that fails its pin, and resending the plan. They also cover an upgrade that rolls back through the guard and one that is kept, hold, automatic upgrades, and not retrying a failed build. An ignored test installs the real pins from the internet.

## Not in this slice

- **Harness logins on the machine.** Per-user logins (`~/.claude`, `~/.codex`) aren't moved or made there. Harnesses that need a login need an API key in the user's secrets, as before. This waits for #30 (ADR 0037) per-user accounts and logins.
- **Machines enrolled before this change.** Their unit runs `/usr/local/bin/superbot-machine` under `ProtectSystem=strict`, so their agent can't replace itself and reports no `upgrade`. botd leaves them alone. Reinstall them, or install the agent by hand into `/usr/local/lib/superbot/` with the new unit (`GET /v1/agent` serves it).
- **Hermes on machines** is best effort. Its installer may need system packages (`libatomic1`, `xz-utils`) and takes about 2.5 GB. Failures show in the heartbeat and audit.
- **Uninstalling** harnesses dropped from the plan, and pruning old Node.js versions beyond the one replaced.
- **A signed release channel.** The agent trusts botd's build because it comes over the pinned mutual-TLS channel with botd's hash. Signing releases separately would protect against a compromised botd, which already controls every machine.
- Copying the user's existing folder, screens on machines, a separate OS user for Bots on the machine, and per-user containers on one virtualised server, as in ADR 0036.
