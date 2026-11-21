# 0059: Refusing guarded runs on a Codex too old to run the hook

## Status

Accepted (21 Nov 2026). The leftover of approvals follow-up 1 ([list](../approvals-followups.md), tracking issue [#13](https://github.com/CG-Labs/superbot/issues/13), M1). It builds on [ADR 0007](0007-approvals.md) (approvals, the hooks and the unguarded-run canary), [ADR 0036](0036-bots-on-the-users-machine.md) (Bots on their owner's machine), [ADR 0039](0039-machine-harnesses-and-agent-upgrades.md) (harness CLIs on machines) and [ADR 0057](0057-harness-hook-e2e-tests.md) (which found the oldest Codex that runs hooks in `codex exec`: 0.141.0).

## Context

Codex 0.132 to 0.140 accept the hook settings the adapter passes but never run the hook. A guarded run on one of them starts, its first shell command runs unchecked, and then the canary stops the run. Machines install the pinned Codex (0.171.0), but a server's Codex is whatever the operator or the Docker image installed, and a machine can be given another version (`codex@<version>` in `MACHINE_HARNESSES`) or have one installed by hand.

## Decision

### Ask the harness where the run happens, before it starts

An adapter may name the oldest release that runs its hook: `Adapter::hooks_since`. Codex says `0.141.0`; the other harnesses say nothing and aren't checked. The test that ties it to CI: `CODEX_MIN_HOOKS` in the `harness-e2e` workflow must be the same version, and every pin in `install.rs` must meet it.

When the Bot's effective policy is `ask`, the runner checks after it knows where the run goes, before anything runs:

- **On this server**: it finds `codex` on the run's own `PATH` (botd's bin folder first, as the run gets it), with relative and empty entries taken from the run's working folder as the harness would take them, and runs `codex --version` there, without botd's secrets, for at most 15 seconds. With per-user accounts ([ADR 0058](0058-harness-os-user-by-default.md)) it still runs as botd: the account gets the same `PATH` and folder, and harness CLIs are installed system-wide for every account to run.
- **On the owner's machine**: it sends `codex --version` as a job, with the same `cwd` and user as the run. The agent finds the binary on its harness `PATH`, as it would for the run. The heartbeat's harness report isn't used: it only knows what the plan installed, not a Codex installed by hand or one earlier on a custom `SUPERBOT_HARNESS_PATH`. No agent change is needed, so every enrolled agent supports it.

The version is the first `major.minor.patch` (with optional `v`, pre-release and build metadata) in what it prints (`codex-cli 0.141.0`). It is compared by semver precedence, so a pre-release comes before its release: `0.141.0-alpha.3` is refused, `0.142.0-alpha.1` passes. Build metadata is ignored.

### Unknown means refused

A Codex that isn't found, doesn't answer in time, exits with an error, or prints no version the parser accepts (`codex-cli dev`, `0.141`) is refused like a too-old one. Approvals fail closed elsewhere (the canary, the hook's timeout), and a Codex whose version can't be read is likely one nobody tested. A Codex built from source says `0.0.0` and is refused too; run a release. The way out for a developer is the same as for the canary: bypass mode for that Bot.

### What the user sees, and the audit log

The run is refused like the other run refusals: given back (it doesn't count against the user's runs), recorded as `bot.run_refused` with outcome `denied`, and the Bot says why in an error bubble, which the client and console already show. No client change is needed.

- `reason`: `harness_outdated` (with `version`) or `harness_version_unknown` (with `detail`, why it couldn't tell). Both carry `harness`, `minimum`, `host` (`server` or `machine`), `machine`, `owner`, `forUser` and `messageId`.
- The message names the minimum, what was found, and the fix. On a server: `npm install -g @openai/codex@<pin>` (from `install.rs`), or rebuild the Docker image. On a machine: keep `codex` in `MACHINE_HARNESSES` at its pin (or `codex@<version>`, 0.141.0 or newer), then `botctl machine harnesses <user>` to send the plan now (ADR 0039). Either way, or set the Bot's approvals to bypass (dev only).
- As with other machine refusals, a shared Bot's chat leaves out the machine's own words (its error); the audit log keeps them.

### Remember only a pass

A version that passed is remembered for 10 minutes, so most runs don't start a process or send a job:

- **Here**, keyed by the file `codex` resolves to, with its size and last change. An update (npm writes new files) is a new key, so it's checked again at once.
- **On a machine**, keyed by the machine.

A refusal is never remembered: once an admin updates Codex, the next run passes. A Codex downgraded within those 10 minutes runs guarded once more and the canary stops it at its first command, as before.

### Stopping a task while it starts

A task has nothing to abort until its run is registered, and the check (like placing it on a machine) happens before that. A stop in that window now marks the task, and the runner checks the mark under the same lock that registers the run: a stopped task says "Stopped." and never starts. The mark is cleared when the next message is taken, so it only ever stops the task that was starting.

### The canary stays

The check covers the one known gap. The canary still stops any guarded run whose harness runs a shell tool without calling the hook, for whatever reason.

## Consequences

- A guarded run on a Codex older than 0.141.0 runs nothing. Before, its first command ran.
- Each guarded Codex run on a cold cache costs one `codex --version`, tens of milliseconds here, or one job round trip on a machine.
- Unguarded runs, and Claude Code, Pi and Hermes runs, are unchanged.
- A Codex whose version can't be read no longer runs guarded. Operators with a dev build use bypass for those Bots.
- Bumping the minimum means changing `hooks_since` and `CODEX_MIN_HOOKS` together; a unit test fails otherwise.

## Alternatives considered

- **Allow unknown versions and rely on the canary.** Keeps odd builds working, but lets a first command through on exactly the CLIs nobody tested.
- **The machine's heartbeat report.** Free, but blind to a Codex the plan didn't install, and wrong for a custom harness `PATH`.
- **A new heartbeat field with each harness's `--version`.** Needs an agent upgrade before it helps, and asks every heartbeat for something only guarded Codex runs need.
- **Checking once at startup.** Misses updates while botd runs, and says nothing about machines.
- **Refusing old Codex pins in `MACHINE_HARNESSES` at startup.** Bypass-mode Bots can still use them, so the check belongs to the run.
