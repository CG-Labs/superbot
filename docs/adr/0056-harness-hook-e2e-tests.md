# 0056: End-to-end hook tests against the real harness CLIs

## Status

Accepted (21 Nov 2026). Approvals follow-up 1 ([list](../approvals-followups.md), tracking issue [#13](https://github.com/CG-Labs/superbot/issues/13), M1). It builds on [ADR 0007](0007-approvals.md) (approvals and the harness hooks), [ADR 0015](0015-hermes-adapter.md) (the Hermes adapter), [ADR 0039](0039-machine-harnesses-and-agent-upgrades.md) (pinned harness CLIs), [ADR 0051](0051-approve-once-per-run.md) and [ADR 0055](0055-harness-sandbox-defaults.md).

## Context

CI tested the policy, the queue and the API, not the harnesses. Each adapter installs SuperBot's gate in its harness's own format: a `PreToolUse` hook in Claude Code's `--settings`, `-c hooks.PreToolUse=…` for Codex, a TypeScript extension for Pi, and a `pre_tool_call` hook in a Hermes managed config. Whether the CLI actually runs that hook, sends what `botd` expects, waits for the answer and honours a block was only checked by hand, and for Hermes against a stub CLI (`server/tests/hermes_e2e.rs`). A CLI release that renames a flag, changes the hook payload or stops running hooks in non-interactive mode would pass CI. The unguarded-run canary stops such a run, but only after its first shell command.

The full path needs a model to decide to call a tool. CI has no paid harness logins, and real models aren't deterministic.

## Decision

### One test, a fake model, the real everything else

`server/tests/harness_e2e.rs` starts the real `botd` (which runs the real `botctl hook`) with one harness as the default, and drives it over the HTTP API like a person would. For each harness, four calls in one Bot's session (each later prompt resumes it):

- **Allowed**: `touch <marker>` matches no class or rule. It runs, without an approval, and the run isn't stopped as unguarded (so the hook ran).
- **Blocked by policy**: a deny rule (`*e2e-forbidden*`) matches. The command never runs, no approval is made, `policy.denied` names the harness, and the agent is told why.
- **Needs approval, approved**: `git -C <repo> push origin HEAD:refs/heads/e2e-approved` to a bare repo in the test folder. One `git_push` approval appears with the harness's name; once approved, the branch is on the remote.
- **Needs approval, denied**: the same with another branch. Once denied, the branch isn't there and the agent is told it was denied.

The model is a fake HTTP server in the test (`FakeModel`), reached through each CLI's own custom-endpoint setting, the same one an operator uses for a self-hosted model:

| Harness | Setting | Wire format |
|---|---|---|
| Claude Code | `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY` | Anthropic Messages, streamed |
| Codex | a `model_providers` entry in `~/.codex/config.toml` | OpenAI Responses, streamed |
| Pi | a provider in `~/.pi/agent/models.json` | OpenAI Chat Completions, streamed |
| Hermes Agent | `SUPERBOT_HERMES_PROVIDER=custom`, `SUPERBOT_HERMES_BASE_URL` (botd's existing settings) | OpenAI Chat Completions, streamed or not |

It is stateless. Each request carries the whole conversation, so it finds the newest prompt's command (`E2E-RUN<<cmd>>`), calls the CLI's shell tool with it (picked by name from the tools the CLI offers, with the argument its schema names), and once that tool's result comes back, replies `E2E-DONE <result>`. Requests without tools (titles, summaries) get plain text. Everything between the model and the shell is the real CLI: its hook config parsing, its hook invocation, its payload, how it waits, and what it does with a block.

The tests are `#[ignore]`d, so `cargo test` stays as it was; a small unit test of the fake model's parsing runs there.

### A separate, gated workflow

`.github/workflows/harness-e2e.yml` runs on pull requests and pushes to main that touch the adapters, approvals, the policy and shell parser, the runner, `botctl`, `main.rs`, the test, its scripts or `Cargo.lock`; weekly; and by hand. Two jobs run in parallel: Claude Code, Codex and Pi (npm, seconds to install) and Hermes Agent (its installer, about 2.7 GB and a minute or two). With a fake model each harness takes seconds; Hermes takes about 40 because each Bot's Hermes builds its runtime on first use, from the installer's uv cache. `SUPERBOT_E2E_REQUIRE=1` makes a missing CLI a failure instead of a skip.

The sandbox (ADR 0055) is off in these runs. It is another layer, it depends on the host's user namespaces (GitHub's Ubuntu 24.04 restricts them), and the pushes go to a folder outside the workspace.

### Pinned to what machines install

The CLIs come from `deploy/install-harness-clis.sh`, which reads the versions from `server/src/adapters/install.rs`, the pins machines already install from (ADR 0039): npm packages checked against the pinned integrity, Hermes's installer at the pinned commit checked against the pinned SHA-256. There is one place to change a version, and CI tests exactly that.

**Bumping a harness**: change its `version` and `integrity` (npm: `npm view <package>@<version> dist.integrity`), or Hermes's commit and the installer's `sha256`, in `install.rs`, plus `HERMES_COMMIT` in the `Dockerfile` and `deploy/install.sh` for Hermes. The `harness-e2e` workflow runs on that change; merge when it's green. To try a version first: `HARNESS_VERSION_CODEX=0.172.0 deploy/install-harness-clis.sh /tmp/clis codex`, then the test with that on `PATH`.

### The oldest Codex that runs hooks in `codex exec`: 0.141.0

Running the test against older releases: 0.141.0 is the first that runs the hook the way the adapter starts Codex. 0.132 to 0.140 accept `features.hooks` and `--dangerously-bypass-hook-trust` but never run the hook, so the canary stops the run after the first command; older releases refuse the flags. CI runs the Codex test a second time at 0.141.0 (`CODEX_MIN_HOOKS`), so a change to the adapter that needs a newer Codex shows up.

### Real models: a manual script

`deploy/harness-e2e.sh` runs the same test with `SUPERBOT_E2E_MODEL=real` on a server where the harnesses are logged in. It builds the test in release mode and starts a throwaway `botd` with its own temp data on a free loopback port, never the running service. botd gets the operator's `HOME` (for the logins) and only harness and provider variables (`ANTHROPIC_*`, `OPENAI_*`, `CODEX_*`, `PI_*`, `HERMES_*`, `SUPERBOT_HERMES_*`, `OPENROUTER_*`, …), plus any named with `--pass-env`; `--env-file` reads a server's `.env` as literal lines for those. The prompt asks the model to run the exact command once and not work around a block. The checks are the same, minus the fake model's reply text, and it ends with a pass/fail line per harness and a non-zero exit on any failure. `--fake` runs the CI variant on any machine with the CLIs.

## Consequences

- A harness release that stops running SuperBot's hook, changes its payload or ignores a block fails CI before the pin is bumped, for all four harnesses.
- The fake model covers what a CLI does with a model's tool call, not whether a real model makes it. The manual script covers that, by hand, on a logged-in server.
- The fake model speaks a subset of three APIs. A CLI that starts relying on more (a new required event or field) fails the test until the fake learns it; the failure says the run ended with an error, and the botd log is printed.
- Codex older than 0.141.0 still starts, and its first command runs before the canary stops it. Refusing guarded runs on older Codex up front is left for later; machines install the pinned version.
- `hermes_e2e.rs` stays: it checks what the real Hermes can't show cheaply (no secret reaches the harness or `hermes gateway stop`, the managed config, the daemon stopped after a run).

## Alternatives considered

- **A cheap real key in CI.** Costs money per run, needs a secret that pull requests from forks can't have, and real models are nondeterministic, so the tests would flake.
- **Replaying recorded model traffic.** Recordings break whenever a CLI changes its prompts or request shape; reading each request for the command and the result is as simple and doesn't go stale.
- **Calling each CLI's hook with a hand-made payload.** Tests `botctl`, not whether the CLI runs the hook, which is the part that breaks.
- **Running in the main `server` workflow.** Every server change would install four CLIs and Hermes's 2.7 GB; the path filter keeps it to changes that can affect the hook path.
