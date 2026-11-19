# 0013: Hermes Agent adapter details

## Status

Accepted (19 Nov 2026). Implements [ADR 0011](0011-hermes-agent-backend.md) option (a) for Hermes Agent v0.23.2. ADR 0012 is users and sessions, so this is 0013.

## Context

ADR 0011 said to add Hermes as one more adapter and left some details to the adapter PR. Running the real CLI showed more that ADR 0011 didn't cover:

- `hermes chat` is a client. The turn runs in a gateway daemon that Hermes starts once per data root and that outlives the client. Killing the client doesn't stop the turn, and a running daemon keeps the env of the client that started it.
- Hermes runs hooks in the daemon's folder (its install), not the Bot's workspace, and says so in the hook's `cwd`.
- In one-shot mode Hermes's own guard blocks commands like `rm -rf` even after SuperBot's hook allowed them.
- A new data root outside `~/.hermes/profiles/` prepares its own dependencies on first use: about 20 seconds and 0.5 GB.

## Decision

- **One data root per Bot**: `HERMES_HOME=DATA_DIR/bots/<id>/hermes`, as ADR 0011 planned. Hermes profiles under one root would be smaller, but they share one daemon, so Bots would share env (including `BOT_ID` and the Bot's token), and stopping one Bot would stop the others' turns. We take the disk cost.
- **Stop the daemon around every run**: `hermes gateway stop --yes` for the Bot's data root before and after each run (only when its `gateway.pid` exists, at most 60 seconds). Stop, timeout, and the unguarded-run canary then really end the turn, and every run starts with fresh env. Without `--yes` Hermes refuses while a session is live.
- **SuperBot's settings in Hermes's managed scope**: `HERMES_MANAGED_DIR=DATA_DIR/bots/<id>/hermes-managed`, rewritten (0600) every run. Hermes merges it over the Bot's own config, and the agent can't change it with `hermes config set`. It holds:
  - the `pre_tool_call` hook (`fail_closed: true`), accepted with `HERMES_ACCEPT_HOOKS=1`;
  - `terminal.env_passthrough`: the names of the variables botd sets for the run, so tools see `BOT_TOKEN` and saved secrets (names only, never values);
  - Hermes memory and user profile off, and its `cronjob` toolset off. This answers ADR 0011's open question: botd owns memory and routines.
- **The hook names the Bot's folder**: `botctl hook hermes --cwd <workspace>` overrides the hook's `cwd`, so relative paths are checked from where the command really runs. A `terminal` call's `workdir` counts as a `cd`.
- **`--yolo`**: Hermes's own approval prompt is off, like `--dangerously-skip-permissions` for Claude Code. SuperBot's hook still gates every tool (tested with the real CLI).
- **Shorter approval wait**: adapters can declare a hook time limit. Hermes stops hooks after 300 seconds, so a Hermes Bot's approval waits at most 240 seconds, then expires (denied), and the hook timeout stays a minute above that.
- **Provider settings outside the Bot**: optional `SUPERBOT_HERMES_PROVIDER` and `SUPERBOT_HERMES_BASE_URL` in botd's env become `--provider` and `--base-url`. Keys stay in the secret store or env, never in a Hermes config file. The model is free text: Hermes has no command that lists models without a prompt.
- **Opt-in install, pinned**: `install.sh --with-hermes` and `HARNESSES="... hermes"` run Hermes's own installer at a pinned commit (v0.23.2), as the user that runs botd, because Hermes refuses a checkout another user owns. Docker installs to `/opt/hermes`, outside the home volume. The bash installer puts `~/.local/bin` on botd's PATH in `.env` instead of linking a user-writable launcher into a root-owned folder.
- **Adapter interface**: adapters can now set env, write the prompt to stdin, clean up before and after a run, and declare a hook time limit. An adapter that reports an error while setting up (for example, it couldn't write the hook config) doesn't run.

## Consequences

- Each Hermes Bot costs about 0.5 GB of disk, and 20 seconds on its first run.
- A turn's daemon stops when the run ends, so Hermes's own background jobs and messaging gateway never run for SuperBot Bots.
- Hermes Bots can't wait more than 4 minutes for an approval.
- `execute_code` runs Python. The hook sees the tools a script calls, not the script's own system calls, the same limit as `python3 script.py` on other harnesses.

Not verified, so left configurable or documented: the provider flags beyond an OpenAI-compatible endpoint (only that was run end to end), how Hermes's own installer behaves when re-run at a new commit, and per-Bot memory and CPU on a small machine (ADR 0011's gate for making Hermes the default).
