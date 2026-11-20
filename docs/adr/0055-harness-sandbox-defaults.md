# 0055: Harness sandboxes on by default

## Status

Accepted (20 Nov 2026). Approvals follow-up 9 ([list](../approvals-followups.md), tracking issue [#13](https://github.com/CG-Labs/superbot/issues/13), M1). It builds on [ADR 0007](0007-approvals.md) (approvals and the policy), [ADR 0009](0009-audit-events.md) (audit events), [ADR 0036](0036-bots-on-the-users-machine.md) (Bots on the user's machine), [ADR 0037](0037-per-user-unix-accounts.md) (per-user accounts), [ADR 0043](0043-bots-own-os-user-on-machines.md) and [ADR 0048](0048-teammates-own-os-user-on-machines.md) (OS users on machines), [ADR 0046](0046-shared-bots-under-isolation.md) (isolated shared Bots), and [ADR 0049](0049-policy-editor-in-the-apps.md) (the policy editor).

## Context

Approvals check what a Bot asks to do. They read commands, not what a script or program does once it runs, so a `python build.py` that deletes `~/.ssh` gets through. Every harness ran with its own guards off: Codex with `--dangerously-bypass-approvals-and-sandbox`, Claude Code with `--dangerously-skip-permissions`, Hermes Agent with `--yolo`. Two harnesses have a sandbox that limits what commands can touch, whatever they are. We wanted that on, as a second layer, without breaking what Bots normally do.

What each harness has (Codex checked on 0.171; the others from their current docs):

- **Codex**: `sandbox_mode = "workspace-write"`. Commands write only in the working folder, `/tmp`, `$TMPDIR`, and `sandbox_workspace_write.writable_roots`; `.git`, `.codex` and `.agents` at a writable root's top stay read-only. The network is off unless `sandbox_workspace_write.network_access = true`. Linux uses bubblewrap with user namespaces (bundled), macOS Seatbelt. `codex exec resume` has no `--sandbox` flag, so we set it as `-c` config. With no user namespaces, every command fails ("bwrap: … namespace …"). A writable root that doesn't exist also fails every command.
- **Claude Code**: `sandbox` settings (`enabled`, `filesystem.allowWrite`, `network.allowedDomains`, `allowUnsandboxedCommands`). It sandboxes Bash only: file tools, hooks and MCP servers run outside it. Commands get their own network and reach out through a local proxy set in `HTTP_PROXY`. With permissions skipped, the proxy lets through any host except local addresses it isn't told about. Linux needs bubblewrap and socat. If the sandbox can't start, it runs commands without it.
- **Pi**: no sandbox and no permission system; its docs say to run it in a container. Its example sandbox is an extension, not a setting.
- **Hermes Agent**: `terminal.backend` runs commands locally (no isolation) or in Docker, over SSH, or on hosted sandboxes. Those move the work off the Bot's folders and logins, and need a daemon or an account; none is a drop-in setting.

## Decision

### A policy setting, separate from the mode

The policy gets `sandbox: bool`, globally and per Bot like every other field (`null` on a Bot follows the global value). It holds in `bypass` too: bypass is about asking, the sandbox about reach. `PUT /api/policy` and `PUT /api/bots/{id}/policy` take it; `botctl policy set <global|bot> sandbox=on|off|inherit` sends it. Changes are `policy.updated` with before and after, like other policy changes. A change applies from the next run.

`GET /api/policy` and a Bot's policy add `sandbox: { harnesses, available }`: which harnesses have one (`claude`, `codex`), and whether it can start on this server.

### New installs on, existing installs off

A new install's policy has the sandbox on. An install from before keeps it off: migration 24 sets `sandbox: false` in the saved policy and records `policy.sandbox_initialized` (system, `migration`), and existing Bots follow it unless an admin sets their own. This mirrors approvals (ADR 0007): an upgrade doesn't change how running Bots behave, and the startup log says how to opt in. A policy JSON without the field reads as off, for the same reason.

### What each harness gets

- **Codex**: `-c sandbox_mode="workspace-write" -c approval_policy="never" -c sandbox_workspace_write.network_access=true`, plus `writable_roots`, instead of the bypass flag. `never`: a blocked command fails and the model sees why; SuperBot's hook stays the approval gate. Network on: Bots install packages, call APIs, and reach botd for `botctl`.
- **Claude Code**: its `sandbox` settings, merged into the `--settings` that already carry the approval hook: `enabled`, `allowUnsandboxedCommands: false` (no way out for a command), `filesystem.allowWrite` as below, and `network.allowedDomains` with botd's API `host:port` so the proxy lets `botctl` through. Other hosts stay reachable, as permissions are skipped. `--dangerously-skip-permissions` stays: approvals are our hook, not Claude Code's prompts.
- **Pi, Hermes Agent**: nothing, documented. `harness.invoked` records `unsupported` so it's visible.

### Where a sandboxed run writes

Both harnesses already allow the working folder and the temp folders. We add, per run:

- **The memory and facts files' folders**, so Bots can keep editing `MEMORY.md` and `USER.md`: `DATA_DIR/bots/<id>` and `DATA_DIR/users/<owner>` here; `ISOLATION_DIR/<owner>/memory` with per-user accounts (ADR 0037); `bots/<id>` on a machine (ADR 0036). Never HOME itself: on a machine `USER.md` sits in HOME, so it stays read-only there. A run for someone other than the owner (ADR 0046) doesn't get the owner's facts folder. Here each folder must exist (Codex refuses one that doesn't); on a machine the job makes the memory folder.
- **Package caches under the run's HOME that exist**: `~/.cache`, `~/.npm`, `~/.cargo/registry`, `~/.cargo/git`, `~/go/pkg/mod`, Bun, Yarn, Gradle and Maven caches. Without them `npm install` and `cargo build` fail, as HOME is read-only. Not followed through links, and never folders holding programs or settings (`~/.local`, `~/.cargo/bin`, `~/.config`): a Bot that could change those changes what runs outside its sandbox later. HOME is botd's here, the account's with per-user accounts, and the machine user's on a machine. The machine agent lists its own (`Layout.caches`); botd keeps only paths under that HOME, and none for a teammate's own user (ADR 0048), whose home is another.

Harness logins (`~/.claude`, `~/.codex`) stay read-only to commands. The harness process itself runs outside its sandbox, so it still reads and refreshes them.

### `botctl` inside Claude Code's sandbox

Sandboxed commands in Claude Code can't open a socket to `127.0.0.1`. `botctl` tries the direct connection first; when that fails with a Bot's credentials, it retries through `HTTP_PROXY` (absolute-form request, `Proxy-Authorization` from the URL). Only a proxy on this machine (loopback) gets `BOT_TOKEN`, since this is plain http; an operator's credentials never take a proxy. Checked against Anthropic's sandbox runtime: through with botd's address listed, refused without.

### Where sandboxes can't start

botd checks once at start whether user namespaces work (`bwrap`, or `unshare` when bwrap isn't installed); machines check for themselves and send it with each run (`Layout.sandbox`; an older agent counts as able). When they can't, the run goes without and `harness.invoked` records `unavailable`, botd prints a warning at start, and the policy editors say so. A Codex run whose sandbox fails anyway gets one clear error naming bubblewrap and the per-Bot switch, instead of a run of failed commands. The installer adds `bubblewrap` and `socat`.

### Audit

`harness.invoked` gets `sandbox`: `on`, `off`, `unsupported`, or `unavailable`. `server.started` records the global setting and whether sandboxes can start.

### The editors

The client's policy editor gets a Sandbox card (On / Off, and Default on a Bot), asking before turning it off. The console's Settings gets a select for all Bots. Both warn when sandboxes can't start on the server.

## Consequences

- A Bot's commands can't change its harness logins, the host's dotfiles, other users' folders, or `DATA_DIR` outside its own memory, even when approvals miss something (Codex, Claude Code).
- Writes outside the workspace now fail unless an admin turns the sandbox off for that Bot. A Codex Bot can't commit in a repo whose `.git` is at the workspace's top; repos in folders inside it are fine.
- Docker's default seccomp blocks user namespaces, so Compose installs run without, and say so. Ubuntu 24.04 limits them with AppArmor unless bubblewrap has a profile.
- Claude Code's sandbox covers Bash only: its file tools can still write outside the workspace, so approvals still matter there.
- Pi and Hermes Agent Bots get no sandbox. Running them in a container is the follow-up, with per-user containers (#29).
