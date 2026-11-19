# 0007: Approvals and harness permission policy

## Status

Accepted

## Context

Every adapter ran its harness with permission prompts off (`--dangerously-skip-permissions` and equivalents). A Bot could push to git, delete files outside its workspace, send email, or pipe an install script into a shell with no one looking. Bots run headless, so the harnesses' own interactive prompts are no use: there is no terminal to answer them. We want risky tool calls to pause for a person, while everything else stays autonomous, on all three harnesses, without harness code leaking out of the adapters.

## Decision

**One policy engine in `botd`, one gate binary, one hook per harness.**

- **Policy** (`server/src/policy.rs`): a mode (`ask` or `bypass`), an action (`allow`, `ask`, `deny`) per risky class, and a timeout. Classes: destructive shell (`rm -rf /`, `git reset --hard`, `dd`, `DROP TABLE`, ...), file deletion outside the workspace, outbound email or messages (mail CLIs, `gh pr create`, Slack webhooks, messaging MCP tools), network installs (`apt`, `npm i`, `curl | sh`), and `git push`. Shell commands go through a real shell parser (`server/src/shell.rs`) that finds every command, including those inside quotes, substitutions, and here-documents. Classification errs towards asking, and a command the parser can't read for certain is denied outright (fail closed). Input size, nesting, and command count are bounded. Rules on top: `deny` rules (the deny list) beat everything; `allow` rules (usually "remember this") skip asking but never override a class set to `deny`.
- **Scope**: one global policy plus optional per-Bot overrides, in SQLite. A versioned migration (`PRAGMA user_version`) adds the tables. Fresh installs start in `ask`. Existing installs start in `bypass`, so an upgrade changes nothing until the owner opts in.
- **Gate**: `botctl hook <harness>` reads the harness's PreToolUse event on stdin and posts it to `POST /api/approvals/check`. botd answers at once (allow or deny), or creates a pending approval and holds the request open until a person decides, the timeout passes, or the run stops. botctl exits 0 to allow and 2 (reason on stderr) to block.
- **Harness hooks** (adapter code only):
  - **Claude Code**: a `PreToolUse` command hook passed with `--settings`. Hook denials hold even with `--dangerously-skip-permissions`, and flag settings outrank project files, so a workspace can't switch the hook off.
  - **Codex**: the same hook format via `-c hooks.PreToolUse=...` and `features.hooks=true`, with `--dangerously-bypass-hook-trust` since we generate the hook ourselves. Codex's hosted tools (web search) don't run hooks.
  - **Pi**: no hook config, only TypeScript extensions. The adapter writes a 30-line extension that runs the same `botctl hook pi` on `tool_call` and blocks on any non-zero exit.
- **Fail closed**: a crashed gate, unreachable server, bad reply, or unknown Bot all block. The harness hook timeout is longer than the server's own wait, so a slow answer is a deny, never a timeout (which harnesses treat as "allow"). If a guarded run shows a shell tool call but no hook check reached botd within 5 seconds, the run is stopped as unguarded: that catches a harness version that ignores hooks.
- **Policy changes mid-run**: bypass runs have no hook, so switching a Bot to `ask` stops its current task. A guarded run that switches to `bypass` keeps its hook, which then allows everything.
- **Queue and audit**: pending approvals live in SQLite, are pushed to clients over SSE (`approval` events), and are expired on restart. The first decision wins. Every request, decision, timeout, rule change, and policy change goes into `audit_events`, which triggers make append-only.
- **Who can decide**: Bots hold a bearer token so `botctl` works; people log in with `AUTH_PASSWORD`. The auth layer tags each request, and deciding, listing approvals, reading the audit log, and changing policy or rules all refuse the Bot token (403). `AUTH_PASSWORD` is removed from the harness environment.

## Alternatives considered

- **MCP `--permission-prompt-tool` (Claude only)**: only fires when Claude would prompt, which `--dangerously-skip-permissions` disables. It's also Claude-specific.
- **Codex approval modes (`-a on-request`) and sandboxing**: these decide by Codex's notion of risk, not ours, and `exec` has no one to ask. They're kept as defense in depth later, not as the gate.
- **An HTTP hook type**: Claude has one, but Codex and Pi don't. A command hook works on all three and keeps a single code path.
- **Running harnesses in a sandbox**: needed eventually (see below), but it's a different layer. Approvals cover actions that are risky even inside a sandbox, like pushing or emailing.

## Consequences

- Risky calls block the run until answered (default 10 minutes, then denied). The Bot sees a plain reason and is told to ask the user, not to work around it.
- Shell classification sees commands, not what they do inside. Commands built at run time (`$CMD`, `eval "$X"`) ask; scripts and programs that delete or send things internally can slip through. This is a guard rail for honest mistakes and prompt injection, not a sandbox.
- Bots run as the same OS user as `botd`, so a determined Bot could read `.env` or the database. Separating them needs a different OS user per harness (follow-up).
- `ALLOW_NO_AUTH=1` (loopback dev) treats unauthenticated callers as a person, so any local process can approve. Dev only.
- Codex hooks rely on a newer Codex; the canary stops guarded runs on versions that skip them.
