# 0011: Hermes Agent as a back end

## Status

Accepted (19 Nov 2026). The product owner, David Kennedy, accepted it on 19 Nov 2026: Hermes Agent is the default harness for managed tiers and the harness that carries the Enterprise SLA; Claude Code and other harnesses stay available as best-effort. The gate below becomes the release checklist for managed tiers. Details: [ADR 0027](0027-expo-primary-hermes-default.md). Option (a), the adapter, is built ([ADR 0015](0015-hermes-adapter.md)). The gate's status is under [Recommendation](#recommendation); per-Bot footprint measured in [ADR 0070](0070-hermes-per-bot-footprint.md).

Was: Proposed (19 Nov 2026), as an assessment for the owner.

ADR 0010 is taken by the secrets store (PR #9, in review), so this is 0011.

## Context

The owner wants SuperBot's back end run by [Hermes Agent](https://github.com/NousResearch/hermes-agent) (Nous Research). Today `botd` is one Rust binary that queues work, owns memory, routines, Bot-to-Bot, approvals, and audit, and drives harness CLIs (Claude Code, Codex, Pi) through one small adapter each ([ADR 0001](0001-backend.md), [ADR 0007](0007-approvals.md), [ADR 0009](0009-audit-events.md)).

Other decisions from the same day shape the answer: one computer (VM or container) per **user** ([roadmap](../ROADMAP.md#decisions-19-nov-2026)), per-user pricing tiers with models hidden behind tiers, and the Linode API for managed machines.

## What Hermes is

Read from the repo and its docs at release v0.23.2 (16 Nov 2026).

- **Licence**: MIT (Nous Research, 2025), same as SuperBot. Direct Python dependencies are pinned to exact versions.
- **Shape**: a full personal agent product, not just a CLI. About 1.1 million lines of Python (3.14 only), plus a TypeScript TUI, an Electron desktop app, and a web dashboard. `botd` is about 7,700 lines of Rust. Very active: daily canary releases, a stable release roughly weekly, and about 54,000 open issues and pull requests.
- **Trust model**: its `SECURITY.md` says "Hermes Agent is a single-tenant personal agent", and that the only real boundary against a hostile model is the OS (a container or VM). Its approval gate and redaction are heuristics, not containment.
- **Agent loop**: its own loop (`AIAgent`), with about 70 tools in 28 toolsets: terminal, files, browser, web, vision, code execution, delegation to subagents, MCP. The terminal can run locally or in Docker, SSH, Modal, Daytona, or Vercel Sandbox. Computer use is a tool.
- **Model providers**: dozens built in (OpenRouter, Anthropic, OpenAI, Gemini, Bedrock, Azure Foundry, Ollama, any OpenAI-compatible endpoint, Nous Portal, ...). Fallback providers and per-session model overrides are supported. Not tied to one vendor.
- **Memory**: `MEMORY.md` (agent notes) and `USER.md` (user profile), small and character-capped, loaded as a frozen snapshot when a session starts. The agent edits them with a `memory` tool. It also has full-text search over past sessions, self-written "skills" (its learning loop), and optional external memory providers. Writes can require approval (`write_approval`).
- **Scheduling**: built-in cron. The gateway daemon ticks every 60 seconds and runs each due job in a fresh session, with delivery to chat platforms.
- **Isolation unit**: a **profile** (its own `HERMES_HOME`: config, keys, memory, sessions, skills, cron, and gateway process). Its docs warn never to point two agents at one profile. "Bot Mode" in its desktop app is a roster of profiles, each with routines and Bot-to-Bot messages: close to SuperBot's own product.
- **Ways to drive it**:
  - One-shot CLI: `hermes chat --oneshot --query-file - --format stream-json` writes JSON lines (`system`, `text` deltas, `tool_use`, `tool_result`, `result` with session id, tokens, and exit code). `--resume <id>`, `-m`, `--provider`, `--source tool`, `--max-turns`. System prompt can be added per call with `HERMES_EPHEMERAL_SYSTEM_PROMPT`.
  - OpenAI-compatible HTTP API server: `/v1/chat/completions`, `/v1/responses`, and `/v1/runs` with SSE events, an approval endpoint, steer, and stop. Bearer key auth.
  - JSON-RPC over stdio or WebSocket (the TUI gateway) and ACP for editors.
  - Messaging gateway: Telegram, Slack, Discord, WhatsApp, Signal, Teams, email, and about 20 more.
- **Hooks and approvals**: shell hooks in `config.yaml`. A `pre_tool_call` hook gets JSON on stdin (`tool_name`, `tool_input`, `session_id`, `cwd`) and blocks by exiting 2, the same contract as Claude Code. `fail_closed: true` turns crashes, timeouts, and bad output into blocks. Hook timeout is capped at 300 seconds. Hooks need one-time consent; headless runs use `HERMES_ACCEPT_HOOKS=1` or an allowlist file. Its own approval gate has `smart`, `manual`, and `off` modes; one-shot runs deny dangerous commands by default.

## Options

### (a) Hermes as one more harness adapter

`server/src/adapters/hermes.rs` next to Claude Code, Codex, and Pi. botd stays in charge of everything else.

- **Fit**
  - **Adapters**: good. The stream-json events map one-to-one onto `AgentEvent` (session, text delta, text, tool, error), and `--resume` gives harness sessions. Each Bot gets its own `HERMES_HOME` under its `state_dir`, which is exactly what Hermes asks for.
  - **Approvals and policy**: good, with work. The adapter writes a `pre_tool_call` hook running `botctl hook hermes` with `fail_closed: true`, and sets `HERMES_ACCEPT_HOOKS=1`. `botctl hook` already exits 2 to block. Three gaps:
    - The policy must learn Hermes tool names: `terminal` is not in `SHELL_TOOLS`, and `write_file` and `patch` are file tools.
    - The 300-second hook cap is shorter than botd's 10-minute approval wait, so Hermes Bots need a shorter wait or the hook fails closed early.
    - The unguarded-run canary in `runner.rs` only starts on tool events named `bash` or `shell`, so it would miss a Hermes version that skips hooks. It must also watch `terminal`, and the adapter needs a test that a run with a skipped hook is stopped.
  - **Audit**: unchanged. Every gated call already goes through `/api/approvals/check`.
  - **Routines and Bot-to-Bot**: unchanged. Bots keep using `botctl`. Hermes's own cron stays off.
  - **Memory**: overlap. botd sends memory in the system prompt; Hermes also loads its own `MEMORY.md` and `USER.md` and learns skills. Either turn Hermes memory off for SuperBot Bots, or let it run and treat it as harness-private (like Claude Code's own files). Decide in the adapter PR.
- **Effort**: **M**. One adapter file (similar to the existing 90 to 100 lines), Hermes tool names in `policy.rs` and the unguarded-run canary, `botctl hook hermes`, the model list, Python 3.14 and Hermes in the installer and Docker image, and the end-to-end hook test from the [approvals follow-ups](../approvals-followups.md).
- **Risks**: upstream churn breaks the stream format or hook contract (pin a stable release, test on upgrade); memory and CPU of a Python agent per Bot on a 4 GB machine (measure); Hermes may start a gateway runtime per profile; a second, overlapping memory system.
- **Licence**: MIT, run as a separate program. No obligations beyond keeping its notice if we ship it in our image.

### (b) Hermes as the primary harness and default engine

Same adapter as (a), but Hermes becomes the default harness for new Bots and the engine behind managed tiers. Claude Code, Codex, and Pi stay as options.

- **Fit**
  - Same as (a) for adapters, approvals, audit, routines, and memory.
  - **Model routing hidden behind tiers**: strong fit. Hermes speaks to many providers and any OpenAI-compatible endpoint, so botd can map a tier to a provider and model per run without the user seeing it. Claude Code and Codex tie each run to one vendor and that vendor's account terms.
  - **Per-user computers**: strong fit. Hermes is single-tenant by design and expects the OS to be the boundary; one VM per user gives it exactly that.
- **Effort**: **L**. On top of (a): Hermes on by default in the installer, Compose image, and managed images; a tier-to-model routing table and provider keys held by the control plane; a supported-version policy (stable tags only, never canary); upgrade tests; docs and support matrix.
- **Risks**: everything in (a), plus we depend on one fast-moving upstream for most runs. Behaviour drift (prompts, tools, the learning loop rewriting skills) shows up as SuperBot bugs. Python supply chain in every user's machine. Support burden for a large codebase we don't own.
- **Licence**: MIT. Fine for managed and self-host, including commercial tiers. Nous Portal is a separate paid service; we don't need it.

### (c) Replace botd's orchestration with Hermes

Hermes's gateway, cron, memory, Bot Mode, and approvals become the back end. botd shrinks to a login, billing, and provisioning shell, or goes away.

- **Fit**
  - **Adapters**: poor. Harness choice becomes Hermes's choice; Claude Code and Codex would only be reachable through Hermes's own integrations. This drops "harness agnostic" ([AGENTS.md](../../AGENTS.md)).
  - **Approvals and policy**: poor. We lose the fail-closed gate, shell parser, policy classes, and rules from ADR 0007 and fall back to Hermes's pattern list and `smart` mode, which its own security policy calls a heuristic.
  - **Audit**: poor. ADR 0009's append-only table and CSV export would have to be rebuilt from Hermes hooks and webhooks.
  - **Routines and memory**: Hermes has its own (cron, profiles, Bot Mode), so we would migrate users' Bots, routines, and memory into them.
  - **Multi-user and SSO (M2)**: no help. Hermes is single-tenant; users, roles, and tenants still have to be built around it.
- **Effort**: **XL**. A rewrite of the product around a large Python codebase, plus data migration for existing installs.
- **Risks**: SuperBot becomes a UI and hosting layer over someone else's product, one that already ships its own desktop app, Bot Mode, and hosted offering. It breaks the Rust-first rule. Our roadmap would follow upstream's.
- **Licence**: MIT. Legally fine; the problem is product and architecture, not licence.

## Recommendation

**Do (a) now, plan for (b) behind a gate, and don't do (c).**

1. Build the Hermes adapter (a) in M2, alongside multi-user work. It is a contained change that keeps botd's approvals, audit, routines, and memory in charge.
2. Make Hermes the default engine (b) in M3, for managed tiers first, only when it passes this gate:
   - the end-to-end approval test passes on the pinned stable version, including fail-closed on hook timeout and the canary stopping a run whose hook was skipped;
   - per-Bot memory and CPU on the smallest managed machine are measured and acceptable;
   - one upstream upgrade has been taken through the test suite without adapter changes, or with small ones;
   - tier-to-model routing works with at least two providers.

   **Gate status (21 Nov 2026): not passed**, so Hermes is not the managed default yet ([ADR 0070](0070-hermes-per-bot-footprint.md), [#33](https://github.com/CG-Labs/superbot/issues/33)).
   - Approvals end to end: **mostly passes.** The canary stops a run whose hook was skipped, against the real Hermes ([ADR 0057](0057-harness-hook-e2e-tests.md), [ADR 0063](0063-canary-covers-every-hooked-tool.md)). Fail-closed on hook timeout is configured and checked in the managed config, but no test makes the real Hermes time a hook out.
   - Footprint: **measured; passes with conditions** ([ADR 0070](0070-hermes-per-bot-footprint.md)). About 330–370 MiB PSS and 5 CPU-seconds per run, nothing while idle, 487 MiB of disk per Bot, a 2.6 GiB install. A Starter (1 vCPU, 2 GiB) fits 4 runs at once for its 3 Bots. Conditions: share one dependency environment across Bots, and cap concurrent runs per machine by tier.
   - Upstream upgrade: **not done.** The pin hasn't moved since it was set.
   - Two providers: **built, not shown.** Tier routes pass a provider to Hermes ([ADR 0033](0033-tiers-model-routing.md)); no run has gone through two real providers yet.
3. Reject (c). It throws away the approval, audit, and multi-user work, and the harness-agnostic, Rust-first design, for features botd already has.

## Consequences

- If accepted: a new adapter, `policy.rs` and the unguarded-run canary learn Hermes tool names, the installer and Docker image gain Python 3.14 and a pinned Hermes, and the roadmap tracks (a) in M2 and the (b) gate in M3.
- Hermes's own approval gate, cron, messaging gateway, and Bot Mode stay unused in SuperBot. botd remains the single place for policy, audit, routines, and Bot-to-Bot.
- Open: whether Hermes's memory and skill learning run for SuperBot Bots; the shorter approval wait for Hermes Bots. Hermes's footprint per Bot on small machines is measured in [ADR 0070](0070-hermes-per-bot-footprint.md).

## Sources

- Repo, README, `LICENSE`, `SECURITY.md`, `pyproject.toml`: <https://github.com/NousResearch/hermes-agent>
- Docs: <https://hermes-agent.nousresearch.com/docs/>, especially Architecture, Programmatic Integration, CLI Reference (`hermes chat`, `--format stream-json`), Event Hooks (shell hooks), Security, Memory, Cron, Profiles, and AI Providers.
