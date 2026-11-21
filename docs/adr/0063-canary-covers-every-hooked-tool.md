# 0063: The unguarded-run canary covers every tool each harness hooks

## Status

Accepted (21 Nov 2026). Approvals follow-up 10 ([list](../approvals-followups.md), tracking issue [#13](https://github.com/CG-Labs/superbot/issues/13), M1). It builds on [ADR 0007](0007-approvals.md) (approvals, the hooks and the canary), [ADR 0057](0057-harness-hook-e2e-tests.md) (hook tests against the real CLIs) and [ADR 0059](0059-refusing-guarded-runs-on-old-codex.md) (old Codex refused up front).

## Context

botd counts every hook call in a run. The canary stops a guarded run whose harness runs a tool without ever calling the hook: that harness isn't enforcing approvals. It started only on the shell tool (`Bash`, `shell`, `bash`, Hermes's `terminal`), so a run whose hook was broken and that only wrote files, called MCP tools or delegated to a subagent ran unchecked and was never stopped.

The follow-up said to extend it "once each harness reports hook calls reliably". We checked that against the real CLIs, at the pinned versions, with the fake model from ADR 0057 calling each tool the CLI offers, a deny rule on a marker in the arguments, and botd's audit log showing whether the hook sent the call:

| Harness | Tools that reached the hook | Not reached |
|---|---|---|
| Claude Code 2.1.329 | `Read`, `Write`, `ToolSearch`, `Agent` (the `*` matcher) | calls it rejects first: `Edit` of a file not read yet or missing, `Skill` with an unknown name |
| Codex 0.171.0 and 0.141.0 | `apply_patch`, MCP tools, `view_image`, `request_user_input`; `update_plan` on 0.141.0 (0.171.0 doesn't offer it to the fake model) | hosted tools (`web_search`), by design |
| Pi 1.5.2 | `read`, `write`, `edit` (the extension's `tool_call` handler) | none found |
| Hermes Agent (pinned commit) | `read_file`, `write_file`, `patch`, `search_files`, `execute_code`, `clarify`, `delegate_task`, `skill_view`, `skill_manage`, `web_search`, `web_extract`, `browser_exec`, `tool_search`, `tool_describe`, `tool_call` | `skills_list` untested (the run timed out starting Hermes's gateway) |

So the hunch held, with two catches. First, a harness checks a call's arguments before its hook: Claude Code refuses an `Edit` of a file it hasn't read without calling the hook, and models do that often. A canary that started on any tool call would stop healthy runs. Second, a harness only shows the canary the tools its JSON output reports. `codex exec --json` has items for commands, `apply_patch` (`file_change`), MCP calls, plans, web searches and subagents, but none for `view_image` or `request_user_input`.

## Decision

### Count calls that ran, not calls that started

Adapters now report `ToolRan` when a tool call finishes without an error:

- **Claude Code**: a `tool_result` in the user turn without `is_error`, matched by id to its `tool_use`.
- **Codex**: an `item.completed` for a tool item whose status isn't `failed` or `declined` and that has no `error` (Codex prints no item for a call its hook blocked).
- **Pi**: `tool_execution_end` with `isError: false`.
- **Hermes**: `tool_result` with `is_error: false`.

Calls refused before the hook, by the hook, or failing all end in an error, so they never count. A call that ran had to pass the hook first, wherever the harness hooks that tool.

### Which tools each harness hooks

`Adapter::hooks_tool` names the tools, as its events call them, whose every run goes through the hook:

- **Claude Code, Pi, Hermes Agent**: every tool.
- **Codex**: commands (`shell`), `apply_patch` (`file_change`) and MCP calls (`mcp_tool_call`). Not web search (hosted, never hooked), not plans (`todo_list`, hooked on 0.141.0, but CI can't make 0.171.0 call `update_plan`) and not subagents (`collab_tool_call`, untested).

The canary starts (`adapters::arms_canary`) on the start of a shell call, as before, or on a hooked tool that ran. Then, as before, it waits 5 seconds and stops the run if the hook was never called, and a run that ends first is still reported. The Bot now says it "used a tool without checking SuperBot's approval gate".

### Tested end to end

`harness_e2e.rs` runs two more calls per tool after the four shell calls: one allowed call that creates a file (it must run and the run must not be stopped as unguarded, so it went through the hook) and one a deny rule blocks (the hook sends it, it never runs, and the agent is told why). The tools: `Write` (Claude Code), `write` (Pi), `write_file` (Hermes), and for Codex an MCP tool from a small stdio server in the test (`python3`) and `apply_patch`, also at 0.141.0. Codex offers MCP tools as they are only to models it doesn't know and `apply_patch` only to ones it does, so the test sets the Bot's model to `gpt-5.5` for that step. The fake model learned to call a named tool, freeform tools (`custom_tool_call`) and tools in a namespace. The real-model script skips these steps, as a real model picks its own tool. `hermes_e2e.rs` checks the canary itself with its stub: a `read_file` that ran without the hook stops the run, one that failed doesn't.

## Consequences

- A guarded run with a broken hook is stopped after its first file write, MCP call or subagent, not only its first shell command.
- Every tool call that runs is counted on all four harnesses, apart from Codex's plans, subagents and hosted tools. Those keep the old behaviour: a run that uses only them isn't stopped.
- A call refused before the hook never stops a run, so healthy runs aren't stopped for a model's bad arguments.
- The canary starts on a non-shell tool once it finished, not when it started. Shell calls still start it when they start.
- A harness release that stops hooking a tool fails the `harness-e2e` workflow before its pin is bumped.

## Alternatives considered

- **Start on every tool call.** Stops healthy Claude Code runs whose first call is refused before the hook, such as an `Edit` of a file not read yet.
- **Leave out the tools a harness rejects before its hook.** Which calls are rejected depends on the arguments and the file system, not the tool's name.
- **List each harness's tools by name.** Every new tool would need a code change, and unknown tools would go unchecked; for the three harnesses that hook everything, "every tool" is what we tested.
- **Count Codex's plans too.** Hooked on 0.141.0 and in Codex's docs, but CI can't show it for the pinned release, and an unchecked plan changes nothing.
