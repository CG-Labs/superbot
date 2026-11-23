# 0193: In-region routes for Claude Code

## Status

Accepted (23 Nov 2026). The seventh slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0139](0139-in-region-model-routes.md) (in-region model routes), [ADR 0077](0077-two-providers-through-tier-routing.md) (named endpoints) and [ADR 0033](0033-tiers-model-routing.md) (tiers). 0193 was reserved for this work.

## Context

ADR 0139 holds a pinned person's model calls to endpoints the tiers file marks as in their region. Only Hermes Agent could take a named endpoint, so a pinned person's Claude Code and Codex Bots were always refused (`residency_pinned`), and every plan offering Claude Code was warned about for every pin. For a residency customer that meant giving up Claude Code, the harness many of them chose SuperBot for.

Claude Code can send every model call to one Anthropic Messages endpoint: `ANTHROPIC_BASE_URL`, with `ANTHROPIC_API_KEY` as its key. That is what an in-region gateway or a regional deployment of a Claude model needs. Codex speaks OpenAI's Responses API, which the tiers file's endpoints don't describe yet.

## Options

1. **A per-harness region setting** (`SUPERBOT_CLAUDE_BASE_URL` and a region beside it). A second way to name an endpoint, outside the plan, with no key handling, fallback rules or audit of its own.
2. **Let a Claude Code route name the tiers file's endpoints** (chosen). The plan's existing `providers`, `regions`, key handling and holding rules (ADR 0077, 0139) apply as they are.
3. **Wait and do Claude Code and Codex together.** Codex needs a new endpoint protocol; nothing in Claude Code's change depends on it.

## Decision

### The tiers file

- A `claude` route may name a `provider`. It must be one of the file's `providers` speaking `anthropic-messages`. Claude Code has no providers of its own, so any other name, or an `openai-chat` endpoint, is refused at startup.
- A `claude` route takes no `fallback`: Claude Code can't switch to another endpoint when a call fails. Refused at startup.
- `codex` and `pi` routes still take no provider.

```json
{ "harness": "claude", "provider": "claude-london", "model": "claude-opus-5-5" }
```

### A run on such a route

Held or not, Claude Code gets:

- `ANTHROPIC_BASE_URL`: the endpoint's `baseUrl`;
- `ANTHROPIC_API_KEY`: the endpoint's key, over any key of the owner's own. A key that isn't there leaves it empty rather than send the owner's to the endpoint (the run is refused first as `provider_key_missing`, ADR 0077);
- `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_VERTEX` and `CLAUDE_CODE_USE_FOUNDRY` empty, so no saved secret or login sends the calls to another account or cloud.

The same variables, all but the key, go in the run's flag settings (`--settings` `env`), which outrank the Bot's own settings files, so a `.claude/settings.json` in the workspace or the Bot's home can't point Claude Code elsewhere. The key stays out of the command line.

A run held to a region (ADR 0139) also gets:

- `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`: no telemetry, error reports or update checks to Anthropic and its vendors;
- `skipWebFetchPreflight: true`: WebFetch doesn't ask Anthropic whether each host is safe;
- `ANTHROPIC_DEFAULT_HAIKU_MODEL` and `ANTHROPIC_SMALL_FAST_MODEL` set to the route's model, so Claude Code's background calls (titles, summaries, WebFetch's reading) use a model the endpoint serves. They went to the endpoint anyway.

Holding works as for Hermes: the Bot's route is kept if its endpoint serves every pinned region, else the plan's first `claude` route that does; with none the run is refused and audited. `harness.invoked` records `provider` and `residency.insteadOf` as before.

### Logins

A run whose route hands the harness its own endpoint's key needs no harness login: on a user's machine with `MACHINE_HARNESS_LOGINS=on` (ADR 0041), for a teammate's run there (ADR 0062), and for a teammate's run under per-user accounts (ADR 0064). Other runs are checked as before.

### Warnings

`GET /api/regions` and the startup log stop warning about a plan's Claude Code for a region once it has a `claude` route to an endpoint marked as there. ADR 0171's startup refusal still doesn't count model routes.

## Consequences

- A residency customer can use Claude Code, with every model call going to an endpoint the operator marks as in their region, and the audit log showing it.
- An operator needs an Anthropic Messages endpoint in the region: a gateway there, or a provider's regional endpoint that speaks the API. botd can't check where it really processes, as in ADR 0139.
- A Claude Code route to an endpoint has no fallback. If the endpoint is down, those runs fail until it is back.
- The endpoint's key is in Claude Code's environment, so the Bot's shell commands can read it, as they can a server-wide or owner's `ANTHROPIC_API_KEY` today. Hermes hides its key from the shell; Claude Code's own way to do that (`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`) also changes how every command runs, so it is left for a later change. Operators should give each plan's endpoint a key scoped to it.

## Not covered

- Codex: still refused for pinned people. It needs an endpoint protocol for OpenAI's Responses API.
- Claude Code through Bedrock, Vertex or Foundry in a region: the tiers file has no endpoint for them.
- What a Bot's tools and MCP servers send, as in ADR 0139.
- Requests Claude Code makes to Anthropic without content that the settings above don't turn off.

## Not done (still on #58)

- In-region routes for Codex.
- Splitting botd's database by region, so one server can hold two regions' chats (ADR 0184).
- Ending a kept pin by itself once the leaver's machine and backups are gone (ADR 0171).

## Tests

- Unit (`tiers.rs`): a `claude` route names only `anthropic-messages` endpoints, never a built-in, and takes no fallback; `codex` still takes no provider; a pinned Claude Code route is swapped for the plan's in-region one, wired with only its key, and the plan has no gap there. (`adapters/claude.rs`): with an endpoint, the base URL and key (over the owner's), the switches empty, the same in flag settings without the key; held, background traffic and WebFetch's check off and the small model the route's; a missing key is empty, not the owner's; without an endpoint, as before.
- End to end on the real router with a stand-in `claude` (`residency_routes_http_tests.rs`): unpinned, the plan's first route with the owner's key and settings; pinned to London, the London endpoint with its key, Bedrock and background traffic off, audited with `insteadOf`, and no warning about the plan; without the endpoint's key, refused. With the real agent over mutual TLS (`machines_logins_tests.rs`): a Claude Code route to an endpoint runs on a machine with logins on and no login.
