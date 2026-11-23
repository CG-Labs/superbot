# 0192: In-region Claude Code and Codex routes

## Status

Accepted (23 Nov 2026). The seventh slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0139](0139-in-region-model-routes.md) (in-region model routes), [ADR 0077](0077-two-providers-through-tier-routing.md) (tiers-file endpoints), [ADR 0129](0129-contractual-data-residency.md) (residency pins) and [ADR 0041](0041-machine-harness-logins-and-folder-copy.md) (harness logins on machines). 0192 was reserved for this work.

## Context

ADR 0139 holds a pinned person's runs to routes whose provider is a tiers-file endpoint marked as in their region. Only Hermes Agent could name such an endpoint. A Claude Code or Codex route named none: it used the harness's own login or key, so botd couldn't say where its model calls went, and every run for a pinned person on those harnesses was refused. A team that works in Claude Code or Codex had to switch harness to sign a residency agreement. ADR 0184 left this as the first item still to do.

Both harnesses can be pointed at another endpoint:

- **Claude Code** reads `ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY`. Settings files can set them too, through their `env` block. Flag settings (`--settings`) outrank user and project settings. Claude Code also makes calls of its own to Anthropic: telemetry, error reports, update checks (`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` turns them off) and a domain check before each WebFetch (`skipWebFetchPreflight`). `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` keeps its credentials from what its Bash tool, hooks and MCP servers get, but Claude Code (2.1.329, the pinned version) refuses to start with it when bubblewrap isn't installed. `CLAUDE_ENV_FILE` names a script Claude Code sources before each Bash command.
- **Codex** takes a custom model provider through config overrides: `model_providers.<id> = {name, base_url, env_key, wire_api}` and `model_provider = "<id>"`. Since early 2026 Codex speaks only the Responses API (`wire_api = "responses"`); Chat Completions was removed. Its shell commands inherit variables whose names contain `KEY` unless told otherwise. `shell_environment_policy.set` overrides a variable there. `analytics.enabled = false` turns off its usage analytics.

## Options

1. **Keep refusing** Claude Code and Codex for pinned people. Safe, but residency customers can only use Hermes Agent.
2. **Trust the operator's own harness settings** (a Bot's `ANTHROPIC_BASE_URL`, a Codex `config.toml`) and mark the harness as in a region. botd can't see or hold those, and a Bot's settings can change them.
3. **Let Claude Code and Codex routes name a tiers-file endpoint** that the harness speaks, with botd giving it the URL and key per run (chosen). ADR 0139's holding then works unchanged: a pinned person's run takes the plan's in-region route for that harness.

## Decision

### Endpoints per harness

Each adapter says which endpoint protocols it speaks. A route may name an endpoint only if its harness speaks the endpoint's protocol; botd refuses to start otherwise, naming the protocols the harness takes.

| Harness | Endpoint protocols | Its own providers | Fallback chain |
|---|---|---|---|
| Hermes Agent | `anthropic-messages`, `openai-chat` | yes (e.g. `openrouter`) | up to 3 |
| Claude Code | `anthropic-messages` | no | no |
| Codex | `openai-responses` (new) | no | no |
| Pi | none | no | no |

- `openai-responses` is a new endpoint protocol: OpenAI's Responses API. Hermes isn't given one, since its managed config has only Chat Completions for OpenAI-style endpoints.
- Claude Code and Codex have no fallback chain botd can hold, so their routes take none. A route with a fallback is refused at startup.
- Two routes for the same harness and model are a duplicate only if they also name the same provider. A plan can then offer the same model on a global and an in-region provider. A Bot set to that model gets the first; a pinned person's run gets the in-region one (ADR 0139, rule 2).

### Claude Code on an endpoint

For a run routed to an endpoint:

- `ANTHROPIC_API_KEY` is the endpoint's key, taken from the person's saved secret named by `keySecret`, as for Hermes. The secret's own name isn't in the run.
- `ANTHROPIC_BASE_URL` is the endpoint's `baseUrl`. `ANTHROPIC_AUTH_TOKEN` and `CLAUDE_CODE_OAUTH_TOKEN` are empty, and `CLAUDE_CODE_USE_BEDROCK`, `_VERTEX` and `_FOUNDRY` are `0`, so neither a login nor the person's own cloud setup takes the run elsewhere.
- The same values, except the key, are in the run's flag settings' `env`, which outrank the Bot's and the user's settings files.
- `CLAUDE_ENV_FILE` is a file botd writes beside the run's settings, which unsets the key and tokens before each Bash command, so the agent's shell doesn't see them.
- Where the computer has said Claude Code's sandbox can start (ADR 0055), which needs bubblewrap, `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` as well, so hooks and MCP servers don't get the key either. Elsewhere, including a machine agent too old to say, the scrub could stop Claude Code from starting, so it is left off.
- When the run is held, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` and `skipWebFetchPreflight: true`, so Claude Code itself calls only the endpoint.

The key is never in the command line, where other users of the host could read it.

### Codex on an endpoint

For a run routed to an endpoint, Codex gets, before the prompt (and for resumed sessions too):

- `-c model_provider="superbot-<name>"` and `-c model_providers.superbot-<name>={name, base_url, env_key, wire_api="responses"}`;
- the key in `SUPERBOT_PROVIDER_<NAME>_API_KEY`, the `env_key`, and `-c shell_environment_policy.set.SUPERBOT_PROVIDER_<NAME>_API_KEY=""`, so its shell commands see it empty;
- when held, `-c analytics.enabled=false`.

Config overrides outrank the Bot's `config.toml`, so the run's provider can't be changed there.

### Logins

A run routed to an endpoint brings its key, so it needs no harness login. botd doesn't refuse it for a missing Claude Code or Codex login on the user's machine, in a teammate's account there, or in a per-user account on the server.

### What doesn't change

- Routes with no provider behave as before: the harness's own login or key, and no region. Pinned people's runs on them are refused, or take the plan's in-region route for the harness if it has one.
- `harness.invoked` records the provider, and for a held run `residency` with `insteadOf`, as for Hermes.
- Admins' residency warnings (`GET /api/regions`, startup) now find a plan's in-region Claude Code and Codex routes, so they warn only where there are none.

## Consequences

- A residency customer can use Claude Code or Codex, given an Anthropic-compatible or Responses endpoint in their region (for example a gateway in front of a cloud provider's regional model service).
- Operators choose per plan: global routes first for everyone, in-region twins for pinned people.
- On an endpoint route, Claude Code's Bash tool doesn't get the person's own `ANTHROPIC_API_KEY` either, and where the scrub is on, hooks and MCP servers don't get their cloud credentials. A Bot that relied on those in its shell needs them under other names.
- A Bot's own `CLAUDE_ENV_FILE` (say, to activate a virtualenv) is replaced on endpoint routes.

## Not covered

- A Bot's or user's settings that set `ANTHROPIC_API_KEY` in their `env` block could replace the tier's key. The base URL and the other values can't be moved, so the call still goes to the endpoint, with their key.
- Processes running as the same OS user can read the run's environment, as with Hermes. Per-user accounts (ADR 0037) keep people apart.
- Endpoints Claude Code or Codex reach natively by cloud credentials (Bedrock, Vertex, Azure) aren't routes; a gateway that speaks the Anthropic or Responses API is.
- Codex's legacy `filters` and Hermes on Responses endpoints.
- What the agent's tools reach (web pages it fetches, MCP servers and Bot tools it calls) is not the model's processing and isn't held, as for Hermes Agent: a pin doesn't cover Bots' own network calls.

## Not done (still on #58)

- Splitting botd's database by region, so one server can hold two regions' chats.
- Ending a kept pin by itself once the leaver's machine and backups are gone (ADR 0171).

## Tests

- Unit (`tiers.rs`): the new protocol and its name; which protocols each harness's routes may name, and the errors for the others, for built-ins and for fallbacks; the same model on two providers; the run's wiring; a pinned run held to the in-region Claude Code and Codex routes, and the residency gap where there are none.
- Unit (`adapters/mod.rs`): Claude Code's key, base URL, cleared tokens, flag settings, Bash env file, the scrub only with its sandbox, the held extras, no key in the arguments, and nothing changed without an endpoint; Codex's provider overrides, key, shell blanking, held analytics, on a resumed session too, and nothing changed without an endpoint.
- End to end on the real router with stand-in `claude` and `codex` (`residency_routes_http_tests.rs`): unpinned runs use the person's own key or Codex's built-in provider; pinned to London, each takes its in-region route with only the tier's key, its tools' copy hidden and its own traffic off, audited with `insteadOf`; no key in the audit log; pinned to Frankfurt, only the harness with an endpoint there runs.
- End to end with a machine (`machines_logins_tests.rs`): a run routed to an endpoint runs on a user's machine where the harness isn't logged in.
- Through the real, pinned Claude Code and Codex (`tests/harness_e2e.rs`, the `harness-e2e` workflow), with the fake model on a host without bubblewrap: a route to an endpoint reaches only it, with its key, though botd's environment and the harness's own settings in HOME name another model; a shell command the agent runs sees no key. Each check fails when the Bash env file or Codex's shell override is taken out.
