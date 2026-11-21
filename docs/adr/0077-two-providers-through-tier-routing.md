# 0077: Two providers through tier routing, with fallback

## Status

Accepted (21 Nov 2026). Closes the last item of the [ADR 0011 gate](0011-hermes-agent-backend.md#recommendation) for making Hermes Agent the managed default: tier-to-model routing works with at least two providers. With it, every item of the gate passes. Part of [#33](https://github.com/CG-Labs/superbot/issues/33) (M3). Extends [ADR 0033](0033-tiers-model-routing.md), which left fallback out of scope.

0076 is the highest number on `main`, and no open PR holds 0077.

## Context

Before this, a tier route could name a provider, and botd passed it to Hermes as `--provider` ([ADR 0033](0033-tiers-model-routing.md)). That only reached providers Hermes has built in, keyed from botd's own environment. One base URL (`SUPERBOT_HERMES_BASE_URL`) served the whole server. Nothing said what happens when a provider fails, and no run had gone through two providers.

What Hermes v0.23.3 offers, read from its source:

- **Named providers.** `providers:` in `config.yaml` defines endpoints by name, each with a URL, a protocol (`transport` or `api_mode`: `anthropic_messages`, `chat_completions`, ...), and the environment variable that holds its key (`key_env`). `--provider <name>` picks one.
- **A fallback chain.** `fallback_providers:` is a list of `{provider, model}` that Hermes tries in order when a call fails. It also chains the legacy `fallback_model`. Subagents inherit the chain unless `delegation` sets their own.
- **The managed layer.** botd already writes a managed `config.yaml` that Hermes merges over the Bot's own, field by field ([ADR 0015](0015-hermes-adapter.md)).
- **Key scrubbing.** Hermes removes `HERMES_PROVIDER_*_API_KEY` from everything it starts (the agent's shell and tools), whatever `env_passthrough` says. Other key names are only removed when the Bot's own config declares them.

## Decision

### The tiers file names endpoints and fallbacks

```json
{
  "providers": {
    "anthropic-api": { "protocol": "anthropic-messages", "baseUrl": "https://api.anthropic.com", "keySecret": "TIER_ANTHROPIC_KEY" },
    "openai-api": { "protocol": "openai-chat", "baseUrl": "https://api.openai.com/v1", "keySecret": "TIER_OPENAI_KEY" }
  },
  "tiers": [
    { "name": "pro", "routes": [
      { "harness": "hermes", "provider": "openai-api", "model": "gpt-5",
        "fallback": [{ "provider": "anthropic-api", "model": "claude-sonnet-4-5" }] }
    ] }
  ]
}
```

- **`providers`** maps a name to an endpoint: its protocol (`anthropic-messages` or `openai-chat`), its base URL, and the name of the secret that holds its key. The file still holds no keys ([ADR 0033](0033-tiers-model-routing.md)).
- A route's **`provider`** can be one of these names, or a Hermes built-in such as `openrouter`, as before.
- A route's **`fallback`** lists up to 3 `{provider, model}` to try in order, each a file endpoint or a built-in.
- botd refuses to start on a mistake:
  - a name that isn't a slug;
  - a URL that doesn't parse as http(s) with a host, is over 200 characters, or carries a user, password, query or fragment;
  - a key secret name that isn't valid, or is one of botd's own secrets, which it keeps from every harness;
  - a provider or fallback on a harness that doesn't take one (only Hermes does);
  - more than 3 fallbacks, a fallback listed twice, or a fallback that is the route itself.
- `GET /api/tiers` shows admins the endpoints (protocol, URL, key secret name; never the key). The startup line counts them. botd warns at startup about each endpoint whose key secret isn't saved.

### How a run uses them

Before each run, botd works out what the route needs (`Tiers::wiring`):

- **The route's own provider.** If it is a file endpoint whose key isn't saved, the run is refused before it starts, and before it counts against any limit. The Bot says the plan's model provider isn't set up yet and to ask an admin. `bot.run_refused` is audited with reason `provider_key_missing`, the provider, and the key's name.
- **Fallbacks.** One whose key isn't saved is left out, and `harness.invoked` lists it as `fallbackSkipped`. The rest are in `fallback`.
- **Other keys.** The keys of the file's endpoints that this route doesn't use are left out of the run. Each key goes only to runs routed to its endpoint.
- **Where keys live.** A key is a saved secret or a variable in botd's own environment (`.env`), like other secrets. Either way, nothing botd starts inherits a tier endpoint's key, or its `_FILE`, from botd. A run routed to the endpoint is handed the key explicitly, and Hermes's `env_passthrough` never lists one.

The Hermes adapter turns that into its managed config and arguments:

- Each endpoint the run uses becomes a `providers:` entry named `superbot-<name>`. The prefix means it never shadows a Hermes built-in. Every field Hermes reads an endpoint's URL, protocol, key, or switch from is set, so the Bot's own `config.yaml` can't point it elsewhere.
- The route's provider goes to `--provider superbot-<name>`, with no `--base-url`.
- The key goes to Hermes as `HERMES_PROVIDER_SUPERBOT_<NAME>_API_KEY`, the only name Hermes reads it from. Hermes strips that name from everything it starts. botd drops the secret's own name (`TIER_OPENAI_KEY`) from the run and from `env_passthrough`, so the agent's shell sees neither.
- **On a managed tier** the fallback chain is exactly the route's, or none:
  - `fallback_providers` is the route's list;
  - `fallback_model` is emptied, since Hermes chains both;
  - `delegation` is pinned to inherit, so subagents take the route and its chain rather than a provider of their own.
- **On an open tier** (`"any"`, self-host) nothing changes: Hermes's own settings decide.

Other adapters don't take providers, so this stays in the Hermes adapter. botd's side is harness-agnostic: endpoints and fallbacks reach every adapter in `RunInput`, and only an adapter that takes a provider uses them.

### Failure behaviour

Hermes decides when to fall back, from its error classifier. botd fixes what it may fall back to. What v0.23.3 does:

| The provider answers | Hermes |
|----------------------|--------|
| 402 (out of credit), 429 (rate limited) | Falls back at once to the next in the chain. |
| 401 or 403 (bad key) | Falls back once its credential refresh fails. |
| 5xx, overloaded, timeouts | Retries with backoff (2 or 3 tries), then falls back. |
| Every provider in the chain fails | The run ends in an error, which the Bot reports. Nothing else is tried: not a built-in, not another tier's provider, not the server's own key. |

botd's rules on top:

- A route whose own key isn't saved never runs (above). A run never moves to another route or harness.
- A fallback without its key is skipped, not tried.
- **A plan change starts a fresh session.** Hermes keeps a session on the provider and model it started with, and refuses to resume it with others. Adapters can now say so (`Adapter::resume_refused`), and the runner starts a fresh session once, as it does when a harness has lost its session. Without this, the first run after a user changed tier failed.

### Install

- **The Anthropic client.** Hermes speaks Anthropic Messages through an optional Python extra. Bots can't install packages ([ADR 0072](0072-one-hermes-environment-per-computer.md)), so `deploy/hermes-share.sh` adds it (`hermes pm install --extra anthropic`). Every install path runs that script: `install.sh`, the Dockerfile, `install-harness-clis.sh`, and machines' harness installs. It takes under a second once the extra is there.
- **A Bot `config.yaml`.** Hermes reads the fallback chain only from a data root that has a `config.yaml` of its own, even when the chain is in the managed layer. The wrapper that script writes now creates an empty one when a Bot has none. Empty means no settings, so nothing else changes, and an existing file is never touched.

## Tests

- **Unit tests:**
  - tiers parsing and validation, wiring, and unused keys;
  - the admin view and the shipped example;
  - the Hermes managed config, arguments and environment for both kinds of tier;
  - Hermes's resume refusal;
  - the wrapper's extra and its `config.yaml`.
- **End to end with the real Hermes** (`hermes_routes_two_providers` in `server/tests/harness_e2e.rs`, run by the `harness-e2e` workflow's Hermes job). The real `botd` runs Hermes at the pin against two fake providers: one speaks Anthropic Messages, the other OpenAI Chat Completions. Each records the key of every call, tags its replies, and can fail on demand. No real key or paid service is used. Two tiers route to one provider each; one falls back to the other. The test checks:
  1. With no keys saved, a run is refused before it starts (`provider_key_missing`), and no provider is called.
  2. On the Anthropic tier, Hermes reaches only that provider, with its key. The agent's shell sees neither the saved key's name nor Hermes's.
  3. After the owner moves to the OpenAI tier, the same Bot reaches only the OpenAI provider, with its own key, in a fresh session. That key is set in botd's environment, not saved, and in step 2 the agent didn't see it either.
  4. With that provider failing (402), the run falls back to the Anthropic provider, with that provider's key.
  5. With both failing, the run ends in an error, and no other model is called.

## Results

On a 4-vCPU cloud VM, Hermes Agent v0.23.3 from the pin:

| Check | Result |
|-------|--------|
| A route with no key saved | refused before it ran; no provider called |
| Anthropic Messages tier | answered by that provider only, with its key; keys hidden from the agent's shell |
| OpenAI Chat tier, after a tier change | answered by that provider only, with its key, in a fresh session |
| Its provider failing (402) | fell back to the Anthropic provider in 5.0 s, the first try included |
| Both failing | the run ended in an error; nothing else called |
| The whole test | 24 s |
| `hermes_hooks_hold`, `hermes_hook_timeout_fails_closed` | still pass |

The test found three problems before it passed, all fixed here:

- Hermes needed its Anthropic extra.
- The route's key reached the agent's shell under its saved name. Review then found the same for a key set in botd's environment, which local runs inherited, and that such a key counted as missing. The test now sets one key that way.
- Hermes ignored the fallback chain for a Bot with no `config.yaml` of its own.

## Known limits

- **Same-user boundary.** Hermes and the agent it runs are one Unix user, so a determined agent could still read the key from Hermes's own process. The boundary SuperBot relies on is between users ([ADR 0037](0037-per-user-unix-accounts.md), [ADR 0058](0058-harness-os-user-by-default.md)). Give each tier endpoint a key of its own, with a spending limit at the provider.
- **Tokens after a fallback.** They are recorded against the route's model. Hermes's stream doesn't say which model answered.
- **Hermes's side tasks.** Titles and compression follow Hermes's own `auxiliary` settings. Those default to the main provider, and botd doesn't pin them.
- **Old setups.** Machines whose agent predates install `after` scripts ([ADR 0072](0072-one-hermes-environment-per-computer.md)), and servers that run Hermes without the wrapper, get no Bot `config.yaml`. Their runs work, but without the fallback chain.
- **Fakes, not vendors.** The test proves botd's routing and Hermes's handling of both protocols. Real vendors' quirks are Hermes's to handle. Pointing a tier at a real provider is a one-line change to the tiers file, and worth one manual run before launch.

## Consequences

- **ADR 0011's gate passes.** Every item now passes:
  - approvals end to end, including the canary and the hook timeout;
  - footprint, with its conditions met;
  - one upgrade through the suite;
  - two providers through tier routing, with fallback.

  Hermes is cleared to be the managed default.
- **Not done here.** Making it the default is [ADR 0079](0079-hermes-default-for-managed-tiers.md). (This said new Bots already took a managed tier's first route's harness; they took `DEFAULT_HARNESS` whenever the tier had it, so Claude on Pro and Max. ADR 0079 fixes that.)
- **Fallback is opt-in per route.** A route with no `fallback` fails as before, and an open tier keeps Hermes's own settings.
- **Keys go only where routed.** A tier endpoint's key is a secret like any other, saved with `botctl secret set` or set in `.env`. It goes only to runs routed to its endpoint.
