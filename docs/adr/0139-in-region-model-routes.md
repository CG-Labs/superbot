# 0139: In-region model routes for pinned data

## Status

Accepted (22 Nov 2026). The second slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0129](0129-contractual-data-residency.md) (residency pins), [ADR 0033](0033-tiers-model-routing.md) (tiers and model routing) and [ADR 0077](0077-two-providers-through-tier-routing.md) (named endpoints and fallback). 0139 was reserved for this work.

## Context

ADR 0129 pins a user or a team to a data region, and holds their machines and backups there. It said plainly that a pin doesn't cover model calls: the harness sends prompts, conversation, tool output and file contents to whatever provider the tier routes to. A customer who signs "UK only" usually means the prompts too, and the DPA template asked the operator to promise that by hand, with nothing in botd to hold them to it.

botd can't see where a provider processes a call. It can only know what the operator tells it, and make every run of pinned data use only what the operator said is in the region.

## Options

1. **Keep it in the DPA only.** The operator promises in-region routes and builds a plan that has only those. Nothing stops a pinned tenant being moved to another plan, a route being added, or a fallback taking a call elsewhere.
2. **A region per tier.** A tier says it is "UK". Coarse: one tier can't serve both UK and EU customers, and its fallbacks would still need checking one by one.
3. **A region per endpoint, checked on every run** (chosen). The operator marks each named endpoint in the tiers file with the data regions it processes in. A pinned run takes only routes whose endpoint is marked as in its region.

## Decision

### Marking endpoints

A named endpoint in the tiers file (ADR 0077) may list `regions`: data region ids, as `MACHINE_REGIONS` names them.

```json
"providers": {
  "claude-london": { "protocol": "anthropic-messages", "baseUrl": "https://<regional-endpoint>", "keySecret": "TIER_UK_KEY", "regions": ["gb-lon"] }
}
```

- Each is a slug of up to 32 characters, at most 16, each once. botd refuses to start otherwise.
- An endpoint may list several regions. That suits, for example, an EU endpoint serving pins to two EU data centres. Listing a region is the operator's statement that the provider processes there, and that the agreements behind those pins accept it.
- A region that isn't in `MACHINE_REGIONS` is a warning, not an error, so a tiers file can be shared between servers.
- Admins see `regions` on `GET /api/tiers`.
- Harness built-ins (such as Hermes's `openrouter`) and routes with no provider (Claude Code, Codex) have no region. botd doesn't know where they process.

### Holding a run

A run is held when its data is pinned: the Bot owner's pin (their team's, else their own, as in ADR 0129), and the asker's pin when someone else asks. Every pinned region must be served.

1. The route the tier picks (ADR 0033) is kept if its own provider is an endpoint whose `regions` include every pinned region.
2. Otherwise the run takes the tier's first route for the same harness whose provider does. The tier still picks the model; a pinned tenant on a plan with both a US and a UK route gets the UK one.
3. Fallbacks whose provider doesn't serve every region are left out. The chain is pinned to what's left, so the harness's own settings can't add a provider, even on a tier where they otherwise could.
4. With no such route, the run is refused before anything starts or is counted:
   - The Bot says so in the chat. The message names the regions and the plan, not the reference, the providers or the models.
   - It is audited as `bot.run_refused` with reason `residency_pinned`, the pins (region, on a user or a team, reference), the harness and the reason.

An open tier (`"routes": "any"`) has no named provider, so a pinned tenant on one doesn't run. That is the fail-closed choice: a contract that says "UK only" can't be kept by a route nobody chose.

`harness.invoked` records `residency` for a held run:

- `regions`, the regions it was held to;
- `fallbackOutsideRegion`, the fallbacks left out;
- `insteadOf`, the route the Bot would have taken.

### Hermes's side tasks

Hermes makes model calls of its own for side tasks: summarising a long conversation, session titles, image analysis, web extraction, approval and search helpers. Each defaults to `auto`, which may pick another provider, and Hermes falls back to OpenRouter when a task's provider is unavailable.

For a held run, botd's managed Hermes config:

- sets every known side task to `provider: main` (the run's own endpoint and model), with `base_url` and `api_key` cleared;
- empties compression's fallback chain;
- keeps subagents on the route, as on any managed tier (ADR 0077).

The run's environment also gets the keys of Hermes's built-in providers empty (`OPENROUTER_API_KEY`, `NOUS_API_KEY`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`), whether they came from saved secrets or botd's environment. The route's own key still reaches Hermes under its own name.

### A pin isn't refused for its routes

Pinning still checks only machines and backups (ADR 0129). A tenant whose plan has no in-region route can be pinned; their Bots' runs are refused until it has one.

- That state is safe, and it is the usual order: pin first while onboarding, then set up the endpoint.
- Refusing the pin would leave their machines and backups free to move in the meantime.
- botd warns at startup, and in `GET /api/regions` under `residency.warnings`, about each pin whose people's plans lack an in-region route for a harness they offer.

## Consequences

- A provider can hold a pinned tenant's model calls to endpoints in their region, fallbacks and Hermes's side tasks included, and show it from the audit log. The DPA's residency annex now says this, and still asks the provider to list the endpoints and their terms.
- The guarantee is only as good as the operator's marks. botd checks that a route names a marked endpoint; it can't check the provider's terms or where a URL really resolves.
- Pinned tenants can use only harnesses that take a named endpoint: Hermes Agent today. Claude Code and Codex routes are refused for them until those adapters can be pointed at a regional endpoint.
- A pinned tenant on an open tier stops running. Operators who pin people on self-hosted servers need a managed tier with marked endpoints for them.

## Not covered

- **What a Bot's tools send.** A shell command or script in a run can call any API with a key the user saved. Egress allow-lists ([ADR 0135](0135-run-limits-and-egress-allow-lists.md)) are the control for that; the DPA says the pin doesn't hold it.
- **Side tasks Hermes adds later** under a name botd doesn't list. They take Hermes's default (`auto`, the main model as of November 2026). The built-in keys being empty keeps them from a router.
- **Harness logins stored in a Bot's Hermes home.** Hermes keeps OAuth logins (such as the Nous Portal) in `HERMES_HOME`. botd doesn't make those for Bots, but doesn't remove one a user made.
- **Runs already started** when a pin is made finish on their route.
- **Remaining on #58:** a region for botd's own database and server backups, or a dedicated deployment per region; showing the pin in the app; an option to refuse startup when a pin can't be kept; keeping a leaver's pin.

## Tests

- `tiers.rs`:
  - `regions` checked on endpoints;
  - a route held to a region: kept, or swapped for the tier's in-region route, with fallbacks outside it left out;
  - its wiring hands over only in-region keys;
  - refusals for no provider, a built-in provider, an endpoint without regions, and two regions one endpoint doesn't both serve;
  - each plan's gaps, and regions that aren't offered.
- `hermes.rs`: a held run's managed config puts every side task on `main` with nothing pointing elsewhere, and the built-in keys are empty in its job while the route's key is handed over. An unheld run is as before.
- `residency_routes_http_tests.rs`, on the real router with a stand-in `hermes`:
  - a pinned user's run takes the London route, with its in-region fallback only, side tasks on the route and no OpenRouter key, all audited;
  - a Claude Code Bot is refused, audited with the pin and not counted, and the chat shows no reference or model;
  - an asker's pin holds a run of someone else's Bot;
  - the warnings name the plan's harness without a route, and a provider's unknown region;
  - unpinned, runs are as before;
  - a team pin holds its member's runs.
- `machines_residency_tests.rs`: a pin on an open plan is warned about in `GET /api/regions`.
