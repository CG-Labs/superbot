# 0079: Hermes Agent is the default harness for managed tiers

## Status

Accepted (21 Nov 2026). Makes Hermes Agent the managed default, as [ADR 0027](0027-expo-primary-hermes-default.md) decided once the [ADR 0011 gate](0011-hermes-agent-backend.md#recommendation) passed. Its last item landed in [#136](https://github.com/CG-Labs/superbot/pull/136) ([ADR 0077](0077-two-providers-through-tier-routing.md)). Closes [#33](https://github.com/CG-Labs/superbot/issues/33) (M3). Changes how [ADR 0033](0033-tiers-model-routing.md) picks a new Bot's harness, and replaces ADR 0027's "the control plane sets `DEFAULT_HARNESS=hermes`".

0078 is the highest number on `main`, and no open PR holds 0079.

## Context

What the code did before this change:

- **New Bots.** A new Bot without a harness got `DEFAULT_HARNESS` (default `claude`). Only when the owner's tier lacked that harness did it get the tier's first one. The shipped Pro and Max plans list Claude Code, so their new Bots got Claude, not Hermes. ADR 0077 said new Bots "already take its first route's harness". That was wrong.
- **Machines.** These install only the harnesses `MACHINE_HARNESSES` lists ([ADR 0039](0039-machine-harnesses-and-agent-upgrades.md)). With it unset, a managed machine got no Hermes. A run there was refused with `harness_missing`.
- **This server.** A run here on a harness that isn't installed got as far as starting the CLI, and the user saw "Couldn't start". A guarded Codex run said "isn't on this server's PATH".
- **Clients.** The client always sent a harness when it created a Bot. It sent the one `/api/state` named when the dialog first opened, which could be the placeholder `claude` from before state loaded.

`DEFAULT_HARNESS=hermes` on the managed server would also change open tiers on the same server, such as `self-host`. It also doesn't fit a tiers file in which each plan has different harnesses.

## Decision

### The default is per tier

- **The tiers file.** A managed tier may name a `defaultHarness`, which must be one of its routes' harnesses. Without one, its first route's harness is the default. An open tier (`"routes": "any"`) can't name one, because its new Bots get `DEFAULT_HARNESS` as before. botd refuses to start on either mistake.
- **New Bots.** `POST /api/bots` without a harness, and the first Bot botd makes, take the owner's tier's default. `/api/state` `defaultHarness` is the caller's tier's default.
- **The shipped tiers.** `deploy/tiers.example.json` sets `"defaultHarness": "hermes"` on Starter, Pro and Max. Hermes is also each plan's first route, so the field states the intent and keeps it if someone reorders the routes.
- **Self-host is unchanged.** Without `TIERS_FILE` there is one open tier, so new Bots get `DEFAULT_HARNESS` and nothing else moves. The installer and image keep Hermes opt-in (`--with-hermes`, `SUPERBOT_HARNESSES`).
- **Visibility.** `GET /api/tiers` (admins) shows each tier's `defaultHarness`. The setup wizard's Plans table shows which harness new Bots get. Clients see only the harness name, never a model.

### Existing Bots stay put unless an admin moves them

A Bot keeps its harness when the default changes. Switching harness drops the session, and the Bot's logins, memory and habits belong to the old harness. On the user's machine, the new harness may not even be installed yet. So nobody is moved without being asked.

- **The endpoint.** `POST /api/tiers/{name}/move-bots` `{user?, dryRun?}` (admins only, `botctl tiers move-bots <tier> [--user <user>] [--dry-run]`) moves every Bot whose owner is on that managed tier and whose harness isn't its default. With `user`, it moves only that person's Bots. Its errors:
  - 400 on an open tier;
  - 404 on an unknown tier;
  - 409 if the named user isn't on that tier.
- **What a move changes.** A moved Bot gets the default harness and loses its session, model and effort, so the tier's route picks the model.
- **Busy Bots.** A Bot that is running, has queued work, or is draining is skipped with `reason: busy`. Run the command again later.
- **Dry runs.** `--dry-run` lists what would move and changes nothing.

### Machines install the managed default

With enrollment on, `MACHINE_HARNESSES` unset, and a tiers file with managed tiers, machines install the managed tiers' default harnesses: pinned Hermes on the shipped plans. `MACHINE_HARNESSES=none` installs nothing, and an explicit list is used as written. botd's startup line says when a plan came from the default.

### A clear refusal when Hermes isn't there

- **On this server.** Before a run starts, botd checks that the Bot's harness CLI is on the run's `PATH`. If it isn't, the run is refused (`bot.run_refused`, reason `harness_missing`, `host: server`) and not counted. The Bot says how to install the CLI here, for example `deploy/install.sh --with-hermes`, or `hermes` in `SUPERBOT_HARNESSES` for Docker. It suggests switching harness only when the tier has another one.
- **On the user's machine.** The existing `harness_missing` refusal stays as it is.
- **At startup.** botd prints which harness new Bots get on each plan. It warns when a managed default isn't installed where runs happen: on this server unless `MACHINE_ROUTING=on`, and in `MACHINE_HARNESSES` when machines are enrolled.

### The client shows the plan's default

The new-Bot dialog lists the default first. On a managed plan it's marked "your plan's default", elsewhere "default". The dialog sends a harness only if the user picks another one, so the server applies the owner's plan. Users pick a plan, not a model.

### Audit

Every state change is audited:

- `bot.created` adds `harnessFrom` (`chosen`, `plan` or `server`) and `tier`.
- Each move is `bot.updated` with `via: tier_default` and the tier. One `tier.bots_moved` (target the tier) records `{to, moved, skipped, user}`.
- A refused run is `bot.run_refused` with reason `harness_missing`.
- `server.started` adds `tierHarnesses`, each managed tier's default.

## Alternatives considered

- **Set `DEFAULT_HARNESS=hermes` on managed servers.** This also changes open tiers on that server, and it can't give one plan Hermes and another plan something else.
- **Move every managed Bot at startup.** That is silent, can't be undone, and drops sessions. On machines without Hermes yet it also turns working Bots into refused ones.
- **Move Bots when their owner changes plan.** The same problem arises, and it would happen inside a billing webhook. Admins can follow a plan change with `move-bots --user`.

## Tests

- **Unit tests, in `tiers.rs`:**
  - the default comes from the first route or from `defaultHarness`;
  - both mistakes are refused;
  - the shipped tiers give Hermes on Starter, Pro and Max and `DEFAULT_HARNESS` on self-host;
  - the startup line and its warnings.
- **Unit tests, elsewhere:**
  - `upkeep.rs`: machines get the managed default only when `MACHINE_HARNESSES` is unset, and `none` opts out.
  - `botctl`: argument parsing for `tiers move-bots`.
- **HTTP tests, in `tiers_http_tests.rs`:**
  - New Bots on a managed tier get its default even though `DEFAULT_HARNESS` is claude, and `/api/state` agrees.
  - A chosen harness is kept, and self-host still gets `DEFAULT_HARNESS`.
  - `harnessFrom` is audited.
  - Without Hermes, a run is refused with `harness_missing` and isn't counted.
  - `move-bots` covers admin-only access, 404, 400 on an open tier, 409 for the wrong user, a dry run, the busy skip and a later retry, a cleared session, both audit events, and self-host Bots left alone.
- **HTTP test, in `harness_version_http_tests.rs`:** a guarded Codex run without Codex now reports `harness_missing`.
- **End to end, in `server/tests/managed_default_harness.rs`, on the real `botd`:**
  - Without a tiers file, Bots get `DEFAULT_HARNESS` and nothing is printed.
  - On the shipped tiers, the first Bot is on Hermes.
  - The startup line and warning appear.
  - A run is refused while Hermes is missing and runs once a stub is on `PATH`.
  - The self-host tier gets claude.
  - A dry run and then a move put an older Claude Bot on Hermes, audited, and it runs.
- **Client, in `plan.test.ts`:** the dialog's harness list puts the default first and labels it.

## Consequences

- **New Bots.** On every shipped managed plan, new Bots run on Hermes Agent, the harness behind the Enterprise SLA. Claude Code, Codex and Pi stay available where a plan lists them, best-effort.
- **Operators.** An operator with an existing managed deployment sees new Bots on Hermes once they update their tiers file, or straight away if Hermes is already each plan's first route. Their existing Bots keep their harness until they run `botctl tiers move-bots`.
- **Hermes on the server.** A managed server that runs Bots itself (`MACHINE_ROUTING` off or assigned) needs Hermes installed (`--with-hermes`). botd warns at startup until it is.
- **Not done here.** Before launch, each shipped tier still needs one run against its real provider (roadmap). Moving a Bot doesn't install anything on the user's machine, or log anyone in. The machine's harness plan does the installing, and Hermes routes use the tier's provider keys.
