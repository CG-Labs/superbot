# 0267: A pinned person's runs take place only on a computer in their region

## Status

Accepted (25 Nov 2026). The fourteenth slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0129](0129-contractual-data-residency.md) (residency pins), [ADR 0139](0139-in-region-model-routes.md) and [ADR 0192](0192-in-region-claude-code-and-codex-routes.md) (runs held to in-region model routes), [ADR 0184](0184-botds-own-data-region.md) (botd's own data region) and [ADR 0036](0036-bots-on-the-users-machine.md) (where a Bot's run takes place). 0267 was reserved for this work.

## Context

A pin holds a person's machine, its backups, their model calls and, with a regional store, their chats to a region. It did not hold the run itself. A Bot's run works on a computer: the harness reads the chat and the files it is given, writes to its workspace, runs tools and browses. Routing (ADR 0036) puts it on its owner's machine or, with `MACHINE_ROUTING=off` or an owner without an assigned machine, on botd's own server. Neither was checked against the pin:

- With routing off, every pinned person's runs took place on botd's server, wherever that was, while their report said their computer was in the region.
- A pinned teammate who asks a shared Bot, or whose data a run carries through Bots asking Bots (ADR 0139), had that run take place on the owner's machine, which may be in another region. Their machine stayed in the region; their run didn't.

ADR 0139 refuses a run whose model route would leave the region. Where the run itself takes place is the same kind of gap.

## Options

1. **Say so in the DPA and the report.** Cheap, but a pin would promise less than it seems to, and nothing would stop the run.
2. **Move the run to a computer in the region** (the asker's machine, say). The Bot's workspace, logins and files are on its owner's computer; running it elsewhere would be another Bot.
3. **Refuse a run that would take place outside the region of anyone it carries** (chosen), as ADR 0139 does for model routes, audited and said in the chat, with admins warned ahead of time and reports and the app saying where each person's Bots run.

## Decision

### Where a run may take place

Before a run is placed, the runner works out where routing would put it, and checks it against the pin of everyone the run carries (`residency::of_run`: the owner, the asker and anyone carried through Bots asking Bots, ADR 0139):

- **botd's own server** is in a region only as the operator states it (`SERVER_DATA_REGION`, ADR 0184). Unstated, it is in none, so a pinned person's run there is refused.
- **The owner's machine** is in a region by its record and its host's tag now, as for its backups (ADR 0129). A machine that is gone isn't in any.
- A run that has nowhere to go (routing refuses it, ADR 0036) is refused as before.

A run that would leave any of those regions is given back (not counted), audited as `bot.run_refused` with `reason: residency_pinned`, `action` `run on botd's server` or `run on a machine outside the region`, `runsOn`, the machine, `serverDataRegion`, the owner, the pins (region, subject and reference), the people and asker, and `error` naming each region and why. The Bot says in the chat that the run's data is pinned there and it runs on a computer that isn't, so it didn't run. It names whose computer, as ADR 0036's refusals do, and on the server tells the reader to ask an admin for a computer in the region.

The check runs only with the control plane on, as every other pin check does: without it there are no machines and no pins can be made.

### Seeing it ahead of time

- **Admins** (startup and `GET /api/regions`): a pin whose people's own Bots run on botd's server outside the region is warned about, naming them and why, and how to fix it: route them to a machine in the region (`MACHINE_ROUTING=on`, or `assigned` with their machine assigned), or run botd in the region and say so in `SERVER_DATA_REGION`.
- **Reports** (ADR 0155): each person gains `runs`, `{ on: server | machine | nowhere, inRegion }`, from routing now; the Markdown table a "Bots run on" column; and the same warning. The report's refusals list the new refusals with the rest.
- **The app** (`GET /api/me/residency`, ADR 0168) returns `runs`. Settings says when a person's Bots run on SuperBot's own server, in the region or not; when not, that they don't run until an admin gives them a computer there, and nothing runs outside the region instead.

It doesn't make a pin `data_outside` or refuse one: no data is outside yet, and runs are refused until it's fixed, as for a missing model route (ADR 0139).

## Consequences

- A pin now holds the place a run takes place, not just the data left behind: no pinned person's run takes place on a computer outside their region.
- **On upgrade**, a botd with pins and routing off whose `SERVER_DATA_REGION` isn't the pin's region refuses those people's runs. Startup and `GET /api/regions` warn first. If botd does run in the region, setting `SERVER_DATA_REGION` is enough; otherwise route them to machines in the region.
- A pinned teammate can no longer use a shared Bot whose owner's machine is in another region. The owner can share one with a machine in the region, or the teammate use their own.
- An asker who is pinned learns that the owner's computer isn't in their region; they learn no more about it than ADR 0036's refusals tell them.

## Not done (still on #58)

- The rest of botd's database per region: accounts, sessions and the audit log are still where botd runs. A pin's report says so.
- Moving a regional store while botd is running.

## Tests

- HTTP (`residency_run_place_http_tests.rs`):
  - with routing off and botd's server stated to be in London, unpinned and London-pinned people's runs take place on it; a Frankfurt pin's run is refused and audited with every field, nothing is counted and the harness isn't run; admins, the report (JSON and Markdown) and the app say their Bots run on botd's server outside the region; unpinned, they run again;
  - with routing on, a Frankfurt-pinned teammate's run of a shared Bot whose owner's machine is in London is refused, nothing reaches the machine, and the owner's own London-pinned runs still go to it; reports say the owner's Bots run on their machine in the region and the teammate's nowhere yet;
  - botd's server is in a region only as `SERVER_DATA_REGION` says, and nothing is checked with the control plane off.
- The ADR 0184 report-mode test now checks that the new warning is shown there.
- Client (`residency.test.ts`): Settings says where your Bots run on SuperBot's server, in the region or not, and adds nothing for a machine or no computer yet.
