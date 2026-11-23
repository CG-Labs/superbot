# 0166: Residency in the app

## Status

Accepted (23 Nov 2026). The fourth slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0129](0129-contractual-data-residency.md) (residency pins), [ADR 0139](0139-in-region-model-routes.md) (in-region model routes), [ADR 0155](0155-residency-reports.md) (residency reports) and [ADR 0087](0087-team-accounts-and-machines.md) (teams). 0166 was reserved for this work.

## Context

A pin is made by a server admin, and until now only admins could see it or its report. The people it holds, and the customer's own admins who signed the agreement, had to ask the provider. ADR 0129 listed "show the pin to the customer in the app" as a follow-up, and ADR 0155 left out self-service.

What a person should see, and what they shouldn't:

- Their own data is theirs to know about: where it must stay, and whether it does.
- A team's pin covers every member. Its report lists every member's machine, host and backups. Team owners and admins already see teammates' machines (ADR 0087); ordinary members don't.
- The agreement reference on a team's pin is already shown only to those who manage the team's members (ADR 0129). The same rule should hold here.
- A report reads the audit log for its period, up to 100,000 events. An admin asking for one is rare; anyone being able to ask needs a limit.

## Options

1. **Keep it admin-only; operators send reports by hand.** No new surface, but customers can't check their pin when they want to, and the provider does the work each time.
2. **Give the customer's own admins a custom-role permission for residency.** Custom roles are server-wide or team-scoped (ADR 0123), and a server-wide one would see every tenant's pins. Too broad for most installs, and it touches RBAC, which other work is changing.
3. **A self-service view under `/api/me`** (chosen). Each person sees the pin on their own data; a team's owners and admins get the team's report. It follows the access people already have, so it needs no new permission.

## Decision

### The view

`GET /api/me/residency`, for everyone signed in, read-only people included (RBAC's `account`); Bots are refused. It returns:

- `pin`: the pin that holds their data (their team's, else their own, as ADR 0129 resolves it), or null. `on` (`user` or `team`), `region`, `pinnedAt`, and for a team pin its `team` (id and name). `reference` is included for their own pin, and for a team pin only when they are the team's owner or an admin.
- `ownPin`: their own pin, when their team's also holds their data (it must agree, ADR 0129).
- `status`: `kept`, or `data_outside`, by the same check a pin uses, for their own data only.
- `machine` and `backups`: their machine's region and whether it is in the pinned region (by record and by host), and how many of their kept backups are in a store outside it.
- `modelRoutes`: whether their plan has a model route in the region (ADR 0139), and the gap if not. It names the plan and harnesses, never models.
- `reports`: which reports they can get: `team` if they manage a pinned team, `user` if they have their own pin.

### The report

`GET /api/me/residency/report`, with the same `from`, `to` and `format` as the admin route, and `on=user|team`:

- `on=user`: the report on their own pin. 404 if they have none.
- `on=team`: the report on their team's pin, for its owners and admins only. Other members get 403 with a plain reason, since it covers everyone on the team.
- With no `on`, the team's if they manage it, else their own, else 403 or 404.

It is the same report, made by the same code, so it carries the same digest the customer can check. It is audited as `residency.report_generated` like an admin's, with the person as the actor and `selfService: true`, so the provider sees who fetched evidence and when.

Bad `on`, `format` and periods are refused (400) before anything else. Each person can fetch 5 reports in a sliding 10-minute window; after that the answer is 429 with when to try again. The count is kept in memory, so a restart clears it; that is fine for a limit whose job is to stop one person reading the audit log in a loop. Admins' routes aren't limited.

### In the app

Settings gains a **Data residency** card, shown only when a pin holds the person's data, or not at all on servers from before this. It says where their data is pinned and under which agreement (as above), whether their computer and backups are in the region, and whether their Bots use models there; anything outside, or a plan with no model in the region, shows as a warning. It says plainly that chats and accounts stay where the server runs, which is what a pin doesn't cover. A button per report downloads it as Markdown: a browser download on the web, the share sheet on phones. A team member without a report is told the team's owners and admins can get it.

### What it doesn't do

- **No pinning or unpinning in the app.** That stays a server admin's act, with a reference and a reason (ADR 0129).
- **No team member sees another member's data.** Only team owners and admins get the team's report, and members' own pins' reports are theirs.
- **No push or email when a pin can't be kept.** The warning shows when they open Settings; admins still get it at startup and in `GET /api/regions`.

## Consequences

- A customer's own people can check their pin and fetch evidence when they want to, with no ticket to the provider, and the provider's audit log records each fetch.
- The DPA's evidence clause can point at the app as well as the admin command.
- The report is now reachable by non-admins, so its contents matter more: it already names only the covered people and counts, never chats, prompts or IP addresses (ADR 0155).

## Tests

- Unit (`residency_me.rs`): the per-person sliding window, its wait time, and forgetting people with nothing in it.
- End to end on the real router with the in-memory Linode provider (`residency_me_http_tests.rs`):
  - a user with no pin sees none and has no report; once pinned she sees the region, reference, status, machine, backups and the open plan's route gap, and gets her report as JSON and Markdown, audited with her as the actor and `selfService`, while an admin's report on her pin isn't; bad `on`, format and periods are refused without counting; the 6th report in 10 minutes is refused with 429 and admins aren't limited; an unpinned read-only user sees nothing; a Bot's token gets neither route;
  - a team pin shows to a member with no reference and no report (403 for the team's), and to its owner with the reference and the team's report covering both members; a member's own agreeing pin shows as `ownPin` and gets its own report.
- RBAC table (`rbac.rs`): both routes are `account`; other methods and paths under them stay admin.
- Client: the card's text for own and team pins, warnings, and the file name (`residency.test.ts`); the card hidden without a pin, downloading a report as Markdown, a member told who can get the team's, and a refused download explained (`ResidencyCard.test.tsx`); the API calls (`api.test.ts`); saving Markdown on phones and the web (`saveCsv.test.ts`).
