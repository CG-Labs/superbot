# 0129: Contractual data residency

## Status

Accepted (22 Nov 2026). The first slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0117](0117-uk-eu-data-regions.md) (UK and EU data regions), [ADR 0071](0071-off-host-machine-backups.md) (off-host machine backups), [ADR 0076](0076-restoring-onto-another-incus-host.md) (restoring onto another Incus host) and [ADR 0087](0087-team-accounts-and-machines.md) (teams). Adds the [DPA residency annex](../security/dpa-template.md#annex-iv-data-residency) and the [DPIA template](../security/dpia-template.md).

0122 to 0128 are reserved by other work in flight. 0129 was free on `main` when this was written.

## Context

ADR 0117 lets an admin give a user or a team a data region, such as London (`gb-lon`) or Frankfurt (`de-fra-2`). Machines are made only there and their backups go to that region's store. That is a setting, not a promise:

- Any admin can change or clear the region at any time. The change is refused only while a machine is elsewhere.
- With `MACHINE_BACKUP_RESIDENCY=warn` (the default), a region without its own store sends its backups to the default store, wherever that is.
- `strict` fixes that for the whole server, but a provider with one EU customer may not want to stop every other customer's backups because one region has no store.
- Nothing records which agreement a region was set under, or who may undo it.

A customer who signs a DPA saying "UK only" needs the product to hold to it for them, whatever other settings say, and needs evidence that it did.

## Options

1. **Tell operators to set `MACHINE_BACKUP_RESIDENCY=strict`.** Server-wide, and it still lets any admin change a region with no record of why.
2. **A per-tenant pin, on top of the region** (chosen). Strict for that tenant only, held until someone unpins it with a reason.
3. **A separate deployment per contract.** Full isolation, including botd's own database. It stays the answer for enterprise dedicated hosting (M5), not for every residency customer.

## Decision

### A pin

- A server admin pins a user (`PUT /api/users/{key}/residency`) or a team (`PUT /api/teams/{id}/residency`) with `{"region": "<id>", "reference": "<the agreement>"}`.
- The region must be one of `MACHINE_REGIONS`. The reference is free text, up to 200 characters, such as a DPA number. Both are stored in a new `residency_pins` table with who pinned it and when.
- Pinning sets the user's or team's data region (ADR 0117) to the pinned region. The same region again replaces the reference.
- `DELETE` on the same path with `{"reason": "..."}` unpins. The reason is required and audited. The data region stays as it was; it can be changed from then on.
- The routes are admin-only. They aren't in the role table, so the router's default (admin) applies.
- A user's data is held by their team's pin, else their own. A member's own pin must agree with their team's, and still holds their own region while the team's is in place, so it survives the team being unpinned.

### A pin is refused unless the region can keep it

A pin is refused (409, `user.residency_pin_refused` or `team.residency_pin_refused`) when:

- **`region_not_ready`**: the region isn't offered; Incus hosts aren't tagged with regions, or none is in this region; or off-host backups are on and no store is in the region (its own, or the default store said to be there with `MACHINE_BACKUP_S3_DATA_REGION`).
- **`data_outside`**: the person's machine, or any backup of theirs that isn't deleted, is outside the region. A machine counts by its record and by its host's tag now, since one made before hosts were tagged may be on any host; a host with no tag counts as outside. A failed backup counts, because its upload may have finished before it failed; deleting the backups ([ADR 0108](0108-deleting-a-destroyed-machines-backups.md)) clears it. For a team, this is checked for every member, and also refused if a member has their own region or own pin elsewhere. The error lists who and why.
- **`pinned`** or **`team_pinned`**: they are already pinned to another region. Unpin first, with a reason.
- **`team_deleting`**: an admin is deleting the team. The delete marks the team under the same operations lock a pin takes, after checking it has no pin, so a pin can't land on a team mid-delete and be removed with it unaudited.

So a pin is never a promise about data that has already left. The operator makes it true first (destroy and purge, as in ADR 0117), then pins.

### While pinned

Every path that places or copies their data checks the pin. A refusal is a 409, and machine refusals are audited as `machine.residency_refused` with `{reason: "residency_pinned", action, pinnedRegion, pinnedOn, reference, error}`, outcome denied.

| Path | Refused when | Audit |
|------|--------------|-------|
| Changing the user's or team's region | It would move away from the pin, or clear it | `user.region_change_refused` / `team.region_change_refused`, reason `residency_pinned` |
| Joining a pinned team | The new member's own region or pin is elsewhere, or any of their data is outside | `team.join_refused`, reason `residency_pinned` |
| Deleting a pinned team (admin) | Always, until unpinned | `team.delete_refused`, reason `residency_pinned` |
| A new machine (asked for, or retried by the reconciler) | It would be outside the region, or Incus hosts aren't tagged with regions (placement keeps to a region only when they are) | `machine.residency_refused`, action `create` |
| A backup | The machine isn't in the region, or no store is in the region. This holds even with `MACHINE_BACKUP_RESIDENCY=warn` | `machine.residency_refused`, action `backup` |
| A restore | The backup's recorded store isn't in the region | action `restore` |
| A restore onto a named host | As above, or the host isn't tagged with the region | action `move` |
| Recovering a lost host | As above, for each pinned machine; it is skipped and listed with the reason | action `recover` |

Placement (ADR 0117) keeps new machines on hosts in the region, but only while hosts are tagged. If the tags are removed after a pin is made, botd only warns at startup, so a new machine for a pinned person is refused on every attempt until they are back. A machine waiting this way stays pending and is audited once.

Scheduled backups of a pinned machine that can't stay in the region are skipped and not audited each time. The reason shows in the backups view and in the RPO alert ([ADR 0074](0074-machine-rpo-and-rto.md)). Only backups an admin asks for are audited as refused.

### Erasure

Erasing a user ([ADR 0102](0102-erasing-a-users-data.md)) deletes their own pin, replaces them as `pinnedBy` with their pseudonym, and scrubs their names and emails from other pins' references, as it does the audit log.

### Startup warns; it doesn't refuse

botd logs a warning at startup for each pin its settings can't keep (for example, a store removed after the pin was made), and for each pinned person with data outside the region. `GET /api/regions` shows the same list under `residency.warnings`.

botd still starts. Refusing to start would take every other tenant down for one tenant's missing store. Each action on the pinned tenant's data is refused instead, which is fail-closed for that tenant. A server-wide startup refusal is still available with `MACHINE_BACKUP_RESIDENCY=strict`.

### Where it shows

- **API**: `residency` (the pin that holds their data, the team's first, or null) and `ownResidency` (the user's own pin, which can be unpinned on its own) on users (`GET /api/users`, `/api/users/{key}`), on `GET /api/users/{key}/region` and `/residency`, on teams (the reference only for admins and those who manage the team's members), and on `GET /api/teams/{id}/region`. `GET /api/regions` counts pinned users and teams per region and lists every pin.
- **botctl**: `botctl user residency <user> [pin <region> <reference...> | unpin <reason...>]`, and the same for `team`.
- **Console**: the pin and a Pin region / Unpin button on Users and Teams; pinned counts and residency warnings in the Machines regions line.

### What a pin doesn't cover

Said plainly in the [DPA annex](../security/dpa-template.md#annex-iv-data-residency) and the [subprocessor list](../security/subprocessors.md):

- **botd's own data.** The database (accounts, chats, routines, the audit log), its files and server backups stay where the operator runs botd. Running botd in the same country is the operator's part.
- **Model calls.** The harness sends prompts, conversation, tool output and file contents to the model provider its tier routes to. A pin doesn't change or check that route. As of November 2026:
  - Anthropic's own API offers US-only processing or global; there is no UK or EU option there. UK or EU processing of Claude models needs a cloud platform with a regional endpoint (Amazon Bedrock, Google Vertex AI, Microsoft Foundry) in the tiers file.
  - OpenAI offers per-project data residency to eligible API customers: Europe (storage and processing in the EEA or Switzerland) and the UK (storage in the UK; processing isn't promised to stay there). It needs an arrangement with OpenAI and the regional API host in the tiers file.
  - Routers such as OpenRouter forward to upstream providers; treat them as having no region unless their own terms say otherwise.
  - Harness logins with a person's own subscription go to that provider under their account, wherever it processes.
- **Other services.** Push, email, webhooks, Stripe and sign-in providers are wherever Annex III says.
- **Leaving a team.** A member who leaves a pinned team is no longer held by its pin. Their machine and backups stay where they are, and their region becomes their own or the default, as ADR 0117 says. Pin them individually first if the agreement covers them after they leave.
- **Other team deletions.** A team deleted because its last member left or was erased, or by the identity provider (a SCIM group delete), takes its pin with it; members leave as above. Only an admin's delete is refused.

## Consequences

- A provider can promise "UK only" or "EU only" for a tenant's machines and backups, hold to it without making the whole server strict, and show it: the pin, its reference and every refusal are in the audit log.
- A pinned tenant whose region loses its store stops getting backups, with warnings and RPO alerts, rather than having them go elsewhere. That is the choice a residency contract asks for. Operators fix the store, or unpin with the customer's agreement.
- Moving a pinned tenant is two audited steps (unpin with a reason, then the ADR 0117 move), never a side effect.
- Model-provider residency stays the operator's routing choice. The DPA annex makes the operator name the providers and regions, and says when processing may leave.

## Follow-ups (in [#58](https://github.com/CG-Labs/superbot/issues/58))

- Hold a pinned tenant's model routes to providers and endpoints the operator marks as in the region, and refuse runs otherwise. **Done** in [ADR 0139](0139-in-region-model-routes.md).
- A data region for botd's own database and server backups, or a documented dedicated deployment per region (enterprise dedicated hosting, M5).
- Show the pin to the customer in the app.
- An option to refuse startup when a pin can't be kept.
- Keep a leaver's pin, or refuse the leave or a SCIM group delete, when the agreement says so.

## Tests

- Unit tests (`residency.rs`): request validation, when a region is ready, and which store a backup is in.
- End to end, against the Incus stand-ins, the S3 stand-in and the fake Linode (`machines_residency_tests.rs`):
  - pin, renew and unpin, each audited; only admins; region and reference checked;
  - a pin refused while a machine is elsewhere, while a failed backup is in another region's store, and while the region has no store;
  - region changes away from a pin refused and audited;
  - a restore onto a host in another region refused before anything is made, audited as a move;
  - with the region's store gone, a pinned backup and restore refused and audited, startup warnings shown, and a lost host's pinned machine skipped and audited, never made elsewhere;
  - a team pin refused while a member's machine is elsewhere; once pinned, the team's and members' regions held, joins with data elsewhere refused, a member's own pin holding her region under the team's, and the team not deleted until unpinned;
  - erasure removing the person's pin and their email from a team pin's reference.
- A unit test for the mark that keeps pins off a team being deleted (`teams.rs`).
- botctl's commands (`residency_commands`).
- The security pack's checks (`security_docs_links.rs`) cover the DPA's residency annex and the DPIA template.
