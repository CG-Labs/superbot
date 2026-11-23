# Runbook: data residency pins

Something is refused for a person or team pinned to a data region, or a pin can't be made ([ADR 0129](../adr/0129-contractual-data-residency.md)). A pin holds machines, backups, restores and their Bots' model calls ([ADR 0139](../adr/0139-in-region-model-routes.md)) to its region whatever else is set, and refuses rather than lets data leave. Severity: [2](severity.md#severities) if a pinned team's backups are refused (they're heading past their RPO) or every run of a pinned team is refused, 3 for one machine, restore or Bot, 4 for a pin that can't be made yet; 1 if data left the region while pinned.

## First five minutes

1. **Who and what.** The person or team, the region and the agreement reference, and what was refused (a new machine, a backup, a restore, a region change, someone joining the team, a Bot's run).
2. **What botd sees:**

   ```sh
   botctl regions                         # regions, hosts and backup stores in each, pins, and residency warnings
   botctl user residency <user>           # the pin that holds their data (their team's first) and their own
   botctl team residency <team>
   ```

   `residency.warnings` lists every pin botd can't keep right now, every pinned person with data outside the region, every pinned person whose plan has no model route in the region for a harness it offers, and every endpoint naming a region that isn't offered. botd logs the same at startup; with `RESIDENCY_STARTUP=refuse` (`residency.startup` in `GET /api/regions`) it doesn't start while a pin can't be kept, and says which.
3. **What the audit log says:**

   ```sh
   botctl audit 50 --action machine.residency_refused,bot.run_refused,user.residency_*,team.residency_*,residency.startup_refused,team.member_leave_failed
   ```

   A machine refusal names the `action` (`create`, `backup`, `restore`, `move`, `recover`) and the `error`. A run refusal has reason `residency_pinned`, the pins, the harness and the `error`; `whileQueued: true` means the pin was made while the run waited for a slot. A held run's `harness.invoked` shows `residency`: the regions, the fallbacks left out and the route it took instead of.
4. **What changed:** a host's region tag removed, a backup store removed or `MACHINE_BACKUP_S3_DATA_REGION` changed, a restore onto a named host, the person joined a team pinned elsewhere, the person moved plan, or an endpoint's `regions` changed in the tiers file (`botctl tiers`).

## Refusals and fixes

| Refused | Usually | Fix |
|---|---|---|
| A pin, `region_not_ready` | The region has no tagged Incus host, or off-host backups are on and no store is in the region | Tag a host in the region and give it a backup store ([data regions](../ops/incus-containers.md#data-regions)); then pin |
| A pin, `data_outside` | Their machine or a backup (failed ones too) is outside the region | Move or rebuild the machine in the region; delete the backups outside it ([ADR 0108](../adr/0108-deleting-a-destroyed-machines-backups.md)); then pin. The error lists who and what |
| A pin, `pinned` or `team_pinned` | Already pinned elsewhere | Unpin first, with a reason: `botctl user residency <user> unpin <reason...>` |
| A backup, `machine.residency_refused` action `backup` | No store in the region any more, or the machine isn't in it | Restore the region's store; until then backups are skipped, and the RPO alert and the [health score](health-score.md#backups) show it |
| A new machine, action `create` | Hosts in the region aren't tagged, or are all full or drained | Tag or add a host in the region (`botctl machine hosts`) |
| A restore or recovery, action `restore`, `move` or `recover` | The backup's store or the target host isn't in the region | Restore from a backup in the region, onto a host tagged with it |
| Joining a team, `team.join_refused` | The person's own region or data is elsewhere | Move their data into the team's region first |
| A Bot's run, `bot.run_refused` reason `residency_pinned` | The plan has no route for the Bot's harness whose endpoint lists the region in `regions`: an open tier (`"routes": "any"`), a Claude Code or Codex Bot (they name no endpoint), or the endpoints aren't marked | Give the plan a Hermes Agent route to an endpoint whose provider processes in the region, and list the region in that endpoint's `regions` ([ADR 0139](../adr/0139-in-region-model-routes.md#marking-endpoints)); or move the person to a plan that has one, and switch the Bot to Hermes Agent. Mark an endpoint only if the provider's terms promise processing there ([DPA IV.4](../security/dpa-template.md#iv4-model-providers)). Don't unpin to make it run |
| A queued run, same reason with `whileQueued: true` | Pinned while the run waited for a slot | Send the message again; it takes the held route, or is refused as above |
| botd itself won't start, `residency.startup_refused` | `RESIDENCY_STARTUP=refuse`, and a pin's region lost a host tag or backup store, or some of its data is outside it. The log line and the audit entry name each pin and why | Put back the tag, store or region. If the customer agrees to end the pin instead: start with `RESIDENCY_STARTUP=warn`, unpin with a reason, and switch back ([ADR 0171](../adr/0171-residency-startup-and-leavers.md)) |
| A SCIM removal answers 500, or a leave is refused, with `team.member_leave_failed` | Keeping the team's pin on the leaver's data failed (a database error, in the entry's `error`); they're still on the team, held by its pin | Fix the database (disk, permissions); the IdP retries, or remove them again ([ADR 0171](../adr/0171-residency-startup-and-leavers.md)) |
| Someone who left a team is refused a region change or another team | They kept the team's pin as their own when they left (`user.residency_pin_kept`; `keptFrom` on their pin), so their old machine and backups stay held | Once their data in the region is gone, or the customer says the agreement no longer covers them: `botctl user residency <user> unpin <reason...>` |

A pin doesn't cover botd's own database and server backups, or what a Bot's own tools send (a script calling an API with a saved key; [egress allow-lists](runbook-run-limits-egress.md) are the control there) ([what a pin doesn't cover](../adr/0129-contractual-data-residency.md#what-a-pin-doesnt-cover), [ADR 0139](../adr/0139-in-region-model-routes.md#not-covered)). A customer asking about those needs the [DPA annex](../security/dpa-template.md#annex-iv-data-residency), not a ticket fix.

## Escalate when

- Data of a pinned person or team is found outside the region (a machine, a backup, a restore) with no refusal in the audit log: a breach of the agreement, [Severity 1](escalation.md#security-incidents), and the customer's DPA notice terms apply.
- A refusal persists after `botctl regions` shows a tagged host and a store in the region.
- The customer wants a pin removed without a reason, or by someone who isn't their admin.

## Afterwards

Note the cause in the ticket and in the customer's record. If a store or a host tag was removed by a change on the Provider's side, add a check for pinned regions to that change's procedure. Tell the TAM ([TAM programme](tam.md)): residency is in the customer's agreement.
