# Runbook: data residency pins

Something is refused for a person or team pinned to a data region, or a pin can't be made ([ADR 0129](../adr/0129-contractual-data-residency.md)). A pin holds machines, backups and restores to its region whatever else is set, and refuses rather than lets data leave. Severity: [2](severity.md#severities) if a pinned team's backups are refused (they're heading past their RPO), 3 for one machine or restore, 4 for a pin that can't be made yet; 1 if data left the region while pinned.

## First five minutes

1. **Who and what.** The person or team, the region and the agreement reference, and what was refused (a new machine, a backup, a restore, a region change, someone joining the team).
2. **What botd sees:**

   ```sh
   botctl regions                         # regions, hosts and backup stores in each, pins, and residency warnings
   botctl user residency <user>           # the pin that holds their data (their team's first) and their own
   botctl team residency <team>
   ```

   `residency.warnings` lists every pin botd can't keep right now, and every pinned person with data outside the region. botd logs the same at startup.
3. **What the audit log says:**

   ```sh
   botctl audit 50 --action machine.residency_refused,user.residency_*,team.residency_*
   ```

   A refusal names the `action` (`create`, `backup`, `restore`, `move`, `recover`) and the `error`.
4. **What changed:** a host's region tag removed, a backup store removed or `MACHINE_BACKUP_S3_DATA_REGION` changed, a restore onto a named host, the person joined a team pinned elsewhere.

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

A pin covers machines and their backups only. botd's own database and server backups, and model calls, stay where they are ([what a pin doesn't cover](../adr/0129-contractual-data-residency.md#what-a-pin-doesnt-cover)). A customer asking about those needs the [DPA annex](../security/dpa-template.md#annex-iv-data-residency), not a ticket fix.

## Escalate when

- Data of a pinned person or team is found outside the region (a machine, a backup, a restore) with no refusal in the audit log: a breach of the agreement, [Severity 1](escalation.md#security-incidents), and the customer's DPA notice terms apply.
- A refusal persists after `botctl regions` shows a tagged host and a store in the region.
- The customer wants a pin removed without a reason, or by someone who isn't their admin.

## Afterwards

Note the cause in the ticket and in the customer's record. If a store or a host tag was removed by a change on the Provider's side, add a check for pinned regions to that change's procedure. Tell the TAM ([TAM programme](tam.md)): residency is in the customer's agreement.
