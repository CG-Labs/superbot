# Runbook: data residency pins

Something is refused for a person or team pinned to a data region, or a pin can't be made ([ADR 0129](../adr/0129-contractual-data-residency.md)). A pin holds machines, backups, restores, their Bots' model calls ([ADR 0139](../adr/0139-in-region-model-routes.md)) and the computer their runs take place on ([ADR 0267](../adr/0267-runs-on-a-computer-in-the-pins-region.md)) to its region whatever else is set, and refuses rather than lets data leave. Severity: [2](severity.md#severities) if a pinned team's backups are refused (they're heading past their RPO) or every run of a pinned team is refused, 3 for one machine, restore or Bot, 4 for a pin that can't be made yet; 1 if data left the region while pinned.

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
| A pin, `server_data_outside` | `RESIDENCY_SERVER_DATA=require`, and botd's own database (`SERVER_DATA_REGION`) or its server backups' off-host store isn't in that region | Pin only to botd's own region. A customer in another region needs a botd there ([ADR 0184](../adr/0184-botds-own-data-region.md)) |
| A pin, `pinned` or `team_pinned` | Already pinned elsewhere | Unpin first, with a reason: `botctl user residency <user> unpin <reason...>` |
| A backup, `machine.residency_refused` action `backup` | No store in the region any more, or the machine isn't in it | Restore the region's store; until then backups are skipped, and the RPO alert and the [health score](health-score.md#backups) show it |
| A new machine, action `create` | Hosts in the region aren't tagged, or are all full or drained | Tag or add a host in the region (`botctl machine hosts`) |
| A restore or recovery, action `restore`, `move` or `recover` | The backup's store or the target host isn't in the region | Restore from a backup in the region, onto a host tagged with it |
| Joining a team, `team.join_refused` | The person's own region or data is elsewhere | Move their data into the team's region first |
| A Bot's run, `bot.run_refused` reason `residency_pinned` | The plan has no route for the Bot's harness whose endpoint lists the region in `regions`: an open tier (`"routes": "any"`), a Claude Code or Codex route with no endpoint, or the endpoints aren't marked | Give the plan a route for that harness to an endpoint whose provider processes in the region, and list the region in that endpoint's `regions` ([ADR 0139](../adr/0139-in-region-model-routes.md#marking-endpoints)): Hermes Agent takes `anthropic-messages` or `openai-chat`, Claude Code `anthropic-messages`, Codex `openai-responses` ([ADR 0192](../adr/0192-in-region-claude-code-and-codex-routes.md)). Or move the person to a plan that has one. Mark an endpoint only if the provider's terms promise processing there ([DPA IV.4](../security/dpa-template.md#iv4-model-providers)). Don't unpin to make it run |
| A Bot's run, `bot.run_refused` reason `residency_pinned` with `runsOn` | The run would take place on a computer outside the region: `server` (routing off, or the owner has no assigned machine, and `SERVER_DATA_REGION` isn't the region) or `machine` (the owner's machine, or its host, is in another region; usually a pinned teammate asking a shared Bot) | Route the person's Bots to a machine in the region (`MACHINE_ROUTING=on`, or `assigned` with their machine assigned). If botd itself runs in the region, set `SERVER_DATA_REGION` to say so. A teammate pinned elsewhere uses a Bot whose owner's machine is in their region. Don't unpin to make it run ([ADR 0267](../adr/0267-runs-on-a-computer-in-the-pins-region.md)) |
| A queued run, same reason with `whileQueued: true` | Pinned while the run waited for a slot | Send the message again; it takes the held route, or is refused as above |
| botd itself won't start, `residency.startup_refused` | `RESIDENCY_STARTUP=refuse`, and a pin's region lost a host tag or backup store, some of its data is outside it, or (with `RESIDENCY_SERVER_DATA=require`) botd's own data region isn't the pin's. The log line and the audit entry name each pin and why | Put back the tag, store or region. If the customer agrees to end the pin instead: start with `RESIDENCY_STARTUP=warn`, unpin with a reason, and switch back ([ADR 0171](../adr/0171-residency-startup-and-leavers.md)) |
| botd itself won't start, `Server data region: ...` | `RESIDENCY_SERVER_DATA=require` with no `SERVER_DATA_REGION`, or server backups copied to a store not said to be in it | Set `SERVER_DATA_REGION`, and `SERVER_BACKUP_S3_DATA_REGION` (or `MACHINE_BACKUP_S3_DATA_REGION` for the machines' store) once the store is in that region ([ADR 0184](../adr/0184-botds-own-data-region.md)) |
| botd itself won't start, `Regional chat stores: ...` | A `REGION_DATA_DIRS` folder isn't mounted (a recorded store is missing), holds another store or file, a region dropped from the setting still holds chats, routines or approvals or its store is gone, the store doesn't open with botd's key, or approvals in it are sealed under another master key ([rotation guide](../ops/master-key-rotation.md#if-something-goes-wrong)). The log line names the region and file | Mount the region's volume back, or put the setting back. Never start botd on an empty folder in its place: chats in the missing store would look gone. If the volume is lost, [restore the store](#restoring-a-regional-chat-store) onto a new one. Only if a dropped region's chats are lost for good (and the customer is told): `REGION_DATA_FORGET=<region>` ([ADR 0215](../adr/0215-pinned-chats-in-a-store-in-their-region.md)) |
| botd itself won't start, `Regional chat stores: <region>'s chat store's backups were copied to ...` | A region's `REGION_DATA_S3_<REGION>_*` bucket or `REGION_DATA_S3_PREFIX` changed or was unset, so copies made before may still hold rows that left the store | Put the setting back, or delete the earlier copies (the message names where they are) and start botd once with `REGION_DATA_S3_FORGET=<region>`, then remove it ([ADR 0246](../adr/0246-copying-store-backups-off-the-host-in-their-region.md)) |
| A pin is `data_outside` with `their Bots have <n> chat messages, routines or approvals in botd's own database, not <region>'s chat store` | Moving them into the store failed (disk full, permissions); botd's log has the error | Fix the folder; the next reconcile pass moves them ([ADR 0215](../adr/0215-pinned-chats-in-a-store-in-their-region.md), [ADR 0228](../adr/0228-routines-and-approvals-in-the-regional-store.md)) |
| A residency warning, `chat store has no backup from the last day`, or `residency.chat_store_backup_failed` | The daily backup into the region's `<folder>/backups/` failed (disk full, permissions); the entry's `error` says why | Free space or fix the folder; botd tries again each hour ([ADR 0215](../adr/0215-pinned-chats-in-a-store-in-their-region.md)) |
| A residency warning, `chat store's backups may still hold the rows of <n> Bots that left it`, or `residency.chat_store_backups_cleared` with outcome failure | Rewriting a store's backups without the rows of Bots that moved out failed: a backup doesn't open with botd's key (one from before a master key rotation), fails its integrity check, or the folder is full; the entry's `error` names the file | Free space or fix the folder; botd tries again each hour. A backup from before a rotation can't be cleared and goes once it is older than the newest `REGION_DATA_BACKUPS`; delete it sooner if the customer asks, after checking a newer backup restores ([ADR 0238](../adr/0238-clearing-moved-rows-from-store-backups.md)) |
| A residency warning, `chat store's backups couldn't all be copied off the host`, `residency.chat_store_backups_copied` with outcome failure, or `residency.chat_store_backups_cleared` failing with `the backups' copies off the host` | Copying a store's backups to its region's `REGION_DATA_S3_<REGION>_BUCKET` failed: the bucket's endpoint or keys are wrong, it refuses writes or deletes (Object Lock, a retention rule, keys without delete rights), or the backups folder can't be read; the entry's `error` says which | Fix the bucket or its keys; botd tries again each hour, and moves out of the store stay listed as earlier copies until a pass succeeds. Nothing is copied anywhere else meanwhile ([ADR 0246](../adr/0246-copying-store-backups-off-the-host-in-their-region.md)) |
| A SCIM removal answers 500, or a leave is refused, with `team.member_leave_failed` | Keeping the team's pin on the leaver's data failed (a database error, in the entry's `error`); they're still on the team, held by its pin | Fix the database (disk, permissions); the IdP retries, or remove them again ([ADR 0171](../adr/0171-residency-startup-and-leavers.md)) |
| Someone who left a team is refused a region change or another team | They kept the team's pin as their own when they left (`user.residency_pin_kept`; `keptFrom` on their pin), so their old machine and backups stay held | It ends by itself on the reconcile pass after their machine is destroyed and its backups are deleted (`user.residency_pin_ended`, [ADR 0205](../adr/0205-ending-a-kept-pin-once-the-data-is-gone.md)); `botctl user residency <user> report` shows what's left. With `RESIDENCY_KEPT_PINS=keep`, or if the customer says the agreement no longer covers them sooner: `botctl user residency <user> unpin <reason...>` |

A pin's chats, routines, approvals, Bots' memory, owners' facts and sign-in sessions (with their SAML sign-ins and push devices) are kept in its region when that region has a chat store (`REGION_DATA_DIRS`; the report's "Chats, routines, approvals and memory" section, [ADR 0215](../adr/0215-pinned-chats-in-a-store-in-their-region.md), [ADR 0228](../adr/0228-routines-and-approvals-in-the-regional-store.md), [ADR 0276](../adr/0276-bots-memory-in-the-regional-store.md), [ADR 0277](../adr/0277-owners-facts-in-the-regional-store.md), [ADR 0283](../adr/0283-sign-ins-in-the-regional-store.md)). A pinned person's Bot's `MEMORY.md` or their own `USER.md` left in `DATA_DIR`, or a session of theirs left in botd's own database, makes the pin `data_outside` until the next reconcile pass moves it into the store. A pin covers botd's own database and server backups only as far as the operator states them to be in its region (`SERVER_DATA_REGION`; the report's "botd's own data" section and `residency.serverData` in `GET /api/regions` show it, and `RESIDENCY_SERVER_DATA=require` holds every pin to it, [ADR 0184](../adr/0184-botds-own-data-region.md)). It doesn't cover what a Bot's own tools send (a script calling an API with a saved key; [egress allow-lists](runbook-run-limits-egress.md) are the control there) ([what a pin doesn't cover](../adr/0129-contractual-data-residency.md#what-a-pin-doesnt-cover), [ADR 0139](../adr/0139-in-region-model-routes.md#not-covered)). A customer asking about those needs the [DPA annex](../security/dpa-template.md#annex-iv-data-residency), not a ticket fix.

## Restoring a regional chat store

When a region's chat store is lost (its volume gone, or mounted empty) or damaged, restore it from a backup in its folder or a copy in its bucket ([ADR 0256](../adr/0256-restoring-a-regional-chat-store.md)). On the server, with botd stopped, as the user botd runs as (`sudo -u superbot ...` on the installer's layout; it refuses another user, root included):

```sh
botd chat-store list gb-lon                                   # the store, its backups and its bucket's copies
botd chat-store restore gb-lon newest                         # what a restore would do; changes nothing
botd chat-store restore gb-lon newest --identity ops.key --yes  # restore (--identity for age-encrypted copies)
```

Add `--home <dir>` or `--env-file <file>` to read botd's settings as `botd support check` does. Mount the region's volume first (an empty one is fine), and restore botd's own database first if it is lost too ([server restore](runbook-server-restore.md)).

The backup must be this region's store, open with the master key (or the previous one), and pass its integrity check; a bucket copy must match its SHA-256. Before it replaces the store, the rows of Bots kept elsewhere now (moved out, or deleted) are taken out of it and erasures made since are run on it again, so a restore never undoes a move or an erasure. Its sign-in sessions are replaced by those of the store it replaces, so a session revoked since stays revoked; if that store is missing or doesn't open, they are dropped and those people sign in again ([ADR 0283](../adr/0283-sign-ins-in-the-regional-store.md)). The store it replaces is kept in `backups/`, so a restore can be undone the same way. botd audits it as `residency.chat_store_restored` at its next start.

| Refused | Why | Fix |
|---|---|---|
| `belongs to uid ...` | Run as another user (root, say), whose files botd couldn't open | Run it as the owner of `DATA_DIR` and the folder: `sudo -u superbot botd chat-store ...` |
| `botd must be stopped` | botd, or another restore, holds the lock | Stop botd (`sudo systemctl stop superbot`; Compose: `docker compose stop botd`) |
| `holds ... of Bots kept elsewhere now that botd hasn't moved yet` | A move out of the store is waiting | Start botd, let it move them (the pin's report shows when), stop it, restore |
| `didn't keep which Bots it deleted` | Someone was erased after the backup by an earlier botd, so botd can't tell which Bots their erasure deleted | Restore a backup made after that erasure |
| `is <region>'s chat store, not ...` or `is of chat store <id>` | The backup is another region's, or an earlier store's in the folder | Pick this store's backup (`list` shows them) |
| `doesn't open with the master key or the previous one` | Made under a master key botd no longer has | Restore a newer backup, or set `SUPERBOT_MASTER_KEY_PREVIOUS` to that key |
| `saved tool inputs of approvals in that backup don't open` | Its approvals were sealed under a master key botd no longer has, so botd wouldn't start | Set `SUPERBOT_MASTER_KEY_PREVIOUS` to that key, or, if it's lost, set `SUPERBOT_FORGET_SEALED=1` so botd drops them at start |
| `give the identity ... --identity` or `doesn't open this copy` | The copy is age-encrypted to other recipients | Give the identity matching `REGION_DATA_AGE_RECIPIENTS` when it was made |
| `the store now doesn't open` | The store is damaged | Add `--replace-unreadable`: it is deleted, not kept |

Routines that come back run on their schedule once botd starts; the command says so. What was written since the backup is lost; tell the customer, with the dry run's counts.

## Escalate when

- Data of a pinned person or team is found outside the region (a machine, a backup, a restore) with no refusal in the audit log: a breach of the agreement, [Severity 1](escalation.md#security-incidents), and the customer's DPA notice terms apply.
- A refusal persists after `botctl regions` shows a tagged host and a store in the region.
- The customer wants a pin removed without a reason, or by someone who isn't their admin.

## Afterwards

Note the cause in the ticket and in the customer's record. If a store or a host tag was removed by a change on the Provider's side, add a check for pinned regions to that change's procedure. Tell the TAM ([TAM programme](tam.md)): residency is in the customer's agreement.
