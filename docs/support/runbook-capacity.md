# Runbook: host capacity

New machines can't be made because no Incus host has room, the hosts are nearly full, a machine sits on a host its team's dedication doesn't allow, or a host (botd's own included) runs short of memory, disk or CPU. Severity: [1](severity.md#severities) when botd's own host's disk is nearly full, since botd's database stops taking writes; 2 when no host is open, machines wait for room for many people, or an Incus host's disk is nearly full, since its machines' writes fail; 3 for one machine waiting, hosts nearly full but still placing, a misplaced machine, a host short of memory or CPU, or stale readings.

The setup is in [per-user containers on Incus](../ops/incus-containers.md#several-hosts), and how placement works in [ADR 0081](../adr/0081-placing-machines-by-host-load.md); this page is the order to work in.

## First five minutes

1. **Which host, which resource.** As an admin on the server:

   ```sh
   botctl machine hosts               # each host: open or why not, machines, allocated, capacity, free; misplaced machines
   botctl machine hosts check         # the same after checking each host now
   botctl audit 50 --action machine.placement_failed
   ```

   The alert names the host and the resource. With metrics on, the capacity dashboard ([`superbot-capacity.json`](../../deploy/grafana/superbot-capacity.json)) shows allocation against `INCUS_CAPACITY` and what each host says it uses, side by side. A support bundle has the week's `machine.placement_failed` in `audit-summary.json`, and [bundle triage](triage.md) lists them as `audit.capacity`, pointing here.
2. **Allocation or use.** Placement counts what machines' plans take against `INCUS_CAPACITY` and `INCUS_MAX_MACHINES`, from botd's own records; a host's memory, disk and load are what the host says it uses. A host can be full by allocation and idle, or within its allocation and out of disk (snapshots and a restore's second copy aren't in any plan). Which one fired decides the section below.
3. **Did anything change?** New customers or a team onboarding, a tier's plan made bigger, a host drained for maintenance and not undrained, a host down or declared lost, a team given hosts of its own, someone joining or leaving a team, `INCUS_CAPACITY` or `INCUS_HOSTS` edited, a residency pin to a region with one host.

## No room for new machines

`SuperBotMachinesWaitingForRoom` (a page) and `SuperBotNoOpenIncusHost` (a page) mean someone has no computer now; `SuperBotMachineRequestsRefusedForRoom` means a request was refused in the last 15 minutes; `SuperBotIncusCapacityLow` means less than 15% of the open hosts' CPUs, memory, disk or machine count is left, so the next requests may be refused. A request with no room is refused (409) before anything is recorded; a machine the reconciler retries waits pending, said once, and is made as soon as there is room. Both are audited as `machine.placement_failed`, whose `error` names each host and why it can't take the machine:

| What the reason says | Means | Fix |
|---|---|---|
| `has 3 of 16 CPUs free, 4 needed` (or memory, disk) | The host's `INCUS_CAPACITY` (or `INCUS_CAPACITY_<NAME>`) is allocated | Add a host to `INCUS_HOSTS`, raise the capacity if the host really has room (CPUs may be overcommitted; memory shouldn't be), or free room: destroy machines nobody uses, or resize down |
| `has 40 of 40 machines` | `INCUS_MAX_MACHINES` reached | As above, or raise the limit if the host's use allows |
| `is drained` | An admin closed it to anything new (`machine.host_drained` says who and why) | `botctl machine host undrain <name>` once its maintenance is done |
| `didn't answer its last check` | The host is failing its checks | `botctl machine hosts check`; if it stays down, [a whole Incus host](runbook-machine-down.md#a-whole-incus-host) |
| `is down`, `was declared lost` | The host is down, or was recovered elsewhere | [A whole Incus host](runbook-machine-down.md#a-whole-incus-host). A lost host takes nothing new until it's configured again |
| `is in gb-lon` | The machine's data stays in another region, and hosts are tagged ([ADR 0117](../adr/0117-uk-eu-data-regions.md)) | Add room in the machine's region. Never move a pinned customer's machine out of it ([residency](runbook-residency.md)) |
| `is dedicated to another team` | Only that team's machines go there ([ADR 0166](../adr/0166-incus-hosts-dedicated-to-a-team.md)) | Room on a shared host, or on the team's own |
| `is shared, and this team's machines go only on its own hosts` | The team has hosts of its own, and none has room | Add room on its hosts, or dedicate another (`botctl machine host dedicate <name> <team-id>`) |
| `none is configured` | No Incus host at all | `INCUS_HOSTS`, or the single host's settings ([Incus](../ops/incus-containers.md#5-botd)) |

Once there's room, waiting machines are made on the next reconcile, and refused requests can be sent again: tell the people whose requests were refused (the event's target is the user).

## Machines on another team's host

`SuperBotMachinesOnAnotherTeamsHost`: a machine is on a host dedicated to another team, or on a shared host while its team has hosts of its own. Placement never puts one there; it happens when the owner joins or leaves a team, since the machine stays where it was. `botctl machine hosts` lists each under `misplaced` with the reason. For a customer who bought dedicated hosts, another team's machine on them breaks what they were sold: Severity 2 until it's moved.

Move each with a restore onto the right host, which makes it again from its newest backup and deletes the old container once the copy is ready: `botctl machine backups <user>`, then `botctl machine restore <user> <backup-id> --host <name> --yes`. Anything since that backup is lost, so take a fresh one first (`botctl machine backup <user>`) and tell the user.

## A host is short of memory, disk or CPU

What hosts say they use, botd's own (`host="botd"`, `kind="server"`) included:

| Alert | Means | Do |
|---|---|---|
| `SuperBotHostMemoryHigh` | Over 90% of memory used for 15 minutes | On an Incus host, containers may be OOM-killed under load: lower its memory in `INCUS_CAPACITY` so placement stops adding, and move machines off. On botd's host, check what else runs there |
| `SuperBotHostDiskFilling` | Over 85% of a disk used | On an Incus host, snapshots and a restore in place's second copy count here but not in `INCUS_CAPACITY`: delete old snapshots, grow the pool, or lower its disk capacity. On botd's host, `DATA_DIR` holds the database, Bot memory and on-host backups: `botd support check` shows each, and old archives can go once their copies are off the host ([backups](runbook-backups.md)) |
| `SuperBotHostDiskFull` | Over 95% used: writes will soon fail | Free space now. On botd's host, botd's database and backups stop first, so the whole service follows: Severity 1, page and post on the status page. Don't delete `app.sqlite*` files or the newest archives to make room |
| `SuperBotHostCPUSaturated` | A 5-minute load over 1.5 per CPU for 30 minutes, so runs there are slow | Lower its CPUs in `INCUS_CAPACITY` (they may be overcommitted) and move machines off, or find the machine using them (`incus list` on the host, sorted by CPU) |

Moving a machine off is the restore onto another host above. Drain the host first (`botctl machine host drain <name> --reason <text>`) so nothing new lands while you do, and undrain it after.

## A host's readings are stale

`SuperBotIncusHostReadingStale`: a host answers botd's checks but hasn't said what it uses for over 15 minutes, so its memory, disk and load metrics keep their last reading and the alerts above can't see it. botd's log says why: `Incus host <name> didn't say what it uses (...)`. Usually the certificate's project can't read the host's resources or storage pool, or the host's Incus was upgraded. Placement is unaffected: it counts plans, not use.

## Before telling the customer it's fixed

1. `botctl machine hosts` shows an open host with room for the plans being asked for, and no machine `misplaced`.
2. No machine waits for room: `botctl machine list pending` has none whose last error starts "No Incus host", and new requests succeed.
3. The host's disk, memory or load is back under its alert, on the dashboard, for at least the alert's own time.

## Escalate when

- Machines wait for room while `botctl machine hosts` shows a host open with room for their plan.
- A disk keeps filling after old snapshots and archives are gone.
- A pinned customer's region has no host with room and none can be added there soon: their machines can't be made anywhere else, by design.
- A dedicated customer's host has another team's machine on it and it can't be moved: tell their TAM.

## Afterwards

Note the cause in the ticket. If hosts ran out, record the growth with the customer's TAM, who plans capacity with them at the next business review; a Provider adds a host before `SuperBotIncusCapacityLow` fires, not after. If a drain was left on, add undraining to the maintenance's checklist.
