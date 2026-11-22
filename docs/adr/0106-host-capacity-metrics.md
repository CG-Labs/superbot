# 0106: Host capacity metrics, alerts and a dashboard

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row A1.1-1 in the [readiness checklist](../security/soc2-readiness-checklist.md). Builds on metrics and structured logs ([ADR 0089](0089-metrics-and-structured-logs.md)), Incus container machines ([ADR 0065](0065-incus-container-machines.md)), several Incus hosts ([ADR 0076](0076-restoring-onto-another-incus-host.md)) and placing machines by host load ([ADR 0081](0081-placing-machines-by-host-load.md)).

0105 is the highest number on `main`. Open PR [#164](https://github.com/CG-Labs/superbot/pull/164) holds 0102.

## Context

`/metrics` showed machines by state, runs and run slots, but nothing about the hosts they run on. An operator couldn't see an Incus host filling up, or botd's own host running out of disk, before something failed:

- Placement (ADR 0081) knows each Incus host's load: what its machines' plans take against `INCUS_CAPACITY` and `INCUS_MAX_MACHINES`. It used that only to pick a host or refuse a machine. The first sign of a full fleet was a refused request.
- That load is what botd has allocated, not what the host uses. Daily snapshots live on the machines' pool (ADR 0065), a restore in place briefly holds two copies (ADR 0071), and the host itself needs memory. None of that is in a plan, so a pool could fill while placement thought there was room.
- botd's own host holds the database, its backups and, without machines, every user's workspace. Nothing watched its disk.

SOC 2's A1.1 asks for capacity to be measured against demand and acted on; the checklist row asks for metrics of each host's CPU, memory and disk against its capacity, and dashboards.

## Decision

### Allocation: placement's own numbers

At each scrape botd calls `placement::loads`, the function placement uses, and writes one sample per configured Incus host (`host` is its `INCUS_HOSTS` name). Nothing new is collected: it reads botd's records, as `GET /api/machines/hosts` does.

| Metric | Meaning |
|---|---|
| `superbot_incus_host_up` | 1 if the host answered its last check |
| `superbot_incus_host_open` | 1 if new machines may go there: up, answering, not drained |
| `superbot_incus_host_machines`, `superbot_incus_host_max_machines` | Machines on it, and `INCUS_MAX_MACHINES` where set |
| `superbot_incus_host_allocated_{cpus,memory_bytes,disk_bytes}` | What its machines' plans take, restores on their way to it included |
| `superbot_incus_host_capacity_{cpus,memory_bytes,disk_bytes}` | `INCUS_CAPACITY`, where set |
| `superbot_incus_machines_waiting_for_room` | Machines waiting to be made because no host has room |

`machine.placement_failed` joins the audit events counted in `superbot_events_total`, and is written from zero so an alert's `increase()` sees the first one.

### Use: what each host says

The same families for every host, labelled `host` and `kind` (`server` or `incus`):

| Metric | Meaning |
|---|---|
| `superbot_host_cpus` | CPU threads |
| `superbot_host_load1`, `superbot_host_load5` | Load averages |
| `superbot_host_memory_bytes`, `superbot_host_memory_used_bytes` | Memory in all and in use |
| `superbot_host_disk_bytes`, `superbot_host_disk_used_bytes` | Space in all and used, labelled `disk` |
| `superbot_host_reading_timestamp_seconds` | When the host was last read; 0 if never |

- **botd's own host** is `host="botd"`, read at each scrape: online CPUs (`sysconf`), `/proc/loadavg`, `/proc/meminfo` (used is all but `MemAvailable`), and `statvfs` on `DATA_DIR` (`disk="data"`) and on `WORKSPACE_DIR` (`disk="workspace"`, only if it's another filesystem). Disk used is all but what botd may still write, so root's reserved blocks count as used, as `df` shows. In a container, `/proc` shows the Docker host's figures: still the server's host.
- **Incus hosts** are read every `MACHINE_RECONCILE_SECONDS`, each host that is up (ADR 0076): `GET /1.0/resources` (CPU threads, memory, and load with the `resources_load` extension) and `GET /1.0/storage-pools/<pool>/resources` (`disk="pool"`). It runs on its own, apart from host checks and reconciling, reads every host at once and gives each 10 seconds, so a host slow to answer holds up neither the others nor machines. It isn't read at scrape time either, so a scrape makes no network calls. A read that fails or runs out of time keeps the last one, its age shows on the timestamp, it's logged once until a read works again, and it never makes a host down: answering the check decides that.
- **Only with `/metrics` on.** botd reads Incus hosts only when `METRICS_LISTEN` is set, so a server without metrics makes no extra calls. botd's own host is read only when scraped.

### Labels stay bounded

The new label values are the operator's own host names (`INCUS_HOSTS`, plus `botd`), `kind` (`server`, `incus`) and `disk` (`data`, `workspace`, `pool`). No machine, user, address, path or pool name. A lost host's use isn't shown, since it is never called. Series grow with configured hosts only.

### Alerts and a dashboard

[`deploy/prometheus/superbot-capacity.rules.yml`](../../deploy/prometheus/superbot-capacity.rules.yml), tested with `promtool` in CI like the SLO and sign-in rules:

| Alert | When | Severity |
|---|---|---|
| `SuperBotMachinesWaitingForRoom` | A machine has waited for room for 5 minutes | page |
| `SuperBotMachineRequestsRefusedForRoom` | A machine was refused or held back for want of room in 15 minutes | ticket |
| `SuperBotIncusCapacityLow` | Under 15% of the open hosts' CPUs, memory, disk or machines (where capped) is left, for 15 minutes | ticket |
| `SuperBotNoOpenIncusHost` | No host is open for 5 minutes | page |
| `SuperBotHostMemoryHigh` | A host uses over 90% of its memory for 15 minutes | ticket |
| `SuperBotHostDiskFilling`, `SuperBotHostDiskFull` | A disk is over 85% full for 15 minutes, or over 95% for 5 | ticket, page |
| `SuperBotHostCPUSaturated` | Load over 1.5 per CPU for 30 minutes | ticket |
| `SuperBotIncusHostReadingStale` | An Incus host answers but hasn't been read for 15 minutes | ticket |

Room left counts only open hosts: a drained or failing host's room isn't room for anything new. It's measured across each botd's fleet, not per host, because `INCUS_PLACEMENT=fill` fills each host before the next by design. The fleet alerts group by `instance` too: botd servers scraped in one job each place machines on their own hosts, so one's spare room or open host mustn't hide another's. What a host uses is alerted per host. The dashboard shows one botd at a time for the same reason.

[`deploy/grafana/superbot-capacity.json`](../../deploy/grafana/superbot-capacity.json) is a Grafana dashboard of all of it, with the alerts' thresholds drawn on its panels. A test renders `/metrics` against two Incus stand-ins and fails if the dashboard or the rules use a metric botd doesn't write.

### Tests

- **Unit**: parsing `/proc/loadavg` and `/proc/meminfo`; botd's own host read for real, one disk per filesystem; each family written once with a sample per host that has it; Incus's resources and pool resources against the stand-in, without `resources_load`, and with a pool that won't say; a failed read keeps the last and is logged once.
- **Against stand-ins** (`machines_placement_tests`): two Incus hosts with capacities. With metrics off, no host is asked; allocation, capacity, the maximum, up and open are shown. With them on, a reading reads both hosts; a host that never answers it holds up neither host checks, reconciling, nor reading the other, and keeps its last reading. A host that stops answering is neither up nor open and keeps its last reading; a drained host is up but not open; a pool that stops saying drops its disk. No email, machine id, label or address reaches the new lines. A machine waiting for room shows in the gauge and leaves it when made.
- **Real Incus** (the `incus-e2e` workflow, ADR 0069): the host's resources and pool space parse.

## Consequences

- Operators see a fleet filling before placement refuses, and a pool or botd's own disk filling before writes fail, in the monitoring system they already scrape botd with.
- A scrape now also reads every machine once more for placement's load, and does a `statvfs` or two: negligible at the hundreds of machines ADR 0089 sized scrapes for.
- With metrics on, botd makes two more small calls per Incus host each reconcile interval.
- Incus memory "used" is Incus's own figure; botd's is all but `MemAvailable`. Both are what each system calls used, not the same formula.
- Not covered: Linode machines' hosts (Linode's), each machine's own CPU and memory (its agent's heartbeat has disk only), node_exporter-level detail (network, disk I/O, inodes), and dashboards for requests and runs (CC2.1-1).
