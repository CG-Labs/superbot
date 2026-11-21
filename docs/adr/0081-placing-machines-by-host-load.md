# 0081: Placing machines on Incus hosts by load

## Status

Accepted (21 Nov 2026). Builds on [ADR 0025](0025-control-plane-linode.md) (the control plane), [ADR 0065](0065-incus-container-machines.md) (Incus container machines), [ADR 0069](0069-validating-incus-containers-on-a-real-host.md) (the real-host test), [ADR 0071](0071-off-host-machine-backups.md) (off-host backups), [ADR 0074](0074-machine-rpo-and-rto.md) (RPO and RTO) and [ADR 0076](0076-restoring-onto-another-incus-host.md) (several hosts, restoring onto another). The next step on [#29](https://github.com/CG-Labs/superbot/issues/29): placing machines by host load, which ADR 0076 left for later.

0079 is the highest number on `main`, and open PR #139 holds 0080.

## Context

ADR 0076 put several Incus hosts behind one provider. Where a machine went was `Fleet::placement()`: the first configured host that is up. That was used for every new machine, for a restore whose own host was lost, and, as "the first other host that is up", for every machine of a lost host. So:

- The first host took every machine until it stopped answering. Nothing knew how big a host was, so it could be filled past its memory or disk, and containers would then fail or be OOM-killed under load.
- A lost host's machines all went to one host, however many there were.
- There was no way to keep new machines off a host that works (for maintenance, or to empty it) short of taking it out of `INCUS_HOSTS` and restarting.

## Decision

### What a host's load is

botd adds up its own records; it doesn't ask Incus. A host's load is every machine on it that isn't destroyed (suspended ones too: they keep their disk and come back with their limits), and each restore on its way to it from another host, from its import until the swap moves the machine's record. Each counts its plan: `c<cpus>-m<GiB>-d<GiB>` is what Incus gives the container, so it is what it takes from the host. Machines from another provider aren't counted.

What a host has to give is configured, as plans are:

| Setting | Meaning | Default |
|---|---|---|
| `INCUS_CAPACITY` | `c<cpus>-m<memory GiB>-d<disk GiB>`, what every host's machines may be given in all. | none: no limit |
| `INCUS_CAPACITY_<NAME>` | One host's own. | `INCUS_CAPACITY` |
| `INCUS_MAX_MACHINES[_<NAME>]` | How many machines a host may have (1 to 100000). | none |
| `INCUS_PLACEMENT` | `spread` (the least loaded host) or `fill` (the first in the order configured). | `spread` |

Capacity is set for every host or for none (botd won't start otherwise), so "least loaded" is one measure across them all. It is what may be allocated, not the hardware: leave headroom for the host, or set CPUs above the real count to overcommit them, which containers handle well. Memory is a hard limit per container (ADR 0065), so it shouldn't be overcommitted.

### Where a machine goes

A host is **open** if it is up, answered its last check (not merely not yet down: a host that is failing gets nothing while it might be going), and isn't drained. It **has room** for a plan if its allocated CPUs, memory and disk, plus the plan's, are within its capacity, and its machines plus one within its maximum. Of the open hosts with room, `spread` picks the one whose fullest measure (CPUs, memory, disk or machines, as a share of its capacity) is lowest after placing the machine, then the one with fewer machines, then the first in order; `fill` picks the first in order. With no capacity set, `spread` picks the host with the fewest machines.

The same choice (`placement::choose`) is used everywhere a machine lands on a host:

- **New machines.** The control plane picks the host and creates the container there (`Hosts::create_on`); the provider no longer picks. A request when no host has room is refused (409) before anything is recorded, naming each host and why: `a has 0 of 16 CPUs free, 2 needed; b is drained`. A machine the reconciler sends (a create retried after a transient failure) that finds no room stays pending with that reason, audited and alerted once, and is made as soon as there is room.
- **A restore whose own host was lost** goes where placement puts it, away from the lost host.
- **A restore onto another host** (`--host`) is refused (409) if that host is drained, failing, or hasn't room. A restore in place needs no room: it replaces the machine where it is.
- **A lost host's machines** (`POST /api/machines/hosts/{name}/recover`): without `to`, each is placed in turn, counting the ones placed before it, so they spread over the hosts with room rather than all going to one. With `to`, each must fit there. One with nowhere to go is skipped with the reason (its certificates are revoked all the same), and recovering again picks it up once there is room. The answer and the alert list the hosts they went to (`toHosts`); `to` is only what was asked. Refused (409) before anything changes if no other host is open.

Placement runs under the control plane's lock (`ops`), as every create and restore does, so two machines can't take the same room.

### No room

`machine.placement_failed` (failure; target the user for a refused request, the machine for one waiting) with the plan and the reason, and an alert through ADR 0061's channels, ADR 0074's `alert` notice: "No Incus host has room for a machine", saying what to do (add capacity or a host, undrain one, or free room; `botctl machine hosts` shows the load). A waiting machine is announced once, not each reconcile.

### Draining

`PUT /api/machines/hosts/{name}/drain` `{reason?}` (`botctl machine host drain <name> [--reason <text>]`) closes a host to anything new: new machines, restores onto it from elsewhere, and a lost host's machines. Its machines stay and work as before, restores in place included. To empty it, move them one at a time with ADR 0076's `botctl machine restore <user> <backup-id> --host <other> --yes`, which deletes each old container once its copy is ready. `DELETE` (`botctl machine host undrain <name>`) opens it again. Both are admin-only, as every `/api/machines` route is (ADR 0012), recorded with who and when, audited once each (`machine.host_drained` with the reason and how many machines are on it, `machine.host_undrained` with when and by whom it was drained), and kept across restarts in `machine_hosts`. A lost host, or one no longer configured, can't be drained (409): nothing goes there anyway.

### What admins see

`GET /api/machines/hosts` (`botctl machine hosts`) gives each configured host its `load`: `machines`, `allocated`, `capacity`, `maxMachines`, `free`, whether it is `open` and, if not, why (`closed`); and `drainedAt`, `drainedBy` and `drainReason`. At the top: the `policy`, and `placement`, where a machine of the first tier would go now, or `placementRefused` saying why none can. `GET /api/machines/substrate` shows each host's capacity and the policy.

### Tests

- **Unit**: room and load per measure, why a host is closed, and the settings (`INCUS_CAPACITY`, `_<NAME>`, all or none, `INCUS_MAX_MACHINES`, `INCUS_PLACEMENT`).
- **Against stand-ins** (`machines_placement_tests`, in the style of ADR 0076's): two hosts with room for two machines each. Machines spread, ties in order; a host that didn't answer its last check is skipped before it is down; a full fleet refuses the request (nothing recorded), audited and alerted; the view shows each host's load and that nothing fits. A drained host gets nothing though it has room; drain is admin-only, checked, audited once; a machine the reconciler sends waits with the reason, announced once, and is made when the host is undrained. Then three hosts of different sizes: a move onto a drained host is refused; a lost host's three machines are placed one by one onto the two hosts with room, the third skipped for want of room, and placed once room is freed. ADR 0076's tests run unchanged with `fill`, which is ADR 0076's old placement.

## Consequences

- With no capacity set, nothing changes but the order: new machines spread by count over the hosts that are up, instead of filling the first. `INCUS_PLACEMENT=fill` keeps ADR 0076's behaviour exactly.
- Capacity is the operator's word, not measured. A host bigger or smaller than configured is filled to what was configured. Reading it from Incus (`/1.0/resources`) is possible but would put a network call in every placement and doesn't know about headroom.
- Load is botd's records, so containers made outside botd on a host aren't counted. Hosts are botd's alone (ADR 0065), so there should be none.
- A restore in place briefly holds two copies of the disk on its host (ADR 0071), which isn't counted. Leave disk headroom for one restore at a time.
- Not covered: resizing a machine checks no room on its host (it may push a host past its capacity; it shows in the load), moving machines off a full or drained host by itself (a rebalancer would need live migration or a restore per machine, which loses work since its backup), and Linode machines (Linode places them).
