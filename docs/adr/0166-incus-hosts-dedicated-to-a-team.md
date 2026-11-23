# 0166: Incus hosts dedicated to a team

## Status

Accepted (23 Nov 2026). The fifth slice of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening), after machines hardened at first boot ([ADR 0126](0126-per-user-machine-hardening.md)), run limits and outbound allow-lists ([ADR 0135](0135-run-limits-and-egress-allow-lists.md)), locked-down run users with a red-team suite ([ADR 0145](0145-locked-down-run-users-and-red-team.md)) and a seccomp filter per run ([ADR 0156](0156-seccomp-filter-per-run.md)). It covers the "dedicated hosts" half of #54's "dedicated or VPC hosts". It builds on placement by load ([ADR 0081](0081-placing-machines-by-host-load.md)), losing a host ([ADR 0076](0076-restoring-onto-another-incus-host.md)), data regions ([ADR 0117](0117-uk-eu-data-regions.md)) and team accounts ([ADR 0087](0087-team-accounts-and-machines.md)).

Numbered 0166 because that number was reserved for this work.

## Context

Incus containers on one host share its kernel (ADR 0065). ADR 0156 narrows the kernel interface each run can reach, but a kernel or runtime escape from one container still crosses every container on that host. [ADR 0120](0120-managed-substrate.md) recommends Incus "only for fleets that serve one organisation: hosts whose containers all belong to one customer (dedicated hosting, M5)". Its other option for customers who need more is a VM per user (`MACHINE_OWN_KERNEL_TIERS`).

Before this change, nothing in botd could promise that. Placement chose a host by region (ADR 0117), state, drain and room (ADR 0081). It never asked whose machine it was placing, so any team's machine could land next to any other's. An operator could run a separate botd per customer, but then that customer can't share the operator's fleet, tiers or console, as ADR 0117 found for regions.

Enterprise buyers ask for this in two ways: "our machines run on hosts nobody else uses" (dedicated hosts), and "our machines are on a network of their own" (a VPC). This ADR does the first. The second is deferred (below).

## Options

1. **A separate botd per customer.** Full isolation, botd's database included. It needs no code, but it doubles operations for each customer, and a team can't use the shared fleet's spare room. It stays the answer when a customer wants botd itself to be theirs.
2. **A setting per host** (`INCUS_DEDICATED_<NAME>=<team-id>`), as regions are tagged. Team ids are runtime data, though: customers come and go without a restart. A typo would silently put a host out of use, and changes wouldn't be audited.
3. **An admin action per host, kept in botd's database**, like draining (ADR 0081). It is checked when it is made, takes effect at once, and is audited.

We chose option 3.

And for what a dedicated host means:

1. **The host prefers its team.** Strangers could still spill onto it when other hosts are full, and the team onto shared hosts. That is no promise at all.
2. **The host takes only its team's machines, and the team's machines go only on its hosts.** Both directions are strict. A full set of team hosts means the team's next machine waits or is refused, as a full region does (ADR 0117).

We chose option 2. Only that version makes "a kernel escape stays within one customer" true.

## Decision

### Dedicating a host

- `PUT /api/machines/hosts/{name}/dedication` `{team, reason?}` dedicates a configured host that isn't lost to a team. `botctl machine host dedicate <name> <team-id> [--reason <text>]` does the same. The reason is one line of up to 200 characters, such as the agreement's reference.
- It is refused (409, audited as `machine.host_dedication_refused`, outcome denied, with the machines' ids) while any of these belongs to someone who isn't on the team:
  - a machine on the host;
  - a create sent there but not yet answered (`placed_on`);
  - a restore on its way there.

  So a host is never dedicated with a stranger already on it. Move those machines first (`botctl machine restore <user> <backup-id> --host <other> --yes`).
- It is also refused while the host is dedicated to another team; share it first. Dedicating it again to the same team changes nothing.
- It is audited as `machine.host_dedicated` with the team, its name, the reason and how many machines are there.
- The routes are for server admins only. They aren't in the role table, so the router's default (Admin) applies, as for residency pins (ADR 0129). A delegated `machines.manage` role can drain hosts but can't make or end this promise to a customer.
- The dedication is stored on the host's row: `dedicated_team`, `dedicated_at`, `dedicated_by` and `dedication_reason`.

### Sharing it again

- `DELETE /api/machines/hosts/{name}/dedication` `{reason}` makes the host shared again. `botctl machine host share <name> --reason <text>` does the same. The reason is required, because a dedication is often a promise to a customer.
- It is audited as `machine.host_shared` with the team, when the host was dedicated, by whom and why, and how many machines are on it.
- It works on a lost host, or one no longer in `INCUS_HOSTS`. That is how an admin lets a team whose only host was lost go onto shared hosts.

### Placement

`placement::choose` and `placement::fits` now take the owner's `Tenant`: their team (as a member or as its service account, ADR 0143) and whether that team has hosts of its own. A team's hosts count while dedicated to it, including lost and unconfigured ones, so losing its only host never sends its machines to a shared one.

- A host dedicated to a team takes only that team's machines. Everyone else, people in no team included, gets "`<host>` is dedicated to another team".
- A team with hosts of its own gets only those. A shared host says "`<host>` is shared, and this team's machines go only on its own hosts".
- Region (ADR 0117) is checked first, then dedication, then state, drain and room (ADR 0081). A team that uses two regions needs hosts dedicated in each.

Every path that places a machine goes through these two functions, so all of them follow the rules:

- a new machine (refused up front when nothing fits);
- a create the reconciler retries (it waits, said once);
- a restore onto a named host;
- a restore after its host was lost;
- recovering a lost host, with or without `to`.

Refusals keep placement's wording ("No Incus host has room for…"), so a machine waiting this way is counted and alerted like any other (`machine.placement_failed`, `superbot_incus_machines_waiting_for_room`). The alert adds a line saying the team's hosts need room or another dedication.

Resizes in place (ADR 0085) and restores onto the same host don't change hosts, so they don't change.

### Team changes leave machines where they are

Joining or leaving a team doesn't move a person's own machine. ADR 0087 already gives back machines the team gave. A machine can therefore end up on a host it shouldn't be on: a leaver's machine on their old team's host, or a joiner's machine on a shared host while the team has hosts of its own.

We don't refuse the join or the leave. That would change team and SCIM flows, and a refused SCIM call can't be retried by a person. Instead such a machine is **misplaced**, and is reported in these places until an admin moves it:

- `GET /api/machines/hosts` and `botctl machine hosts` list it under `misplaced`, with its host and why;
- botd logs a warning at startup, and `dedicationWarnings` in the hosts view says the same;
- `/metrics` counts it (`superbot_incus_machines_misplaced`), and `SuperBotMachinesOnAnotherTeamsHost` opens a ticket after 15 minutes.

A move is a restore onto a host it may use, and `fits` allows that move only.

A host dedicated to a team that is later deleted stays dedicated and takes nobody's new machines. botd warns about it until an admin shares it. Clearing the dedication when the team is deleted would end a promise without an audited reason.

### Where it shows

- **API**:
  - each host has `dedicatedTeam`, `dedicatedAt`, `dedicatedBy`, `dedicationReason` and `load.dedicatedTo`;
  - the hosts view has `dedicated`: each team with hosts of its own, its name, its hosts, and where its next first-tier machine would go, or why nowhere;
  - the hosts view also has `misplaced` and `dedicationWarnings`;
  - `placement` stays the preview for someone in no team.
- **botctl**: `botctl machine host dedicate`, `botctl machine host share`, and `botctl machine hosts`.
- **Metrics**: `superbot_incus_host_dedicated` per host, 1 or 0. Labels are host names only, never team ids, as ADR 0106 keeps people and tenants out of labels. Also `superbot_incus_machines_misplaced`.
- **Docs**: the [Incus guide](../ops/incus-containers.md#hosts-dedicated-to-a-team) and [access control](../security/access-control.md).

The console has no host view (hosts are botctl's, ADR 0081), so it isn't changed.

## Consequences

- An operator can promise a customer that their machines share a kernel with nobody else's, and hold botd to it. The promise is audited when it is made and when it ends, and every refusal it causes is audited too.
- A customer with dedicated hosts gets no machine when those hosts are full, rather than one on a shared host. Operators watch `dedicated[].placementRefused` and the room alerts, and add or dedicate hosts in time.
- Nothing changes for a server with no dedicated hosts, or on Linode, where every machine already has its own VM. The routes return 409 there, as other host routes do. Linode's dedicated CPU plans are a `MACHINE_TIERS` choice and need no code.
- Dedicated hosts are priced per host, not per machine. A team pays for the room it leaves empty. That pricing is the operator's; this change adds no cost of its own.
- This is not a separate deployment. botd, its database and botd's certificate on each host (ADR 0065) are still shared.

## Tests

- **Unit** (`machines/placement.rs`): `not_for` for a dedicated and a shared host, against a team with and without hosts of its own and against someone in no team; the view shows `dedicatedTo`.
- **End to end** (`machines_dedicated_tests.rs`, Incus stand-ins, the S3 stand-in and the real agent):
  - routes: admins only, unknown host and team, a reason with a newline, unknown fields, idempotent and audited once, and refused while the host is dedicated to another team;
  - placement under spread: strangers and other teams skip an empty dedicated host; the team goes onto it though a shared host ties and comes first; once it is full, the team's request is refused naming the shared hosts, a retried create waits and is said once, and strangers are refused rather than placed there;
  - the view's `dedicated`, `misplaced` and warnings, and the two metrics, with no team id in labels;
  - dedicating is refused while a stranger's machine is there, or a create sent there is unanswered; the refusal is audited as denied;
  - sharing needs a reason, is audited once, and lets anyone back on;
  - a host dedicated to a team that is then deleted takes nobody and is warned about until shared;
  - the red-team case: no `--host` restore crosses teams either way; recovering a lost dedicated host onto a shared one skips every machine; by placement, the team's machines fill its other host and the rest wait, never placed on the shared host with room;
  - a leaver's and a joiner's machines are reported as misplaced, with reasons, a warning and the metric, until moved by a restore.

  Each end-to-end test fails with the dedication check removed from placement. The red-team case also runs as its own step in CI's isolation job, beside ADR 0145's red-team suite.
- **botctl**: request building for `dedicate` and `share`, with `share` refused without `--reason`.
- **Alert rules**: `promtool test rules` for `SuperBotMachinesOnAnotherTeamsHost`, firing after 15 minutes and clearing once the machine is moved. The capacity test checks the rules use only metrics botd writes.

## Deferred

- **VPC hosts**, #54's next slice: a network of its own per team at the provider, for example a Linode VPC per team or OVN networks per team on Incus, together with egress policy enforced there, which would bind root too (ADR 0135).
- Dedicated hosts for one user rather than a team.
- A setting that makes dedication required, so that shared hosts take nobody (`INCUS_SHARED_HOSTS=off`), for fleets that sell only dedicated hosting.
- Moving misplaced machines automatically, which needs a backup and a restore each, and the owner's downtime.
- Refusing a team join or leave that would leave a machine misplaced, where the customer's agreement asks for it.
- Incus VMs (`type: virtual-machine`) on dedicated hosts, for customers who want both (ADR 0120's option d).
