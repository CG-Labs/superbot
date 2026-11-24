# 0251: A record of deleted teams, and a view of team networks

## Status

Accepted (24 Nov 2026). The twelfth slice of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening). It does two things [ADR 0236](0236-removing-the-networks-of-teams-that-are-gone.md) deferred: "removing a gone team's network when audit retention has pruned its `team.deleted` event", and "a `botctl` view listing each team network with its team (or that it is gone) and what is on it".

Numbered 0251 because 0249 and 0250 went to other work while this was in review.

## Context

ADR 0236 removes the network of a team this server deleted once nothing is on it. It knows a team is one this server deleted from its own audit log: a `team.deleted` event that succeeded, for a team no longer in the teams table. That keeps another control plane's networks on the same Linode account or Incus host safe, because their teams are never in this server's log.

That has two gaps:

1. **Audit retention.** Under `AUDIT_RETENTION_DAYS`, a deletion older than the window leaves the log. The network of that team then looks like another server's and stays for ever. This happens whenever the network outlives the window: a gone team's own service still on it, team networks or removal turned off for a while, or a provider that kept refusing. On Linode each one keeps using up the account's 10 VPCs per data center. On Incus each one keeps a name on the project's access list.
2. **No view.** A network's label names its team only by digest. Admins can't tell from the provider whether a network is a live team's, a deleted team's that something keeps, or another server's. They see `machine.team_network_kept` once, then nothing.

## Options

For the record of deleted teams:

1. **Exempt `team.deleted` from audit retention.** Retention prunes the log from its start as one run, so the hash chain stays whole (ADR 0122). Keeping one kind of event would break that, and keeps the team's name past the window the operator chose.
2. **Treat a team network with no known team as removable after a while.** That is ADR 0236's option 2 again: it would remove another control plane's networks.
3. **Keep a small record of teams this server deleted, outside the audit log.** Only the team's id and when. A trigger on the teams table writes it, so every way a team is deleted (an admin, the last member leaving, SCIM) is covered without each path remembering to.

We chose option 3.

For the view: a `botctl` command and admin API that read the provider now, the same reads the reconciler makes, and change nothing.

## Decision

### The record

A new table, `deleted_teams`, holds `id` and `deleted_at` (Unix ms). An `AFTER DELETE` trigger on `teams` inserts the row in the same statement as the delete, so it can't be missed or written for a delete that didn't happen. The ADR 0236 `team.deleted` event is still written as before; the record doesn't replace it.

On upgrade, the migration fills the table once from the audit log, with the same rule ADR 0236 used: successful `team.deleted` events for teams not in the teams table, at the event's time. Teams whose deletion retention had already pruned before this upgrade can't be known, and their networks stay until an admin removes them, as before.

`Db::deleted_teams` now reads the table, still leaving out any id that is in the teams table. The sweep is otherwise unchanged.

The rows are kept for ever. Each is a random id and a time, with no name and nothing about anyone, so it holds nothing erasure or retention protects, and they are few. Keeping them means a gone team's network is removed whenever it is finally empty, however long that takes.

### The view

`GET /api/machines/team-networks` (`botctl machine team-networks`), for admins and custom roles with `machines.manage`, like the substrate and host views. With team networks off it answers 409. It lists every team network the provider has, under any label prefix, sorted by region and label, with:

- `id`, `label`, `region` and `subnet`.
- `status`: `team` (with `team.id` and `team.name`), `deleted` (with `team.id` and `team.deletedAt`, from the record; no name, which this server no longer keeps), or `unknown` (no team this server has or deleted: another server's, or one deleted before this record and pruned from the log).
- `machines`: our machines on it, each with its `id`, `userId`, `state`, `inUse` (booted with the interface) and `leaving` (its owner isn't on the network's team, so the sweep takes it off).
- `others`: how many other things are on it or use it, each of which keeps it from being removed: interfaces that aren't our machines' (the team's own services, or another server's machines) and, on Incus, anything in another project on the network or behind its ACL (from both `used_by` lists, which removal checks too, read separately so the machines the sweep may change are still only botd's own project's).
- `error` instead of the last two when its members couldn't be read.

The view also returns the `teamNetwork` settings, so `remove: off` explains a deleted team's network that stays. It doesn't list what Linode says is on a subnet besides interfaces (NodeBalancers, databases); removal still checks those itself.

## Consequences

- A deleted team's network goes once nothing is on it, whatever `AUDIT_RETENTION_DAYS` is.
- Another control plane's networks are still never touched: its teams are never in this server's record.
- Restoring botd's database from a backup restores the record with it. A team deleted after that backup is back in the teams table, so nothing about it changes.
- Admins can see which networks are a deleted team's and why each stays, without matching digests by hand.
- The view makes one provider call per network, as the sweep does, so it is no lighter than a reconcile.

## Tests

- **Unit** (`db.rs`): deleting a team writes one record at that time, a second delete writes nothing, a live team said to be deleted and a failed deletion aren't recorded, an install from before reads its audit log once on upgrade (at the event's time), and the record outlives pruning the event under retention.
- **End to end** (`machines_team_network_tests.rs`, the in-memory provider): with the `team.deleted` events pruned, a deleted team's machines leave its network and it is removed; another with its own service on it is kept; another server's network is never touched. The view shows each as `team`, `deleted` or `unknown`, with our machines (and whether each is leaving) and the count of others; members get 403, and with team networks off it is 409.
- **Incus** (`incus/tests.rs`, `machines_incus_team_network_tests.rs`, the stand-in): a container in another project on the network, or a NIC behind its ACL, isn't a member but is counted in `others`, and the view shows a deleted team's network kept by an operator's service in the `default` project until it is moved off.
- **botctl**: `machine team-networks` sends the request; extra arguments are refused.

## Deferred

- Removing networks while team networks are off (ADR 0236).
- Removing the networks of teams deleted, and pruned from the audit log, before this record began. An admin can find them as `unknown` in the view.
- Listing what Linode says is on a subnet besides interfaces, in the view.
