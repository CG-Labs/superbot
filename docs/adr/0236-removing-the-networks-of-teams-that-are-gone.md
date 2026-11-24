# 0236: Removing the networks of teams that are gone

## Status

Accepted (24 Nov 2026). The eleventh slice of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening). It does what [ADR 0189](0189-a-network-of-its-own-per-team.md) and [ADR 0212](0212-an-ovn-network-per-team-on-incus.md) deferred: "deleting a team's VPC when the team is deleted, once botd can tell nothing of the team's is still on it", and "removing networks, ACLs and access-list entries of teams that are gone".

Numbered 0236 because that number was reserved for this work.

## Context

With `MACHINE_TEAM_NETWORK` on, each team gets a network of its own per region: a Linode VPC (ADR 0189), or an isolated OVN network on each Incus host with an ACL of the same name, added to the restricted project's network access list (ADR 0212). When a team is deleted, its members leave first, and the sweep takes their machines off its network. The network itself stayed, empty, for ever:

- **Linode.** VPCs are free, but an account can have only 10 per data center by default. Every team with machines in a region takes one there, gone or not, so after ten teams had come and gone, no new team's first machine in that region could be made.
- **Incus.** Each gone team left an OVN network, an ACL and a name on the project's access list on every host it had used. The access list only grows (ADR 0212). It lets botd's project use networks no team of this server's has any more.
- **Admins** had to find these by hand. A label says which team only by digest, so they couldn't tell a gone team's network from a live one's without botd.

Two things make removing one risky:

1. **Something else may be on it.** The operator puts the team's own services on its network (ADR 0189). A gone team's database may still be there, waiting to be moved.
2. **It may not be ours.** Labels end in `-team-<digest>-<region>` under any prefix, and botd finds them that way, so a machine keeps its network when `MACHINE_LABEL_PREFIX` changes. On a Linode account or Incus host shared with another control plane, that one's team networks look the same. A team botd has never heard of could be one it deleted, or one another server has.

## Options

1. **Keep them** and document removing them by hand. Simple, but gone teams use up Linode's limit and grow Incus's access list, and admins can't tell which are gone.
2. **Remove any team network whose team isn't on this server.** That would remove another control plane's networks, and the networks of teams this server had before its database was restored from an older backup.
3. **Remove the network of a team this server deleted, once nothing at all is on it.** A team this server deleted is known from its own audit log. Nothing at all means none of our machines and nothing else: no Linode, NodeBalancer or any other thing Linode lists on a subnet, and no Incus instance in any project, nor anything using its ACL.

We chose option 3, on by default, with a setting to turn it off.

## Decision

### The setting

`MACHINE_TEAM_NETWORK_REMOVE` is `when-empty` (the default) or `off`. Like `MACHINE_TEAM_NETWORK_JOIN`, it needs `MACHINE_TEAM_NETWORK=vpc` or `ovn`, and botd refuses to start with an unknown value. It shows as `remove` in the substrate view's `teamNetwork`. It is on by default because removing an empty network takes reach away from nothing, and on Incus it takes a name off the project's access list.

### Which networks

Each reconcile already lists every team network and reads its members (ADR 0189). Then, for each network whose label's team digest is that of a team this server deleted:

- **A team this server deleted** is one with a `team.deleted` event in its audit log, succeeded, that isn't in its teams table. Team ids are random and never reused. Another control plane's teams are never in this server's log, so their networks are never touched. Audit events are kept for ever by default. Under `AUDIT_RETENTION_DAYS`, a team deleted before the window stays on its network until an admin removes it.
- **None of our machines still on it.** A network with a machine of ours still on it, leaving or not, waits for the next pass, as does one whose members couldn't be read. So the sweep never calls the network "kept" while it is only waiting for its own leavers.
- **Under the lock** team changes and creates take, the team is checked to be still gone, and the provider is asked to remove the network.

### What the provider removes

A new provider call, `remove_team_network`, removes a network only if nothing is on it. Ok(false) means something is, and it stays. Ok(true) means it is gone, or was already.

- **Linode.** The VPC's subnets are read. If any subnet has a non-empty list of anything (`linodes`, `nodebalancers`, or any list Linode adds later), the VPC stays. Otherwise `DELETE /vpcs/{id}`. Linode refuses to delete a VPC with Linodes on it anyway, so a race fails safe.
- **Incus.** The network must be one botd made for a team: an OVN network with the mark. Its `used_by` must be empty, in any project, and so must its ACL's. Then the ACL is deleted, then the network, while the project's access list still names it, and last its name is taken off that list under an ETag. The list is never left empty, since an empty list lets the project use every network. A network already gone still has its name taken off.
- **Several Incus hosts.** Each host's network is removed on that host, by its `host/name` id.

### What is audited

- `machine.team_network_removed` (target `team_network`, actor the control plane) with the team, label, region, subnet and `teamDeletedAt`.
- `machine.team_network_kept` with `reason: "something is still on it"`, once per network per botd run, so admins know why it stays.
- A failure is `machine.team_network_removed` with outcome `failure` and the error, once per reason. It is tried again every pass.

The reconciler adds `removed` and `kept` to `teamNetworks`.

## Consequences

- A deleted team's network goes within a pass or two of its last machine leaving. On Linode a running leaver is powered off, taken off and powered on, so it takes two passes; on Incus leavers are unplugged at once, so it goes in the same pass.
- A gone team's own services keep its network until the operator moves them off; then it goes on the next pass.
- On Incus the project's access list shrinks again as teams go.
- A create already under way for someone whose team was just deleted can meet its network being removed. The create then fails as one whose network couldn't be made does (ADR 0189), and is retried with no team network, as its owner is in no team now.
- A network an admin removed by hand, or one whose Incus access-list edit failed after the network went, isn't listed again, so nothing is retried for it. The failure is audited with the error.
- Turning team networks off stops the sweep, as before: networks then stay until it is on again or an admin removes them.

## Tests

- **Unit** (`machines/team_network.rs`): `when-empty` by default, `off` taken, anything else refused, and the setting refused without team networks.
- **Linode** (`machines/linode.rs`, against the stand-in): an empty VPC is deleted and one already gone counts as removed. VPCs with Linodes, a NodeBalancer, some other list, or a Linode on a second subnet are kept, with no delete sent. A path id that isn't a number is refused.
- **Incus** (`machines/incus/tests.rs`, against the stand-in, which now lists a network's `used_by` and deletes networks): a network with a container on it, or whose ACL a NIC elsewhere uses, is kept with nothing deleted. One nothing uses goes as ACL, network, then access list, its name alone taken off the list. One already gone counts as removed. A list that would be left empty is left as it is. A network botd didn't make is refused.
- **End to end** (`machines_team_network_tests.rs`, the in-memory provider):
  - A deleted team's machines leave its network, and only then is it removed, audited.
  - A live team's network, and an empty one of a team this server never had, are never touched.
  - A deleted team's network with its own service still on it is kept, audited once, and goes once the service is moved off.
  - A failed removal is audited once and tried again.
  - With `off`, it stays and the provider is never asked.
- **End to end on Incus** (`machines_incus_team_network_tests.rs`): a deleted team's containers are unplugged while running, and its network, ACL and access-list name go in the same pass, leaving the machines' firewall.

## Deferred

- Removing a gone team's network when audit retention has pruned its `team.deleted` event. That needs a record of deleted teams kept outside the audit log. Done in [ADR 0249](0249-a-record-of-deleted-teams-and-a-view-of-team-networks.md).
- Removing networks while team networks are off.
- A `botctl` view listing each team network with its team (or that it is gone) and what is on it. Done in [ADR 0249](0249-a-record-of-deleted-teams-and-a-view-of-team-networks.md).
