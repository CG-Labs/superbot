# 0189: A network of its own per team, on Linode

## Status

Accepted (23 Nov 2026). The seventh slice of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening), after machines hardened at first boot ([ADR 0126](0126-per-user-machine-hardening.md)), run limits and outbound allow-lists ([ADR 0135](0135-run-limits-and-egress-allow-lists.md)), locked-down run users with a red-team suite ([ADR 0145](0145-locked-down-run-users-and-red-team.md)), a seccomp filter per run ([ADR 0156](0156-seccomp-filter-per-run.md)), Incus hosts dedicated to a team ([ADR 0166](0166-incus-hosts-dedicated-to-a-team.md)) and outbound rules at the provider ([ADR 0179](0179-outbound-rules-at-the-provider.md)). It is the "VPC hosts" half of #54's "dedicated or VPC hosts", which ADRs 0166 and 0179 deferred. It builds on the machines' firewall ([ADR 0035](0035-machine-firewall-auto-enroll.md)) and team accounts ([ADR 0087](0087-team-accounts-and-machines.md)).

Numbered 0189 because that number was reserved for this work.

## Context

Enterprise buyers ask for "our machines on a network of their own". In practice they mean two things:

1. **Our Bots reach our private services.** A team's database, internal API or build cache sits on a private address. Today no machine can reach one: ADR 0126's rules keep every user but root off private ranges inside the machine, and ADR 0179's firewall rules keep root off them too.
2. **Nobody else's machines reach them.** A private network shared by every customer would be worse than none.

Today no machine shares a private network with another. Linodes get no private address, and Incus containers have port isolation (ADR 0065).

On Linode, a VPC is a regional private network that routes only between its own members, never to another VPC or to Linode's shared private network. VPCs are free. A Linode joins one through a network interface on a subnet. With configuration-profile interfaces, the Linode's Cloud Firewall applies to the VPC interface as well as the public one, inbound and outbound. Linode's newer "Linode interfaces" each take a firewall of their own instead. An interface can be added to a running Linode, taking effect at its next boot, but can't be removed while it is active. A subnet must be in RFC 1918 space, outside `192.168.128.0/17`, and no smaller than a `/29`.

## Options

1. **One VPC for every machine.** Simple, but it is the shared network buyers don't want. The firewall would be the only thing between customers.
2. **A VPC per team, with machines reaching each other on it.** Teammates' machines would talk to each other privately. But each teammate has a machine of their own that admins manage without seeing into (ADR 0087), and ADR 0145 keeps people's files apart on a machine. Opening machine-to-machine traffic inside a team would undo that between machines.
3. **A VPC per team for the team's own services.** The team's machines join it. Its services, which the operator puts on it, are reachable from them. The firewall still drops every inbound packet but botd's and SSH's, on the VPC interface too, so machines don't reach each other.
4. **Operator-named networks per team** (`botctl team network set <team> <vpc>`). More flexible, but it needs storage, routes and audit for a choice that option 3 makes automatically. It can come later if needed.

We chose option 3.

## Decision

### Turning it on

`MACHINE_TEAM_NETWORK=vpc` turns it on. It is off by default, because it adds reachability rather than taking it away. It needs:

- **Linode.** With `MACHINE_PROVIDER=incus` it is a startup error: there are no team networks on Incus yet (see Deferred).
- **`MACHINE_FIREWALL=on`**, since the firewall's inbound drops are what keep teammates' machines apart on the VPC.

`MACHINE_TEAM_NETWORK_SUBNET` is the range of every team's subnet, `10.248.0.0/22` by default (1,020 addresses). The same range in every VPC is safe because VPCs never route to each other. It must be IPv4, inside `10.0.0.0/8`, `172.16.0.0/12` or `192.168.0.0/17`, no smaller than a `/29`, and must not meet `MACHINE_EGRESS_DENY`. An operator's own deny list always wins, and the team network would otherwise let part of it through.

### A team's network

The team is the machine owner's team, as a member or as its service account: the same as ADR 0166's placement.

- **One VPC per team and region**, labelled `<MACHINE_LABEL_PREFIX>-team-<first 12 hex digits of SHA-256 of the team id>-<region>`. The label says which team without naming it, and is the same every time, so it is how botd finds the VPC again. It has one subnet, `machines`, with `MACHINE_TEAM_NETWORK_SUBNET`.
- It is made when the team's first machine in that region is, before the create is sent, and audited as `machine.team_network_created` (target `team_network`, with the team, label, region, subnet and the machine it was made for). It is found by its label after that. A create that loses a race to another finds the winner's.
- A VPC by that label in another region, or whose `machines` subnet has another range, is a refusal, not adopted. A VPC with no `machines` subnet gets one.
- If the network can't be made, the create isn't sent. The machine fails with "The team's network couldn't be set up", audited as `machine.create_failed` with step `network`, as a firewall that can't be set up is (ADR 0035). A machine is never made off its team's network by accident.

### Joining

A team member's new machine is created with two configuration-profile interfaces: public first (the primary, through which it reaches the internet and botd), then the VPC on the team's subnet. `interface_generation` is set to `legacy_config`, so an account that defaults to Linode interfaces still gets the kind that the machine's firewall covers. `machine.created` carries `teamNetwork`, the VPC's id.

People in no team get no VPC interface, as before.

### What it lets through

- **At the firewall**, the outbound rules (ADR 0179) get `team-network-tcp` and `team-network-udp`: accept to the subnet. They come after botd's port and before the drops. The firewall is shared by every machine, so the rules are on non-team machines too. There they let nothing through: a Linode reaches that range only through an interface on a VPC that holds it, and VPCs never route to each other. With `MACHINE_FIREWALL_EGRESS=off`, outbound is open anyway, and nothing is added. Existing firewalls get the rules on the reconciler's next pass, as ADR 0179's did.
- **Inside the machine**, a team machine's harness egress rules (ADR 0126) accept the subnet before the deny lists, for every user, Bots and teammates included. Reaching the team's services is the point. The rest of the private ranges stay denied. A machine's outbound allow-list (ADR 0135), when one is set, still binds: the subnet must be on it.
- **Inbound** is unchanged. The firewall drops every packet but botd's to the agent port and the operator's SSH sources, on the VPC interface too. Teammates' machines can't reach each other there.

### Leaving

Every reconcile lists the VPCs whose labels end in `-team-<12 hex digits>-<region>`, whatever prefix they were made under (a machine keeps its network when `MACHINE_LABEL_PREFIX` changes), and each one's interfaces. For each interface on one of our machines whose owner isn't on the VPC's team (they left, moved teams, or the team is gone):

- A running machine is suspended through the normal suspend path, audited as `machine.suspended` and `machine.team_network_leaving` (with the VPC's team and the owner's team now).
- Once it is suspended and Linode says it is off, its VPC interface is removed, audited as `machine.team_network_left`. If the sweep was what suspended it, it is resumed (`resuming: true`); so is one whose owner rejoined the team before it was taken off. A resume that fails is tried again every pass until it works, unless the machine must stay off by then: its owner disabled, a disable hold on it, or its team machine given back; and none is tried in a pass that couldn't read every network's members, since that machine might still be on one it must leave. A machine its owner or an admin had suspended stays off. botd remembers which machines it suspended only in memory, so after a restart such a machine stays suspended for its owner to resume.
- A machine being made, being destroyed or in error is handled once it is suspended or gone.
- Anything else on the VPC is the team's, not ours, and is left alone: the operator's services, or Linodes of another control plane.

The reconciler reports `teamNetworks: {leaving, left, errors}` when any are non-zero. A failed removal is audited with the error, and tried again on the next pass.

### Where it shows

- `GET /api/machines/substrate` shows `teamNetwork` (`{kind: "vpc", subnet}`, or null), and the firewall's `outbound` shows the two accept rules.
- `.env.example`, [backend.md](../backend.md), [access control](../security/access-control.md), [the security architecture](../security/architecture.md) and [the configuration baseline](../security/configuration-baseline.md).

## Consequences

- A team's Bots can reach the team's own private services, which the operator puts on the team's VPC, and nothing else private. No other team's machine can reach them.
- Turning it on changes nothing for existing machines. Only machines made after it join. A rebuilt machine's egress rules let the subnet through if its owner is on a team; if Linode's rebuild drops the interface, the machine is just off the network, which is the safe direction.
- A member who leaves a team loses reach to its network at once: their machine is powered off and back on within two reconcile passes. A team's machines given back on leaving (ADR 0087) are suspended already.
- VPCs and their interfaces cost nothing on Linode. botd never deletes a team's VPC, as the team's services may be on it. An empty one can be deleted from Linode's console.
- More provider calls per reconcile: one list of VPCs, and one list of interfaces per team VPC.

## Tests

- **Unit** (`machines/team_network.rs`): off unless `vpc`; the default subnet; ranges Linode refuses (host bits set, not an address, IPv6, outside its RFC 1918 space, `192.168.128.0/17`, smaller than a `/29`); a subnet meeting `MACHINE_EGRESS_DENY` refused; labels name the team by digest and the region, the same each time, and are refused when too long or with two dashes in a row.
- **Linode** (`machines/linode.rs`, against the stand-in): the accept rules come after botd's port and before the drops, read back as ours, and a firewall without them is set again; none with outbound open. A create with a subnet sends public then VPC configuration-profile interfaces, and one without sends neither. A VPC is found by its exact label, made with its subnet, given a missing subnet, refused in another region or with another range, and a lost race is reported. Team VPCs are listed by prefix; members are read from every subnet, skipping interfaces with no profile; removal tolerates a gone Linode, reports Linode's refusal of an active interface, and never sends an id that isn't a number.
- **Hardening** (`machines/hardening.rs`): a team machine's egress rules accept the subnet before the deny lists, and no other machine's mention it.
- **Settings** (`machines/mod.rs`): on Linode, the firewall's outbound rules carry the subnet; nothing with egress off; refused without the firewall, without the control plane, with another value, and on Incus.
- **End to end** (`machines_team_network_tests.rs`, the in-memory provider): two teams' machines are on two networks, each made once and audited, and someone in no team is on none; the user data lets the subnet through only on team machines; the substrate shows it; a team's own service on its network is never touched; a member who leaves is suspended, taken off and resumed, audited; one who rejoins before being taken off is resumed still on it; a resume that fails is tried again, but never once its owner is disabled; a network made under another prefix is still swept; one who leaves with the machine suspended is taken off and left suspended; and a network that can't be made fails the create before it is sent.

## Deferred

- **Existing machines joining** without a rebuild. An interface can be added to a running Linode for its next boot, but its egress rules were written at its first boot. Rebuilding or recreating a machine is the way for now.
- **Incus: an OVN network per team**, with dedicated hosts (ADR 0166). Containers there already can't reach each other (port isolation) or private ranges (the network ACL). A team network would need an OVN network per team and the ACL carved for it.
- **Linode interfaces** (the newer generation), each with a firewall of its own. Configuration-profile interfaces are what one firewall per Linode covers today.
- Per-team subnets, operator-named VPCs and NAT gateways, should a team need its range to differ or its outbound traffic to leave from its own address.
- Deleting a team's VPC when the team is deleted, once botd can tell nothing of the team's is still on it.
