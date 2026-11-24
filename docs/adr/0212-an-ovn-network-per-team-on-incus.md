# 0212: An OVN network of its own per team on Incus

## Status

Accepted (23 Nov 2026). The ninth slice of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening). It does what [ADR 0189](0189-a-network-of-its-own-per-team.md) and [ADR 0202](0202-existing-machines-join-their-teams-network.md) deferred first: "Incus: an OVN network per team". It builds on Incus containers ([ADR 0065](0065-incus-container-machines.md)), their network ACL ([ADR 0179](0179-outbound-rules-at-the-provider.md)) and several Incus hosts ([ADR 0076](0076-restoring-onto-another-incus-host.md)).

## Context

On Linode, `MACHINE_TEAM_NETWORK=vpc` gives each team a VPC its machines share, apart from every other team's (ADR 0189), and machines already made join it (ADR 0202). On Incus, botd refused to start with team networks on. Containers there sit on one bridge, `incusbr0`, with port isolation and one network ACL that drops traffic to private ranges. That keeps every container apart, a team's included. A team whose machines need to reach each other, or a private service of the team's own, had no way to do it on Incus.

Incus has OVN networks: virtual networks that live in OVN, not on the host. Since `network_ovn_isolated` (Incus 6.x), one can have no uplink at all (`network: none`). It then has its own router and DHCP and reaches nothing outside. That is what a team network is.

Three things shaped the design:

1. **ACL rules can't be carved.** Incus applies an ACL's drop rules before its allow rules, whatever their order. The machines' ACL drops all private ranges, and a team subnet is a private range. So "allow the team's subnet" can't be added to that ACL.
2. **Restricted projects.** botd's project is restricted, and the guide sets `restricted.networks.access=incusbr0`. A project without `features.networks` uses the default project's networks, only those the list names.
3. **The NIC inside the container.** The image's cloud-init network config brings up `eth0` only. A second NIC needs a network config that names it.

## Options

1. **Keep refusing** team networks on Incus. Simple, but teams on Incus get nothing, and Incus is the self-hosted path.
2. **A bridge per team.** Bridges are plain Linux bridges on one host, with NAT and an uplink by default. Isolating them needs the same care, and they can't span a cluster.
3. **An isolated OVN network per team**, with a second NIC behind an ACL of its own, plugged in and out while the container runs.

We chose option 3.

## Decision

### Turning it on

- `MACHINE_TEAM_NETWORK=ovn` with `MACHINE_PROVIDER=incus`. `vpc` on Incus, or `ovn` on Linode, makes botd refuse to start, naming the right one.
- `MACHINE_TEAM_NETWORK_SUBNET` (default `10.248.0.0/22`) may be anywhere in RFC 1918, a `/29` or larger. Linode's narrower VPC ranges still apply to `vpc`.
- The subnet must not meet anything containers reach or are kept off through `eth0`: botd's machine address (`MACHINE_CONTROL_URL`), an `INCUS_EGRESS_ALLOW` address, an `INCUS_EGRESS_DENY` range or an Incus host. The team NIC's route would take that traffic, so botd would be unreachable, or the denied range reachable. botd refuses to start if it does.
- At each create and in the admin check, botd also asks Incus for `network_ovn_isolated` and for the bridge's own range. A subnet meeting the bridge's would take over containers' default route. Either failing holds the create back, with the reason on the machine.

### The network

One per team per region, per Incus host, named as the VPC is: `<prefix>-team-<12 hex of the team id's digest>-<region>`. It is made the first time a team member's machine needs it, and audited as `machine.team_network_created`:

- `type: ovn`, `network: none` (no uplink), `ipv4.address` the subnet's first address as router, `ipv4.nat: false`, `ipv4.dhcp.gateway: none` (DHCP hands out addresses but no default route), `ipv6.address: none`.
- Marked `user.superbot.team-network=true` and `user.superbot.region`. botd lists only marked networks. A network of the same name without the mark, or with another subnet or region, is refused rather than used.
- If the project has an access list and no networks of its own, the network's name is added to `restricted.networks.access` first, under an ETag. That loosens nothing: it names one more network, made by botd for one team. A project with `features.networks` or no list is left alone.

### Its ACL and the NIC

- An ACL named after the network: no inbound rules, and one outbound rule, to the team's subnet. OVN's ACLs are stateful, so replies come back, and OVN adds its own baseline rules (ARP, DHCP and DNS to the router). Nothing else gets in, so teammates' machines can't reach each other, as on Linode, where the firewall's inbound drops keep them apart (ADR 0189). The team's own services, put on the network by the operator, are reachable. Anything else in the ACL is set back when the next team machine is made.
- The team NIC is device `eth1` on the network, behind that ACL with both default actions `drop`, and with MAC, IPv4 and IPv6 filtering, so a container can't claim a teammate's address.
- `eth0` and the machines' ACL are as before. The machines' firewall sweep now keeps exactly that `eth1` and nothing else: an `eth1` that isn't exactly a team NIC is removed like any other extra NIC.

### Inside the container

Every container is now made, and rebuilt, with a `cloud-init.network-config` that brings up `eth0` as before and `eth1` as optional, with DHCP but no DNS or routes from it. It is marked `user.superbot.team-nic=eth1`. Plugging or unplugging `eth1` later needs nothing from the machine. Its egress rules let the team subnet through, as on Linode (ADR 0202).

### Joining and leaving while running

- A new team member's machine is made with `eth1`.
- Incus plugs NICs into running containers and unplugs them again. A new provider flag, `team_network_hotplug`, says so. The sweep of ADR 0189 and 0202 is otherwise unchanged:
  - **Joining.** A machine already made joins at once, once its egress rules let the subnet through and it is behind the firewall. It is audited `machine.team_network_joining` with `atOnce: true`, then `machine.team_network_joined` on the next pass. `MACHINE_TEAM_NETWORK_JOIN=when-idle` never restarts anything on Incus.
  - **Leaving.** A running machine whose owner leaves loses `eth1` at once, without a power-off. It is audited `machine.team_network_left` with `inUse: true`. Its rules lose the subnet on the next heartbeat.
- A container made before this change lacks the marker, so its cloud-init wouldn't bring up `eth1`. Joining is refused with "rebuild it to join", audited once. A container with an `eth1` of its own isn't touched until the firewall sweep has removed that device.

### Several hosts

With several Incus hosts (ADR 0076), each host has its own team networks. botd lists them as `<host>/<name>`. A machine joins only its own host's, and a new machine's network is made on the host it is placed on. Teammates on different hosts are on different networks. They share the range but never meet. On an Incus cluster, the network is per region, as VPCs are per Linode region.

### Where it shows

- `GET /api/machines/substrate`: `teamNetwork.kind: ovn`, and under settings the team NIC's shape. The admin check adds `team network`.
- The configuration baseline: `MACHINE_TEAM_NETWORK` passes with `vpc` on Linode or `ovn` on Incus, and fails with the wrong kind for the provider.
- `.env.example`, [the Incus guide](../ops/incus-containers.md), [backend.md](../backend.md), [access control](../security/access-control.md), [the security architecture](../security/architecture.md) and [the configuration baseline](../security/configuration-baseline.md).

## Consequences

- Teams on Incus get a private network of their own for their services, with nothing between teams, and teammates' machines apart as on Linode. A container's other traffic is exactly as before.
- Incus hosts need OVN: an OVN northbound database Incus is pointed at (`network.ovn.northbound_connection`) and `ovn-controller` on every host. No uplink network is needed, since team networks have none.
- Joining and leaving don't restart containers on Incus. A run in progress goes on.
- botd now edits the project's network access list, only to add team networks. It never removes them. The list grows by one name per team and region.
- A restore or a move to another host (ADR 0076) puts the container back with `eth0` only. The sweep puts `eth1` back on the next pass, unless `MACHINE_TEAM_NETWORK_JOIN=off`.
- A backup's `eth1` names the team network and ACL on the host it came from. Incus won't import a backup whose devices it can't load, and a host that never served the team has neither. So the import sends `X-Incus-devices` (the `backup_override_config` extension), which puts `eth1` on the host's own bridge with no ACL. The copy stays stopped until the restore replaces every device. An Incus without that extension gets no override, as before, so a restore of a team member's container onto such a host fails until the team has a machine there.
- Networks and ACLs of teams that are gone stay until an admin removes them, as VPCs do.

## Tests

- **Unit** (`machines/team_network.rs`): `ovn` takes any RFC 1918 range of a `/29` or more and nothing else. (`machines/incus/tests.rs`): router and subnet arithmetic; a subnet meeting botd's address or `INCUS_EGRESS_DENY` is refused. Against the stand-in: a team network is an isolated OVN network with the router first, no gateway, the mark and region, and the project's access list extended once. It is made once, and refused for another subnet or region or an unmarked network of the same name. A project with networks of its own is left alone. Members are containers with a NIC on it. Leaving unplugs from a running container and never takes `eth0`. Joining plugs the exact team NIC once.
- **Several hosts** (`machines/incus/fleet.rs`): networks and members are listed as `host/name`, made only on a host directly, and joined only on the machine's own host.
- **Startup** (`machines/mod.rs`): `ovn` on Incus is taken and shown, and the provider says it hot-plugs. `vpc` on Incus, `ovn` on Linode, and subnets meeting botd's address, an allowed address, a denied range or an Incus host are refused.
- **End to end** (`machines_incus_team_network_tests.rs`, the Incus provider over mutual TLS to the stand-in, which now refuses networks a restricted project's list doesn't name):
  - A team's containers get `eth1` on one OVN network behind its ACL, which lets nothing in. Someone in no team gets none.
  - The firewall sweep keeps the team NIC but removes a loosened one, and the sweep puts it back at once.
  - A leaver is unplugged while running, never powered off, audited `inUse: true`.
  - The ACL is set back at the next create.
  - A container made before this change is refused once until rebuilt.
  - The admin check fails without `network_ovn_isolated` or with a bridge on the same range, and then nothing is made.
- **Baseline** (`baseline.rs`): `ovn` on Incus passes; `vpc` on Incus and `ovn` on Linode fail.

## Deferred

- **Linode interfaces**, each with a firewall of its own, so Linodes that have them can join too (ADR 0202).
- One team network across several standalone Incus hosts, which would need OVN interconnect.
- Keeping `eth1` through a restore, rather than the sweep putting it back.
- Removing networks, ACLs and access-list entries of teams that are gone.
