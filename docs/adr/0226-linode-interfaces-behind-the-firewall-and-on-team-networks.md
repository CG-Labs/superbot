# 0226: Linode interfaces behind the firewall and on team networks

## Status

Accepted (24 Nov 2026). The tenth slice of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening). It does the last thing [ADR 0189](0189-a-network-of-its-own-per-team.md), [ADR 0202](0202-existing-machines-join-their-teams-network.md) and [ADR 0212](0212-an-ovn-network-per-team-on-incus.md) deferred for Linode: "Linode interfaces, each with a firewall of its own, so machines that have them can join too". It builds on the machines' firewall ([ADR 0035](0035-machine-firewall-auto-enroll.md)) and its outbound rules ([ADR 0135](0135-run-limits-and-egress-allow-lists.md), [ADR 0179](0179-outbound-rules-at-the-provider.md)).

## Context

A Linode has one of two kinds of network interface:

- **Configuration-profile interfaces** (`legacy_config`), the older kind. One Cloud Firewall on the Linode covers all of them, public and VPC.
- **Linode interfaces** (`linode`), the newer kind. Each public or VPC interface takes a firewall of its own, as a `linode_interface` firewall device. Linode refuses a `linode` device for such a Linode, and a create's top-level `firewall_id` applies only to the older kind. Interfaces can be added or removed only while the Linode is powered off. VLAN interfaces take no firewall with either kind. An account can be set to give new Linodes Linode interfaces by default.

botd knew only the older kind. That left four gaps:

1. **The firewall.** A machine with Linode interfaces couldn't be put behind the machines' firewall. Attaching it as a `linode` device was refused, so the firewall sweep failed on it every pass, and its inbound drops and outbound rules didn't apply.
2. **Creates.** A machine on no team network was created without saying which kind it wanted. On an account that defaults to Linode interfaces, it got them, and with them gap 1. Team members' machines already asked for `legacy_config` (ADR 0189).
3. **Joining.** A machine with Linode interfaces was refused a team network until rebuilt (ADR 0202).
4. **Leaving.** The sweep read VPC members by their configuration profile. A Linode interface has none (`config_id: null`), so the sweep skipped it, and a machine whose owner left the team stayed on the team's network.

## Options

1. **Keep refusing**, and document that accounts must default to configuration profiles. Gaps 1, 2 and 4 stay, since botd still can't see or fix machines that have the newer kind.
2. **Always create configuration profiles, and cover what exists.** Say `legacy_config` on every create. Put the firewall on each interface of machines that already have Linode interfaces, and let them join and leave their team's network while off.
3. **Option 2, and also let an operator choose Linode interfaces** for new machines, for accounts or regions where Linode wants them.

We chose option 3. Linode is moving accounts to the newer kind, so an operator should be able to use it. The default stays `legacy`, which is what every machine botd made so far has, so nothing changes for anyone who doesn't ask.

## Decision

### The setting

- `MACHINE_LINODE_INTERFACES`: `legacy` (the default) or `linode`. It is the kind of interface new machines get.
- `linode` needs `MACHINE_FIREWALL=on`. Each Linode interface needs a firewall named on it, and leaving it to the account's default could leave a machine open. botd refuses to start without the firewall, as it does for team networks (ADR 0189).
- Set with Incus, or without the control plane, botd refuses to start and says why. Any other value is refused, naming the two allowed.
- `GET /api/machines/substrate` shows it as `settings.interfaces`.

### Creates

Every create now says which kind it wants, so the account's default never decides whether the firewall covers a machine:

- `legacy`: `interface_generation: legacy_config`, the firewall on the Linode, and on a team network public then VPC interfaces, as before.
- `linode`: `interface_generation: linode`, with no top-level firewall. The interfaces are public (the default route) and, on a team network, VPC, each with the machines' firewall. The VPC address is picked by Linode, with no public address mapped onto it.
- An account that refuses the asked-for kind fails the create. The error names `MACHINE_LINODE_INTERFACES`.

### The firewall

- **Covered.** A machine with Linode interfaces counts as behind the firewall only if every public and VPC interface it has is behind it. If any is not, or it has none, it is not. A new provider check, `firewall_covers`, asks this for one machine. The machines' firewall sweep and the team network's checks use it. The firewall's device list groups `linode_interface` devices by their Linode, read from the device's parent or URL. A Linode only partly covered counts as some other device, so the firewall is never released while it is still on one of its interfaces.
- **Attach.** The sweep attaches the firewall to each public and VPC interface not yet behind it. A machine with none is refused, with the reason.
- **Detach.** Detaching removes every device of the machine, on the Linode or on any of its interfaces.

### Joining while off

The rules-first order of ADR 0202 is unchanged. The machine's egress rules must let the subnet through, and it must be behind the firewall, before it joins. A new provider check, `team_network_needs_power_off`, says whether a machine's interfaces are added only while it is off. Linode answers yes for Linode interfaces. Then:

- **Off.** botd adds the VPC interface once the provider says the machine is off, not just when botd has asked for it. It is audited `machine.team_network_joining` with `whileOff: true`. The interface has the firewall the public interface is behind, which is the machines' firewall (checked first). A machine already on another VPC, with no public interface, or whose public interface has no enabled firewall, is refused with the reason, audited once.
- **Running, `MACHINE_TEAM_NETWORK_JOIN=next-boot`.** It waits until its owner or an admin powers it off. botd doesn't power it off for this. The sweep counts it as `awaitingPowerOff`.
- **Running, `when-idle`.** Once its agent says it runs nothing, botd powers it off (`machine.team_network_restarting` with `toJoin: true`). Once it is off at the provider, botd adds the interface and powers it on again, onto the network. botd powers it on again whatever happens: if the interface is refused, if the owner leaves the team meanwhile, or if it isn't off after 10 minutes. A machine refused once isn't powered off again for this. It waits, as with `next-boot`, until botd restarts.
- **Running, `off`.** Nothing joins, as before.

Which machines botd powered off to join is kept in memory, as other joins are (ADR 0202). If botd restarts in between, the machine stays off until its owner powers it on.

### Leaving

- Members are read by interface, not configuration profile. A Linode interface with no profile is now a member, marked as removable only while off.
- A running machine whose owner leaves is powered off first, even if its interface isn't in use yet. Then the interface is removed and the machine powered on again, as in ADR 0189. A machine already off is just taken off.

## Consequences

- Machines that have Linode interfaces, from an account default or made by hand, are now behind the machines' firewall, on every interface. Their inbound drops and outbound rules apply as on any other machine.
- New machines never depend on the account's default kind.
- Machines with Linode interfaces join and leave their team's network. Under `when-idle` that costs one power cycle while idle, as joining already did for machines that needed a boot (ADR 0202). Under `next-boot` it waits for the owner.
- A machine with Linode interfaces can't join or leave while running. Its owner sees a power-off at a quiet time under `when-idle`, or nothing until they power it off themselves.
- `MACHINE_LINODE_INTERFACES=linode` makes machines with both public and VPC interfaces behind one firewall each, which is what Linode recommends for the newer kind.

## Tests

- **Unit** (`machines/linode/interfaces.rs`, against a stateful stand-in with Linode's rules):
  - The kind is `legacy` unless `linode` is asked for.
  - A create always names the kind and puts the firewall on every interface.
  - An interface device's Linode is read from its URL.
  - A Linode with Linode interfaces is covered only when each public and VPC interface is. Attach covers each one, and a Linode with none is refused.
  - A Linode with Linode interfaces joins only while off, behind its public interface's firewall. It is refused while on, on another VPC, with no public interface, or when that interface has no enabled firewall.
  - An account that refuses the asked-for kind gets an error naming the setting.
- **Linode** (`machines/linode.rs`): members include a Linode interface with no profile, marked for removal only while off. Leaving removes the interface itself. A running Linode-interface machine is refused a join with the reason.
- **Startup** (`machines/mod.rs`): `legacy` by default and `linode` when asked, shown in the settings. `linode` without the firewall, an unknown value, the setting on Incus and the setting without the control plane are refused.
- **End to end** (`machines_team_network_tests.rs`, the in-memory provider, which now refuses to add or remove a Linode interface while the machine is on):
  - Under `next-boot`, a running machine waits (`awaitingPowerOff`), is never powered off by botd, waits again while its provider still says it is shutting down, joins once off, is left off, and uses the network from its next boot.
  - A leaver is powered off, taken off and powered on again. A Linode interface not in use yet is still taken off only while off.
  - Under `when-idle`, an idle machine is powered off, held off until its provider says it is off, given its interface, and powered on. When refused, it is powered on again without the interface and not powered off again for it. Powered off by its owner later, it joins and is left off.

## Deferred

- Replacing another firewall already on a Linode interface. Linode allows one per interface, so attaching is refused until an admin removes the other one, as with any refused attach.
- Reading the account's default interface kind and warning when it differs from `MACHINE_LINODE_INTERFACES`.
- Joining at a scheduled time, rather than when idle or at the owner's next power-off.
