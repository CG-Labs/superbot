# 0179: Outbound rules at the provider, binding root

## Status

Accepted (23 Nov 2026). The sixth slice of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening), after machines hardened at first boot ([ADR 0126](0126-per-user-machine-hardening.md)), run limits and outbound allow-lists ([ADR 0135](0135-run-limits-and-egress-allow-lists.md)), locked-down run users with a red-team suite ([ADR 0145](0145-locked-down-run-users-and-red-team.md)), a seccomp filter per run ([ADR 0156](0156-seccomp-filter-per-run.md)) and Incus hosts dedicated to a team ([ADR 0166](0166-incus-hosts-dedicated-to-a-team.md)). It is the "egress policy at the provider" half of #54's "VPC hosts". It builds on the machines' provider firewall ([ADR 0035](0035-machine-firewall-auto-enroll.md)) and Incus containers' network ACL ([ADR 0065](0065-incus-container-machines.md)).

Numbered 0179 because that number was reserved for this work.

## Context

Every machine has one line on the way out that only the machine itself enforces: ADR 0126's nftables table keeps every user but root and the OS's network daemons off private, shared and link-local addresses (cloud metadata included) and `MACHINE_EGRESS_DENY`. Root passes, and root can lift the table. ADRs 0126, 0135, 0145 and 0156 each deferred "egress policy at the provider, which would hold root too".

The two providers differ:

- **Incus.** The machines' network ACL already drops TCP and UDP from the whole container to private ranges, the Incus host and `INCUS_EGRESS_DENY`. Incus enforces it on the host, outside the container, so root inside can't lift it (ADR 0065). Containers on the bridge also have port isolation, so they can't reach each other.
- **Linode.** The machines' Cloud Firewall drops inbound but accepts all outbound (ADR 0035). A process that becomes root on a Linode (a Bot that escapes ADR 0145's lock, or one with `MACHINE_BOT_USER=off`) can reach every address the in-machine rules deny: `MACHINE_EGRESS_DENY` (an operator's office or internal services, often on public addresses), Linode's private network ranges, and anything else private the Linode can route to. ADR 0126 says it plainly: "Linode's cloud firewall still accepts all outbound."

Linode's Cloud Firewall takes outbound rules (TCP, UDP, ICMP, IPENCAP; accept or drop, to addresses and ports), applied in order, on the public and private networks. It never filters DHCP, router advertisements or the metadata service. A firewall takes at most 25 rules, and a rule at most 255 addresses.

## Options

1. **Leave it to the machine.** Today's state. Root isn't bound on Linode.
2. **An outbound allow-list at the provider** (ADR 0135's list, deny by default). The firewall is per machine, not per user, so it would also cut off the agent, apt, harness installs and model providers, which root needs. ADR 0135 turned this down for that reason, and it still holds.
3. **The machines' deny list at the provider.** The same list ADR 0126 loads inside every machine, as drop rules on the firewall. Nothing a machine needs is on it: botd is reached on its machine port (let through if botd is on a denied address), names resolve through Linode's public resolvers, and the metadata service is never filtered. It binds root, as the Incus ACL already does.
4. **A network of its own per team** (a Linode VPC or OVN network per team). See Deferred: on its own it adds reachability between a team's machines, not a line around them.

We chose option 3.

## Decision

### The rules

On Linode, with `MACHINE_FIREWALL=on`, the machines' firewall gets outbound rules beside its inbound ones, outbound policy still accept:

1. **`control-plane-port`**: accept TCP to botd's address on its machine port, first, only when `MACHINE_CONTROL_URL` names an address inside the deny list. With botd on a public address, there is no such rule.
2. **`no-private-tcp`** and **`no-private-udp`**: drop TCP and UDP, every port, to the deny list.

The deny list is ADR 0126's, so the firewall and the machine agree: `10/8`, `100.64/10`, `169.254/16`, `172.16/12`, `192.168/16`, `fc00::/7` and `fe80::/10`, plus `MACHINE_EGRESS_DENY` (without ranges inside another). With `MACHINE_HARDENING=off` it is the built-in ranges only, as `MACHINE_EGRESS_DENY` needs hardening on.

- **ICMP stays open.** IPv6 neighbour discovery to the router uses link-local ICMPv6, and dropping it would cut a Linode's IPv6 off. The Incus ACL also drops only TCP and UDP.
- **The metadata service stays reachable from root.** Linode's firewall never filters it. ADR 0126's table still keeps every other user off it, and the enrollment token it serves is single-use and short-lived (ADR 0031).
- **Over 255 ranges is a startup error,** naming `MACHINE_FIREWALL_EGRESS=off` as the way out. Linode would refuse the rules, and every machine create would fail.
- **A `MACHINE_CONTROL_URL` that names a host, not an address,** gets no carve-out, as with the Incus ACL. botd on a private address must be named by its address.

### On by default

`MACHINE_FIREWALL_EGRESS` is `on` unless set to `off`, and needs `MACHINE_FIREWALL=on`. It takes nothing a machine uses away, as ADR 0126's hardening didn't, and it closes a gap ADR 0126 already documented. `off` keeps outbound open at the provider, for an operator whose machines' root must reach a private service; the in-machine rules still bind every other user.

With `MACHINE_PROVIDER=incus`, `off` is a startup error: the network ACL always drops containers' private traffic, and a setting that claims otherwise would mislead. `on` changes nothing there.

### Existing firewalls

The provider reads a firewall's rules as the control plane's only when its outbound rules are exactly these, in this order (a drop before the carve-out would cut botd off). Linode's own spellings count as the same: no ports or `1-65535` for every port, upper-case IPv6, addresses in any order. Anything else reads as not ours, and the reconciler sets the rules again on its next pass (ADR 0035's repair), audited as `machine.firewall_updated`. So an upgrade puts the outbound rules on every existing machine without a rebuild or a reboot, and turning it off takes them off the same way. A firewall made after this is made with them, before any machine is behind it.

### Where it shows

- `machine.firewall_created` and `machine.firewall_updated` carry `outbound`, the rules as sent.
- `GET /api/machines/substrate` shows `firewall.outbound` and `settings.firewallEgress` (`on` or `off`) with `settings.egressRules`.
- Startup says "outbound TCP and UDP dropped to the machines' deny list", or "outbound open (MACHINE_FIREWALL_EGRESS=off)".
- `.env.example`, [backend.md](../backend.md), [the security architecture](../security/architecture.md) and [access control](../security/access-control.md).

## Consequences

- On Linode, root on a machine can no longer reach private, shared and link-local ranges or `MACHINE_EGRESS_DENY` over TCP or UDP. Both providers now hold that line outside the machine.
- Upgrading changes every Linode firewall once, on the reconciler's first pass, with an audit event. Machines need no rebuild.
- A Linode's root can't reach a private service, even one an operator meant it to. `MACHINE_FIREWALL_EGRESS=off`, or leaving the address out of the list, isn't possible per destination yet; it wasn't for Bots either (ADR 0126).
- No cost: Cloud Firewalls and their rules are free.

## Tests

- **Unit** (`machines/linode.rs`): the rules for a public and a private botd, IPv4 and IPv6, the carve-out first; an address of the other family is never inside; over 255 ranges refused. The rules as sent: every port left out, addresses split by family. Read back: Linode's spellings are ours; a swapped order, a missing UDP rule, a narrower list, another protocol, a firewall from before this and one with the rules after they are turned off are not. Against the Linode stand-in, a firewall is made with the rules, one without them reads as not ours, and setting the rules sends them.
- **Settings** (`machines/firewall.rs`, `machines/mod.rs`): on with the firewall unless `off`, refused without it or with another value; the deny list is ADR 0126's with or without hardening; botd's address is read only when it is one. A Linode control plane gets the rules, with `MACHINE_EGRESS_DENY` and a carve-out for a private botd, and none with `off`; startup says which. Incus refuses `off`.
- **End to end** (`machines_lockdown_tests.rs`, the fake provider): `machine.firewall_created` carries the provider's outbound rules, and a firewall whose rules were changed is set again with them, in `machine.firewall_updated`.

## Deferred

- **A network of its own per team** (a Linode VPC, or an Incus OVN network per team with dedicated hosts). Today no machine shares a private network with another: Linodes get no private address, and Incus containers have port isolation. A team network would let a team's machines reach each other, which is a feature to ask for, and would need the deny list carved for it on both sides. It stays #54's last part.
- Per-destination exceptions to the deny list, for root and Bots alike.
- ICMP to private ranges, once IPv6 neighbour discovery can be told apart.
- Outbound rules for the machines' own allow-lists at the provider (option 2), should a provider ever filter per process.
