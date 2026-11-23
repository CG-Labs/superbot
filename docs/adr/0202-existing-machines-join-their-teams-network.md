# 0202: Existing machines join their team's network without a rebuild

## Status

Accepted (23 Nov 2026). The eighth slice of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening). It does what [ADR 0189](0189-a-network-of-its-own-per-team.md) deferred first: "existing machines joining without a rebuild". It builds on the in-machine egress rules of [ADR 0126](0126-per-user-machine-hardening.md) and the agent's heartbeat follow-ups, as outbound allow-lists use them ([ADR 0135](0135-run-limits-and-egress-allow-lists.md)).

## Context

ADR 0189 puts a team member's machine on the team's Linode VPC when the machine is made. Turning `MACHINE_TEAM_NETWORK=vpc` on changes nothing for machines that already exist. Neither does someone with a machine joining a team. Their only way on was a rebuild or a new machine, which costs the machine's state and a few minutes of the user's time.

Two things stand in the way:

1. **The machine's own egress rules.** The first boot writes the harness egress rules (ADR 0126) as a script, `/usr/local/lib/superbot/egress`, which the unit runs again on every boot. Only a team machine's script accepts the team's subnet, before the deny lists. Without that line the machine can be on the VPC and still not reach anything there.
2. **The interface.** Linode lets an interface be added to a running Linode's configuration profile. It takes effect at the next boot. An interface not in use yet can be removed while the machine runs. An interface in use can't.

## Options

1. **Keep rebuilds as the only way.** Simple, but it is exactly what operators turning the feature on asked us not to make them do to every machine.
2. **Rewrite the rules from botd**, by sending the whole new script. botd would then own a copy of the first boot's script for every agent version, and a mistake would replace the machine's rules wholesale.
3. **The agent edits one line of its own script.** botd sends only the subnet. The agent validates it, puts its accept line in place of any other in the deny lists' heredoc, and runs the script, as the unit does at boot. Then botd adds the interface, for the next boot. Restarting the machine is the operator's choice: wait for one, or have botd do it when the machine is idle.

We chose option 3.

## Decision

### The rules first

- The agent has a new endpoint, `PUT /v1/team-network {subnet}`, and a new capability, `team_network`. The subnet must be an IPv4 network with no host bits, inside RFC 1918, no smaller than a `/29`; anything else is refused, so nothing but a CIDR ever reaches the script. `null` takes the line out.
- The agent writes the script atomically (a new file, mode `0755`, renamed over the old) and runs it. The script replaces the rules' table whole, in one transaction, so the machine is never left half-way. It is run with `SUPERBOT_HARDENING_STATE` set to a place under the agent's state directory, since the unit's own place under `/run` is read-only to the agent.
- Only the first boot's script is edited: one whose deny lists sit in the quoted `cat <<'DENY'` heredoc. A script that isn't is left alone and reported `failed`. A machine with no script (not hardened) reports `none`: it has no deny rules, so nothing needs letting through.
- Every heartbeat now carries `teamNetwork: {subnet, state: on | failed | none, error}`, read from the script itself. botd keeps it with the machine's other upkeep. A change is audited as `machine.team_network_rules_loaded`, or `machine.team_network_rules_failed` (outcome failure).
- After each heartbeat, botd sends the agent the subnet it should let through: the team network's if the owner is on a team, else none. It sends only when the agent's rules differ or failed, and at most every 10 minutes for the same answer, as for allow-lists. Machines with no script are never sent anything.

The edited script is exactly the one a first boot on the network would write. A unit test holds the two to that.

### Then the interface

Each reconcile pass, after the leaving step of ADR 0189, looks at every machine of ours that is running or suspended, whose owner is on a team, and that has no interface on any team network. If its agent says its rules let the team's subnet through, or that it has no rules, then under the lock team changes take, and with the owner's team checked again:

- The team's VPC is found or made, as for a new machine (`machine.team_network_created`).
- The machine is given a VPC interface on the team's subnet, for its next boot. On Linode, an empty interface list means "public only", so the public interface is added first, keeping it the primary. This is audited as `machine.team_network_joining`, with the team, VPC, subnet and join mode.
- Linode refuses some machines, with a reason. They stay off the network until rebuilt: machines with Linode interfaces (the newer kind, each with its own firewall, which our one firewall doesn't cover), machines with more than one configuration profile, machines on another VPC, and machines whose first interface isn't public. A refusal is audited once per machine and reason (outcome failure), not on every pass.

A machine whose agent hasn't confirmed the subnet yet is counted as `waiting`. Agents too old to report wait until they are upgraded ([ADR 0039](0039-machine-harnesses-and-agent-upgrades.md)). The machine is never put on a network its rules would block.

### Then the boot

`MACHINE_TEAM_NETWORK_JOIN` decides when the interface comes into use:

- **`next-boot`** (the default). botd waits for the machine's next boot, whether its owner's, an admin's, or an upgrade's. Until then the reconciler counts it as `pending`.
- **`when-idle`**. Once a fresh heartbeat shows no runs on the machine, botd suspends it through the normal suspend path and powers it on again on the next pass, as it does for leaving (ADR 0189). This is audited as `machine.suspended`, then `machine.team_network_restarting`, then `machine.resumed`. A run that starts between that heartbeat and the power-off ends with it, as a rebuild's would. The same rules as leaving apply to powering on: never for a disabled owner, a disable hold or a returned team machine.
- **`off`**. Only new or rebuilt machines join, as before this ADR. No agent is sent a subnet.

It needs `MACHINE_TEAM_NETWORK=vpc`; set without it, botd refuses to start.

Once the machine uses the interface, `machine.team_network_joined` is audited. botd remembers which machines it put on only in memory. After a restart it learns them again from Linode's "not in use yet" flag, so a machine still waiting for its boot is audited as joined once it boots. One that booted while botd was down is not.

### Leaving before the boot

A machine whose owner leaves the team while its interface isn't in use yet loses the interface at once. It isn't powered off for it, since nothing went through it. This is audited as `machine.team_network_left` with `inUse: false`. Its rules lose the subnet on the next heartbeat. A machine using the interface leaves as ADR 0189 says.

### Where it shows

- The reconciler reports `teamNetworks` with `joining`, `pending`, `restarting`, `joined` and `waiting` beside `leaving`, `left`, `resumed` and `errors`, each only when non-zero.
- `GET /api/machines/substrate` shows `teamNetwork.join`.
- `.env.example`, [backend.md](../backend.md), [access control](../security/access-control.md) and [the security architecture](../security/architecture.md).

## Consequences

- Turning team networks on, or joining a team, now reaches existing machines. With `next-boot` they join over the following days as machines restart. With `when-idle` they join within a few reconcile passes of their next idle moment.
- The order is safe both ways. A machine's rules let the subnet through before the interface exists, and lose it after the interface goes. The subnet is private, and a Linode reaches it only through an interface on a VPC that holds it. So a machine whose rules let it through but that isn't on the VPC reaches nothing new.
- `when-idle` powers machines off without asking their owners. It is opt-in, and only ever when idle. Restarting a machine already drops its in-memory state, as rebuilds and upgrades do.
- More agent calls: at most one per machine per 10 minutes while its rules are wrong. More provider calls per reconcile: one instance read and one configuration list per joining machine, until it joins or is refused.

## Tests

- **Unit** (`machines/team_rules.rs`): only private IPv4 networks no smaller than a `/29` are taken, and nothing else reaches the script; the accept line goes first in the deny lists, only one, and comes out again; scripts that aren't ours and lines outside the heredoc are left alone. (`machines/hardening.rs`): the edited script equals the first boot's script for a team machine.
- **Agent** (`machines/agent.rs`): the subnet is written in and loaded, read back, and withdrawn; the script keeps its mode and leaves no temporary file; a script that fails says so until a change; a missing script is `none`; someone else's is untouched and `failed`.
- **Linode** (`machines/linode.rs`, against the stand-in): members say whether their interface is in use; joining adds public then VPC to a machine with none, VPC alone after a public one, nothing when already on; and it refuses Linode interfaces, two profiles and another VPC, and never sends an id that isn't a number.
- **End to end, in memory** (`machines_team_network_tests.rs`): a machine made before its owner joined a team waits until its rules let the subnet through, joins for its next boot without being restarted, and loses the interface at once, without a power-off, if its owner leaves first; a refusal is audited once; it is joined once it boots, audited once.
- **End to end, real agent** (`machines_team_network_tests.rs`, over mutual TLS): with `when-idle`, the agent lets the subnet through when its owner joins a team, the machine joins, stays on while a run is in progress, and is powered off and on once idle; leaving takes it off and the agent's rules lose the subnet, all audited.

## Deferred

- **Incus: an OVN network per team**, as ADR 0189 deferred.
- **Linode interfaces**, each with a firewall of its own, so machines that have them can join too.
- Restarting a machine on a schedule the team picks, rather than when idle.
