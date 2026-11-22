# 0135: Run limits and outbound allow-lists on users' machines

## Status

Accepted (22 Nov 2026). The second slice of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening), after machines hardened at first boot ([ADR 0126](0126-per-user-machine-hardening.md)). Builds on Bots running on their owner's machine ([ADR 0036](0036-bots-on-the-users-machine.md)), the Bots' and teammates' own OS users ([ADR 0043](0043-bots-own-os-user-on-machines.md), [ADR 0048](0048-teammates-own-os-user-on-machines.md)), tiers and their limits ([ADR 0040](0040-billing-v0-tier-limits.md)) and rebuilds ([ADR 0056](0056-rebuilding-machines-enrolled-before-0039.md)).

Numbered 0135 because that number was reserved for this work.

## Context

After ADR 0126, each machine is held to its plan's size, and its Bots can't reach private or metadata addresses. Two gaps were left inside the machine:

- **One run could starve the rest.** Every run on a machine shared its CPUs, memory and process table with the agent and with the owner's other runs (up to the tier's `concurrentRuns`). A runaway build, a fork bomb or a leak in one run could get the agent killed by the kernel's OOM killer, or make it miss heartbeats, and take the others down with it.
- **Outbound was open to the whole internet.** Some admins want Bots to reach only the model providers and registries they use, and nothing else, so a Bot can't send the owner's files anywhere it likes.

## Options

For limits:

1. **systemd transient units per run** (`systemd-run --scope`). systemd does the cgroup work, but the agent would need D-Bus, and Incus containers and minimal images don't always have a usable systemd user manager.
2. **The agent's own cgroup, delegated by systemd.** The unit sets `Delegate=`, and the agent makes a cgroup per run under its own. No new dependency; it works the same on a Linode VM and in an Incus container with cgroup v2.
3. **`setrlimit` per process.** Per process, not per run: a run's children each get the full limit, and there's no CPU share or OOM group.

For allow-lists:

1. **An HTTP proxy** that every run must use. It can filter by hostname, but only for tools that honour proxy settings; everything else would have to be blocked anyway.
2. **nftables on the machine, beside ADR 0126's rules**, with hosts resolved to addresses by the agent. It holds every program, proxy-aware or not, and the deny rules stay as they are.
3. **The provider's firewall** (Linode Cloud Firewall, OVN ACLs). It would hold root too, but it is per machine, not per OS user, so it would also cut off the agent, apt and the harness installs.

We chose limits option 2 and allow-list option 2.

## Decision

### Run limits

- **Per tier, with safe defaults.** A tier's limits may set `runLimits` (`MACHINE_TIERS`, [ADR 0040](0040-billing-v0-tier-limits.md)), as shares of the machine so they hold whatever its size: `cpuPercent` (of all its CPUs, 1 to 100), `memoryPercent` (1 to 100), `pids` (16 to 65536) and `ioWeight` (1 to 10000, 100 is even). Each one left out takes the default: 80% of the CPUs, 75% of the memory, 1024 processes, weight 100. Each run gets these on its own, so one run can't take the whole machine, and the others keep a share.
- **On by default** with `MACHINE_RUN_LIMITS` (`on` or `off`). With it on, the agent's systemd unit gets `Delegate=cpu memory pids io` and `SUPERBOT_RUN_CGROUPS=delegated`. That reaches new and rebuilt machines; a machine enrolled before keeps running, unlimited, until it is rebuilt.
- **Enforced by the agent.** At start, the agent moves its own processes into an `agent` cgroup, turns on the controllers below its unit's cgroup, and makes `runs`, capped at 90% of the machine's memory so the agent always has room. Each run gets `runs/<job>`: `cpu.max`, `memory.max` with `memory.oom.group` (the kernel kills the whole run, not a random process), no swap, `pids.max`, and `io.weight` where the io controller is there. The harness joins its cgroup before it drops to the Bots' or a teammate's user, so it can't move itself out. An empty cgroup is removed when its run ends, or swept at the next start if something outlived it.
- **Sent only to agents that can hold them.** botd sends a run's limits only to an agent whose heartbeat says it can (`run_limits`), because agents from before reject unknown fields. The heartbeat reports whether runs are limited and, if not, why.
- **Audited.** `machine.run_limits_unavailable` (a failure) when an agent can't hold runs to limits, for example a unit from before `Delegate=`. A run reports what its cgroup saw: OOM kills, memory at its limit, refused forks, CPU time held back. botd audits `machine.run_limited` when a run was killed for memory (a failure, and the Bot tells its chat why), had forks refused, or was held back on CPU for 5 seconds or more. `bot.run_routed` records the limits each run was sent.

### Outbound allow-lists

- **Off by default.** The server has one policy for every machine: `open` (today's behaviour) or `allow_list`, a list of hosts and networks. A user can have their own: `inherit` (the default), `open` (their machine stays open while the server's is a list), or `allow_list`, whose entries join the server's. Entries are hostnames (`api.anthropic.com`), IP addresses and CIDRs, at most 256. Wildcards, ports and URLs are refused, as are CIDRs with host bits set and `/0`.
- **Admins only.** `GET`/`PUT /api/machines/egress-policy` for the server's, `GET`/`PUT /api/users/{key}/machine/egress-policy` for a user's: what they get, and whether their machine has it loaded. `botctl machine egress [open|allow <entry>...]` and `botctl user egress <user> [inherit|open|allow <entry>...]`, and in the console's Machines tab. Stored in botd's settings, not new tables.
- **Deny by default, beside ADR 0126's rules.** The agent loads the list as its own nftables table, `inet superbot_allow`: loopback, root and the OS's network daemons pass (as in ADR 0126), and DNS to the resolvers in `/etc/resolv.conf`; then the list's addresses; everything else from any other user is rejected. A packet must pass both tables, so a listed private or metadata address is still denied. The agent resolves hostnames when it loads the list and every 5 minutes after, replacing the table whole, so the rules follow a host's addresses. A host that doesn't resolve allows nothing until it does, and the report says which.
- **Delivered and checked.** botd sends a machine its effective policy when an admin changes it, and again (at most every 10 minutes) whenever a heartbeat shows the agent holds another or failed to load it. The agent saves it, so a restart holds to it, and loads it again on start. While a user's effective policy is a list that isn't loaded on their machine, botd doesn't start Bot runs there: the run is given back, `bot.run_refused` with `egress_policy_pending`, and the Bot says so.
- **Audited.** `server.egress_policy_changed` and `user.egress_policy_changed`, with what was added and removed, and `machine.egress_policy_applied` and `machine.egress_policy_failed` (a failure) when a machine loads or fails to load it.

### What binds whom

- The allow-list holds every user but root and the OS's daemons, so it binds Bots only with `MACHINE_BOT_USER=on`, like ADR 0126's rules: a Bot that runs as root could lift it. Run limits hold either way, but a Bot running as root could move itself out of its cgroup.
- The harness reaches botd through the agent's relay on loopback, which always passes. Model providers, package registries and any other host a harness needs must be listed.

## Tests

- Unit tests: limits as shares of a machine, cgroup setup and counters on a plain folder, entry checking, the rules' order, host resolution, the effective policy and its id, and tier validation.
- End to end on loopback (`machines_egress_policy_tests`): the real agent over mutual TLS with a stand-in `nft`; only admins set a policy, bad entries are refused, a list that fails to load holds runs back and says why, a user's entries join the server's, and every change and report is audited once.
- As root in CI's isolation job (`machines_hardening_tests`): in a network namespace of its own, a harness user (one made after the rules loaded too) reaches only the list's entries, a listed private address stays denied, root passes, and `open` removes the table; and in a real cgroup, a run is held as the Bots' user and can't leave its cgroup, is OOM-killed as a whole over its memory, has forks refused at its process limit, is throttled on CPU, and a run beside it isn't starved.
- On a real Incus host (`machines_incus_e2e_tests`): both containers hold runs to limits, and with a list a new user reaches a listed address but not an unlisted one, root isn't held, and names still resolve.

## Consequences

- One run can no longer take a machine's memory or process table, or all of its CPU, and an OOM kill takes only that run, not the agent.
- An allow-list is per server and per user, not per Bot or per team. A run's tools see a refused connection for an unlisted host.
- Hosts behind CDNs change addresses. Between refreshes a harness may resolve an address the agent hasn't seen yet and be refused until the next refresh. Lists of CIDRs avoid this.
- Machines enrolled before `Delegate=` need a rebuild for run limits; they report it, and runs aren't refused for it.

## Deferred

- Dedicated or VPC hosts for enterprise tiers, and egress policy at the provider (Linode VPC, OVN ACLs), which would hold root too.
- The M5 red-team exercise against all of #54.
- Wildcard domains, which need a filtering DNS resolver or proxy on the machine.
- Per-team and per-Bot policies, and run limits set per user rather than per tier.
- Applying `Delegate=` to machines enrolled before this without a rebuild.
