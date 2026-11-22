# Runbook: run limits and outbound allow-lists

Bot runs on users' machines are killed, slow, or can't reach a host, because of their run limits or an outbound allow-list ([ADR 0135](../adr/0135-run-limits-and-egress-allow-lists.md), [ADR 0126](../adr/0126-per-user-machine-hardening.md)). Severity: [2](severity.md#severities) if an allow-list change stopped runs for many people, 3 for one person or one task, 4 for tuning.

## First five minutes

1. **Who and what.** The person, the Bot, what the run was doing, and what it said: killed, refused before starting, or a tool that couldn't connect (and to which host).
2. **What their machine holds:**

   ```sh
   botctl user egress <user>        # the server's list, theirs, what they get, whether their machine has it loaded, and its run limits
   botctl machine egress            # the server's list for every machine
   botctl machine show <user>       # the machine, its agent and state
   ```

3. **What the audit log says:**

   ```sh
   botctl audit 50 --action machine.run_limited,machine.run_limits_unavailable --actor user:<email>
   botctl audit 50 --action machine.egress_policy_*,server.egress_policy_changed,user.egress_policy_changed
   botctl audit 50 --action bot.run_refused --bot <bot>
   ```

4. **What changed:** the server's or their list, the tier's `runLimits` in `MACHINE_TIERS`, a resize, a rebuild, or a new tool the Bot started using.

## Run limits

| Sign | Why | What to do |
|---|---|---|
| `machine.run_limited`, killed for memory (the Bot says so in the chat) | The run went over its share of the machine's memory (default 75%) | A smaller job, or a larger machine (`botctl machine resize <user> <tier>`), or a higher `memoryPercent` for the tier |
| `machine.run_limited`, forks refused | The run hit its process limit (default 1024) | A higher `pids` for the tier, if the work needs it (parallel builds do) |
| `machine.run_limited`, CPU held back | The run used its CPU share (default 80%) for 5 seconds or more | Usually fine. A higher `cpuPercent` if runs are slow and the machine is otherwise idle |
| `machine.run_limits_unavailable` | The machine was enrolled before run limits, or its systemd unit lacks `Delegate=` | Runs still go, unlimited. `botctl machine rebuild <user>` gives it limits ([rebuild](../adr/0056-rebuilding-machines-enrolled-before-0039.md)) |

Limits are per run and per tier, never per person or Bot. botd sends them with each run, so a tier change applies from the next run once botd has it.

## Allow-lists

| Sign | Why | What to do |
|---|---|---|
| `bot.run_refused` with `egress_policy_pending` | The person's list isn't loaded on their machine yet, so botd holds runs back | `botctl user egress <user>` shows whether it's loaded; `machine.egress_policy_failed` says why not. Often a machine that's off or an agent from before allow-lists (rebuild it) |
| A tool can't connect to a host | The host isn't on the list | Add it: `botctl machine egress allow <host>...` for everyone, or `botctl user egress <user> allow <host>...` for one person (whose entries join the server's). Each sets the whole list, so give the existing entries too. Model providers, package registries and git hosts must be listed |
| A listed host is refused sometimes | It's behind a CDN and its addresses change; the agent resolves names every 5 minutes | List the provider's published CIDRs instead of the name |
| A listed private address is refused | The machine's hardening rules deny private, shared and metadata addresses whatever the list says | Expected; reach it through a public endpoint, or ask engineering about dedicated hosts |
| A Bot reaches hosts not on the list | Its runs are root (`MACHINE_BOT_USER` off), which the list doesn't hold | `botctl machine bot-user <user>`; lists bind only Bots running as their own user |

Every change to a list is audited with what was added and removed, so a list can be put back from the audit log.

## Escalate when

- A run reaches a host that isn't listed while `MACHINE_BOT_USER` is on, or a run leaves its cgroup: a security issue, [Severity 1](escalation.md#security-incidents).
- `machine.egress_policy_failed` persists on a running machine with a current agent.
- One run's use starves the others on the same machine despite limits.

## Afterwards

Note the cause in the ticket. If the customer tuned a tier's limits or their list, put the change and the reason in their record so the next [health check](health-check.md#5-bots-and-machines) knows it was on purpose.
