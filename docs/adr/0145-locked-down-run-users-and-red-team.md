# 0145: Locked-down run users by default, and a red-team suite

## Status

Accepted (22 Nov 2026). The third slice of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening), after machines hardened at first boot ([ADR 0126](0126-per-user-machine-hardening.md)) and run limits with outbound allow-lists ([ADR 0135](0135-run-limits-and-egress-allow-lists.md)). Builds on per-user isolation ([ADR 0029](0029-per-user-isolation.md)), per-user Unix accounts on one server ([ADR 0037](0037-per-user-unix-accounts.md), [ADR 0058](0058-harness-os-user-by-default.md)), and the Bots' and teammates' own OS users on machines ([ADR 0043](0043-bots-own-os-user-on-machines.md), [ADR 0048](0048-teammates-own-os-user-on-machines.md)).

Numbered 0145 because that number was reserved for this work.

## Context

#54 asks that each Bot's harness run as a separate, unprivileged OS user: no shared home, no access to other Bots' files or the server's data and secrets, no sudo. And for a red-team scenario that tries to break out and shows it fails.

Most of the parts were there, but not on by default, and not tight:

- **On a machine, Bots ran as root unless an admin opted in.** `MACHINE_BOT_USER` was off by default, so a Bot could read the agent's key, lift ADR 0126's egress rules and ADR 0135's allow-list, and leave its cgroup. Both ADRs said their rules bind Bots only with it on.
- **Nothing stopped a run getting privileges back.** A Bots' or teammate's user was unprivileged, but a run could still exec a setuid program or one with file capabilities. Nothing checked that the user wasn't in `sudo`, `docker` or `adm`, or had a sudo rule, for example one an image or an admin added by hand.
- **Files in shared places were readable.** The agent unit's `PrivateTmp=yes` gives the agent and every run one `/tmp`. With the usual umask 022, the owner's run left files there that a teammate's run could read.
- **Other users' processes were visible.** Any run could list every process on the machine, with its command line.
- **One server, `ISOLATION=users`:** a per-user account could not use sudo (ADR 0037's sudo rule is only for the service account), but its run could still exec setuid programs.

## Options

For whom each run is:

1. **A uid per Bot.** Every Bot its own user. But an owner's Bots share the owner's workspace on purpose (one folder, one set of harness logins, files passed between them); giving each its own uid means either a shared group over all of it, which puts back what it took away, or copies and syncs between Bots. The data a Bot could reach would not shrink.
2. **A uid per person (owner or teammate), as today, made the default and locked down.** The boundary is the person, which is where the data and the secrets already split (ADR 0029, 0046): an owner's Bots run as `superbot-bots` on the owner's machine (`sb-u-<id>` on one server), each teammate's runs of them as the teammate's own user (`superbot-t-<hash>`, `sb-t-<hash>`).
3. **A container or VM per run.** Strong, but heavy for every chat turn, and machines are already one per person (ADR 0036). Dedicated or VPC hosts are #54's next slice.

We chose option 2.

For "no sudo":

1. **Trust the image.** Today's state.
2. **Check users at start and lock processes down.** No new privileges on every process a run starts, and the agent refuses a run user that has any way up.
3. **Remove setuid bits from the machine.** Breaks the OS's own tools for root, and comes back with each package update.

We chose option 2.

## Decision

### Bots' own user on by default

- **`MACHINE_BOT_USER` is on unless set to `off`.** Anything else is still refused. New and rebuilt machines get the user at first boot, as before.
- **Upgrading moves files over, as ADR 0043 already does.** After a heartbeat botd asks each idle agent to switch; the agent makes `superbot-bots`, hands it the Bots' home (workspace, logins, folder copy) without following links, and runs every harness, login and cleanup as it from then on. Runs wait for it (`bot_user_pending`) and never fall back to root or the server. An agent too old to switch is refused (`agent_outdated`) until it's upgraded or rebuilt, as before.
- **Opting out is loud.** `MACHINE_BOT_USER=off` logs a warning at every start that Bots run as root and what that gives them. The installer's upgrade says what will change for a control plane that never set it, and warns again for one that set `off`.
- **`MACHINE_TEAMMATE_USERS` still needs it,** and stays off by default: turning it on changes how shared Bots log in (ADR 0048), so it remains an admin's choice. It can now be turned on alone.

### Locked down

Every process the agent starts as a Bots' or teammate's user (harness runs, logins in a terminal, folder copies, cleanups, the sandbox probe) gets:

- **No new privileges** (`PR_SET_NO_NEW_PRIVS`), for its whole life and every exec: setuid and setgid programs (sudo, su, pkexec, newgrp, a copied root shell) run with the caller's ids, and file capabilities aren't granted. Screens get it too.
- **umask 077**, so what it makes, in `/tmp` included, is its own.
- **A temporary folder of its own.** Each run gets `TMPDIR=<home>/.tmp/<job>` (0700, made as its user), removed in the background when it ends; logins get `<home>/.tmp`, made before each one (as the teammate, for a teammate's). At its start, on a thread of its own and off its requests' path, the agent removes from those folders whatever neither it nor anything in it has changed for a day (as their owner, without following links, and looking through at most 50,000 entries per leftover), so what crashed runs and logins left doesn't pile up.
- **An OOM score floor of 500,** set while the agent is still root. On a machine short of memory the kernel kills a run before the agent or the OS's daemons, and a run can't lower its score back down, even where a root process up the tree once set the floor lower.
- **Joining its cgroup first,** as in ADR 0135, so it can't leave it.

The agent **refuses a run user with a way up**: one that is root or in root's group, in a group that gives root or other users' files (`root`, `sudo`, `wheel`, `admin`, `adm`, `docker`, `lxd`, `incus`, `incus-admin`, `libvirt`, `disk`, `shadow`, `systemd-journal`, `staff`), or with a sudo rule: sudo itself is asked (`sudo -l -U <user>`, as root, so rules from any source it reads count), and its files are read too (`/etc/sudoers`, `/etc/sudoers.d` and what they include; by name, uid, group, nested `User_Alias` or `ALL`), in case it can't answer. The Bots' user is checked at start and before each switch; a teammate's at each run. A refused Bots' user shows as `bot_user_failed` with the reason, as any other failure to make it; runs wait.

The agent's unit adds `ProtectProc=invisible`: a run sees only its own user's processes, not the agent's or another person's. It already had `NoNewPrivileges=yes` and `PrivateTmp=yes`. Units change on new and rebuilt machines; an agent upgrade keeps the old unit, so the code above holds the line without it.

Each heartbeat says the agent can lock runs down (`locked_down`), and the agent view shows `botUser.lockedDown`, so an admin can see which machines still run an agent from before this.

### One server

`superbot-run`, which every run under `ISOLATION=users` goes through, sets no new privileges before it execs the harness. Per-user accounts already had no sudo and no shell. With `ISOLATION=users`, botd checks for harness sandboxes with no new privileges too, so a host whose only `bwrap` is setuid is seen as having none.

### Red team

A suite of scenarios, run as root in CI's isolation job, tries what a hostile Bot would, each as a real locked-down run on a real kernel, and asserts each is stopped:

- **Privilege escalation** (`as_root_red_team_a_run_cant_raise_its_privileges`): a sudo rule for the run user, a setuid copy of `id` and a `cat` with `cap_dac_read_search` don't help a locked-down run (each works for the same user without the lock, so the test can tell). A sudo rule or a privileged group is found.
- **Cross-person and secrets** (`as_root_red_team_bots_cant_reach_another_persons_files_or_the_agents_secrets`): the real agent over mutual TLS runs a Bot for its owner and a teammate. Neither reads the other's home, logins or `/tmp` files; neither reads the agent's key, certificates, records or the agent's process. Giving the Bots' user a sudo rule, or the `docker` group, makes the agent refuse it.
- **Getting past the allow-list** (`as_root_red_team_a_run_cant_get_past_or_change_the_allow_list`): in a network namespace with ADR 0135's rules, a run reaches only listed addresses, and can't send raw packets, flush or delete the rules, or change links, routes or namespaces; root still can.
- **Exhausting the machine** (`as_root_red_team_a_run_cant_exhaust_the_machine`): a fork bomb, a memory balloon and a CPU spin, each in its own run, are held to their limits, a run beside them finishes, a real agent keeps answering heartbeats over mutual TLS within 2 seconds, and a run can't raise its own limits, leave its cgroup, make a child cgroup or lower its OOM score.

`deploy/test-isolation.sh` also checks that a run through `superbot-run` can't gain privileges.

## Consequences

- A fresh or upgraded control plane runs every Bot on a machine as an unprivileged, locked-down user, so ADR 0126's egress rules and ADR 0135's allow-list and cgroups bind Bots by default.
- Agents from before ADR 0043 hold runs until an admin upgrades or rebuilds them. That is the price of a secure default; `MACHINE_BOT_USER=off` is there for an admin who must keep them running meanwhile.
- A harness that relies on a setuid helper won't get it. A setuid `bwrap` (from distributions before unprivileged user namespaces) can't start a sandbox under no new privileges; the sandbox probe now runs the same way, so botd sees that and handles it as ADR 0055 does for any host without a working sandbox: the run goes without, `harness.invoked` records `unavailable`, and botd warns at start. AppArmor's `bwrap` profiles still apply, since entering a profile from unconfined is allowed.
- A teammate's run sees and reads less of the owner's: no files in `/tmp`, no processes (on new and rebuilt machines).
- Tools that list every process on the machine see only their own user's.

## Deferred

- Dedicated or VPC hosts for enterprise tiers, and egress policy at the provider (Linode VPC, OVN ACLs), which would hold root too: #54's next slice.
- Disk quotas per run user. A run can still fill the machine's disk; storage limits (ADR 0082) count it after the fact.
- `ProtectProc=invisible` on machines enrolled before this without a rebuild.
- A seccomp filter per run, beyond what harness sandboxes already apply.
