# 0126: Per-user machines hardened at first boot

## Status

Accepted (22 Nov 2026). Part of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening). Builds on machines and their first boot ([ADR 0025](0025-control-plane-linode.md), [ADR 0031](0031-machine-enrollment-mtls.md), [ADR 0035](0035-machine-firewall-auto-enroll.md)), Incus containers and their isolation boundary ([ADR 0065](0065-incus-container-machines.md), [ADR 0069](0069-validating-incus-containers-on-a-real-host.md)), the Bots' and teammates' own OS users ([ADR 0043](0043-bots-own-os-user-on-machines.md), [ADR 0048](0048-teammates-own-os-user-on-machines.md)) and rebuilds ([ADR 0056](0056-rebuilding-machines-enrolled-before-0039.md)).

Numbered 0126 because 0119 to 0125 are taken by other open PRs.

## Context

#54 asks for harnesses as a separate OS user, cgroup and egress limits, dedicated or VPC hosts, and a red-team scenario. Much of that exists:

- **Separate OS users.** On a machine the agent stays root and runs every Bot as `superbot-bots` (ADR 0043), and a teammate's runs as their own `superbot-t-…` user (ADR 0048).
- **cgroup limits per machine.** An Incus container is held to its tier's CPUs, memory and processes (ADR 0065). A Linode is a VM of its plan's size.
- **A kernel of its own.** Linode VMs, and `MACHINE_OWN_KERNEL_TIERS` for the tiers that must have one ([ADR 0120](0120-managed-substrate.md)).
- **Inbound.** The provider firewall drops everything but the agent's port from botd, and SSH only from `MACHINE_SSH_SOURCES` (ADR 0035).

What was missing is inside the machine:

- **Outbound was open to everything.** A Linode's firewall accepts all outbound traffic, so any process on it, a Bot included, could reach the cloud metadata service at `169.254.169.254` and its IPv6 twin. That keeps the machine's user data for the machine's life (ADR 0035), and any private network the provider gives it. On Incus the network ACL already drops private ranges for the whole container (ADR 0065), but that is the container's limit, the same for root and for Bots.
- **The OS was the image's defaults.** sshd's settings were the image's, which on some images allow root to sign in with a password. Linode sets a random root password (ADR 0025). Nothing turned on security updates where the image didn't, and the kernel settings were the defaults.
- **Nothing reported on any of it.** botd couldn't tell a hardened machine from one that wasn't.

## Options

1. **Ship a hardened image.** Strongest, but it means building and publishing an image per provider and per release. Incus and Linode both start from stock cloud images today, and a custom image would pin us to one distribution release.
2. **Have the agent apply hardening at runtime, from botd's settings.** It could reach machines enrolled before this. But it puts sshd, apt and nftables logic in the agent, which upgrades itself, and a failed upgrade would undo it.
3. **Harden in the first boot that botd already writes.** That is cloud-init user data, before the agent installs. It reaches every new and rebuilt machine with no new image and no new agent protocol. The agent only reports what the first boot left.

We chose 3. A machine enrolled before this gets hardening when it is rebuilt (ADR 0056).

## Decision

### On by default

| Setting | Meaning |
|---------|---------|
| `MACHINE_HARDENING` | `on` (the default) or `off`. Needs `MACHINE_CONTROL_URL`, like every machine setting. |
| `MACHINE_EGRESS_DENY` | More CIDRs that Bots and teammates can't reach from a machine, comma-separated, on top of the built-in list. Each must be a network's own address. A range inside another is dropped, because nft refuses overlapping ranges. Setting it with `MACHINE_HARDENING=off` is a startup error. |

Machine settings are off by default when they add a feature (ADR 0043, 0045, 0048). This one is on, as sandboxes ([ADR 0055](0055-harness-sandbox-defaults.md)) and encrypted backups ([ADR 0114](0114-backups-encrypted-by-default.md)) are, because it takes no feature away:

- SSH still lets root in with a key, which is how an operator gets in (`MACHINE_SSH_SOURCES`, `MACHINE_AUTHORIZED_KEYS`).
- Updates are the distribution's security updates only, and never reboot.
- No Bot needs a private address. Bots call botd through the agent on loopback (ADR 0036), and names resolve through the resolver.

Self-hosted servers have no machines, so nothing changes for them.

### What the first boot does

The cloud-init user data gets five more files. Before the agent downloads, the first boot runs one more step. The egress rules are loaded before the agent ever starts, so no Bot runs without them. No step stops the machine from enrolling. Each step's outcome goes to `/etc/superbot/hardening` as a `step=state` line (`on`, `partial`, `none` or `failed`). nftables and unattended-upgrades are installed only if the image lacks them.

| Step | File | What it does |
|------|------|--------------|
| `ssh` | `/etc/ssh/sshd_config.d/00-superbot-hardening.conf` | `PermitRootLogin prohibit-password`, `AllowUsers root`, no passwords or keyboard-interactive, `MaxAuthTries 3`, a 30-second login grace, idle sessions dropped, and no TCP, agent, X11 or socket forwarding or tunnels. sshd keeps the first value it reads and reads its drop-ins first, so `00-` wins over the image's settings. The step checks `sshd -t` and that `sshd -T` reports no passwords. If either fails, it removes the file and records `failed` rather than break sshd. With no sshd, it records `none`. |
| `kernel` | `/etc/sysctl.d/60-superbot-hardening.conf` | Hides kernel pointers and `dmesg`, sets `ptrace` to descendants only, turns off unprivileged BPF and SysRq, hardens the BPF JIT, protects links, FIFOs and regular files in sticky folders, turns off setuid core dumps, and turns off redirects and source routing, with reverse-path filtering, SYN cookies and logged martians. `systemd-sysctl` applies it on every later boot. In a container the `kernel.*` keys are the host's, so the step records `partial`. That is not a failure: the Incus host's own settings apply (below). |
| `updates` | `/etc/apt/apt.conf.d/52superbot-upgrades` | Turns on daily package lists and unattended upgrades and weekly autoclean, removes unused kernels, and sets `Automatic-Reboot "false"`. It sorts after the package's own `20auto-upgrades`, so it wins. The origins stay the distribution's default, its security pocket. The step enables `apt-daily` and `apt-daily-upgrade`. |
| egress | `/usr/local/lib/superbot/egress` and `superbot-egress.service` | Below. |

### Egress rules on the machine

The script loads one nftables table, `inet superbot_egress`, with one chain on the output hook:

1. Loopback passes. Bots reach the agent's relay to botd this way.
2. Root passes, and so do the OS's own network daemons that exist on the machine: `systemd-resolve`, `systemd-network`, `systemd-timesync`, `_apt` and chrony or ntp. They are matched by uid, looked up when the rules load.
3. Port 53 to each resolver in `/etc/resolv.conf` passes, so names still resolve where the resolver is on a private address.
4. Everything else to the deny list is rejected and counted. The list is `10/8`, `100.64/10`, `169.254/16`, `172.16/12`, `192.168/16`, `fc00::/7` and `fe80::/10` (the same as the Incus ACL's), plus `MACHINE_EGRESS_DENY`. That covers Linode's and other clouds' metadata addresses, Linode's private network, and the Incus bridge and host.

The rules name who may pass, not who may not. So the Bots' user, every teammate's user, and any user a Bot's run or an install makes later is held from the moment it exists, with no race against a reload. A uid that root makes later can pass only if it is one of the named daemons, and those are looked up only at boot.

`superbot-egress.service` loads the rules again on every boot, after the network is up and before `superbot-machine.service`, which wants it. The script writes `on` or `failed` to `/run/superbot-hardening/egress`. `/run` is cleared at boot, so that file speaks only for this boot.

If the rules fail to load, the machine still runs, and botd records the failure (below). We chose this over refusing runs: a missing package mirror at first boot shouldn't take a user's machine away. botd's records are what an operator acts on. Rebuilding the machine tries again.

**What this does not cover:**

- **Bots that run as root.** With `MACHINE_BOT_USER=off` (still the default), Bots run as root, and root passes and can change the rules. Turn on `MACHINE_BOT_USER` for the rules to bind Bots. `.env.example` and the docs say so.
- **The internet.** Public addresses stay open: harnesses need model providers, package registries and the web. An allow-list of providers is future work (Deferred).
- **Containers already behind the Incus ACL.** There, the ACL already holds the whole container. These rules add the line between root and Bots, and cover `MACHINE_EGRESS_DENY` inside the machine.

### Reported in the heartbeat

The agent adds `hardening` to its heartbeat: each step from `/etc/superbot/hardening`, whether this boot's egress rules are loaded, and whether `/run/reboot-required` exists. Only root writes those files, but the agent still reads at most 1 KiB of each, and at most eight short lower-case `step=state` lines. An agent on a machine that wasn't hardened sends nothing. botd keeps the report with the agent's other reports (`agentUpkeep.hardening` in the admin's machine view) and audits changes, once each:

| Action | When |
|--------|------|
| `machine.hardened` | Every step is `on`, `partial` or `none`, and the egress rules are loaded. Recorded the first time, and again after a failure. |
| `machine.hardening_failed` | A step `failed`, or the egress rules aren't loaded (`failing` lists which). Outcome `failure`. Recorded again only when what fails changes. |
| `machine.reboot_required` | Updates start waiting on a reboot. A reboot is the operator's call, since it ends Bots' runs. |

### What the Incus host must do

A container shares its host's kernel (ADR 0065), so `kernel.*` hardening belongs on the host. The operator guide's host checklist gains it: the same sysctls in the host's `/etc/sysctl.d`, unattended security updates on the host, and no swap if containers mustn't use it (ADR 0069).

## Tests

- **Unit:** the settings (on by default, `off`, bad values, `MACHINE_EGRESS_DENY` checked, duplicates and nested ranges dropped), the egress script (loopback, then named uids, then the deny lists; no harness user ever passes by name; no empty set), the SSH drop-in's name and keywords, and the agent reading the status files with care.
- **botd:** the user data carries every file, and its first boot hardens and loads the rules before it downloads, enrolls and starts the agent. Both scripts pass `sh -n`. The token is still in one place, and `MACHINE_HARDENING=off` leaves all of it out. Heartbeats are recorded once per change, and admins see the report.
- **As root, in CI's isolation job** (`machines_hardening_tests`): in a network namespace of its own, the real script loads the real rules. `nobody` is refused at every private, shared, link-local and metadata range and at a `MACHINE_EGRESS_DENY` range, but still sends to a public address. Root sends to the same private and metadata addresses. A user made after the rules loaded is held too. Each probe has a control without the rules.
- **On a real Incus host** (`machines_incus_e2e_tests`): both containers record every step, with the rules loaded and the unit enabled, sshd allowing no passwords and unattended upgrades on. A user made inside the container can't reach botd's machine port, which root reaches, or the metadata address, but still reaches the internet and resolves names. botd records `machine.hardened` for each.

## Consequences

- New and rebuilt machines take a little longer to enroll when the image lacks nftables or unattended-upgrades, since they are installed first.
- Existing machines are unchanged until rebuilt. Their heartbeat has no `hardening`, which tells them apart.
- An operator who needs Bots to reach a private service from a machine has to turn hardening off, for now. A per-destination allow is future work.
- Linode's cloud firewall still accepts all outbound. These rules are what holds Bots back there.

## Deferred

- Hardening machines enrolled before this without a rebuild (option 2, for the egress rules at least).
- cgroup limits per run inside a machine (CPU, memory and processes per Bot or teammate), beyond the machine's own.
- An outbound allow-list (model providers, registries) per tier, and per-user egress policy at the provider (Linode VPC, OVN ACLs).
- auditd and file integrity checks. Kernel audit isn't namespaced, so it can't run in a container; VMs could have it.
- Dedicated or VPC hosts for enterprise tiers, and the M5 red-team exercise against all of this.
