# 0156: A seccomp filter on every run

## Status

Accepted (23 Nov 2026). The fourth slice of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening), after machines hardened at first boot ([ADR 0126](0126-per-user-machine-hardening.md)), run limits and outbound allow-lists ([ADR 0135](0135-run-limits-and-egress-allow-lists.md)), and locked-down run users with a red-team suite ([ADR 0145](0145-locked-down-run-users-and-red-team.md)), which deferred this filter.

Numbered 0156 because that number was reserved for this work.

## Context

ADR 0145 locks every run down: an unprivileged user, no new privileges, its own umask and temporary folder, an OOM score floor, a cgroup it can't leave. What a locked-down run can still reach is the whole kernel's system call interface. That matters most where machines share a kernel: Incus containers on one host (ADR 0065) share it, so a kernel bug reached from one user's run crosses every user on that host. `MACHINE_OWN_KERNEL_TIERS` (ADR 0120) gives the tiers that need it a VM instead, but not every tier.

Several kernel interfaces are where exploits keep starting, and a harness run doesn't use them:

- **Keyrings** (`keyctl`, `add_key`, `request_key`).
- **eBPF and perf events** (`bpf`, `perf_event_open`). ADR 0126's sysctls turn off unprivileged eBPF and restrict perf, but inside a container those sysctls are the host's, so the machine can't set them.
- **`userfaultfd`**, used to win races in kernel exploits.
- **io_uring**, which Google, Docker and ChromeOS turn off for untrusted code after a run of bugs.
- **File handles** (`open_by_handle_at`, the "shocker" container escape), `lookup_dcookie` and `fanotify_init`.
- **The kernel log** (`syslog`), which can leak kernel addresses; `dmesg_restrict` is another of the host's sysctls in a container.
- **Calls only an administrator makes**: modules, kexec, reboot, swap, accounting, quotas and setting the clock. These need capabilities a run hasn't got, so refusing them costs nothing and still holds if a kernel bug ever grants one.

Harness sandboxes (bubblewrap, Codex's Landlock and seccomp, Chromium's sandbox; ADR 0055, ADR 0107) apply filters of their own, but only inside the sandbox, only for some harnesses, and not for what a run starts outside it.

## Options

1. **An allow-list of system calls**, as Docker's default profile is. Tightest, but a harness, its tools, Node, Python, browsers and sandboxes together use hundreds of calls, which change with each kernel and libc. A call missed there breaks runs in ways that are hard to trace back.
2. **A short deny-list of the risky interfaces above**, with everything else allowed. It closes the interfaces exploits use most, and can't break what a run does, since none of them are things a run does.
3. **AppArmor or SELinux profiles.** They depend on the distribution and the host (containers can't load their own AppArmor profiles without the host's help), and they confine files more than system calls, which ADR 0145 already does by user.

We chose option 2. It is the same filter on every machine and on one server, with no dependency on the host.

## Decision

### The filter

A classic BPF seccomp program (`server/src/machines/seccomp.rs`), built at compile time, so installing it allocates nothing between fork and exec:

1. A call through another ABI is **killed**: the i386 ABI or x32 on x86_64, or 32-bit Arm on aarch64. A filter for one ABI can't read another's numbers, so that is the usual way around a deny-list.
2. The listed calls fail with **EPERM**: `keyctl`, `add_key`, `request_key`, `bpf`, `perf_event_open`, `userfaultfd`, `open_by_handle_at`, `lookup_dcookie`, `fanotify_init`, `syslog`, `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `reboot`, `swapon`, `swapoff`, `acct`, `quotactl`, `quotactl_fd`, `settimeofday`, `clock_settime`, `clock_adjtime`, and on x86_64 `iopl`, `ioperm`, `uselib` and `_sysctl`.
3. io_uring's three calls fail with **ENOSYS**, as on a kernel without it, since that is what programs that can do without it look for before falling back (libuv, and so Node).
4. Everything else is allowed.

User namespaces, mounts inside them, `pivot_root`, `seccomp`, `prctl`, Landlock and `ptrace` stay allowed, so harness sandboxes and Chromium's still start, and debuggers still work on a run's own processes (Yama still limits `ptrace` to descendants, ADR 0126). The filter can only ever be added to: a run can install a stricter one of its own, but never remove this one.

x86_64 and aarch64 have a filter. On any other architecture the agent runs without it and says so (below).

### Where it applies

Wherever ADR 0145 locks a process down, after no new privileges and before exec:

- **On a machine:** every harness run and folder copy (`job::run`), every login in a terminal, and every screen's programs (Xvfb, the window manager, the session bus, the viewer), as a Bots' or a teammate's user.
- **On one server:** `superbot-run`, which every run under `ISOLATION=users` goes through, installs it before it starts the harness. A run that can't get the filter doesn't start (fail closed, like no new privileges).

Root's processes (the agent itself, upgrades, `MACHINE_BOT_USER=off`) don't get it. There is no setting: like no new privileges, the filter takes nothing away from a run, and `MACHINE_BOT_USER=off` is still the admin's way out of every lock.

### Reported

Each heartbeat says the agent filters runs (`seccomp` in `can`, `wire::CAN_SECCOMP`), and the admin's machine view shows `botUser.seccomp` beside `botUser.lockedDown`; `machine.bot_user_ready` carries it too. An agent from before this, or on an architecture without a filter, shows `false`, so an admin can see which machines to upgrade.

## Tests

- **Unit** (any user): the program is run through an interpreter as the kernel would, on every listed call (its error), on calls harnesses and sandboxes need and every other number below 500 (allowed), on i386, 32-bit Arm and x32 calls (killed); each call is listed once. A real child process with the filter installed gets EPERM from `keyctl`, `add_key`, `bpf`, `perf_event_open`, `userfaultfd` and `syslog`, ENOSYS from `io_uring_setup`, still answers `getpid`, runs a shell and `ls`, and shows `Seccomp: 2`. The agent view reports `seccomp`. A locked-down run through `job::run` shows `Seccomp: 2`.
- **Red team, as root in CI's isolation job** (`as_root_red_team_a_run_cant_reach_the_kernels_riskier_interfaces`): as a real unprivileged user, a probe calls `keyctl`, `add_key`, `io_uring_setup`, `userfaultfd`, `perf_event_open`, `bpf`, `syslog` and `open_by_handle_at` with arguments that get past the kernel's own first checks. Without the lock the same user gets answers (a keyring, a ring, `EFAULT`) from the first four that the filter would refuse, so the probe can tell; as a locked-down run each gets its error, `getpid` still works, and making a user namespace works exactly as it does without the filter. The owner's and the teammate's runs through the real agent over mutual TLS (`as_root_red_team_bots_cant_reach_another_persons_files_or_the_agents_secrets`) show `Seccomp: 2`.
- **One server** (`deploy/test-isolation.sh`): a run through `superbot-run` shows `Seccomp: 2`.

## Consequences

- A run can't use keyrings, eBPF, perf, userfaultfd, io_uring, file handles or the kernel log, on any machine and on one server, whatever the host's sysctls. On Incus, where those sysctls are the host's, that is the line ADR 0126 couldn't draw.
- Tools that use these get an error: `perf`, `bpftrace`, `dmesg` and `keyctl` fail; Node and other io_uring users fall back to threads. Nothing SuperBot runs needs them.
- A 32-bit (i386, x32 or 32-bit Arm) program a run starts is killed at its first system call.
- Kernel code behind user namespaces stays reachable, because harness sandboxes need them. A host that doesn't need sandboxes can turn unprivileged user namespaces off itself.

## Deferred

- An allow-list filter per harness, once each harness's calls are measured in CI.
- Filtering arguments: `clone` and `unshare` flags (user namespaces, above), `ioctl` requests, `socket` families.
- Dedicated or VPC hosts for enterprise tiers, and egress policy at the provider: #54's next slice.
- Disk quotas per run user (ADR 0145).
