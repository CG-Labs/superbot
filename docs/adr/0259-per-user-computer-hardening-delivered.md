# 0259: Per-user computer hardening is delivered, and what follows it

## Status

Accepted (24 Nov 2026). Closes the scope of [#54](https://github.com/CG-Labs/superbot/issues/54) (M5, per-user computer hardening) after twelve slices, the last [ADR 0251](0251-a-record-of-deleted-teams-and-a-view-of-team-networks.md). The follow-ups below are proposed, not started.

## Context

#54 asks for four things: "Harness as a separate OS user, cgroup and egress limits, dedicated/VPC hosts; red-team scenario." Each is now merged, tested, and on by default where it is safe to be:

| #54 asks for | Delivered by | Checked by |
|---|---|---|
| Harness as a separate OS user | Bots on a machine run as an unprivileged user per person ([ADR 0043](0043-bots-own-os-user-on-machines.md)), locked down by default: no new privileges, no privileged groups or sudo, umask 077, hidden processes ([ADR 0145](0145-locked-down-run-users-and-red-team.md)), and a seccomp filter on every run ([ADR 0156](0156-seccomp-filter-per-run.md)). On one server, a Unix account per user ([ADR 0037](0037-per-user-unix-accounts.md), [ADR 0058](0058-harness-os-user-by-default.md)) through `superbot-run`. | `machines_redteam_tests` as root in CI; `deploy/test-isolation.sh` |
| cgroup limits | A cgroup per run, held to its tier's `runLimits` ([ADR 0135](0135-run-limits-and-egress-allow-lists.md)) | `machines_hardening_tests` and the red team's "exhaust the machine" scenario, as root in CI |
| Egress limits | nftables deny rules for every run user from first boot ([ADR 0126](0126-per-user-machine-hardening.md)), outbound allow-lists per server and per user (ADR 0135), and the same deny list at the provider, which binds root too ([ADR 0179](0179-outbound-rules-at-the-provider.md)) | `machines_hardening_tests` and the red team's allow-list scenario, as root in CI; provider stand-in tests |
| Dedicated hosts | Incus hosts dedicated to a team ([ADR 0166](0166-incus-hosts-dedicated-to-a-team.md)) | `machines_dedicated_tests`, including a red-team placement test |
| VPC hosts | A network per team on Linode ([ADR 0189](0189-a-network-of-its-own-per-team.md), [ADR 0202](0202-existing-machines-join-their-teams-network.md), [ADR 0226](0226-linode-interfaces-behind-the-firewall-and-on-team-networks.md)) and on Incus over OVN ([ADR 0212](0212-an-ovn-network-per-team-on-incus.md)), removed when the team is gone ([ADR 0236](0236-removing-the-networks-of-teams-that-are-gone.md), ADR 0251) | `machines_team_network_tests`, `machines_incus_team_network_tests` |
| Red-team scenario | Cross-person file reads, the agent's key and records, privilege escalation, the allow-list, exhausting the machine (ADR 0145), and the kernel's riskier interfaces (ADR 0156) | five `as_root_red_team_*` tests in the server workflow |

The last three slices (ADRs 0226, 0236, 0251) were already follow-ups the ADRs had deferred, not things the issue names. Each ADR still defers more, so #54 would never end if every deferral stayed under it.

## Options

1. **Keep #54 open** and keep taking deferred items under it.
2. **Call #54 delivered**, and list the deferred items as follow-ups, ranked, each for an issue of its own.

We chose option 2. Each follow-up is a separate choice with its own cost and priority, and is easier to weigh, schedule or drop as an issue of its own than as a thirteenth slice of a finished one.

## Decision

#54 is delivered. The roadmap says so, and no further slices are made under it.

These follow-ups are proposed, in order of value. None is started. Each would need an issue (under M5, or later) and an ADR of its own.

1. **Disk quotas per run user** (deferred by ADR 0145 and ADR 0156). A run can still fill its machine's disk, for its owner and every teammate. It is the one way to exhaust a machine the red team doesn't stop; storage limits ([ADR 0082](0082-storage-limits-per-tier.md)) only count it afterwards. Likely shape: filesystem project quotas per run user on VMs, a size limit on each run's `TMPDIR`, and a red-team scenario that fills the disk.
2. **Bringing older machines up to date without a rebuild.** Machines enrolled before ADR 0126, ADR 0135 or ADR 0145 keep running without the first boot's egress rules, `Delegate=` (so runs aren't held to limits) or `ProtectProc=invisible` until rebuilt. The agent could apply the egress rules, `Delegate=` and `ProtectProc=invisible` itself, as it already edits its egress rules for team networks (ADR 0202), with a fleet view of what is missing where.
3. **Per-destination exceptions to the deny list** (ADR 0126, ADR 0179), for Bots and root alike, so a Bot can reach one private service without a team network or turning hardening off.
4. **Finer egress policy** (ADR 0135): wildcard domains in allow-lists, through a filtering resolver on the machine; allow-lists per team and per Bot; run limits per user rather than per tier.
5. **Narrower seccomp filters** (ADR 0156): an allow-list per harness once its calls are measured in CI, and filtering `clone`, `unshare`, `ioctl` and `socket` arguments.
6. **auditd and file integrity checks** on machines that are VMs (ADR 0126); containers can't have them.
7. **Team network and dedicated host extras**: one team network across standalone Incus hosts through OVN interconnect (ADR 0212); joining at a time the team picks (ADR 0202, ADR 0226); removing networks while team networks are off (ADR 0236, ADR 0251); keeping `eth1` through a restore (ADR 0212); and hosts dedicated to one user, dedication required (`INCUS_SHARED_HOSTS=off`), and moving misplaced machines (ADR 0166).

## Consequences

- #54 can be closed once this is merged. No behaviour changes, and nothing needs upgrading.
- The follow-ups stay visible in one place, ranked, rather than only in the Deferred sections of twelve ADRs.
- Until disk quotas exist, operators who share a machine between teammates rely on storage limits and alerts for a full disk.

## Tests

None: this changes only docs. The links are checked by the docs workflow's site build.
