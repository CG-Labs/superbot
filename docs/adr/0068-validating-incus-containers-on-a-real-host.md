# 0068: Validating Incus containers on a real host

## Status

Accepted. Follows [ADR 0065](0065-incus-container-machines.md) (Incus containers) and [ADR 0067](0067-clearing-enrollment-data-from-containers.md) (clearing enrollment data) on [#29](https://github.com/CG-Labs/superbot/issues/29) (M3). Both were built and tested against a stand-in for the Incus API only.

## Context

The stand-in models what we knew about Incus. It couldn't tell us:

- what a restricted project really refuses;
- whether cloud-init, enrollment and the token scrub work in a real container;
- what the network ACL, port isolation and address filters really block, including traffic from the host itself;
- whether resize, suspend, resume, rebuild and the reconciler behave the same on a real host.

## Decision

### A real host in CI

The test runs on free GitHub-hosted runners and needs no secrets or paid services.

- `deploy/incus-e2e-host.sh` turns a throwaway Ubuntu host into an Incus host as the operator guide describes: Incus from Zabbly or Ubuntu's own package, a btrfs pool (so disk sizes are enforced), the `superbot0` bridge, the restricted `superbot` project, the API on the bridge's address, and a trusted client certificate. It writes the `INCUS_*` settings to an env file. It refuses to run unless `SUPERBOT_INCUS_E2E_THROWAWAY=1`.
- `machines_incus_e2e_tests` is one ignored test. It runs only with `SUPERBOT_INCUS_E2E=1`. It builds botd's control plane from those settings, the same way `main` does, and drives the real Incus provider, the reconciler and the real `superbot-machine` agent.
- The `incus-e2e` workflow runs it against Zabbly's stable Incus and Zabbly's 6.0 LTS. Against Ubuntu 24.04's own Incus 6.0.0, it checks that the preflight check refuses the host and names why. It runs when the machines code changes, weekly, and by hand. Failures dump the instances (without their user data), cloud-init's and the agent's logs, the ACLs and Incus's journal.

The test sends the same calls to Incus that botd does. It also uses a test-only `exec` to look inside containers, which botd never does.

### What the test checks

For two users' containers, A and B:

- **Enrollment.** Created sized by tier, cloud-init finishes, the agent enrolls over mutual TLS and heartbeats.
- **ADR 0067.** The reconciler clears `cloud-init.user-data`, turns on daily snapshots only after that, and doesn't restart the container. No enrollment token (`sbe_`) is left anywhere in `/var/lib/cloud`, `/etc/superbot` or `/var/log`. Two `machine.user_data_cleared` events are audited.
- **Sizing and hardening.** CPU count, `memory.max` and `pids.max` match the tier. The security keys are set. Each container has its own non-identity id map. There is no `/dev/incus`.
- **Isolation.** B runs a listener on a non-agent port. A can't reach B's agent port or that listener over IPv4 or IPv6, and can't ping B. A can't reach the host's Incus API, SSH or a decoy listener on the gateway, and the decoy counts no hits. A can reach botd's machine port, DNS and the internet. The host reaches B's agent port but not B's listener. B can't reach A's agent.
- **Lifecycle.** Suspend stops the container and resume restarts it, with heartbeats again. Resize to a larger tier changes the limits and the root disk live.
- **Reconciler.** The reconciler converges with nothing to change. A NIC whose inbound default was changed to `allow`, and an ACL emptied of its outbound rules, are both put back.
- **Rebuild.** Cloud-init runs again with the new user data, and the container keeps the same address and ACL.
- **Destroy.** Both instances and the ACL are gone, and `machine.firewall_deleted` is audited once.

### What the real host showed

1. **Every create was refused.** A restricted project treats `limits.memory.swap` as a low-level option (`restricted.containers.lowlevel=block`), so Incus refused every container. botd no longer sets it. The stand-in now refuses low-level keys as Incus does. Memory stays hard-limited (`limits.memory.enforce=hard`). Whether containers swap is the host's choice: give the host no swap, or accept that a container at its limit can swap.
2. **The preflight check passed a host that can't make containers.** Ubuntu 24.04's own Incus is 6.0.0. It has every extension the check asked for but refuses `security.acls.default.*` on a container's NIC, so every create fails. Those keys need the `network_bridge_acl_devices` extension: Incus 6.9, or 6.0.4 on the 6.0 LTS. The check now requires it and names it when it is missing. The guide says to install Incus from Zabbly, not Ubuntu's archive. On the 6.0 LTS (6.0.7), containers then failed to start: the NIC's IPv6 filter needs the `br_netfilter` module there. Later releases don't. The guide and the host script load it. Isolation was checked with it loaded on both.
3. **The token was left inside the container.** The first boot deleted `user-data.txt` and its `.i` copy and the NoCloud seed. cloud-init also writes the merged config to `/var/lib/cloud/instance/cloud-config.txt` and caches it in `obj.pkl`, and both held the token. The first boot now deletes them too, on Incus and Linode. On later boots cloud-init finds no seed and stays disabled, and the agent keeps running. This removes the `obj.pkl` residue [ADR 0035](0035-machine-firewall-auto-enroll.md) recorded.
4. **Host-to-container traffic is filtered.** ADR 0065 left this unverified. The ACL's default inbound drop also applies to traffic that starts on the host: the host reaches only the agent port from the gateway.
5. **Neighbours can't ping each other.** ADR 0065 said ICMP isn't filtered. Port isolation blocks all traffic between containers, ICMP included. Containers can still ping the gateway and the internet.
6. **Everything else matched the stand-in:**
      - the NoCloud seed working with `security.guestapi=false`;
   - DHCP and DNS on the bridge despite the private-range deny;
   - live resize of a running container on btrfs;
   - ETag'd PUTs and PATCHes;
   - rebuild;
   - the ACL round trip.

With a cached image, a container enrolls in about 6 seconds and a rebuild finishes cloud-init in about 4. The whole test takes about a minute on a nested VM. CI adds the image download and the build.

### What isn't tested

- **Incus VMs.** GitHub's runners have no nested virtualisation, and botd makes containers only.
- **Bridges without IPv6.** The test's bridge has IPv6, and filtering is checked there.
- **zfs and lvm pools, and clusters.** Only btrfs (and `dir` for the preflight warning) were run.
- **botd on a separate host.** The test runs botd on the Incus host, reaching containers from the gateway. A remote botd routes the subnet the same way and isn't tested.

Two kernel features are needed: nftables' bridge family (for the ACL and the NIC filters) and a btrfs, zfs or lvm pool. GitHub's runners and stock Ubuntu have both. Some minimal or nested kernels lack them, and the guide says how to check.

## Consequences

- Container machines are validated on a real Incus host, and every change to the machines code is checked against one in CI.
- Container sizes no longer limit swap. The guide says so.
- No enrollment token is left in a container after its first boot.
- ADR 0065's open questions about host-to-container traffic and ICMP are answered, and its text is corrected.
