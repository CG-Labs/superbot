# 0065: Per-user containers on a virtualised server (Incus)

## Status

Accepted. The last item listed as remaining on [#29](https://github.com/CG-Labs/superbot/issues/29) (M3), after [ADR 0025](0025-control-plane-linode.md) (machines), [ADR 0031](0031-machine-enrollment-mtls.md) (enrollment and mTLS), [ADR 0035](0035-machine-firewall-auto-enroll.md) (firewall), [ADR 0036](0036-bots-on-the-users-machine.md) (Bots on machines) and [ADR 0056](0056-rebuilding-machines-enrolled-before-0039.md) (rebuilds). Built and tested against a stand-in for the Incus API only; not yet run against a real Incus host.

## Context

The roadmap's isolation decision is one computer per user: a VM, or **one container per user on a virtualised server**. Linode VMs are built. A container per user on one big host is cheaper and denser, and suits smaller tiers and self-run managed setups.

Everything that makes a machine useful is already provider-agnostic. Enrollment, mutual TLS, Bots, harness CLIs, logins, the user's folder, the Bots' own OS user, screens, teammates and rebuilds all talk to the agent at the machine's address. They need a machine with systemd, cloud-init, a root user that can make OS users, and an IP botd can reach. So the work is a second provider behind the existing `MachineProvider` trait, not a second control plane.

## Decision

### Incus system containers

The substrate is [Incus](https://linuxcontainers.org/incus/) system containers:

- A full OS per container, with systemd, cloud-init and its own users. The agent, `superbot-bots`, teammates' users and screens work unchanged.
- Unprivileged containers are Incus's default, with per-container id maps and AppArmor and seccomp profiles.
- A REST API over mutual TLS. botd stays Rust-only and talks HTTPS with the same TLS code it uses for machines. There is no Docker socket and no shelling out.
- Incus runs on any Linux host or cluster: a dedicated server, a big VM, or on-prem. Moving to Incus VMs later is an instance type change.

Docker was rejected. Application containers have no init, cloud-init or real OS users, and the Docker API is root on the host. Plain LXC with SSH was rejected because botd would have to script a host over SSH. Kubernetes was rejected as too much for one container per user.

### Settings

`MACHINE_PROVIDER=incus` picks it. The default is `linode`, and anything else is a startup error. Self-hosted servers set none of this.

| Setting | Meaning |
|---------|---------|
| `INCUS_URL` | The Incus API, `https://<ip>[:port]` (port 8443 by default). Needed. It must be an IP address, so containers can be denied that address; a host name is refused. |
| `INCUS_CLIENT_CERT`, `INCUS_CLIENT_KEY` | botd's client certificate and key (PEM, or `_FILE`). The key is a server secret: kept from Bots and harnesses, and redacted. |
| `INCUS_SERVER_CERT` | The Incus host's certificate. botd pins it by SHA-256 and talks to nothing else. |
| `INCUS_PROJECT` | Default `superbot`. Must be restricted (below). The `default` project is refused. |
| `INCUS_NETWORK`, `INCUS_STORAGE_POOL` | Default `incusbr0` and `default`. |
| `INCUS_IMAGE_SERVER` | Default `https://images.linuxcontainers.org`, or `local` for images already on the host. |
| `INCUS_EGRESS_DENY` | More CIDRs containers may never reach, on top of the built-in list. |
| `MACHINE_IMAGE` | Default `ubuntu/24.04/cloud`. It must be a cloud variant so cloud-init runs. |
| `MACHINE_TIERS` | Plans are `c<cpus>-m<memory GiB>-d<disk GiB>`. Default `starter=c1-m2-d20,pro=c2-m4-d40,max=c4-m8-d80`. Other plan names are a startup error. |
| `MACHINE_REGIONS` | Optional. `local` for a lone host, or cluster member names (sent as `target`). |

It also needs `MACHINE_CONTROL_URL` and `MACHINE_FIREWALL=on`. The firewall is what keeps containers off each other, the host and private addresses, so Incus without it is a startup error. So is setting both `MACHINE_PROVIDER=incus` and `LINODE_TOKEN`. Startup makes no calls to Incus.

### Lifecycle

| Control plane | Incus |
|---------------|-------|
| create | `POST /1.0/instances` with `start: true`. The instance name is the machine's label, so a second create gets "already exists" and the existing reconciler adopts it. botd waits up to 20 s. If the image is still downloading, the machine shows as `provisioning` and the reconciler picks it up. |
| get | The instance and its state. A missing instance with a create still running is `provisioning`, not gone. |
| suspend / resume | A clean stop (30 s), then a forced stop if needed. Start. |
| resize | New `limits.*` and root disk size, applied to the running container. |
| backups | `snapshots.schedule=@daily`, kept 7 days, on the container's own pool. |
| destroy | Forced stop, then delete. A missing container counts as deleted only once no create of it is still running, so a create that finishes late can't leave one behind. |
| rebuild ([ADR 0056](0056-rebuilding-machines-enrolled-before-0039.md)) | Forced stop, new cloud-init user data, `POST .../rebuild` from the image, start. Same name, address and firewall. A rebuild that outlasts 60 s is reported as maybe sent and left stopped. While it waits for the machine to enroll, the rebuild worker starts a stopped machine under the control plane's lock, only if it is still meant to be running (not suspended meanwhile). Incus refuses to start it while the rebuild still runs. |

The provider trait gained defaults so Linode is unchanged: `substrate()` (`vm` or `container`), default tiers and image, `check_plan`, `plan_view`, `settings` and `preflight`.

### Sized by tier

Each tier's plan becomes:

- `limits.cpu`
- `limits.memory` with `limits.memory.enforce=hard` and no swap
- `limits.processes` (1024 per GiB, at least 2048)
- the root disk's `size`

A user plan's machine size ([ADR 0040](0040-billing-v0-tier-limits.md)) that this provider can't make is refused with a 400 at request and resize time, not sent to Incus.

### The isolation boundary

The requirement is that a container must not reach other users' containers, the host's secrets, or botd's `DATA_DIR`. This is what does that, and what it doesn't cover.

**Every container.** These are set by botd on create, and Incus enforces them:

- Unprivileged (`security.privileged=false`), with its own uid/gid range (`security.idmap.isolated=true`). Root in one container is an unprivileged id on the host and a different one from every other container.
- No nesting. No `/dev/incus` (`security.guestapi=false`), so it can't read its own config, including the enrollment token in its cloud-init user data.
- No profiles (`profiles: []`), so nothing on the host can add a device or loosen a setting. Exactly two devices: a root disk from the pool, and one NIC. Nothing from the host is mounted, so neither `DATA_DIR` nor host files are visible.

**The project.** Before every create, botd checks the project:

- `restricted=true` is set.
- None of the `restricted.containers.*` or `restricted.devices.*` settings is `allow`.
- No host paths and no raw id maps are allowed.

If any check fails, botd makes nothing, and the machine shows the reason. Incus enforces a restricted project for every client, so even a wrong request from botd can't make a privileged container, a nested one, or one with a host path.

**The network.** The NIC has these settings:

- `security.port_isolation`: no frames to other containers on the bridge.
- MAC, IPv4 and IPv6 filtering: a container can't take another's address.
- The machines' network ACL (the firewall, [ADR 0035](0035-machine-firewall-auto-enroll.md)):
  - **Inbound** defaults to drop. The only allow is the firewall's rule: TCP to the agent's port from `MACHINE_FIREWALL_SOURCES` (by default the control URL's address), plus SSH if `MACHINE_SSH_SOURCES` is set.
  - **Outbound** is open to the internet, for harness APIs and package mirrors. TCP and UDP are dropped to:
    - private, shared and link-local ranges (`10/8`, `100.64/10`, `169.254/16`, `172.16/12`, `192.168/16`, `fc00::/7`, `fe80::/10`), which include the bridge and the host's address on it;
    - the Incus host in `INCUS_URL`;
    - `INCUS_EGRESS_DENY`.

    If `MACHINE_CONTROL_URL` is one of those addresses, it is carved out. Only TCP to botd's machine port stays open, for enrollment and the agent's calls to botd.
- The reconciler keeps the ACL right. Changed inbound rules, loosened outbound rules, a disabled rule, or a container taken off the ACL are put back and audited, as with Linode. A container counts as behind the ACL only if its network is exactly as attached: eth0 with every setting above, no other NIC and no profiles. One loosened in place, such as a default changed to `allow` or a filter turned off while it still names the ACL, is attached again.

**botd's side.** These settings protect botd and the host:

- botd pins the Incus host's certificate.
- The client key never leaves botd's process. It is a server secret, stripped from harnesses and redacted.
- Containers have no route to botd's admin API (`DATA_DIR` lives behind it) other than its public HTTPS. That is the same as any machine. Its machine port speaks only mutual TLS with per-machine certificates.

**What this does not cover:**

- **A shared kernel.** A kernel or container-runtime escape crosses every boundary above. VMs (Linode, or Incus VMs later) are the stronger boundary. Use containers where that trade-off is accepted, keep the host patched, and dedicate the host to SuperBot containers.
- **botd's certificate is effectively an Incus admin.** On a plain bridge (no OVN), Incus keeps network ACLs in the `default` project and checks permissions there, so a project-restricted client certificate can't manage them. botd therefore uses a trusted certificate. Anyone who has botd's key can change the project or make privileged containers. The pre-create check catches drift, not a compromised botd. Treat the key like `LINODE_TOKEN`, firewall the Incus API to botd's address, and run botd on a separate host where possible.
- **ICMP is not filtered** to private ranges, so containers can ping. ARP and neighbour discovery are limited by port isolation and the filters.
- **Public addresses of the host** other than `INCUS_URL`'s are not denied unless listed in `INCUS_EGRESS_DENY`.
- **Host-to-container traffic.** Whether the ACL's default inbound drop also filters traffic that starts on the Incus host itself depends on Incus's bridge firewall. This is unverified on a live host. Containers' inbound from other containers and from outside is covered either way.
- **Disk sizes** are enforced only by pools whose driver supports quotas (zfs, btrfs, lvm). The `dir` driver doesn't, and the preflight check says so.
- **Snapshots** are on the same pool and host, not off-host backups.
- **The enrollment token** is in the instance's config (`cloud-init.user-data`), readable by Incus admins, until the container enrolls or misses its deadline; then botd removes it ([ADR 0067](0067-clearing-enrollment-data-from-containers.md)). It is single-use and expires in 60 minutes. The first boot also deletes the NoCloud seed copy inside the container.

### Placement and routing are unchanged

A container is a machine with `provider: incus`, an id equal to its name, and its bridge address as `ipv4`. botd dials the agent there, so botd needs a route to the bridge. On the same host that is direct. From another host, route the bridge's subnet to the Incus host. Everything after enrollment is the same code path as Linode.

### Switching providers

A machine row keeps the provider that made it. With another provider configured, botd leaves such a machine alone:

- The reconciler, the firewall sync and rebuilds skip it.
- Suspend, resume, resize, destroy, retry and rebuild return 409 and name its provider.
- Its agent is still reached as before.

There is no migration between substrates in this slice.

### Admin view and `botctl`

`GET /api/machines/substrate` (admin) shows the provider, the substrate, each tier's plan with its CPUs, memory, disk and process limit, the regions, the firewall, and the provider's settings. For Incus, the settings include the pinned certificate fingerprint, the denied ranges, the exact outbound rules and the isolation summary. `?check=true` asks the host:

- that botd is trusted, with the API extensions it needs;
- that the project is restricted;
- that the network is a managed bridge;
- that the storage pool enforces sizes.

`botctl machine list|show|request|suspend|resume|resize|destroy --yes|substrate [check]|reconcile` covers the machine itself, alongside the existing placement, agent and rebuild commands. The console's Machines table shows each machine's provider.

### Tests

There is a stateful stand-in for the Incus API (`machines/incus_standin.rs`). It speaks TLS 1.3. It lets any client certificate through the handshake but answers only trusted ones, as Incus does. It returns sync and async replies with operations to wait on, ETags with `If-Match`, Incus's error shapes, used-by lists on ACLs, and a restricted project that refuses privileged, nested or host-path containers.

Unit tests cover:

- plan parsing and the outbound rule computation, including the carve-out for botd's port;
- settings and credentials;
- the exact create body;
- refusal without the firewall or in a loosened project;
- every lifecycle call, held and failed creates, deleting during a held create, a slow rebuild left stopped until Incus is done (and the rebuild worker starting it only if it wasn't suspended), and the ACL round trip, including tampering and NICs loosened in place;
- the pin and trust checks.

Integration tests run botd end to end on loopback. A user's container is requested over HTTP, made behind the ACL, enrolled by the real agent from its cloud-init user data, and heartbeats over mutual TLS. It is then suspended, resumed, resized, snapshotted and destroyed, and the ACL goes with the last machine. Two users' containers are isolated, the reconciler restores a container removed from the ACL and loosened outbound rules, the admin view and preflight work, and machines from another provider are left alone.

## Consequences

- Managed hosting can run many users per host, with the same Bots, logins, folders, OS users and screens as on Linode. Nothing above the provider changed.
- A container's boundary is weaker than a VM's, which is stated above and in the operator guide ([docs/ops/incus-containers.md](../ops/incus-containers.md)).
- botd holds a host-admin credential for the Incus host. That is the same class of secret as `LINODE_TOKEN`.

## Follow-ups

- Validate against a real Incus host: host-to-container filtering, IPv6 filtering on bridges without IPv6, cloud-init and rebuild timings, and the extension names the preflight check expects.
- Off-host backups: export snapshots to customer S3 ([#40](https://github.com/CG-Labs/superbot/issues/40)).
- Clear `cloud-init.user-data` from the instance's config once it has enrolled (done, [ADR 0067](0067-clearing-enrollment-data-from-containers.md)).
- Per-container egress allowlists and DNS policy (M5).
- Resize machines when a user's tier changes ([#31](https://github.com/CG-Labs/superbot/issues/31)).
- OVN networks with per-project ACLs, so botd can use a restricted client certificate.
- Per-project quotas (`limits.instances`, `limits.cpu`, `limits.memory`) as a host-wide ceiling.
- Incus VM instances for tiers that need their own kernel.
- Migrating a user's machine between substrates.
