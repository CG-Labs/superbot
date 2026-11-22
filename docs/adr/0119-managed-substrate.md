# 0119: The managed substrate: Linode VMs, Incus containers, an orchestrator, or a mix by tier

## Status

Proposed — awaiting David's decision. For [#43](https://github.com/CG-Labs/superbot/issues/43) (M4, "Revisit managed substrate"), which revisits decision 2 of the [roadmap](../ROADMAP.md#decisions-19-nov-2026): "Provision per-user machines with the Linode API until a production-ready system exists", to be revisited before M4. The recommendation below is engineering's. The call is the product owner's, David Kennedy's. The small code this ADR adds is opt-in and works with any of the options, so it is built now. Builds on [ADR 0025](0025-control-plane-linode.md) (Linode), [ADR 0065](0065-incus-container-machines.md) (Incus containers), [ADR 0074](0074-machine-rpo-and-rto.md) (RPO and RTO), [ADR 0076](0076-restoring-onto-another-incus-host.md) (losing a host), [ADR 0081](0081-placing-machines-by-host-load.md) (placement), [ADR 0106](0106-host-capacity-metrics.md) (capacity), [ADR 0110](0110-linode-machine-recovery-objectives.md) (Linode recovery) and [ADR 0117](0117-uk-eu-data-regions.md) (regions).

0117 is the highest number on `main`. Open PR [#181](https://github.com/CG-Labs/superbot/pull/181) holds 0118.

## Context

Decision 2 was made before any provider existed: ADR 0025 built the Linode client after it. Since then the control plane has grown a second provider and most of what a production system needs. This is what the code does today, not what it could do.

**One trait, two providers, one at a time.** `MachineProvider` (`server/src/machines/provider.rs`) creates, sizes, stops, starts, backs up, rebuilds and deletes a machine by a unique label, and manages its firewall. Two providers implement it: Linode API v4 VMs (`linode.rs`) and Incus system containers on one or more hosts (`incus.rs`, `incus/fleet.rs`). Everything above the trait doesn't care which: enrollment and mutual TLS, Bots on the machine, harness CLIs and logins, the user's folder, the Bots' own OS user, screens, teammates, rebuilds, resizes and regions. But a control plane runs **one** provider (`MACHINE_PROVIDER=linode|incus`). A machine made by the other is left alone, with a 409 on every change, and nothing moves a machine between substrates (ADR 0065).

**What each provider gives today:**

| | Linode (ADR 0025) | Incus (ADR 0065) |
|--|--|--|
| A machine is | A VM with its own kernel | An unprivileged system container sharing its host's kernel |
| Firewall | One Linode Cloud Firewall per control plane ([ADR 0035](0035-machine-firewall-auto-enroll.md)) | A network ACL with port isolation, address filters and outbound denied to private ranges and the host |
| Backups | Linode Backups: daily in Linode's window, kept in the same data centre. RPO of 26 hours held and alerted (ADR 0110) | Off-host exports to S3-compatible storage, age-encrypted once the operator sets recipients, with a warning until then ([ADR 0114](0114-backups-encrypted-by-default.md)). RPO per tier (26, 14 and 8 hours) and an RTO of 60 minutes, both measured (ADR 0074) |
| Restore | By hand in Cloud Manager, with a 4-hour target the operator drills and botd doesn't measure (ADR 0110) | botd restores, onto the same host or another, and times it against the RTO (ADR 0071, ADR 0076) |
| A host is lost | Linode's to recover | An admin declares it lost, and botd restores its machines onto hosts with room (ADR 0076, ADR 0081). Not yet drilled on production hardware (checklist A1.3-1) |
| Regions | Linode's region per machine, such as `gb-lon` and `de-fra-2`; backups stay with the Linode (ADR 0117) | Hosts tagged by region, a backup store per region, and strict residency (ADR 0117) |
| Capacity | Linode's | Placement by load, plus capacity metrics, alerts and a dashboard (ADR 0081, ADR 0106) |
| Export to another provider | No (`exports()` is false) | Yes |
| Tested against the real thing | Not in CI, which uses a stand-in (ADR 0025), and no run against real Linode is recorded in the repo | Yes, on a real Incus host in CI ([ADR 0069](0069-validating-incus-containers-on-a-real-host.md)) |

**What the machine has to withstand.** A Bot runs shell commands a model chose, on its owner's machine. After the public launch, owners are strangers to each other. The roadmap's exit criteria set the bar: M3's "user A's computer and Bots cannot reach user B's", and M5's "per-user isolation passes a red-team scenario", with "dedicated or VPC hosts for enterprise" in M5's scope.

## Criteria

1. **Per-user isolation**: what stands between two users' machines, and what an escape crosses.
2. **Cost per user per tier**: what one more user on a tier costs each month, running and suspended.
3. **Provisioning latency**: from an admin's request to the machine's agent enrolling.
4. **Backups and restore**: RPO and RTO, whether they are measured, and what a disaster loses.
5. **Regions and residency**: London and Frankfurt, as ADR 0117 promises.
6. **Operational burden** for a team of one or two.
7. **SOC 2 evidence**: what the provider's report covers and what we must show ourselves.
8. **Lock-in**: what it takes to leave.
9. **Migration path**: from today's code, and between options later.

**No prices here.** The repo has no hosting prices, and they change. Cost is given as a formula per option, with every input named, so the owner can fill in current prices. The plan sizes are the repo's own: `MACHINE_TIERS` maps Starter, Pro and Max to Linode's `g6-standard-1`, `-2` and `-4`, or to Incus's `c1-m2-d20`, `c2-m4-d40` and `c4-m8-d80`, which is 1, 2 and 4 vCPUs with 2, 4 and 8 GiB of memory ([ADR 0070](0070-hermes-per-bot-footprint.md)).

## Options

### (a) Stay on Linode VMs, one per user

- **Isolation.** The strongest boundary built. Each user has their own kernel behind Linode's hypervisor, so an escape from one machine has to break the hypervisor to reach another user. What remains: `LINODE_TOKEN` can make and delete every machine (it is a server secret, never given to Bots). And Linode keeps each machine's cloud-init data, with its one-time, 60-minute enrollment token, in its metadata service (ADR 0035).
- **Cost.** For a user on tier *t*, each month: **L(t) + B(t)**. *L(t)* is Linode's price for the tier's plan, and *B(t)* is Linode Backups for that plan, which Linode bills per machine on top of the plan. A suspended Linode is billed in full until it is destroyed (ADR 0025), so a user who stops using it costs as much as one who doesn't. Cost grows linearly with users. There is no density: an idle Hermes uses no CPU (ADR 0070), but the plan is paid in full.
- **Latency.** Linode makes the VM, then it boots, runs cloud-init, downloads the agent and enrolls. Nothing measures this; the code below starts to. After enrolling, the agent installs the harnesses, which costs the same on any substrate: Hermes alone is a 2,604 MiB install (ADR 0070).
- **Backups.** One a day, held to a 26-hour RPO with alerts. The restore is manual and untimed, and the backups sit in the same data centre as the machine, so losing that data centre loses both (ADR 0110). No export.
- **Regions.** Done: a machine goes in its user's region, and its backups follow it.
- **Operations.** The least of any option. There are no hosts, kernels or Incus releases to patch. What remains is the token, the firewall, and the restore procedure.
- **SOC 2.** Physical and host controls are inherited from Linode's (Akamai's) report, which the operator reviews (checklist CC6.4-1). A1.2-2 is done (ADR 0110). Missing: a timed restore drill of a Linode machine.
- **Lock-in.** Only `linode.rs` knows Linode's API. But a machine can't be exported, so leaving Linode means a new machine for each user elsewhere. botd keeps their memory and facts, and their folder copy goes to the new machine ([ADR 0041](0041-machine-harness-logins-and-folder-copy.md)), but their harness logins and anything else on the old machine's disk don't move.
- **Migration.** None to launch: this is what decision 2 already says.

### (b) Incus containers on a fleet of hosts

- **Isolation.** Each container is unprivileged with its own id map, no nesting and no `/dev/incus`, in a restricted project that botd checks before every create. The ACL keeps it off its neighbours, the host and private ranges (ADR 0065). But containers on a host **share its kernel**, so a kernel or runtime escape crosses every user on that host. And botd's Incus certificate is effectively host admin on a plain bridge (without OVN). ADR 0065 and the [operator guide](../ops/incus-containers.md) say both. Nobody has red-teamed it.
- **Cost.** For a user on tier *t*, each month: **(H + O) / N(t) + S(t)**.
  - *H* is a host's monthly price, and *O* is the operator's time on that host each month (patching, upgrades, drills), costed.
  - *N(t)* is how many tier-*t* machines a host holds: the smallest of its CPUs × *k* ÷ the tier's CPUs, its memory ÷ the tier's memory, its disk ÷ the tier's disk, and `INCUS_MAX_MACHINES`. *k* is the CPU overcommit an operator chooses. Memory is a hard limit per container and shouldn't be overcommitted (ADR 0081).
  - *S(t)* is off-host backup storage: the disk in use × copies kept × the store's price per GiB. Exports are full each time, and the default schedule keeps 14, 28 and 56 copies at 14 days' retention (ADR 0074).
  - Add spare room for a lost host's machines in the same region (ADR 0076, ADR 0117). Suspended containers keep their place in placement (ADR 0081), so they cost room but not CPU.

  *Worked example, assumptions labelled:* the operator guide's example capacity `INCUS_CAPACITY=c32-m128-d2000`, and an assumed *k* of 2. Memory then binds every tier: 64 Starter, 32 Pro or 16 Max machines per host (128 ÷ 2, 4 or 8 GiB). Disk allows 100, 50 and 25, and CPU at *k* = 2 allows 64, 32 and 16. Containers cost less than Linode for tier *t* when **(H + O) / N(t) + S(t) < L(t) + B(t)**. The owner can check that with today's prices.
- **Latency.** With a cached image, a container enrolls in about 6 seconds (ADR 0069, on a nested VM in CI), then installs the harnesses as above.
- **Backups.** The best story built: off-host and optionally encrypted, an RPO per tier, a measured RTO, restores onto another host, a store per region, and drills on a real Incus host in CI. Gaps: the host-loss drill on production hardware (A1.3-1), manual recovery of a lost host (automatic recovery needs fencing), and full exports.
- **Regions.** Done, given hosts in each region. A lost host's machines stay in their region, so each region needs **at least two hosts**: four for London and Frankfurt.
- **Operations.** The most of the options built. Rent and set up hosts in each region. Keep their kernels and Incus (7.0.1 or later, from Zabbly) patched, and their storage pools and nftables right. Watch capacity, declare lost hosts, and run the drills.
- **SOC 2.** The operator owns more of the controls: patching evidence for the hosts (CC7.1), who can reach them, and the host-loss drill (A1.3-1). Capacity (A1.1-1) is done. Physical controls are inherited from wherever the hosts run.
- **Lock-in.** Low. Incus is open source and runs on any Linux host. Machines export to S3, and hosts can be replaced one at a time by restoring their machines elsewhere (ADR 0076).
- **Migration.** From Linode, nothing in the code: switching `MACHINE_PROVIDER` leaves Linode machines unmanaged. Each user would get a new machine, as when leaving Linode.

### (c) A production orchestrator: Kubernetes (LKE or k3s) or Nomad

Nothing is built. It would be a third provider behind the trait.

- **Fit.** An orchestrator schedules application containers. A SuperBot machine is a whole OS: systemd, cloud-init, real OS users for Bots and teammates, and screens. ADR 0065 rejected Docker for that reason, and Kubernetes as too much for one container per user. To make a pod a machine needs a runtime that gives it a full OS or its own kernel, such as KubeVirt, Kata Containers or Sysbox. This repo has never run or tested any of them, and VM runtimes need hosts that support virtualisation.
- **Isolation.** With an ordinary runtime, it's (b)'s shared kernel. With a VM runtime, it's close to (a). The firewall guarantees of ADR 0035 and ADR 0065 would have to be rebuilt as network policies, which only some network plugins enforce. botd dials each machine's agent directly (ADR 0031), and pod addresses can't be reached from outside the cluster without more routing.
- **What it would replace.** Scheduling, restarts and placement. botd already does placement by load (ADR 0081), host-loss recovery (ADR 0076) and reconciliation (ADR 0025). Billing, enrollment, tiers, regions and backups would stay botd's. An orchestrator would sit beside the control plane, not replace any of it.
- **Cost.** (b)'s formula with nodes as hosts, plus the cluster's own overhead: a managed control plane on LKE, or servers to run on k3s or Nomad.
- **Latency.** Seconds for a pod with its image already pulled; more for VM runtimes. Unmeasured.
- **Backups.** Volume snapshots depend on the storage driver. None of ADR 0071 and 0074's export, RPO and RTO machinery carries over without being ported.
- **Regions.** A cluster per region.
- **Operations.** The most of all: cluster upgrades on the orchestrator's release cadence, network and storage plugins, ingress, and the runtime above. For a team of one or two, that is a job in itself.
- **SOC 2.** More systems in scope: the cluster API and its access control, its secret store, and node images.
- **Lock-in.** The Kubernetes API is portable. A managed cluster's storage and load balancers are less so.
- **Migration.** A new provider, and the same lack of a move between substrates.

### (d) A mix by tier

For example, containers for the lower tiers (for density) and VMs for tiers or customers that need their own kernel (Enterprise, regulated buyers).

- It gets (b)'s cost where a shared kernel is accepted, and (a)'s boundary where it isn't.
- **It isn't possible today.** A control plane has one provider, and a machine from another is left alone. There are three ways to get there:
  1. A provider per tier in one control plane. This touches tier mapping, placement, the reconciler, firewall sync, backups and the admin views. Real work, its own ADR.
  2. Incus VMs (`type: virtual-machine`) as a second kind of plan on the same fleet, which ADR 0065 lists as a follow-up. That needs hosts with hardware virtualisation, and new isolation checks for VMs.
  3. Two botd deployments, one per substrate. But one organisation can't span them, as ADR 0117 found for regions.
- **Operations and SOC 2.** Those of both (a) and (b), until one is dropped.

### Summary

| Criterion | (a) Linode VMs | (b) Incus fleet | (c) Orchestrator | (d) Mix by tier |
|--|--|--|--|--|
| Isolation | Own kernel | Shared kernel per host | Depends on runtime | Own kernel where needed |
| Cost per user | Highest; billed while suspended | Lowest at density | (b) plus a cluster | Between |
| Latency | Unmeasured | About 6 s to enroll | Unmeasured | Per substrate |
| Backups and recovery | Daily, same data centre, manual restore | Off-host, per-tier RPO, measured RTO | To be built | Per substrate |
| Regions | Done | Done, two hosts per region | A cluster per region | Per substrate |
| Operations | Least | More | Most | Both (a) and (b) |
| SOC 2 evidence | Mostly inherited | More of it ours | Most of it ours | Both |
| Lock-in | No export | Low | Low to medium | Mixed |
| Migration from today | None | New machine per user | New provider | Code to run two providers |

## Recommendation

1. **Don't adopt an orchestrator now (c).** It solves scheduling that botd already does, needs extra runtimes before it fits a whole-OS machine, and adds the most operations work of any option for a tiny team. Revisit it if any of these comes true: the Incus fleet outgrows what one person can patch and drill; there is someone whose job is running clusters; or customers ask to run their machines on their own clusters.
2. **Launch M4's public managed tiers on Linode VMs (a)**, as decision 2 says. Public sign-up means strangers whose Bots run commands a model chose. A kernel per user is the boundary we can defend today, and it is the least operations work. Set `MACHINE_OWN_KERNEL_TIERS=all` on that server (below), so a later settings change can't quietly put those users on a shared kernel. Before launch:
   - time a restore of a Linode machine, as ADR 0110's procedure says;
   - run the Linode provider once against a real Linode account and record it, as ADR 0069 did for Incus;
   - price the tiers with formula (a), including that suspended machines are billed.
3. **Use Incus containers (b) only for fleets that serve one organisation**: hosts whose containers all belong to one customer (dedicated hosting, M5), or the operator's own team. There, a kernel escape stays within one customer. Don't mix strangers on a host until all three of these are done:
   - the container boundary passes a red-team scenario (M5's exit criterion);
   - the host-loss drill has run on production hardware (A1.3-1);
   - botd can use a project-restricted Incus certificate (OVN, an ADR 0065 follow-up).
4. **Make the mix by tier (d) the target**, once step 3's conditions are met and enrollment times and costs have been measured. Lower tiers would go on Incus where formula (b) beats (a), and tiers promised their own kernel on VMs. The first step is a provider per tier in one control plane, or Incus VMs, in its own ADR. `MACHINE_OWN_KERNEL_TIERS` is the setting it will route by.

**If David chooses differently:**

- **(b) for public tiers now.** Leave `MACHINE_OWN_KERNEL_TIERS` unset. Rent at least two hosts per region. Run the A1.3-1 drill before launch. Keep the shared kernel stated in the security pack, as [access control](../security/access-control.md) now does.
- **(c).** It needs a new provider and its own ADR, which isn't M4-sized.
- **(d) at launch.** Running two providers in one control plane comes first.

**What David is asked to decide:**

1. Whether (c) is ruled out for now.
2. Whether public tiers launch on Linode VMs.
3. Whether a shared kernel is acceptable for any public tier, and which.
4. Prices for the formulas, which decide whether (b) or (d) is worth its operations work.

## What this ADR builds

Both pieces are opt-in, and neither changes what happens on a server that doesn't use them.

### `MACHINE_OWN_KERNEL_TIERS`

- A comma-separated list of tiers from `MACHINE_TIERS` whose machines must have a kernel of their own, or `all`. Unset by default.
- A tier that isn't in `MACHINE_TIERS`, or one listed twice, stops botd at start.
- With a provider whose machines share their host's kernel (`MACHINE_PROVIDER=incus`), botd refuses to start and names the tiers: "MACHINE_OWN_KERNEL_TIERS: pro must have a kernel of their own, and incus machines are containers that share their host's (ADR 0119)". It's a startup error, not a warning, because the setting records a promise to customers.
- A control plane has one provider today, so the check covers the whole server. It is per tier so that the mix by tier (d) can send those tiers to a VM provider without a new setting.
- `GET /api/machines/substrate` and `botctl machine substrate` show `kernel` (`own` or `shared`), and `ownKernel` for each tier. The startup line names those tiers.
- **`MachineProvider::substrate()` no longer has a default.** It used to default to `vm`, so a new provider that forgot to override it would have claimed its own kernel and passed this check. Each provider now says what it makes: `vm` for Linode and the fake provider, `container` for Incus.

### How long a machine takes to come up

A machine's first `machine.enrolled` audit event now has these fields: `first: true`, `provider`, `tier`, and `sinceRequestSeconds`, the time from the machine's request to its agent enrolling. Later enrollments, after a rebuild, a restore or a new token, don't have them. Export them with `/api/audit?action=machine.enrolled` or the CSV to compare substrates with real numbers. This counts from the request, so it includes time spent pending (rate limits, or no room on a host). For a machine made before enrollment was turned on, it includes that whole wait.

## Consequences

- Nothing changes for a server that doesn't set `MACHINE_OWN_KERNEL_TIERS`.
- An operator who promises customers their own kernel can make botd hold to it. An Incus server that sets it won't start, by design.
- Provisioning time per provider and tier can be read from the audit log, so the revisit in step 4 can use measurements rather than estimates.
- A new provider must state its substrate. An orchestrator provider couldn't claim VM isolation by omission.
- Until the owner decides, decision 2 stands, and this ADR stays Proposed.

## Tests

- **Settings** (`machines/mod.rs`):
  - unset by default;
  - a list, `all`, trimming and case;
  - unknown and repeated tiers, and `all` mixed with tiers;
  - refused with Incus, naming the tiers.

  The Incus case fails without the check and passes with it.
- **The substrate view**: own kernel and a per-tier flag with the fake provider (`machines_http_tests.rs`); shared kernel and no flag with Incus (`machines_incus_tests.rs`).
- **Enrollment** (`machines_mtls_tests.rs`): the first enrollment records its provider, tier and seconds since the request, within the test's own time. A second enrollment by hand doesn't.
