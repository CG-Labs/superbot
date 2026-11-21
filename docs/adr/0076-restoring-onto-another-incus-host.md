# 0076: Restoring machines onto another Incus host

## Status

Accepted. Builds on [ADR 0065](0065-incus-container-machines.md) (Incus container machines), [ADR 0067](0067-clearing-enrollment-data-from-containers.md) (enrollment data cleared once spent), [ADR 0069](0069-validating-incus-containers-on-a-real-host.md) (the real-host test), [ADR 0071](0071-off-host-machine-backups.md) (off-host backups and restore) and [ADR 0074](0074-machine-rpo-and-rto.md) (RPO and RTO). The control plane's next step on [#29](https://github.com/CG-Labs/superbot/issues/29): losing a whole Incus host.

## Context

ADR 0071 sends every container's backup off the host and can restore it with fresh enrollment, but only in place: onto the host the machine is on. botd knew one Incus host (`INCUS_URL`). If that host is lost (disk, hardware, the provider's server gone), the backups are safe in the store but there is nowhere to restore them, and nothing in botd says the host is gone.

## Decision

### Several hosts behind one provider

`MACHINE_PROVIDER=incus` can have several hosts. botd still has one provider. It sends each call to the right host.

| Setting | Meaning | Default |
|---|---|---|
| `INCUS_HOST_NAME` | The name of the `INCUS_URL` host. | `main` |
| `INCUS_HOSTS` | More hosts, as `name=https://<incus-host-ip>:8443,...`. | none |
| `INCUS_SERVER_CERT_<NAME>` (or `_FILE`) | Each extra host's pinned certificate. `<NAME>` is its name in capitals with `-` as `_`. | required |
| `INCUS_PROJECT_<NAME>`, `INCUS_NETWORK_<NAME>`, `INCUS_STORAGE_POOL_<NAME>` | That host's, if it differs from the first. | the first host's |
| `INCUS_HOST_DOWN_MINUTES` (1 to 1440) | How long a host may not answer before it is down. | 10 |

botd's client certificate is the same on every host. Names are lowercase letters, digits and dashes, up to 32 characters.

- **Provider ids name the host**: `<host>/<container>`. The container keeps the machine's label on every host, so a moved machine's container has the same name. At startup, provider ids from before there were hosts (`<container>`) become `<first host>/<container>`.
- **Placement**: new machines go on the first host that is up, in the order configured. Spreading machines by load is later.
- **Isolation**: every host's address is denied to every container, as `INCUS_URL`'s always was (ADR 0065). The firewall is kept the same on every host that is up.
- **Pinning**: each host's certificate is recorded the first time botd sees it (`machine_hosts`). If a name's certificate changes, botd refuses to start, so a name can't quietly point at another host and have its machines taken for that host's. A new host gets a new name.

### Up, down and lost

Each reconcile interval, botd asks every host that isn't lost for its server info.

- **Down.** A host that hasn't answered for `INCUS_HOST_DOWN_MINUTES` is down. It is audited once as `machine.host_down` (target type `host`, with how many machines are on it and the last error) and alerted through ADR 0061's operator channels (ADR 0074's `alert` notice). Nothing new goes there. Its machines keep their state: a `get` that fails to reach the host is an error, never "not found", so nothing is marked lost, revoked or restored because a host was silent. Their RPO is still tracked, and a breach's alert says the host isn't answering.
- **Up again.** The first answer brings it back up, audited and alerted as `machine.host_up`.
- **Lost** is only ever declared by an admin. botd never decides a host is gone on its own: a host down for an hour may come back with its containers, and restoring them elsewhere first would leave two copies of each machine, both of which think they are it. A lost host is never called again, even if it answers. Destroying a machine there succeeds without it. A lost name stays lost; a replacement host gets a new name.

### Recovering a lost host

`POST /api/machines/hosts/{name}/recover` `{to?, identity?}` (`botctl machine host recover <name> [--to <host>] [--identity <age-key-file>] --yes`):

1. Refused (409) while the host answers. Then its containers are still there, and the way to move them is one restore at a time with `--host` (below), which deletes each old copy.
2. `to` is the host to restore onto: the first other host that is up by default. It must be up.
3. If any machine's newest backup is encrypted and there is no `identity`, it is refused (400) before anything changes.
4. The host is declared lost: recorded with who did it, audited once as `machine.host_lost`, and alerted.
5. For each machine on it:
   - Its enrollment tokens and certificates are revoked (`reason: host_lost`). Nothing from that host's disks is trusted again.
   - If it has a finished off-host backup, a restore from the newest one onto `to` is recorded and audited as `machine.restore_requested` with `fromHost`, `toHost` and `reason: host_lost`.
   - If it has none, it goes to error with a message saying so, audited as `machine.lost` (`reason: host_lost`, `restorable: false`). It is to be destroyed and requested again.
   - One already restoring, or that can't be restored now, is skipped and listed.
6. The restores run two at a time, each as ADR 0071's restore: import onto `to` beside nothing, today's settings, firewall and a fresh enrollment token pushed onto its disk (never into the provider's config, ADR 0067), then the swap, a boot, and enrolling anew. The firewall is set up on `to` first if it isn't there.
7. The machine's record names its new host as soon as the swap is done (`provider_id` is `<to>/<label>`), so whatever happens next happens there.

It answers 202 with what it restores, what it can't, and what it skipped. Running it again picks up machines it skipped and announces nothing twice.

### Moving one machine

`POST /api/users/{key}/machine/restore` takes `host`: the host to restore onto (`botctl machine restore <user> <backup-id> --host <name> --yes`). By default a restore is onto the machine's own host, or the first host that is up when its own was lost. Onto another host, the machine's own host must be up (its old container is deleted once the copy is ready, so there is never a second copy) or lost. While it is down, the restore is refused: declare it lost first. This is also how to drain a host that still works.

### What admins see

- `GET /api/machines/hosts[?check=true]` (`botctl machine hosts [check]`): every host botd has known, its state, when it stopped answering, the last error, when it was lost and by whom, how many machines are on it, and where new machines go. `check` asks every host now.
- Each machine's admin view and its line in `GET /api/machines/recovery` have `host`. The recovery view lists the hosts too, and each restore names `fromHost`, `toHost` and `reason`.
- `POST /api/machines/reconcile` returns `hostsDown`.

### RPO and RTO

ADR 0074's targets don't change. A host-loss restore is a restore: timed from its request (when the host was declared lost) to its agent enrolling on the new host, against the tier's RTO, and recorded with `fromHost` and `toHost`. Its RTO doesn't count the time before the declaration: noticing (up to `INCUS_HOST_DOWN_MINUTES`, then the alert) and an admin deciding the host is gone. Restores run two at a time, so a host with many machines takes longer than one restore, roughly machines ÷ 2 × one restore's time. ADR 0074's guidance stands: don't contract an RTO for a whole host's machines until the manual drill shows it on production hardware.

The data lost is everything since each machine's newest off-host backup: at most its tier's RPO when botd kept it, which is what the RPO promises.

### Tests and drills

- **Against stand-ins** (`machines_hosts_tests`): two Incus stand-ins as hosts `a` and `b`, the S3 stand-in, and the real agent. Host `a` stops answering: nothing is lost or revoked while it is only failing; after the threshold it is down, audited and alerted once, and new machines go to `b`. Restores are refused while `a` is down and not lost. Declared lost: certificates revoked, the backed-up machine restored onto `b` from its backup with a fresh token and behind the firewall there, its record moved, enrolled anew and timed; the machine with no backup in error. `a` coming back is never called again, and destroying a machine on it doesn't need it. A host that comes back is up again and can't be recovered; a machine moved between two up hosts leaves no copy behind. Pinning and old provider ids are checked at startup.
- **On a real Incus host in CI** (the `incus-e2e` job, ADR 0069): one Incus stands in for two hosts. Host `a` is the `superbot` project reached through a TCP forwarder on loopback, and host `b` a second restricted project, `superbot-b`, made by `deploy/incus-e2e-host.sh`. A real container on `a` enrolls and is backed up, encrypted, to versitygw. Then `a` is lost: the forwarder closes and the container is deleted. botd finds `a` down, the test declares it lost, and the container is made again in `b` from the backup, with the backup's files, a new identity, the firewall, and only its new certificate, within its tier's RTO. The timing is in the job summary and uploaded as `host-drill-<incus>`. The two projects share one kernel and storage, so this checks botd's side of a host loss (routing, ids, detection, recovery and re-enrollment), not the network between real hosts.

## Consequences

- Losing a whole Incus host is recoverable without a code change or a restart: add a host to `INCUS_HOSTS` ahead of time (or add one and restart botd), then recover the lost one.
- A spare host costs money while it waits. One can be added only when needed, at the cost of a restart and the time to set it up (docs/ops/incus-containers.md) on top of the RTO.
- Recovery is manual by design. Automatic recovery would need fencing: proof the old host can't come back (its provider's API powering it off, say), which is per hosting provider and later.
- Not covered: provisioning a new host (an operator's job, as in ADR 0065), placement by load or capacity, live migration between hosts that both work (Incus can do it, but botd's restore is what's drilled), and Linode machines (Linode's own backups). botd itself being lost is ADR 0030's self-host backup and drill.
