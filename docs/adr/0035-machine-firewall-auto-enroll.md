# 0035: Machine firewall and hands-free enrollment

## Status

Accepted. Next slice of [#29](https://github.com/CG-Labs/superbot/issues/29) (M3), after [ADR 0025](0025-control-plane-linode.md) (machines) and [ADR 0031](0031-machine-enrollment-mtls.md) (enrollment and mTLS). Moving Bots onto machines is still to come.

## Context

ADR 0031 gave a machine a one-time token and a way to swap it for a certificate. Two gaps were left:

- A new Linode is open to the internet: SSH, the agent port, anything that listens.
- Enrollment needed the agent to start and use its token. Nothing told anyone when that didn't happen.

We want a machine that comes up enrolled and locked down with no manual steps, and a clear signal when it doesn't.

## Decision

### Off by default

Everything here is behind the existing control-plane settings. Self-hosted servers set none of them.

| Setting | Meaning |
|---------|---------|
| `MACHINE_FIREWALL` | `on` puts every machine behind a Linode Cloud Firewall. Default off. Needs `MACHINE_CONTROL_URL`, because the firewall's only job is to open the agent port to botd. |
| `MACHINE_FIREWALL_SOURCES` | CIDRs that may reach the agent port. Default: the control URL's address, if it is an IP. With a host name it must be set. |
| `MACHINE_SSH_SOURCES` | CIDRs that may reach port 22. Unset: SSH is closed. |
| `MACHINE_ENROLL_TIMEOUT_MINUTES` | How long a machine has to enroll, 5 to 60. Default 15. |

Every misconfiguration is a startup error, not a silent no-op. That includes sources set with the firewall off, the firewall on without enrollment, and an address with host bits set (`10.0.0.1/8`).

### One firewall per control plane

botd keeps one firewall, labelled `<MACHINE_LABEL_PREFIX>-fw` and tagged with the prefix.

- **Inbound** is `DROP` by default. There are at most two rules: TCP on the agent port from the sources, and TCP 22 from the SSH sources if any are set.
- **Outbound** is `ACCEPT`. Machines need package mirrors, botd, and later the model providers. Egress limits are M5.

All machines share the rules, so one firewall does the job. It stays within Linode's limits (25 rules, and one firewall per Linode).

**When a machine is created:**

1. botd finds the firewall by label, or creates it. If the create races another, or its answer was lost, botd finds it again.
2. If the rules differ from what botd configured, botd sets them back. If someone disabled the firewall, botd enables it again, since a disabled firewall filters nothing.
3. botd passes the firewall's id in the Linode create (`firewall_id`), so the machine is behind it from its first packet. There is no window between boot and attach.

If botd can't get the firewall, it creates no machine and mints no token:

- On a transient error (rate limit, network), the machine stays pending and the next pass retries.
- On a refusal (for example, a token without Firewalls scope), the machine moves to `error`.

**Each reconcile pass** keeps things right while any machine exists. It restores changed rules, re-enables a disabled firewall, re-creates a deleted one, and reattaches machines that are off it. These are machines taken off at the provider, adopted after a lost create, or made before the firewall was turned on. A machine botd can't attach (Linode allows one firewall per Linode) is audited once per distinct error, not on every pass.

A machine that is still behind an older firewall of ours stays there. This happens after a `MACHINE_LABEL_PREFIX` change, for example. Moving it would mean detaching first, since Linode allows one firewall per Linode, and that would leave it open for a moment. Instead, botd keeps that firewall's rules and status right too, and deletes it with its last machine. New machines go behind the current one.

**When a machine is destroyed,** botd takes it off the firewall. Linode does this on delete too, so it is idempotent. When no live machine of ours uses the firewall and Linode reports no devices of any kind on it, botd deletes it. It never deletes a firewall that still covers something botd doesn't know, such as a NodeBalancer someone attached. If the delete fails, the empty firewall costs nothing and the next machine reuses it.

The provider trait has the firewall operations: find by label, get by id, create, set rules, enable, list devices, attach, detach, delete. So the in-memory fake covers all of it in tests, and only the Linode adapter knows Linode's API.

### First boot installs and enrolls

The cloud-init user data writes:

- the CA certificate,
- `/etc/superbot/machine.env` (control URL, machine id, listen address),
- the token, in its own `0600` file,
- the systemd unit,
- a first-boot script.

`runcmd` runs the script, which:

1. Downloads `superbot-machine` from botd's `/v1/agent`, trusting only botd's CA (`curl --cacert`, with retries while the network comes up).
2. Checks the binary against the SHA-256 written into the user data, then installs it.
3. Runs `superbot-machine enroll` once. The agent reads the token file, swaps the token for a certificate, and deletes the file.
4. Deletes cloud-init's copies of the user data (`/var/lib/cloud/instance/user-data.txt*`).
5. Enables and starts `superbot-machine.service`. A failed enroll still starts the service, so a new token can be tried without a reboot.

**Agent source: botd serves its own build.** botd serves the `superbot-machine` binary built from the same commit, from beside its own binary. We chose this over a pinned GitHub release because:

- The agent always speaks the same wire protocol as the botd that enrolls it. No version matrix, no release lag.
- No dependency on GitHub, or on any download host but botd itself.
- The trust is the same as enrollment's: botd's CA, plus a hash botd computed from the bytes it serves.

The cost is that botd must ship next to the agent binary. The installer and the Docker image already do. Without it, the user data has no download and no first-boot script, and enrollment needs the agent installed some other way, as in ADR 0031.

### The token

- botd keeps only its SHA-256 (ADR 0031). It is in the user data once, in its file entry. It is never on a command line, in a script, or in an environment variable at rest.
- The first-boot script has no `set -x` and doesn't echo it.
- `CreateSpec`'s `Debug` prints `[redacted]` for the user data, so no error or log line can carry it.
- Audit events record that a token was issued and used, never the token. A test reads every audit event, the machines API, and the SQLite files (including the WAL), and finds neither the first nor a re-issued token.
- On the machine, the agent deletes its token file, and the script deletes cloud-init's copies.

**Known residue:** Linode's metadata service keeps the user data for the life of the Linode. cloud-init's merged config and cache (`cloud-config.txt`, `obj.pkl`) also held it. The first boot now deletes them too ([ADR 0069](0069-validating-incus-containers-on-a-real-host.md)), but on a Linode cloud-init can write them again from the metadata service on a later boot. Those copies are spent. The token was marked used when the machine enrolled, and enrolling revokes every other unused token for the machine. A machine that never enrolled still has a live token until it expires (`TOKEN_MINUTES`). Disabling cloud-init after first boot would stop that, but it risks breaking networking on stock images, so we don't.

### Machines that don't enroll in time

Each token sets the machine's `enroll_by` deadline, from the time it was minted plus the timeout. Each reconcile pass checks provisioning and running machines whose enrollment is `none` or `revoked`. For each one past `enroll_by`, botd sets `enroll_overdue_at` and records `machine.enroll_timeout` (failure). The update is conditional, so it happens once per deadline. Both the admin and the own-machine views include `enrollOverdueAt`, and the console shows "Didn't enroll in time".

A late enrollment still counts and clears the flag. A new token from an admin restarts the clock.

### Audit

| Action | When |
|--------|------|
| `machine.firewall_created` / `_updated` / `_deleted` | The firewall itself (target `firewall`); `_updated` records the rules it replaced, or that it was disabled. |
| `machine.firewall_attached` / `_detached` | A machine put back behind it, or taken off at destroy. |
| `machine.firewall_failed` | Attach, detach or delete failed (`step`). |
| `machine.create_failed` | Now with `step`: `firewall` or `create`. |
| `machine.enroll_timeout` | A machine missed its enrollment deadline. |

Schema migration 13 adds `firewall_id`, `enroll_by` and `enroll_overdue_at` to `machines`.

## Consequences

- The Linode token needs **Firewalls: read/write** as well as Linodes when `MACHINE_FIREWALL=on`. Without it, creates fail early with a clear error and no machine is made.
- Turning the firewall on for an existing fleet attaches every live machine on the next pass. Turning it off stops botd making or fixing the firewall, and new machines are made without it. Machines already behind it stay behind it, so access isn't silently widened. They are still taken off it at destroy, and the last one out deletes it.
- Tests use the in-memory provider for behaviour and a local Linode stand-in for request shapes. They cover rules JSON, the `X-Filter` label lookup, device ids on detach, and `firewall_id` on create. Nothing calls Linode.

## Deferred

- Per-user egress limits (M5).
- Pushing agent upgrades to running machines.
- Removing the user data from Linode's metadata service after first boot. Linode's API can't do this for a running Linode today.
