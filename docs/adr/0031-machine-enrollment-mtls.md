# 0031: Machine enrollment and mutual TLS

## Status

Accepted. Next slice of [#29](https://github.com/CG-Labs/superbot/issues/29) (M3). It builds on [ADR 0025](0025-control-plane-linode.md) (one machine per user, whose "out of scope" section sketched this), [ADR 0029](0029-per-user-isolation.md) (the `MachineLink` routing hook) and [ADR 0010](0010-secrets.md) (the master key). Moving a user's Bots onto their machine is the next slice: [ADR 0036](0036-bots-on-the-users-machine.md), which replaces the agent's 501 on `/v1/jobs` with the job protocol.

## Context

ADR 0025 made machines; ADR 0029 picks the owner's machine for each run and refuses rather than falls back. But botd had no way to talk to a machine, and no way to know that whatever answered at a machine's address was that machine. Without that, routing can only refuse.

We need: a machine proves which machine (and so which user) it is; botd proves it is the control plane; neither can be faked by another machine, another user, or whoever gets the IP next; and all of it ends when the machine is suspended or destroyed.

## Decision

### Off by default

Enrollment is on only when `MACHINE_CONTROL_URL` is set, and that needs the control plane (`LINODE_TOKEN`). Self-hosted servers set neither and nothing changes: no new port, no new keys, the same `Unenrolled` link.

| Setting | Meaning |
|---------|---------|
| `MACHINE_CONTROL_URL` | `https://<host>:<port>` as machines reach botd. The port is required. Turns enrollment on. |
| `MACHINE_LISTEN` | Where botd listens for machines. Default `0.0.0.0:<port of the URL>`. |
| `MACHINE_AGENT_PORT` | Where each machine's agent answers. Default 7443. |

`MACHINE_LISTEN` or `MACHINE_AGENT_PORT` without the URL is a startup error, not a silent no-op.

### One CA, derived from the master key

The control-plane CA's Ed25519 key is derived from the master key: `HMAC-SHA256(HMAC-SHA256(master, "superbot/derive"), "machine-ca/v1")`. Its certificate is fixed (name, serial, dates) and Ed25519 signs deterministically, so the same master key always gives the same CA, byte for byte. Nothing is written to disk: the CA key is kept exactly where the master key is (outside `DATA_DIR` and backups, ADR 0010), and the installers and backup scripts don't change. A new master key means a new CA, and every machine re-enrolls.

Identities are URI SANs, so the certificate says who, and botd's database says whether:

- the control plane: `spiffe://superbot/control-plane` (plus the host from `MACHINE_CONTROL_URL`);
- a machine: `spiffe://superbot/user/<user id>/machine/<machine id>`.

Leaf certificates are ECDSA P-256, 30 days, for both client and server use. botd's own certificate lives in memory and renews itself with a third of its life left.

### Enrollment

1. When botd asks the provider to create a machine, it mints a **token**: `sbe_` and 32 random bytes, bound to that machine, valid 60 minutes, kept only as a SHA-256 hash. Each create attempt gets a fresh one.
2. The token rides in cloud-init user data (Linode `metadata.user_data`) with the CA certificate, the control URL, the machine id and a systemd unit. If `superbot-machine` ships next to `botd`, cloud-init downloads it from botd's machine port, trusting only the CA, checks its SHA-256, and starts it.
3. The agent makes its key on the machine and sends `POST /v1/enroll {machineId, token, csr}`. botd checks the CSR's signature and uses only its public key; every name in the certificate is botd's.
4. In one transaction botd uses the token (unused, unrevoked, unexpired, for this machine), revokes the machine's other unused tokens and any earlier certificates (`replaced`), and records the new one. Two enrollments with one token can't both win.

A refused token is a 401 with one message whatever the reason (used, revoked, expired, other machine), so a caller learns nothing; the reason is audited. Guesses (tokens botd never issued) are not audited, since anyone can reach the port. A bad CSR doesn't use the token.

An admin can issue a new token for a running machine (`POST /api/users/{user}/machine/enrollment`). It is shown once and never audited.

### Mutual TLS, both ways

TLS 1.3 only (rustls with aws-lc-rs).

- **Machine → botd** (botd's machine port, separate from the API): the agent trusts only the CA and checks the hostname. botd asks for a client certificate but doesn't require one, because enrollment has none. Every other call is checked against the database: the certificate must be one botd issued, active and in date; its URI must match botd's record of machine and owner; the machine must not be destroyed and its owner not disabled; and the path's machine id must be the certificate's own. A certificate acts only for its own machine and user, whatever the request names (403 `machine_mismatch`, audited).
- **botd → machine** (the agent's port): botd pins the SHA-256 fingerprints of that machine's usable certificates, and shows its control-plane certificate. A reused IP, another user's machine, or anything else at that address fails the handshake. The agent requires a CA certificate with the control-plane URI, so one machine can't call another.

Routing (`MACHINE_ROUTING=on`) now refuses a running machine with no usable certificate (`machine_not_enrolled`), and otherwise hands the job to the `Mtls` link, pinned to that machine.

### Rotation, hold, revocation

- **Rotation.** The agent asks for a new certificate (`POST /v1/machines/{id}/certificate`) with a third of its life left, signing in with the current one. It checks at start and every minute, and takes up a certificate that `superbot-machine enroll` saved by hand. The new one is recorded only if the current one is still active in the same transaction, so a rotation racing a hold or revocation can't undo it. The old one keeps working until the new one is first used; then the older ones are revoked (`rotated`). A machine that never got the answer isn't locked out: it asks again, and the unused one is revoked (`superseded`).
- **Suspend** holds the machine's certificates; **resume** releases them. A stopped machine can't receive a new token, so it keeps its key.
- **Destroy**, a machine **lost** at the provider, or an admin (`DELETE /api/users/{user}/machine/certificates`) revokes every certificate and unused token. Re-enrolling needs a new token.

Revocation is botd's database, checked on every call and every pin: there is no CRL or OCSP to fetch, and short lives bound a certificate that escapes.

`machines.enrollment` shows the result: `none`, `enrolled`, `held`, or `revoked`. `agent_seen_at`, `agent_version` and `agent_error` show the last heartbeat; botd asks every enrolled running machine on each reconcile interval, a few at a time and in a loop of its own, so agents that don't answer can't hold up provider checks. Users see `enrollment` and `agentSeenAt` for their own machine.

### The agent

`superbot-machine` is a small Rust binary in this repo (`server/src/bin/superbot-machine.rs`), sharing botd's `pki` and `wire` modules and nothing else. It enrolls (retrying; slowly when the token was refused), keeps its key and certificate together in one file in its state directory (`0600`, replaced in one rename, and refused on load unless the key is the certificate's), deletes the token file once used, rotates, and answers `GET /v1/heartbeat`. `POST /v1/jobs` answers 501: it is connected, but it can't run Bots yet. `superbot-machine enroll` and `superbot-machine status` help an operator check one by hand.

### Audit

| Event | When |
|-------|------|
| `machine.enroll_token_issued` | A token was minted (at create, or by an admin) |
| `machine.enrolled` | A machine enrolled |
| `machine.enroll_failed` (denied) | `wrong_machine`, `token_used`, `token_revoked`, `token_expired`, `machine_not_ready`, `user_disabled`, `bad_csr` |
| `machine.cert_rotated` | A new certificate was issued for an old one |
| `machine.cert_revoked` | `replaced`, `rotated`, `superseded`, `destroyed`, `lost`, `admin` |
| `machine.cert_held`, `machine.cert_released` | Suspend and resume |
| `access.denied` | A certificate refused: `identity_mismatch`, `revoked`, `held`, `expired`, `machine_gone`, `user_disabled`, `machine_mismatch` |

Calls a machine makes are audited as `system:machine_agent` on behalf of the machine's owner, with its IP. Heartbeats are not audited.

### Testing

All on loopback with the fake provider: the real router, botd's machine port and the real agent. Tests cover single-use, expired, revoked and wrong-machine tokens, two enrollments racing for one token, no certificate, another CA's certificate, a certificate botd never recorded, rotation (including a lost answer), hold on suspend, revocation on destroy, loss and admin action, and a cross-user test: user A's machine certificate can't read or rotate for user B's machine, botd won't take A's agent as B's when it answers at B's address, and B's certificate can't call A's agent.

## Consequences

- `MACHINE_ROUTING=on` with enrollment on reaches the owner's machine over authenticated, pinned TLS, and refuses there with a clear reason until machines run Bots.
- One new listening port on managed control planes, open to the internet: it serves only enrollment (token-gated), the CA-pinned agent download, and calls with a valid machine certificate. Both ports serve at most 256 connections at once, each for at most 10 minutes, and botd reads the agent binary once at start.
- Rotating the master key rotates the CA too. Amended by [ADR 0096](0096-master-key-rotation.md): a rotation keeps the derived-key root, so the CA stays, unless `SUPERBOT_ROTATE_DERIVED_KEYS=1`.
- Linode metadata (user data) needs a region and image that support it; others would need another way to deliver the token (an admin-issued token works).
- The agent binary botd serves must suit the machines' architecture (both x86_64 Linux today).

## Deferred

- **Moving Bots onto machines** (next on #29): the run protocol behind `POST /v1/jobs`, and moving each user's folder, memory and harness logins there.
- Pushing an agent upgrade to running machines; today a machine gets the agent at first boot.
- A firewall rule set at the provider (Linode Cloud Firewall) limiting the agent port to the control plane. Done in [ADR 0035](0035-machine-firewall-auto-enroll.md), with hands-free first-boot enrollment and an enrollment timeout.
- The control plane's own CA with an offline root, if the master-key-derived CA proves too coupled.
