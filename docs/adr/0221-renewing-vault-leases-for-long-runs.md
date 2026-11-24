# 0221: Renewing Vault leases while a run lasts

## Status

Accepted (24 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on short-lived credentials for each run ([ADR 0185](0185-short-lived-credentials-per-run.md)), which left renewing leases for long runs out, and follows the STS sessions ([ADR 0194](0194-sts-sessions-for-each-run.md)) in stopping a run whose credentials end.

## Context

With `VAULT_RUN_CREDENTIALS`, botd makes a lease for each run and revokes it when the run ends. If botd can't revoke it (botd killed, host lost, Vault down at that moment), the lease lasts until its TTL. ADR 0185 told operators to set the role's `default_ttl` a little over the longest run (`RUN_TIMEOUT_MINUTES`, 60 by default), because nothing renewed a lease: a shorter TTL meant a credential lapsing mid-run, with the run going on and failing in confusing ways.

That makes the longest a leaked credential outlives botd about the length of a run: an hour by default, longer on servers with long runs. Vault's usual answer is a short `default_ttl` (minutes) with a longer `max_ttl`, and a client that renews the lease while it needs it. A role set up that way today breaks runs.

## Options

1. **Keep long TTLs.** Simple, but every lease botd fails to revoke lives a run's length.
2. **Make a new lease when the old one is near its end** and hand it to the run. The run's environment is fixed when its harness starts, so the new values can't reach it.
3. **Renew the run's leases from botd while the run lasts.** Chosen: the run keeps the credentials it started with, a short `default_ttl` bounds how long one outlives botd, and `max_ttl` bounds it overall.
4. **Vault Agent's lease renewal.** Needs Vault Agent beside botd and doesn't know when a run ends.

## Decision

### When a lease is renewed

As a run's leases are made, each that Vault marked `renewable` and that would end before the run could (its TTL is shorter than `RUN_TIMEOUT_MINUTES` plus five minutes, the same margin as botd's token in ADR 0185) is handed to a renewer for that run. Leases that already outlast the run, have no TTL, or can't be revoked (STS, GCP, Entra tokens) are not renewed. There is no new setting: renewing only keeps a lease alive while its run lives, and it changes nothing for roles whose TTL already covers a run.

The renewer is a thread for the run, started only when one of its leases needs it. It renews each lease two thirds of the way through its current TTL, asking for the TTL the lease was made with (the role's `default_ttl`), never past the run's latest end. So a lease botd stops renewing ends no more than a `default_ttl` later, and the last renewal ends with the run's deadline rather than an increment after it. When the run ends, however it ends, the renewer stops before the leases are revoked, so it never renews a lease being revoked.

Renewal is `PUT sys/leases/renew/<lease id>` with `{"increment": <seconds>}`, the lease id in the path like revocation's, so a policy can allow renewing only the leases of botd's own paths (`sys/leases/renew/aws/creds/bots/*`). It is sent with botd's current token. The token that made the lease still bounds it: ADR 0185 already makes sure that token lives past the run.

### When a lease can't be kept alive

Like the STS sessions, a run stops when one of its credentials ends for good, rather than going on with a key that no longer works.

- **Vault gives less than asked** (the role's `max_ttl`, or the token's) or says the lease is no longer renewable: that renewal is its last. If it ends before the run could, the run stops then.
- **Vault refuses** (400 or 404: the lease is gone or not renewable; 403 with a fresh token: the policy doesn't allow renewing): final, and the run stops when the lease would have ended anyway.
- **Vault can't answer** (down, 5xx, an answer that isn't a lease): tried again, after a third of the time left, between one and thirty seconds. If the lease runs out first, the run stops then.
- **A lease made not renewable** that ends before the run could stops the run when it ends. Before this ADR such a run went on without working credentials.

The runner's timer follows the leases' end as it is learnt (a `watch` channel), and stops the run at that end or at the run timeout, whichever comes first. The Bot says its short-lived credentials expired and it stopped, as for an STS session. The run's result is still `timeout`.

If botd can't start the renewer thread, the leases can't be renewed, so the run stops when the first ends.

### Audit and redaction

- `secret.lease_renewed` for each renewal and each failed one: target the path (`secret_lease`), the Bot, `store`, `path`, `leaseId`, `increment` asked for, and `userId` for a path with `{owner}`. A renewal carries the `ttl` Vault gave and `expiresAt`; its last, which ends the run, has `final: true`. A failure has `error`: `refused`, the error's kind (`unavailable`), or `expired` when the lease ran out while renewals failed. Never a value.
- Values stay redacted while the lease lives, as before. Renewing doesn't change when they are forgotten: once Vault confirms the revoke.

### Code

`leases::Issuer` gains `renew`, which by default refuses (for backends whose tokens can't be renewed). `vault::Vault` implements it. `leases::Leases` holds the run's renewer and a `watch` of when its first lease ends for good, which `Leases::ends` hands the runner. `RunCredentials::issue` picks the leases to renew once all are made, so a run refused for a missing field never starts one.

## Consequences

- No change for roles whose `default_ttl` already covers a run, beyond a run stopping when a non-renewable lease ends before it could.
- Operators can now set `default_ttl` to a few minutes and `max_ttl` over `RUN_TIMEOUT_MINUTES` plus five minutes. A lease botd can't revoke then ends within `default_ttl` of botd's last renewal, not a run's length.
- botd's Vault policy needs `update` on `sys/leases/renew/<path>/*` for each listed path. Without it the first renewal is refused, audited, and the run stops when its lease ends.
- Each renewal is one Vault request and one audit event: a run of an hour with a 15-minute `default_ttl` renews each lease about six times.
- botd still doesn't keep lease ids across restarts. A lease from a run botd didn't see end ends within its `default_ttl`, which this ADR makes short.
- Tested in `server/src/secrets/leases.rs` (renewed by the TTL it was made with while the run lasts and not after, the last renewal held to the run's end, leases that outlast the run left alone, a capped renewal and a lease made not renewable ending the run, a refusal, failures tried again until the lease runs out), against the stand-in Vault in `vault.rs` (the HTTP API with the lease id in the path, renewed in the secrets' namespace, the role's max TTL, a revoked lease refused, a policy without renew named, Vault down, lease ids that can't be part of a path), and on the real router in `run_credentials_http_tests.rs` (a run outlives its lease's TTL by renewing it, then stops when the max TTL ends it, and the lease is revoked).
- Ops guide: [docs/ops/vault.md](../ops/vault.md#renewing-leases-for-long-runs).
