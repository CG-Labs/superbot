# 0067: Clearing enrollment data from containers' config

## Status

Accepted. A follow-up of [ADR 0065](0065-incus-container-machines.md) (Incus containers) on [#29](https://github.com/CG-Labs/superbot/issues/29) (M3). Built and tested against the Incus stand-in only.

## Context

A machine enrolls with a one-time token in its cloud-init user data ([ADR 0031](0031-machine-enrollment-mtls.md), [ADR 0035](0035-machine-firewall-auto-enroll.md)). Inside the machine, the first boot deletes cloud-init's copies of it.

For an Incus container, botd puts that user data in the instance's config as `cloud-init.user-data`, at create and again at each rebuild ([ADR 0056](0056-rebuilding-machines-enrolled-before-0039.md)). Nothing removed it. It stayed readable for the container's whole life:

- through the API (`GET /1.0/instances/<name>`) and `incus config show`;
- in every snapshot taken while it was there, because a snapshot copies the config;
- in anything that exports or backs up the config later (off-host backups, [#40](https://github.com/CG-Labs/superbot/issues/40)).

After enrollment the token is spent: used once, and every other unused token for the machine is revoked. But a machine that hasn't enrolled yet has a live token there, until it expires (`TOKEN_MINUTES`, 60). The user data also says how to reach botd and which CA to trust. None of it needs to stay once the container has booted.

Linode is different. Its metadata service keeps the user data and its API can't remove it from a running Linode, as ADR 0035 records. That stays as it is.

## Decision

### The reconciler clears it

On each pass, for a machine that is provisioning, running or suspended, the provider says whether the user data is still in the machine's config (`ProviderMachine::user_data`). The reconciler clears it when it is spent:

| When | Why it is safe |
|------|----------------|
| The machine enrolled after its latest token was issued (`enrolled_at` set and `enroll_by` cleared). | The token is used. A rebuild issues a new token, and so sets `enroll_by` again, before it writes new user data. So a machine waiting to enroll again after a rebuild keeps it. |
| Its enrollment deadline passed (`enroll_overdue_at`), the container is running, and no rebuild is underway. | A running container has already rendered the user data into its own NoCloud seed, so a late enrollment still works. A rebuild that is still waiting for the machine might still need it. |

A container that never started keeps its user data until it starts or is rebuilt, because it hasn't read the data yet. Its token still expires within the hour, as before.

On destroy, the token is revoked and the delete removes the instance together with its config. There is no separate step.

### How it is removed

`MachineProvider::clear_user_data` removes the key without restarting the machine. The default does nothing, and Linode uses it.

Incus removes `cloud-init.user-data` the way `incus config unset` does:

1. `GET` the instance and its ETag.
2. `PUT` it back without the key, with `If-Match`.
3. If another client changed the instance meanwhile, Incus answers 412. botd reads it again and keeps the other client's change. After three tries the step is left for the next pass.

A `PATCH` with an empty value only usually unsets a key, so botd doesn't use one.

Incus applies `cloud-init.*` keys at the next start. The image renders them into the seed only on create and copy. So removing the key from a running container changes nothing inside it, and the container is never stopped or started.

Clearing is idempotent:

- A machine whose config no longer holds the key isn't asked again.
- An instance that is already gone counts as cleared.
- A failure is retried on the next pass.

### Audited

| Event | When |
|-------|------|
| `machine.user_data_cleared` | The key was removed. Details: `providerId`, and `reason`, which is `enrolled` or `enroll_timeout`. |
| `machine.user_data_clear_failed` | Removing it failed. Same details plus `error`, with outcome `failure`. The machine's `lastError` says why, and the next pass tries again. |

### Snapshots wait for it

The reconciler turns on a machine's daily snapshots only once its config holds no user data. Otherwise a snapshot taken before enrollment would keep a copy of the token, and a snapshot's config can't be edited. Providers that never report user data (Linode) turn backups on exactly as before.

## Consequences

- An Incus container's config holds a live enrollment token only between its create (or rebuild) and its enrollment, or its deadline. After that, `incus config show` no longer shows the enrollment data.
- Daily snapshots of a new container start once it has enrolled, normally a few minutes later. A container that never starts or never enrolls gets none.
- Residue: a machine that already had snapshots turned on and is then rebuilt keeps the new user data until it enrolls again. A scheduled snapshot in that window copies it, and that copy is spent or expired within the hour. Snapshots expire after 7 days.
- Linode is unchanged. Its metadata service keeps the user data (ADR 0035).

## Tests

Unit tests against the Incus stand-in check that:

- the key is removed with an `If-Match` PUT and everything else is unchanged, including the vendor data with the SSH keys;
- the container is not stopped or restarted (the stand-in counts boots);
- clearing twice, or clearing a container that is gone, succeeds;
- a stopped container stays stopped;
- a rebuild writes the user data again;
- a change made by another client between the GET and the PUT is kept, and one that keeps changing is left alone.

The stand-in now models Incus's PUT (only writable fields are replaced, read-only ones are ignored) and its PATCH (config and devices are merged, an empty value unsets a key, `If-Match` is honoured).

End-to-end tests with the real agent check that:

- the user data stays until the machine enrolls, then goes once, audited, with no further calls to Incus;
- snapshots start only after that;
- after a missed deadline it is cleared from a running container but not while a rebuild is queued, and not from one that never started;
- a late enrollment still works after it is cleared;
- a failed clear is audited and retried;
- a Linode-like provider never clears anything.
