# Runbook: external secrets store

botd reads Bots' keys and its own secrets from an external store (`SECRETS_BACKEND`: HashiCorp Vault, Azure Key Vault, GCP Secret Manager or AWS Secrets Manager), and can make short-lived credentials for each run. It fails closed: when the store can't be read, Bot runs that need it are refused rather than given an old value. Severity: [1](severity.md#severities) when runs are refused for everyone (`secrets_unavailable` on every Bot), since Bots don't run; 2 when they're refused for many people, botd can't sign in to the store while its cache still holds (runs stop when the cache runs out, `SECRETS_CACHE_SECONDS`), or a rotation after a leak didn't land; 3 for one user's folder, one per-run credential entry, or long runs stopping when their lease ends. A leaked key itself is Severity 1 whatever the store does.

The setup and day-to-day steps are in the [Vault](../ops/vault.md) and [cloud secret managers](../ops/cloud-secrets.md) guides; this page is the order to work in.

## First five minutes

1. **Is it the store, or one name?** As an admin on the server:

   ```sh
   botctl secrets backend                 # which backend, and whether it answers now (exits 1 if not)
   botctl secrets                         # each name, where it comes from, what it shadows
   botctl audit 50 --action 'secret.*'
   botctl audit 20 --action bot.run_refused
   ```

   botd's log has the store's own reason for each failure (`Vault answered 503 ...`, `AppRole login at auth/approle answered 400 ...`, a JWT that expired); the audit log has only codes. A support bundle has the week's `secret.*` failures in `audit-summary.json`, and [bundle triage](triage.md) lists them as `audit.secrets`, with runs refused `secrets_unavailable` under `audit.run_limits` pointing here.
2. **Who's affected.** Every Bot (botd's sign-in or the store itself), one user's Bots (their folder, with `SECRETS_USER_FOLDERS=1`, or their own per-run role or app), or only Bots given short-lived credentials for each run (`VAULT_RUN_CREDENTIALS`, `AWS_RUN_CREDENTIALS`, `GCP_RUN_CREDENTIALS`, `AZURE_RUN_CREDENTIALS`).
3. **Did anything change?** The store's address, network or firewall; botd's token, AppRole secret, certificate, managed identity, service account or IAM role; the store's policy or a secret disabled; Vault sealed, upgraded or failed over; a cloud outage; `SECRETS_*` or `VAULT_*` settings; an upgrade of botd.

## Runs refused

`bot.run_refused` with reason `secrets_unavailable`: the Bot says the secret store can't be read, and the run doesn't start. Cached answers stand for `SECRETS_CACHE_SECONDS` (300 by default); after that every run that needs a name it can't read is refused, and so is a run whose short-lived credentials couldn't be made. botd never falls back to an older value or the sealed store's copy.

1. `botctl secrets backend`. If it says the store doesn't answer, the cause is the store or botd's sign-in: the next two sections.
2. If it answers, the refusal is narrower: a name in one user's folder, or a per-run credential. The `secret.read` and `secret.lease_issued` failures around the refusal's time name the folder or path, and their `error` the kind (below).
3. Runs work again as soon as the store answers; nothing needs a restart. To have new runs read now rather than when the cache runs out, `botctl secrets refresh`.

## Reading and signing in

| What botd records | Usually | Fix |
|---|---|---|
| `secret.read` failure, `op` `read` or `list` | The store didn't answer, refused botd, or answered with an error, for one name or a folder's list | The `error` (below) and botd's log line say which. A disabled secret, or a disabled latest version on Google, is an error, not "not there": enable it or delete it ([day to day](../ops/cloud-secrets.md#day-to-day)) |
| `secret.vault_login` failure | Vault refused botd's sign-in: an AppRole secret id used up or expired, a Kubernetes or JWT token Vault's role doesn't bind, a cloud identity the role doesn't name, an `ec2` nonce Vault holds for another instance | The `method`, `role` and namespace are in the event. Fix the role or the credential ([Vault](../ops/vault.md#set-up-botd), [Kubernetes and JWT](../ops/vault.md#kubernetes-and-jwt-sign-in), [cloud sign-in](../ops/vault.md#cloud-sign-in-aws-google-cloud-azure)) |
| `secret.backend_login` failure | botd couldn't get its own cloud identity's token: the metadata server, a managed identity not assigned, an expired client secret or certificate, web identity's token file | The `method` says which. `botctl secrets backend` tries again now ([check it](../ops/cloud-secrets.md#check-it)) |
| `secret.cache_refreshed` failure | A refresh couldn't read a name, or botd needs a restart for a startup setting whose value changed | `botctl secrets refresh` lists each name's result. After a leak, a name that couldn't be read stays uncached and refused, never the old value; restart botd for the names it flags ([rotating a value now](../ops/vault.md#rotating-a-value-now)) |
| `secret.vault_events` failure, `state` `lost` | Vault's change event stream dropped: a proxy that doesn't pass WebSocket upgrades or closes idle connections, a token that changed, a standby | botd subscribes again by itself and reads everything cached once it's back (`resumed`). Meanwhile the cache time bounds how old an answer gets ([following change events](../ops/vault.md#following-vaults-change-events)) |
| `secret.gcp_events` failure, `state` `lost` | Pulls from the Pub/Sub subscription for Secret Manager's change events failed: the subscription deleted, botd's `roles/pubsub.subscriber` removed, Pub/Sub out of reach | botd pulls again by itself and reads everything cached once a pull works (`resumed`). Meanwhile the cache time bounds how old an answer gets ([following change events](../ops/cloud-secrets.md#following-secret-managers-change-events)) |
| `secret.read_events_dropped` | More than 10,000 read events waited to be audited, and the oldest were dropped | Reads went on; some aren't in the audit log, which matters for the customer's evidence. A database that can't keep up: `botd support check`, and a longer `SECRETS_CACHE_SECONDS` |

The `error` on these events is a kind, never the store's words:

| `error` | Means |
|---|---|
| `unavailable` | The store didn't answer, refused botd, or answered with something botd won't use. Almost every external store failure; botd's log has the store's reason |
| `invalid` | Rare here: a value or name botd's own rules refuse, such as a reserved name, or a value over 64 KiB or with a NUL |
| `store error` | Rare here: what the store holds can't be read as a value, such as one that isn't text |
| `read-only` | Rare here: something tried to write to the external store, which botd only reads. Saving a key in the app goes to the sealed store instead |

## Short-lived credentials for each run

Each run's leases, STS sessions or tokens are made as it starts (`secret.lease_issued`), renewed while it lasts (`secret.lease_renewed`, Vault only) and revoked (`secret.lease_revoked`) or, where the cloud can't revoke, released with their expiry (`secret.lease_released`) when it ends. A failure to make one refuses the run; a renewal that fails stops the run when its lease ends.

| `error` | On | Usually | Fix |
|---|---|---|---|
| `unavailable` | `secret.lease_issued`, `secret.lease_renewed`, `secret.lease_revoked` | The issuer refused or didn't answer: a role or policy that doesn't allow it (`AccessDenied`, `sts:TagSession`, Token Creator, a federated credential), a session longer than the role allows | botd's log names the role, API or policy to check. Per backend: [Vault](../ops/vault.md#short-lived-credentials-for-each-run), [AWS](../ops/cloud-secrets.md#short-lived-aws-credentials-for-each-run), [GCP](../ops/cloud-secrets.md#short-lived-gcp-credentials-for-each-run), [Azure](../ops/cloud-secrets.md#short-lived-azure-credentials-for-each-run) |
| `narrowing` | `secret.lease_issued` | The run's ids can't stand in the entry's session policy or boundary, or it grew past STS's size with them | Shorten the policy ([narrowing](../ops/cloud-secrets.md#narrowing-each-runs-session), [downscoping](../ops/cloud-secrets.md#downscoping-each-runs-gcp-token)) |
| `apps` | `secret.lease_issued` | The `apps=` file mapping users to their own Entra apps can't be read or doesn't check | Fix the file; it's read again at each run, so no restart ([each user's own app](../ops/cloud-secrets.md#another-tenant-or-each-users-own-app)) |
| `missing_fields` | `secret.lease_issued` | The lease came back without a field the entry names | The role's output: name the fields it gives |
| `expired` | `secret.lease_renewed` | The lease ran out before botd could renew it: the issuer was down too long | The run stopped. Raise the role's TTL, or look at why the issuer was unreachable |
| `refused` | `secret.lease_renewed` | Vault wouldn't renew: the lease was revoked, or the policy lacks `sys/leases/renew` | The run stops when the lease ends ([renewing leases](../ops/vault.md#renewing-leases-for-long-runs)) |

A renewal that succeeds with `final` set means Vault gave less than asked (the role's `max_ttl`): the run will stop when the lease ends. Raise `max_ttl` over `RUN_TIMEOUT_MINUTES`.

## Before telling the customer it's fixed

1. `botctl secrets backend` answers, and `botctl secrets` lists the names the customer's Bots need, from the store expected.
2. A Bot that was refused runs, and `botctl audit 20 --action bot.run_refused` has no new `secrets_unavailable`.
3. If a value was rotated because of a leak, `botctl secrets refresh <NAME>` says `changed` (or `unchanged` when botd already had it), and the old value is revoked at its provider: running Bots keep the environment they started with.

## Escalate when

- `botctl secrets backend` answers but runs are still refused `secrets_unavailable`.
- A new run gets a value the store no longer holds after a refresh said `changed`.
- A lease or token is still valid after its run ended and botd recorded it revoked.
- The store's own audit device shows reads botd's audit log doesn't, beyond a recorded `secret.read_events_dropped`.

## Afterwards

Note the cause in the ticket. If botd's credential to the store rotated or will expire (an AppRole secret id, a client secret, a certificate), put who holds it and when it ends in the customer's onboarding record. If runs were refused for long, suggest a longer `SECRETS_CACHE_SECONDS` (rotations then need `botctl secrets refresh`), or Vault's change events. If the customer's agreement promises Bots keep running through a store outage, that's a conversation for their TAM, since botd fails closed by design.
