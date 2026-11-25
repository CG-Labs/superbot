# 0285: Product access controls in the evidence bundle

## Status

Accepted (25 Nov 2026). Seventeenth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Closes three readiness checklist rows that still said Gap after the product shipped them: CC6.1-4 (an external secret vault), CC6.3-3 (custom roles and service accounts) and CC6.8-2 (egress allow-lists for runs). Adds `egress.json` and `secrets.json` to botd's monthly evidence bundle ([ADR 0142](0142-type-ii-evidence-bundles.md)) and custom role definitions to `access-review.json`, bumping the bundle's format to 4.

## Context

The [readiness checklist](../security/soc2-readiness-checklist.md) is meant to track the code on `main`. Three of its CC6 rows were written in M4 as "Planned for M5" and never moved, though M5 delivered them:

- External secrets managers: HashiCorp Vault and OpenBao ([ADR 0125](0125-external-secrets-backend-vault.md)), Azure Key Vault and Google Secret Manager ([ADR 0136](0136-cloud-secret-managers.md)), AWS Secrets Manager ([ADR 0146](0146-aws-secrets-manager.md)), workload sign-in ([ADR 0159](0159-vault-kubernetes-and-jwt-sign-in.md)), users' secrets there ([ADR 0174](0174-users-secrets-in-the-external-store.md)) and short-lived run credentials ([ADR 0185](0185-short-lived-credentials-per-run.md)).
- Custom roles ([ADR 0123](0123-custom-roles.md)) and service accounts ([ADR 0143](0143-service-accounts.md)), finished in [ADR 0272](0272-advanced-rbac-delivered.md).
- Machine egress allow-lists ([ADR 0135](0135-run-limits-and-egress-allow-lists.md)), which botd waits for each machine to load before it runs anything there.

Marking them Done is a docs change. A Type II audit asks more: that each control operated through the observation period. Two of the three are settings an operator can turn off at any time (the allow-list's mode, `SECRETS_BACKEND`), so "the code exists" says nothing about a month. The monthly bundle already showed most CC6 controls holding; it showed none of these.

## Decision

### Done on the code, evidence in the bundle

The three rows go to Done with links to their ADRs, code and tests, as every other product row does. The bundle carries the evidence for each month, and, as with `audit-integrity.json` ([ADR 0261](0261-audit-integrity-evidence.md)), names a row in its manifest only for a month the period shows the control held, so the coverage report shows a lapse as a gap rather than as covered.

### `egress.json`: was every run held to an allow-list?

CC6.8-2 is named only when all of these hold:

- machines are on and at least one enrolled machine is running when the bundle is made;
- the server's policy was `allow_list` for the whole period. Its modes come from `server.egress_policy_changed` events: the mode at the period's start is the `from` of the first change at or after it, or the mode now if there was none;
- no user with a machine had their own policy set to `open` at any point in the period, from `user.egress_policy_changed`;
- no running machine's effective policy is open now;
- the change events were read whole (capped at 10,000).

A machine that hasn't loaded its current list yet doesn't stop the row: botd refuses its runs until it has (fail closed, ADR 0135), so no run escaped. It is still listed (`notInPlace`), as is every failed load (`machine.egress_policy_failed`, by event id).

The file holds the server's mode, how many entries, and the policy id (a digest of the list); each running machine's policy and what its agent last reported loading (state, address count, how many hosts didn't resolve); and counts of the period's changes, loads and failures. It never holds a host, range or address from a list: those describe the customer's network and suppliers, and an auditor needs only to know a list was enforced. The id lets anyone with server access match a month to the list in force.

### `secrets.json`: did every start read from an external manager?

`SECRETS_BACKEND` is read once, at start. So botd now records the backend kind in each `server.started` event (`vaultBackend`: `local`, `vault`, `azure-keyvault`, `gcp-secret-manager` or `aws`). The detail is not called `secretsBackend` because the audit log redacts any detail key that says "secret".

CC6.1-4 is named only when every start in force during the period used an external manager: the last start before the period and each start in it. A start recorded before this change has no backend and counts as `unknown`, so the first month after upgrading doesn't name the row. That is the honest answer: botd didn't record it then. Likewise, with no start before the period on record (a new server, or audit retention pruned it), whatever ran until the period's first start is `unknown`, and a period with more than 10,000 starts, past what the file reads, names nothing.

The file holds the backend now (kind, cache time, whether users' secrets live there, how many run-credential paths, read without calling the manager), each start in force with its backend, counts of reads, sign-ins and leases with failures, and the ids of any `secret.read_events_dropped` events. It never holds an address, path, role or secret name.

### Custom roles in `access-review.json`

CC6.3-3 is about the product's capability, which needs no condition. `access-review.json` already listed who holds which custom role; it now also lists each role's definition: id, base role, permissions, longest grant, whether it can be requested, and how many hold it server-wide and per team. Its name and description are left out, as names are elsewhere in the bundle. The manifest names CC6.3-3 for the file.

### Counts, not events

Both new files carry the period's matching events as counts by action, outcome and day, without the event list other files include. The events would copy allow-list hosts and secret names into the bundle; the monthly audit export has them in full.

### Format 4

botd's `FORMAT` goes from 3 to 4 because the bundle gained two files and `access-review.json` changed shape. `superbot-evidence coverage` requires `egress.json` and `secrets.json` from format 4, so older bundles still verify, and counts their exceptions with the rest.

## Consequences

- The CC6 summary moves from 8 Done, 4 Partial and 6 Gap to 11, 4 and 3.
- An operator who wants CC6.8-2 and CC6.1-4 covered each month must run with a server-wide allow-list and an external manager. A managed service that doesn't will show those rows as gaps in its coverage report, which is accurate.
- The first month after upgrading never names CC6.1-4.
- `server.started` gains one field; nothing reads it but the bundle.

## Not done

- Counting per-user allow-lists while the server's policy is open. A server whose users each have their own list holds every run, but proving that would mean replaying each user's policy through the period; the server-wide list is the documented setting for the managed service.
- Machines that stopped during the period. The bundle sees running machines when it is made; a machine destroyed mid-month is covered only by the policy's timeline.
- Checking the agent's firewall rules from botd. The agent's report is what botd trusts for running; the bundle trusts the same.
- Proving which manager a start used beyond botd's own record. The manager's own audit log is the operator's to keep.
