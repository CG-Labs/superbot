# 0322: Runbooks for the secrets store and the audit trail

## Status

Accepted (26 Nov 2026). Twentieth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after runbooks for SCIM, backups and the license ([ADR 0313](0313-runbooks-for-scim-backups-and-the-license.md)).

Numbering: this number was reserved for this work.

## Context

Bundle triage (ADR 0220) groups the bundle's audit failures by the runbook they point at. Since ADR 0313 every group but `audit.other` had one. Two areas Enterprise customers buy on fell into `audit.other`, with nothing to read:

- **The external secrets store** (`SECRETS_BACKEND`: Vault, Azure Key Vault, GCP Secret Manager, AWS Secrets Manager; [ADR 0125](0125-external-secrets-backend-vault.md) onwards). botd fails closed, so when the store can't be read Bot runs are refused `secrets_unavailable`, which triage counted under run limits and pointed at the run limits runbook, where it isn't. Its sign-ins, reads and per-run leases record a dozen `secret.*` actions with an `error` kind each.
- **The audit trail**: the SIEM export and write-once archive ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md) onwards), the daily check of the hash chain (`audit.verified`), and checkpoint timestamps ([ADR 0149](0149-signed-and-timestamped-audit-checkpoints.md)). Its failures are quiet, since Bots carry on, but they are what auditors rely on, and a failed chain check can mean someone changed the log. Triage listed a failed check as one more `audit.other` line, with no warning. A stopped sink (`audit.export_stopped`, [ADR 0264](0264-audit-export-starts-and-stops-on-the-chain.md)) is recorded as a success, so the summary's failure counts skipped it entirely.

The audit export guide said "alert on `superbot_audit_export_failing == 1`" and gave a `delta()` for stopped sinks, but no rules shipped, unlike backups, encryption, capacity and the health score. And `superbot_events_total` only gets a series for an event once it happens, so `increase()` can't see the first failed chain check after a restart.

Constraints: Rust first, no new dependencies, nothing that changes what botd records or sends, and no edits to the Vault, SAML, RBAC or residency code other M5 tracks are changing.

## Decision

### Two runbooks in the shape of the others

- [`runbook-secrets.md`](../support/runbook-secrets.md): runs refused; every `secret.*` action botd records for reads and sign-ins, with every `error` kind (`secrets::Error::kind` and the lease code's own); per-run credentials and their leases. Severity 1 when runs are refused for everyone, 2 for many or a rotation after a leak that didn't land, 3 for one user or one entry.
- [`runbook-audit-trail.md`](../support/runbook-audit-trail.md): the export failing (each reason the sinks record), a sink stopped, the chain check failed (each reason, with the checkpoint's and timestamp's), timestamps failing. Severity 3 for export and timestamps, since events wait in botd's database; 2 for a failed chain check until it's explained; 1 when it isn't, which is a suspected security incident. It says not to restart or restore before taking a copy with `botd database backup`, since that's the evidence: SQLite's online backup holds what's still in the WAL, which copying `app.sqlite` by itself while botd runs can miss.

Both link the setup guides for detail rather than repeat them.

### Triage points at them

- Two audit groups: `audit.secrets` (`secret.*`) and `audit.audit_trail` (`audit.*`), each naming its runbook.
- `audit.export_stopped` counts in its group though it's recorded as a success: the SIEM gets nothing from then on.
- `audit.audit_trail` is always a warning, not only at 10. A failed `audit.verified` suggests Severity 2 (so `botctl support-triage` exits 1) and adds the chain section with "take a copy with `botd database backup` first" as its next step.
- Runs refused `secrets_unavailable` add the secrets runbook's runs refused section to `audit.run_limits`.

### Prometheus rules for the audit trail

[`superbot-audit-trail.rules.yml`](../../deploy/prometheus/superbot-audit-trail.rules.yml), tested with promtool in CI: a sink failing for 15 minutes, a sink stopped in the last hour, timestamps failing for an hour (tickets), and a failed chain check in the last day (a page). Each links its runbook section. botd now writes `superbot_events_total{event="audit.verified",outcome="failure"} 0` and `{event="audit.export_stopped",outcome="success"} 0` from start, like `machine.placement_failed`, so the first of each is an increase.

A stopped sink is alerted on by its event, not by `superbot_audit_export_stopped_sinks` rising, which the audit export guide suggested: swapping back to a sink stopped before while taking out the current one leaves the number the same, though a sink just stopped. The stop is recorded as botd starts, so the counter goes from the old process's value to 1, which Prometheus counts as an increase either way. The gauge rising is kept with `or`, for a Prometheus that never scraped the counter before the stop. The guide now points at the rule.

## Alternatives

- **One runbook for both.** They fail for different reasons, are owned by different people (the platform team for the store, security for the audit trail), and have different worst cases (Bots stopped against a log that may be changed).
- **Rules for the secrets store too.** botd has no store gauge; the store being down shows as refused runs, which the error and health score rules already watch. A gauge would mean changing the Vault code another track is changing.
- **A rule for an export falling behind.** The S3 archive batches up to a day, so any threshold is wrong for one sink kind or another; `superbot_audit_export_failing` already says when delivery fails.
- **Reason codes in the bundle's problem list for secrets.** The `error` text can carry a path or a host; the bundle has none, and `error` kinds are enough to pick a row.
- **Health check items for the export and the store.** Worth doing, but the health check code is shared with tracks in flight; left for a later slice.

## Tests

`support_docs`: the audit trail runbook explains every reason each sink, the chain check (with its checkpoint and timestamp reasons) and the timestamp code records, and both stop reasons, each in its section; the secrets runbook names every `secret.*` action in `secrets/` and every `error` kind, and runs refused `secrets_unavailable`; triage, the ops guides and the index point at both; every alert links a heading that exists. `audit_checkpoint_http_tests`: with a sink and a TSA set, the rules use only metrics `/metrics` writes, and the chain check's failure count starts at 0. `obs::metrics`: alerted failures start at 0. `support_triage`: secrets and audit trail failures form their groups, a stopped sink counts, a failed chain check suggests 2 with the chain section, and `secrets_unavailable` opens the runs refused section. promtool: each alert fires and stays quiet when it should.
