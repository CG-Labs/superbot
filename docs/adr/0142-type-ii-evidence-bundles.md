# 0142: Type II evidence bundles, made by botd and written monthly

## Status

Accepted (22 Nov 2026). Second slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Builds the first item [ADR 0130](0130-policy-set-and-type-ii-evidence.md) deferred: automating the monthly collection in its [evidence plan](../security/soc2-evidence-plan.md). Reads the audit log ([ADR 0009](0009-audit-events.md), [ADR 0019](0019-audit-actors.md)), the access-review report ([ADR 0099](0099-access-review-report.md)), server backups ([ADR 0109](0109-server-backups-off-the-host.md)) and the retention settings ([ADR 0098](0098-chat-retention.md), [ADR 0112](0112-harness-session-and-teammate-files-retention.md)) through their existing interfaces, and redacts as the support bundle does ([ADR 0131](0131-support-bundle.md)).

Numbered 0142 because 0136 to 0141 are held by work in flight.

## Context

A Type II auditor samples evidence from the whole observation period, and evidence not kept at the time can't be made later. The evidence plan's monthly calendar asked the operator to run `botctl audit export`, the access-review export and several state commands by hand, each month, without missing one. Three things shape an automated version:

- **The evidence must not become a second copy of customer data.** Audit exports carry emails, names, IP addresses and free-text reasons (a tool's input, an admin's note). An evidence store is read by more people than the server, and kept longer.
- **It must be checkable.** An auditor needs to know a file wasn't edited after it was collected, and that a month wasn't left out.
- **Rust first, no new dependencies, no new schema.** botd already holds the data. The audit log's schema and events are being changed by other work (SIEM export, [#56](https://github.com/CG-Labs/superbot/issues/56)), so this reads it with the existing filter and adds only new event names.

## Decision

### One bundle per period, made by botd

`GET /api/evidence/bundle?from=<YYYY-MM-DD>&to=<YYYY-MM-DD>` answers an admin with a tar of one folder, `superbot-evidence-<from>_<to>-<UTC time>/`, in the support bundle's ustar writer. The period is whole UTC days, `from` included and `to` not; with neither, the calendar month before today. At most 400 days, ending no later than tomorrow. It isn't in the RBAC table, so it is admin-only by default: members, read-only users, Bots and every custom role get 403 ([ADR 0123](0123-custom-roles.md)). `GET /api/evidence` shows the schedule, the folder, the bundles in it and the newest made.

`botctl evidence bundle [--from <date> --to <date>] [-o <file>]` saves it, private and never over an existing file, and prints its manifest's digest and how to check it. `botctl evidence` shows the schedule.

| File | Contents | Criteria |
|---|---|---|
| `access-review.json` | A snapshot of the access-review report: per person their id, role and custom role's permissions, status, admin, break-glass, SCIM tenant, team and team role, second factor and when it was set up, last sign-in time and method, how many Bots, browser sessions and API tokens, and machine; the report's digest and summary; the MFA policy; the period's account, role, session, SCIM, team, sign-up and `access_review.*` events, with sign-offs' digests | CC1.3, CC6.1, CC6.2, CC6.3 |
| `changes.json` | Every `server.started` in the period with its version, the version at the period's start and each change of version; policy, encryption, egress, license and tier changes; machine agent upgrades | CC5.1, CC5.2, CC8.1 |
| `backups.json` | Server backups now (off host or not, store, RPO, retention, the newest archive and copy, past the RPO), backup encryption per target, database encryption, open machine RPO breaches; every server copy, machine backup, RPO breach and recovery, and restore in the period, by day | A1.2, A1.3, CC6.7, CC7.5, CC9.1 |
| `retention.json` | Each retention setting, each deletion pass's last counts, the legal holds (Bot, who, when; never the reason), whether audit retention keeps the period plus a year; every pruning pass, hold, erasure and deletion in the period | C1.2, CC6.5 |
| `sign-ins-and-alerts.json` | Every sign-in, failure, second factor, `auth.suspicious_sign_in` and alert sent or failed, status incident, host and panic event, counted by action and outcome, by day, and listed | CC6.1, CC6.6, CC7.2 |
| `audit-summary.json` | Every event in the period counted by action and outcome, the first and last ids, and a digest | CC2.1, CC4.1, CC7.2 |
| `manifest.json` | Format, botd's version, the period, when it was made, and each file's size, SHA-256, criteria and checklist rows | |
| `SHA256SUMS` | Every other file's digest, for `sha256sum -c` | |

The evidence plan's [bundle table](../security/soc2-evidence-plan.md#the-evidence-bundle) gives each file's checklist rows; a unit test checks the code's mapping against it, the control mapping and the checklist. `FORMAT` (1) is bumped when a file's shape changes.

Snapshots are of the moment the bundle is made, which is after the period; the README and each file say so. A Type II report wants the state during the period too, which is why the schedule makes them on the 1st.

### What leaves the audit log

Events are read a page at a time, oldest first, with the existing `audit::Filter`, and each is shown as: id, time, action, outcome; the actor's kind, id, role, sign-in method and IdP; the target's type and id; the Bot's id; and its details reduced to what can't be free text: numbers, booleans, a reason only as a code (the support bundle's `reason_code`), versions in version fields, codes (`admin`, `sso`, `burst_ip`) in a short list of fields such as `from`, `to`, `method`, `pattern` and `digest`, and nested objects of numbers and booleans (an access review's summary). Names, emails, IP addresses, user agents, notes, paths and messages never leave. Ids are opaque (`u1a2b3c4`); the access-review CSV, kept in the evidence store beside the bundle, says who they are.

Every string then goes through the support bundle's redaction (known secret values, credential shapes, URL paths, emails, IP addresses) and botd's own. Up to 5,000 events are listed per file; all are counted.

### Checkable

- The manifest lists each file's SHA-256, `SHA256SUMS` repeats them, and the audit log records every bundle as `evidence.bundle_created` with its name, period, size, the tar's SHA-256 and the manifest's. A file changed later no longer matches the audit log, which is itself in the server's backups.
- `audit-summary.json`'s digest is SHA-256 over one line per event, oldest first: `id`, unix ms, action and outcome, tab-separated, each ending in a newline. Erasure ([ADR 0102](0102-erasing-a-users-data.md)) rewrites actors, not these fields, so a bundle made again for the same period gives the same digest unless events were added or deleted; audit retention deleting events is the expected exception.

### Monthly, with retention

With `EVIDENCE_BUNDLES=monthly` (off by default), botd checks every hour, from a minute after start, that `EVIDENCE_DIR` (default `DATA_DIR/evidence`) holds a bundle for last month, and writes one if not: folder mode 0700, file 0600, written to a hidden partial file and renamed. It is audited as `evidence.bundle_created` by the system actor `evidence`; a failure to write is logged every hour and audited once per period as `evidence.bundle_failed`. Bundles whose period ended more than `EVIDENCE_RETENTION_DAYS` ago (default 760: a 12-month period plus a year, and a month's grace; 0 keeps them forever) are deleted, audited as `evidence.bundles_pruned` with their names. Files that aren't bundles are left alone.

Inside botd rather than a systemd timer and a script: it needs no credentials (an operator command would need a token or the password, which `AUTH_MFA` refuses over HTTP Basic), works the same under Compose, and the default folder is in `DATA_DIR`, so the server backups copy it off the host ([ADR 0109](0109-server-backups-off-the-host.md)). The operator still copies bundles to the evidence store the security owner runs.

## Alternatives considered

- **A systemd timer and Compose job running `botctl`**: the usual shape here (server backups), but needs a long-lived operator credential on disk, breaks under required MFA, and is two schedules to keep in step.
- **Exporting the raw audit log monthly** (the plan's existing calendar step): complete, and still allowed, but carries personal data and free text into a store kept longer than the server's own retention.
- **A hash chain in the audit log**: real tamper evidence for the log itself (CC7.2-2), but changes its schema, which the SIEM work is changing now. The bundle's digests are recorded in the log instead, and the chain is left to that work.
- **Uploading bundles to the evidence store**: needs credentials and a choice of store on every server; the off-host server backups already carry them, and the provider picks the store.

## Tests

- `evidence::tests`: periods (last month by default, both dates or neither, order, length, not in the future), names that say their period, action matching, details keeping codes and counts and never names, emails, notes, paths or nested text, settings and their errors, and each file's criteria and rows existing in the control mapping and checklist and matching the evidence plan's table.
- `evidence_http_tests.rs`, on the real router: members, read-only users, a custom role with every delegable permission and Bots get 403 on both routes, nobody gets 401; an admin gets a tar any `tar` reads, with every file, `SHA256SUMS` and manifest digests that match, audited once with the tar's and manifest's digests, matching the response header; each file carries its evidence (people with roles, admin and second factor, a sign-off's digest without its notes, version changes, a backup copy and a restore by day, a pruning pass, a failed and a suspicious sign-in) and the audit digest is reproducible from the log; a secret, a name, an email and its domain, a chat, a hold's reason, an IP address, a review's note and a Bot's name appear nowhere; bad periods are 400 and make nothing; the schedule writes last month once, private, prunes only bundles past retention, and audits both; a folder it can't write is audited once, not every hour.
- `auth_review_http_tests.rs` checks the routes refuse callers without credentials and are admin-only; `botctl` tests check `evidence bundle`'s options.

## Consequences

- No checklist row moves to **Done**: the bundle collects evidence of controls, it isn't one. Rows whose evidence it now collects say so, with what is still manual ([checklist](../security/soc2-readiness-checklist.md)).
- botd doesn't know the commit it was built from, only its version; the commit of each release comes from the image's revision label and the merged pull requests the plan still exports from GitHub.
- CI runs, merged pull requests, branch protection, alert history from Alertmanager and everything outside SuperBot stay on the plan's manual calendar.
- Bundles made on request and on the schedule are kept by whoever saves them; only the schedule's folder has retention.

## Deferred

- Exporting CI runs and merged pull requests from GitHub on the same schedule (needs a GitHub token on the server, or a workflow of its own).
- Recording the build's commit in `server.started`, so `changes.json` shows commits as well as versions.
- A tamper-evident audit log and SIEM export ([#56](https://github.com/CG-Labs/superbot/issues/56)).
- A console button for the bundle.
