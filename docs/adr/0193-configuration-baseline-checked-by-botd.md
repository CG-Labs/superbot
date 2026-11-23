# 0193: botd checks itself against the configuration baseline

## Status

Accepted (23 Nov 2026). Seventh slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Automates the check the [configuration baseline](../security/configuration-baseline.md) asks for (checklist row CC5.1-1), and adds a sixth file to the evidence bundle ([ADR 0142](0142-type-ii-evidence-bundles.md)), its format 3, with the coverage report ([ADR 0169](0169-evidence-coverage-report.md)) taught that older bundles don't have it.

## Context

CC5.1 asks for control activities chosen to reduce risk, and for the managed service that is a hardened configuration: many protections are off by default so a first install works anywhere, and the [configuration baseline](../security/configuration-baseline.md) says which the managed service turns on. The information security policy requires each server checked against it quarterly and after every upgrade and production change. Until now that check was by hand: run six `botctl` commands, save the server's settings with secrets removed, and compare both with a table of 23 rows. It was the "Left:" of CC5.1-1 and on #57's remaining list.

A hand check every quarter leaves the months between unsampled, and an auditor sampling the observation period wants to see the configuration held on the days they pick, not that someone looked four times. botd already knows most of the answers: it parsed every setting at startup, and the rest (MFA policy, retention) is in its database.

## Decision

### A rule per row

`server/src/config_baseline.rs` holds one rule per setting in the baseline's table, in its order, each with the table's baseline text. A unit test parses the table and requires the same settings and baseline text in the same order, so a row added to the document fails CI until botd can judge it, and a rule can't drift from the text an auditor reads. A new row, `CONFIG_BASELINE` itself, makes the check part of the baseline.

Each rule judges plain facts and returns one of five results with what it observed:

- **pass** or **fail**.
- **exception**: failing, but named in `CONFIG_BASELINE_EXCEPTIONS`, the place an exception approved under the information security policy is recorded. A listed setting that no longer fails is reported, so the exception is removed; a name not in the table stops botd at startup.
- **manual**: botd can't tell. The image's signature (botd sees only its own version), whether `TEAMS` is needed (whether more than one customer shares the server), and whether retention days match contracts.
- **not applicable**: the machine rules without the control plane or enrolled machines; isolation when every Bot runs on users' machines; outbound rules without the firewall.

Facts come from what botd parsed at startup (kept on `App` because some values, like `AUTH_MFA`'s pin or the metrics token's presence, aren't kept elsewhere) and from the database at the time of the check (the MFA policy an admin set), so a check later in the month sees later changes. Retention days are judged as parsed, not as the database holds them: the retention jobs write them there only after the check at start, so reading the database would refuse a server whose retention was just fixed, and pass one whose retention was just shortened. Two judgements are stricter than "the setting is set": `AUTH_MFA` passes only when pinned by the environment, since a policy set in the app can be turned off by any admin; `AUDIT_RETENTION_DAYS` passes when empty or at least 730 days, the longest common observation period plus the year after it.

### When it runs

- `CONFIG_BASELINE=on` checks at every start, which follows every upgrade and every change of settings (both need a restart). botd logs one line and a warning per failing setting, and audits `server.baseline_checked`.
- `required` also refuses to start while a setting fails (after auditing the refusal), for operators who'd rather a server stay down than run outside the baseline. A failing setting can be waived only by naming it as an exception.
- `off` (the default) checks nothing at start: a first self-hosted install fails eight rules, and warning about each on every start would be noise for people who never asked for this baseline.
- `GET /api/baseline` (`botctl baseline`) checks on request, whatever the setting, audited the same way with source `request`. Admins only, like every route rbac doesn't list. `botctl baseline` exits 1 while a setting fails, so a cron job or CI step notices, as `botctl audit verify` does.

The audit event holds the source, mode, outcome (`failure` when a setting fails), counts, the failing, waived and unused-exception setting names, the version and a SHA-256 over each check's setting, result and observed value. Observed values aren't in the audit log: the digest says whether two checks found the same server, and the report says what it found. Observed values are from a fixed vocabulary (`on`, `required`, `730 days`, `2 recipients`), never a value an operator typed, a secret, a path or a host.

### In the evidence bundle

The bundle gains `baseline.json`: the check as of the bundle's making, without auditing it, and every `server.baseline_checked` in the period, each reduced to known setting names, codes, counts and a well-formed digest, whatever the event's details say. It maps to CC5.1 and CC7.1 (configuration monitoring) and row CC5.1-1. The bundle's format goes from 2 to 3.

The coverage report knows each expected file's first format: a format-2 bundle without `baseline.json` still checks, and a format-3 one without it fails, so the store's existing months aren't broken by the new file.

## Alternatives considered

- **A script that diffs a settings file against the table**: no botd change, but it sees the file, not what botd made of it (defaults, the database's MFA policy and retention, settings that failed to parse), and needs the secrets removed by hand.
- **Refuse to start whenever a protection is off**: breaks every first install and self-hosting customers who chose otherwise; `required` makes it opt-in for the managed service.
- **Check on a schedule as well**: settings change only at restart, and the database-held ones (MFA policy, retention) are already audited when changed and listed in the bundle; a daily event would add volume, not evidence.
- **Put observed values in the audit event**: more to read in the log, but observed values could grow to include something sensitive later; the digest ties the event to a report.
- **Machine-readable baseline (TOML) instead of Markdown**: one source for code and doc, but auditors and the policies link the Markdown; the test keeps the two in step instead.

## Tests

- Unit tests in `config_baseline.rs`: a server set up as the baseline says passes all but the four manual rows; a fresh self-hosted server fails the eight protections off by default, with the machine rules not applicable; each rule fails on its own setting alone; exceptions waive and unused ones are reported; the digest depends on the settings and not the time; `CONFIG_BASELINE` parsing and unknown exception names refused; an audit event's forged names and codes don't reach the bundle; and every row of the document's table has a rule with its baseline text, in order.
- `config_baseline_http_tests.rs`: only admins get `/api/baseline` (member, read-only, a custom role with every delegable permission, a Bot and no one are refused, and nothing is audited); the report has every rule in order and its counts add up; the audit event has the request's source, digest and failing settings and no observed values. At startup, `on` audits a check whose digest a later check repeats, `off` audits nothing, and `required` refuses with the failing settings named, audits the refusal, and starts when exceptions waive them. The evidence bundle's `baseline.json` holds the check now and each in the period, with forged names, emails and addresses left out, and the manifest maps it.
- `evidence_http_tests.rs` lists the new file; `coverage.rs` checks a format-2 bundle without it passes and a format-3 one fails; `auth_review_http_tests.rs` keeps the route admin-only.

## Consequences

- CC5.1-1 stays Partial: the baseline is a draft until approved, managed servers need `CONFIG_BASELINE` on, and the manual rows still need a person each quarter. The quarterly check is now `botctl baseline` plus those rows.
- A row added to the baseline needs a rule in the same pull request; a protection that ships off by default and is added to the baseline gets checked from then on.
- Upgrading a server with `required` set to a version whose baseline gained a row it fails stops it until the setting is fixed or excepted. That is the intent; the release notes should name new rows.
- Evidence bundles are format 3; tools reading them should ignore files they don't know.

## Deferred

- Checking the settings of machines' agents directly (botd judges what it tells them to apply; each machine's `machine.hardened` event says what it did).
- Checking the image's signature from inside botd.
- An admin console view of the report.
