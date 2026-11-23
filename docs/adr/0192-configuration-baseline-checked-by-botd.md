# 0192: The configuration baseline checked by botd

## Status

Accepted (23 Nov 2026). Seventh slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Automates "checking servers against the baseline", left open by [ADR 0148](0148-change-management-evidence-from-github.md), which drafted the [configuration baseline](../security/configuration-baseline.md). Adds a file to the evidence bundle ([ADR 0142](0142-type-ii-evidence-bundles.md)) that the coverage report ([ADR 0169](0169-evidence-coverage-report.md)) checks. Serves CC5.1 and checklist row CC5.1-1.

## Context

The draft information security policy has the operator check every managed server against the configuration baseline quarterly and after every upgrade and production change. The baseline's "Checking a server" steps were all manual: run six `botctl` commands, save the settings with secrets removed by hand, compare them with a 25-row table, and write down each difference. That has three problems for a Type II audit:

- **It is error-prone.** Many protections are off by default, several settings interact (`MACHINE_FIREWALL_EGRESS` only means something with the firewall, `MACHINE_TEAMMATE_USERS` needs `MACHINE_BOT_USER`), and some depend on what botd holds at run time, not on `.env` (the MFA policy an admin set, audit retention).
- **Saving the settings by hand risks leaking secrets** into the evidence store, which the plan files as Confidential.
- **Nothing showed that a check happened.** The audit log recorded no check, and the monthly bundle recorded a few of the settings, not the baseline.

## Decision

### botd judges each setting

`server/src/baseline.rs` has a rule for every setting in the baseline's table (`SETTINGS`, in the table's order; a unit test holds the two equal). Each rule reads the value botd runs with, through the same parser botd started with (`mfa::policy`, `database_encryption::Policy::from_env`, `machines::firewall::Settings::from_env` and so on), so the check can't disagree with botd about what a value means. Settings botd changes at run time come from its state: the MFA policy in force, audit, chat, session and teammate-file retention from the database, the evidence schedule and whether a control plane runs machines.

Each setting gets one of five statuses:

- **pass** and **fail**: meets the baseline or doesn't. A value botd couldn't parse fails as `invalid` (botd wouldn't start with it, so this shows only a mismatch between the check and the running server).
- **excepted**: fails, but is listed in `BASELINE_EXCEPTIONS`, for an exception approved under the policy.
- **notApplicable**: the baseline doesn't ask for it here. The machine settings on a server with no control plane; `MACHINE_FIREWALL` on Incus (the baseline asks for it on Linode); `MACHINE_FIREWALL_EGRESS` without the firewall; `ISOLATION` when `MACHINE_ROUTING=on` runs every Bot on a machine; `AUTH_BREAK_GLASS` until an admin besides the owner has signed in.
- **manual**: only a person can judge it, and the value is recorded for them. botd can't verify its own image's signature (`SUPERBOT_VERSION`), can't tell whether more than one customer shares the server (`TEAMS` when off), and can't read a contract (the retention periods).

`AUDIT_RETENTION_DAYS` passes when unset or at least 730 days, a 12-month observation period plus the year the retention policy keeps events after it; the bundle's `retention.json` already judges it against each period.

Values are shown only as codes, day counts or botd's version: `on`, `required`, `admins`, `set`/`unset` for age recipients, and `off`/`loopback`/`token`/`public` for metrics. Never a key, token, address or name, so the output can be saved and filed as it is.

### Where it shows

- `GET /api/evidence/baseline` (admins, beside the other evidence routes) and `botctl evidence baseline [json]`, which prints a line per setting with deviations first and exits non-zero on a deviation, so a cron job or the post-change checklist notices. Each check is audited as `evidence.baseline_checked` with the counts, the names of the settings that fail or are excepted, the number of unknown exceptions and the digest. Settings' values aren't in the event.
- `baseline.json` in every evidence bundle, scheduled or on request, mapped to CC5.1 and CC5.1-1, so each month's bundle records the baseline as botd ran on the 1st. The bundle's format stays 2: it gains a file, and no file's shape changes. The coverage report checks the file like any other when a manifest lists it, never requires it (bundles made before it lack it), and counts its `exceptions` (`deviations`, `excepted`, `unknownExceptions`) beside the change-management, vulnerability and drill bundles' exceptions.

The digest is the SHA-256 of one line per setting, in the baseline's order: setting, status and value, tab-separated. Two checks with the same settings have the same digest whenever they ran, so an auditor can see from the audit log alone whether anything changed between the quarterly checks.

### Exceptions

`BASELINE_EXCEPTIONS` is a comma-separated list of setting names, read when each check runs. It holds names only: the reason, approver and expiry stay in the exception register the policy describes, which is no place for free text in `.env` or the bundle. A name the baseline doesn't have makes the check fail (`unknownExceptions`), since a typo would otherwise hide nothing and say nothing. A listed setting that passes anyway is reported as `unneededExceptions`, so stale exceptions get removed. Manual and not-applicable settings aren't changed by an exception.

## Alternatives considered

- **A script outside botd reading `.env`**: no server change, but it would reimplement every parser and default, miss what botd holds at run time (an admin's MFA policy, retention set in the console), and read secrets from the file.
- **Check only the settings already in the bundle** (MFA, encryption, retention): less code, but most of the baseline (machines, metrics, testing mode, the evidence schedule) would stay manual.
- **Refuse to start when the baseline isn't met**: the baseline is for the managed service, and botd's defaults are chosen so a first self-hosted install works anywhere. botd already refuses the setups that are unsafe for everyone.
- **Exceptions with reasons in `.env`**: one place for everything, but free text in settings and bundles, which ADR 0142 keeps out.
- **Bump the bundle's format**: older readers would warn on every new bundle for an added file they can ignore.

## Tests

- `baseline.rs`: the managed service's settings pass except the four manual ones; a default install fails exactly where protections are off by default, with machine settings not applicable; each rule reads values as botd does (aliases, `_FILE`, invalid values, routing, Incus, firewall egress, metrics on loopback, public and with a token); break-glass and audit retention follow botd's state; exceptions turn a failure into excepted and report unknown and unneeded names; the digest follows settings, not time; no secret, key or address reaches the report or the audit details; the rules match the baseline's table setting for setting.
- `evidence_http_tests.rs`: the route is admins only (members, read-only users, a custom role with every delegable permission, Bots and anonymous callers refused), audited with the response's digest and counts and no values, and follows the MFA policy in force; every bundle has `baseline.json` with each setting, the MFA deviation and its controls in the manifest.
- `coverage.rs`: a botd bundle with `baseline.json` checks and its deviations and exceptions are counted, one without it still checks, and a changed file fails; the evidence plan's table lists the file with its controls.
- `botctl`: the summary prints deviations first, unknown and unneeded exceptions and the digest.

## Consequences

- CC5.1-1 stays Partial: the baseline and its exceptions still need approving, and the check run on each managed server quarterly and after changes. What a person checks by hand is now four settings, not 25.
- A new baseline setting needs a rule in `SETTINGS` and `judge`, or the unit test fails; changing a rule changes the digest, so the first check after an upgrade may differ with no setting changed.
- `baseline.json` names settings and their codes; it holds no secrets, addresses or names, as ADR 0142 requires.

## Deferred

- Showing the check in the console's settings or support tab.
- Checking the host under the server (disk encryption, SSH, OS updates), which botd can't see; that stays manual, and belongs with machine and host hardening ([#54](https://github.com/CG-Labs/superbot/issues/54)).
- Comparing two checks' settings directly, beyond their digests.
