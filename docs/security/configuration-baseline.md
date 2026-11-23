# Configuration baseline for managed servers

The settings every managed SuperBot server runs with, and how to check each one. The [information security policy](policies/information-security.md#configuration-baseline) requires this baseline and a check of each server against it at least quarterly and after every upgrade; the [change management policy](policies/change-management.md#production-changes) checks it after every production change. Part of the [security pack](README.md) and the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57)), checklist row CC5.1-1. **Draft, not adopted. SuperBot is not SOC 2 certified.**

botd checks itself against this table ([ADR 0193](../adr/0193-configuration-baseline-checked-by-botd.md)): `botctl baseline` shows each setting as `pass`, `fail`, `exception` (failing under an approved exception), `manual` (for a person to check: botd can't see an image's signature or a contract) or `not_applicable` (no machines, say), and exits 1 while one fails. A test holds botd's rules to this table, so a row added here needs a rule there.

A self-hosting customer can use it as a starting point for their own. Settings are in the server's `.env` (Compose) or the installer's env file; each is described in [`.env.example`](../../.env.example) or the [install guide](../../deploy/README.md). Many protections are off by default so that a first install works anywhere; the managed service turns them on.

## Settings

| Setting | Baseline | Why | How to check |
|---------|----------|-----|--------------|
| `SUPERBOT_VERSION` | A released, signed version, never a local build | Changes reach production only through releases ([change management](policies/change-management.md#production-changes)) | `cosign verify` on the image ([verifying the images](../../deploy/README.md#verifying-the-images)); `changes.json` in the [evidence bundle](soc2-evidence-plan.md#the-evidence-bundle) lists each version botd started with |
| `AUTH_MFA` | `admins` or `all` | A second factor for every admin (CC6.1-1, [ADR 0094](../adr/0094-totp-second-factor.md)) | The MFA policy in the bundle's `access-review.json`; the setup checklist (`botctl setup`) |
| `AUTH_BREAK_GLASS` | `0` once admins sign in with SSO or sign-in codes | The owner's password is for getting back in, not daily use ([ADR 0012](../adr/0012-users-sessions-rbac.md)) | The settings file |
| `SIGNIN_ALERTS` | `on` (the default) | Suspicious sign-ins are reported and alerted (CC7.2-1, [ADR 0104](../adr/0104-suspicious-sign-in-alerts.md)) | The settings file; `auth.suspicious_sign_in` events in the bundle's `sign-ins-and-alerts.json` |
| `TESTING_MODE` | Unset | Testing mode turns off licensing and billing and is for test servers only | The start-up log and the console say when it is on |
| `SUPERBOT_DATABASE_ENCRYPTION` | `required` | The database is encrypted at rest (C1.1-1, [ADR 0116](../adr/0116-database-encrypted-at-rest.md)) | `botctl database` |
| `SUPERBOT_BACKUP_ENCRYPTION` | `required` | No backup is written plain (CC6.7-2, [ADR 0114](../adr/0114-backups-encrypted-by-default.md)) | `botctl backups` |
| `SERVER_BACKUP_OFF_HOST` | `on`, with a store set | Server backups leave the host, and botd refuses to start without a store (A1.2-1, [ADR 0109](../adr/0109-server-backups-off-the-host.md)) | `botctl backups` |
| `MACHINE_BACKUP_AGE_RECIPIENTS` | Set, with the key kept off the host | Machine backups are encrypted (CC6.7-2) | `botctl backups`; `botctl machine recovery` |
| `ISOLATION` | `users` on a server where Bots run locally | Each user's Bots run as their own Unix account ([ADR 0037](../adr/0037-per-user-unix-accounts.md)) | `botctl user isolation <user>` |
| `TEAMS` | `on` when more than one customer shares a server | Sharing stops at a team ([ADR 0087](../adr/0087-team-accounts-and-machines.md)) | The settings file |
| `MACHINE_HARDENING` | `on` (the default) | Machines are hardened at first boot ([ADR 0126](../adr/0126-per-user-machine-hardening.md)) | `machine.hardened` and `machine.hardening_failed` audit events |
| `MACHINE_RUN_LIMITS` | `on` (the default) | Each run is held to its tier's limits ([ADR 0135](../adr/0135-run-limits-and-egress-allow-lists.md)) | The settings file |
| `MACHINE_BOT_USER` | `on` (the default) | Bots run as an unprivileged user on their machine, so its egress rules bind them ([ADR 0043](../adr/0043-bots-own-os-user-on-machines.md)) | The settings file |
| `MACHINE_TEAMMATE_USERS` | `on` | Teammates' runs can't read the owner's files ([ADR 0048](../adr/0048-teammates-own-os-user-on-machines.md)) | The settings file |
| `MACHINE_FIREWALL` | `on` for Linode machines | Only botd reaches a machine's agent ([ADR 0035](../adr/0035-machine-firewall-auto-enroll.md)) | `machine.firewall_*` audit events |
| `MACHINE_FIREWALL_EGRESS` | `on` (the default with the firewall) | Linode's firewall keeps the whole machine, root included, off private ranges and `MACHINE_EGRESS_DENY` ([ADR 0179](../adr/0179-outbound-rules-at-the-provider.md)) | `outbound` in `machine.firewall_created` and `machine.firewall_updated` |
| `MACHINE_ON_DISABLE` | `suspend` (the default) | A disabled user's machine is powered off ([ADR 0124](../adr/0124-deprovisioning-stops-bots-and-machines.md)) | The settings file |
| `SUPERBOT_CHROMIUM_SANDBOX` | Unset (Chromium's sandbox on) | Browsers stay sandboxed (CC6.8-3, [ADR 0107](../adr/0107-chromium-sandbox-in-the-container.md)) | botd's start-up log line `Chromium sandbox: on` |
| `METRICS_LISTEN` | Off, loopback, or with `METRICS_TOKEN` | Metrics are never public without a token ([ADR 0089](../adr/0089-metrics-and-structured-logs.md)) | The settings file |
| `AUDIT_RETENTION_DAYS` | Empty, or at least the observation period plus a year | Audit events outlive the audit that samples them ([retention](policies/data-classification-and-retention.md#retention)) | `botctl retention`; the bundle's `retention.json` says whether the period plus a year is kept |
| `CHAT_RETENTION_DAYS`, `HARNESS_SESSION_RETENTION_DAYS`, `TEAMMATE_FILES_RETENTION_DAYS` | What the [retention policy](policies/data-classification-and-retention.md#retention) and customers' contracts say | Data isn't kept longer than agreed (C1.2-1) | `botctl retention` |
| `EVIDENCE_BUNDLES` | `monthly` | Each month's evidence is written on the 1st ([ADR 0142](../adr/0142-type-ii-evidence-bundles.md)) | `botctl evidence` |
| `CONFIG_BASELINE` | `on` or `required` | botd checks itself against this table at every start, so after every upgrade and change of settings, and audits it ([ADR 0193](../adr/0193-configuration-baseline-checked-by-botd.md)) | `botctl baseline`; the bundle's `baseline.json` |

botd also refuses to start in some unsafe setups whatever the baseline says: an SSO provider making accounts without an allow-list ([ADR 0103](../adr/0103-sso-jit-needs-an-allow-list.md)), or a model provider over plain HTTP ([ADR 0097](../adr/0097-model-providers-over-https.md)).

## Checking a server

With `CONFIG_BASELINE=on`, botd checks at every start, which follows every upgrade and every change of settings: it logs one line with the result and a warning for each failing setting, and audits the check as `server.baseline_checked` (who, `ok`, counts, the failing and waived settings, and a digest of the result, never an observed value). `required` also refuses to start while a setting fails. `botctl baseline` checks on request, audited the same way. The digest depends only on the settings, so two checks with the same digest found the same server.

An approved exception (under the [information security policy](policies/information-security.md#exceptions)) goes in `CONFIG_BASELINE_EXCEPTIONS`, a comma-separated list of settings from this table: botd reports the setting as `exception` rather than `fail`, and warns when a listed setting no longer fails, so the exception is removed. botd refuses to start on a name that isn't in the table.

Quarterly, the operator:

1. Runs `botctl baseline` and saves the output, and checks each `manual` row by hand: the image's signature, the retention days against the policy and contracts, and whether more than one customer shares the server.
2. Records each `fail` and `exception` with what was done about it: fixed, or the approved exception.

The output, the manual checks and any exceptions go to the evidence store under CC5.1 ([evidence plan](soc2-evidence-plan.md#collection-calendar)). Between checks, the monthly evidence bundle's `baseline.json` holds the server checked as of the bundle's making and every check in its month, and its other files record the MFA policy, backup and database encryption and retention settings, and every change to them.

## Changing the baseline

A change to this page goes through a pull request like any other change ([change management](policies/change-management.md#code-changes)), and the security owner approves it. A new protection that is off by default is added here when it ships.
