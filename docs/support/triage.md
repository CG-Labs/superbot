# Bundle triage

The support engineer's first read of a customer's [support bundle](support-bundle.md) ([ADR 0220](../adr/0220-support-bundle-triage.md)): what it shows, the [severity](severity.md) that suggests, which runbook to open for each problem, and what to ask the customer that the bundle can't answer. It turns the bundle's files into the ticket's first internal note, so the first response comes sooner and starts from the evidence.

`botctl support-triage` does it. It runs anywhere `botctl` does, on the support engineer's own machine, and needs no botd, no sign-in and no ticket system: it reads the file the customer attached. It reads both bundles: `botctl support-bundle`'s (botd running) and `botd support bundle`'s ([offline](support-check.md#the-offline-bundle), botd down).

## Running it

```sh
# The tar the customer attached, as sent
botctl support-triage superbot-support-20261124T050000Z.tar

# For the ticket's internal note, with the plan's response target
botctl support-triage superbot-support-20261124T050000Z.tar --plan pro --markdown > triage.md

# Gzipped, unpacked into a folder, or on stdin
botctl support-triage bundle.tar.gz
botctl support-triage ./superbot-support-20261124T050000Z/
cat bundle.tar | botctl support-triage - --json
```

| Option | What it does |
|---|---|
| `<bundle>` | The bundle: a `.tar` or `.tar.gz` file, the folder it was unpacked into (or the folder holding that one), or `-` for a tar on stdin |
| `--plan <plan>` | The customer's plan: `self-host`, `starter`, `pro`, `max` or `enterprise`. Adds the first response target for the suggested severity, from [severity](severity.md#response-targets); Enterprise's is the default the agreement may change |
| `--latest <version>` | The newest SuperBot release. A bundle from an older botd says so, as a warning when it's a minor release or more behind, so support checks the changelog for a fix first |
| `--production` | The server is production even though it runs in testing mode, so the suggestion isn't held to Severity 3 ([below](#the-suggested-severity)) |
| `--as-of <time>` | When "now" is, for how old the bundle is. Now by default |
| `--markdown`, `--json` | Markdown for the ticket, or JSON for a ticket system's hook. Plain text by default |

It prints the triage on stdout and exits 1 when it suggests Severity 1 or 2, so a ticket system's hook can raise the ticket's priority and page the on-call engineer ([escalation](escalation.md#timed-escalation)). A file it can't read as a bundle is an error on stderr, with nothing on stdout, and exits 1 too.

## What it says

First the bundle (its name, online or offline, botd's version and when it was made) and the suggested severity with the findings that set it. Then each finding, the worst first:

- its level: `fail` suggests Severity 1 or 2, `warn` is worth a look, `info` is context;
- the severity it suggests on its own, if any;
- what it is, in a sentence, with the counts and reason codes from the bundle;
- the evidence: the file, and what in it;
- the runbooks and pages to read, and the next step where there's an obvious one.

Then the runbooks to open, and the questions for the customer: who and how many are affected, since when and what changed, the error text and a request id, which no bundle can answer, and the files that were taken out of it, if any.

## The suggested severity

The most severe of the findings' suggestions, from [severity's definitions](severity.md#severities). Support sets the severity, from these and from what the customer says, and says why if it differs from the customer's: a bundle shows the server, not how many people are stuck, so it can suggest a lower severity than the truth, never a reason to lower the customer's.

A server in testing mode isn't production, and Severity 1 and 2 are for production, so the suggestion is held to Severity 3 and the triage says so. When the customer's production server runs in testing mode anyway, `--production` lifts it.

## The findings

| Finding | From | When | Suggests | Read |
|---|---|---|---|---|
| `status.api`, `status.database` | `health.json`, the status page's checks | Major outage | 1 | [The server itself](runbook-machine-down.md#the-server-itself), [Severity 1](runbook-major-incident.md) |
| | | Partial outage; degraded | 2; 3 | |
| `status.machines`, `status.runners`, `status.notifications` | the same | Major or partial outage; degraded | 2; 3 (notifications partial: 3) | [Machine down](runbook-machine-down.md), [harness outage](runbook-harness-outage.md), [approvals](runbook-approvals-stuck.md) |
| `status.incident` | the status page's incidents | One is open: link the ticket to it | | [Incidents](incident-review.md) |
| `approvals.unheard` | approvals and the last 15 minutes | Approvals wait and every notification failed | 2 | [Approval queue stuck](runbook-approvals-stuck.md) |
| `approvals.waiting`, `notifications.failed` | the same | The oldest waiting 30 minutes or more; notifications failing | 3 | the same |
| `runs.waiting` | runs | Runs waiting for a slot | 3 | [Run limits](runbook-run-limits-egress.md#run-limits) |
| `api.errors` | the last 15 minutes | 5% of 20 or more requests failed; 25% | 3; 2 | [The server itself](runbook-machine-down.md#the-server-itself) |
| `runs.failing` | the same | 20% of 4 or more Bot runs failed; 50% | 3; 2 | [Harness outage](runbook-harness-outage.md) |
| `machines.error`, `machines.hosts`, `machines.rpo` | machines | A machine in error; an Incus host down or lost; a machine past its RPO | 3; 2; 2 | [Machine down](runbook-machine-down.md) |
| `harness.none` | `version.json` | No harness on the server and no managed machines | 2 | [Harness outage](runbook-harness-outage.md) |
| `setup.open` | the setup checklist | Items not done | 4 | [Onboarding](onboarding.md) |
| `onboarding.open` | `onboarding.json` | Onboarding checklist items botd sees open, for the TAM. Not `first_bundle`, since the bundle is one; items agreed at kickoff show too, as the bundle has no skips | | [Onboarding check](onboarding-check.md) |
| `health_check.open` | `health-check.json` | Monthly health check items botd sees open, for the TAM. Not `score`, `sign_in`, `runs` or `setup`, which the score's signals and the setup checklist already show | | [Health check](health-check.md#in-the-support-bundle) and each item's guide |
| `health_check.saml` | the same | A native SAML certificate in use ends within 60 days with nothing to replace it: sign-in through that provider stops when it does | | [SAML](runbook-saml.md#first-five-minutes) |
| `signal.identity` | `health-score.json` | At risk; watch. The reasons pick SAML or other sign-in, and SCIM: a revoked or expired token, or a tenant whose tokens all end soon, is provisioning stopped; other SCIM reasons are the table | 2; 3 | [SAML](runbook-saml.md#reasons-and-fixes), [sign-in](runbook-sign-in.md#reasons-and-fixes), [SCIM stopped](runbook-scim.md#provisioning-stopped), [SCIM reasons](runbook-scim.md#reasons-and-fixes) |
| `signal.backups` | the same | At risk (past the RPO); watch. The facts pick server backups (not set up, on the host, none copied, past the RPO) or machines' | 2; none | [Server backups](runbook-backups.md#server-backups), [machine backups](runbook-backups.md#machine-backups) |
| `signal.license` | the same | No usable license, so Bots don't run; otherwise at risk (grace, seats over); watch | 1; 2; 4 | [Bots stopped](runbook-license.md#bots-stopped); [license and seats](runbook-license.md) |
| `signal.runs`, `signal.approvals` | the same | At risk; watch | 3; none | [Harness outage](runbook-harness-outage.md), [run limits](runbook-run-limits-egress.md) (and [Bots stopped](runbook-license.md#bots-stopped) for runs refused `unlicensed`), [approvals](runbook-approvals-stuck.md) |
| `signal.adoption` | the same | Watch or at risk: for the TAM | | [Adoption](health-score.md#adoption) |
| `score.at_risk` | the same | The score's band is at risk: tell the TAM and the support manager | | [Escalation](escalation.md) |
| `score.falling` | `health-score-history.json` | The score fell 15 points or more, or left healthy | | [History](health-score.md#history) |
| `audit.sign_in`, `audit.scim`, `audit.access`, `audit.residency`, `audit.backups`, `audit.capacity`, `audit.run_limits`, `audit.machines`, `audit.approvals`, `audit.harness`, `audit.license`, `audit.secrets`, `audit.audit_trail`, `audit.other` | `audit-summary.json` | Failures and denials in the bundle's 7 days, by the runbook they point at, with the newest reason codes; a warning at 10 or more (not `audit.other`). `audit.backups` is server and machine backup failures and RPO breaches (`server.backup_*`, `machine.backup*`, `machine.rpo_breached`), apart from machine failures. `audit.capacity` is machines refused or waiting because no Incus host has room (`machine.placement_failed`), apart from machines down. `audit.secrets` is the secrets store's failures (`secret.*`); runs refused `secrets_unavailable` add its runs refused section to `audit.run_limits` | | the runbook for each: [SCIM](runbook-scim.md#reasons-and-fixes), [backups](runbook-backups.md), [no room for new machines](runbook-capacity.md#no-room-for-new-machines), [license](runbook-license.md), [secrets store](runbook-secrets.md) for theirs |
| `audit.audit_trail` | the same | SIEM export failures and stopped sinks (`audit.export_failing`, `audit.export_stopped`, which counts though recorded as a success), failed timestamps, and failed chain checks; always a warning. A failed check of the chain (`audit.verified`) may mean the log was changed | 2 for a failed chain check; none | [Audit trail](runbook-audit-trail.md), [the chain check failed](runbook-audit-trail.md#the-chain-check-failed) |
| `audit.truncated` | the same | The summary hit its limit | | |
| `logs.problems`, `logs.panic`, `logs.none` | `logs.jsonl` or `logs.txt` | Warnings (or, in text logs, lines that report a failure) by message, the most frequent first; a panic (`server.panic`), which is a bug for level 3; no logs, with the reason the offline bundle gives (no `--logs`, an unreadable file, a failed or empty journal) | | [Panics](runbook-server-errors.md#panics), [escalation](escalation.md) |
| `check.botd` | `check.json`, the offline bundle | botd isn't running (unless stopped on purpose), or holds its lock but `/healthz` doesn't answer (hung, unless it's still starting) | 1 | [The server itself](runbook-machine-down.md#the-server-itself), [Severity 1](runbook-major-incident.md) |
| `check.data_dir`, `check.master_key` | the same | Failed | 1 | [Server restore](runbook-server-restore.md) |
| `check.database` | the same | Failed; warned | 1; 3 | [Server restore](runbook-server-restore.md); [the checks](support-check.md#the-checks) |
| `check.disk` | the same | Failed; warned | 1; 3 | [The server itself](runbook-machine-down.md#the-server-itself) |
| `check.license` | the same | Failed: no usable license, so Bots don't run; warned | 1; none | [Bots stopped](runbook-license.md#bots-stopped); [license and seats](runbook-license.md) |
| `check.backups` | the same | Failed; warned | 2; none | [Server backups](runbook-backups.md#server-backups) |
| The rest | the same | Failed; warned | 2; none | [The checks](support-check.md#the-checks) |
| `check.before_upgrade` | the same | It was checked before an upgrade | | [Upgrades](runbook-upgrade.md#before-an-upgrade) |
| `version.behind`, `botd.restarted` | `version.json` | Older than `--latest`; botd started under 10 minutes before the bundle | | [Upgrades](runbook-upgrade.md) |
| `bundle.stale`, `bundle.format`, `bundle.unreadable` | the bundle | Made a day or more ago; by a newer botd than this `botctl` knows; a file that isn't JSON | | |

A check finding brings `botd support check`'s own fix as its next step.

## Reading a bundle safely

The bundle comes from outside the Provider, so the triage treats it as untrusted. It reads only the files bundles have, only plain files, all from one folder (two bundles in one tar are refused), at most 64 MiB unpacked in all (a gzip that unpacks to more is refused), and never writes the bundle to disk. Text from the bundle (an incident title, a log message) is cut to 240 characters and stripped of control characters, and the Markdown escapes it, so it can't break the table, add HTML, or make a link or an image the ticket system might fetch.

The triage repeats only what the bundle already has, which botd redacted before the customer sent it ([what's never in it](support-bundle.md#whats-never-in-it)): no secrets, chats, names, emails or IP addresses. If a bundle has one anyway, that's a bug: tell `<security-email>`, and keep the triage out of the ticket until it's removed.

## Where it fits

1. A ticket arrives with a bundle. The support engineer (level 1) runs `botctl support-triage <bundle> --plan <plan> --markdown` and pastes the result into the ticket's internal note.
2. A suggested Severity 1 or 2: check it against what the customer says, then follow [timed escalation](escalation.md#timed-escalation). For Severity 1, the incident commander starts the [Severity 1 runbook](runbook-major-incident.md).
3. Open the runbooks it lists, starting with the worst finding, and send the first response with the questions it lists.
4. When the customer sends a fresh bundle after a fix, triage it again: what's gone is what the fix fixed.

## Not in it

- A diagnosis. It points at runbooks; it doesn't decide the cause, and a clean triage doesn't mean nothing is wrong.
- Users' machines' own logs and anything from before botd last started, which the bundle doesn't have ([not in it, yet](support-bundle.md#not-in-it-yet)).
- Any change on the customer's server: it reads a file.
