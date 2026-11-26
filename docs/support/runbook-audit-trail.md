# Runbook: audit trail

The audit log's copy off the host stops (a SIEM or the write-once archive), its daily check of the hash chain fails, or its checkpoints stop being timestamped. Bots and people carry on, so it's easy to leave, but the audit trail is what the customer's security team and auditors rely on, and what proves nobody changed the log. Severity: [3](severity.md#severities) when the export or timestamps fail, since events wait in botd's database and nothing is lost yet; 2 when a check of the chain fails, until it's explained; 1 as soon as it isn't explained by a restore or an erasure, or a sink was taken out by someone nobody can name: that's a suspected security incident.

The settings and checks are in the [audit export guide](../ops/audit-export.md); this page is the order to work in.

## First five minutes

1. **Which part.** As an admin on the server:

   ```sh
   botctl audit chain                 # the head, last checkpoint and timestamp, the export's lag, stopped sinks, the last check
   botctl audit siem                  # each sink: delivered, pending, failing, the last error
   botctl audit 50 --action 'audit.*'
   ```

   A support bundle has the week's `audit.*` failures, and every stopped sink, in `audit-summary.json`; [bundle triage](triage.md) lists them as `audit.audit_trail`, and suggests Severity 2 when a chain check failed. The Prometheus rules in [`superbot-audit-trail.rules.yml`](../../deploy/prometheus/superbot-audit-trail.rules.yml) raise the same four things: a failing sink, a stopped sink, failing timestamps and a failed check.
2. **A failed chain check comes first.** Before anything else: don't restart botd, restore a backup or run `botctl audit verify` with new options. Take a consistent copy of the database somewhere safe, outside `DATA_DIR`: `botd database backup DATA_DIR/app.sqlite <safe-dir>/app-evidence.sqlite` (SQLite's online backup, so it holds events still in `app.sqlite-wal`; with an encrypted database it needs the master key, from `SUPERBOT_MASTER_KEY_FILE` or `~/.config/superbot/master.key`, and stays encrypted). Don't copy `app.sqlite` by itself while botd runs: recent events may be only in the WAL. Keep the master key with the copy if the database is encrypted, and tell the customer's security owner. Then [the chain check failed](#the-chain-check-failed).
3. **Did anything change?** `AUDIT_EXPORT` or a sink's token edited, the SIEM's collector, token, data collection rule or API key rotated, a network or proxy change, the archive bucket's policy or Object Lock, a restore, an erasure, an upgrade, or the TSA's address or CA.

## The export is failing

After 3 failures in a row botd records `audit.export_failing` with a `reason`, and keeps retrying from 1 second up to 5 minutes for as long as it takes. Events wait in the database meanwhile, and retention never deletes one a sink hasn't taken, so nothing is lost; the database grows instead. `audit.export_recovered` follows when the sink takes events again.

| Reason | Usually | Fix |
|---|---|---|
| `delivery_failed` | The SIEM refused or didn't answer: a rotated token or API key (HTTP 401 or 403), a collector moved or down, TLS to a syslog host, a proxy, a data collection rule without the stream, or an archive object that read back different | The event's `error` and `botctl audit siem` have the status and botd's hint. Fix the token in `AUDIT_EXPORT_HEADERS` (or `AUDIT_EXPORT_HEADERS_<NAME>`), the URL or the network, and restart botd if a setting changed ([delivery and failures](../ops/audit-export.md#delivery-and-failures)) |
| `sign_in_failed` | Azure Monitor or Google SecOps: botd couldn't get a token from Entra ID or Google | The managed identity, app or service account and its role on the data collection rule or SecOps instance ([Sentinel](../ops/audit-export.md#microsoft-sentinel-azure-monitor), [SecOps](../ops/audit-export.md#google-secops)) |
| `unreadable` | botd couldn't read an event or a checkpoint's record from its database: a damaged row | Export stops before it, rather than skip it. `botctl audit verify` names the row; treat it as [the chain check failed](#the-chain-check-failed) and the database as the [server restore](runbook-server-restore.md) runbook does |
| `cursor_unsaved` | The event went, but botd couldn't save how far it got: a full disk or a database error | `botd support check` (disk, database). Once saved, the sink may get a batch twice; SIEMs de-duplicate on `host` and `id` |
| `not_write_once` | The S3 archive's bucket doesn't have Object Lock on, or has no default retention when `AUDIT_EXPORT_S3_LOCK` relies on one, so botd won't write to it | A new bucket made without Object Lock, or its retention removed. Use a bucket with Object Lock and a default retention, or `AUDIT_EXPORT_S3_LOCK=compliance` with `AUDIT_EXPORT_S3_RETAIN_DAYS` ([archive](../ops/audit-export.md#archive-events-to-write-once-s3)). `AUDIT_EXPORT_S3_LOCK=off` only for a bucket that's meant not to be write-once |

A long failure is worth Severity 2 when the database is filling the disk (`botd support check`'s disk), or the customer's agreement promises events in its SIEM within a time.

## A sink was stopped

`audit.export_stopped` is recorded once when botd starts without a sink it was sending to: `reason` `removed` (other sinks still run) or `export_off` (none does), with the last event it took (`delivered`) and how many it hadn't (`pending`). It's a success in the audit log, since someone changed a setting, but from then on that SIEM gets nothing, which is exactly what someone covering their tracks would do first. So:

1. Find who changed `AUDIT_EXPORT` and why: the change record, the customer's admins. botd can't name them; the setting lives in `.env`.
2. If nobody can, it's a suspected security incident: Severity 1, and the customer's [incident response](../security/policies/incident-response.md).
3. If it was meant (a SIEM retired or replaced), check the replacement started with `all` (`audit.export_started` with `skipped` 0), or the evidence bundle for that month won't show every event delivered ([changing the sink](../ops/audit-export.md#changing-the-sink)).

`audit.export_resumed` is a stopped sink set again, or one retention outran: `missed` names the events it will never get. Those can still be exported with `botctl audit export` for the SIEM to take by hand, while they're kept.

## The chain check failed

botd checks the whole chain a minute after starting and once a day, and records `audit.verified`; a failed one has the first break's `reason`. `botctl audit verify` runs the same check now and names `firstBroken`.

| Reason | Means | Then |
|---|---|---|
| `contents` | An event was changed after it was written | Compare it with the SIEM's copy (`id`, `chainPrev`, `chainHash`). Unexplained: Severity 1 |
| `link` | An event before it was removed, added or reordered, or the start was cut without an anchor | The same. A restore from a backup older than events the SIEM already has shows here too |
| `unsealed` | An event has no seal at all: written around botd, straight into the database | Severity 1 unless an engineer did it on purpose and recorded it |
| `erased` | An event's personal fields were cleared, but no `audit.erased` names it | A real erasure always names its rows (`botctl user erase`); a cleared salt without one is someone editing the database |
| `pin` | An event differs from a hash given with `--pin`, or is missing | The history on the host isn't the one the SIEM saw. After a restore, expected and worth recording; otherwise Severity 1 |
| `checkpoint` | A signed checkpoint doesn't hold. `checkpoints.firstBroken` says why: `head` (events before it were changed and the chain rebuilt), `key` (a key botd doesn't trust), `signature`, `record` (its record is gone or differs) or `malformed` | `head` and `signature` mean the chain was rebuilt: Severity 1. `key` after a master key rotation: pin the keys from before (`botctl audit verify --key`) |
| `timestamp` | A checkpoint's RFC 3161 token doesn't hold: `imprint`, `nonce`, `signature`, `certificate`, `untrusted`, `record` or `malformed` | `imprint` means it stamps another head: the chain was rebuilt. `untrusted` or `certificate` can be a CA file that changed |
| `archive` | An event differs from the write-once archive (`--archive`, or the daily check of new objects) | The archive can't be changed: the database is what moved. Severity 1 unless a restore explains it ([check the archive](../ops/audit-export.md#check-the-archive)) |
| `unreadable` | The log couldn't be read to the end | A damaged database: the [server restore](runbook-server-restore.md) runbook, from the copy you took |
| `broken` | The check failed with no first break named | Run `botctl audit verify` and read its answer in full |

Then, in this order:

1. Hold the copy you took. Note `firstBroken`, the head and the last checkpoint.
2. Pin a few events the SIEM holds, from before and after the break: `botctl audit verify --pin <id>:<hash> ...`. With the archive, `botctl audit verify --archive`. Exported lines can be checked without botd too: `botctl audit verify-lines` ([without botd](../ops/audit-export.md#check-exported-events-without-botd)).
3. Explained (a restore, recorded in its ticket; a recorded repair): note it in the ticket and the customer's record, then Severity 3.
4. Not explained: Severity 1, the [Severity 1 runbook](runbook-major-incident.md), with the security owner as the incident's lead, and the customer's [incident response](../security/policies/incident-response.md). The DPA's breach notice may apply.

## Timestamps are failing

With `AUDIT_TIMESTAMP_URL`, each checkpoint goes to a TSA. Timestamping never holds up the log: checkpoints wait as pending and are stamped oldest first. After 3 failures in a row botd records `audit.timestamp_failing` with a `reason`; `audit.timestamp_recovered` follows.

| Reason | Usually | Fix |
|---|---|---|
| `unreachable` | The TSA is down, or the server can't reach it (egress, proxy, DNS) | Check from the server (`curl -sI <tsa-url>`). Free TSAs have outages: moving to another is one setting, `AUDIT_TIMESTAMP_URL`, with its CA in `AUDIT_TIMESTAMP_CA_FILE` |
| `refused` | The TSA answered with an error, or granted the request with no token | Its status in `botctl audit chain`. Some TSAs limit requests: a longer `AUDIT_CHECKPOINT_MINUTES` sends fewer |
| `malformed` | The reply isn't a time-stamp token, or is too big | A URL that isn't the TSA's endpoint (a web page) |
| `imprint`, `nonce` | The token stamps something else, or answers another request | A proxy or TSA misbehaving. Change TSA; escalate if it persists |
| `signature`, `certificate` | The token's signature doesn't verify, uses an algorithm botd doesn't take, or the TSA's certificate isn't for time-stamping or wasn't valid then | The TSA changed its certificate or algorithm. Check its published certificates; change TSA if needed |
| `untrusted` | The TSA's certificate doesn't chain to `AUDIT_TIMESTAMP_CA_FILE` | The TSA moved to a new CA: update the file to its current chain and restart botd |
| `unsaved` | The token was good, but botd couldn't save it | A full disk or a database error: `botd support check` |

Pending checkpoints are stamped once the TSA answers, with the time they're stamped, so a long outage leaves a stretch the tokens don't cover. The evidence bundle's `audit-integrity.json` counts it.

## Before telling the customer it's fixed

1. `botctl audit siem` shows every sink taking events, `failing` false and `pending` falling; `botctl audit chain` shows the last check passed and, with a TSA, a recent timestamp.
2. The SIEM has the events from the failure: pick one from the middle and find it there by `host` and `id`.
3. After a failed chain check, `botctl audit verify` passes, or its break is explained and written down in the ticket.

## Escalate when

- A chain check fails and a restore or a recorded repair doesn't explain it: Severity 1, the security owner leading.
- A sink stopped and nobody can say who changed `AUDIT_EXPORT`.
- The export fails with `unreadable` again after the database is restored, or with an error the SIEM's side doesn't explain.
- Timestamps fail on two different TSAs.

## Afterwards

Note the cause in the ticket. If a token or key rotated, put who holds it and when it next rotates in the customer's onboarding record. A failed chain check that was explained still goes in the monthly health check's notes and the next business review, and an unexplained one gets a written review ([incident reviews](incident-review.md)). Make sure the customer's SIEM alerts on `audit.export_stopped` and failed `audit.verified` events, and their Prometheus loads the audit trail rules.
