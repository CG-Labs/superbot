# 0183: A daily check of new archive objects

## Status

Accepted (23 Nov 2026). Sixth slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the write-once S3 archive ([ADR 0154](0154-write-once-s3-audit-archive.md)), checking it ([ADR 0163](0163-checking-the-audit-archive.md)) and an archive alongside a SIEM ([ADR 0173](0173-an-archive-alongside-a-siem.md)). ADR 0163's "When" options had "also in the daily self-check ... later, perhaps limited to new objects", and the "Later" lists of ADRs 0163 and 0173, and the roadmap, have "a daily automatic check of new archive objects".

## Context

`botctl audit verify --archive` compares the log with the archive, but only when someone runs it. Run on the whole archive it costs one `GET` per object, about 100,000 a year at the default batch length, so the guide says to run it weekly from cron. Most installs won't set that up. Until someone does, a log rebuilt from a changed event goes unnoticed: botd's daily self-check reads only the log, whose own chain still holds.

Constraints: no new dependencies or secrets; no new RBAC or routes (other work in flight); reuse ADR 0163's check unchanged; cheap enough to run every day for years.

## Options

**What the daily check reads**

1. **The whole archive every day.** Simple, but 100,000 `GET`s a day after a year.
2. **Only objects past the head the last passing check reached**, picking the chain up from that head. That's about 288 objects a day at 5-minute batches. But a forged object named for old events, or a new version written over an old object, would never be read.
3. **Option 2, plus any object the store says was written to since the last pass began.** The listing already gives each version's `LastModified`, which the store sets and no writer can. So a forged copy, a new version or a delete marker on an old object is read the next day, at the cost of the objects it touches.

**How a log rebuilt from an event already checked is caught**

The objects that event is in aren't read again. But rebuilding the chain from an event changes the hash of every event after it, including the head the last pass reached. So:

1. **Hold the saved head to the log.** Save the head's hash with the pass, and fail when the log's hash for that event differs (`mismatch`). That's one row read. If retention has deleted that event, the anchor's hash is checked when it's the same event. Otherwise the events after the head are in the new objects, and those are compared anyway.
2. **Read every object again now and then.** That's what the check by hand is for.

**On or off by default**

The check needs `s3:ListBucketVersions`, which export alone doesn't. So an archive set up before this slice may fail its first daily check until that right is granted.

1. **On (`daily`), with `AUDIT_EXPORT_S3_CHECK=off`.** A check that can't read the archive fails loudly, and the error names the right. Silently skipping it would leave the gap this slice closes.
2. **Off until asked for.** Nothing changes on upgrade, but the installs that most need the check are the ones that won't turn it on.

## Decision

Option 3 for what's read, option 1 for a rebuilt log, on by default.

- **When.** With an S3 archive in `AUDIT_EXPORT`, the daily self-check (a minute after start, then every 24 hours) checks the archive first and then the chain, and records one `audit.verified` with both parts, as `GET /api/audit/verify?archive=on` does. `AUDIT_EXPORT_S3_CHECK=off` leaves the archive out. Any other value stops botd at startup.
- **The last pass.** A check that passes saves its head (id and hash) and when it began, as `audit_export:<sink>#checked` beside the sink's cursors. So a different archive starts with a whole check. The first daily check, with no pass saved, reads the whole archive, as the check by hand does. A whole check by hand (no `--from`/`--to`) that passes also saves its head. A pass replaces the saved one only if it is further on (a later head, or the same head from a later check), so a check overtaken by one that overlapped it never moves the saved head back. A check that fails saves nothing, so the next day reads from the same place and fails again until the problem is fixed or explained.
- **What's read.** Every object whose last event is past the saved head, and every object with a version or delete marker the listing says was written within an hour before the last pass began (the hour allows for the store's clock). A version the listing gives no time for counts as new. Everything else is `skipped`. The listing itself is still whole, so `stray` keys are always found.
- **Carrying on.** The walk starts at the saved head: the first new event must link to it (`link`), and events up to it are repeats, compared with the log as before. The `start` check is left out, since the last pass already made it. `behind` still applies: the archive must reach what botd delivered.
- **The head still holds.** Before reading, the saved head's hash must still be this server's for that event, or the anchor's when retention deleted it (`mismatch`, or `missing` when the event is gone without retention). Either one also breaks the log check with reason `archive`, like any archived event that differs.
- **The answer.** The archive block gains `after`, the saved head it carried on from (null for a whole check), and `audit.verified` records it with `skipped`. `GET /api/audit/chain`'s `verification` now includes the archive's part, and the app's audit log shows an `Archive check` line under `Last check`. `GET /api/audit/siem`'s `archive` shows `dailyCheck`, and the startup summary says whether new objects are checked daily.
- **The S3 client.** `object_versions` now returns each version's `LastModified`. The S3 test stand-in records when each version and delete marker was written and lists it.

## What it proves

- **A rebuilt log**, from any event, fails the next daily check. If the event was archived since the last pass, it fails as `mismatch` at that event. If it was already checked, the saved head no longer matches. Either way `audit.verified` fails with reason `archive`, and botd logs a warning.
- **A forged object** named for old events, a new version over an old object, or a changed copy under a new key, is read the next day because the store dates it, and fails as in ADR 0163 (`contents`, `overwritten`, `checkpoint`, `link`).
- **A missing new object** fails as `link` or `behind`, as before.
- **It doesn't prove** that old objects are still there. In compliance mode nobody can delete them. In governance mode, or with the lock off, someone who can delete versions for good could remove an old object, and only a whole check (`botctl audit verify --archive`) would see the gap. So keep the whole check from cron for those modes. Like the check by hand, it doesn't help against someone who controls botd while it runs.

## Consequences

- The daily cost is one listing of every version (1,000 per page, about 105 pages after a year at 5-minute batches) plus one `GET` per new object, about 288 a day. The first daily check after an upgrade reads the whole archive once.
- An archive whose key lacks `s3:ListBucketVersions` gets a failing `audit.verified` each day until the right is granted or `AUDIT_EXPORT_S3_CHECK=off` is set. The upgrade note in the changelog says so.
- A failure that can't be fixed, such as an object really lost in governance mode, keeps the daily check failing. That's deliberate: the archive no longer proves what it should. The guide explains how to look into it.
- Later: more than one SIEM (per-sink headers), checking checkpoint timestamp tokens from the archive, exporting each event's chain digest so contents can be checked after retention, and gzip.
