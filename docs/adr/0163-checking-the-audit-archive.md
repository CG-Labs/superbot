# 0163: Checking the audit archive

## Status

Accepted (23 Nov 2026). Fourth slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the hash chain ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)), signed checkpoints ([ADR 0149](0149-signed-and-timestamped-audit-checkpoints.md)) and the write-once S3 archive ([ADR 0154](0154-write-once-s3-audit-archive.md)), whose "Later" list had "a `botctl audit verify` that reads the archive itself to check continuity and pin every batch's head".

## Context

The archive is the copy of the log nobody can change. It only helps if someone compares the log with it. Today that means downloading the objects and pinning hashes by hand (`--pin`). Nobody does that for every event, and nothing checks that the archive itself is whole: no missing objects, no gaps, locks in place, and as far as botd says it got.

Constraints: no new dependencies; reuse botd's SigV4 client and checkpoint checks; no new secrets or RBAC (other work in flight); the archive's key keeps no delete rights.

## Options

**Who reads the archive**

1. **botd, behind `GET /api/audit/verify?archive=on`** (`botctl audit verify --archive`). botd already has the archive's settings and key, the log, the trusted checkpoint keys and the anchor. It records the result as `audit.verified`, like any check.
2. **botctl, with its own S3 credentials.** This is independent of a compromised botd. But it needs the store's keys on the operator's machine, a second S3 client in botctl, and the log's hashes over the API anyway. Someone who controls botd can fake that API, so this gains little over pinning by hand, which already works without botd.
3. **A standalone script** (`aws s3 cp` plus `jq`). It's documented, but it won't check locks, versions or signatures.

**Which version counts**

Object Lock protects versions, not keys. Anyone with `s3:PutObject` can add a new version on top of a locked one.

1. **The newest version**, what a plain `GET` returns. A forger with the archive's key could then replace any object.
2. **The oldest version**, which is the one botd wrote and the lock protects. A later version that differs is reported (`overwritten`). One that matches is a retried batch ([ADR 0154](0154-write-once-s3-audit-archive.md)) and is only counted. A delete marker only hides an object, which is still read and counted as `hidden`. This needs `s3:ListBucketVersions`.

**What's compared with the log**

1. **Each batch's head** (`x-amz-meta-superbot-chain-head`), from the listing alone. This is cheap, but a changed event in the middle of the log only shows if its chain was rebuilt, and then only at the next head.
2. **Every event's hash**, from the bodies. This costs one `GET` per object, but it's the same as pinning every event, and the bodies are needed anyway to check links and checkpoints.

**When**

1. **On demand**, with `--from`/`--to` to keep it cheap.
2. **Also in the daily self-check.** That's one `GET` per object every day, about 100,000 a year at the default batch length. Later, perhaps limited to new objects.

## Decision

Reader option 1, version option 2, comparison option 2, on demand.

### The check

botd lists every version under `<prefix>/` and groups the versions by key. Keys that don't match `<yyyy>/<mm>/<dd>/<20-digit first>-<20-digit last>.jsonl` are `stray`. Objects outside `--from`/`--to` are skipped. The rest are read four at a time, oldest version first, in id order. For each object:

- **Shape**: the key's ids, `-first-id`, `-last-id`, `-events`, `-chain-prev`, `-chain-head` and `-schema` match the body (`metadata`), and ids rise within it (`order`).
- **Lock**: unless the lock is `off`, the version has a lock mode and a retain-until date (`unlocked`). A date that has passed is counted (`lockExpired`) but isn't a failure: the operator chose the period.
- **Chain**: each event's `chainPrev` is the previous event's `chainHash`, across objects too (`link`). An event at or below the head so far is a repeat that a restarted export can leave. Repeats are counted and still compared with the log, and a repeated checkpoint's signature must still hold, since its details aren't covered by the hash compared. They don't move the chain.
- **Checkpoints**: each `audit.checkpoint` must hold its own signature under a trusted key (botd's current and past keys, or `--key`). If it links to the event before it, it must also name that event (`checkpoint`). This reuses `audit_checkpoint::check_signed`, the same code the log check runs. Timestamp tokens aren't checked here.
- **The log**: each event's hash must equal this server's `chain_hash` for that id (`mismatch`), or the id must be at or below the anchor retention keeps, with the anchor's own hash equal (`gone`). Otherwise it's `missing`. The archive's hashes aren't bound to its contents on their own (the salted digest that binds them stays in the log), so while the row is here its contents must match too: the columns nothing may change, `chainPrev`, and, unless an erasure has cleared the row's salt, the erasable ones (`contents`, counted as `altered`). That is the case for repeats as well, so a copied batch with changed contents and the same hashes fails. Rows are read as stored, in one query with their salt. In `details`, each `[redacted]` the export wrote can stand for whatever it covered, since the export redacted with the secrets known then.
- **Completeness**: if the archive ends before the `delivered` cursor read when the check started, it's `behind`. This only applies when botd has cut a batch for this archive and the cursor is in range. With `AUDIT_EXPORT_START=new`, an empty archive is fine. botd also saves the first event of the first batch it ever cuts for an archive (`<sink>#start`, beside its cursors). A check whose range covers that event fails as `start` if the archive begins later: its first objects are gone. Starting from `new`, or after retention deleted older events, is fine, since that event is where it began. Archives started before botd saved it aren't asked.

### The answer

`Report` gains an `archive` block: the counts, `first`, `head`, `delivered`, `start`, `problems`, and the first 20 `firstProblems` (`key`, `id`, `reason`, `error`). Each `mismatch` or `missing` event also breaks the log check with reason `archive`, so `firstBroken` and `audit.verified`'s reason name it. Any archive problem fails the check, so `botctl` exits 1. `archive=on` with no S3 archive configured is a 409; any value other than `on` or `off` is a 400. The archive check is admin-only, like `verify`.

### The S3 client

`object_versions(prefix)` returns every version and delete marker with `IsLatest`, in listing order. `get_version(key, version)` reads one version, by the id the listing gave, `null` included (an object written before versioning was on). The backup code's `versions()` now uses the same parser.

## What it proves

- **A rebuilt log**: someone with `app.sqlite` changes an event and reseals the chain from there. The log check passes, but every event they changed that the archive holds fails as `mismatch`. They can't change the archive's locked versions.
- **A forged archive object**: someone with the archive's key adds a version or a new key. The first version still decides, the new version is `overwritten`, and a new key is `stray`, or breaks the chain as `link` if it's named like botd's.
- **A missing object**: in compliance mode it can't be deleted. In governance mode, or with the lock off, it shows as `link` at the next object, `behind` at the end, or `start` at the beginning.
- **A changed copy**: someone with the archive's key writes a batch again under a new key, with an event's contents changed and its hashes kept. While this server still has the event, it fails as `contents`. Once retention deleted it here, nothing binds those contents, since the export doesn't carry the salted digest.
- **It doesn't prove** anything about events not yet archived (up to `AUDIT_EXPORT_S3_BATCH_SECONDS` plus any outage). It doesn't help against someone who controls botd while the check runs, since botd does the reading. For that, use the archive's own copy with checkpoints checked by OpenSSL, as ADR 0149 shows, or pin from a SIEM.

## Consequences

- One listing (1,000 versions per page) plus one `GET` per version of each object read. A whole year at 5-minute batches is about 105,000 objects, so use `--from` for frequent checks.
- The archive's key needs `s3:ListBucketVersions` for this check, though export doesn't. Without it the check fails with an error naming the right.
- The S3 test stand-in now keeps object bodies per version, lists real versions and delete markers, and serves `GET ?versionId=`.
- Later: an archive alongside a SIEM (a second cursor), a daily automatic check of new objects, checking checkpoint timestamp tokens from the archive, exporting each event's chain digest so contents can be checked after retention, and gzip.
