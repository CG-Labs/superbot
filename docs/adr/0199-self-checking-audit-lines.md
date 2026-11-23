# 0199: Exported audit events that check themselves, and an offline checker

## Status

Accepted (23 Nov 2026). Eighth slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the hash chain ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)), signed checkpoints ([ADR 0149](0149-signed-and-timestamped-audit-checkpoints.md)), the write-once archive and its check ([ADR 0154](0154-write-once-s3-audit-archive.md), [ADR 0163](0163-checking-the-audit-archive.md), [ADR 0183](0183-daily-check-of-new-archive-objects.md)) and several SIEMs ([ADR 0191](0191-several-siems-with-their-own-headers.md)). The "Later" lists of ADRs 0163, 0183 and 0191, and the roadmap, have "each event's chain digest in the export, so contents can be checked after retention".

## Context

Each exported line has `chainPrev` and `chainHash`, but the hash is over the fixed fields **and a digest** of the erasable ones (ADR 0122). The digest wasn't exported, so nobody could work a line's hash out from what it says. That leaves two gaps:

1. **After retention.** The archive check (ADR 0163) holds what the archive says to this server's rows. Once retention deletes a row, nothing binds the archived contents. A copy of a batch under a new key with an event's details changed and its hashes kept still links, and passes.
2. **Without botd.** Regulated customers keep the archive for years, often after the server is gone, and auditors want to check it with their own tools. Today every check runs inside botd, against its database.

Constraints: no new dependencies; lines already in SIEMs and archives stay valid, and a batch resent after the upgrade must be byte-identical to the first try (or the archive check calls it `overwritten`); erasure (ADR 0122) must still work, so an erased person's details never become checkable guesses; a value masked as a secret on export must not become guessable either.

## Options

**What to export**

1. **The digest only.** Binds the fixed fields (who acted, what, when, the outcome, the IdP) and the digest, not the details. It reveals nothing, since it is a salted hash.
2. **The digest and the salt.** Anyone can then work the digest out from the line, so every field is bound. But a salt next to a hidden value lets anyone test guesses at it. That's fine when the line shows everything the digest covers, and not when erasure or redaction hid something.
3. **The canonical bytes.** No help: the line already has the values, and the bytes would carry what redaction hid.

**Which events carry them**

1. **Every event sent from now on.** But a resent archive batch cut before the upgrade would change, and SIEMs behind each other would disagree about the same event.
2. **Events after a marker saved once.** Every sink sends the same line for the same event, and a checker can hold every event after the marker to having a digest.

**How to check without botd**

1. **A script in the docs** (jq plus sha256sum). Fragile: the canonical form is JSON arrays whose bytes must match serde's.
2. **A `botctl` command** that shares the checking code with botd. `botctl` is already the operator's offline tool (`support report`), a static binary with no server.

## Decision

Option 2 for what (the salt only when it hides nothing), option 2 for which, option 2 for how.

- **`chainDigest`** is added to every exported line (SIEM and archive, JSON and syslog) for events after the marker. **`chainSalt`** is added only when the line, as exported, works out to that digest. So it is left out for erased rows (their salt is gone) and for rows whose details were redacted or reformatted on the way out.
- **The marker** is saved as the setting `audit_export:#digests` the first time botd starts the export with this version. It is set past everything any sink had delivered or cut a batch of, including sinks no longer configured, so an archive turned back on resends its batch as it was. If it can't be saved, no digests are sent until a restart saves it. `GET /api/audit/siem` shows it as `digestsAfter`.
- **A line checks itself.** `chainHash = SHA256(domain, chainPrev, fixed fields, chainDigest)` as ADR 0122 has it. With the salt, `chainDigest = SHA256(domain, salt, erasable fields)` too. The code is one module (`audit_line.rs`) that botd and `botctl` both build, so there is one definition of the canonical form.
- **The archive check** now works each line's hash out again. It counts lines bound in full (`bound`), in their fixed fields only (`boundFixed`) and not at all (`unbound`, exported before the marker). Two new reasons: `digest` (the hash doesn't follow from what the line says) and `unbound` (an event after the marker with no digest: it was stripped, or the object isn't botd's). Both apply to every copy, repeats included, and whether or not the row is still here.
- **`botctl audit verify-lines <file|dir|->... [--key <hex>]...`** checks exported lines with no botd and no network. It reads files, directories (their `.jsonl`, `.ndjson`, `.json`, `.log` files) and stdin, in any order and with copies. Syslog lines are read from their first `{`, other sources' lines are counted and skipped. For each `host` it checks:
  - each line against its hash;
  - copies of an event against each other (`conflict`);
  - each event's link to the one before (`link`);
  - the marker rule (`unbound`), from `--digests-after` (the `digestsAfter` botd shows, pinned like the key) or, without it, from the first line with a digest;
  - signed checkpoints, under the keys given or, with none, under their own (`checkpoint`).

  It prints a JSON report and exits 1 on any problem.

## Consequences

- An archive outlives the rows it came from: after retention, a changed event is caught by its own hash, not only by comparison with a row that's gone.
- An auditor can check a SIEM export or a copy of the archive on their own machine, years later, with one binary and the checkpoint key (`botctl audit key`), pinned with `--key`.
- A line without its salt is bound only in its fixed fields. That is true of erased and export-redacted rows, and of a forged copy with the salt stripped, so after retention such a copy can still change details unseen. `boundFixed` says how many lines rest on that. With the row still here, the comparison with it catches the change as before.
- Without `--digests-after`, lines stripped of every digest bind nothing, and pass: the lines alone can't say they ever had one. So the marker is pinned like the checkpoint key, and `verify-lines` says when it isn't.
- Lines grow by about 100 bytes (two hex fields).
- Events before the marker stay as they were (`unbound`). Use `botctl audit verify --archive` while their rows are still here.
- The offline check doesn't read RFC 3161 timestamp tokens. `openssl ts -verify` does (see the ops guide).
- Later: checking checkpoint timestamp tokens from the archive, and gzip.
