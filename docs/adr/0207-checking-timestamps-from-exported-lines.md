# 0207: Checking checkpoint timestamps from the archive and exported lines

## Status

Accepted (23 Nov 2026). Ninth slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on signed, timestamped checkpoints ([ADR 0149](0149-signed-and-timestamped-audit-checkpoints.md)), the archive check ([ADR 0163](0163-checking-the-audit-archive.md), [ADR 0183](0183-daily-check-of-new-archive-objects.md)) and self-checking lines with `botctl audit verify-lines` ([ADR 0199](0199-self-checking-audit-lines.md)), whose "Later" list has "checking checkpoint timestamp tokens from the archive".

## Context

Each `audit.checkpoint_timestamped` event records the token's SHA-256 (`timestampSha256`), its time and its TSA certificate in its `details`, which the chain covers. The token itself travels in the line's `checkpoint` object, which no hash covers (ADR 0149). `botctl audit verify` checks tokens against the `audit_checkpoints` table, but:

1. **The archive check** read the timestamp line's hash and links, never its token. A copy of a batch with a token swapped, or stripped, passed. And once retention deletes the rows, the archive is the only place the tokens are.
2. **Offline**, `verify-lines` didn't read tokens at all. An auditor had to run `openssl ts -verify` by hand, one line at a time, and match the result to the chain themselves.
3. **The export** sent a timestamp line without its `checkpoint` object if the record couldn't be read. Such a line is indistinguishable from a stripped one.

Constraints: no new dependencies; the check must run in `botctl`, with no botd and no network; export batches must stay byte-identical on retry; lines already archived stay valid.

## Options

**What the token is held to**

1. **The token alone**, checked under its own certificate. Proves nothing: anyone can make a token.
2. **The chain-bound details.** The token must hash to `timestampSha256`, stamp the checkpoint's statement and signature (its imprint), carry the recorded time and TSA certificate, and chain to the CA certificates trusted. The statement and signature come from the checkpoint's own event when it's among the lines, else from the record the line carries, whose signature must then hold under the trusted keys.

**Where the code lives**

1. **botd only.** Leaves the offline gap.
2. **Shared**, as `audit_line.rs` is (ADR 0199). `tsa.rs`, the RFC 3161 reader, drops its two uses of botd's crate so `botctl` can build it too.

**A timestamp line with no token**

1. **Count it as unstamped.** A stripped token would pass.
2. **Fail it** (`token`), and make the export fail a batch whose checkpoint record can't be read, so it retries rather than sends a line without its token.

## Decision

Option 2 in each.

- **One check**, `audit_line::check_timestamp`, used by botd's archive check (by hand and daily) and by `botctl audit verify-lines`. It fails as `timestamp`, with the sub-reason in the error: `token` (missing or not base64), `record` (the token, its time or its TSA certificate isn't what the event recorded, or the record carried differs from the checkpoint's own event), the checkpoint's own reasons (`key`, `signature`, ...), or `tsa::verify`'s (`imprint`, `nonce`, `signature`, `untrusted`, ...).
- **Trust.** botd uses `AUDIT_TIMESTAMP_CA_FILE`. `verify-lines` takes `--timestamp-ca <pem>`, repeatable. Without either, a token holds under the certificate it carries, `trustedTimestamps` is null, and `verify-lines` says so in its `note`. With them, a token that doesn't chain fails as `untrusted`. The chain is checked at the token's time, so a TSA certificate that has since expired still holds.
- **Counts.** The archive check and `verify-lines` report `timestamps`, `trustedTimestamps` and `lastTimestamp`. A timestamp counts once, and only if every copy of it holds; every copy is checked, repeats included. `verify-lines` also counts `unstamped`: checkpoints made with a TSA (`"timestamp": "pending"`) whose timestamp isn't among the lines. That isn't a failure, since the TSA may still be catching up.
- **Export.** A checkpoint record that can't be read fails the batch (`unreadable`), which is retried as the same batch. It doesn't move the batch cursor, so a retry stays byte-identical.
- **The app** shows the count in its `Archive check` line.

## Consequences

- A swapped or stripped token in the archive is caught, by hand and the next day, with or without the row here.
- An auditor checks every timestamp in a SIEM export or archive copy with one command, and OpenSSL stays a cross-check.
- A line forged whole, with a real token from the forger's own TSA, holds together. Only the CA tells it apart, so `--timestamp-ca`, like `--key`, should be pinned. While the row is here, the comparison with it catches the forgery as before.
- `AUDIT_TIMESTAMP_CA_FILE` must keep the CA of every TSA ever used, or the archive check fails as `untrusted` after a change of TSA. The ops guide says so.
- No revocation check: like the in-database check, it reads no CRL or OCSP.
- Later, if asked: gzip of archive objects.
