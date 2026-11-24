# 0227: Gzip for the audit export

## Status

Accepted (24 Nov 2026). Eleventh slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the SIEM export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)), the write-once archive and its checks ([ADR 0154](0154-write-once-s3-audit-archive.md), [ADR 0163](0163-checking-the-audit-archive.md), [ADR 0183](0183-daily-check-of-new-archive-objects.md)), several SIEMs ([ADR 0191](0191-several-siems-with-their-own-headers.md)), self-checking lines ([ADR 0199](0199-self-checking-audit-lines.md)) and the Azure Monitor sink ([ADR 0217](0217-audit-export-to-azure-monitor.md)). ADRs 0199, 0207 and 0217 left gzip for later.

## Context

Audit lines are JSON with long repeated keys and hex hashes. They compress about tenfold. Today every byte goes out and is kept uncompressed:

1. **The archive is kept for years.** A compliance archive is often locked for seven years, in a store that charges per GB per month, and Object Lock means nobody can delete anything early to save money. A 10,000-event object is a few MB of JSON lines.
2. **Every SIEM batch crosses the network uncompressed.** Splunk HEC, Elastic `_bulk`, Vector, Logstash's `http` input, Datadog and Azure's Logs Ingestion API all take `Content-Encoding: gzip`. Egress and ingestion endpoints often charge or throttle by bytes on the wire.
3. **The checks read what was written.** The archive check (by hand and daily) and `botctl audit verify-lines` must read compressed objects as well as plain ones, since an archive turned to gzip holds both, and must not be fooled by a gzip bomb or by bytes hidden after the gzip.

Constraints: Rust only, no new dependencies (`flate2` is already used); off by default, so keys and bodies that downstream tools read stay as they are; the chain, the lines and the checks don't change; a retry still writes the same object.

## Options

**What the archive's objects are**

1. **Plain `.jsonl` with `Content-Encoding: gzip`.** The key stays the same. But clients disagree on that header: some (browsers, `curl --compressed`, some SDKs) undo it on the way down and some don't, so a download can be either.
2. **`.jsonl.gz` objects, `Content-Type: application/gzip`, no `Content-Encoding`.** Every client gets the same bytes, and the key says what they are. Athena, Splunk's S3 input and `zcat` all go by the `.gz`.

**How the check compares versions**

1. **Byte for byte**, as for plain objects. A retry after a botd upgrade could gzip the same lines into other bytes, and show as `overwritten`.
2. **By what they hold**: gunzip each version and compare the lines.

**How SIEM compression is set**

1. **One setting for everything**, the archive included. Simple, but turning on gzip for a SIEM would change the archive's keys too.
2. **`AUDIT_EXPORT_COMPRESS` for SIEM bodies, `AUDIT_EXPORT_S3_COMPRESS` for the archive**, with `AUDIT_EXPORT_COMPRESS_<NAME>` for a named SIEM, like `AUDIT_EXPORT_START_<NAME>`.

## Decision

Option 2 each time.

- **Archive.** `AUDIT_EXPORT_S3_COMPRESS=gzip` (default `off`) writes each batch as `<prefix>/<yyyy>/<mm>/<dd>/<first id>-<last id>.jsonl.gz`, a single gzip member of the same JSON lines, with `Content-Type: application/gzip`. Metadata, the lock, the checksum and the read-back are as before; the checksum and `bytes` are the stored object's. The status's `lastObject` adds `uncompressedBytes`, and `archive.compress` shows the setting. A retried batch has the same key.
- **Archive check.** Keys ending `.jsonl` or `.jsonl.gz` are botd's. A `.gz` object's body is gunzipped before anything else, all members, and must be gzip to its last byte. It may hold at most 256 MB uncompressed, the same limit as a plain object: past that, or anything that isn't gzip, makes it `unreadable`. A plain key holding gzip isn't JSON, so it is unreadable too. Versions of one key are compared by their gunzipped lines, so a retry that compressed differently counts as `retried`, not `overwritten`. An archive switched to gzip part way holds both kinds of key, and the chain runs across them. A batch cut before the switch and retried after it is written to the `.gz` key with the same ids, so its events show as `repeated`, as any restarted batch's do.
- **SIEMs.** `AUDIT_EXPORT_COMPRESS=gzip` (default `off`) gzips every webhook and Azure Monitor request body and adds `Content-Encoding: gzip`. A named sink's `AUDIT_EXPORT_COMPRESS_<NAME>` (`gzip` or `off`) overrides it for that sink. Azure's 1 MB applies before compression too, so Azure bodies are cut at 1 MB first and then compressed. Syslog has no compression in RFC 5425: `AUDIT_EXPORT_COMPRESS_<NAME>=gzip` for a syslog sink stops botd, and so does `AUDIT_EXPORT_COMPRESS=gzip` when no sink could take it. So does `AUDIT_EXPORT_COMPRESS_<NAME>` naming the archive, which points to `AUDIT_EXPORT_S3_COMPRESS`. `botctl audit siem` shows `compress` for each sink, and the startup line says which are gzipped.
- **Offline.** `botctl audit verify-lines` reads gzip wherever it finds it: files whose bytes start as gzip, whatever their name; `.jsonl.gz`, `.ndjson.gz`, `.json.gz` and `.log.gz` files in a directory; and stdin, so `cat audit/*/*/*/*.jsonl.gz | botctl audit verify-lines -` works, many members after one another. A cut or damaged gzip stops the check and names the file, and so does one that unpacks past `--max-gunzip-mb` (default 4096 MB, well over an archive object's 256 MB), so a small crafted file can't fill the operator's memory. Names that aren't UTF-8 are matched by their suffix, not skipped.

## Consequences

- An archive with gzip on needs about a tenth of the storage, for as long as it's locked. SIEM batches use about a tenth of the bandwidth.
- Nothing about tamper evidence changes. The lines, hashes, digests, checkpoints and timestamps are the same bytes once gunzipped, and every check reads them the same way.
- Turning on archive gzip changes its keys from then on. Tools that list `*.jsonl` must also take `*.jsonl.gz`. It's off by default for that reason, and for collectors that don't take `Content-Encoding: gzip`.
- A collector that doesn't take gzip answers an error (often 400 or 415), which shows as a failing export like any other. Turn compression off for that sink.
- Compressing costs botd some CPU: one `flate2` pass at the default level, on at most 200 events for a SIEM and 10,000 for the archive.
- Later, if asked: other SIEMs' native APIs (Google SecOps, Datadog), and zstd once stores and collectors take it widely.
