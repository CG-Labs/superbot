# 0330: The audit export holds back pinned people's audit details from sinks outside their region

## Status

Accepted (26 Nov 2026). A slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Follows [ADR 0316](0316-audit-details-in-the-regional-store.md) (audit details in the regional store) and [ADR 0321](0321-events-about-a-pinned-person-in-their-store.md) (events about a pinned person), which left the SIEM export and the write-once archive on #58's list, and builds on the export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md), [ADR 0173](0173-an-archive-alongside-a-siem.md), [ADR 0191](0191-several-siems-with-their-own-headers.md)), its digests ([ADR 0199](0199-self-checking-audit-lines.md)) and the archive ([ADR 0154](0154-write-once-s3-audit-archive.md)). 0330 was reserved for this work.

## Context

After ADR 0316 and ADR 0321, a pinned person's IP addresses, browsers, names, sessions and what changed are kept in their region's chat store, and botd's own log holds only each event's sealed row. But the export reads the log whole, through the view that joins each row to its details, and sends every event whole to every sink in `AUDIT_EXPORT`. A London customer's audit details then go to a SIEM in the US, or to an archive bucket anywhere, and a pin's report could only say so in general.

The export's lines check themselves (ADR 0199): the fields no erasure may change, `chainPrev` and `chainDigest` give `chainHash`, and with `chainSalt` the fields an erasure may rewrite give the digest. An erased event already goes without its salt and is still bound by its fixed fields. So a line can lose its erasable fields and still sit on the chain.

## Options

1. **Say so in the report and leave it.** It is what a pin's report already did, and the gap a customer is most likely to ask about after ADR 0316.
2. **Leave pinned people's events out of the export.** A SIEM's chain would have holes, the export's in-order, every-event delivery and the archive's check would break, and a SOC would lose the fact that something happened.
3. **A sink per region, each getting only its region's events.** The export's cursors, retention and status are per sink; splitting the log across them would need a chain per region.
4. **Every sink gets every event; one outside the region gets the sealed row** (chosen). It is what botd's own log holds for that event (ADR 0316), so the line still gives its hash and still links the chain.

## Decision

### Where a sink is

The operator says which data region each sink keeps what it gets in: `AUDIT_EXPORT_DATA_REGION` for every sink, and `AUDIT_EXPORT_DATA_REGION_<NAME>` for a named one, which wins (`off` takes the server-wide one away). botd can't see where a SIEM or a bucket is, so this is the operator's word, as `SERVER_DATA_REGION` is (ADR 0184). A region id is lowercase letters, digits and inner dashes. It needn't be one of `MACHINE_REGIONS`: a SIEM in a region botd has no machines in is what the setting is for.

Not stated, a sink gets every event whole, as before. This keeps upgrades unchanged, and a pin's report lists such a sink as not covered.

### What a sink gets

An event whose details a region's chat store keeps (botd's row says `{"inChatStore":"<region>"}`) goes whole to a sink stated to be in that region. To a sink stated to be anywhere else it goes as its sealed row: the fields an erasure may rewrite empty but `details`, which names the store, and no `chainSalt`. Its `chainDigest` still goes, so the line gives its hash from its fixed fields, as an erased event's does (`botctl audit verify-lines` counts it as bound to them). Events whose details are in botd's own log go whole everywhere, as before, including those of people pinned to a region with no store: their details aren't held in the region in the first place.

Which events are held back is read from botd's rows, not worked out again from pins, so the export follows exactly where the details are at the time of the batch. A pin, unpin or move after an event is sent changes nothing already sent.

### The archive

A retried archive batch must be the same object (ADR 0154): a later version that differs is reported as overwritten. So when the export cuts an archive batch it records which of its events it holds back, with the region named, in a table of botd's own (`audit_export_held`), in the same transaction as the batch's last id. A retry, after a restart too, holds back exactly those, whoever has moved since. A cut that couldn't be saved sent nothing, so the batch is cut again. A batch cut before this change has no record, and went whole on its first try, so its retries go whole too: on the upgrade, at most that one batch reaches an archive outside the region whole.

The archive's check compares each archived event with this server's row. An event the archive holds only the sealed row of is held to the fields no erasure may change, as an erased one is, and counted as `heldBack`, only when botd's record says it sent that event sealed, naming that region. A line that only looks sealed is held to every field: someone who can replace an object can't strip an event's details and keep its hash, which the line still gives from its fixed fields, and pass. Retention deletes the record with its event.

### Saying so

- `GET /api/audit/siem`, `botctl audit siem` and the startup line give each sink's `dataRegion` and how many events it has been sent as sealed rows since botd started (`heldBack`).
- A pin's residency report gets an `auditExport` section: each sink by name and kind (never its address), its stated region and whether it gets their events whole, held back, or `partly`: held back but for the events whose details are still in botd's own database (a move into the store that failed or hasn't run yet; the report's chat section counts them), which go whole. The report reads that from where the details are, not from the store being there. What the pin doesn't cover lists the sinks that get them whole and aren't stated to be in the region, in place of the general line ADR 0316 added, and how many go whole to those `partly`.
- The DPA template's annex IV, the data flows page and the ops guides say the same.

## Consequences

- With each sink's region stated, a pinned person's audit details reach only sinks in their region. Sinks elsewhere still see that each event happened, its kind and outcome, and hold the chain.
- A SOC outside the region can't see who did what for pinned people. It can still alert on kinds and outcomes, and ask the region's SIEM, or botd, for the details.
- With the archive's region stated elsewhere, the archive no longer holds pinned people's details, so they can't be recovered from it once the store and its backups lose them.
- A sink whose region the operator changes doesn't resend what it already got.

## Not done (still on #58)

- Accounts and `usage_daily` stay in botd's own database. A pin's report says so.
- An event a pinned person makes about someone pinned in another region stays in the first person's store, and goes whole only to sinks in that region.
- A pinned person whose region has no chat store has their audit details in botd's log, which the export sends whole everywhere.

## Tests

- `audit_export`: a sink's region is its own, else the server-wide one, `off` taking it away, and a bad id stops botd; the startup line names it; an event's sealed row has every erasable field empty but `details`, keeps its fixed fields and digest, and drops its salt.
- `audit_archive_verify`: an archived sealed row botd recorded sending is held to its fixed fields only; one botd sent whole, or recorded under another region, and a line that isn't one (an actor left, more details, a region that isn't text), are held to all of them.
- `db`: an archive batch's cut records what it holds back with it, only the batch's own events, per sink; a batch cut before has no record; cutting again replaces what wasn't delivered; retention deletes the record.
- `db::chats`: botd's rows say which events a store keeps, from one store to another, and none once unpinned.
- `residency_report`: sinks that get events whole outside the region are not covered, held back or in the region they are, those held back but for events still in botd's database say how many, and the Markdown names what each gets.
- HTTP (`machines_residency_tests.rs`): with London's store, a pinned person's event goes whole to London's SIEM and to one with no stated region, and as its sealed row to a US SIEM and the archive, whose lines still check; events in botd's log go whole everywhere; `GET /api/audit/siem` counts what it held back; the archive still checks against the log, and a copy of a batch with an event botd sent whole stripped to look sealed fails as `contents`; the report names each sink and lists only the one with no stated region as not covered.
