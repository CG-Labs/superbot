# 0169: Evidence coverage report over the evidence store

## Status

Accepted (23 Nov 2026). Fifth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds a third command to `superbot-evidence` ([ADR 0148](0148-change-management-evidence-from-github.md)) that reads the bundles the earlier slices make: botd's evidence bundles ([ADR 0142](0142-type-ii-evidence-bundles.md)), the change-management bundles (ADR 0148) and the vulnerability bundles ([ADR 0086](0086-vulnerability-remediation-evidence.md)). Serves the [evidence plan](../security/soc2-evidence-plan.md#checking-the-stores-coverage)'s monthly calendar and its dry run before the observation period.

## Context

Three tools now make monthly bundles, on three schedules (botd's own timer, a GitHub workflow, an operator by hand), and the operator copies each to an evidence store. A Type II auditor samples days and months from the whole observation period, so what matters is that **no day is missing and no file changed** after it was collected. Today nothing checks that:

- A month can be lost without anyone seeing: botd's schedule is off on one server, the workflow's artifact expired before it was copied, a bundle was made for the wrong dates.
- `sha256sum -c SHA256SUMS` checks one unpacked bundle at a time, and doesn't notice a file added beside the others, a `SHA256SUMS` rewritten to match an edit, or a manifest whose period disagrees with its name.
- Which [readiness checklist](../security/soc2-readiness-checklist.md) rows have automated evidence at all, and for how much of the period, is spread over three tables in the plan.

The plan's first step before the period starts is a dry-run month "then fix what was hard to collect". That needs a way to see what is missing.

## Decision

### A command that only reads

`superbot-evidence coverage <evidence store> [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [--checklist <file>] [--json] [-o <file>]`, in the same binary, sharing its period rules and digests. It needs no token and makes no network request, and it never writes into the store: the report goes to stdout, or with `-o` to a new private file (never over one), with its SHA-256 printed so it can be filed like a bundle.

Inside the existing binary rather than `botctl` or botd: the store is outside every server, holds bundles from GitHub as well as from botd, and is read by the security owner, who already runs `superbot-evidence`. botd knows only its own bundles.

### Finding bundles

The store is searched to a depth of 8 (the plan's layout is `<criterion>/<month>/`). A bundle is a `.tar` as made, or a folder unpacked from one, whose single top folder is named `superbot-evidence-`, `superbot-changes-` or `superbot-vulns-` followed by `<from>_<to>-<UTC time>`; the name, not the file name, gives its kind and period, since operators rename files. Hidden files (botd's partial writes) are skipped; other tars and files are counted as passed over, not errors. The tar reader takes the ustar the tools write and what GNU or BSD `tar` writes when a bundle is unpacked and packed again (directory entries, `./` names, long names in pax or GNU headers), refuses links and devices, checks each header's checksum, and refuses a tar over 256 MiB.

### Checking each bundle

A bundle **checks** only if all of these hold; each failure is listed, with the file:

- `SHA256SUMS` exists, every line in it names a file that exists with that digest, and every other file is listed in it (a file added later fails).
- `manifest.json` is SuperBot's, its `kind` is the one the name says (botd's has none), it has a `format` and `createdAt`, and its period is the name's.
- Every file the manifest lists exists with the manifest's digest, and every file other than the manifest and `SHA256SUMS` is listed in it. So an edit with `SHA256SUMS` rewritten to match still fails, unless the manifest is rewritten too, which changes the manifest's own digest; the report prints that digest for each bundle, to compare with what was recorded when it was made (botd's `evidence.bundle_created` event, the workflow's summary).
- Every file its kind always has is there (for botd's, the six in the evidence plan's table; for the others, their tools' `SECTIONS`).

Warnings, which don't fail a bundle: a format newer than the tool knows, a bundle made before its period ended (its last events may be missing), and one made more than 7 days after it (its snapshots, such as the access review, are of then, not of the period). The exception lists in `pull-requests.json` and `vulnerability-alerts.json` are counted per bundle, as the first thing an auditor samples.

### Coverage

For the period (given, or from the first bundle that checks to the last; whole UTC days, `to` not included, at most 400 days, as for the bundles), a day counts:

- **for a kind of bundle** when a bundle of that kind that checks covers it;
- **for a checklist row or a criterion** when a bundle that checks covers it and its manifest maps one of its files to that row or criterion.

The rows and criteria each kind is expected to cover are always listed, so a kind with no bundles at all shows as gaps rather than disappearing. The report shows each kind month by month (complete, partial, missing) with its gaps as date ranges, each row and criterion with its days covered, gaps and the kinds that feed it, and every bundle with its period, manifest digest, whether it checks and whether it is in the period. With `--checklist` (the readiness checklist's Markdown), it also lists the rows no bundle collects evidence for, with their status, and warns about rows a bundle names that the checklist doesn't have. The checklist is read at run time, not built in, so the report follows the copy the operator has and the binary doesn't embed docs.

The report is **complete** when every bundle found checks and every kind covers every day. It exits 0 when complete, 2 when not (the report is still printed), and 1 on an error, so a scheduled job can alert on it. Markdown by default, for the store and the management review; `--json` for tools.

What it doesn't do: judge the evidence. A complete report says evidence was collected for each day and not changed since, not that the controls worked; the report says so.

## Alternatives considered

- **A shell script around `sha256sum -c`**: checks digests, but misses added files, rewritten sums and manifests, and can't say which rows or days are missing.
- **botd checking its own `EVIDENCE_DIR`**: one schedule, and a console view, but botd can't see the GitHub bundles or the store, and a server checking evidence about itself is weaker evidence.
- **Building the checklist into the binary**: no `--checklist` flag, but the `Dockerfile` builds every binary without `docs/`, and every new checklist row would need a release of the tool.
- **Checking each manifest's digest against botd's audit log**: stronger, but needs a credential for every server in the store; the report prints the digests to compare instead.

## Tests

- Unit tests in `coverage.rs`: a bundle checks; each kind of tampering fails it with its reason (a changed, missing or added file; a file changed with `SHA256SUMS` resealed; a file added and resealed; a manifest with the wrong period, kind or product, without a format or creation time, or leaving out a file; a missing expected file); a newer format and a late bundle only warn; names give kind and period, and malformed ones don't; real change-management and vulnerability bundles from their own `build` check; tars as written and as packed again by `tar` (`./`, directory entries) read, and damaged, cut-short, link and two-folder tars don't; gaps and months; a report over three months with one kind missing two months and a tampered bundle lists exactly those problems, the right month grid, row and criterion coverage, the rows with no automated evidence, exceptions, and a complete report for a covered month; options and the default period; rows read from the real checklist; botd's kind matches the evidence plan's table and botd's format and prefix.
- `server/tests/evidence_coverage.rs` starts the real botd, downloads two months of evidence bundles, keeps one as its tar and unpacks the other in the plan's folders beside a note and a partial file, and runs the real binary: both check with the manifest digests botd sent, botd's kind and its rows are complete, the two kinds not there are each one gap over the period, the rows without automated evidence include CC1.1-1, and the store is unchanged; one byte appended to a file fails that bundle and opens exactly its month as a gap; with no dates the period is the bundles' span; a Markdown report saved with `-o` is private and never overwritten; exit codes 2 and 1.

## Consequences

- No checklist row changes status: the report checks that evidence was kept, it isn't a control. It makes the plan's dry-run month measurable: run it until it is complete.
- The three bundle formats are now read by a tool, so changing one's file names, manifest fields or folder name needs this command updated in the same change; the tests that build real bundles catch it for the GitHub bundles, and the end-to-end test for botd's.
- The report names bundles by their path in the store and lists their digests, periods and exception counts; it holds nothing from inside them, so it is no more sensitive than the store's listing.

## Deferred

- Checking each botd bundle's manifest digest against its `evidence.bundle_created` event automatically.
- Coverage for evidence that isn't a bundle (Alertmanager exports, drill artifacts, run logs).
- A console view of botd's own `EVIDENCE_DIR` coverage.
