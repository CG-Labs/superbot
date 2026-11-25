# 0296: Control-testing samples from the evidence store

## Status

Accepted (25 Nov 2026). A slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds two commands to `superbot-evidence` ([ADR 0148](0148-change-management-evidence-from-github.md)) that read the evidence store as the coverage report does ([ADR 0169](0169-evidence-coverage-report.md)), and the populations the change-management, vulnerability, register, alerts and evidence bundles already hold ([ADR 0086](0086-vulnerability-remediation-evidence.md), [ADR 0142](0142-type-ii-evidence-bundles.md), [ADR 0204](0204-policy-register-checked-and-bundled.md), [ADR 0288](0288-alert-history-evidence-from-prometheus.md)). Serves readiness checklist row CC4.1-1 and the dry run the [evidence plan](../security/soc2-evidence-plan.md#testing-samples) asks for before the observation period. No certification is claimed: SuperBot is not SOC 2 certified, no audit has started and no observation period has begun.

## Context

A Type II auditor tests a control by drawing a sample from its population for the period (every change, every access grant, every day's backups) and checking each item drawn against the control. The evidence store now holds most of those populations, checked against their digests and covered day by day, but nothing turned them into samples. CC4.1-1 (an independent evaluation of the controls) was a **Gap** with no tool behind it, and the evidence plan's last step before the period ("agree the sample sizes with the auditor") had nothing to practise on: a security owner wanting to test a quarter's controls as an auditor would had to pull lists out of nine files in five kinds of bundle by hand, decide the sizes, pick items with no record of how, and keep the results in a spreadsheet nobody could check later.

Three things make a sample worth having. Its population must be complete, or the sample says nothing about the items left out. Its selection must be re-performable, so nobody can be suspected of picking the items that pass. And its results must be tied to the exact sample, so a worksheet can't quietly drop an item that failed.

## Decision

### `superbot-evidence sample`

`superbot-evidence sample <evidence store> [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [--seed <text>] [--size <test>=<n>]... [-o <file>]` reads every bundle in the store with the coverage report's scan, keeping only the files the tests read, and gathers nine populations, each from the bundles of one kind that check against their digests:

| Test | From | Items | Checklist rows |
|------|------|-------|----------------|
| `merged-pull-requests` | change-management `pull-requests.json` | merged in the period, by number | CC3.4-1, CC8.1-1, CC8.1-2 |
| `production-changes` | register `production-changes.json` | made in the period, by id | CC8.1-2 |
| `access-grants` | register `access.json` | granted in the period, by person, system, level and day | CC6.2-2 |
| `access-reviews` | register `access.json` | done in the period, by system and day | CC6.1-2, CC6.3-2 |
| `security-events` | register `incidents.json` | detected in the period, by id | CC7.3-1, CC7.4-1, CC7.4-2, CC7.5-1 |
| `reported-vulnerabilities` | register `vulnerabilities.json` | received in the period, by id | CC2.3-1, CC4.2-1 |
| `closed-vulnerability-alerts` | vulnerability `vulnerability-alerts.json` | closed in the period, by source and number | CC4.2-1, CC7.1-2 |
| `pages` | alerts `alerts.json` | episodes of severity `page` that started in the period | CC7.2-1 |
| `backup-days` | evidence `backups.json` | each day of each evidence bundle's period, by bundle and day | A1.2-1 |

An item listed in more than one bundle (a register change carried in two months' bundles) is taken from the newest, and bundles of later periods are read for items dated in the period: a register bundle carries a change, grant or finding still open at its start, with its later state (a January change checked in February is in February's bundle with its check), while only bundles overlapping the period count towards its days. A population is **complete** only when bundles of its kind cover every day of the period and none that could hold its items failed its digests or lacked the file; a tar too damaged to tell its kind counts against every population; otherwise the samples list the missing days, the failed bundles and those without the file. An incomplete population is still sampled, since part of it can be tested, but it is never mistaken for the whole.

Each item is copied with the fields needed to find and test it (a pull request's number, url, author, merger, approvers and whether its checks passed; a change's record digest, approver and dates), never a title, note or name: the bundles already leave those out, and the samples are a subset of the bundles, not new evidence.

**Sizes** follow a table by population, standing in for how often the control runs, as auditors commonly size samples: 1 of a population of 1 (yearly), 2 of up to 12 (quarterly or monthly), 5 of up to 52 (weekly), and 25 of more (daily or per event), never more than the population. `--size <test>=<n>` sets what the auditor agrees instead, and the bundle records which was used. These are a starting point for the conversation with the auditor, not a claim about what any auditor will accept.

**Selection** ranks every item by `SHA-256("<seed>\n<test>\n<item>\n")` and takes the lowest ranks. Anyone with the store and the seed can draw the same sample with `sha256sum`. The default seed is the SHA-256 of `superbot-samples`, the period and each population's own SHA-256 (of its sorted item ids), so the same store always gives the same sample, and choosing different items means changing the evidence, which its digests show. `--seed <text>` takes the auditor's seed instead, recorded as given.

It writes one bundle, `superbot-samples-<from>_<to>-<UTC time>/`, manifest kind `audit-samples`, in the change-management bundle's shape (private, never overwritten, `SHA256SUMS` and a manifest): `samples.json` (the basis, seed, sizes, each population's size, digest, bundles and gaps, and each item drawn with its rank, bundle and fields) and `worksheet.csv`, one line per item drawn with what to check and empty columns for the tester. The manifest lists every bundle read by name, path in the store and manifest digest.

### `superbot-evidence results`

`superbot-evidence results <samples bundle> <worksheet.csv> [-o <file>]` reads the samples bundle (a `.tar` or its folder), checks it against its own `SHA256SUMS` and manifest, and reads the worksheet: RFC 4180 CSV, columns by name, a byte-order mark allowed (spreadsheets add one). Each recognised column must appear once, and every line must be an item the bundle drew, at most once, with a `result` of `pass`, `fail` or `n/a`, a `tester` who is a plain register id, a `tested_on` day not in the future, and a plain `reference` (a ticket id, URL or SHA-256). A worksheet that doesn't hold together is refused with every problem listed, and nothing is written.

It writes `superbot-results-<from>_<to>-<UTC time>/`, kind `audit-results`, with `results.json`: each item's result, tester, day and reference; each test's counts and a conclusion in words; and the exceptions: deviations, deviations with no reference, items not tested, items marked not applicable, items tested before the samples were drawn, and the populations that were incomplete. The manifest names the samples bundle by its manifest digest and the worksheet by name, size and SHA-256; the worksheet's notes stay out, as people write names in notes. It exits 0 only when every item was tested, none deviated and every population was complete, and 2 otherwise, like the coverage report, so a clean run means something.

### Where they go

Neither kind is added to the coverage report: they are tests of the evidence, not daily evidence of a control, and counting them would let a store look covered by its own samples. They are kept beside the store, with the filled-in worksheet. Deviations are deficiencies, recorded in the [policy register](../security/policy-register.md) with an owner and due date and evaluated under CC4.2.

### What it doesn't do

It doesn't judge any item: the check column says what to look at, and a person looks. It doesn't make the tester independent: CC4.1-1 stays a **Gap** until someone who doesn't run the controls tests them, or a readiness assessor does. Exceptions the bundles already flag (a pull request without an approval, an access review late) are reviewed in full, not sampled. Results that pass say the items drawn passed; only an auditor concludes whether a control operated effectively.

## Alternatives considered

- **A random sample from the operating system's generator**: unbiased, but nobody can re-perform it, and a sample that can't be re-performed invites the question of whether it was drawn more than once.
- **Leaving sampling to the auditor's tools**: they will use their own in the audit. This is for the readiness assessment, the dry run and the operator's own quarterly testing, where there is no auditor yet, and an auditor can still re-perform it or use the populations it lists.
- **Sampling inside botd**: botd holds only the evidence bundle's populations; the change-management, vulnerability and register populations come from GitHub and the private register, which only the store brings together.
- **Copying each item whole into the sample**: simpler, but it would carry whatever fields a bundle adds later; the fields are listed per test instead, and a unit test checks no others are copied.
- **A spreadsheet file (`.xlsx`)**: richer, but needs a library to write and read, and a CSV opens in any spreadsheet and diffs as text.
- **Adding samples and results to the coverage report's kinds**: see above; they would count as coverage of the rows they test.

## Tests

- Unit tests in `sample.rs`: sizes follow the table and never exceed the population; populations come only from bundles that check, dated in the period, with the newest copy of each item, the listed fields only, pages only, and each day of an evidence bundle with that day's backup counts; a bundle changed after it was made is left out and makes its populations incomplete, and a damaged tar makes every population incomplete; later bundles give an item's newer state but no days; missing days are listed; the draw is reproducible from the store, re-performed from the ranks, changed by a given seed and by a different store, and sized by `--size`; the worksheet has a line per item drawn with empty result columns and no fields beyond those listed; CSV quoting round-trips; results count deviations, references, testers, untested and early items, and the worksheet is refused for items not drawn, duplicates, repeated columns, unknown results, testers that aren't register ids, future or missing days, references that aren't plain, and missing columns; each test reads a file its kind always has and names rows of its own criteria; the evidence plan's table matches the tests.
- `server/tests/control_testing_samples.rs`: the real binary on a store of two months' bundles made by `superbot-evidence register`: `tar -xf` and `sha256sum -c`, the same samples twice, the sample re-performed from the seed with SHA-256 alone, incomplete populations listed, no names or notes from the register in the bundle, a given seed and size; then a filled-in worksheet with a deviation gives exit 2, the deviation, the incomplete populations and the worksheet's digest without its notes; a worksheet naming an item not drawn and a samples bundle changed after it was made are refused, writing nothing.
- `coverage.rs`: the scan that keeps named files returns them unchanged.

## Consequences

- A security owner can test a quarter's controls on samples drawn from the store, with a record an auditor can re-perform, before an auditor is engaged; the evidence plan's calendar adds this quarterly, and its dry run includes it.
- CC4.1-1 still needs someone independent to do the testing: the tool lowers the cost of an internal audit, it isn't one.
- The populations are only as complete as the store: a month without a bundle of a kind makes that test's population incomplete, so the coverage report's gaps show up here too.
- A new bundle kind or file holding a population needs a new test in `TESTS`, a row in the evidence plan's table (a unit test checks they match), and a field list.
