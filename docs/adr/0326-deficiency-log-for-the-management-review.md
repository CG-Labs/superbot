# 0326: A deficiency log for the management review

## Status

Accepted (26 Nov 2026). A slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds a command to `superbot-evidence` ([ADR 0148](0148-change-management-evidence-from-github.md)) that reads the evidence store as the coverage report does ([ADR 0169](0169-evidence-coverage-report.md)), and the results bundles of control testing ([ADR 0296](0296-control-testing-samples-from-the-evidence-store.md)). Serves readiness checklist rows CC4.2-1 (deficiencies reported to management and fixed) and CC1.2-1 (the quarterly management review), and the "Management review" section of the draft [information security policy](../security/policies/information-security.md#management-review). No certification is claimed: SuperBot is not SOC 2 certified, no audit has started, no observation period has begun, and the policies are drafts until they are adopted.

## Context

Each bundle in the evidence store lists its exceptions: the change-management bundle the pull requests merged without an approval, the vulnerability bundle the alerts overdue, the register bundle the access reviews late, the roles unfilled, the policies not approved, and so on, 23 files in seven kinds of bundle, each month. The results bundle of control testing adds the deviations. CC4.2 asks that deficiencies are communicated to those responsible for corrective action, including management, in time; the information security policy asks for a quarterly management review of open checklist items, risks, incidents, vulnerabilities, access reviews, drills, vendors and exceptions.

Nothing brought those lists together. A security owner preparing the review had to open every bundle of the quarter, copy out each exception, and work out by hand whether last month's was still there this month: an item is listed again each month while it stays open, and no longer once it's put right. Nobody could show the review what it had been told, or what had changed since the last one. CC4.2-1's evidence ("tracker of findings with severity, owner and due date; closure records") had, for the bundles' own findings, nothing but the bundles.

## Decision

### `superbot-evidence deficiencies`

`superbot-evidence deficiencies <evidence store> [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [--checklist <soc2-readiness-checklist.md>] [--results <results bundle>]... [--since <previous log>] [-o <file>]` reads every bundle in the store with the coverage report's scan, keeping only the manifest and the 23 files with exceptions, and every results bundle given. The period defaults to last month, like the other commands; for the quarterly review it is the quarter.

**Findings.** Every item of every exception list, in every bundle that checks against its digests and whose period overlaps this one, is a finding. A finding is tracked by its source (the kind of bundle, or `audit-results`), its scope (the repository a change-management, vulnerability or drill bundle names; for a results bundle, the samples it tested, by their period and the first 16 hex digits of their manifest's SHA-256, so a later worksheet of the same samples replaces an earlier one, but results of samples drawn with another seed or size, which may not have drawn an item, never clear its deviation), file, list, and key. Bundles write an item as its id followed by its state in brackets (`CHG-2 emergency on hosting (made 2027-01-06, not reviewed, due 2027-01-08)`), so a string's key is what comes before its first ` (`, or before a `: ` that starts a date span (`Engineering lead: 2026-08-01 to 2026-09-01`), with a trailing ` to <the bundle's period end>` read as such (`none in the year to <period end>`): a condition that runs on from month to month is one finding, not a new one each month. Any other date is kept, as it names a record (`F-1 of hosting on 2026-08-01` is the same finding in August's bundle and September's). A number (a pull request) is its own key, and an object is known by its `id` or `number`, or else whole. Its id is the first 16 hex digits of the SHA-256 of all five, so the same exception has the same id in every log and the register can name it. A list that is `null` (the bundle couldn't judge it, as when GitHub refused the token) says nothing either way and is skipped.

**Still listed.** A finding is still listed when the newest bundle of its group (source, scope, file and list), by period and then by when it was made, lists it. botd's evidence bundles name no server, so for them every bundle of the latest period counts: one server's newest bundle can't clear another server's finding. A finding no longer listed was either put right or was about something past (a pull request merged without an approval stays a fact, but the next month's bundle is about the next month's pull requests); the log says so and leaves the register to say which.

**Owners.** With `--checklist`, each finding names the owners of the checklist rows its file serves (the evidence plan's rows, the same table the coverage report checks; for a deviation, its test's rows), and the log lists the checklist's open rows, those not `Done`, by owner. The checklist is read, never changed.

**Since.** With `--since`, the previous log (checked against its own digests) is compared by id: which findings it listed as still listed are still listed, which are no longer, and which are new.

**The store.** The log carries the coverage report's problems for the period, since a month without a bundle is a month with no findings, not a clean month, and it names the security owner as the store's owner.

It writes one bundle, `superbot-deficiencies-<from>_<to>-<UTC time>/`, manifest kind `deficiency-log`, in the shape of the others (private, never overwritten, `SHA256SUMS` and a manifest): `deficiencies.json` (the basis, a summary, each finding with its controls, owners, first and last listing and the bundles judged newest, the testing summaries, the store's problems, the comparison and the open checklist rows) and `deficiencies.md`, the same for the review's papers, with what is still listed grouped by owner. The manifest lists every bundle read by name, path and manifest digest, each results bundle and the previous log by manifest digest, and the checklist by SHA-256. It copies only what the bundles hold, which already leave out names, titles and notes. It exits 0 only when nothing is still listed and the store is complete for the period, and 2 otherwise, like the coverage report.

### Where it goes

The log is kept beside the store, with the review's minutes, like samples and results. It isn't added to the coverage report's kinds: it summarises the evidence, it isn't evidence of a control operating, and counting it would let a store look covered by its own summary.

### What it doesn't do

It doesn't invent a severity or a due date: the bundles' exceptions have none of their own (an overdue alert's due date is already in its item), and choosing them is the security owner's judgement. Each finding still listed is to be recorded in the [policy register](../security/policy-register.md) with a severity, owner and due date (as a risk, or as an `internal` vulnerability), or the reason it is accepted, where the register bundle then judges it against its deadline. It doesn't hold the review: CC1.2-1 stays a **Gap** until reviews meet and keep minutes, and CC4.2-1 stays **Partial** until the policy is approved and findings are tracked to closure. It lists what the bundles flagged, not every deficiency, and is not a SOC 2 opinion.

## Alternatives considered

- **A tracker in GitHub issues, opened by a workflow**: closures would be visible, but the register and its findings are private, and the evidence store is kept offline; issues on a public repository would publish them.
- **Keys of the whole item text**: simpler, but an item's text carries its state (`not reviewed, due 2027-01-08`), so every change of state would look like a finding put right and a new one.
- **Judging "still listed" against any bundle of the latest period**: simpler, but two register bundles made on different days of the same month (one before a fix, one after) would keep a fixed finding open. Only evidence bundles, which can't be told apart by server, are judged that way.
- **Severity by exception list**: a fixed table (an unfilled role High, a late access review Medium) would look authoritative and be wrong for half the cases; the register already holds severity for findings recorded there.
- **Changing checklist statuses from the log**: the statuses are a judgement of the whole row, kept by hand and counted by a test; the log only reads them.

## Tests

- Unit tests in `deficiencies.rs`: an item is tracked by its id, not its state, a condition that runs on keeps one key across months, and a date naming a record is kept even on the period's first or last day; a finding is still listed only while the newest bundle of its group lists it, and a later bundle without the list, or with a `null` list, doesn't clear it; bundles that don't check or don't overlap the period are left out; every evidence bundle of the latest period counts as newest; control-testing deviations are findings of their test's rows, a later worksheet of the same samples clears a deviation it no longer lists, results of other samples never do, and results that don't name their samples are refused; `--since` says what was put right and what is new; the Markdown groups what is still listed by owner; the bundle checks against its own digests; options are refused when repeated or unknown; every file with exceptions maps to its criteria and rows.
- `server/tests/deficiency_log.rs`: the real binary on a store of two months' register bundles made by `superbot-evidence register`, the second after an incident's review was recorded: `tar -xf` and `sha256sum -c`; the overdue review no longer listed and its late review still listed; an unfilled role one finding across both months, with the row and owner from the real readiness checklist; exit 2; no names or notes from the register in the log; the same store gives the same findings and ids, and `--since` the first log nothing new; then a results bundle's deviation is a finding of its test's row and owner; a samples bundle given as results, a results bundle given as the previous log, a results bundle given twice and a file that isn't the checklist are refused, writing nothing.

## Consequences

- The quarterly management review has a list of what the bundles flagged, who owns it, and what changed since the last review, made in one command from the store; the evidence plan's calendar adds it to the quarter.
- The register stays the tracker of record: the log's ids let a register entry name the finding it tracks, and the next log shows whether it is still listed.
- Findings are only as complete as the store: a month without a bundle of a kind has no findings of that kind, so the log carries the store's gaps and doesn't exit 0 while there are any.
- A new bundle file with exceptions needs adding to the coverage report's list of them (a unit test checks each maps to its controls).
