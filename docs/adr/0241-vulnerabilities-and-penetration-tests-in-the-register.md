# 0241: Vulnerabilities and penetration tests in the register

## Status

Accepted (24 Nov 2026). Twelfth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds `vulnerabilities` and `penTests` to the [policy register](../security/policy-register.md#vulnerabilities-and-penetration-tests) and an eleventh file, `vulnerabilities.json`, to the register bundle ([ADR 0204](0204-policy-register-checked-and-bundled.md)), which the coverage report ([ADR 0169](0169-evidence-coverage-report.md)) checks. Adds a yearly external penetration test to the draft [information security policy](../security/policies/information-security.md#vulnerability-management). Serves readiness checklist rows CC2.3-1, CC3.2-2 and CC4.2-1 in the [evidence plan](../security/soc2-evidence-plan.md#the-register-bundle).

## Context

The information security policy says vulnerabilities from any source (CI scans, reports under `SECURITY.md`, penetration tests, vendors) are tracked with a severity, an owner and a due date, and fixed or accepted within 30 days for Critical and High and 90 for the rest. Only the scans had evidence: the monthly vulnerability bundle judges every Dependabot and code scanning alert against those windows ([ADR 0086](0086-vulnerability-remediation-evidence.md)). The evidence plan said the rest "are still tracked by hand", the readiness checklist's CC2.3-1 asked for "a log of reports and responses" and CC4.2-1 for "a tracker for findings outside the scans", and CC3.2-2 (an external penetration test, with findings fixed) was a Gap with no rule for how often or what a retest is.

`SECURITY.md` already sets measurable targets for reports: acknowledged in 3 days, severity confirmed in 10, fixed in the policy's windows. An auditor samples the reports received in the period and asks for each step's date.

## Decision

### Vulnerabilities and tests in the register, by id only

The register gains two optional fields, so the register format stays `1` and existing registers still read:

- `vulnerabilities`: `id`, `source` (`report`, `pentest`, `vendor` or `internal`), `penTest` (for `pentest` only, and required for it), `incident`, `received`, `acknowledged` (for `report` only), `assessed`, `severity` and `owner` (together), `fixed`, or `accepted` and `acceptedBy` (together), `notes`.
- `penTests`: `id`, `vendor`, `reported`, `reportSha256`, `retested` and `retestSha256` (together), `notes`.

`incident` and `vendor` are optional links to ids the register already holds, checked when given: a vulnerability being exploited is an incident, and a tester is often a vendor, but neither is required. Scan alerts are not recorded here: the vulnerability bundle has them from GitHub, and recording them twice would let the two drift.

A register that doesn't hold together is refused, listing every problem: unknown ids, a source or severity not in the lists, `penTest` on another source or missing on `pentest`, `acknowledged` on anything but a report, half of a pair, both fixed and accepted, fixed or accepted before being assessed, one assessed as `none` that is also fixed or accepted, dates out of order, a digest that isn't SHA-256 hex. The register holds no reporter, tester, customer or affected component: those stay in the private GitHub security advisory and the tester's report, which `reportSha256` points to.

### The policy's windows, from the day received

Deadlines are calendar days from `received`, as `SECURITY.md` states its targets, not business days as the incident plan's are. The fix windows are `vulns::Windows::default()`, the same values the vulnerability bundle uses, so the two bundles can't disagree on what 30 days for High means. A vulnerability not yet assessed is held to the shortest window (the bundle's `unknown`), so leaving one unassessed can't buy time. One assessed as `none` (not a vulnerability) is closed by the assessment and needs no fix.

Acknowledgement is checked only for reports: a penetration test, a vendor's advisory or the provider's own finding has nobody to answer. `SECURITY.md`'s 14-day updates and 90-day disclosure are left to the advisory, which records them.

### Who may accept

The policy says vulnerabilities are "fixed or accepted with a reason" and that management accepts risks above the appetite. An accepted vulnerability is a risk kept, so `acceptedBy` must hold or deputise Security owner or Management on the day, checked by role like every other approval in the register (`accepterNotInRole`). The reason goes in the advisory or the risk register; the register's `notes` never reach the bundle.

### A yearly penetration test, and retests of its fixes

The evidence plan's calendar already listed a yearly penetration test, but no policy required one. The information security policy now does: an external test at least yearly, the first within a year of the policy's first approval, its Critical and High findings retested within 30 days of the last of them being fixed. The bundle flags `noPenTest` when none was reported in the year to the period's end and the first is due. A retest is due only once every Critical and High finding of the test is fixed or accepted, 30 days after the last fix; a retest before that last fix doesn't count, since it can't have tested it (`retestOverdue`, `retestLate`). Accepted findings need no retest. Medium and Low findings are held to their fix windows but not to a retest, which testers usually charge for.

### `vulnerabilities.json`

A new file in the register bundle, judged as of the period's end like the rest: the information security policy's latest approval, the last test and when the next is due, and the windows; every vulnerability received before the period's end and not finished before it (a report is finished once both closed and acknowledged), with each due date and step, its severity and owner role, and who accepted it with the role they held; the tests in the year, or with a retest pending, with their digests, finding counts, retest due date and whether the retest covers the fixes; counts by severity and source; and the exceptions `notAcknowledged`, `acknowledgedLate`, `notAssessed`, `assessedLate`, `fixOverdue`, `closedLate`, `accepterNotInRole`, `noPenTest`, `retestOverdue`, `retestLate`. As in [ADR 0223](0223-incidents-in-the-register.md), something done late is flagged in the bundle of the period it was done in, and something overdue in every bundle until done.

### Coverage that can lapse

The manifest maps `vulnerabilities.json` to CC2.3-1 and CC4.2-1 while the information security policy is in the policy set and approved within a year, and to CC3.2-2 while a penetration test was reported within the year. A month with no reports is normal, so the vulnerability rows don't need one; the policy's approval is what makes "nothing reported" a statement under a policy in force rather than an empty file. A year without a test is a gap for CC3.2-2 as well as an exception.

### Older bundles still verify

The register bundle's manifest format goes from 4 to 5, and `register::SINCE_FORMAT` names format 5 as the one that added `vulnerabilities.json`. A format-4 bundle without it still verifies, a format-5 bundle without it fails, and its exceptions are counted like the other files'.

## Consequences

- CC2.3, CC3.2 and CC4.2 have monthly evidence for vulnerabilities outside the scans and for the penetration test once the policy is adopted and the register is kept. No status moves: CC2.3-1 and CC4.2-1 stay Partial until the policy is approved and private vulnerability reporting is turned on, and CC3.2-2 stays a Gap until a test is done.
- The security owner records each report, finding and test in the register, and keeps each tester's report and retest letter in the store.
- The bundle shows the records were kept and hold together, not that every report was recorded. The auditor compares it with the repository's security advisories and the tester's report, which `reportSha256` points to.

## Not done

- Reading GitHub security advisories or private vulnerability reports through the API: they need an admin token and hold reporters' details; the register stays the one place they are recorded.
- `SECURITY.md`'s 14-day updates to reporters and 90-day coordinated disclosure.
- Linking a vulnerability to a risk in the risk register, or an accepted one to an acceptance end date.
- Commissioning the penetration test itself, which costs money and needs a tester.
