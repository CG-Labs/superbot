# 0279: Vendors' assurance reports in the register

## Status

Accepted (25 Nov 2026). Sixteenth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds `assuranceReports` to the [policy register](../security/policy-register.md#vendors-assurance-reports) and checks them in the register bundle's `vendors.json` ([ADR 0204](0204-policy-register-checked-and-bundled.md)), bumping its format to 7. Writes the staleness rule the draft [vendor management policy](../security/policies/vendor-management.md#yearly-review) left open. Serves readiness checklist rows CC6.4-1 and CC9.2-1 in the [evidence plan](../security/soc2-evidence-plan.md#the-register-bundle).

## Context

SuperBot's managed service runs on a hosting provider and stores backups with an object storage provider. In a SOC 2 report those are subservice organisations, normally carved out: the service inherits their physical and environmental controls, and the auditor tests that the provider monitors them. The usual evidence is the provider's yearly review of each vendor's own SOC 2 report: which report (and the period it covers), what the vendor's auditor found, and how the provider meets the complementary user entity controls (CUECs) the report expects of its customers. That is CC6.4-1, and it was the one register-backed row whose evidence was only a date.

The register held vendors with an assessment and `reviewed` dates ([ADR 0204](0204-policy-register-checked-and-bundled.md)), and the bundle mapped `vendors.json` to CC6.4-1 whenever a hosting vendor had any review in the year. It could not show which report was read, whether that report still covered the vendor (a SOC 2 Type II period ending 14 months ago says little about now), whether the auditor's opinion was qualified or found deviations, or whether the CUECs were looked at. An auditor would ask for all of that.

## Decision

### Report reviews in the register, by digest

The register gains an optional `assuranceReports` list, so its format stays `1` and existing registers still read. Each entry is one review of one document: `id`, `vendor`, `kind` (`soc2-type2`, `soc2-type1`, `iso27001` or `questionnaire`), `coversFrom` and `coversTo` (a Type II's period, a Type I's date, a certificate's issue and expiry, the day a questionnaire was answered), `reportSha256`, `opinion` (SOC 2 only: `unqualified`, `qualified`, `adverse`, `disclaimed`), `deviations`, `risk` (the register risk that treats findings), `cuecsSha256` (the note of how the provider meets each CUEC), `bridgedTo` and `bridgeSha256` (a SOC 2 bridge letter), `reviewed`, `reviewedBy`, `notes`.

The documents stay in the evidence store; the register holds their SHA-256, so the bundle names no auditor and quotes no report. A register that doesn't hold together is refused, listing every problem: an unknown vendor, person or risk, a kind's wrong dates (a Type II without a start, a Type I with one), an opinion on anything but a SOC 2 report or a SOC 2 report without one, half a bridge letter or one on a non-SOC 2 document, a bridge that doesn't extend the period, and a review dated before the document existed.

A separate list, rather than fields on each vendor, because a vendor has a new report every year and the review history is the evidence. A report review also counts as the vendor's yearly review, so the keeper doesn't record the same act twice.

### What the policy says, made checkable

- **Every Critical and High vendor in use at the period's end has a report reviewed within a year** (`noAssuranceReport`). A questionnaire counts where a vendor has no report, as the policy allows.
- **The newest one still speaks for it** (`reportStale`): an ISO 27001 certificate not expired by the period's last day; a SOC 2 report whose period, or bridge letter, ended at most 92 days before the period's end. 92 days is the register's quarter: vendors issue reports yearly, a few months after their period, and a bridge letter covers the gap. The policy now says so. A questionnaire is held to the yearly review only.
- **A hosting provider's report is independent** (`hostingWithoutIndependentReport`): a SOC 2 Type II or ISO 27001. Its physical controls are inherited; a vendor's own answers are not an auditor's. A Type I is not enough for a Type II audit, since it says nothing about operation over time.
- **Each review holds up**, judged in the month it was made: by someone holding or deputising the Security owner or Management role (`reviewerNotInRole`); a SOC 2 report with its CUEC note (`cuecsNotNoted`); a modified opinion listed for sampling (`opinionNotUnqualified`); deviations or a modified opinion treated by a risk (`findingsWithoutRisk`), as the policy's "findings go in the register" asks.

### Coverage that can lapse

The manifest maps `vendors.json` to CC6.4-1 only while every Critical or High hosting vendor in use at the period's end has an independent report reviewed in the year that still speaks for it and holds up. A hosting provider whose report went stale, or whose qualified opinion nobody treated, shows as a gap in the coverage report, not as covered. CC9.2-1 still maps while any Critical or High vendor was assessed or reviewed in the year, a report review counting.

### A format bump without a new file

`vendors.json` keeps its name and gains `assuranceReports`, per-vendor `newestReport`, `reportCoveredTo` and `reportStale`, and seven exception lists. The register bundle's manifest format goes from 6 to 7 because the file's shape changed, as `register::FORMAT` says it should. `SINCE_FORMAT` is unchanged: no file was added, so a format-6 bundle still verifies, and the coverage report counts the new exceptions like any others.

## Consequences

- CC6.4-1 and CC9.2 have evidence that names the documents reviewed and what they found, once the register is kept. No status moves: CC6.4-1 and CC9.2-1 stay Gap until the policy is adopted and a review is recorded.
- A register that recorded only `reviewed` dates for its hosting vendor loses CC6.4-1 in its next bundle until a report review is added. That is intended: the date alone was never what CC6.4 asks for.
- The security owner keeps each report, CUEC note and bridge letter in the store and records its digest.

## Not done

- Reading the reports. The register says what the reviewer found; the tool can't check a PDF says it.
- Listing each CUEC and how it is met in the register. The note is free text with legal and vendor detail that doesn't belong in evidence; its digest is enough to find it.
- Subservice organisations of the vendors (the inclusive or carve-out method of their own reports), and per-region reports: one entry per document handles both.
- Tying a vendor to the [subprocessor list](../security/subprocessors.md) or to CC9.2-2's change notices to customers.
