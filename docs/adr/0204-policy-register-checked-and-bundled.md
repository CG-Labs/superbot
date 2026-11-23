# 0204: The policy register, checked and bundled

## Status

Accepted (23 Nov 2026). Eighth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds a fifth command to `superbot-evidence` ([ADR 0148](0148-change-management-evidence-from-github.md)) and a fifth kind of bundle to the coverage report ([ADR 0169](0169-evidence-coverage-report.md)). Serves CC1.2, CC1.3, CC1.4, CC2.2, CC3.1, CC3.2, CC3.3, CC5.1, CC5.3, CC6.4 and CC9.2 in the [evidence plan](../security/soc2-evidence-plan.md#the-register-bundle).

## Context

The draft [policy set](../security/policies/README.md) ([ADR 0130](0130-policy-set-and-type-ii-evidence.md)) keeps much of what an auditor samples in "a private policy register kept outside this repository": who holds each role and their deputy, each policy's approval at a commit, acknowledgements and training, the risk register and its reviews, quarterly management reviews, vendor assessments and reviews, and exceptions. The register had no format, so:

- nothing said what a complete register holds, or checked one against the policies' cadences (yearly reviews, acknowledgement at hire, quarterly management reviews, exceptions ending within a year);
- the coverage report counted every row whose evidence is "the register" as records people keep, with no way to see a month in which they weren't kept;
- an approval named a commit, but nothing checked that the text approved was the text in force, or that the approver held the role the policy's header names;
- botd's baseline check ([ADR 0195](0195-configuration-baseline-checked-by-botd.md)) reports settings a server excepted with `BASELINE_EXCEPTIONS`, but nothing tied them to an approved exception.

## Decision

### A register with a format

The register is one JSON file the security owner keeps in the evidence store, never in this repository: format `superbotRegister: 1`, with people, role assignments, policy approvals, acknowledgements, training, risks, risk reviews, management reviews, vendors and exceptions ([format](../security/policy-register.md), [template](../security/policy-register-template.json)). Dates are UTC days. Unknown fields are refused, so a misspelt field can't hide a record. People are referred to by ids that must be plain (letters, digits, `.`, `_`, `-`), so an email can't become an id that reaches evidence.

JSON rather than a spreadsheet or a database: it diffs, can be signed and digested, needs no service, and is what the rest of `superbot-evidence` reads. A record is added or closed, never edited; the tool can't enforce that, so each bundle records the register's SHA-256 and the register as read is kept beside it.

### `superbot-evidence register`

`superbot-evidence register <register.json> [--policies <folder>] [--baseline <file>]... [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>]`, with the binary's period rules and private, never-overwritten output, and no token or network. It first checks the register holds together (every person, role and policy it names exists, ids are plain and unique, scores are 1 to 5, dates are in order, hex digests are hex) and refuses it otherwise, listing every problem and writing nothing: a register that doesn't hold together can't be sampled. Then it checks the period against the policies and writes a bundle in the change-management bundle's shape, folder `superbot-register-<from>_<to>-<UTC time>/`, manifest kind `policy-register`, with seven files: `roles.json`, `policies.json`, `people.json`, `risks.json`, `management-reviews.json`, `vendors.json` and `policy-exceptions.json` ([what each shows](../security/soc2-evidence-plan.md#the-register-bundle)).

- **Cadences are the policies'**, in code as constants: a year is 365 days, a quarter 92, and a newcomer has 30 days from joining (or the policy's first approval) to acknowledge and train. A finding is an exception in the bundle, never a refusal: the bundle is the record of what was found, and the security owner fixes or explains it.
- **Roles are checked day by day**: each of the six roles has a holder and a deputy, not the same person, both personnel that day, and no overlapping assignments. Approvals, acceptances of risk above the appetite, exception approvals and management reviews are checked against the role the approver held on that day, from the same assignments, with a deputy counting for the role, and only while the person is personnel (joined, not left), so a stale assignment can't make a leaver's approval count. Only records dated before the period's end count, so a later approval can't clear a past month's finding. An accepted risk needs a dated acceptance: by Management above the appetite, and by Management or the risk's owner role within it.
- **Policy texts.** With `--policies <folder>` (the repository's policy folder at the commit in force), each policy's latest approval must be of that file's SHA-256, and by the role its `| Approver |` header names. Without it, the built-in policy set and Management are used and the manifest says the texts weren't checked.
- **Baseline exceptions.** Each `--baseline` (`botctl evidence baseline json`, or the month's evidence bundle's `baseline.json`) must have been checked in the period or the 7 days after it: botd makes the monthly bundle after its month ends, and the coverage report already warns about bundles made later than that. Each setting it lists as excepted must have an exception approved before the period's end, in force on the day of the check, naming the setting. Only the file's name, size and SHA-256, when it was checked, its settings digest and the excepted setting names are kept.
- **Coverage that can lapse.** The manifest maps a file to its rows only while the register holds a current record for it (the roles filled, an approval within a year, acknowledgements and training within a year, a risk reviewed within a year, a management review within a quarter, a vendor reviewed within a year, a baseline checked). A register let lapse shows as a gap in the coverage report rather than as covered, as drill bundles without drills do (ADR 0177).
- **Records after the period are left out** and counted, so a bundle made late for a past month shows that month as it was.
- **A month at most.** What the bundle shows is judged as of the period's end, so a period of up to 31 days is allowed (the other kinds allow 400): over six months, an approval in the last week would otherwise map rows for all six, and the coverage report would count months with no current record as covered.

### Privacy

The bundle names people by register id only, and holds no names, risk titles, notes or reasons: the store's evidence can be shared with an auditor without the register, which maps ids to people and is kept beside it. The register itself is Internal under the [data classification policy](../security/policies/data-classification-and-retention.md#classes).

### Coverage

The coverage report gains the fifth kind, `policy-register`, with its seven files expected and their exceptions counted.

## Consequences

- Rows whose evidence was "the register" (CC1.2-1, CC1.3-1, CC1.4-1, CC2.2-1, CC3.1-1, CC3.2-1, CC3.3-1, CC5.1-1, CC5.3-1, CC6.4-1, CC9.2-1) get monthly, digest-sealed evidence that the coverage report sees, once a register exists. No checklist status moves: the register has to be kept, and the people and approvals in it are the provider's to supply.
- The bundle shows the register was kept and holds together, not that what it says happened. Approvals, training and reviews are what people wrote; the auditor still samples the minutes, certificates and sign-offs behind them, which the register points to by digest where it can.
- The cadences live in the policies and in code. A change to one is made in the other in the same PR, and a unit test checks the template parses against the real policies and names every role and policy.
- One file and no service means one keeper at a time. That fits a small provider; a larger one can generate the register from its HR and GRC systems.

## Not done

- A code of conduct (CC1.1-1) and its acknowledgements: the register can hold its acknowledgements once the policy exists.
- Background checks (CC1.4-1), performance reviews (CC1.5-1), and reviews of access outside SuperBot (CC6.3-2) stay outside the register's checks.
- Signing the register or keeping it append-only in tooling.
