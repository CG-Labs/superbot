# 0214: A code of conduct, with its acknowledgements and concerns in the register

## Status

Accepted (23 Nov 2026). Ninth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds a ninth policy to the [policy set](../security/policies/README.md) ([ADR 0130](0130-policy-set-and-type-ii-evidence.md)) and an eighth file, `conduct.json`, to the register bundle ([ADR 0204](0204-policy-register-checked-and-bundled.md)), which the coverage report ([ADR 0169](0169-evidence-coverage-report.md)) checks. Serves CC1.1 in the [evidence plan](../security/soc2-evidence-plan.md#the-register-bundle).

## Context

CC1.1-1, "a code of conduct and ethics policy, acknowledged by everyone with access", was the only CC1 row with no draft at all: the [readiness checklist](../security/soc2-readiness-checklist.md) had it as a Gap, and ADR 0204 left it out ("the register can hold its acknowledgements once the policy exists"). The roadmap's remaining items for #57 list it. Most of what is left on #57 is for people to do (naming role holders, approving policies, turning on repository settings, the observation period, the auditor). This one can be done in the repository.

An auditor testing CC1.1 looks for three things: written standards of conduct, an acknowledgement of them from each person at hire and yearly, and evidence that breaches are reported and dealt with in time (the COSO points of focus "evaluates adherence to standards of conduct" and "addresses deviations in a timely manner"). The [acceptable use policy](../security/policies/acceptable-use.md) covers using the provider's systems and customers' data. It doesn't cover integrity (honest records and evidence, conflicts of interest, bribery), a channel for raising concerns without retaliation, or how concerns are handled.

## Decision

### A ninth policy

[`code-of-conduct.md`](../security/policies/code-of-conduct.md) is a draft like the others: owned by the People lead, approved by Management, reviewed yearly, covering CC1.1-1 and CC1.5-1, and checked by the same CI test (header, references, no emails, no certification claim). It sets standards of conduct: honest records and evidence (never backdated or edited, which the evidence plan relies on), honesty with customers, auditors and regulators (including never claiming a certification), customers' trust, conflicts of interest, gifts and bribery, fair dealing and the law, respect, and security duties. It also says how to raise a concern: with the People lead, Management or the security owner, through a confidential channel that can be used anonymously, or with an independent reviewer for concerns about Management, with no retaliation for raising one in good faith. Concerns are recorded by id, triaged within 7 days by someone holding the People lead, Management or Security owner role and not involved, closed within 90 days with an outcome, and counted in each quarterly management review. The channel, the independent reviewer and the gift threshold are square-bracket placeholders the provider fills in, as in the other policies.

7 and 90 days are common defaults for a small organisation's whistleblowing process. The EU Whistleblowing Directive asks for acknowledgement within 7 days and feedback within 3 months, which these meet. They are constants in `register.rs`, changed with the policy in the same PR, like the other cadences.

### Acknowledged like the others

`code-of-conduct` joins the information security and acceptable use policies in `ACKNOWLEDGED`, so `people.json` already chases each person's acknowledgement within 30 days of joining (or of the policy's first approval) and yearly, with no new rule. The built-in policy set gains it, so approvals of it are checked by role and text like every other.

### Conduct concerns in the register

The register gains an optional `conductConcerns` list. Each record has `id`, `received`, `triaged` and `handledBy` (together), `closed` and `outcome` (together: `substantiated`, `not-substantiated`, `withdrawn` or `referred`), and `notes` ([format](../security/policy-register.md#conduct-concerns)). A register that doesn't hold together is refused, as before: a closed concern needs an outcome and a triage, an unknown handler or outcome is refused, and dates must be in order.

The register records no reporter, no subject and no category. A concern names people by definition, and the register sits beside every bundle given to an auditor. What the auditor samples (the case file) stays with the people lead and is pointed to by id. The field is optional and the register format stays `1`, so existing registers still read.

### `conduct.json`

A new file in the register bundle, judged as of the period's end like the rest:

- **The code**: whether it is in the policy set given, its latest approval before the period's end, and how many of the people with access at the end acknowledged it within a year. Exceptions for a missing approval or acknowledgement are not repeated here, since `policies.json` and `people.json` already report them.
- **Concerns**: every concern received before the period's end and not closed before it began, with its deadlines, triage, handler and the role they held that day (holder or deputy, while personnel, through the same role check as approvals), closing and outcome, counted by outcome for those closed in the period. Exceptions: `triagedLate` (late, or untriaged past its deadline), `closedLate` (late, or open past its deadline), `handlerNotInRole`. A register with no concerns has no exceptions: no concerns is normal.
- **Coverage that can lapse**, as in ADR 0204: the manifest maps `conduct.json` to CC1.1-1 only while the code is in the set, approved within a year, and acknowledged by someone within a year. A month in which the code lapsed is a gap in the coverage report, not covered.

### Older bundles still verify

The register bundle's manifest format goes from 1 to 2. The coverage report requires every file a kind always has, so `register::SINCE_FORMAT` names the format that added `conduct.json`. A format-1 bundle without it still verifies, a format-2 bundle without it fails, and its exceptions are counted like the other files'. Existing evidence stores keep passing.

## Consequences

- CC1.1-1 moves from Gap to Partial: a draft exists, and evidence for it is collected monthly once it is adopted. It doesn't reach Done until the code is approved, the channel and reviewer are named, and people have acknowledged it. No other row moves.
- The policy set is nine policies. CI checks all nine, and the register's built-in set, the template and the policies' own folder agree, which `register.rs`'s test checks.
- Every register's people now owe a third acknowledgement. A provider adopting the set after this change gets it from the start. One that approved the others earlier owes it within 30 days of approving the code.
- The bundle shows concerns were recorded and handled in time, not that they were handled well. The auditor samples the case files behind the ids.

## Not done

- Conflict-of-interest and gift declarations as register records: the code has the people lead keep them, but nothing checks them yet.
- Background checks (CC1.4-1), performance reviews (CC1.5-1), and the case files themselves stay outside the register.
- The provider's confidential channel itself: a mailbox or form is the provider's choice, not part of SuperBot.
