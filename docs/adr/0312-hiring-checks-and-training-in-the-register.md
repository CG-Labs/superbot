# 0312: Hiring checks and training in the register, with draft courses

## Status

Accepted (26 Nov 2026). A slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Changes the policy register `superbot-evidence register` checks and the `people.json` it writes ([ADR 0204](0204-policy-register-checked-and-bundled.md)), and adds draft training courses to the [security pack](../security/training/README.md). Moves readiness checklist rows CC1.4-1 (hiring checks and security training) and CC2.2-1 (policies communicated, with awareness training) from **Gap** to **Partial**. No certification is claimed: SuperBot is not SOC 2 certified, no audit has started and no observation period has begun.

## Context

The draft [information security policy](../security/policies/information-security.md#people) asks for a background check before access where the law allows, security awareness training at onboarding and yearly, and secure-development training for engineers yearly, with the people lead keeping the records. CC1.4 (competence) and CC2.2 (internal communication) rest on those records.

Three things were missing:

- **No courses.** There was nothing to train anyone on. An auditor asks for the training content as well as the completions, and which version was in force.
- **Half the training was checked.** The register checked `security-awareness` for everyone and nothing else. Secure-development training for engineers wasn't recorded or chased, and the register didn't know who the engineers were.
- **No hiring checks.** Background checks weren't recorded at all, so CC1.4-1 had nothing to show for "before access".

And `people.json` named CC1.4-1 whenever anyone had trained within the year, and CC2.2-1 whenever anyone had acknowledged a policy, even with others missing. So the coverage report counted a month as covered for both rows while people flagged as untrained or unscreened were still in scope.

## Decision

### Two draft courses in the pack

[`docs/security/training/`](../security/training/README.md) holds `security-awareness.md` (everyone) and `secure-development.md` (engineers). Each has a header like the policies' (`Course`, `Owner`, `Audience`, `Review`, `Status`, `Controls`), modules tied to the policies a person acknowledges and to how SuperBot is built (isolation between customers, the Bot as untrusted input, secrets kept out of this public repository, reviews and CI, fix windows), and a short knowledge check whose answers the people lead keeps. They are drafts that a provider adopts with the policy set, like the policies themselves. The `Course` row is the id the register's training records use, and never changes.

### Screenings and engineers in the register

- **`screenings`**: `person`, `kind` (`check` or `exempt`), `at`, `by`, `recordSha256`, `notes`. A screening is due by the day someone joins, or within 30 days of the information security policy's first approval for anyone already in scope. `people.json` reports anyone at the period's end missing one (`notScreened`), screened after it was due (`screenedLate`), and any screening recorded by someone who didn't hold or deputise People lead that day (`screenerNotInRole`). Such a record doesn't count as a screening, so an exemption only counts when the people lead granted it. The recorder can't be the person screened.
- **Only a digest of the record.** The report (or the reasons for an exemption) stays in the people lead's file; the register keeps its SHA-256, and the bundle carries the kind, the day, who recorded it with the role they held, and the digest. Nothing about the outcome, the agency or the reasons reaches the bundle, so it names nobody beyond register ids.
- **Engineers**: a person is an engineer when marked `engineer`, or while they hold or deputise the Engineering lead role on the period's last day, from the start of their unbroken time in it, so swapping holder and deputy or replacing the other person doesn't restart anyone's clock. `secure-development` is due within 30 days of becoming one (or of the policy's first approval) and yearly, chased like awareness training: `secureDevelopmentNotTrained`, `secureDevelopmentLate`, `secureDevelopmentOverdue`.

### The courses' texts recorded each month

`register --training <folder>` reads each course file, checks its header names its id, and `people.json` records each one's SHA-256 under `courses` (and the manifest `trainingTextsRecorded`). So the bundle shows which text was in force that month, the way `--policies` shows the policies' texts. Without it, `courseTextsRecorded` is false and the command says the texts weren't recorded.

### The rows named only while everyone holds up

`people.json` names CC1.4-1 only while nobody at the period's end is unscreened or owes awareness or secure-development training (missing or overdue), and CC2.2-1 only while nobody owes an acknowledgement or awareness training. A late record is flagged but still counts: the control happened, late. This follows production access and branch protection, whose files name their rows only while the control held for everyone ([ADR 0231](0231-production-access-in-the-register.md), [ADR 0303](0303-branch-protection-judged-against-the-policy.md)). The bundle's format is 9.

## Alternatives considered

- **Approving the courses in `policyApprovals`**: it would show each course approved by its owner, but the courses aren't policies, a missed course approval would hold up CC5.3-1's policy checks, and the courses' digests already show which text was given. Later work if the auditor wants a sign-off.
- **A digest of the course on every training record**: proves which text each person took, but makes every record harder to keep for little more than the monthly digest gives.
- **Recording screening outcomes**: a failed check is a hiring decision for the people lead and the law, not evidence the register should carry; the bundle shows only that a check was done, or why not.
- **A role for engineers instead of a flag**: the policies' roles are single holders with a deputy; engineering is a group. The flag, plus the Engineering lead and deputy always counting, covers it.
- **Keeping "anyone trained" for the rows**: the coverage report would keep calling a month covered while people in scope owe training, which is the gap the exceptions find.

## Tests

- Unit tests in `register.rs`: screenings missing, late, before access, by the People lead's deputy and by someone who couldn't record one (which doesn't count); nobody due before the policy is approved; engineers by flag and by the Engineering lead role, from when they became one, unbroken by a swap of holder and deputy; the rows left out while anyone owes a screening, acknowledgement or training, and kept for a late screening; the course folder read in order, with a missing file, a header naming another course, and a header after the first section refused; parse refusals for a bad kind, a self-screening, a bad digest and an unknown person; the template screens everyone, has an engineer and uses only the folder's courses; notes never reach the bundle.
- `server/tests/register_evidence.rs`: the real binary with `--training docs/security/training` records both courses' digests and `trainingTextsRecorded`, counts engineers and screenings, and still names CC1.4-1 and CC2.2-1.
- `server/tests/security_docs_links.rs`: the training folder holds exactly the courses the register checks, each with its id, an owner role, a yearly review, a draft status, real checklist rows and a knowledge check; no certification claims or email addresses; the pack and the information security policy link them.

## Consequences

- A provider's first monthly bundle after adopting the policies lists everyone not yet screened or trained, and leaves CC1.4-1 and CC2.2-1 uncovered until they are, which is the truth.
- Registers without `screenings` still parse, but everyone at the period's end is reported as not screened once the grace period is over.
- Changing a course changes its digest in the next bundle; an auditor can match it to the commit.
- Older register bundles (format 8) keep their manifests as written; the coverage report reads either.
