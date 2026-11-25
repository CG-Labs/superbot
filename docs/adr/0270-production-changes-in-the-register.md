# 0270: Production changes in the register

## Status

Accepted (25 Nov 2026). Fifteenth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds `changes` to the [policy register](../security/policy-register.md#production-changes), `emergencyChanges` to its management reviews, and a twelfth file, `production-changes.json`, to the register bundle ([ADR 0204](0204-policy-register-checked-and-bundled.md)), which the coverage report ([ADR 0169](0169-evidence-coverage-report.md)) checks. Writes the deadlines the draft [change management policy](../security/policies/change-management.md#production-changes) left open. Serves readiness checklist row CC8.1-2 in the [evidence plan](../security/soc2-evidence-plan.md#the-register-bundle).

## Context

The change management policy has two halves. Code changes already have evidence: the monthly change-management bundle exports every pull request merged into `main` with its approvers and checks ([ADR 0148](0148-change-management-evidence-from-github.md)). Production changes don't: upgrading a managed server, changing its settings, the tiers file, the hosting or storage accounts or DNS happen outside GitHub. botd's evidence bundle records the versions a server started and some settings changing ([ADR 0142](0142-type-ii-evidence-bundles.md)), but not who approved the change, whether it was recorded first, or whether it was checked afterwards. The readiness checklist's CC8.1-2 named exactly this as left: "records of production and emergency changes (who approved each, which neither bundle can show)".

An auditor testing CC8.1 samples the period's production changes and asks, for each: the change record, an approval by someone other than the person who made it, made before the change, and the check afterwards; for an emergency change, the incident, the after-the-fact review and the management review that went through it. The policy said all of that, but not when the check, the code follow-up or the management review were due, so nothing could be judged late.

## Decision

### Changes in the register, by id only

The register gains an optional `changes` list, so its format stays `1` and existing registers still read: `id`, `system` (a production system the register already holds, [ADR 0231](0231-production-access-in-the-register.md)), `kind` (`standard` by default, or `emergency`), `recorded` and `recordSha256` (the change record's day and digest; always required), `approved` and `approvedBy` (together), `made` and `madeBy`, `incident` (required for an emergency change), `interrupts` and `startsAt` (together; a UTC time on the day it was made) with `announcedAt`, `verified`, `reviewed` and `reviewedBy` (together; emergency only), `code`, `pullRequest` and `followedUp` (together; emergency code changes only), `notes`. Management reviews gain `emergencyChanges`, the ids they went through.

What changed, why, the risk and the rollback stay in the change record (a pull request, issue or ticket), which `recordSha256` points to; the register holds when each step happened and who did it, by register id, so the bundle names nobody. A register that doesn't hold together is refused, listing every problem: an unknown system, person, incident or change id, a change made while its system wasn't in use, an emergency change without an incident or made before it was detected, half of a pair, review or code fields on a standard change, a pull request without `code`, a maintenance start on another day, steps dated before the change, a management review listing a change that isn't an emergency change made by then.

### What the policy says, made checkable

- **Standard changes** are recorded and approved before they are made, by someone other than whoever makes it, who is personnel that day (`notRecordedFirst`, `notApproved`, `approvedAfterMade`, `selfApproved`, `approverNotPersonnel`). The policy names no approving role, so the bundle records the role the approver held (`heldRole`) for the auditor rather than refusing other approvers.
- **Maintenance** that may interrupt the service is announced at least 48 hours before `startsAt`, measured in hours as the policy states it (`maintenanceNotAnnounced`). Emergency changes aren't announced ahead; the status page's incident covers them.
- **Access**: whoever makes a change has a grant to that system on record that day (`madeWithoutAccess`). This joins the change records to the access records, so a change made by someone the access review never saw shows up.
- **The check afterwards** of the service and the configuration baseline is due the same or the next business day (`notChecked`, `checkedLate`). The policy said "after a change"; a day is what an operator can keep to and what makes "never checked" visible.
- **Emergency changes** are approved by the incident's recorded commander while still personnel, or by whoever holds or deputises the Security owner role that day, since the security owner takes over command from the on-call operator (`emergencyApproverNotCommander`). The commander may make the change themselves and record it afterwards: speed is the point. It is then reviewed within 2 business days by a second person, who neither made nor approved it (`reviewOverdue`, `reviewLate`, `reviewerNotSecondPerson`); a code change goes through a normal pull request within 5 business days (`followUpOverdue`, `followUpLate`), a deadline the policy now states; and the first management review after it lists it (`notInManagementReview`), flagged in the period of the review that missed it.

How a change was made and approved is judged once, in the bundle of the period it was made in. A check, review or follow-up done late is flagged in the bundle of the period it was done in, and one overdue in every bundle until it is done, as in [ADR 0223](0223-incidents-in-the-register.md). Business days are Monday to Friday, without public holidays, like the incident plan's.

### `production-changes.json`

The new file lists every change made before the period's end and still being handled in it, with its system, kind, record digest, approval and the role the approver held, who made it and whether they had access, the incident, the maintenance window and its notice in hours, and each due date and step, with the management review that listed an emergency change; the period's management reviews that listed emergency changes, with their minutes' SHA-256, so a listing can be followed to the minutes after the change itself has left the file; counts by kind, systems changed and changes not yet checked; and the exceptions above. It is named `production-changes.json` because botd's own evidence bundle already has a `changes.json` (configuration changes), and the coverage report counts exceptions by file name.

### Coverage that can lapse

The manifest maps `production-changes.json` to CC8.1-2 while the change management policy is in the policy set and approved within a year. A month with no production changes is possible, so the row doesn't need one; the policy's approval is what makes "nothing changed" a statement under a policy in force rather than an empty file. Late or unapproved changes are exceptions to sample, not a gap.

### Older bundles still verify

The register bundle's manifest format goes from 5 to 6, and `register::SINCE_FORMAT` names format 6 as the one that added `production-changes.json`. A format-5 bundle without it still verifies, a format-6 bundle without it fails, and its exceptions are counted like the other files'.

## Consequences

- CC8.1 has monthly evidence for production and emergency changes once the policy is adopted and the register is kept. No status moves: CC8.1-2 stays Partial until the policy is approved and changes are recorded, and CC8.1-1 stays a Gap until `main` is protected.
- The engineering lead or operator records each production change in the register, and keeps each change record in the store.
- The bundle shows the records were kept and hold together, not that every change was recorded. The auditor compares it with botd's own record of versions started and settings changed (`changes.json` in each server's evidence bundle) and the hosting provider's activity log.

## Not done

- Matching each recorded change to botd's own record of a version or setting changing, or flagging a change botd saw that the register doesn't have. Both are possible, since the server's evidence bundle lists them, but its entries carry no change id, so the match would be by day and guesswork.
- Matching emergency code changes' `pullRequest` against the change-management bundle, or recording why each of that bundle's exceptions happened (CC8.1-1's monthly review).
- Checking the change against a `--baseline` file made after it: a baseline check names no system, so it can't be bound to one change.
- A role that must approve standard changes: the policy names none, and choosing one is management's call when it adopts the policy.
