# 0231: Production access in the register

## Status

Accepted (24 Nov 2026). Eleventh slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds `systems`, `access` and `accessReviews` to the [policy register](../security/policy-register.md#production-access), a tenth file, `access.json`, to the register bundle ([ADR 0204](0204-policy-register-checked-and-bundled.md)), which the coverage report ([ADR 0169](0169-evidence-coverage-report.md)) checks, and `--access-review` to `superbot-evidence register`. Adds readiness checklist row CC6.2-2 and serves CC6.1-2 and CC6.3-2 in the [evidence plan](../security/soc2-evidence-plan.md#the-register-bundle).

## Context

Access is what a Type II auditor samples first. For SuperBot's own users the evidence is collected: the access-review report and its signed-off digest ([ADR 0099](0099-access-review-report.md)), kept monthly in the evidence bundle's `access-review.json` ([ADR 0142](0142-type-ii-evidence-bundles.md)). For everything else that runs the service (the hosting provider's console, the code host, object storage, DNS, payments, the shells on servers) the evidence plan said "Reviews of access outside SuperBot" and "Requests and approvals for production access outside SuperBot" were manual, with nothing to check them.

The draft [access control policy](../security/policies/access-control.md) already sets measurable rules for those systems: a written request approved by the security owner, and admin access to a managed server or the hosting provider by Management too, nobody approving their own; a leaver's access removed by their last day; a quarterly review of each system's users, by the security owner or a delegate who isn't reviewing their own access, signed off "in the register"; findings fixed within 5 business days, 1 for admin access; and MFA on every production account. The register had no place for any of it, and the auditor's sample (every leaver in the period, a handful of grants, each quarter's reviews) had nothing to be drawn from.

## Decision

### Systems, grants and reviews in the register, by id only

The register gains three optional fields, so the register format stays `1` and existing registers still read:

- `systems`: `id`, `kind` (`superbot` for a managed server, `hosting` for the hosting provider, `other` by default), `since`, `until` (the day it was retired), `notes`. Kind decides two things: admin access to `superbot` and `hosting` needs Management's approval as well, and `superbot` reviews are matched to botd's sign-offs.
- `access`: `person`, `system`, `level` (`admin` or `user`), `requested`, `approved` and `approvedBy` (together, a list), `granted`, `removed` (the first day without it), `notes`. A change of level ends one grant and starts another, so each record has one level for its whole life.
- `accessReviews`: `system`, `at`, `by`, `listSha256`, `mfa` (required), `findings` (`id`, `admin`, `fixed`), `notes`.

A register that doesn't hold together is refused, listing every problem, as before: unknown people or systems, ids that aren't plain, an unknown kind or level, `approved` without `approvedBy`, dates out of order (requested, approved, granted, removed; a grant or review before the system's `since`), a finding fixed before its review, a digest that isn't SHA-256 hex. `mfa` has no default, since a review that didn't look at second factors must say so.

The register holds no account names, emails or what a finding was about: those stay in the exported user list and the request, kept in the store. `listSha256` ties the review to the list exported for it.

### Approvals by role, not by head count

The policy says "approved by the security owner; admin access ... also needs management's approval. Nobody approves their own request." The check is by role on the day of the approval, like every other approval in the register: among the approvers other than the grantee, someone held or deputised Security owner, and for admin on `superbot` or `hosting`, someone held or deputised Management. One approver holding both is enough. Requiring two different people would make the security owner's own admin access impossible to grant in a three-person team, where the only other person with either role deputises the security owner and holds Management. The policy names roles, so the check does too; an approval by the grantee is flagged separately as `selfApproved` even when someone else also approved.

Only grants made in the period are checked: a written request recorded (`grantNotRequested`) and approved as above. Access that existed before the register was started can be recorded with just `granted`, and isn't reported in every later bundle.

### Leavers

A leaver's access is due gone by their `left` day, the register's first day they aren't personnel, matching the policy's "by the end of their last day". A grant ends at `removed` or when its system is retired. Access a leaver still holds is `leaverNotRemoved` in every bundle until `removed` is set; access removed after `left` is `leaverRemovedLate` in the bundle of the month it was removed, as in [ADR 0223](0223-incidents-in-the-register.md). Since `removed` is the first day without access, a removal dated on a month's first day belongs to that month's bundle, so a leaver chased at one month's end is reported removed late in the next. "At once when they leave for cause" can't be told apart from an ordinary leaving in the register, so it isn't checked.

### Reviews each quarter, with MFA recorded

Each system in use at the period's end needs a review within 92 days of the last (a new one, of its `since`): `reviewOverdue`. The reviewer holds or deputises Security owner, or is a delegate who is personnel and holds no grant on that system that day, which is how the register can tell "isn't reviewing their own access": otherwise `reviewerNotAllowed`. A finding is due within 5 business days of the review, 1 if `admin`: `findingOverdue` while open past it, `findingFixedLate` in the month it was fixed late. Business days are Monday to Friday, as for incidents.

`mfa` turns CC6.1-2's "evidence of each production system's MFA setting" into a record: a system whose latest review says `false` is `mfaNotRequired` until a review says `true`. The reviewer looks at each account's second factor in the system's own console, which is the only place it can be seen for most of them.

### Managed servers matched to botd's sign-offs

For a `superbot` system, the review is done in SuperBot itself: the admin signs off the access-review report, which records `access_review.completed` with the report's digest. `listSha256` is that digest. With `--access-review <system>=<file>` (repeatable; a `superbot` system's register id and the `access-review.json` from that server's evidence bundle), the bundle checks that each review of that system recorded in the period has a sign-off of the same digest on the same UTC day in that system's own files, and flags `signOffNotFound` otherwise. The day matters as well as the digest because the report's digest is the same whenever access is unchanged, so a digest alone could match an old sign-off. The server matters too: the digest covers who has access, not which server, so two servers with the same users (one restored from a copy of the other) would otherwise confirm each other's reviews. A review of a server given no file isn't checked, and is listed in `reviewedWithoutSignOffFile` so the gap shows. When the file lists only its first events (`eventsListed` below `eventsTotal`), the exception says so. Without any such file, `signOffsChecked` is `false` and nothing is flagged, so a register kept without botd's files still bundles.

This is the one place the register bundle reads another bundle. It reads only `period.events` and `periodCovered`, records each file's SHA-256 and sign-off count, and never copies the people in it.

### `access.json`

A new file in the register bundle, judged as of the period's end like the rest: each system in use in the period with its grants at the end, its last review, the next due and its MFA finding; each grant live in the period with its request, approvals (and the role each approver held), grant, removal and a leaver's removal due date; each review in the period, or with a finding still open in it, with the reviewer's role or delegation, the list's digest, MFA, the matching sign-off's time and each finding's due date; and the exceptions: `grantNotRequested`, `grantNotApproved`, `grantApproverNotInRole`, `selfApproved`, `grantedToNonPersonnel`, `leaverNotRemoved`, `leaverRemovedLate`, `reviewOverdue`, `mfaNotRequired`, `reviewerNotAllowed`, `signOffNotFound`, `findingOverdue`, `findingFixedLate`.

### Coverage that can lapse

The manifest maps `access.json` to CC6.1-2 and CC6.3-2 only while every system in use at the period's end is current (reviewed within 92 days, or added within 92 days) and at least one has a review in that time, and to CC6.2-2 only while every system in use at the end has at least one live grant recorded. A register with no systems maps nothing: the policy's scope always has some, so an empty list is a gap, not a clean month. Grants made without approval and late removals are exceptions, not gaps: the auditor reads them as deviations, which is what they are.

### A new checklist row

CC6.2 had only the product row CC6.2-1 (JIT accounts need an allow-list). Approving production access before it is granted, and removing it when people leave, is a process control the policy already holds; it becomes CC6.2-2, Partial like the other rows the unadopted policy set answers.

### Older bundles still verify

The register bundle's manifest format goes from 3 to 4, and `register::SINCE_FORMAT` names format 4 as the one that added `access.json`. A format-3 bundle without it still verifies, a format-4 bundle without it fails, and its exceptions are counted like the other files'.

## Consequences

- CC6.1, CC6.2 and CC6.3 have monthly evidence for production access outside SuperBot once the policy is adopted and the register is kept. No status moves to Done: CC6.1-2, CC6.2-2 and CC6.3-2 stay Partial until the policy is approved and reviews exist.
- The security owner records each system, each grant and each quarterly review in the register, and keeps each exported user list and written request in the store.
- The bundle shows the records were kept and hold together, not that the register lists every account that exists. The auditor compares it with each system's own user list, which `listSha256` points to.

## Not done

- Reading user lists from the hosting provider, the code host or DNS APIs. Each has its own API and token scope; the register stays the one place they are recorded, and the review compares it with the list.
- Checking that a role change removed access the new role doesn't need within 5 business days: the register has no mapping from role to systems.
- Rotating shared secrets when someone who could see them leaves, and break-glass use reviewed at the next access review.
- Leaving "for cause", which needs removal at once.
- Holiday calendars for business days.
