# 0223: Incidents, breach notices, reviews and tabletops in the register

## Status

Accepted (24 Nov 2026). Tenth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds `incidents`, `tabletops` and `breachNoticeHours` to the [policy register](../security/policy-register.md#incidents) and a ninth file, `incidents.json`, to the register bundle ([ADR 0204](0204-policy-register-checked-and-bundled.md)), which the coverage report ([ADR 0169](0169-evidence-coverage-report.md)) checks. Serves CC7.3, CC7.4 and CC7.5 in the [evidence plan](../security/soc2-evidence-plan.md#the-register-bundle).

## Context

The evidence plan had nothing collected for CC7.3 ("How it's collected: None"), only an audit export per incident for CC7.4, and nothing for CC7.5's post-incident reviews. Those are the rows an auditor samples hardest in a Type II period: they pick incidents and check that each was triaged in time, that customers were told of a breach within the contract's hours, that a review was written, and that its actions were done. They also check that the plan was exercised.

The draft [incident response plan](../security/policies/incident-response.md) already sets measurable deadlines: a commander within 15 minutes, 1 hour, 1 business day or 5 business days by severity; breach notices within the [DPA](../security/dpa-template.md#8-personal-data-breaches)'s hours (48 suggested); a written review within 10 business days of closing every SEV-1, SEV-2, personal data breach and outage that spent over a quarter of the error budget, with owned actions and due dates; and a yearly tabletop with every role. Nothing checked any of them. The other cadences (approvals, acknowledgements, risks, vendors, exceptions, conduct concerns) are checked by `superbot-evidence register`, and incidents are records people keep in the same way.

## Decision

### Incidents in the register, by id and time only

The register gains three optional fields ([format](../security/policy-register.md#incidents)), so the register format stays `1` and existing registers still read:

- `incidents`: `id`, `detected`; `triaged`, `commander` and `severity` (together, since triage is naming the commander and setting the severity); `breach` and `awareAt` (together); `customersNotifiedAt` (only for a breach); `errorBudget`; `closed`; `reviewed` and `reviewSha256` (together); `actions`; `notes`.
- `tabletops`: `at`, `attendees`, `recordSha256`, `actions`, `notes`.
- `breachNoticeHours`: the DPA's commitment, 1 to 168. Without it the bundle uses the template's 48 and says so in its basis.

Actions (`id`, `owner` as a role, `due`, `done`) are shared by reviews and tabletops, with ids unique across the register so a finding names one. A register that doesn't hold together is refused, listing every problem, as before: an unknown commander, attendee, role or severity; a breach with severity `none`; a notice without a breach; a review before closing or closing before triage; dates or times out of order; a digest that isn't SHA-256 hex.

The register holds no customer, user, attacker or data description. Those go in the incident record, which the register points to by id, since the register is kept beside every bundle given to an auditor.

### Days, except for breach notices

Every date is a UTC day, like the rest of the register. SEV-1 and SEV-2 must be triaged on the day detected or the next: 15 minutes and 1 hour can't be judged from days, and the incident record's timeline, which the auditor samples, has the minutes. SEV-3 has a business day and the rest 5. An event not yet triaged has no severity, so it is held to 5 business days, the longest. Business days are Monday to Friday, and public holidays are not excluded, since they differ by country; a provider who missed a deadline only because of a holiday explains it to the auditor.

Breach notices are the one place hours matter: a DPA commits to "within 48 hours", and a regulator's 72 hours start from the same awareness. So `awareAt` and `customersNotifiedAt` are RFC 3339 times, and the notice is due `breachNoticeHours` after `awareAt`.

### `incidents.json`

A new file in the register bundle, judged as of the period's end like the rest:

- **The plan**: whether it is in the policy set given, its latest approval, its last tabletop and the next one due.
- **Incidents**: every event detected before the period's end and not finished before it began (finished means closed, reviewed if a review is needed, notified if a breach, and every action done). Each has its triage due date, triage, severity, commander and the role they held that day (holder or deputy, while personnel, the same role check as approvals), notice due date, closing, review due date and actions. Counted by severity for those detected in the period.
- **Tabletops**: those in the year to the period's end, or with actions still open, with the roles present and missing.
- **Exceptions**: `notTriaged`, `triagedLate`, `commanderNotInRole`, `breachNotNotified`, `breachNoticeLate`, `reviewOverdue`, `reviewLate`, `actionOverdue`, `actionDoneLate`, `noTabletop` (from a year after the plan's first approval), `tabletopRolesMissing` (Security owner, Operator, Engineering lead and Privacy lead, the roles the plan's runbook uses; Management and People lead aren't needed), `tabletopNoRecord`.

Something done late is an exception only in the bundle of the period it was done in; something not done past its deadline is one in every bundle until it is done. This differs from `conduct.json`, which reports a late triage again while the concern stays open. Incidents stay listed until their actions are done, which can be months, and repeating a late triage in every one of those bundles would make the auditor count one lapse many times.

### Coverage that can lapse

As in ADR 0204, the manifest maps `incidents.json` to CC7.3-1, CC7.4-2 and CC7.5-1 only while the plan is in the set and approved within a year, and to CC7.4-1 too only with a tabletop in the year that has a record. A register with no incidents still maps them: no incidents is normal, and the file then shows the plan in force and nothing missed. A month in which the plan lapsed is a gap in the coverage report.

### Older bundles still verify

The register bundle's manifest format goes from 2 to 3, and `register::SINCE_FORMAT` names format 3 as the one that added `incidents.json`. A format-2 bundle without it still verifies, a format-3 bundle without it fails, and its exceptions are counted like the other files'.

## Consequences

- CC7.3 to CC7.5 have monthly evidence once the plan is adopted and incidents are recorded. No checklist status moves: CC7.3-1, CC7.4-1 and CC7.4-2 stay Partial and CC7.5-1 stays a Gap until the plan is approved, a tabletop is held and reviews exist.
- The security owner records every security event in the register as well as in the incident tracker, including those that weren't incidents. That is the population an auditor samples from.
- The bundle shows events were recorded and handled in time, not that they were handled well or that every event was recorded. The auditor compares the register with the tracker and the alerts.

## Not done

- Reading incidents from the tracker or from botd's status page incidents: trackers differ, and status page incidents are outages, not security events. The register stays the one place they are recorded.
- Minute-level checks of the SEV-1 and SEV-2 response targets and of the status page's 15-minute outage notice.
- Customer notices for security incidents other than breaches (SEV-1 and SEV-2 within `[N]` business days): the plan leaves the number open, so there is nothing to check against yet.
- Holiday calendars for business days.
