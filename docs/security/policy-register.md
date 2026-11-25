# Policy register

The records the [policy set](policies/README.md) calls for that people keep, in one JSON file that `superbot-evidence register` checks against the policies' cadences and turns into a monthly [register bundle](soc2-evidence-plan.md#the-register-bundle) ([ADR 0204](../adr/0204-policy-register-checked-and-bundled.md)). Part of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57)). SuperBot is not SOC 2 certified; a register that checks shows records were kept and hold together, not that what they say happened, and the auditor decides what is enough.

## Keeping it

- **Private.** The register names people, so it lives in the security owner's evidence store, never in this repository. Start from the [template](policy-register-template.json), replace every `<...>` placeholder, date and zero digest, and give each person an id that isn't their name or email (`person-1`, `p-042`): ids are all the bundle carries.
- **As things happen.** Add a record when a role changes hands, a policy is approved, someone joins, acknowledges or trains, a risk is found or reviewed, management meets, a vendor is taken on or reviewed or its assurance report is read, an exception is approved or reviewed, a conduct concern is received, triaged or closed, or a security event is detected, triaged, notified, closed or reviewed, a tabletop is held, production access is granted, removed or reviewed, or a vulnerability is received, acknowledged, assessed, fixed or accepted, or a penetration test reports or retests, or a production change is recorded, approved, made, checked or reviewed. Records are only added or closed, never rewritten: the bundle's manifest records the register's SHA-256, and the register as read is kept beside each bundle.
- **Checked monthly**, with the other bundles:

```sh
superbot-evidence register register.json --policies docs/security/policies \
  --description docs/security/soc2-system-description.md \
  --baseline baseline-<server>.json --access-review <server>=access-review-<server>.json \
  --from 2027-03-01 --to 2027-04-01
```

`--policies` is this repository's policy folder at the commit in force: each approval must be of that text (by SHA-256) and by someone holding (or deputising) the role the policy's header names as its Approver, while personnel. `--description` is the [system description](soc2-system-description.md) at that commit, checked the same way: it must have a section for each of DC1 to DC9, and its approval goes in `policies.json` under `systemDescription` and maps CC2.3-4 ([ADR 0292](../adr/0292-soc2-system-description.md)). Every approval is checked the same way: by role, on the day, by someone who had joined and not left. Each `--baseline` is a server's `botctl evidence baseline json`, or the `baseline.json` in the month's evidence bundle, checked in the period or the 7 days after it (botd makes the bundle on the 1st); every setting it lists as excepted must have an exception approved before the period's end and in force the day it was checked. Each `--access-review` is a managed server's system id in the register, `=`, and the `access-review.json` from that server's evidence bundle for the period (or a later one): each review of that server recorded in the period must match one of the `access_review.completed` sign-offs in its own files, since the report's digest covers who has access, not which server (see [production access](#production-access)). Without `--from` and `--to` the period is last month; a bundle covers at most a month (31 days), since what it shows is judged as of the period's end, so a record made late can't cover the months before it. It refuses a register that doesn't hold together, listing every problem, and writes nothing; otherwise it writes the bundle (never over a file) and prints what it found. Each finding is an exception in the bundle for the security owner to fix or explain, not a refusal.

## The format

One JSON object. Dates are `YYYY-MM-DD` (UTC days); a record dated on or after the period's end is left out of that period's bundle. Unknown fields are refused, so a typo can't hide a record. Ids are letters, digits, `.`, `_` and `-`, up to 64.

| Field | What it holds |
|-------|---------------|
| `superbotRegister` | The format, `1`. |
| `notes` | Free text for the register's keeper; never in the bundle. |
| `riskAppetite` | The highest risk score (likelihood times impact, 1 to 25) the risk owner may accept; above it, or with none set, only Management may. |
| `people` | Everyone with access to production systems or customer data: `id`, `name` (never in the bundle), `joined`, and `left` when they go. |
| `roles` | Assignments of the policies' roles (Management, Security owner, Engineering lead, Operator, People lead, Privacy lead): `role`, `holder`, `deputy`, `from`, and `until` when it ends. End the old assignment with `until` when a role changes hands, since a role's assignments mustn't overlap; each role needs a holder and a deputy, not the same person, every day. |
| `policyApprovals` | `policy` (its file name, such as `access-control`, or `soc2-system-description` for the [system description](soc2-system-description.md)), `sha256` (`sha256sum` of the file as approved), `commit`, `approvedBy`, `approvedAt`. Each policy, and the system description, needs one within a year. |
| `acknowledgements` | `person`, `policy`, `at`. Everyone acknowledges the information security, acceptable use and code of conduct policies within 30 days of joining (or of the policy's first approval) and yearly. |
| `training` | `person`, `course`, `at`. Everyone takes `security-awareness` on the same terms. |
| `risks` | `id`, `title` (never in the bundle), `owner` (a role), `likelihood` and `impact` (1 to 5), `treatment` (`reduce`, `accept`, `transfer` or `avoid`), `controls` (readiness checklist row ids, such as `CC6.1-1`; a reduced risk needs one), `fraud`, `identified`, `reviewed` (dates), `closed`, `notes`; for an accepted risk, `acceptedBy` (the owner role's holder, or Management; only Management above the appetite), `acceptedAt` and `acceptedUntil`, its next review. An accepted risk without a dated acceptance is reported. Each open risk is reviewed yearly, and at least one is a fraud risk. |
| `riskReviews` | Full reviews of the register: `at`, `by`. One a year. |
| `managementReviews` | `at`, `attendees`, `minutesSha256` (the minutes' SHA-256; the minutes go in the store), `emergencyChanges` (the ids of the emergency changes it went through). One a quarter, with Management and the security owner. |
| `vendors` | `id`, `tier` (`critical`, `high` or `low`), `hosting` (it runs the service, so its assurance report covers CC6.4), `since`, `until`, `assessed`, `approvedBy` (the security owner or Management), `reviewed` (dates), `notes`. Assessed before use and reviewed yearly. |
| `assuranceReports` | Reviews of vendors' SOC 2 reports, ISO 27001 certificates and questionnaire answers: `id`, `vendor`, `kind`, `coversFrom`, `coversTo`, `reportSha256`, `opinion`, `deviations`, `risk`, `cuecsSha256`, `bridgedTo` and `bridgeSha256` (together), `reviewed`, `reviewedBy`, `notes`. See [vendors' assurance reports](#vendors-assurance-reports). |
| `exceptions` | Exceptions to a policy: `id`, `policy`, `setting` (a [configuration baseline](configuration-baseline.md) setting, as in `BASELINE_EXCEPTIONS`), `approvedBy` (the security owner or Management), `approvedAt`, `ends` (within a year), `reviewed` (dates, each quarter), `closed`, `notes`. |
| `conductConcerns` | Concerns raised under the [code of conduct](policies/code-of-conduct.md#raising-a-concern): `id`, `received`, `triaged` and `handledBy` (together), `closed` and `outcome` (together), `notes`. See [conduct concerns](#conduct-concerns). |
| `breachNoticeHours` | Hours the provider has to tell customers of a possible personal data breach, from becoming aware: the signed DPAs' commitment (1 to 168). Without it, the [DPA template](dpa-template.md)'s suggested 48. |
| `incidents` | Security events under the [incident response plan](policies/incident-response.md): `id`, `detected`; `triaged`, `commander` and `severity` (together); `breach` and `awareAt` (together), `customersNotifiedAt`; `errorBudget`; `closed`, `reviewed` and `reviewSha256` (together), `actions`, `notes`. See [incidents](#incidents). |
| `tabletops` | Yearly exercises of the plan: `at`, `attendees`, `recordSha256` (the record's SHA-256; the record goes in the store), `actions`, `notes`. |
| `systems` | Production systems in the [access control policy](policies/access-control.md#scope)'s scope: `id`, `kind` (`superbot` for a managed server, `hosting` for the hosting provider, `other` by default), `since`, `until` (the day it was retired), `notes`. See [production access](#production-access). |
| `access` | Grants of production access: `person`, `system`, `level` (`admin` or `user`), `requested`, `approved` and `approvedBy` (together; a list of people), `granted`, `removed` (the first day without it), `notes`. |
| `accessReviews` | Quarterly reviews of each system's users: `system`, `at`, `by`, `listSha256` (the reviewed user list's SHA-256; for a managed server, the access-review report's digest), `mfa` (whether every account needs a second factor; required), `findings` (`id`, `admin`, `fixed`), `notes`. |
| `vulnerabilities` | Vulnerabilities found outside the CI scans: `id`, `source` (`report`, `pentest`, `vendor` or `internal`), `penTest` (for `pentest`), `incident`, `received`, `acknowledged` (for `report`); `assessed`, `severity` and `owner` (together); `fixed`, or `accepted` and `acceptedBy` (together), `notes`. See [vulnerabilities and penetration tests](#vulnerabilities-and-penetration-tests). |
| `penTests` | External penetration tests: `id`, `vendor`, `reported`, `reportSha256` (the tester's report's SHA-256), `retested` and `retestSha256` (together), `notes`. One a year. |
| `changes` | Changes to production systems under the [change management policy](policies/change-management.md#production-changes): `id`, `system`, `kind` (`standard` by default, or `emergency`), `recorded` and `recordSha256` (the change record's SHA-256), `approved` and `approvedBy` (together), `made`, `madeBy`, `incident` (for `emergency`), `interrupts` and `startsAt` (together), `announcedAt`, `verified`; for `emergency`, `reviewed` and `reviewedBy` (together), `code`, `pullRequest` and `followedUp` (together); `notes`. See [production changes](#production-changes). |

## Conduct concerns

The [code of conduct](policies/code-of-conduct.md#handling-concerns) has every concern recorded when it is received, triaged within 7 days by someone holding (or deputising) the People lead, Management or Security owner role, and closed within 90 days ([ADR 0214](../adr/0214-code-of-conduct-and-concerns-in-the-register.md)). The register holds only what shows that happened:

```json
{ "id": "CC-2027-01", "received": "2027-03-02", "triaged": "2027-03-04", "handledBy": "person-1",
  "closed": "2027-04-10", "outcome": "not-substantiated" }
```

- `outcome` is `substantiated`, `not-substantiated`, `withdrawn` or `referred` (to an incident, the authorities or another process). A concern is triaged before it is closed, even one withdrawn.
- Never put who raised a concern, who it is about, or what it says in the register, its ids or its `notes`: they go in the people lead's confidential case file. `notes` never reach the bundle, but the register is kept beside it.
- A register with no concerns is normal. The bundle counts concerns by outcome and flags each triaged or closed late, or still open past its deadline, and each handled by someone not holding one of those roles that day.

## Incidents

The [incident response plan](policies/incident-response.md) has every security event triaged by the security owner or operator, who names a commander and sets a severity; customers told of a possible personal data breach within the DPA's hours; a written review within 10 business days of closing every SEV-1, SEV-2, possible breach and outage that spent over a quarter of the error budget, with owned actions; and a tabletop exercise every year with every role ([ADR 0223](../adr/0223-incidents-in-the-register.md)). The incident ticket, its timeline, the notices and the review stay in the store; the register holds only what shows those happened, and when:

```json
{ "id": "INC-2027-03", "detected": "2027-03-08", "triaged": "2027-03-08", "commander": "person-2",
  "severity": "SEV-2", "breach": true, "awareAt": "2027-03-08T10:00:00Z",
  "customersNotifiedAt": "2027-03-09T16:00:00Z", "closed": "2027-03-12",
  "reviewed": "2027-03-19", "reviewSha256": "<sha256 of the review>",
  "actions": [{ "id": "INC-2027-03-A1", "owner": "Engineering lead", "due": "2027-04-30", "done": "2027-04-20" }] }
```

- Record every security event, including one triaged as not an incident (`"severity": "none"`): that it was looked at, in time, is the evidence. `commander` is who triaged it and took command; they must hold or deputise the Security owner or Operator role that day.
- Triage is due on the day detected or the next for SEV-1 and SEV-2 (their 15-minute and 1-hour targets are judged in the incident record, which has the times), within a business day for SEV-3, and within 5 for the rest and for an event nobody has triaged yet. Business days are Monday to Friday; public holidays are not excluded, since they differ by country.
- `breach` is a possible personal data breach; `awareAt` and `customersNotifiedAt` are UTC times (`YYYY-MM-DDTHH:MM:SSZ`), since the DPA's commitment is in hours. A breach has a severity other than `none`.
- `errorBudget` is an outage that spent over a quarter of the month's error budget. It, a breach, SEV-1 and SEV-2 need a written review; `reviewSha256` is the review document's SHA-256.
- `actions` are the review's (or tabletop's) follow-ups: `id` (unique across the register), `owner` (a role), `due`, and `done` when finished.
- A tabletop's `attendees` must include someone holding or deputising each of Security owner, Operator, Engineering lead and Privacy lead that day (the plan's "every role"; Management and People lead aren't required). The first is due a year after the plan's first approval.
- Never put customers', users' or attackers' names, addresses or what was exposed in the register, its ids or its `notes`: they go in the incident record. `notes` never reach the bundle.
- A register with no incidents is normal, but a year without a tabletop is not. The bundle counts events by severity and flags triage, notices, reviews and actions late or overdue, a commander not holding the role, and a missing, incomplete or unrecorded tabletop. Something done late is flagged in the bundle of the month it was done; something overdue, in every bundle until it is done.

## Production access

The [access control policy](policies/access-control.md#granting-access) has production access requested in writing and approved by the security owner, and admin access to a managed server or the hosting provider by Management too, nobody approving their own; a leaver's access removed by their last day; and every system reviewed each quarter, by the security owner or a delegate who isn't reviewing their own access, with findings fixed within 5 business days, or 1 for admin access ([ADR 0231](../adr/0231-production-access-in-the-register.md)). The written request, the approval and each system's user list stay in the store; the register holds only what shows those happened:

```json
"systems": [{ "id": "hosting", "kind": "hosting", "since": "2026-12-01" }],
"access": [{ "person": "person-3", "system": "hosting", "level": "admin", "requested": "2027-03-08",
  "approved": "2027-03-09", "approvedBy": ["person-1", "person-2"], "granted": "2027-03-10" }],
"accessReviews": [{ "system": "hosting", "at": "2027-03-15", "by": "person-2",
  "listSha256": "<sha256 of the user list>", "mfa": true,
  "findings": [{ "id": "AF-2027-03-1", "admin": true, "fixed": "2027-03-16" }] }]
```

- List every system the policy's scope names that you use: each managed server (`superbot`), the hosting provider (`hosting`), and the code host, object storage, DNS, payments, SMTP, push and error tracker accounts (`other`). Record each person's access to each, with one record per level: a change of level ends one grant (`removed`) and starts another.
- Approvals are checked by role on the day: someone other than the grantee holding or deputising the Security owner role, and for `admin` on a `superbot` or `hosting` system someone other than the grantee holding or deputising Management (one person holding both is enough). A grant made in a bundle's period without `requested` is flagged, since the policy asks for a written request. Access granted before the register was started can be recorded without `requested` or `approved`; only grants made in a bundle's period are checked.
- A leaver's access is due gone by their `left` day, the first day they aren't personnel; retiring the system (`until`) ends it too. Access still recorded is flagged in every bundle until `removed` is set; removed late, in the bundle of the month it was removed.
- Each system in use is reviewed within 92 days of the last review (a new one, of its `since`). `listSha256` is the SHA-256 of the user list exported for the review, kept in the store; for a managed server it is the access-review report's digest, the one its `access_review.completed` sign-off records, and with `--access-review <system>=<file>` the bundle checks that a sign-off of that digest was made on that server that UTC day. A review of a server given no file is listed as not checked (`reviewedWithoutSignOffFile`). `mfa` is whether every account on the system was seen to need a second factor; a system whose latest review says `false` is flagged until a review says `true`.
- A finding's `id` is unique across the register; `admin` is set when it concerns admin access, which must be fixed within 1 business day rather than 5.
- The bundle lists each system, grant and review by id, flags each problem above, and maps `access.json` to CC6.1-2, CC6.2-2 and CC6.3-2 only while every system in use at the period's end has been reviewed in time and has its access recorded. Never put names, emails or account names in the register's ids: `notes` never reach the bundle.

## Vulnerabilities and penetration tests

The [information security policy](policies/information-security.md#vulnerability-management) has every vulnerability tracked with a severity, an owner and a due date, and fixed, or accepted by the security owner or Management, within 30 days for Critical and High and 90 for the rest; [`SECURITY.md`](../../SECURITY.md) has reports acknowledged within 3 days and assessed within 10; and the policy has an external penetration test every year, its Critical and High findings retested within 30 days of the last being fixed or accepted ([ADR 0241](../adr/0241-vulnerabilities-and-penetration-tests-in-the-register.md)). The monthly [vulnerability bundle](soc2-evidence-plan.md#the-vulnerability-bundle) already covers Dependabot and code scanning alerts, so record only the rest here. The report, the advisory, the fix and the tester's documents stay in the store or the private GitHub security advisory; the register holds only what shows those happened, and when:

```json
"penTests": [{ "id": "PT-2027", "vendor": "vendor-7", "reported": "2027-05-10",
  "reportSha256": "<sha256 of the report>", "retested": "2027-06-20", "retestSha256": "<sha256 of the retest letter>" }],
"vulnerabilities": [
  { "id": "V-2027-04", "source": "report", "received": "2027-03-02", "acknowledged": "2027-03-03",
    "assessed": "2027-03-06", "severity": "high", "owner": "Engineering lead", "fixed": "2027-03-20" },
  { "id": "V-2027-07", "source": "pentest", "penTest": "PT-2027", "received": "2027-05-10",
    "assessed": "2027-05-12", "severity": "low", "owner": "Operator",
    "accepted": "2027-06-01", "acceptedBy": "person-1" }]
```

- `source` is `report` (under `SECURITY.md`), `pentest` (with `penTest` naming the test), `vendor` (a vendor's advisory that affects the service) or `internal` (found by the provider, such as in a review). `incident` names the incident it was triaged as, when it was one; `vendor` names the tester when it is in `vendors`.
- Every deadline is in calendar days from `received`, the day it was reported or found, as `SECURITY.md`'s are. `acknowledged` is the day the reporter heard back, for reports only. `assessed` is the day its `severity` (`critical`, `high`, `medium`, `low`, or `none` for not a vulnerability) was set and an `owner` role named. Until it is assessed it is held to the shortest window.
- It is closed by `fixed` (released, or deployed to the managed service) or by `accepted` with `acceptedBy` holding or deputising the Security owner or Management role that day; the reason goes in the advisory or the risk register. One assessed as `none` is closed by being assessed.
- A penetration test is due a year after the last, the first a year after the information security policy's first approval. Once each of its `critical` and `high` findings is fixed or accepted, a retest of the fixes is due within 30 days of the last of them being fixed or accepted; `retested` counts only if it is on or after the last fix.
- Never put reporters', testers' or customers' names, or what is affected, in the register's ids: `notes` never reach the bundle, and the advisory holds the detail.
- A register with no vulnerabilities is normal, but a year without a penetration test is not. The bundle counts vulnerabilities by severity and source, flags each acknowledgement, assessment, fix and retest late or overdue, each acceptance by someone not holding the role, and a missing penetration test. It maps `vulnerabilities.json` to CC2.3-1 and CC4.2-1 while the information security policy's approval is current, and to CC3.2-2 while there was a penetration test in the year.

## Production changes

The [change management policy](policies/change-management.md#production-changes) has every production change (upgrading a managed server or host, changing its settings, the tiers file, the hosting or storage accounts, DNS) recorded and approved by someone other than whoever makes it, before it is made; planned changes that may interrupt the service announced at least 48 hours ahead; and the service and the configuration baseline checked the same or the next business day. An emergency change is approved by the incident commander, reviewed by a second person within 2 business days, followed by a normal pull request within 5 if it was code, and listed in the next quarterly management review ([ADR 0270](../adr/0270-production-changes-in-the-register.md)). Code changes to this repository aren't recorded here: the monthly [change-management bundle](soc2-evidence-plan.md#the-change-management-bundle) has them from GitHub. The change record (what, why, the risk, how to roll back, who approved it) stays in the store or the pull request, issue or ticket it was written in; the register holds only what shows those happened, and when:

```json
"changes": [
  { "id": "CHG-2027-031", "system": "superbot-1", "recorded": "2027-03-03", "recordSha256": "<sha256 of the change record>",
    "approved": "2027-03-04", "approvedBy": "person-2", "made": "2027-03-06", "madeBy": "person-3",
    "interrupts": true, "startsAt": "2027-03-06T22:00:00Z", "announcedAt": "2027-03-03T12:00:00Z", "verified": "2027-03-08" },
  { "id": "CHG-2027-032", "system": "hosting", "kind": "emergency", "incident": "INC-2027-03",
    "recorded": "2027-03-09", "recordSha256": "<sha256 of the incident's change entry>",
    "approved": "2027-03-08", "approvedBy": "person-2", "made": "2027-03-08", "madeBy": "person-2", "verified": "2027-03-08",
    "reviewed": "2027-03-10", "reviewedBy": "person-3", "code": true, "pullRequest": 1234, "followedUp": "2027-03-12" }
]
```

- `system` is one of the register's [production systems](#production-access), in use the day the change was `made`. Whoever made it (`madeBy`) should have a grant to it on record that day; one without is flagged, so record the access too.
- A standard change is `recorded` (`recordSha256` is the change record's SHA-256, kept in the store) and `approved` on or before the day it is `made`, by someone other than `madeBy` who is personnel that day. The policy names no approving role; the bundle shows the role the approver held.
- `interrupts` marks a change that may interrupt the service; `startsAt` is when the maintenance starts (a UTC time on the day it was made) and `announcedAt` when it was announced on the status page, at least 48 hours before. An emergency change needs no announcement.
- `verified` is the day the operator checked the service (health, `/status`, alerts) and the server against the configuration baseline: the day it was made or the next business day.
- An `emergency` change names the `incident` it was made in, made on or after the day it was detected. `approvedBy` is that incident's `commander`, or someone holding or deputising the Security owner role that day, who takes over command; they may make it themselves and record it afterwards. `reviewed` is due within 2 business days, by someone who neither made nor approved it. A change to code (`code`) is followed by a normal pull request: its number (`pullRequest`) and the day it merged (`followedUp`), within 5 business days. The first management review after it lists it in `emergencyChanges`.
- Never put customers' names, hostnames, addresses or what the change did in the register's ids: `notes` never reach the bundle.
- A month with no production changes is normal. The bundle counts changes by kind, flags each recorded or approved after it was made, unapproved, self-approved (standard) or approved by someone not personnel, made without recorded access, announced late or not at all, not checked in time, an emergency change approved by someone other than the commander or the security owner, reviewed late or by someone who made or approved it, without its pull request in time, or missed by the next management review. How a change was made and approved is judged in the bundle of the month it was made; something done late, in the bundle of the month it was done; something overdue, in every bundle until it is done. It maps `production-changes.json` to CC8.1-2 while the change management policy's approval is current.

## Vendors' assurance reports

The [vendor management policy](policies/vendor-management.md#yearly-review) has every Critical and High vendor's newest assurance report read yearly, by the security owner or Management, for its exceptions and for the complementary user entity controls it expects of the provider, with a note of how the provider meets each; findings treated as risks; a hosting provider's report a SOC 2 Type II or ISO 27001, since the service inherits its physical security (CC6.4-1); and a SOC 2 report more than 92 days past its period topped up with the vendor's bridge letter ([ADR 0279](../adr/0279-vendor-assurance-reports-in-the-register.md)). The report, the note and the bridge letter stay in the store; the register holds only what shows the review happened, of which document, and what it found:

```json
"assuranceReports": [
  { "id": "AR-2027-01", "vendor": "linode", "kind": "soc2-type2", "coversFrom": "2025-10-01", "coversTo": "2026-09-30",
    "reportSha256": "<sha256 of the report>", "opinion": "unqualified", "deviations": true, "risk": "R-07",
    "cuecsSha256": "<sha256 of the note of complementary controls>",
    "bridgedTo": "2026-12-31", "bridgeSha256": "<sha256 of the bridge letter>", "reviewed": "2027-01-08", "reviewedBy": "person-2" }
]
```

- `kind` is `soc2-type2` (`coversFrom` to `coversTo`, its period), `soc2-type1` (`coversTo`, its date), `iso27001` (`coversFrom`, the certificate's issue, to `coversTo`, its expiry) or `questionnaire` (`coversTo`, the day it was answered), for a vendor with neither report. Record one entry per document reviewed; a later review of the same report is a new entry.
- `opinion` is the SOC 2 auditor's: `unqualified`, `qualified`, `adverse` or `disclaimed`; `deviations` is whether its tests of controls found any. Either finding names the `risk` in the register that treats it, identified before the end of the period being judged: a risk added later treats only later months. `cuecsSha256` is the SHA-256 of the note of how the provider meets each complementary user entity control the report lists; a SOC 2 report without one is flagged.
- A SOC 2 report speaks for its vendor until 92 days after its period, or after `bridgedTo`, the day the vendor's bridge letter speaks to (on or before the review: a letter received later is a new entry); an ISO 27001 certificate until it expires; a questionnaire for the year the review counts for. `reviewedBy` must hold or deputise the Security owner or Management role that day. A report review also counts as its vendor's yearly review.
- The bundle's `vendors.json` lists the year's report reviews by id with their digests, and flags a Critical or High vendor in use with no report reviewed in the year, or whose newest one no longer speaks for it, a hosting provider without a SOC 2 Type II or ISO 27001, and, in the month it was reviewed, a reviewer not holding the role, a SOC 2 report without its note of complementary controls, an opinion other than unqualified, and findings without a risk. It maps `vendors.json` to CC6.4-1 only while every hosting provider in use at the period's end has a SOC 2 Type II or ISO 27001 reviewed in the year that still speaks for it and holds up (reviewer, note, findings treated). Never put the auditor's or vendor's staff names in the register's ids: `notes` never reach the bundle.

The cadences are the policies' ([information security](policies/information-security.md), [vendor management](policies/vendor-management.md), [code of conduct](policies/code-of-conduct.md), [incident response](policies/incident-response.md), [access control](policies/access-control.md), [change management](policies/change-management.md), [the policy set](policies/README.md#adopting-them), and [`SECURITY.md`](../../SECURITY.md)): a year is 365 days and a quarter 92. Change them in the policies first, then in [`register.rs`](../../server/src/bin/superbot-evidence/register.rs), whose unit tests check the template against the policies.
