# Quarterly business review template

A template for the review the technical account manager (TAM) holds each quarter with an Enterprise customer's sponsor and owner ([TAM programme](tam.md#cadence)). Copy it into the customer's record, fill it in from the last three [health checks](health-check.md) and the support system, and send it two business days before the meeting. An hour is enough; the second half is about what comes next, not what went wrong.

Keep it free of personal data that isn't needed: people by role, Bots by purpose, incidents by ticket number. The [health score](health-score.md) report has no names or emails and can be pasted as it is.

Start with `botctl business-review` ([below](#draft-it-first)): it fills in what botd recorded over the quarter, so the TAM's time goes on goals, tickets and what's next.

## Draft it first

```sh
# The last three whole months, as this template in Markdown
botctl business-review -o review-2026-q3.md

# A quarter ending with another month (this month at the latest)
botctl business-review --to 2026-09 -o review-2026-q3.md

# For a CRM or a deck
botctl business-review --to 2026-09 --json
```

| Option | What it does |
|---|---|
| `--to <YYYY-MM>` | The quarter's last month, UTC. The last whole month by default; this month shows its figures so far and says so |
| `--json` | The figures as botd sends them, from `GET /api/support/business-review?to=<YYYY-MM>` (admins only), instead of Markdown |
| `-o <file>` | Save it, readable by you only, instead of printing it |

It runs on the customer's server, signed in as an admin (`SUPERBOT_TOKEN`, or the password); on a self-hosted one, the customer's admin runs it and sends the file. The console's Support tab has the same as **Draft business review**, with the month to end on. Each draft is recorded in the audit log as `support.business_review_drafted`, with its months and counts. Design: [ADR 0262](../adr/0262-business-review-draft.md).

What botd fills in, month by month or for the quarter:

| Section | From botd's records | Left to fill in |
|---|---|---|
| Heading | botd's version and data regions | The customer, attendees, deployment type |
| 1. Their goals | Nothing | All of it |
| 2. Health | The score and band botd recorded at each month's end ([history](health-score.md#history)), the signals at watch or at risk then, the month's health checks (`support.health_checked`) with the last one's open items, the quarter's trend, and each signal flagged | What was done about each signal |
| 3. Adoption and usage | People active in the last 30 days and licensed seats now; runs finished, failed or timed out, refused at a plan's limit, token limits reached and runs held to run limits, by month; runs and failures by the harness that ran them, for the quarter | Seats bought, teams that grew or stopped (`botctl usage`) |
| 4. Support and incidents | Status page incidents posted in the quarter or still open: impact, times, duration and whether a review was drafted ([drafts](incident-review.md#the-review-draft)); the `botctl support-report` command for the quarter's months | Tickets, each Severity 1 and 2's cause and actions |
| 5. Security, compliance and data | Access reviews signed off; changes to native SAML, SCIM tokens, custom roles, role grants and residency pins; single sign-on, SCIM and approval failures, machine backup failures and residency refusals by month; backups now, machine restores and residency warnings | The last restore drill, security pack and DPA changes |
| 6. What's next | botd's version, and when the license ends | Releases that matter, roadmap asks, their plans |
| 7. Actions | A row for each signal at watch or at risk at the quarter's end, each incident still open and each major or critical one with no review | Owners, dates, the rest |

Like the health check, it holds codes, counts, dates, harness names, region ids and incident ids: never a person's name or email, an incident's title, an address or a bucket. Months are calendar months in UTC. When the audit log keeps less than the quarter reaches back (`AUDIT_RETENTION_DAYS`), the draft says its earliest months show fewer events than happened.

---

## `<customer>`: business review, `<quarter>`

**Attendees:** `<sponsor>`, `<customer owner>`, `<tam-name>`, and anyone invited for an agenda item.
**Deployment:** `<managed shared | dedicated | VPC | on-premises>`, `<connected | air-gapped>`, version `<version>`, region `<region>`.

### 1. Their goals

What they said they wanted at kickoff or the last review, in their words, and where each stands: met, on track, or not yet (and why).

| Goal | Measure | Last quarter | This quarter |
|---|---|---|---|
| `<goal>` | `<measure>` | | |

### 2. Health

| | Month 1 | Month 2 | Month 3 |
|---|---|---|---|
| Health score and band | | | |
| Signals at watch or at risk | | | |

Take the scores from the health checks' records. For the quarter as a whole, `botctl health-score --days 90` on the server, and `botctl health-score history --days 90` for how it moved day by day (or ask the customer's admin for their output).

For each signal at watch or at risk this quarter: what it was, what was done, and whether it's fixed.

### 3. Adoption and usage

- People with a seat, and active in the last 30 days (the score's `adoption` facts), against seats bought.
- Bot runs per month and the share that failed (`runs` facts), and which harnesses.
- Usage against the plan's limits (`botctl usage`), and anyone at a limit every month.
- Teams or uses that grew, and ones that stopped.

### 4. Support and incidents

- Tickets opened and closed by severity; response targets met and missed: `botctl support-report <export> --customer "<customer>" --from <first month> --to <last month> --markdown` on the ticket system's export, with the customer's agreed `--target`s ([support report](support-report.md)).
- Severity 1 and 2 incidents: ticket, date, impact, cause, and the review's actions with their state. Each review's "Status page targets" section ([incident reviews](incident-review.md#what-it-holds)) says whether the first post and the hourly updates were on time.
- Tickets on the same thing more than once, and what would stop them.

### 5. Security, compliance and data

- Access review signed off this quarter (if their policy asks), SSO and SCIM changes, custom roles added or removed.
- Backups within their RPO; the last restore drill and its times against the RTO.
- Residency pins and any refusals; changes to the security pack, DPA or subprocessors they were told about.

### 6. What's next

- Releases since the last review that matter to them, and the next upgrade window.
- Roadmap items they asked for, with what the Provider can say about them (no dates that aren't committed).
- Their plans for next quarter: new teams, regions, identity provider or network changes, renewals and seats.

### 7. Actions

| Action | Owner | Due |
|---|---|---|
| | | |

---

## After the review

Send the filled-in review and its actions to the attendees within 3 business days, and put the actions in the support system with their owners. Anything the customer asked for that the TAM can't promise goes to the support manager or the product owner, with an answer back to the customer by the next check-in.
