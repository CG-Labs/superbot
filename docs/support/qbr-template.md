# Quarterly business review template

A template for the review the technical account manager (TAM) holds each quarter with an Enterprise customer's sponsor and owner ([TAM programme](tam.md#cadence)). Copy it into the customer's record, fill it in from the last three [health checks](health-check.md) and the support system, and send it two business days before the meeting. An hour is enough; the second half is about what comes next, not what went wrong.

Keep it free of personal data that isn't needed: people by role, Bots by purpose, incidents by ticket number. The [health score](health-score.md) report has no names or emails and can be pasted as it is.

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

Take the scores from the health checks' records. For the quarter as a whole, `botctl health-score --days 90` on the server (or ask the customer's admin for its output).

For each signal at watch or at risk this quarter: what it was, what was done, and whether it's fixed.

### 3. Adoption and usage

- People with a seat, and active in the last 30 days (the score's `adoption` facts), against seats bought.
- Bot runs per month and the share that failed (`runs` facts), and which harnesses.
- Usage against the plan's limits (`botctl usage`), and anyone at a limit every month.
- Teams or uses that grew, and ones that stopped.

### 4. Support and incidents

- Tickets opened and closed by severity; response targets met and missed (from the support system).
- Severity 1 and 2 incidents: ticket, date, impact, cause, and the review's actions with their state.
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
