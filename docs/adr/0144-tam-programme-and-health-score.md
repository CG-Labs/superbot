# 0144: TAM programme and customer health score

## Status

Accepted (22 Nov 2026). Second slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the tiers, severities, runbooks and support bundle ([ADR 0131](0131-support-bundle.md)). Reads what the audit log ([ADR 0009](0009-audit-events.md)), server backups, machine RPO tracking and the license already record; adds no new collection.

Numbering: this number was reserved for this work.

## Context

The support tiers promise Enterprise customers a named technical account manager (TAM) who "runs the success cadence". The first slice named the cadence (week 1, monthly, quarterly) but not what a TAM does at each step, what a check covers, or how a TAM tells a healthy customer from one about to leave. Without that, every TAM invents it, and the signals are noticed only when the customer complains.

botd already records the signals a TAM needs: who signed in, how Bot runs ended, single sign-on and SCIM failures with reason codes, approvals that expired, backups against their RPO, and the license's seats and end. The data is there; what's missing is one place that reads it the same way every time.

Constraints:

- **Nothing personal leaves.** The score goes into review decks and tickets, so it must carry no names, emails, IP addresses, Bot names, chats or free-text reasons, as the support bundle doesn't ([ADR 0131](0131-support-bundle.md)).
- **Explainable.** A TAM has to tell a customer why the number is what it is, and what would move it.
- **Rust first, no new dependencies, harness agnostic.**
- **No contact with customers from botd.** botd computes; people decide what to do.

## Decision

### Playbooks

[`docs/support/tam.md`](../support/tam.md) is the programme: who gets a TAM (Enterprise; a backup TAM named too), what a TAM does and doesn't, the cadence from kickoff (within 5 business days of signing) through weekly onboarding check-ins, a monthly [health check](../support/health-check.md), a [quarterly business review](../support/qbr-template.md), restore drills and incident reviews, and handover. Contacts and capacity are placeholders (`<tam-name>`, `<backup-tam-name>`, `<tam-accounts-per-person>`) the Provider fills in. Records of each check and review live in the Provider's customer record, never in this repository.

Five new runbooks cover the M5 features that landed since the first slice: SAML sign-in, custom roles, residency pins, air-gapped installs, and run limits and allow-lists. Each keeps the first slice's shape (first five minutes, escalate when, afterwards).

### Six signals, each ok, watch or at risk

| Signal | Weight | Judged by |
|---|---|---|
| `adoption` | 25 | Share of people with a seat who signed in, or whose session or token was used, in the window |
| `runs` | 20 | Share of finished Bot runs that ended `error` or `timeout` |
| `identity` | 20 | Share of single sign-on attempts that failed; count of SCIM requests with a valid token that were refused or failed, and of revoked tokens still in use. The worse of the two |
| `backups` | 20 | Server backups against their RPO, whether they leave the host, and whether one has yet; machines past their RPO; machine backups that failed |
| `approvals` | 10 | Share of approvals asked for that expired unanswered |
| `license` | 5 | Days to its end; seats in use against the cap |

Each signal is ok (100 points), watch (50) or at risk (0), or n/a when there's nothing to judge. The thresholds are in [the playbook](../support/health-score.md), with what to do for each signal.

- **Discrete verdicts, not a continuous curve.** "Runs: watch, 7% failed" is something a TAM can say and a customer can check; a curve gives 63.4 and no reason. Two thresholds per signal are also easy to test at their edges.
- **Weights favour adoption.** Unused seats are the earliest sign a customer won't renew. Runs, identity and backups break the product for people; approvals and the license matter but are fixed quickly.
- **The score is the weighted mean of signals that aren't n/a.** A new server isn't marked down for runs it hasn't had or SSO it doesn't use. With nothing to judge at all, the score is null and the band `unknown`.
- **Small samples aren't judged.** A share of fewer than 10 events (runs, sign-ins, approvals) is n/a, with the counts still shown. One failed run out of three is not a 33% failure rate.
- **A signal at risk keeps the band out of healthy.** Healthy is 80 or more with no signal at risk; watch is 50 to 79, or 80 or more with a signal at risk; at risk is below 50. A customer whose backups are past their RPO isn't healthy however well adoption goes.
- **Unauthenticated SCIM probes are only counted.** A SCIM request with no token or an unknown one can come from anyone on the internet, so it would let a stranger move a customer's score. A revoked token still in use is counted as a failure: it means the IdP's provisioning stopped.
- **The window is 7 to 90 days, 30 by default.** Shorter is noise; a quarter covers the business review, and longer is history rather than health. When the audit log keeps fewer days than asked (`AUDIT_RETENTION_DAYS`), the report says `partial`.

### Two records added

The score needs two things botd didn't keep:

- **Refused SCIM requests.** A SCIM request with a valid token that botd answers with an error (a duplicate user, a bad request, no seat left, a server error) wasn't audited unless it changed something, so an IdP could fail to provision people for weeks with nothing to count. SCIM's guard now records `scim.request_failed` after the handler, with the tenant, status, method, resource and reason (the error's `scimType` in snake case, such as `invalid_value`, so it stays a code in the score and the support bundle, or `status_<code>`), never the request body. A 404 isn't recorded: IdPs look people up and repeat deletes in their normal course. A request that also has its own event (`scim.group_member_refused`) is counted once, by this one. The tenant's rate limit bounds how many an IdP can cause.
- **When each person was last seen.** Sessions and API tokens are pruned 30 days after they stop working, so a token used early in a 90-day window could take its only record of use with it. `users.last_seen_at` follows each session's own (written at most once a minute, as the session's is), is filled from the sessions there are when the column is added, and is cleared when a person is erased.

### Computed on demand, from existing data

`GET /api/support/health-score?days=<n>` computes the report from the audit log (one grouped query over the window: action, outcome, sign-in method and the `result` or `reason` code, counts only), users' last sign-in and last use, whether a SCIM token was used, server backup status (age from the newest archive copied off the host), open machine RPO breaches and the license. Failures the audit log throttles (unverified sign-in failures and bad SCIM tokens, logged at most once a minute per address) carry how many weren't logged in `unloggedSinceLast`; those are summed apart, since they were of any reason. Single sign-on counts them as failures under the reason `throttled`, so a flood of `bad_signature` isn't counted as a handful. SCIM counts them only as unauthenticated, never as a revoked token, so guesses can't move the score. It returns the score, band, the signals at risk and at watch, and each signal's status, summary, facts and playbook anchor. Reason codes go through the support bundle's `reason_code`, so a free-text reason becomes `[text]`.

It isn't in the RBAC table, so it takes the default for unlisted routes: admins only, as the support bundle. It isn't audited: it's a read of aggregate counts, like usage. `botctl health-score [--days <n>] [json]` calls it with the operator's credentials and prints one line per signal, then which signals to look at and where the playbook is.

No history is stored: botd doesn't keep past scores. A TAM records each check's score in the customer's record. Storing scores would add a table, a retention question and a background job for something a monthly note does well enough.

### In the support bundle

The bundle carries the same report for the last 30 days as `health-score.json`, scrubbed like the other files, so support sees the shape of the last month with the first ticket. The bundle's `FORMAT` goes from 1 to 2.

## Alternatives

- **A continuous score per signal (linear between thresholds).** Smoother, but harder to explain and to test; rejected for discrete verdicts.
- **Equal weights.** Simpler, but a failed license check would weigh as much as half the users never signing in.
- **Storing daily scores in the database.** Gives trends in the console, but adds storage, retention and a job. Left for later if TAMs ask; a console view can add it then.
- **Including support-system data (tickets, response times, satisfaction).** botd can't see the ticket system, and pulling from it would tie botd to one vendor. The review template puts them beside the score instead.
- **Letting customers' members see the score.** It's for the customer's admins and the TAM; members gain nothing from it, and the adoption signal is about them.
- **Sending the score to the Provider automatically.** That would be new collection from self-hosted servers, against the bundle's rule that the customer chooses what leaves. The customer's admin runs the command or sends a bundle.

## Tests

- `health_score.rs`: rules judge at their thresholds; weights sum to 100 and ids are unique; the score is the weighted mean of what can be judged, and a new server is judged on what it has; one signal at risk keeps a high score out of healthy; failed runs are errors and timeouts only; identity takes the worse of SSO and SCIM, and unauthenticated SCIM is only counted; backups take the worst of server and machines; the license is judged by its end and seats; the window is checked; audit counts become inputs; and the playbook's table, sections, bands and window match the code.
- `scim_http_tests.rs`: a duplicate user and a malformed request with a valid token are each audited once as `scim.request_failed` with their reason, a 404 lookup and a bad token aren't, and the score counts them. `db.rs`: a token's use outlives its pruned session.
- `health_score_http_tests.rs`, on the real router: members, read-only users, a custom role with every delegable permission, and Bots get 403, nobody gets 401, an admin gets the report; a window outside 7 to 90 days, or not a number, is 400; the report counts the people, runs, refusals, sign-ins, SCIM failures and approvals the database recorded, and carries no email or Bot name; the grouped audit query starts where asked and returns no actor.
- `support_http_tests.rs`: the bundle has `health-score.json` with every signal, and its manifest lists it.
- botctl's tests: the window and `json` flags, and the summary's lines.
- `server/tests/support_docs.rs`: every runbook (found by name) keeps its shape; this ADR's and the playbooks' links resolve; the TAM cadence links the kickoff agenda, health check, score and review; and TAM contacts are placeholders.

## Consequences

- TAMs and support read the same six signals the same way, and each points to a runbook.
- The score is only as good as the audit log's retention: a short `AUDIT_RETENTION_DAYS` makes long windows partial.
- No trend in botd; TAMs keep it in their records until there's a console view with history.
- The thresholds are a starting point. A Provider changing them changes the code and the playbook together, and the test keeps them in step.
- Still to do for #60: a console button for the bundle and the score, score history, the Provider's real contacts, TAMs and on-call rota, and a support report from the ticket system.
