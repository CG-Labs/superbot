# 0278: The TAM handover, drafted from botd's records

## Status

Accepted (25 Nov 2026). Fourteenth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the monthly health check in the support bundle ([ADR 0271](0271-health-check-in-the-support-bundle.md)).

Numbering: this number was reserved for this work.

## Context

Every Enterprise customer has a named technical account manager and a backup ([TAM programme](../support/tam.md), [ADR 0144](0144-tam-programme-and-health-score.md)). When a customer changes TAM, or its TAM is away for more than two weeks, the [handover](../support/tam.md#handover) asks for a note in the customer's record: the deployment summary, the last health score with its signals and what's being done, open tickets, incident actions and promises, the people, and the dates coming up. It is the one part of the TAM's cadence botd didn't help with: the monthly check (ADR 0252) and the quarterly review (ADR 0262) are drafted from botd's records, the handover was written by hand from a dozen commands.

botd holds most of it: the health check's reading of its records (ADR 0252) already covers the deployment, the score and what's open; the audit log has the last health check, business review draft and access review; status page incidents have their reviews (ADR 0201); the license, native SAML certificates and SCIM tokens have their end dates.

Constraints as before: Rust first, no new dependencies, codes and counts only, and no change to RBAC, the audit format, the support bundle or air-gapped installs, which other M5 tracks are changing.

## Decision

### A draft of the note, as of now

`tam_handover.rs` builds the handover's five parts for the deployment **as it is when drafted**; a handover is a snapshot taken on the day, so the draft takes no period.

- **The deployment:** botd's version; single sign-on providers by id and kind (Entra, Google, OpenID Connect, Apple, GitHub, SAML through a broker, native SAML); SCIM, its working tokens and the Google Workspace sync; custom roles and the people holding one; machines and their data regions; the health score's backups summary; the approvals policy; Bots counted by harness (never named); people active in 30 days and licensed seats; the license.
- **Health:** the 30-day health score and band, each signal at risk then at watch with its summary, the last month's trend from the score's history (ADR 0157), the newest `support.health_checked` with its open items, and the newest `support.business_review_drafted` with its months.
- **Open work:** every item the monthly health check judges open now, with its detail and guide, and status page incidents still open or of major or critical impact, resolved in the last 92 days, with no review drafted. The health check's judgement is reused (`health_check::gather_with` takes the score and history the draft already read), so the two never disagree.
- **The people:** left entirely to the TAM. botd names nobody.
- **Upcoming dates:** the license's end, native SAML certificates ending within 60 days (whether a newer one is already in use), every token of a SCIM tenant ending within 14 days, the next monthly health check (31 days after the last, now if none), the next quarterly review (the first day of the month after the quarter that follows the last draft's) and the next access review (92 days after the last), soonest first, each marked overdue once its day has passed.

Tickets, incident actions, promises, where it runs, the IdP's admin, model provider accounts, the network, the renewal, upgrade windows, the next restore drill and check-in stay **"To fill in"**, with the command that fills them where there is one.

### Where it's served

`GET /api/support/tam-handover[?format=markdown]` (admins: the route isn't in RBAC's table, so no custom role reaches it, as with the health check and the business review), as JSON or a Markdown download; `botctl tam-handover [--json] [-o <file>]`, Markdown by default; and a **Draft TAM handover** link in the console's Support tab, a download made only when clicked. Unknown parameters are refused without echoing anything that isn't an id. The name says TAM because `botctl user handover` already gives a disabled user's Bots to someone else.

When botd can't read the incidents or the score's history, there is no draft (a 500 saying so) rather than one that says there were none, and nothing is recorded. Each draft is recorded as `support.tam_handover_drafted`, with the format, the score and band, the open item ids, the number of incidents and the dates overdue, so handovers show in the audit log beside the monthly checks and quarterly reviews. It isn't recorded as `support.health_checked`: reading the health check for a handover isn't the TAM's monthly check, and counting it as one would move the next check's due date. The draft holds codes, counts, dates, provider ids, harness names, region ids and incident ids: never a person's name or email, a Bot's name, an incident's title, an address or a bucket.

## Alternatives

- **Fold it into the business review.** The review covers a closed quarter for the customer's sponsor; the handover is for the incoming TAM, today, with what's open and due. Different readers and different periods.
- **Put it in the support bundle.** A bundle goes with a ticket to support engineers; a handover goes into the customer's record. The bundle's format is also being read by other work, and the health check it would repeat is already in it (ADR 0271).
- **Store each handover in botd.** Handover notes hold the people and promises, which belong in the Provider's support system or CRM, not on the customer's server. botd records only that a draft was made.
- **A `--days` window.** The health score's 30 days and the history's month are the windows the monthly check uses; a handover that read different ones would disagree with the last check.

## Tests

`tam_handover`'s unit tests: the query takes a format and refuses anything else without echoing it; dates come soonest first with those botd knows only roughly last, and are marked when overdue; with no records the health check is due now and the review and access review are unknown; a license in grace is overdue; the draft has the five parts in order with each line from the records and "To fill in" for the rest; a new server reads plainly; an open incident is to resolve and review; text from records can't break a table or add a link off the repository; the JSON and audit details hold codes and counts. `tam_handover_http_tests`: admins only (members, read-only, a custom role with every delegable permission and Bots refused), JSON and the Markdown download with its headers, each draft audited and not as a health check; bad parameters refused and not recorded; records botd can't read are no draft and not recorded; on a real server, Bots by harness, the last health check and business review, the next review's date, an unreviewed major incident followed until it's reviewed and resolved, with no name, email, Bot name or incident title in either form. `botctl`'s tests: the options. `interface_http_tests`: the console's link is a download made only when clicked. `tests/support_docs.rs`: the TAM page explains the command, each option, the route, the audit action and the console's link, says what botd fills in for each of the five parts, and the index points at the command.
