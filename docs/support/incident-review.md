# Incidents and their reviews

The incident commander's tools ([escalation](escalation.md#inside-the-provider)): posting and updating the status page from the server's shell with `botctl incident`, and a draft of the review every Severity 1 needs ([after a Severity 1](escalation.md#after-a-severity-1)) with `botctl incident review`, made from what botd already recorded. The draft fills in what records can say: the public timeline, botd's restarts and configuration changes, what failed while it lasted, and whether the status page's targets were kept. People write the rest: impact, cause, lessons and actions. Design: [ADR 0201](../adr/0201-incident-review-drafts.md). Running the incident itself: the [Severity 1 runbook](runbook-major-incident.md).

## Posting and updating

The same incidents as the console's Status tab and `/api/status/incidents` ([ADR 0090](../adr/0090-status-page-and-uptime-slo.md)), for when the console is slow or down, or the commander works from a shell. Admins only, and every change is audited (`status.incident_created`, `status.incident_updated`, `status.incident_deleted`). **Anyone can read what you post**: no customer names, hostnames, error text or internal details.

```sh
botctl incidents                                   # the newest 100, open or not, open ones first
botctl incident open "Bot runs fail" "Runs are failing for some customers. We're looking into it." \
  --impact major --component runners --component api
botctl incident update inc_3f2a9c identified "A configuration change broke runs. We're rolling it back."
botctl incident update inc_3f2a9c monitoring "Rolled back. Runs are succeeding again; we're watching."
botctl incident resolve inc_3f2a9c "Fixed. Runs have succeeded for an hour."
botctl incident edit inc_3f2a9c --impact critical --component runners
botctl incident delete inc_3f2a9c --yes           # only for one posted by mistake
```

| Option | What it does |
|---|---|
| `--impact` | `none`, `minor` (the default), `major`, `critical` or `maintenance`. It raises the components named to degraded, partial outage or major outage on the public page while the incident is open |
| `--component` | One of `api`, `database`, `machines`, `runners`, `notifications`; repeat it for each. `edit` replaces the list |
| `--state` | `open` only: the first entry's state, `investigating` by default |
| `--title` | `edit` only: a new title, up to 120 characters |
| `--yes` | `delete` only, which takes the incident and its timeline off the page for good |

The states are `investigating`, `identified`, `monitoring` and `resolved`; each update's text is up to 2,000 characters and goes on the incident's public timeline. Resolving ends the incident (a later update in another state reopens it). The [SLO](../slo.md#status-page-and-incidents) asks for the first post within 15 minutes of confirming an incident and an update at least hourly until it's resolved: each update says what's known, what's being done and when the next update comes ([severity](severity.md#updates-until-its-fixed)).

## The review draft

```sh
botctl incident review inc_3f2a9c --detected 2026-11-20T09:40:00Z -o review-inc_3f2a9c.md
```

It prints Markdown, or saves it with `-o` to a new file (never over one, readable only by you). The console's Status tab has a **Draft review** link on each incident that downloads the same file, and an admin can fetch it from `GET /api/status/incidents/{id}/review?format=markdown` (JSON without `format`). Each draft is audited as `status.incident_reviewed`.

| Option | What it does |
|---|---|
| `--detected <time>` | When the incident was detected: the page alert, the probe or the first customer report. YYYY-MM-DD, RFC 3339 or unix milliseconds, at or before the first post. With it, the draft judges the 15-minute first post and measures the incident from detection; without it, from the first post |
| `--lead-hours <n>` | How far before the start to look for changes and botd's starts: 1 to 168 hours, 24 by default |
| `--json` | The draft's data as JSON instead of Markdown, for a script or another document |
| `-o <file>` | Save it to this file instead of printing it |

Make it once the incident is resolved. A draft of an open one runs to now and says so at the top.

### What it holds

| Section | From | Filled in |
|---|---|---|
| Summary | The incident: id, status page impact, components, detected, posted, identified, resolved, duration | All but the severity |
| Timeline (UTC) | Every status page post, botd's starts (with the version) and changes to its configuration from the lead-in to the end, nearest the start first when there are more than 50 | Add what people did and decided, and when |
| Status page targets | The first post against detection (15 minutes), and every stretch between posts over an hour while it was open (time spent resolved before a reopening doesn't count). Maintenance has no update target | Yes |
| What botd saw | Bot runs finished and failed, sign-in failures, requests denied, all failures and denials, and audit events, while it lasted and for the same length of time just before; the most frequent failures while it lasted | Yes |
| Impact, cause, what went well | | Left for people |
| What went badly | A missed first-post or update target | Add the rest |
| Actions | | One row each: action, owner by role, due date, ticket |

"Changes" are successful audit events that change how botd behaves: the approval policy and its rules, roles, SSO and MFA settings, the license, notifications, egress policies, setup, tiers and users' tiers and roles, SCIM and service tokens, secrets set or deleted, billing mail settings, Bots' settings, and botd starting. Traffic (runs, sign-ins, auto-approved tool calls, API calls) is counted, not listed. For the full log of any stretch: `botctl audit --from <time> --to <time>`.

The draft reads at most 20,000 audit events for the lead-in and as many for the incident; on a busier server it says its counts are low.

### What it never holds

Like the [support bundle](support-bundle.md), the draft names nobody. Actors are kinds (`user`, `bot`, `system`) and targets are types (`policy`, `role`, `bot`), never names, emails, ids, IP addresses or sign-in subjects; free-text reasons and details aren't read. The only free text is the status page's, which was written for the public. Keep it that way as you fill it in: people by role ("the on-call engineer"), customers by ticket number.

## Finishing the review

Within 5 business days of a Severity 1 ([escalation](escalation.md#after-a-severity-1)):

1. **Draft it** once the incident is resolved, with `--detected` from the alert or the first ticket.
2. **Complete the timeline** from the incident channel and the ticket: who (by role) did what, and the decisions.
3. **Write impact and cause.** Impact from the draft's counts and the tickets: customers, people and Bots affected, for how long, and data lost against the plan's RPO ([machine recovery objectives](../security/machine-recovery-objectives.md)). Cause down to the one that, fixed, stops it happening again.
4. **Write what went well and badly**, starting from the targets the draft flagged, and **actions** with an owner by role, a due date and a ticket each.
5. **Share it**: link it from the incident's last status page update (`botctl incident update <id> resolved "<text with the link>"`), send it to affected Enterprise customers through their [TAM](tam.md), and walk through it at the next [quarterly business review](qbr-template.md#4-support-and-incidents).
6. **Change the runbooks** the review changes, in this folder.

A rollback after an upgrade or a Severity 2 that the [runbooks](README.md#the-playbooks) didn't cover gets a review the same way.
