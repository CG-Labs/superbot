# 0302: Team owners and admins hear of requests for team roles themselves

## Status

Accepted (26 Nov 2026). Part of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"): the first follow-up [ADR 0272](0272-advanced-rbac-delivered.md) ranked, on top of [ADR 0209](0209-requests-for-time-bound-roles.md) (requests for time-bound roles), [ADR 0263](0263-team-owners-decide-requests-for-team-roles.md) (team owners decide requests for team roles), [ADR 0061](0061-approval-notifications.md) (notifications) and [ADR 0080](0080-client-push-notifications.md) (push).

0302 was set aside for this change; other open pull requests hold 0298, 0301 and 0303 to 0305.

## Context

Since ADR 0263, a team's owners and admins decide requests for roles in their team. But a new request still goes only to the server's notification email list and webhook (ADR 0209), which reach server admins. The team's owners and admins learn of it only when they open Team and see the count.

So a team whose owner rarely opens Team leaves its members waiting a week until the request lapses, or a server admin decides it after all: the help-desk load ADR 0263 meant to take off them. ADR 0263 and ADR 0272 both named this as the gap, and noted the notifier had no way to reach chosen people.

## Decision

### Who hears of it

A new request within a team also reaches the people who may decide it there (`role_requests::team_deciders`): the team's **owners and admins** who are active, not read-only, not service accounts, and not the asker.

Nobody on the team hears of it when the team can't decide it, since ADR 0263 refuses those approvals:

- the asker is one of the team's owners or admins, or
- their role in the team comes from their identity provider (a SCIM mapping or team role group).

Requests across the server reach only the notification list and webhook, as before. The alert's own text says "in Roles" for these, rather than also naming Team.

The list is worked out when the request is made, and the notice goes at once. Requests have no delay or digest: ADR 0209 already caps them at 5 pending and 10 a day per person, and push keeps its per-person hourly limit (ADR 0080).

### How it reaches them

- **Email**, while email is on and `email.deciders` is on, to each one's address, one message each. That is the switch that already sends a Bot's approvals to its owner and operators: "the people who can answer". It's on by default. The console and the app now label it that way.
- **Push**, to their phones that opted into approvals, whatever the email switches say, as ADR 0080 does for a Bot's deciders.
- The server's email list and webhook get the alert as before. The webhook's JSON adds `appLink` for these alerts.

The notifier gains one general piece: an alert may carry an **audience** (`notify::Audience`), the people who can act on it themselves, with the app page they act on it in and what their phones show. `Notifier::alert_plan` adds their addresses and devices to the global plan, keeping out anyone read-only, disabled or a service account. Only this alert uses it today.

### What it says

- **Email** is the alert the list gets: who asked, the role, the hours, the reason, the team, and when it lapses. It adds a link to the app's Team screen, for the team's owners and admins, beside the console link for admins. The team's owners and admins already see all of this on Team (ADR 0263).
- **Push** says only "Request for a team role" and "Someone on *team* is waiting for your decision": no name, role or reason, since a lock screen may show it (ADR 0080). Its data is `{type: "role_request", url: "/team"}`. The app opens Team for that type whatever the URL says, as it never follows a push's URL.

### Audit

Each send is the usual `notification.sent` or `notification.failed`, with `event: "role.requested"` and the role as target. Email's details list every address it went to and push's every person, so who heard of a request is on the record. Nothing new is stored.

## Alternatives considered

- **A setting of its own** (`email.teamManagers`). It splits one idea, "the people who can answer get email too", into two switches that would almost always match. Push is per phone already.
- **Email the team's members too, or anyone holding `users.manage` in the team.** They can't decide it (ADR 0263), so it would only be noise.
- **Wait and fold requests into a digest, as approvals do.** Approvals come in bursts from a running Bot. Requests come from people, a few a day at most, and a decision can take days.
- **Tell the asker when it's decided.** Useful, but a different audience and event. The audience mechanism makes it a small change later.
- **Per-person targets for every alert now**, such as server admins' own alerts (ADR 0272 suggested "then for server admins' own alerts"). Each alert needs its own rule for who may act on it. This change adds the mechanism and the first rule.

## Consequences

- A request for a team role reaches the team's owners and admins who may decide it, by email and on their phones, without a server admin passing it on or anyone watching Team.
- Server admins still get every request, so a team with nobody to decide stays covered.
- No new tables, columns, settings or routes. One switch's label changes in the console and the app, and the app's push handling gains one destination.
- ADR 0272's other follow-ups are unchanged and not started: `botctl` team commands for owners, Bot handover under `bots.manage`, two approvers for chosen roles, handing several Bots to a service account at once, and a per-role switch for what teams may give.

## Tests

- `team_role_requests_http_tests::team_owners_and_admins_hear_of_requests_they_may_decide`, on the real router with a stand-in mail server and push provider: a member's team request reaches the list, the team's owner and admin by email and push, never a read-only or disabled admin, the asker, a plain member or another team's owner; the email links to Team; the push names nobody; the audit lists who heard. A team admin's own request and a request across the server reach only the list. With `email.deciders` off, owners and admins still hear on their phones.
- `notify::push::tests::pushes_never_carry_what_a_bot_asked_to_run`: an alert with no audience sends no push, and one with an audience sends only its title, body and Team link.
- The client's `push.test.ts`: `role_request` opens Team, and never its URL.
