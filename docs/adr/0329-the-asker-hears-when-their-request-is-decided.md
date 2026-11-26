# 0329: The person who asked hears when their request for a role is decided

## Status

Accepted (26 Nov 2026). Part of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"). Deferred by [ADR 0302](0302-team-owners-hear-of-requests-for-team-roles.md) ("Tell the asker when it's decided ... the audience mechanism makes it a small change later"). Builds on [ADR 0209](0209-requests-for-time-bound-roles.md) (requests for time-bound roles), [ADR 0263](0263-team-owners-decide-requests-for-team-roles.md) (team owners decide them), [ADR 0320](0320-two-approvers-for-chosen-roles.md) (two approvers), [ADR 0061](0061-approval-notifications.md) (notifications) and [ADR 0080](0080-client-push-notifications.md) (push).

0329 was set aside for this change; other open pull requests hold 0327, 0328, 0330 and 0331.

## Context

Requests for roles are just-in-time access: someone asks for a time-bound role for a few hours, and an admin, or their team's owners and admins, decide. Since ADR 0302 the people who decide hear of a new request by email and push. The person who asked hears nothing. They learn the outcome only by opening Settings and looking at **Your requests**.

So someone on call who asked for access at 2am waits for a role that was given minutes later, or keeps reloading Settings. A denial with a note ("ask your lead") goes unread. A request nobody decides lapses after 7 days without a word. The time between "approved" and "using it" is part of the time-bound role's hours, so a late look also wastes the grant.

ADR 0302 added `notify::Audience`, the people who can act on an alert, but every audience so far is deciders: it rides along with the server's notification email list and webhook, keeps out read-only people (who can't approve), and its email follows `email.deciders`. A notice about your own request fits none of that.

## Options

1. **Tell the asker, through the same alert path, with an audience that is only them.** One flag on `Audience` changes who the plan reaches; email, push, redaction and the audit of each send stay as they are.
2. **Send decisions to the notification list and webhook too.** Admins decided the request or can read it in the audit log; mailing the list for every decision is noise, and the webhook would now carry who was given what.
3. **A per-person inbox in the app.** Useful one day for many kinds of notice, but it's a new store and screen, and still says nothing when the app is closed.
4. **Do nothing; the request's status shows in Settings.** The gap above stays.

We chose option 1.

## Decision

### When

| The request | The asker hears |
|---|---|
| Approved (by the only approver, or the second of two) | Yes |
| Given its first of two approvals | No: it's still pending, and the next notice is the decision |
| Denied | Yes, with the note |
| Lapsed: nobody decided within 7 days | Yes |
| Lapsed: the role stopped being requestable | Yes |
| Lapsed: they were disabled | No |
| Withdrawn by them | No |

Whoever decided (a server admin, or the team's owners and admins), the asker hears the same.

### Where

- **Only them.** Never the notification email list or the webhook. `Audience` gains `only`; with it set, `Notifier::alert_plan` starts from an empty plan rather than the global one, and the email has no console link.
- **Email** to their address while email is on (`email.enabled`, with SMTP set). It doesn't follow `email.deciders`: that switch is for "the people who can answer", and the asker isn't being asked anything; it's their own request, and they asked for it.
- **Push** to their phones that want approvals, as ADR 0302 does for deciders. The app's switch now reads "An approval or request is waiting for you, or yours is decided".
- **Read-only people too.** They may ask for roles (ADR 0209), so they hear by email. The rule that read-only people never get push devices (they can't register one) is unchanged.
- Service accounts and disabled people are never in a plan, as before. The asker is read fresh when the notice is made, so someone disabled meanwhile hears nothing.

### What it says

- **Email**: "Your request for *role* was approved", "was denied" or "lapsed". An approval says until when they hold it, where (across the server or in which team), for how many hours, who approved it (both people for two approvers) and the approver's note. A denial says who denied it, the note, and what was asked. A lapse says why, and what was asked. Each links to the app's Settings, where **Your requests** lists it. Like every alert, the text goes through secret redaction. Its lines are kept whole rather than cut at 200 characters as other alerts' are, since a note runs to 500.
- **Push**: "Your request for a role", with "It was approved.", "It was denied." or "It lapsed with no decision." No role, team, person or note: a lock screen may show it (ADR 0080). Its data is `{type: "role_decision", url: "/settings"}`; the app opens Settings for that type whatever the URL says, as it never follows a push's URL.

### Audit

Each send is the usual `notification.sent` or `notification.failed`, with `event` set to `role.request_approved`, `role.request_denied` or `role.request_lapsed`, the role as target, and email's `to` or push's `users` naming the asker. Nothing new is stored.

## Alternatives considered

- **Follow `email.deciders` for the asker's email too.** An operator who turned it off to keep email to the list would also silence people's own decisions, which nobody else receives. The switch's label ("email goes to the people who can answer") doesn't describe the asker.
- **A separate push switch for "my requests".** It needs a new column on push devices and a third toggle for something that happens a few times a month. The approvals switch already covers requests for roles (ADR 0302).
- **Tell the asker of a first approval.** It changes nothing for them, and for team requests the second approver is often moments behind. The decision is the notice that matters.
- **Name the role in the push.** Role names such as "Prod database admin" say what someone is doing; the lock screen rule from ADR 0080 holds.
- **Warn before a granted role ends.** Useful, and could use the same `only` audience, but it is a reminder on a timer, not a decision. Left for later.

## Consequences

- Someone who asks for a role hears the outcome by email and on their phone as soon as it's decided, or when it lapses, without watching Settings.
- The notification list and webhook carry exactly what they did before.
- `notify::Audience` can now reach a person about their own things; a later notice (such as a role about to end) can reuse it.
- No migration, setting, route or permission changes. One push type (`role_decision`) and one switch label are new in the app.
- ADR 0272's last follow-up is unchanged and not started: a per-role switch for what teams may give, worth it only if roles gain team permissions a team's owners don't hold.

## Tests

- `role_requests_http_tests::the_asker_hears_when_their_request_is_decided_or_lapses`, on the real router with a stand-in mail server and push provider: an approval reaches only the asker, by email (until when, hours, approver, note, a Settings link, no console link, not the reason) and push (no role; opens Settings), audited with `event` and the asker; a read-only asker hears of a denial by email with `email.deciders` off, with a note of over 400 characters whole; a lapse with no decision is told; a withdrawn request and one from someone since disabled tell nobody; with two approvers the first approval tells the asker nothing and the second names both approvers; admins' phones get nothing.
- `team_role_requests_http_tests::a_first_approval_tells_the_others_who_may_give_the_second`: the second approval, by a team's owner, now tells the asker and nobody else.
- `notify::tests::an_alert_only_for_its_audience_skips_the_list_and_the_webhook`: an audience of deciders gets the list, the webhook and only people who may approve; one that is `only` them gets neither the list nor the webhook, keeps read-only people, never disabled ones, follows `email.enabled` alone, and its email links to the app and not the console.
- The client's `push.test.ts`: `role_decision` opens Settings, and never its URL.
