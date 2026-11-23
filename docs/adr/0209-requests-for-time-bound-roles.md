# 0209: Requests for time-bound roles

## Status

Accepted (23 Nov 2026). Eleventh slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0197](0197-time-bound-custom-roles.md) (time-bound roles), [ADR 0123](0123-custom-roles.md) (custom roles) and [ADR 0132](0132-custom-roles-in-the-apps.md) (roles within a team).

0209 was set aside for this change; other open pull requests hold 0207, 0208, 0210 and 0211.

## Context

ADR 0197 lets an admin give a role until an end, so elevated access goes away by itself. But the admin still has to know who needs it and when. In practice the person who needs `machines.manage` for an incident, or `audit.view` for an audit window, asks in chat, and the admin gives the role by hand. The "why" lives in chat, not in the audit log, and there's no record of who asked or who agreed.

Regulated customers (SOX, SOC 2 CC6.2/CC6.3, ISO 27001 A.5.18, PCI DSS 7.2) want just-in-time access: a person asks for a named role, for a short time, with a reason; someone else approves; the grant ends by itself; and all of it is evidence. ADR 0197 named this as the next building block, with ends as the part it would use.

## Decision

### Which roles can be asked for

- A custom role has `requestable` (default false), set by an admin with `POST|PATCH /api/roles`, the app, the console or `botctl role add|edit --requestable yes|no`.
- Only a time-bound role (`maxDays`, ADR 0197) can be requestable. Without `maxDays` it's refused with 400. Clearing `maxDays` while requestable is refused with 409; the check runs in the same transaction as the write, so the two can't be raced apart. So every request is for access that ends by itself.
- A role that isn't requestable answers 404 to a request, as an unknown one does, so asking can't be used to list the server's roles.

### Asking

- `POST /api/me/role-requests` `{role, scope: org|team, hours, reason}`. `hours` is 1 to the role's limit (`maxDays × 24`). `reason` is required, up to 500 characters.
- `GET /api/me/role-requests` lists the requestable roles with, for each scope, whether you may ask and why not (the same check `POST` makes), and your last 50 requests.
- Only a signed-in person asks. Admins (who have it all), Bots and service accounts can't. Service accounts can't reach `/api/me` at all (ADR 0143).
- A request never changes a built-in role and never replaces a custom role:
  - Across the server, the role's base must be the person's built-in role. A read-only person asks only for roles built on read-only, so a request can't turn read-only into member.
  - In a team, it's only the team they're on, and never for a read-only person, since team permissions do nothing for them.
  - If they hold another custom role in that scope, they're refused. If they hold the same role with an end, asking again renews it (a new end, from approval). If they hold it with no end, there's nothing to ask for.
- At most one pending request per person, role and scope (a unique partial index), at most 5 pending per person, and at most 10 requests per person in a day, withdrawn ones too (429). The daily cap bounds the alerts below: asking and withdrawing over and over can't flood the email list or webhook.
- Read-only people can ask. This is the one write the "read-only changes nothing" review test allows, because asking changes no access until an admin approves.
- A new request goes to the server's notification email list and webhook (`notify::alert`), with the role, scope, hours and reason, so it doesn't wait for someone to open the Roles screen.

### Deciding

- Admins only: `GET /api/role-requests`, `POST /api/role-requests/{id}/approve` `{hours?, note?}`, `POST /api/role-requests/{id}/deny` `{note?}`. A delegate with `users.manage` can't decide, since they can't give roles either.
- Nobody approves their own request.
- An approver can shorten the time, never lengthen it. The time runs from approval, not from the request, so a request approved late still gets the hours asked.
- Approval checks everything again, in one transaction with the write: the role is still requestable and within its (maybe lowered) limit; the person is active, not an admin, and their base and team still fit; they hold no other role there. It then writes the role and its end the way ADR 0197 does (two statements, since the trigger clears an end when the role changes), drops any SCIM or SAML grant for that scope as giving a role by hand does, and marks the request approved with `grantedUntil`. A refused approval leaves the request pending, with the reason.
- The person withdraws their own pending request with `POST /api/me/role-requests/{id}/cancel`.
- Undecided requests lapse after 7 days. They lapse at once when the role stops being requestable or the person is disabled: SQLite triggers on `roles` and `users` mark the pending requests the moment that changes, so making the role requestable again, or enabling the person again, before the sweep can't bring them back, and approval refuses a marked request in its transaction. The ADR 0197 sweep (every 60 seconds) and every request handler then close and audit them.
- Deleting a role, team or person deletes their requests (`ON DELETE CASCADE`). Erasing a person deletes the person's requests and replaces them as decider with their pseudonym.

### Evidence

- Audited as `role.requested`, `role.request_approved`, `role.request_denied`, `role.request_cancelled` and `role.request_lapsed` (by the system actor `roles`, with why). Each names the request, role, person, scope, team and hours.
- Approval also writes the usual `role.assigned`, with `request` and `reason` (the asker's), `from`, `expiresAt` and what it took from SCIM or SAML. So the access history reads the same whether a role was given by hand or by request, and the end is cleared later as `role.expired`.
- These are new event names in the existing audit log. Nothing in the audit chain, export or SIEM forwarding changes.

### Where it shows

- App: **Request access** under Settings (for everyone but admins, only when a role is requestable or you've asked): pick the role, scope and time within its limit, say why, see your requests and withdraw pending ones. **Requests** at the top of Roles for admins, with Approve (as asked or shorter) and Deny, each with an optional note. A **People may request it** checkbox on a time-bound role.
- Console: the same requests and checkbox on the Roles tab.
- `botctl role request <role> --for 8h --reason TEXT [--team]`, `role my-requests`, `role withdraw <id>`, and for admins `role requests [status]`, `role approve <id> [--for 4h] [--note]` and `role deny <id> [--note]`.

## Alternatives considered

- **Let any role be requested.** A standing role from a request is standing access nobody chose to give for good. Requiring `maxDays` makes every request end by itself.
- **Let a request change someone's built-in role.** Across the server a custom role's base becomes the holder's role, so read-only asking for a member-based role would become member, and keep it when the role ends. Matching bases keeps a request from ever moving a built-in role.
- **Replace the role they hold.** When the new one ends they'd be left with neither. Refusing keeps one role in each scope, as ADR 0123 has it.
- **Let `users.manage` decide.** Delegates can't give roles by hand today. Requests shouldn't be a way around that.
- **Two approvers, or approval chains.** Stronger, but most self-hosted teams have one or two admins and would be stuck. One approver who isn't the asker, with everything in the audit log, meets the usual control. A quorum can come later on the same requests.
- **Start the time when the request is made.** A request approved late would get less than asked, or nothing. Starting at approval is what the approver sees and agrees to.
- **Requests from the IdP, through SCIM.** The IdP would own the approval, but SCIM has no request flow, and groups give standing access (ADR 0197). This stays inside SuperBot, where the role and its end are.
- **Push notifications to admins.** The global email and webhook alert reaches the people who already watch the server. Push to each admin's phone needs per-admin targeting the notification service doesn't have yet.

## Consequences

- Elevated access can be asked for, approved and ended without anyone giving or taking it by hand, and each step is in the audit log, with the reason.
- One more table (`role_requests`) and one more column (`roles.requestable`). Old roles aren't requestable until an admin says so.
- Read-only people can create one kind of record. It's capped (5 pending, one per role and scope) and changes nothing until approved.
- Still to do for #53: service accounts owning Bots.
