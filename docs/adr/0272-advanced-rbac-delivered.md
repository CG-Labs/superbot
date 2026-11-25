# 0272: Advanced RBAC is delivered, and what follows it

## Status

Accepted (25 Nov 2026). Closes the scope of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC") after sixteen slices, the last [ADR 0263](0263-team-owners-decide-requests-for-team-roles.md). The follow-ups below are proposed, not started.

0272 was set aside for this change; other open pull requests hold 0273 to 0276.

## Context

#53 asks for "Custom roles and service accounts", and the roadmap's M5 scope says the same: "advanced RBAC (custom roles, service accounts)". Both are merged, tested, and in the server, the app, the console and `botctl`:

| #53 asks for | Delivered by | Checked by |
|---|---|---|
| Custom roles | Roles built on member or read-only from six fixed permissions, given across the server or within a team, deny by default and kept away from admins ([ADR 0123](0123-custom-roles.md)); a roles editor in the app and the console, effective permissions in Users, and `botctl role` ([ADR 0132](0132-custom-roles-in-the-apps.md)); SCIM and SAML groups mapped to roles, never admin ([ADR 0138](0138-scim-group-role-mapping.md), [ADR 0160](0160-saml-groups-and-role-mapping.md), [ADR 0206](0206-scim-team-role-groups.md)); time-bound roles ([ADR 0197](0197-time-bound-custom-roles.md)) and requests for them, approved by someone else ([ADR 0209](0209-requests-for-time-bound-roles.md)); team owners and admins give roles in their team ([ADR 0254](0254-team-owners-give-custom-roles-in-their-team.md)) and decide their team's requests (ADR 0263) | `rbac` unit tests (the route matrix and the delegate limits), `roles_http_tests`, `team_roles_http_tests`, `role_requests_http_tests`, the SCIM and SAML mapping tests, the client tests |
| Service accounts | Non-human callers holding member, read-only or a custom role, never admin, through hashed, scoped, expiring tokens, capped on every request by their owner ([ADR 0143](0143-service-accounts.md)); in the app and the console ([ADR 0152](0152-service-accounts-in-the-apps.md)); granted Bots, never beyond their owner ([ADR 0170](0170-service-accounts-granted-bots.md)); delegates' own accounts, acting in their team only while their owner is on it ([ADR 0182](0182-delegates-own-service-accounts.md)); keeping and being handed their owner's Bots ([ADR 0222](0222-service-accounts-keep-their-owners-bots.md), [ADR 0229](0229-handing-bots-to-service-accounts.md)); every owner sees and stops their own ([ADR 0239](0239-owners-see-and-stop-their-service-accounts.md)) | `service_accounts_http_tests`, `service_account_bots_http_tests`, `kept_bots_http_tests`, the `botctl` request tests |
| Reviewable by an auditor | People and service accounts in the signed-off access review, with roles, ends, owners, tokens and flags, in its CSV and the evidence bundle ([ADR 0165](0165-service-accounts-in-access-reviews.md), [ADR 0188](0188-service-accounts-off-their-team-in-access-reviews.md)); every grant, request, decision and expiry audited | `access_review_http_tests`, `evidence_http_tests` |

The last three ADRs (0239, 0254, 0263) each said "still to do for #53: nothing from its scope" and built follow-ups an earlier ADR had deferred. Each still defers more, so #53 would never end if every deferral stayed under it. [ADR 0259](0259-per-user-computer-hardening-delivered.md) met the same question for #54.

## Options

1. **Keep #53 open** and keep taking deferred items under it.
2. **Call #53 delivered**, and list the deferred items as follow-ups, ranked, each for an issue of its own.

We chose option 2, as ADR 0259 did. Each follow-up is a separate choice with its own cost and priority, and is easier to weigh, schedule or drop as an issue of its own than as a seventeenth slice of a finished one.

## Decision

#53 is delivered. The roadmap says so, and no further slices are made under it.

These follow-ups are proposed, in order of value. None is started. Each would need an issue (under M5, or later) and an ADR of its own.

1. **Telling a team's owners and admins of new requests themselves** (deferred by ADR 0209 and ADR 0263). A request for a team role goes to the server's notification email and webhook, and the team's owners and admins see it only when they open Team. A team whose owner never opens it leaves its members waiting, or a server admin decides instead. Likely shape: per-person targets in the notification service (email and push to chosen users), used first for team requests and then for server admins' own alerts.
2. **`botctl` team commands for owners** (deferred by ADR 0254 and ADR 0263). Team owners and admins give roles and decide requests only in the app or with raw API calls; `botctl role assign|approve|deny` call the server admin routes, which refuse them. Likely shape: `botctl team role assign|unassign` and `botctl team requests|approve|deny` on `/api/team/members/{user}/custom-role` and `/api/team/role-requests`, with the same tests as the other `botctl` request builders.
3. **Bot handover under `bots.manage`** (deferred by ADR 0123). Handing a disabled person's Bots and routines to someone else ([ADR 0047](0047-disabled-users-routines.md)) still needs a server admin, though a `bots.manage` holder already lists a person's Bots and routines and resumes them. Offboarding is the main delegated chore that is left to admins. It needs a rule for what the handover may not reach (admins' Bots, primary Bots) and a line in `rbac::classify`.
4. **Two approvers for chosen roles** (deferred by ADR 0209). One approver who isn't the asker meets the usual control, but some roles (`users.manage` across the server, `machines.manage`) may warrant two. Likely shape: a per-role `approvals: 2` on the same requests, the second approval giving the role, and both approvers in `role.request_approved`.
5. **Handing several Bots to a service account at once** (deferred by ADR 0229, ADR 0239 and ADR 0263). Today it's one `PUT /api/bots/{id}/keeper` per Bot. A list in one request, checked against the 20-per-account limit in one transaction, saves scripts and the app a loop.
6. **A per-role switch for what teams may give** (deferred by ADR 0254 and ADR 0263). It guards nothing while every team permission is one a team's owners already hold. It's worth it only if roles gain team permissions owners don't hold.

Rejected by the ADRs above and not proposed here: team-defined roles (ADR 0254), group-given time-bound roles (ADR 0197), the IdP sending roles (ADR 0138), delegates managing each other (ADR 0123), and service accounts owning, sharing or claiming Bots (ADR 0222, ADR 0229).

## Consequences

- #53 can be closed once this is merged. No behaviour changes, and nothing needs upgrading.
- The follow-ups stay visible in one place, ranked, rather than only in the Alternatives and Consequences sections of sixteen ADRs.
- Until owners are told of requests themselves, a team that relies on its own owners to decide them should watch the count on Team, or leave the server's notification email reaching someone who does.
- Until handover is delegated, offboarding a person's Bots and routines stays with a server admin.

## Tests

None: this changes only docs. The links are checked by the docs workflow's site build.
