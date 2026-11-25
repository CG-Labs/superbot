# 0263: Team owners and admins decide requests for roles in their team

## Status

Accepted (25 Nov 2026). Sixteenth slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0209](0209-requests-for-time-bound-roles.md) (requests for time-bound roles) and [ADR 0254](0254-team-owners-give-custom-roles-in-their-team.md) (team owners give custom roles in their team).

0263 was set aside for this change; other open pull requests hold 0264 to 0267.

## Context

ADR 0209 lets a person ask for a requestable, time-bound role, across the server or within their own team, and sends every request to server admins. ADR 0254 then let a team's owners and admins give any custom role with a team permission to their team's plain members by hand, with or without an end. It named "team owners approving requests for team roles" as the next follow-up.

So a member asking for `users.manage` in their team for onboarding week waited on a server admin, though the team's own owner could have given the same role by hand. Either the server admin became the help desk for every team's requests, or the owner gave the role by hand, losing the request's reason, its "someone else approved" record and its end by default.

## Decision

### Who decides, and what

A team's **owners and admins** decide the requests made within their team, beside server admins:

- `GET /api/team/role-requests?status=pending|approved|denied|cancelled|lapsed|all`: the team's requests, pending ones by default, newest first, with how many are pending. Same shape as `GET /api/role-requests`, plus the team.
- `POST /api/team/role-requests/{id}/approve` `{hours?, note?}`: as ADR 0209's approval, for the hours asked or fewer, from now.
- `POST /api/team/role-requests/{id}/deny` `{note?}`.

Server admins keep `/api/role-requests` for every request, team ones included, as before. Whoever acts first decides it; the other sees it's decided (409).

Requests across the server stay with server admins only. They change someone's role across the server, which no team owner can do.

### What an approval checks

The approval is ADR 0209's: the same transaction rereads the request, the role, the person and their team membership, and refuses (409, leaving it pending) if anything no longer fits. Team owners and admins get two more checks, read in that same transaction:

- **Plain members only.** If the person is now one of the team's owners or admins, it's refused, as ADR 0254 refuses giving them a role: they can already do all of it. A server admin can still approve it.
- **Not over the identity provider.** If a SCIM mapping or team role group gave them their role in the team (ADR 0138, ADR 0206), it's refused: the IdP owns it, as in ADR 0254. A server admin's approval takes it over, as before.

The rest is as ADR 0209: never your own request (409), never longer than asked (400), the role must still be requestable and within its limit, and the person active, on the team, not read-only and holding no other role there.

### Who doesn't

- **Team-role holders** with `users.manage` in the team can't see or decide requests (403), as they can't give roles (ADR 0254).
- **Service accounts and Bots** never do: the routes need a person who is an owner or admin of the team.
- **Read-only owners and admins** may list (the route is `Account`, like `GET /api/team`), but approving and denying are `Write`, so RBAC refuses them.
- **Other teams' requests**, and requests from someone no longer on the team, are 404 and left out of the list, so a team owner learns nothing about people outside their team.

Denying needs no such checks: it changes no one's access. A team's owners and admins may deny a request from another of them, or one over an IdP role.

### Audit

`role.request_approved`, `role.request_denied` and the `role.assigned` an approval writes carry `via: "team"` when a team's owner or admin acted, as ADR 0254's grants do. The actor is that person. A server admin's decision has no `via`, as before. The end is cleared by the existing sweep as `role.expired`.

### Where it shows

- `GET /api/team` adds `roleRequests`, the number pending, for the team's owners and admins who can write, beside `roleChoices`.
- The new-request alert (ADR 0209) says a team request can also be decided by the team's owners and admins in Team.
- **App.** On the Team screen, owners and admins see **Requests for team roles** when any wait, each with who asked, the role, what it adds in the team, the hours and the reason. They approve (as asked or shorter) or deny, with an optional note the asker sees. A request from the team's owners or admins, or over an IdP role, offers only Deny, with why; your own says who decides it. The app fetches the list only when `roleRequests` is above zero, so members and older servers aren't asked.
- The console stays admin-only, and `botctl role requests|approve|deny` stay on the admin routes.

## Alternatives considered

- **Only server admins decide, as ADR 0209.** It leaves server admins as every team's help desk, and since ADR 0254 owners can already give the role by hand, it guards nothing.
- **Route team requests to the team only.** Server admins are the backstop when a team has one owner who is away, or the owner is the one asking. Keeping both is simpler than a hand-off rule.
- **Let team owners approve requests across the server.** A role across the server changes what someone may do everywhere; team owners can't give that by hand either.
- **Notify the team's owners and admins directly.** The notification service sends to the server's email list and webhook, not to chosen people. The count on `GET /api/team` and the Team screen show it; per-person notices can come with per-person targeting.
- **A separate "teams may decide requests for this role" switch.** As ADR 0254 found for giving, owners can grant more by making someone a team admin, so it would guard nothing.

## Consequences

- A team member's request for a team role can be approved by their own team's owners and admins, with the request's reason, the approver and the end in the audit log, without a server admin.
- No new tables or columns: one more query over `role_requests` by team, and one more check value read in the approval's transaction.
- Still to do for #53: nothing from its scope. Follow-ups could be handing several Bots to a service account in one request, `botctl` team commands for owners, or notifying a team's owners and admins of new requests directly.
