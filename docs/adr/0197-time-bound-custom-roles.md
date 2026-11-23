# 0197: Time-bound custom roles

## Status

Accepted (23 Nov 2026). Tenth slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0123](0123-custom-roles.md) (custom roles), [ADR 0132](0132-custom-roles-in-the-apps.md) (roles within a team) and [ADR 0099](0099-access-review-report.md) (access reviews).

0197 was set aside for this change; other open pull requests hold 0198 to 0201.

## Context

A custom role, once given, is held until someone takes it away. Regulated customers (SOX, PCI, HIPAA, SOC 2 CC6.2/CC6.3) want elevated access to be temporary: an on-call engineer gets `machines.manage` for a shift, an auditor gets `audit.view` for the audit window, a contractor gets `users.manage` for a week. Today an admin has to remember to take it back, and the access review only finds it at the next review.

Two things are missing:

1. A way to give a role until a time, after which it stops granting anything, without anyone acting.
2. A way to say a role is only ever given like that, so a powerful role can't become standing access by mistake, or through a group mapping nobody watches.

## Decision

### Ends on roles given by hand

- `PUT /api/roles/{id}/users/{user}` and `PUT /api/roles/{id}/teams/{team}/users/{user}` take an optional body `{expiresAt, reason}`. No body, or `{}`, works as before.
  - `expiresAt` is Unix ms. It must be in the future and at most 365 days away. `null` or absent means no end.
  - `reason` is up to 500 characters. It goes into the audit event only.
  - Unknown fields are refused with 400, so a typo like `until` doesn't silently give standing access.
- Giving the role again to someone who holds it moves the end, or clears it. That is audited as `role.assigned`, with the previous end in `from`, even when only the end changed.
- The end lives on the holder's row, beside the role: `users.role_expires_at` and `team_members.role_expires_at`.

### Enforcement

- The row readers (`user_row`, `team_member_row`) treat a role whose end has passed as not held. Every check that reads a user or a team member sees no custom role at once: the same session, the same request, before any sweep. There's no separate check for each route to forget.
- A sweep every 60 seconds clears ended roles, and so does the start of every `/api/roles` handler, so the admin screens show what is really held.
  - Each one is audited as `role.expired` by the system actor `roles`, with the user, the scope (`org` or `team`), the team, the end, and, across the server, the built-in role they keep.
  - Across the server they keep the role's base as their built-in role, as when an admin takes it away. Someone who was an admin before is never made admin again by an end.
- An end follows its role. SQLite triggers clear `role_expires_at` whenever `role_id` changes without the end being set, so a role given later by SCIM, by SAML, or by setting a built-in role never inherits an old end.

### Time-bound roles

- A role can have `maxDays` (1 to 365), set on create or with `PATCH`, or cleared with `null`. A time-bound role:
  - is given only by hand, and only with an end at most `maxDays` days away. The limit is checked in the same SQL statement that writes the role, so a limit set at the same moment can't be raced;
  - can't be mapped to a SCIM group (ADR 0138), a SCIM role group (ADR 0180) or a SAML group (ADR 0160), since a group gives standing access;
  - can't be held by a service account (ADR 0143), which holds its role for as long as it exists, and isn't offered to them.
- Making a role time-bound, or lowering its limit, is refused with 409 while anyone holds it with no end or with a later end than the new limit allows, while a service account holds it, or while a group is mapped to it. The count is taken in the same transaction as the write.
- `role.created` and `role.updated` record `maxDays`.

### Where the end shows

- `GET /api/roles/{id}` holders, `customRole` in the admin user views, `/api/auth/me` and `/api/team`, and the user's `roleExpiresAt`.
- The access review shows `customRole.expiresAt` and `team.customRole.expiresAt`. The digest covers the ends only when there is one, so reports with no ended roles keep their digests, and moving an end makes an earlier sign-off stale (409). The CSV role cells end with ` until <RFC 3339>`.
- The app and the console offer an end (8 hours, 1 day, 7 days, 30 days, 90 days, or none) and a reason when giving a role, and only ends within the limit for a time-bound role, starting at the shortest. They show "ends in 3 days" beside each holder, and a time limit field on the role. The console's user and team dropdowns don't offer time-bound roles, since those need an end; they're given from the Roles tab.
- `botctl role assign <role> <user> [--team T] [--for 8h|7d] [--reason TEXT]`, and `botctl role add|edit --max-days N|none`.

## Alternatives considered

- **Ends on the role, not on each holder.** One end for everyone suits an audit window, but not a shift rota or a contractor. Per holder covers both; a time-bound role's limit gives the shared ceiling.
- **Enforce only in the sweep.** Up to a minute of access past the end, and a failed sweep leaves it open. Reading the end at every row read closes it at the end exactly. The sweep only tidies and audits.
- **Check the end in each permission check.** Many call sites, and a new one could forget. The row reader is the one place every check passes through.
- **Restore the role they had before.** Someone who was an admin would get admin back by a timer, unreviewed. Keeping the base matches taking the role away by hand.
- **Approval requests for roles (request, approve, then grant).** Useful, but a larger workflow with its own screens and notifications. Ends are the building block it would use, so they come first.
- **Let groups give time-bound roles with an end per sync.** The IdP would extend it at every push, so it's standing access by another name.

## Consequences

- Admins can give elevated access that ends by itself, with a reason on record, and mark the roles that must only be given that way.
- Every grant, change of end, and end is in the audit log, which is the evidence SOC 2 CC6.2/CC6.3 asks for.
- A role mapped from a group onto someone whose role ended but wasn't swept yet is given at the next SCIM push or sign-in after the sweep (at most a minute later), since group grants only fill an empty role.
- The time-bound check counts in-transaction, so making a widely held role time-bound needs its holders given an end first. The 409 says how many.
- Still to do for #53: service accounts owning Bots. That needs a rule for whose machine, plan, keys and memory a service account's Bot uses, and touches the machine code throughout.
