# 0102: Erasing a user's data

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50), and GDPR erasure, [#48](https://github.com/CG-Labs/superbot/issues/48); moves checklist row CC6.5-1 from Gap to Partial in the [readiness checklist](../security/soc2-readiness-checklist.md). Builds on users that are disabled, never deleted ([ADR 0012](0012-users-sessions-rbac.md)), the append-only audit log ([ADR 0009](0009-audit-events.md)), SCIM's soft delete ([ADR 0023](0023-scim.md)), teams ([ADR 0087](0087-team-accounts-and-machines.md), [ADR 0095](0095-scim-groups-as-teams.md)) and legal holds ([ADR 0098](0098-chat-retention.md)).

## Context

botd never deleted a person. Disabling someone (by an admin, or SCIM's `DELETE`) ends their sessions and keeps everything: their email and name, sign-in identities, second factor, sealed secrets, Bots, chats and routines, and every audit event that names them. That is right for offboarding, since an owner needs a leaver's Bots and history, but GDPR article 17 gives people the right to have their personal data erased, and SOC 2 CC6.5 asks for a disposal path that is tested and leaves evidence.

Erasure fights with three things botd must keep:

- **The audit log.** It is append-only (database triggers refuse `UPDATE` and `DELETE`), and auditors need its events to stay: who did what, when. Deleting a person's events would also delete the evidence of the erasure.
- **References.** The user's id is a foreign key from machines, usage, billing, teams and many `created_by` columns. Deleting the row means rewriting or orphaning all of them.
- **Duties to keep data.** A legal hold (ADR 0098) is a duty to preserve chat; a team needs an owner; a running subscription has invoices a business must keep; a machine is a disk at a provider that botd can't wipe from the database.

## Decision

**`POST /api/users/{key}/erase` (`botctl user erase <user> --yes`): admin-only, refused while a duty to keep data applies, and leaving a tombstone and a pseudonymised audit log.**

- **Who.** Admins only: the route is under `/api/users`, which RBAC classifies as admin (`rbac::classify`), and the auth review's router walk checks members, read-only users and Bots get 403. Never the owner (break-glass) account, and never yourself (409): another admin does it, so two people are involved.
- **Refusals (409, audited as `user.erase_refused` with a `reason`).** Checked in this order, before anything changes:
  - `legal_hold`: a Bot they own is held, or has messages from a held Bot; or a held Bot's chat has a message they sent or one of their Bots wrote. The message names the Bots; release the holds first. Checked again inside the final transaction, so a hold placed meanwhile still wins.
  - `last_team_owner`: they are the only owner of a team with other members. Make someone else an owner, or delete the team. Erasing a team's last member deletes the team (`team.deleted`, reason `empty`), unless it pays for a plan, which `team_billing::may_delete` refuses as deleting a team does.
  - `paying`: their own plan has a subscription that is still paying. Cancel it first.
  - `team_pays`: they are the last member of a team whose plan is still paying, which would go with them. Cancel the team's plan first. Checked before the machine is destroyed, so a refusal destroys nothing.
  - `checkout_paid`: their last Stripe checkout page was paid and its plan is on the way. An open page is expired at Stripe first (as opening a new checkout does, under the same per-user lock, held until the erasure ends), so it can't be paid once they're gone; if Stripe can't say, 502 to try again.
  - `primary_bot`: they own the primary Bot, which can't be deleted. Give it to someone else first.
  - `machine`: they have a machine. Destroy it first, or erase with `destroyMachine: true` (`--destroy-machine`), which destroys it through the control plane as `DELETE /api/users/{key}/machine` does (`machine.destroy_requested`) and continues only once it is destroyed.
- **What goes.** In order, as disabling and deleting already do, then one database transaction. Once they are disabled (so they can't make more), their Bots are listed again, and runs they asked for and runs on their Bots are stopped and waited for (up to 30 seconds, else 409 to try again), since a run records its end as whoever asked. The Bots an erasure takes on are saved (`erasing_bots:<id>` in `settings`) until it finishes, so a retry after it stopped part way (a hold placed meanwhile, a folder that couldn't be deleted: 500, logged) still erases what those Bots wrote. Nothing is marked erased until every step before the transaction has succeeded.
  - Their access: disabled as an admin's disable does (sessions revoked, SSO and MFA state dropped, routines run for them paused, screens rotated, offboarding off teammates' machines with reason `deleted`); their team membership (`team.member_left`, reason `erased`); their grants on others' Bots (`bot.access_revoked`, reason `user_erased`); runs they asked for in others' Bots stopped.
  - Their Bots, as deleting a Bot does (`bot.deleted`, reason `user_erased`): chat, routines, approvals, notifications, screens and the Bot's folder under `DATA_DIR/bots/`.
  - Their sealed secrets (`secrets::user_forget`), and their folders under `DATA_DIR/users/` and, without per-user isolation, `WORKSPACE_DIR/users/`.
  - What botd keeps in memory about their storage (the last measurement and warning), and, in the transaction, their destroyed machines' last reports of what their homes held ([ADR 0105](0105-machine-disk-use-in-storage-limits.md)), counted as `diskReports`.
  - In the transaction: sessions, login codes, push devices, sign-in identities, second factor and recovery codes, the SCIM link, signups and team invites by their email, billing emails and email preferences, unfinished checkouts, routines they wrote in others' Bots. Messages they sent in others' Bots, and messages their Bots wrote into others' chats, become `[erased]` with no question or requester; who asked for a run is cleared on the rest. Approvals they decided name the pseudonym, without the note.
- **The tombstone.** The user row stays, so every foreign key still holds and nothing is orphaned: no email, name `Erased user`, read-only, disabled, no IdP subject, last sign-in or plan, and new columns `erased_at`, `erased_by` and `erased_as` (the pseudonym, unique). Ids in other tables (`created_by`, `owner_id`, usage, invoices) still point at it; none of them is personal data once the row has none. `GET /api/users/{key}` shows the tombstone with `erasedAt` and `erasedAs`; every other admin route for them answers 410 Gone, and lookups by id or email elsewhere (grants, teams, handover) find nobody (404). An erased user can never be enabled again.
- **The audit log.** Events stay; the erasure rewrites them, in the same transaction, to name the user by a **pseudonym**: `erased-` and 64 random bits as hex, not derived from the id, so it can't be reversed. In every event about them (as actor, target or `onBehalfOf`, or naming their id, email or IdP subject in its details): their id becomes the pseudonym; when they are the actor (including as a visitor without an account, known by their email, as on `signup.submitted`), their name, email, IdP subject, IP address, user agent and session id are cleared; in details, their id becomes the pseudonym wherever it appears, and their emails, name and subjects where a whole value or an email inside a value. Names, emails and sign-in subjects they had before, as `user.created`, `user.updated`, `user.identity_linked` and `user.identity_unlinked` events about them recorded, are scrubbed only from events that name them by id, since someone else may hold them now. The event's time, action, outcome, target type, Bot, role and auth method never change. The pseudonym is stable: every event about them, and the tombstone, carry the same one, so an auditor can still follow one person's history.
- **Keeping the log append-only.** The `audit_events_no_update` trigger now allows an update only while a settings row `audit_erasing` holds a pseudonym, which only `erase_user` writes and deletes inside its transaction, and then only the changes above: id-type columns kept or set to that pseudonym, identifying columns kept or cleared, details free; time, action, outcome and the rest unchanged. Deleting events is still refused. Any other `UPDATE` fails as before.
- **Evidence.** `user.erased`, recorded after the transaction, names the actor (the admin) and targets the pseudonym, with counts of what went (Bots, sessions, identities, secrets, messages, audit events rewritten, files) and the machine and team. Each step's own event (`bot.deleted`, `bot.access_revoked`, `team.member_left`, `user.disabled`, `machine.destroy_requested`) is recorded too, before the rewrite, and so names the pseudonym afterwards.
- **Idempotent.** Erasing an erased user answers 200 with `already: true` and the same pseudonym, and changes and records nothing. One erasure runs at a time per server.
- **SCIM `DELETE` stays a soft delete.** IdPs send `DELETE` when someone leaves, which is offboarding, not an erasure request; turning it into erasure would destroy an owner's Bots and history without anyone asking, and it can't honour holds or teams. Erasure is an admin's explicit follow-up, for SCIM users as for anyone. Erasing a SCIM user deletes the SCIM link, so the tenant sees 404 and provisioning the same person again makes a new user with none of the old history (ADR 0023's restore no longer applies to them).

## What it doesn't cover

- **The isolation folder.** With per-user isolation, their OS user's home (`ISOLATION_DIR/<id>`) belongs to that OS user and only the root helper can remove it. The response reports `isolationFolderLeft`; the operator removes the OS user (`superbot-userctl`). A machine's disk goes with the machine.
- **Backups.** Server backups keep the erased data until `SUPERBOT_BACKUP_RETENTION_DAYS` ends, and machine backups until theirs (deleting those on request is CC6.5-2).
- **Billing records.** Stripe customers, subscriptions and invoices are kept: a business must keep invoices for years, which is a legal basis to keep them (GDPR 17(3)(b)). They name the customer at Stripe, not in botd's database; botd's billing emails go.
- **Harness session files and teammates' archived work** outside the folders above (ADR 0098's remaining items), and their work archived into an owner's `from-teammates/` folder, which is the owner's.
- **Bots' names and memory** that mention them by name, in Bots that aren't theirs, and free text in others' chats that names them (only what they sent is erased).
- **Short names in old audit details.** A name or subject shorter than 8 characters is replaced only in events already found by their id or email, so a short name in an unrelated event's free text stays.
- **Background jobs** already queued for them (offboarding, a machine being destroyed) finish under their old id and record it in their own events.

## Alternatives considered

- **Deleting the user row.** Every foreign key to `users` would need rewriting or cascading, and machines, usage and invoices would lose their owner. The tombstone carries no personal data and keeps the database consistent.
- **Deleting their audit events.** Removes the evidence of who did what, including the erasure. Auditors need the events; GDPR allows keeping them pseudonymised (articles 17(3) and 89).
- **A deterministic pseudonym (a hash of the id).** Anyone with the id could recompute it. A random one, stored only on the tombstone, can't be linked back once the id is gone from the log.
- **Erasing on SCIM `DELETE` (or a setting for it).** See above: offboarding and erasure are different requests, and the IdP can't see holds or teams. A setting can be added later on top of the same function.
- **Transferring a last owner's team automatically.** Picking a new owner is a decision for the admin or the team; refusing with a clear message is simpler and safer.
- **Destroying the machine without asking.** A machine's disk may hold work the owner wants; `destroyMachine: true` makes it a choice.

## Consequences

- Checklist row CC6.5-1 is Partial: an admin API and `botctl` command, tested ([`server/src/erasure_http_tests.rs`](../../server/src/erasure_http_tests.rs): no personal data left in any table, the audit log pseudonymised and still append-only, legal holds, RBAC, last team owner, machines, idempotency; plus unit tests in [`server/src/erasure.rs`](../../server/src/erasure.rs)), with `user.erased`. Left: the isolation folder, backups, and the items above.
- New route `POST /api/users/{key}/erase`; new `botctl user erase`. New audit actions `user.erased` and `user.erase_refused`. New columns `users.erased_at`, `erased_by`, `erased_as`; the `audit_events_no_update` trigger allows the erasure's rewrite.
- Admin routes for an erased user answer 410; lookups by id or email elsewhere answer 404.
