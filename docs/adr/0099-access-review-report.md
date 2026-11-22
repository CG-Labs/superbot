# 0099: The access-review report and its sign-off

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row CC6.3-1 and gives row CC6.3-2 its tool, in the [readiness checklist](../security/soc2-readiness-checklist.md). Builds on the admin portal ([ADR 0021](0021-admin-portal.md)) and the audit log ([ADR 0009](0009-audit-events.md), [ADR 0019](0019-audit-actors.md)).

0097 is the highest number on `main`, and open PR #158 renumbers its ADR to 0098, so this is 0099.

## Context

SOC 2's CC6.2 and CC6.3 expect access to be reviewed on a schedule: someone accountable looks at who can get in, with what rights, removes what shouldn't be there, and leaves a dated record that they did. Auditors ask for the list that was reviewed and the sign-off, for every review in the period.

SuperBot had the pieces but not the report. The admin portal shows each person's role, last sign-in and Bot access one person at a time, sessions are listed on another screen, second factors and machines on others, and nothing records that anyone looked. A reviewer would have to stitch screenshots together, and nothing would tie the sign-off to what they saw.

## Decision

### One report, admins only

`GET /api/access-review` returns everyone who has an account, grouped by the SCIM tenant that manages them (if any) and then their team (ADR 0087), each with:

- **Who**: id, name, email, role, status (`active` or `disabled`), whether they're the owner (break-glass) account, and their tier.
- **Where they come from**: the SCIM tenant and whether it deleted them ([ADR 0023](0023-scim.md)), and their team and team role.
- **How they sign in**: whether a second factor is on and since when ([ADR 0094](0094-totp-second-factor.md)), and when and how they last signed in.
- **Bot access**: for admins, `all` (their role reaches every Bot, so listing each adds nothing); for everyone else, each Bot they can reach as ACLs decide it for their role now ([ADR 0017](0017-bot-acls.md)), with its owner, whether it's theirs, the access level and any grant.
- **Live sign-ins**: browser sessions and API tokens (bearer sessions for the client and `botctl`), each with its id, method, label, when it started, was last used and ends. Never the token or its hash.
- **Machine**: their machine that isn't destroyed, its state and enrollment, and whether it's assigned so their Bots run on it ([ADR 0036](0036-bots-on-the-users-machine.md)).

A summary counts people, active and disabled, admins, active people without a second factor, SCIM-managed people, sessions, API tokens and machines.

It is admin-only by RBAC's default arm (a route nobody classified needs `Admin`, [ADR 0012](0012-users-sessions-rbac.md)), and the handlers also refuse Bots. Team owners and admins don't get it: ADR 0087 lets them manage teammates' machines but not see their sign-ins or Bots, and a team-scoped report would have to decide which of these columns they may see. That is left for when a customer asks.

The report is metadata only. It never carries a token, its hash, a sign-in code, a second-factor secret, a secret value or an IP address. IP addresses and user agents stay on the sessions screen, where an admin investigating one person looks; a reviewer needs to know a credential exists, not where it was last used.

### Exportable and dated

`GET /api/access-review/export.csv` is the same report as RFC 4180 CSV, one row per person, with the same formula escaping as the audit export. Every row starts with when the report was generated and ends with its digest, and the file is named `superbot-access-review-<UTC time>.csv`, so a saved copy says when it was true. Each export is audited as `access_review.exported` with the digest and the summary. The app passes the digest of the report on screen (`?digest=`); if access changed since, the export is a 409, so the saved file is the report being reviewed.

### A sign-off tied to what was seen

Every report has a **digest**: SHA-256 over the parts that define access (each person's role, status, email, SCIM tenant, team and team role, second factor, Bot access with grants, the ids of their sessions and tokens, and their machine and its assignment). When a session was last used is left out, so the reviewer's own requests don't change it under them.

`POST /api/access-review/complete` `{digest, notes?}` signs off. botd rebuilds the report; if the digest doesn't match, access changed since the reviewer loaded it (someone was added, a grant changed, a token was made) and the answer is 409, asking them to reload. Otherwise it writes `access_review.completed` to the audit log with the reviewer as the actor (their id, email, role, sign-in method and session, as every event has, ADR 0019), the time, the digest, the summary and up to 500 characters of notes. Unlike other audit writes, which log a failed insert and carry on, the sign-off is the operation: if it can't be saved, the answer is 500, never a success. The audit log is append-only, so the sign-off can't be edited afterwards. The report lists the last 20 sign-offs.

We considered a separate reviews table. The audit log already is the append-only, attributed, exportable record auditors are pointed at, with retention and filters; a second store would need its own triggers and export. A sign-off is one event, `GET /api/audit?action=access_review.*` finds them all, and the audit CSV export carries them.

We also considered a per-person sign-off (keep or remove, person by person). It's heavier for small teams, and the actions it would record (disable, change role, revoke a grant or session) are audited already where they're done. One sign-off over a digest says the whole list was reviewed; the changes the reviewer made are next to it in the log.

### In the app

Admins get **Access review** in the sidebar of the Expo client: the summary, everyone by tenant and team with flags for what to look at twice (admins, no second factor, disabled people still signed in or still holding a machine, SCIM-deleted people), Export CSV (a download on web, the share sheet on phones, named as the server named it, which botd lets a browser on another origin read), notes and **Mark as reviewed**, and the past sign-offs. Others see that it's for admins.

## Consequences

- Checklist row CC6.3-1 is done. CC6.3-2, periodic reviews signed off, is a process row: the product now records each one, but someone still has to do them, every quarter, for admins, operators and production access outside SuperBot.
- Reviewing is a whole-server report. On a server with very many people it is one long page and one larger response; paging can come when someone needs it.
- A busy server may change between loading and signing off (a new sign-in is a new session id). The reviewer reloads and signs again; that is the point of the digest.
- The check and the save are not one transaction: the store takes its lock per query, and the report reads many tables. A change that lands in the same instant as a sign-off is not refused; it is in the audit log right beside it, the sign-off still names the digest the reviewer saw, and the next report's digest differs.
- Team-scoped reviews for team owners, and a reminder when a review is due, are not built.
