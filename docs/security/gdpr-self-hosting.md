# GDPR guide for self-hosters

How to meet common GDPR duties with what SuperBot has today, when you run the server yourself. Written from the code on `main`, with links to the design records (ADRs) behind each statement. Part of the [security pack](README.md).

> **Guidance, not legal advice.** It explains what the software does and doesn't do. Whether your use of it complies with the GDPR or UK GDPR depends on your organisation, your purposes and your contracts; ask your own counsel. Nothing here is a certification.

## Who is controller and who is processor

| Who | Role, usually | Why |
|-----|---------------|-----|
| **You**, running SuperBot for your own organisation | Controller of your users' account data and of the content they and their Bots handle | You decide why and how it is processed: who gets access, which Bots run, which model providers they use, how long data is kept. |
| **You**, running SuperBot for your own clients | Processor for each client, who is the controller | Sign a DPA with each client; the [DPA template](dpa-template.md) is a starting point. |
| **CG-Labs** (SuperBot's authors) | Neither, through the software | SuperBot sends nothing to CG-Labs: no telemetry, analytics or crash reporting, and the licence key is checked offline ([subprocessors](subprocessors.md), [ADR 0038](../adr/0038-self-host-license-key.md)). A support contract where CG-Labs sees your data would be a separate arrangement. |
| **Outside services you turn on** (hosting, backup storage, model providers, Stripe, push, email, webhooks, identity providers) | Your processors, or in some cases independent controllers under their own terms | Every one is off until you configure it; the [subprocessor list](subprocessors.md) says what each receives and the setting that turns it on. Check each provider's terms and DPA. |
| **A person signing in a harness with their own Claude or ChatGPT subscription** | That person's own relationship with the provider | Those runs go to the provider under the person's own account ([ADR 0041](../adr/0041-machine-harness-logins-and-folder-copy.md)). Decide whether you allow it. |

Your records of processing (GDPR Article 30) can start from [data flows](data-flows.md) and the [subprocessor list](subprocessors.md).

## Where personal data lives

Full detail, including encryption: [data flows](data-flows.md#what-is-stored-where).

| Place | What it holds |
|-------|---------------|
| `DATA_DIR/app.sqlite` on the server | Users, SSO identities, teams, sessions (hashes only), Bots, chat history, routines, approvals, sealed secrets, push tokens (sealed), audit log, usage and billing ids, access requests from the signup form. |
| `DATA_DIR/users/<id>/` and `DATA_DIR/bots/<id>/` | Each user's facts (`USER.md`) and each Bot's memory and folder. |
| `WORKSPACE_DIR/users/<id>/`, or `ISOLATION_DIR/<id>/` with per-user accounts | Each user's working folder on the server, and their harness sessions ([deploy guide](../../deploy/README.md#one-unix-account-per-user)). |
| Each user's machine (managed setups) | Their working folder, copies of Bot memory and `USER.md`, harness logins and sessions. |
| Server backups, on the host and off it | Copies of `DATA_DIR` ([backup and restore](../ops/backup-restore.md)). |
| Machine backups | Full copies of machines' disks, harness logins included ([machine recovery objectives](machine-recovery-objectives.md)). |
| Outside services | What each receives ([subprocessors](subprocessors.md)): for example prompts and files at model providers, billing records at Stripe. |
| People's devices | A session token and the server address; chats only in memory. |

## Retention settings

Set these in `.env` to match your retention policy. Each deletion pass is audited with its counts, never the content. Details and exceptions: [data flows: retention](data-flows.md#retention).

| Data | Setting | Default |
|------|---------|---------|
| Chat history | `CHAT_RETENTION_DAYS` ([ADR 0098](../adr/0098-chat-retention.md)) | Kept forever |
| Harness session files | `HARNESS_SESSION_RETENTION_DAYS` ([ADR 0112](../adr/0112-harness-session-and-teammate-files-retention.md)) | Kept forever |
| Teammates' archived work | `TEAMMATE_FILES_RETENTION_DAYS` ([ADR 0112](../adr/0112-harness-session-and-teammate-files-retention.md)) | Kept forever |
| Audit log | `AUDIT_RETENTION_DAYS` ([deploy guide](../../deploy/README.md#audit-log-retention)) | Kept forever |
| Sessions | `SESSION_IDLE_TIMEOUT`, `SESSION_MAX_AGE` | 7 days idle, 30 days at most |
| Server backups | `SUPERBOT_BACKUP_RETENTION_DAYS` on the host, `SERVER_BACKUP_RETENTION_DAYS` off it ([ADR 0109](../adr/0109-server-backups-off-the-host.md)) | 14 days, 30 days; the newest off-host copy is always kept |
| Incus machine backups | `MACHINE_BACKUP_RETENTION`, per plan ([ADR 0071](../adr/0071-off-host-machine-backups.md)) | 14 days; the newest of a live machine is always kept |
| Linode machine backups | Linode's own ([machine recovery objectives](machine-recovery-objectives.md#linode-machines)) | The newest daily one and two weekly ones, deleted with the machine |
| Access requests from the signup form | None | Kept until deleted (see [what is missing](#what-exists-and-what-is-missing)) |

`botctl retention` shows the settings, each last pass and held Bots. A Bot an admin holds (`botctl retention hold`, a legal hold) is skipped by retention and can't be deleted or erased until released ([ADR 0098](../adr/0098-chat-retention.md)). Deleted rows stay in server backups until the backups' own retention ends.

## Answering requests

You have one month to answer most requests (GDPR Article 12(3)). Every command below is for admins, on the server ([`botctl` admin commands](../../server/src/bin/botctl.rs)); each `<user>` is an id or email. Erasure and the user routes are under `/api/users`, which only admins reach ([ADR 0012](../adr/0012-users-sessions-rbac.md)). Check the requester's identity first.

### Access

There is no single export of everything about a person yet. Collect it from these:

| What | How |
|------|-----|
| Account: name, email, role, status, SSO identities, second factor, last sign-in | `GET /api/users/<user>`; `botctl user identities <user>` |
| Bots they can see, with their access and grants | `GET /api/users/<user>/bots`; `botctl bot access <bot>` |
| Chat history | `GET /api/bots/<bot>/messages` for each Bot: returns the latest 200 messages only. Older messages, and what they sent in others' Bots, are in the `messages` table of `app.sqlite` (read a copy, not the live file). |
| Routines that run for them | `botctl user routines <user>` |
| Usage this billing period | `botctl usage user <user> json` |
| Live sessions | `botctl sessions <user>` |
| Their saved secrets | `GET /api/users/<user>/secrets` returns names only; values are sealed and never returned ([ADR 0044](../adr/0044-client-personal-secrets.md)). |
| Audit events by them, and by Bots acting for them | `botctl audit export --actor user:<user> > by.csv` and `botctl audit export --on-behalf-of <user> > for.csv`; add `--from` and `--to` to narrow it. |
| Facts, Bot memory and working files | The folders in [where personal data lives](#where-personal-data-lives). On a user's machine, through your hosting access (for example `incus exec` on the Incus host); SuperBot has no route to copy them out. |
| Billing | Your Stripe dashboard, for their customer id. |

### Rectification and restriction

- **Correct a name or email**: `PATCH /api/users/<user>` with `name` or `email`; audited as `user.updated`. For users your identity provider provisions over SCIM, change it at the IdP.
- **Restrict processing**: `botctl user disable <user>` ends their sessions and pauses the routines that run for them, and keeps their data. `botctl user enable <user>` lets them sign in again but leaves those routines paused; `botctl user resume-routines <user>` restarts them, or set `ROUTINES_ON_ENABLE=resume` to restart them on enable ([ADR 0047](../adr/0047-disabled-users-routines.md)).

### Erasure

`botctl user erase <user> [--destroy-machine] [--delete-backups] --yes` (`POST /api/users/<user>/erase`) deletes the person's Bots, chats, routines, sign-ins, second factor, sealed secrets and botd's folders for them; turns what they sent in others' chats into `[erased]`; keeps their user row with no personal data; and rewrites the audit log to name them by a random pseudonym. It is recorded as `user.erased` with counts, naming the admin who ran it. Another admin must run it: never on yourself or the owner account ([ADR 0102](../adr/0102-erasing-a-users-data.md), tests in [`server/src/erasure_http_tests.rs`](../../server/src/erasure_http_tests.rs)).

Before you run it:

1. **Legal holds.** It is refused while a Bot of theirs, or a chat they wrote in, is held. Decide whether the duty to preserve outweighs the request (GDPR Article 17(3)), then release the hold or refuse the request with that reason.
2. **Work the organisation keeps.** Erasure deletes every Bot they own. To keep a Bot, give it to someone else first (`botctl bot owner <bot> <user>`, or `botctl user disable <user>` then `botctl user handover <user> <to>`). The Bot and its chat are then kept, but what the person sent in it becomes `[erased]`.
3. **Other refusals.** Make someone else owner of a team where they are the only owner, cancel a plan that is still paying, give away the primary Bot, and destroy their machine or pass `--destroy-machine`. With machine backups kept, pass `--delete-backups` ([ADR 0108](../adr/0108-deleting-a-destroyed-machines-backups.md)). Each refusal is a 409 with its reason, audited as `user.erase_refused`.

After it:

1. **Per-user account.** With per-user accounts on, the answer says `isolationFolderLeft`. Remove the OS account (`sb-u-<id>`) and its folder under `ISOLATION_DIR` as root; SuperBot has no command for it yet.
2. **Backups.** Server backups keep their data until their retention ends (14 days on the host, 30 off it, by default). The newest off-host copy is never deleted for age: while backups keep running it is one taken after the erasure, but if they stop, the last copy keeps the person's data until you delete it by hand. Check `botctl backups` shows a copy newer than the erasure before you confirm it. Restoring an older backup brings the person back, so keep your own record of erasures outside SuperBot (the restored audit log won't have them) and erase again after any restore.
3. **Outside services.** Delete their Stripe customer if you have no legal need to keep invoices. What Bots already sent to model providers is held under those providers' terms.
4. **What erasure doesn't reach**: other people's Bots' memory and chat text that mention them by name, short names in old audit details, and work they left in an owner's `from-teammates/` folder (that owner's files). Harness session files and archived work go by their retention settings ([ADR 0102](../adr/0102-erasing-a-users-data.md)).

An IdP's SCIM delete only disables a user and keeps their data; erasure is always an admin's separate step ([data flows: SCIM](data-flows.md#identity-providers-scim-inbound)).

### Portability

There is no machine-readable export for GDPR Article 20 yet. The API's JSON and the audit CSV above are machine-readable but partial.

## Breaches

As controller you must tell your supervisory authority within 72 hours of becoming aware of a personal data breach, unless it is unlikely to be a risk, and tell affected people when the risk is high (GDPR Articles 33 and 34). SuperBot helps you find and contain one:

- **Find**: suspicious sign-in alerts (`auth.suspicious_sign_in`, on by default, [ADR 0104](../adr/0104-suspicious-sign-in-alerts.md)); the audit log, filtered by actor, session, sign-in method, outcome, Bot or time and exported as CSV ([access control: audit log](access-control.md#audit-log)); service alerts if you load the Prometheus rules ([ADR 0113](../adr/0113-service-dashboards-and-error-reporting.md)).
- **Contain**: `botctl user disable <user>`, `botctl session revoke-all <user>`, `botctl machine revoke <user> --yes` (revokes a machine's certificates), deleting secrets, and rotating the master key if it may have leaked ([ADR 0096](../adr/0096-master-key-rotation.md)).

You still need your own incident response plan; the [readiness checklist](soc2-readiness-checklist.md) lists it as CC7.4-1.

## Impact assessments

If your use needs a data protection impact assessment (GDPR Article 35), [architecture](architecture.md), [data flows](data-flows.md) and [access control](access-control.md) describe the processing and the safeguards. A DPIA template for customers is planned for M5 ([roadmap](../ROADMAP.md)).

## What exists and what is missing

| Duty | Exists | Missing (follow-ups) |
|------|--------|----------------------|
| Access (Article 15) | Admin routes and `botctl` commands for each piece, above. | One export of everything about a person, from one command; chat history beyond the latest 200 messages per Bot without reading the database; copying files off a user's machine. |
| Portability (Article 20) | JSON from the API, CSV from the audit log. | A machine-readable export in one file. |
| Rectification and restriction (Articles 16, 18) | Admins change name and email, and disable users. | Nothing. |
| Erasure (Article 17) | `botctl user erase`, tested and audited, with holds, a pseudonymised audit log and machine backups deleted on request ([ADR 0102](../adr/0102-erasing-a-users-data.md), [ADR 0108](../adr/0108-deleting-a-destroyed-machines-backups.md)). | Removing the per-user OS account and folder; erasing from server backups before their retention ends; deleting access requests from people who never got an account ([ADR 0022](../adr/0022-landing-and-signups.md) noted their retention isn't built). |
| Self-service | People manage their own secrets, second factor and push devices in the apps. | Seeing or downloading their own data, or asking for erasure, in the apps. |
| Retention (Article 5(1)(e)) | Settings for chat, harness sessions, archived work, audit log, sessions and backups. | Retention for access requests and for Bots' memory. |
| Region | You choose where the server, machines and backups run. | A UK/EU region choice for managed plans (M4, [roadmap](../ROADMAP.md)). |
| Impact assessment (Article 35) | The pages above. | A DPIA template (M5). |
