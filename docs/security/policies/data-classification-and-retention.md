# Data classification and retention policy

What data a managed SuperBot service holds, how sensitive each kind is, how each class is handled, how long it is kept and how it is disposed of. Part of the [policy set](README.md). What is stored where, and how it is encrypted, is in [data flows](../data-flows.md). **Draft, not adopted. SuperBot is not SOC 2 certified.**

| Field | Value |
|-------|-------|
| Owner | Security owner |
| Approver | Management |
| Review | Yearly, and when SuperBot starts storing a new kind of data |
| Status | Draft, not yet approved |
| Controls | C1.1-1, C1.1-2, C1.2-1, CC6.5-1, CC6.5-2 |

## Classes

| Class | Meaning | Examples |
|-------|---------|----------|
| Restricted | Lets someone into the service or other data. Exposure is a SEV-1 or SEV-2 incident. | The master key; backup age identities; sealed secret values; session and API tokens; TOTP secrets and recovery codes; provider and SCIM tokens; machine certificates' private keys |
| Confidential | Customers' content and personal data. Exposure may be a personal data breach. | Chats and prompts; Bots' memory, `USER.md` and working folders; harness session files; screens; teammates' archived work; users' names, emails and SSO identities; audit events (they carry actors and IP addresses); backups, which hold all of the above |
| Internal | About the service, holding no customer content | Metrics, which have no per-user labels; logs and traces, which carry no prompt, message or secret ([ADR 0118](../../adr/0118-harness-run-traces-and-per-tier-metrics.md)); configuration without secrets; this register and the risk register |
| Public | Meant to be published | This repository and its docs; the status page, which shows no customer data; published plans |

Data takes the class of the most sensitive thing in it: a backup is Confidential, and holds Restricted values sealed.

## Inventory

| Data | Class | Where ([data flows](../data-flows.md#what-is-stored-where)) | Retention setting | SuperBot's default |
|------|-------|----------------------------------------------------------------|-------------------|--------------------|
| Sealed secrets, TOTP secrets | Restricted | botd's database, sealed under the master key ([ADR 0010](../../adr/0010-secrets.md)) | Deleted with the secret, or when the user is erased | Until deleted |
| Sessions | Restricted | botd's database, as hashes | `SESSION_IDLE_TIMEOUT`, `SESSION_MAX_AGE` | 7 days idle, 30 days at most |
| Chat history | Confidential | botd's database | `CHAT_RETENTION_DAYS` ([ADR 0098](../../adr/0098-chat-retention.md)) | Kept forever |
| Harness session files | Confidential | Server, per-user accounts, machines | `HARNESS_SESSION_RETENTION_DAYS` ([ADR 0112](../../adr/0112-harness-session-and-teammate-files-retention.md)) | Kept forever |
| Teammates' archived work | Confidential | The owner's `from-teammates/` folder | `TEAMMATE_FILES_RETENTION_DAYS` ([ADR 0112](../../adr/0112-harness-session-and-teammate-files-retention.md)) | Kept forever |
| Bots' memory, `USER.md`, working folders | Confidential | Server or machine disk | None; deleted with the Bot, the user or the machine | Until deleted |
| Audit log | Confidential | botd's database | `AUDIT_RETENTION_DAYS` ([ADR 0009](../../adr/0009-audit-events.md)) | Kept forever |
| Server backups | Confidential | On the host, and off the host | `SUPERBOT_BACKUP_RETENTION_DAYS`, `SERVER_BACKUP_RETENTION_DAYS` ([ADR 0030](../../adr/0030-backup-restore-drill.md), [ADR 0109](../../adr/0109-server-backups-off-the-host.md)) | 14 days on the host, 30 off it |
| Machine backups | Confidential | Object storage, or Linode Backups | Per plan ([ADR 0071](../../adr/0071-off-host-machine-backups.md)) | 14 days |
| Metrics, logs, traces | Internal | The operator's Prometheus, log store and trace collector | The operator's tools | The operator's |

## Handling

| Class | Stored | Moved | Who may see it |
|-------|--------|-------|----------------|
| Restricted | Encrypted, and only where the product puts it or in the password manager; never in the repository, tickets, chats or logs | Never by email or chat; in person or through the password manager | Only the roles that need it ([access control policy](access-control.md#secrets-and-keys)) |
| Confidential | Encrypted at rest: botd's database with SQLCipher ([ADR 0116](../../adr/0116-database-encrypted-at-rest.md)), backups with age ([ADR 0114](../../adr/0114-backups-encrypted-by-default.md)), and the hosts' disks for the files beside the database | Only over TLS; only to the vendors in the [subprocessor list](../subprocessors.md) the provider has assessed ([vendor management](vendor-management.md)) | The customer; the provider's personnel only for that customer's request or an incident ([acceptable use](acceptable-use.md)) |
| Internal | The provider's systems, with access control | Over TLS | Personnel who need it |
| Public | Anywhere | Anywhere | Anyone |

Customers decide what their people put into chats and files, which their harness sends to the model provider; the provider doesn't classify customers' content any finer than Confidential.

## Retention

The managed service sets every retention period on, not left at "kept forever", to what its customers' contracts say. Until a contract says otherwise:

| Data | Period |
|------|--------|
| Chat history (`CHAT_RETENTION_DAYS`) | `[N]` days |
| Harness session files (`HARNESS_SESSION_RETENTION_DAYS`) | `[N]` days |
| Teammates' archived work (`TEAMMATE_FILES_RETENTION_DAYS`) | `[N]` days |
| Audit log (`AUDIT_RETENTION_DAYS`) | At least the audit observation period plus a year, `[N]` days (400 suggested) |
| Server and machine backups | SuperBot's defaults above, or what the contract says |

Retention passes are audited with their counts (`chat.pruned`, `harness_sessions.pruned`, `teammate_files.pruned`, `audit.pruned`); `botctl retention` shows the settings, the last passes and the holds. Deleted rows stay in backups until those expire.

## Legal holds

When a customer, a regulator or a court needs data kept, or an incident needs evidence, the privacy lead or the incident commander places a hold on the Bots involved: `botctl retention hold <bot> "<reason>"`. Held Bots' chats and files are skipped by every retention pass, and a held Bot can't be deleted ([ADR 0098](../../adr/0098-chat-retention.md), [ADR 0112](../../adr/0112-harness-session-and-teammate-files-retention.md)). The hold's reason and owner are recorded, holds are reviewed quarterly, and `botctl retention release <bot>` ends one when it's no longer needed. The audit log has no per-Bot hold: raise `AUDIT_RETENTION_DAYS` instead.

## Disposal

- **A person, on request.** `botctl user erase <user> --yes` deletes their Bots, chats, sign-ins, second factor and secrets and keeps the audit log under a pseudonym ([ADR 0102](../../adr/0102-erasing-a-users-data.md)); `--delete-backups` deletes their machines' backups too ([ADR 0108](../../adr/0108-deleting-a-destroyed-machines-backups.md)). The operator then removes their per-user isolation folder, and server backups age out. The privacy lead answers the request within the time the law and the DPA give.
- **A destroyed machine's backups.** `botctl machine delete-backups <machine-id> --yes`, or at the end of their retention.
- **A customer leaving.** Their users are erased and machines destroyed within `[N]` days of the contract ending, as the DPA says, and the provider confirms it in writing.
- **Media.** Disks and hosts are wiped by the hosting provider under its own controls, checked in the [yearly vendor review](vendor-management.md#yearly-review). Personnel's devices are wiped before reuse or disposal ([acceptable use](acceptable-use.md)).
