# Provision users and teams from Google Workspace

botd reads your Google Workspace directory and keeps SuperBot's users in step with it: the people in groups you choose get an account, follow their name, email and suspension in Google, and lose access when they leave the groups. Groups you choose can become teams. Design: [ADR 0162](../adr/0162-google-workspace-directory-sync.md).

**Why not SCIM?** Google Workspace pushes SCIM only to apps in its own catalog. Custom SCIM apps exist only as a limited beta. So botd pulls instead: a service account with read-only access lists users and group members through the [Admin SDK Directory API](https://developers.google.com/workspace/admin/directory/v1/guides), and each pass runs the changes through SuperBot's own SCIM code ([SCIM guide](scim.md)). The rules are the same: same roles, same deprovisioning, same teams, same audit events. If your Workspace has Google's custom SCIM beta, you can point it at `/scim/v2` with a token instead ([SCIM guide](scim.md)). Don't use both on the same tenant.

You need: a Workspace super admin, a Google Cloud project, and SuperBot with SCIM on. Below, replace `example.com` with your domain.

## 1. Make a service account and its key

In the [Google Cloud console](https://console.cloud.google.com), in any project:

1. **APIs & Services → Library**: enable the **Admin SDK API**.
2. **IAM & Admin → Service accounts → Create service account**: name it `superbot-directory`. It needs no project roles.
3. Open it. Note its **Unique ID** (a long number); step 2 needs it.
4. **Keys → Add key → Create new key → JSON**. Keep the file safe: it is the account's only credential. If your organization blocks key creation (`iam.disableServiceAccountKeyCreation`), an organization admin has to allow it for this project.

## 2. Let it read the directory

Pick one.

**A. Domain-wide delegation (most common).** In the [Admin console](https://admin.google.com): **Security → Access and data control → API controls → Manage Domain Wide Delegation → Add new**:

- **Client ID**: the service account's Unique ID.
- **OAuth scopes**, exactly these two, both read-only:

```text
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly
```

The service account then acts as an admin you name in `GOOGLE_DIRECTORY_ADMIN`. Pick one who can read users and groups. A dedicated admin with a custom role that has only **Users → Read** and **Groups → Read** is best: botd can never do more than that admin can, and never more than the two scopes allow.

**B. An admin role for the service account itself.** In the Admin console: **Account → Admin roles**, make a custom role with **Users → Read** and **Groups → Read**, then **Assign service accounts** and enter the service account's email. Leave `GOOGLE_DIRECTORY_ADMIN` empty. This needs no delegation at all.

## 3. Choose the groups

- **Who gets an account**: one or more groups, e.g. `superbot-users@example.com`. Nested groups count. Members from outside your Workspace never get one. A group with everyone in your organization as a member gives everyone an account.
- **Teams** (optional, needs `SCIM_GROUPS=on`): groups that become SuperBot teams, e.g. `eng@example.com`. Their members get an account too. A person is on one team at most: if they are in two team groups, the first one listed wins. Two addresses of one Google group are one team.

## 4. Configure SuperBot

Save the key. It is botd's own secret, never given to Bots:

```bash
botctl secret set GOOGLE_DIRECTORY_CREDENTIALS < superbot-directory-key.json
# Docker: docker compose exec -T botd botctl secret set GOOGLE_DIRECTORY_CREDENTIALS < superbot-directory-key.json
# Or set GOOGLE_DIRECTORY_CREDENTIALS_FILE to the file's path (readable only by botd).
```

In `.env` (installer: `/home/superbot/superbot/.env`; Docker: `deploy/docker/.env`):

```bash
SCIM=on
GOOGLE_DIRECTORY_SYNC=on
GOOGLE_DIRECTORY_ADMIN=superbot-reader@example.com    # option A only
GOOGLE_DIRECTORY_GROUPS=superbot-users@example.com
# SCIM_GROUPS=on
# GOOGLE_DIRECTORY_TEAM_GROUPS=eng@example.com,design@example.com
# With Sign in with Google (google.md), people sign in to the account the sync made:
# GOOGLE_DIRECTORY_SSO=google
```

Restart botd. Its log says `Google Workspace sync: on, ...`. botd refuses to start if the key is missing or isn't a service account key, if a setting is wrong, or if a SCIM token already writes the sync's tenant.

| Setting | Default | |
|---------|---------|---|
| `GOOGLE_DIRECTORY_SYNC` | `off` | `on` needs `SCIM=on`. |
| `GOOGLE_DIRECTORY_GROUPS` | | Group emails, comma separated. Their members get an account. |
| `GOOGLE_DIRECTORY_TEAM_GROUPS` | | Group emails that become teams too. Needs `SCIM_GROUPS=on`. At most 50 groups across both lists. |
| `GOOGLE_DIRECTORY_ADMIN` | | The admin the service account acts as (option A). Empty for option B. |
| `GOOGLE_DIRECTORY_SSO` | | A Google provider from `SSO_PROVIDERS`. Each user's Directory id is their `sub` there, so their sign-in is linked to the account. |
| `GOOGLE_DIRECTORY_TENANT` | `google` | The SCIM tenant the users and teams belong to. No SCIM token may use it. |
| `GOOGLE_DIRECTORY_CUSTOMER` | `my_customer` | Or your customer ID (`C0...`). |
| `GOOGLE_DIRECTORY_INTERVAL_MINUTES` | `30` | 5 to 1440. The first pass runs a minute after botd starts. |
| `GOOGLE_DIRECTORY_MAX_REMOVALS` | `10` | A pass that would remove or disable more people than this changes nobody until an admin forces it. |

New users get `SCIM_DEFAULT_ROLE` (member, or readonly). The sync never makes admins and never changes roles. Promote people with `botctl user role`.

## 5. Check it

```bash
botctl scim google              # settings, the last pass, and the last good pass
botctl scim google sync         # a pass now; prints what it did
botctl users                    # the people it made
```

With `GOOGLE_DIRECTORY_SSO`, have someone in the group sign in with Google: they land in the account the sync made for them.

## What happens

| In Google | In SuperBot |
|-----------|-------------|
| Someone is in a chosen group | A user with `SCIM_DEFAULT_ROLE`, keyed by their Directory id (never their email). With `GOOGLE_DIRECTORY_SSO`, their Google sign-in is linked, also for users the tenant had before it was set |
| Their name or primary email changes | The user is updated |
| Their primary organization, `organization` external id, or `manager` relation changes | Their [enterprise attributes](scim.md#enterprise-attributes) follow: `organization` (its name), `department`, `costCenter`, `employeeNumber`, and `manager` once the manager has an account here too (a manager added in the same pass is set on the next). Shown to admins and in the access review; never used for access ([ADR 0176](../adr/0176-scim-enterprise-user-extension.md)) |
| They are suspended or archived | The user is disabled, their sessions end, their Bots' runs stop, and their machine is suspended, as with SCIM ([ADR 0124](../adr/0124-deprovisioning-stops-bots-and-machines.md)) |
| They are active again | The user is enabled again, if the sync disabled them (below) |
| They leave every chosen group, or are deleted | The user is deleted from the tenant as with a SCIM `DELETE`: disabled, nothing destroyed. Added back, they return as the same user |
| A team group's members change | People join and leave its team. A renamed group renames its team |
| A team group leaves `GOOGLE_DIRECTORY_TEAM_GROUPS` | Its people leave the team, as when an IdP deletes a SCIM group, and join the team of any other team group they're in, in the same pass |
| A suspended person never had an account | Nothing: no account is made for them |

**An admin's disable holds.** Google decides name, email, and who has access, with one exception. If an admin disables someone in SuperBot, the sync leaves them disabled even while Google has them active. It only enables people it disabled itself, also when it takes on someone who signed in with Google before and was disabled; if the audit log no longer shows who disabled someone, they stay disabled too. Each pass lists them as `held`. To let the sync manage them again, enable them (`botctl user enable` or the admin portal).

**Fail-closed.** A pass that can't sign in, reach Google, find a group, or read every page of a list changes nobody, and the next pass tries again (in 5 minutes at most, as after a pass with failed writes). So does a pass that would remove or disable more than `GOOGLE_DIRECTORY_MAX_REMOVALS` people, or leave nobody active in the tenant (people an admin disabled don't count as active), which is what an empty answer looks like. Removals come last, and wait too if earlier writes failed and nobody would stay active. Check the groups in Google, then run `botctl scim google sync --force`.

**One person, one user.** Email never matches people. If a SuperBot user already has someone's email, that person's create fails (and is listed in the pass) until you link that user's Google identity (`botctl user link <user> <google provider> <directory id>`) or change one of the emails. The owner account is never managed.

## Audit

Every change is audited as the SCIM events of the [SCIM guide](scim.md), with the actor `scim:google-directory`, method `google_directory`. Each pass is also `scim.google_sync` (target `scim_tenant:<tenant>`):

- **success**: what it did: `created`, `updated`, `enabled`, `disabled`, `linked`, `deleted`, `held`, `skippedSuspended`, `outsideDomain`, `teams`, how long it took, and what started it (`schedule` or `admin`, with `force`).
- **failure**: the `reason` and `detail` when nobody was changed, or the SCIM writes that failed (`failed`, `failures`; each also `scim.request_failed`).
- **denied**: too many removals (`too_many_removals`, `would_remove_everyone`).

An admin's `botctl scim google sync` is `scim.google_sync_requested` first, by that admin. `GET /api/scim/google` (admins only) shows the settings and the last passes. It never shows the key.

## Limits

- Polling, not push: changes in Google reach SuperBot within `GOOGLE_DIRECTORY_INTERVAL_MINUTES`. Run `botctl scim google sync` to apply one now.
- Users and group membership only: no organizational units, aliases, custom attributes, or roles from Google.
- At most 50 groups. A Directory list over 2,000 pages, or a page over 16 MiB, fails the pass.
- The Directory API has [quotas](https://developers.google.com/workspace/admin/directory/v1/limits). A pass reads each group, its members, and the customer's users, 500 at a time. A rate-limited pass fails and is tried again.

## Troubleshooting

`botctl scim google` shows the last pass's `reason` and `detail`.

| `reason` | Fix |
|----------|-----|
| `credentials` | The key is missing or isn't a JSON service account key. Save it again. |
| `sign_in` | Google refused the service account. With option A: the Client ID and both scopes in domain-wide delegation, and `GOOGLE_DIRECTORY_ADMIN` is a real admin. With option B: the role is assigned to the service account, and `GOOGLE_DIRECTORY_ADMIN` is empty. |
| `forbidden` | The admin (or role) can't read users or groups, or the Admin SDK API is off in the project. |
| `group_not_found` | A group email is wrong, or isn't in this Workspace. |
| `unreachable`, `google_error`, `rate_limited` | Google couldn't be reached or answered with an error. The next pass tries again. |
| `odd_answer`, `too_large` | Google's answer wasn't a full Directory API answer. Nobody was changed. |
| `too_many_removals`, `would_remove_everyone` | See **Fail-closed** above. |
| `running` | A pass was already running. |
