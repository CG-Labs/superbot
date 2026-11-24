# Provision users and teams from Google Workspace

botd reads your Google Workspace directory and keeps SuperBot's users in step with it: the people in groups or organizational units you choose get an account, follow their name, email and suspension in Google, and lose access when they leave them. Groups and organizational units you choose can become teams. Design: [ADR 0162](../adr/0162-google-workspace-directory-sync.md), and [ADR 0234](../adr/0234-google-workspace-organizational-units.md) for organizational units.

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

If you choose [organizational units](#3-choose-the-groups-or-organizational-units) (other than `/`), add a third read-only scope, and give that admin **Organizational Units → Read** too:

```text
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly
```

**B. An admin role for the service account itself.** In the Admin console: **Account → Admin roles**, make a custom role with **Users → Read** and **Groups → Read** (and **Organizational Units → Read** if you choose organizational units), then **Assign service accounts** and enter the service account's email. Leave `GOOGLE_DIRECTORY_ADMIN` empty. This needs no delegation at all.

## 3. Choose the groups or organizational units

- **Who gets an account**: one or more groups, e.g. `superbot-users@example.com`. Nested groups count. Members from outside your Workspace never get one. A group with everyone in your organization as a member gives everyone an account.
- **Teams** (optional, needs `SCIM_GROUPS=on`): groups that become SuperBot teams, e.g. `eng@example.com`. Their members get an account too. A person is on one team at most: if they are in two team groups, the first one listed wins. Two addresses of one Google group are one team.

Or, if you organize people by **organizational unit** (OU), choose OUs instead of groups, or as well ([ADR 0234](../adr/0234-google-workspace-organizational-units.md)):

- **Who gets an account**: OUs by path, e.g. `/Sales`, or by id, e.g. `id:03ph8a2z1abcdef` (its `orgUnitId` from the Directory API's [`orgunits.list`](https://developers.google.com/workspace/admin/directory/reference/rest/v1/orgunits/list); an id keeps working when the OU is renamed or moved). An OU includes the OUs below it: `/Engineering` covers `/Engineering/Platform`. `/` is everyone.
- **Teams** (optional, needs `SCIM_GROUPS=on`): OUs that become teams, named by their path (`Engineering/Platform`). Their people get an account too. Each person is on the team of the deepest team OU they're in, so `/Engineering` and `/Engineering/Platform` can both be teams. Team groups come first: someone on a team group stays on it. `/` can't be a team.

Moving someone to an OU you didn't choose removes them, like leaving every group, and with [push](#6-push-changes-at-once-optional) that happens within seconds: a move is a change to the user, which Google pushes. Taking someone out of a group is pushed too with [group push](#push-group-membership-changes-too), within a couple of minutes.

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
# SCIM_GROUP_ROLES=on
# GOOGLE_DIRECTORY_ROLE_GROUPS=auditors@example.com     # role groups: declare each one (below)
# Organizational units, with or instead of groups (needs the third scope above):
# GOOGLE_DIRECTORY_ORG_UNITS=/Sales,/Support
# GOOGLE_DIRECTORY_TEAM_ORG_UNITS=/Engineering,/Engineering/Platform
# With Sign in with Google (google.md), people sign in to the account the sync made:
# GOOGLE_DIRECTORY_SSO=google
```

Restart botd. Its log says `Google Workspace sync: on, ...`. botd refuses to start if the key is missing or isn't a service account key, if a setting is wrong, or if a SCIM token already writes the sync's tenant.

| Setting | Default | |
|---------|---------|---|
| `GOOGLE_DIRECTORY_SYNC` | `off` | `on` needs `SCIM=on`. |
| `GOOGLE_DIRECTORY_GROUPS` | | Group emails, comma separated. Their members get an account. This or `GOOGLE_DIRECTORY_ORG_UNITS` (or a team list) must name at least one. |
| `GOOGLE_DIRECTORY_TEAM_GROUPS` | | Group emails that become teams too. Needs `SCIM_GROUPS=on`. |
| `GOOGLE_DIRECTORY_ROLE_GROUPS` | | Group emails that are [role groups](scim.md#role-groups): they give a custom role, across the server or (declared with `--team`) within each member's team, and are no team. Needs `SCIM_GROUPS=on` and `SCIM_GROUP_ROLES=on`. Being in one gives no account. Not also a team group. At most 50 groups across the three lists. |
| `GOOGLE_DIRECTORY_ORG_UNITS` | | Organizational unit paths (`/Sales`) or ids (`id:...`), comma separated. The people in them, or in OUs below them, get an account. `/` is everyone. |
| `GOOGLE_DIRECTORY_TEAM_ORG_UNITS` | | OUs that become teams too, each person on their deepest one's. Needs `SCIM_GROUPS=on`. Not `/`. At most 50 OUs across the two lists. |
| `GOOGLE_DIRECTORY_ADMIN` | | The admin the service account acts as (option A). Empty for option B. |
| `GOOGLE_DIRECTORY_SSO` | | A Google provider from `SSO_PROVIDERS`. Each user's Directory id is their `sub` there, so their sign-in is linked to the account. |
| `GOOGLE_DIRECTORY_TENANT` | `google` | The SCIM tenant the users and teams belong to. No SCIM token may use it. |
| `GOOGLE_DIRECTORY_CUSTOMER` | `my_customer` | Or your customer ID (`C0...`). |
| `GOOGLE_DIRECTORY_INTERVAL_MINUTES` | `30` | 5 to 1440. The first pass runs a minute after botd starts. |
| `GOOGLE_DIRECTORY_MAX_REMOVALS` | `10` | A pass that would remove or disable more people than this changes nobody until an admin forces it. |
| `GOOGLE_DIRECTORY_PUSH` | `off` | `on`: Google tells botd when a user changes, and a pass runs within seconds ([below](#6-push-changes-at-once-optional)). Needs an https `PUBLIC_URL` Google can reach. |
| `GOOGLE_DIRECTORY_PUSH_GROUPS` | `off` | `on`: Google also tells botd when a group's members change ([below](#push-group-membership-changes-too)). Needs `GOOGLE_DIRECTORY_PUSH=on`, a group in one of the three group lists, and the read-only audit scope. |

New users get `SCIM_DEFAULT_ROLE` (member, or readonly). The sync never makes admins. Promote people with `botctl user role`.

**Role groups.** Declare each group in `GOOGLE_DIRECTORY_ROLE_GROUPS` in the sync's tenant, by its email, with the custom role it gives ([ADR 0180](../adr/0180-scim-role-groups.md)):

```bash
botctl scim role-group add google auditors@example.com Auditor
botctl scim role-group add google team-leads@example.com Lead --team   # Lead within each member's team
```

The next pass pushes it with its members who have an account, and they hold the role while they're in it, whatever team they're on; a [team role group](scim.md#team-role-groups)'s members hold it within the team they're on, if it's one of `GOOGLE_DIRECTORY_TEAM_GROUPS` ([ADR 0206](../adr/0206-scim-team-role-groups.md)). A listed group nobody declared is never pushed (it would become a team) and is named in the pass's `roleGroups.undeclared`. A declared group taken off the list is deleted on the next pass: its members lose the role, and the declaration waits again.

## 5. Check it

```bash
botctl scim google              # settings, the last pass, and the last good pass
botctl scim google sync         # a pass now; prints what it did
botctl users                    # the people it made
```

With `GOOGLE_DIRECTORY_SSO`, have someone in the group sign in with Google: they land in the account the sync made for them.

## 6. Push changes at once (optional)

By default a suspension in Google reaches SuperBot at the next pass, up to `GOOGLE_DIRECTORY_INTERVAL_MINUTES` later. With push, Google tells botd as soon as a user is added, changed (suspended, archived, renamed), deleted or undeleted, and a pass runs within seconds, so a leaver's sessions, Bots and machine stop at once ([ADR 0216](../adr/0216-google-workspace-push.md)).

It needs nothing new in Google: the read-only user scope already lets the service account watch users. botd must be reachable from the internet over https, with a certificate from a public CA (Google refuses self-signed ones), at `PUBLIC_URL`:

```bash
PUBLIC_URL=https://superbot.example.com
GOOGLE_DIRECTORY_PUSH=on
```

Restart botd. About 10 seconds later it asks Google for a channel for each kind of change (`add`, `update`, `delete`, `undelete`), sent to `https://superbot.example.com/scim/google/push`, and audits `scim.google_push_watching`. Channels end after a few hours, so botd makes new ones before they do. `botctl scim google` shows `push`: whether it's watching, when each channel ends, how many changes Google has sent, and the last failure.

What to know:

- **A notification is only a nudge.** botd reads nothing from it but which channel sent it, then runs the same full pass as the schedule, with every check above. A burst of changes (a bulk suspension) becomes one pass, and pushed passes are at least 30 seconds apart. The schedule keeps running: if push stops, nothing is missed, only slower.
- **Group membership isn't pushed by this alone.** The Directory API has no watch for group members, so someone taken out of a chosen group, but not suspended, waits for the next scheduled pass. Turn on [group push](#push-group-membership-changes-too), suspend leavers in Google, move them to an OU you didn't choose (if you [choose OUs](#3-choose-the-groups-or-organizational-units)), or run `botctl scim google sync`.
- **Each channel has its own secret.** Google sends it back with every notification, and botd refuses (401) any that doesn't match, audited as `scim.google_push_refused` (at most one event per address every few minutes). The secrets are derived from botd's master key, so channels made before a restart still work, and botd stops them when they next deliver. Turning push off stops them the same way.
- If your proxy only forwards some paths, forward `POST /scim/google/push` to botd. The bundled Caddy forwards everything.

### Push group membership changes too

Google records every member added to or removed from a group, and every group deleted, in its Admin log, within a couple of minutes, and the [Reports API](https://developers.google.com/workspace/admin/reports/v1/guides/push) can watch that log. With group push, botd watches those three events (`ADD_GROUP_MEMBER`, `REMOVE_GROUP_MEMBER`, `DELETE_GROUP`), and each one starts the same full pass, so someone taken out of a chosen group loses access within minutes instead of at the next scheduled pass ([ADR 0244](../adr/0244-google-workspace-group-membership-push.md)).

It needs one more read-only scope. With domain-wide delegation (option A), add it to the service account's entry, so it reads:

```text
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.reports.audit.readonly
```

(with the organizational unit scope too, if you use it), and give `GOOGLE_DIRECTORY_ADMIN` the **Reports** privilege. With option B, add **Reports** to the service account's admin role. Then:

```bash
GOOGLE_DIRECTORY_PUSH=on
GOOGLE_DIRECTORY_PUSH_GROUPS=on
```

Restart botd. It makes three more channels, sent to the same address, and audits `scim.google_push_watching` with `"watch": "groups"`. `botctl scim google` shows them under `push.groups`.

What to know:

- **Only group channels use the audit scope.** botd asks Google for a token with that scope alone when it makes, renews or stops a group channel, and passes never carry it. So the audit scope missing (or **Reports** not granted) fails group push only: `push.groups.failure` says why, `scim.google_push_failed` (with `"watch": "groups"`) is audited once, botd tries again every 5 minutes, and user push and the passes go on as before.
- **Changes in the Admin console or through the Directory API** are logged as admin activity: an admin's change, Google Cloud Directory Sync, an HR system or Terraform. A change a group's own manager makes in Google Groups, or a dynamic group's membership following its query, isn't, and still waits for the schedule.
- **Any group's change starts a pass**, not just a chosen group's, since a chosen group can hold another. Passes are at least 30 seconds apart, and a burst of changes is one pass. A Workspace whose groups change all day reads its directory that often; leave group push off if that's too many reads for your [quotas](https://developers.google.com/workspace/admin/directory/v1/limits).
- Google may drop a notification now and then. The schedule still runs, so nothing is missed, only slower.

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
| Someone moves to another organizational unit | They follow it: onto the team of their new deepest team OU, or deleted from the tenant if no chosen OU (or group) holds them any more. Pushed within seconds with push on |
| A team OU is renamed or moved | Its team is renamed to the new path and keeps its people (it's keyed by the OU's id) |
| A declared role group's members change | People with an account gain or lose its role, as with a SCIM role group |
| A suspended person never had an account | Nothing: no account is made for them |

**An admin's disable holds.** Google decides name, email, and who has access, with one exception. If an admin disables someone in SuperBot, the sync leaves them disabled even while Google has them active. It only enables people it disabled itself, also when it takes on someone who signed in with Google before and was disabled; if the audit log no longer shows who disabled someone, they stay disabled too. Each pass lists them as `held`. To let the sync manage them again, enable them (`botctl user enable` or the admin portal).

**Fail-closed.** A pass that can't sign in, reach Google, find a group or organizational unit, or read every page of a list changes nobody, and the next pass tries again (in 5 minutes at most, as after a pass with failed writes). So does a pass that would remove or disable more than `GOOGLE_DIRECTORY_MAX_REMOVALS` people, or leave nobody active in the tenant (people an admin disabled don't count as active), which is what an empty answer looks like. Removals come last, and wait too if earlier writes failed and nobody would stay active. Check the groups in Google, then run `botctl scim google sync --force`.

**One person, one user.** Email never matches people. If a SuperBot user already has someone's email, that person's create fails (and is listed in the pass) until you link that user's Google identity (`botctl user link <user> <google provider> <directory id>`) or change one of the emails. The owner account is never managed.

## Audit

Every change is audited as the SCIM events of the [SCIM guide](scim.md), with the actor `scim:google-directory`, method `google_directory`. Each pass is also `scim.google_sync` (target `scim_tenant:<tenant>`):

- **success**: what it did: `created`, `updated`, `enabled`, `disabled`, `linked`, `deleted`, `held`, `skippedSuspended`, `outsideDomain`, `teams`, `roleGroups` (with `undeclared`), `orgUnits` (each OU chosen, with its path now, how many people it holds, and whether it's a team), how long it took, and what started it (`schedule`, `admin` with `force`, or `push` with the changes Google sent in `pushed`).
- **failure**: the `reason` and `detail` when nobody was changed, or the SCIM writes that failed (`failed`, `failures`; each also `scim.request_failed`).
- **denied**: too many removals (`too_many_removals`, `would_remove_everyone`).

An admin's `botctl scim google sync` is `scim.google_sync_requested` first, by that admin. `GET /api/scim/google` (admins only) shows the settings and the last passes. It never shows the key.

With push on: `scim.google_push_watching` when botd first has channels, and again once they work after a failure (`recovered`); `scim.google_push_failed` (failure) once when Google refuses a channel, with `reason`, `detail` and how many old channels still work (`channelsLeft`, until `channelsEnd`), each saying which set of channels (`watch`: `users`, or `groups` with group push); and `scim.google_push_refused` (failure) for a notification botd didn't ask for (`reason`: `missing`, `unknown_channel` or `bad_token`). Renewals aren't audited.

## Limits

- Changes in Google reach SuperBot within `GOOGLE_DIRECTORY_INTERVAL_MINUTES`, or within seconds for user changes with [push](#6-push-changes-at-once-optional), and within a couple of minutes for group membership changes with [group push](#push-group-membership-changes-too). Run `botctl scim google sync` to apply one now.
- Users, group membership and organizational units only: no aliases, custom attributes, or roles from Google. OUs give accounts and teams, never roles.
- At most 50 groups and 50 organizational units. A Directory list over 2,000 pages, or a page over 16 MiB, fails the pass.
- The Directory API has [quotas](https://developers.google.com/workspace/admin/directory/v1/limits). A pass reads each group, its members, each organizational unit, and the customer's users, 500 at a time. A rate-limited pass fails and is tried again.

## Troubleshooting

`botctl scim google` shows the last pass's `reason` and `detail`.

| `reason` | Fix |
|----------|-----|
| `credentials` | The key is missing or isn't a JSON service account key. Save it again. |
| `sign_in` | Google refused the service account. With option A: the Client ID and both scopes (all three with organizational units) in domain-wide delegation, and `GOOGLE_DIRECTORY_ADMIN` is a real admin. With option B: the role is assigned to the service account, and `GOOGLE_DIRECTORY_ADMIN` is empty. |
| `forbidden` | The admin (or role) can't read users, groups or organizational units, or the Admin SDK API is off in the project. |
| `group_not_found` | A group email is wrong, or isn't in this Workspace. |
| `org_unit_not_found` | An organizational unit's path or id is wrong, or it was deleted, renamed or moved (name it by id to follow renames). Nobody in it was removed. |
| `unreachable`, `google_error`, `rate_limited` | Google couldn't be reached or answered with an error. The next pass tries again. |
| `odd_answer`, `too_large` | Google's answer wasn't a full Directory API answer. Nobody was changed. |
| `too_many_removals`, `would_remove_everyone` | See **Fail-closed** above. |
| `running` | A pass was already running. |

With push on, `push.failure` shows why Google refused a channel. `forbidden` or `sign_in`: the same checks as above (the read-only user scope is enough). For group push, `push.groups.failure`: `sign_in` means the audit scope isn't in domain-wide delegation; `forbidden`, that the admin (or role) lacks **Reports**. A channel that Google makes but never delivers to usually means botd isn't reachable at `PUBLIC_URL` over https with a public certificate. botd keeps trying every 5 minutes, and the schedule runs meanwhile.
