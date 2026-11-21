# Provision users with SCIM (Entra ID, Okta)

Lets your IdP create SuperBot users when people are assigned the app, keep their name and email current, and disable them when they leave. Disabling ends their sessions at once. With `SCIM_GROUPS=on`, its groups become SuperBot teams, and people join and leave teams as the groups say. Design: [ADR 0023](../adr/0023-scim.md), groups: [ADR 0095](../adr/0095-scim-groups-as-teams.md).

Users, and groups as teams. Group-to-role mapping and bulk come later. SCIM never gives anyone a role above `SCIM_DEFAULT_ROLE` (member, or readonly), nor any team role but member; admins promote people as before.

You need: SuperBot on HTTPS at a fixed address, like `https://superbot.example.com`, and an admin's `botctl` on the server. Below, replace `superbot.example.com` with yours.

## 1. Turn SCIM on

In `.env` (or `deploy/docker/.env`), then restart botd:

```sh
SCIM=on
# SCIM_DEFAULT_ROLE=member          # or readonly; admin is refused
# SCIM_GROUPS=on                    # groups become teams (see "Groups as teams" below)
```

botd logs `SCIM: on at /scim/v2` on start, and whether groups are teams. Off, `/scim/v2` answers 404.

## 2. Make a token

Each IdP connection is a **tenant** with its own tokens. A tenant only sees the users it provisioned.

**Link SSO if people sign in with the same IdP** (recommended). Then the IdP's `externalId` is the person's SSO subject, and each provisioned user can sign in with SSO straight away, as one user, never matched by email. Use the provider id from `SSO_PROVIDERS` ([Entra](entra.md), [OIDC/Okta](oidc.md)):

```sh
export SUPERBOT_PASSWORD=<your AUTH_PASSWORD>      # or SUPERBOT_TOKEN from botctl login
botctl scim token create entra --sso entra --label "Entra provisioning"
# Docker: docker compose exec -e SUPERBOT_PASSWORD botd botctl scim token create entra --sso entra
```

It prints an `sbp_…` token **once**. Paste it into the IdP, then forget it. Leave out `--sso` if people sign in with codes, or are linked by hand. A tenant's first token fixes its SSO link; all its tokens share it.

```sh
botctl scim tokens                                   # ids, tenants, last use; never values
botctl scim token create entra --sso entra           # a second token, for rotation
botctl scim token revoke <id>                        # its users stay as they are
```

## 3a. Microsoft Entra ID

In the [Microsoft Entra admin center](https://entra.microsoft.com): **Identity → Applications → Enterprise applications**. Use the enterprise app of your SuperBot SSO registration, or **New application → Create your own application → Integrate any other application you don't find in the gallery (Non-gallery)**.

1. **Provisioning → Get started**, **Provisioning Mode: Automatic**.
2. **Admin Credentials**: **Tenant URL** `https://superbot.example.com/scim/v2`, **Secret Token** the `sbp_…` token. **Test Connection**, then **Save**.
3. **Mappings**:
   - **Provision Microsoft Entra ID Groups**: **No**, unless `SCIM_GROUPS=on` and you want groups as teams. Then **Yes**, with the default mappings (`displayName → displayName`, `objectId → externalId`, `members → members`).
   - **Provision Microsoft Entra ID Users**: if the tenant links SSO (`--sso`), edit the **externalId** mapping: source attribute **objectId** (the default, `mailNickname`, is refused). Keep `userPrincipalName → userName`, `mail → emails[type eq "work"].value`, `Switch([IsSoftDeleted], …) → active`, and the name mappings. Others are ignored.
4. **Settings → Scope: Sync only assigned users and groups**. Assign people under **Users and groups**. With groups as teams, assign only the groups that are teams: a person is on one team at most.
5. **Provisioning Status: On**, **Save**. Entra syncs about every 40 minutes; **Provision on demand** does one person now.

Removing someone from the app, or disabling or deleting them in Entra, sets `active` to false: SuperBot disables them and ends their sessions. When Entra deletes them for good (30 days after a soft delete), it sends `DELETE`; SuperBot keeps the disabled user and its audit history.

## 3b. Okta

In the Okta Admin Console, open SuperBot's app integration (the OIDC app from [oidc.md](oidc.md), or a new **SWA**/**OIDC** app for provisioning only).

1. **General → App Settings → Edit → Provisioning: SCIM**, **Save**.
2. **Provisioning → Integration → Edit**:
   - **SCIM connector base URL**: `https://superbot.example.com/scim/v2`
   - **Unique identifier field for users**: `userName`
   - **Supported provisioning actions**: **Push New Users**, **Push Profile Updates**, and **Push Groups** if `SCIM_GROUPS=on`. Leave **Import Groups** off.
   - **Authentication Mode**: **HTTP Header**, **Authorization**: the `sbp_…` token.
   - **Test Connector Configuration**, then **Save**.
3. **Provisioning → To App → Edit**: enable **Create Users**, **Update User Attributes**, **Deactivate Users**. **Save**.
4. **Assignments**: assign people or groups (groups here only choose who is provisioned).
5. With groups as teams: **Push Groups → + Push Groups**, pick each team's group. Okta pushes its name and members.

Okta sends its user id (`00u…`) as `externalId`. That is the `sub` in Okta's ID tokens, so `--sso okta` (your OIDC provider's id, with the default `SSO_OKTA_SUBJECT_CLAIM=sub`) links each person's SSO identity. Okta's placeholder password is ignored. Unassigning or deactivating someone sets `active` to false; Okta never deletes users.

## Google Workspace

Google has no generic SCIM client for custom apps. Put Entra ID or Okta in front of Google (they can sync from it), or use a provisioning connector that speaks SCIM 2.0. Use `--sso` only with the provider whose subjects the connector sends as `externalId`.

## What happens

| IdP does | SuperBot does |
|----------|---------------|
| Creates a user | A new user with `SCIM_DEFAULT_ROLE`. With `--sso`, its SSO identity too. If an admin already linked that identity to a user, that user is taken on instead |
| Updates name, email, `userName` | Updates the user. Roles never change |
| Sets `active: false` | Disables the user, ends all sessions, closes open screens, and pauses the routines that run for them ([ADR 0047](../adr/0047-disabled-users-routines.md)). Still listed, so the IdP can reactivate |
| Sets `active: true` | Enables the user. Their paused routines stay paused until an admin resumes them (`botctl user resume-routines`) or hands them over (`botctl user handover`), unless `ROUTINES_ON_ENABLE=resume` |
| Deletes (`DELETE`) | Disables the user, ends sessions, and pauses their routines; the tenant no longer sees it. Nothing is destroyed. Provisioning the same `externalId` again brings back the same user |
| Sends `groups` on a user, roles, a password | Ignored |

## Groups as teams

With `SCIM_GROUPS=on` ([ADR 0095](../adr/0095-scim-groups-as-teams.md)):

| IdP does | SuperBot does |
|----------|---------------|
| Creates a group | A new team named after it. Its members join it |
| Adds a member | They join the team as a member and get their machine (a disabled person gets it once enabled). Sharing with people outside the team stops |
| Removes a member | They leave the team: grants with teammates end, they're removed from teammates' machines and accounts, and the machine the team gave them is suspended, then destroyed after `TEAM_MACHINE_DAYS` |
| Renames a group | Renames the team |
| Deletes a group | Everyone leaves, then the team goes. A team paying for a plan is kept, empty, until a server admin ends the plan |
| Deletes a user | They leave the team too |

- **Members must be users this tenant provisioned**, by their SCIM id: push users before groups (Entra and Okta do). Anyone else is a 400.
- **One team per person.** Adding someone who's on another team is a 409. Assign SuperBot only the groups that are teams, not "All staff".
- **No roles from the IdP.** Everyone joins as a member. A new team has no owner: a server admin names one (`PUT /api/teams/<team>/members/<user>` with `{"role":"owner"}`, or the console's Teams tab). Owners and admins then manage machines, roles and billing.
- **The IdP decides who's on its teams.** Invites, removing people, leaving, and renaming or deleting the team are refused in SuperBot (409); change the group instead.
- Audited as `scim.group_created`, `scim.group_updated`, `scim.group_deleted`, and the usual `team.member_joined` (`via: scim`) and `team.member_left` (reason `scim_removed`, `scim_group_deleted` or `scim_user_deleted`).

**The IdP is in charge.** For users it provisioned, the IdP decides name, email, and `active`: an admin can disable one in SuperBot, but the IdP's next update can enable them again. Remove people in the IdP.

**One person, one user.** Email never matches people. If a SuperBot user already has the email, the IdP gets a 409: link that user's SSO identity (`botctl user link <user> <provider> <subject>`) and retry, or change one of the emails. The owner account is never managed by SCIM.

**Audit.** Every change is logged with the token as the actor: `botctl audit --method scim_token`, or `--actor system:scim:<token id>`. Bad tokens are logged as `scim.auth_failed` (throttled), with `reason` `missing`, `unknown`, or `revoked`; a revoked token names which one, so you can find the IdP still sending it. Tokens themselves never are logged.

## Limits

600 requests a minute per tenant, then 429 with `Retry-After` (Entra and Okta wait and retry). An IP sending 20 bad tokens in 10 minutes gets 429 for its bad tokens for a while; a valid token from that IP still works, since Entra and Okta send from addresses they share with other customers. Bodies are capped at 64 KiB (about 900 group members in one request). Lists return at most 200 users or groups per page.

## Troubleshooting

- **404 on every request**: `SCIM=on` isn't set, or botd wasn't restarted.
- **401**: the token is wrong or revoked. Make a new one; check the IdP sends `Authorization: Bearer sbp_…`.
- **403 "Unknown Host"**: add the public hostname to `ALLOWED_HOSTS` (Compose adds `SUPERBOT_DOMAIN`).
- **400 "externalId is required" or "externalId: …"**: the tenant links SSO, and the IdP didn't send the person's subject. Entra: map **objectId** to **externalId**.
- **409 "Another SuperBot user has this email"**: see *One person, one user* above.
- **409 on a user that exists**: the IdP is creating someone this tenant already has. Entra and Okta look the user up first and then update instead; check the matching attribute is `userName`.
- **Group errors (501)**: `SCIM_GROUPS` is off. Turn group provisioning off in the IdP, or turn `SCIM_GROUPS=on`.
- **400 "isn't a user this tenant provisioned"** on a group: the member wasn't provisioned by this tenant yet (or was deleted). Assign the person to the app too.
- **409 "is on another team"** on a group: the person is in two team groups. Remove them from one.
