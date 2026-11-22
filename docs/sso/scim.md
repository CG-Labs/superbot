# Provision users and teams with SCIM (Entra ID, Okta)

Lets your IdP create SuperBot users when people are assigned the app, keep their name and email current, and disable them when they leave. Disabling ends their sessions at once. With `SCIM_GROUPS=on`, the groups it pushes become [teams](#groups-as-teams), and people join and leave them as the IdP says. With `SCIM_GROUP_ROLES=on` as well, an admin can [map a group to a custom role](#groups-to-roles). Design: [ADR 0023](../adr/0023-scim.md), [ADR 0095](../adr/0095-scim-groups-as-teams.md), [ADR 0138](../adr/0138-scim-group-role-mapping.md).

SCIM never gives anyone a role above `SCIM_DEFAULT_ROLE` (member, or readonly), never a team role, and never admin; admins promote people as before. The IdP can't name a role: only an admin's mapping can give one. Bulk isn't supported.

You need: SuperBot on HTTPS at a fixed address, like `https://superbot.example.com`, and an admin's `botctl` on the server. Below, replace `superbot.example.com` with yours.

## 1. Turn SCIM on

In `.env` (or `deploy/docker/.env`), then restart botd:

```sh
SCIM=on
# SCIM_DEFAULT_ROLE=member          # or readonly; admin is refused
# SCIM_GROUPS=on                    # pushed groups become teams (off by default)
# SCIM_GROUP_ROLES=on               # admins may map groups to custom roles (off by default; needs SCIM_GROUPS=on)
```

botd logs `SCIM: on at /scim/v2` on start, whether groups are teams, and whether they can carry roles. Off, `/scim/v2` answers 404.

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
   - **Provision Microsoft Entra ID Groups**: with `SCIM_GROUPS=on`, leave it **Yes** (keep `displayName → displayName`, `objectId → externalId`, `members → members`). Otherwise set **Enabled** to **No**.
   - **Provision Microsoft Entra ID Users**: if the tenant links SSO (`--sso`), edit the **externalId** mapping: source attribute **objectId** (the default, `mailNickname`, is refused). Keep `userPrincipalName → userName`, `mail → emails[type eq "work"].value`, `Switch([IsSoftDeleted], …) → active`, and the name mappings. Others are ignored.
4. **Settings → Scope: Sync only assigned users and groups**. Assign people under **Users and groups**.
5. **Provisioning Status: On**, **Save**. Entra syncs about every 40 minutes; **Provision on demand** does one person now.

Removing someone from the app, or disabling or deleting them in Entra, sets `active` to false: SuperBot disables them and ends their sessions. When Entra deletes them for good (30 days after a soft delete), it sends `DELETE`; SuperBot keeps the disabled user and its audit history.

## 3b. Okta

In the Okta Admin Console, open SuperBot's app integration (the OIDC app from [oidc.md](oidc.md), or a new **SWA**/**OIDC** app for provisioning only).

1. **General → App Settings → Edit → Provisioning: SCIM**, **Save**.
2. **Provisioning → Integration → Edit**:
   - **SCIM connector base URL**: `https://superbot.example.com/scim/v2`
   - **Unique identifier field for users**: `userName`
   - **Supported provisioning actions**: **Push New Users**, **Push Profile Updates**, and with `SCIM_GROUPS=on`, **Push Groups**. Leave **Import Groups** off.
   - **Authentication Mode**: **HTTP Header**, **Authorization**: the `sbp_…` token.
   - **Test Connector Configuration**, then **Save**.
3. **Provisioning → To App → Edit**: enable **Create Users**, **Update User Attributes**, **Deactivate Users**. **Save**.
4. **Assignments**: assign people or groups (groups here only choose who is provisioned).
5. With `SCIM_GROUPS=on`: **Push Groups → Push Groups → Find groups by name**, pick the groups to be teams, and **Save**. Okta creates each one, or links it to a team an admin linked by name (below).

Okta sends its user id (`00u…`) as `externalId`. That is the `sub` in Okta's ID tokens, so `--sso okta` (your OIDC provider's id, with the default `SSO_OKTA_SUBJECT_CLAIM=sub`) links each person's SSO identity. Okta's placeholder password is ignored. Unassigning or deactivating someone sets `active` to false; Okta never deletes users.

## Google Workspace

Google has no generic SCIM client for custom apps. Put Entra ID or Okta in front of Google (they can sync from it), or use a provisioning connector that speaks SCIM 2.0. Use `--sso` only with the provider whose subjects the connector sends as `externalId`.

## What happens

| IdP does | SuperBot does |
|----------|---------------|
| Creates a user | A new user with `SCIM_DEFAULT_ROLE`. With `--sso`, its SSO identity too. If an admin already linked that identity to a user, that user is taken on instead |
| Updates name, email, `userName` | Updates the user. Roles never change |
| Sets `active: false` | Disables the user, ends all sessions, closes open screens, and pauses the routines that run for them ([ADR 0047](../adr/0047-disabled-users-routines.md)). Stops every run and queued message on their Bots and the runs on others' Bots that are for them, ends those runs' Bot tokens, and suspends their machine (`MACHINE_ON_DISABLE`, [ADR 0124](../adr/0124-deprovisioning-stops-bots-and-machines.md)). Still listed, so the IdP can reactivate |
| Sets `active: true` | Enables the user, and resumes the machine their deactivation suspended. Their paused routines stay paused until an admin resumes them (`botctl user resume-routines`) or hands them over (`botctl user handover`), unless `ROUTINES_ON_ENABLE=resume` |
| Deletes (`DELETE`) | Disables the user, ends sessions, pauses their routines, stops their Bots' runs, and suspends their machine; the tenant no longer sees it. Nothing is destroyed. Provisioning the same `externalId` again brings back the same user, and their machine |
| Sends `roles`, `groups` on a user, a password | Ignored |

**The IdP is in charge.** For users it provisioned, the IdP decides name, email, and `active`: an admin can disable one in SuperBot, but the IdP's next update can enable them again. Remove people in the IdP.

**One person, one user.** Email never matches people. If a SuperBot user already has the email, the IdP gets a 409: link that user's SSO identity (`botctl user link <user> <provider> <subject>`) and retry, or change one of the emails. The owner account is never managed by SCIM.

**Audit.** Every change is logged with the token as the actor: `botctl audit --method scim_token`, or `--actor system:scim:<token id>`. Each deactivation or deletion also records `user.deprovisioned`, with the Bots it stopped and what happened to the machine (`suspended`, `held` until it finishes building, `failed` and retried by the reconciler, `already_suspended`, `kept`, or `none`). Bad tokens are logged as `scim.auth_failed` (throttled), with `reason` `missing`, `unknown`, or `revoked`; a revoked token names which one, so you can find the IdP still sending it. Tokens themselves never are logged.

## Groups as teams

With `SCIM_GROUPS=on`, each group the IdP pushes is a SuperBot [team](../adr/0087-team-accounts-and-machines.md): its members share Bots, get the team's machines, and are on its plan if it pays ([ADR 0093](../adr/0093-team-billing.md)).

| IdP does | SuperBot does |
|----------|---------------|
| Creates a group | A new team with that name, **no owner and no machines**. Give it an owner (`PUT /api/teams/<id>/members/<user> {"role":"owner"}`, or the console's Teams tab) and turn machines on (`PATCH /api/teams/<id> {"machines":true}`) |
| Adds a member | They join as a plain member, exactly as a team admin's add: the team's machine, its plan, and the seat sync. Disabled people join too, without a machine, and get the team's when they're enabled |
| Removes a member | They leave as a team admin's removal would: grants between teammates go, they're removed from teammates' machines and accounts, their team machine is suspended and destroyed after `TEAM_MACHINE_DAYS`, and the seat sync runs. Even the team's last owner (logged as `ownerless`) |
| Renames the group | Renames the team |
| Deletes the group | Its members leave, as above. A team the IdP made, left empty, is deleted, unless it pays for a plan; a team an admin linked, or one with people the IdP doesn't manage, stays, managed by hand again |
| Deletes a user | They also leave the team their group put them on |

**Only its own people.** A group holds only people this tenant provisioned. Adding anyone else is a 400. People on the team the tenant doesn't manage are never shown or removed. Someone on another team is a 409: a person is on one team at most, and SCIM never moves them; take them out of the other group first.

**Never a team role.** Everyone joins as `member`. Owners and admins are set in SuperBot, not the IdP.

**Teams made by hand** are invisible to SCIM until an admin links one to a tenant:

```sh
botctl scim group link entra <team id> --external-id <Entra group objectId>   # Entra
botctl scim group link okta <team id> --name "Sales"                          # Okta, by group name
botctl scim groups                                                            # links, their teams, and counts
botctl scim group unlink <team id>                                            # managed by hand again; nobody leaves
```

The IdP takes the team on when it pushes the group with that `externalId` (or, without one, that name), and then manages the tenant's people on it. Its owner and anyone else stay.

**Audit.** `scim.group_created`, `scim.group_adopted`, `scim.group_resumed` (a retried `POST` that had stopped partway), `scim.group_updated` (with `added`, `removed`, `ownerless`), `scim.group_deleted` (with `teamFate`), `scim.group_member_refused`, `scim.group_linked`, `scim.group_unlinked`, and each join and leave as `team.member_joined` (via `scim`) and `team.member_left` (reason `scim`), with the token as the actor.

## Groups to roles

With `SCIM_GROUP_ROLES=on` (and `SCIM_GROUPS=on`), an admin maps a tenant's group to a [custom role](../adr/0123-custom-roles.md). The group's members hold the role while they are in it: SCIM adding someone gives it, and their leaving the team, however they leave, takes it away. The IdP only says who is in the group; the role is always the admin's choice. Design: [ADR 0138](../adr/0138-scim-group-role-mapping.md).

```sh
botctl roles                                       # custom roles; make one with botctl role add
botctl scim groups                                 # groups, and the team id each one is
botctl scim role map <team id> "Support Lead"      # within the group's team (only its team permissions apply)
botctl scim role map <team id> Auditor --org       # across the server
botctl scim role-mappings                          # every mapping, how many people it gave the role to
botctl scim role show <mapping id>                 # who holds it through the mapping
botctl scim role unmap <mapping id>                # takes it back from them; roles given by hand stay
```

The console's SCIM section lists the mappings and removes them. Or the admin API: `GET`/`POST /api/scim/role-mappings` (`{"team": "<id>", "role": "<id or name>", "scope": "team" | "org"}`, team by default), `GET`/`DELETE /api/scim/role-mappings/<id>`.

A group has at most one role in its team and one across the server. Mapping it gives the role to the members it has now, and the response lists who got it and who was skipped, and why.

**Never admin.** A mapping is refused (400, audited as `scim.role_map_refused`) for `admin`, for a built-in role, and for any role whose permissions act on admins: across the server, `bots.manage` (anyone's Bots and routines) and `machines.manage` (anyone's machine); within a team, `machines.manage` (the team's machines, its owners' too). Other permissions keep their holders away from admins ([limits on delegates](../adr/0123-custom-roles.md#limits-on-delegates)). A mapped role can't gain those permissions later (409), nor be deleted while mapped (409).

**Only what it gave.** A mapping never changes:

- an admin or the owner account (across the server);
- anyone who holds a custom role already in that scope, given by hand or by another mapping;
- a read-only person (within a team: read-only people change nothing there).

Each skip is audited as `scim.role_skipped`. Taking a role away clears only one the mapping gave and nobody has changed since: an admin giving, changing or taking away that person's role by hand, or setting their built-in role, makes it theirs, and the mapping lets it be. Across the server, losing the role puts back the built-in role they had before (a read-only person the role made a member is read-only again).

**When it's taken away.** When they leave the group (by SCIM, by a team admin's removal, or a SCIM `DELETE` of the user), when the mapping is removed, and when the group goes (the IdP deletes it, or an admin unlinks it). Turning `SCIM_GROUP_ROLES` off stops new grants and new mappings; leaving still takes away what mappings gave.

**Audit.** `scim.role_mapped`, `scim.role_unmapped` (reason `mapping_removed` or `group_removed`, with who lost the role), `scim.role_map_refused`, `scim.role_skipped`, and each grant as `role.assigned` and `role.unassigned` with `via: "scim"`, the mapping, the tenant and (for team roles) the team, and a reason when taken away (`left_group`, `mapping_removed`, `group_removed`). A change of built-in role is `user.role_changed` (reason `scim_group`), with the same offboarding as any other change of role. A join's grant has the SCIM token as its actor; a mapping's, the admin.

## Limits

600 requests a minute per tenant, then 429 with `Retry-After` (Entra and Okta wait and retry). An IP sending 20 bad tokens in 10 minutes gets 429 for its bad tokens for a while; a valid token from that IP still works, since Entra and Okta send from addresses they share with other customers. Bodies are capped at 64 KiB, or 1 MiB for groups (a `PUT` carries every member). Lists return at most 200 users or groups per page. No groups in groups.

## Troubleshooting

- **404 on every request**: `SCIM=on` isn't set, or botd wasn't restarted.
- **401**: the token is wrong or revoked. Make a new one; check the IdP sends `Authorization: Bearer sbp_…`.
- **403 "Unknown Host"**: add the public hostname to `ALLOWED_HOSTS` (Compose adds `SUPERBOT_DOMAIN`).
- **400 "externalId is required" or "externalId: …"**: the tenant links SSO, and the IdP didn't send the person's subject. Entra: map **objectId** to **externalId**.
- **409 "Another SuperBot user has this email"**: see *One person, one user* above.
- **409 on a user that exists**: the IdP is creating someone this tenant already has. Entra and Okta look the user up first and then update instead; check the matching attribute is `userName`.
- **Group errors (501)**: `SCIM_GROUPS=on` isn't set. Set it, or turn group provisioning off in the IdP.
- **409 "Mapping SCIM groups to roles is off"**: set `SCIM_GROUP_ROLES=on` (with `SCIM_GROUPS=on`) and restart botd.
- **A member didn't get the mapped role**: `botctl audit --action scim.role_skipped` says why (`admin`, `owner`, `has_role`, `readonly`, `not_on_team`).
- **409 on adding a group member**: they're on another team. Take them out of that group (or team) first.
- **400 "isn't a user this tenant provisioned"**: provision the user before the group, or check the IdP sends the user's SuperBot id (it does once it has provisioned them).
- **409 creating a group**: this tenant already has a group with that name or `externalId`. Names are unique per tenant in any ASCII case (`Eng` and `ENG` clash; `Équipe` and `éQUIPE` don't).
