# Runbook: custom roles and permissions

Someone can't do what their custom role should let them, or can do something it shouldn't ([ADR 0123](../adr/0123-custom-roles.md), [ADR 0132](../adr/0132-custom-roles-in-the-apps.md)). Severity: [3](severity.md#severities) for one person refused; 2 if a whole helpdesk or team can't work; 1 if someone has access they must not (that's a security incident).

## First five minutes

1. **Who, what, where.** The person, what they tried (the page or the command), the time (UTC) and the message. Across the server, or in one team?
2. **What they have:**

   ```sh
   botctl role show <role>          # its base, permissions, and who holds it across the server and in teams
   botctl users                     # each person's role and effective permissions
   ```

3. **What the audit log says:**

   ```sh
   botctl audit 50 --action access.denied --actor user:<email>
   botctl audit 50 --action role.*,user.role_changed
   ```

   A refusal by role has `need`, the permission the route asks for. A `reason` of `delegate_limit`, with a `limit`, is one of the limits below.
4. **What changed:** a role edited (`role.updated`, which moves everyone holding it to its new base at once), given or taken away, the person moved team, or made read-only.

## Why a holder is refused

| Sign | Why | What to do |
|---|---|---|
| `delegate_limit`, `protected_user` | Delegates can't change, sign in as or sign out an admin, the owner account, or anyone with a custom role across the server (themselves included), nor hand over their Bots ([ADR 0315](../adr/0315-bot-handover-under-bots-manage.md)) | Working as intended. An admin does it |
| `delegate_limit`, `admin_role` | Delegates can't make anyone an admin | An admin does it |
| `delegate_limit`, `tier` | Changing a tier needs `billing.manage` too | Add it to the role, if the customer wants that |
| `delegate_limit`, `team_role` | In a team, delegates can't invite or remove owners, admins or anyone with a team role | A team owner or admin does it |
| `delegate_limit`, `primary_bot`, `self` or `service_account` on `botctl user handover` | With `bots.manage`, a handover is refused when the leaver owns the primary Bot, when it's to the holder themselves, or from a service account's token ([ADR 0315](../adr/0315-bot-handover-under-bots-manage.md)) | Working as intended. An admin, or another holder for `self`, does it: `botctl user handover <user> <to> [--resume]` |
| A team owner's `botctl role assign --team`, `role requests`, `role approve` or `role deny` is refused (403) | Those are the server admins' routes. In their own team, owners and admins use the team's ([ADR 0311](../adr/0311-botctl-team-commands-for-owners.md)) | `botctl team roles`, `botctl team role assign <role> <user>`, `botctl team requests`, `botctl team approve\|deny <request>`; the error names the one to use |
| A request stays pending after it was approved | The role needs two approvers ([ADR 0320](../adr/0320-two-approvers-for-chosen-roles.md)): the first approval doesn't give it. `role.request_first_approved` names the first approver | Someone else who may decide it approves too. If the first approver has since lost the right to approve, the next approval becomes the first |
| `role approve` answers 409 "You gave this request its first approval", or 400 above the first approval's hours | The second approval must be someone else's, for the first's hours or fewer (ADR 0320) | Another admin, or the team's owner or admin, approves it, with `--for` at most the first's |
| `role edit --approvals 2` answers 409 | Fewer than two active admins could approve requests across the server, so none would ever be given (ADR 0320) | Make a second admin first, or keep one approver |
| 403 on a route no permission names | Secrets, policy, SSO, SCIM, retention, server backups, the license, setup, roles themselves and a few machine actions stay with admins ([ADR 0123](../adr/0123-custom-roles.md#permissions)) | Working as intended. An admin does it |
| A team role does nothing | Team roles apply only in that team, and only while the person is on it and not read-only | `botctl role show <role>` shows where it's held; give it across the server if that's what they need |
| An unknown permission in the role | A role saved by a newer version, or edited by hand: unknown names grant nothing | `botctl role edit <role> --perms <a,b>` with the names `botctl roles` lists |

## Someone has more than they should

1. Take it away now: `botctl role unassign <role> <user>` (and `--team <team>` for a team role), or `botctl user role <user> member`, which also removes a custom role across the server.
2. If they acted with it, find what they did: `botctl audit 200 --actor user:<email>`. Sign-in codes they made are `user.login_code_created`.
3. Treat access they used and shouldn't have had as a [security incident](escalation.md#security-incidents).

## Escalate when

- A holder can do something no permission in their role names, or a route opens to someone whose role doesn't name it: a bug in role checks, [Severity 1](escalation.md#security-incidents).
- `botctl users` shows effective permissions that don't match the role's.
- A role edit or delete is refused (409) and nobody holds it.

## Afterwards

Note the cause in the ticket. If the customer expected a permission the product doesn't have, record it as a feature request with their reason, and tell their TAM ([TAM programme](tam.md)). Suggest an [access review](../adr/0099-access-review-report.md) if roles changed a lot this quarter.
