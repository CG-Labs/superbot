# 0048: Policy editor in the apps

## Status

Accepted (20 Nov 2026). Approvals follow-up 4 ([list](../approvals-followups.md), tracking issue [#13](https://github.com/CG-Labs/superbot/issues/13), M1). It builds on [ADR 0007](0007-approvals.md) (approvals and the policy engine), [ADR 0009](0009-audit-events.md) (audit events), [ADR 0012](0012-users-sessions-rbac.md) (roles), [ADR 0017](0017-bot-acls.md) (Bot access), [ADR 0027](0027-expo-primary-hermes-default.md) (the Expo client is the interface) and [ADR 0032](0032-console-admin-only.md) (the console is for admins).

0046 and 0047 are taken by open PR [#106](https://github.com/CG-Labs/superbot/pull/106), so this is 0048.

## Context

The policy (ADR 0007) is a mode (`ask` or `bypass`), an action per risky class (`allow`, `ask`, `deny`), a timeout, and allow/deny rules, globally and per Bot. The client and the console only switched the mode. Class actions, the timeout, and rules needed `botctl` or raw API calls, so most admins never changed them, and nobody but an admin on a shell could see which rules a Bot runs under.

The API already had everything for the global policy and rules: `GET|PUT /api/policy`, `GET|PUT|DELETE /api/bots/{id}/policy`, `GET|POST /api/policy/rules`, `DELETE /api/policy/rules/{id}`, each change audited (`policy.updated`, `policy.reset`, `rule.added`, `rule.removed`). Two gaps showed up once a screen sat on top of it:

- A Bot's override could set a field but never put one field back to following the global policy. The only way back was `DELETE`, which dropped every field at once.
- Rules took any size of pattern, tool and note.

## Decision

### Who may do what: unchanged

The editor follows the rules already on the routes; it adds no new permission.

| | Global policy and rules | One Bot's policy and rules |
|---|---|---|
| Read | Anyone signed in (`read`) | Anyone who can view the Bot (ADR 0017); others get 404 |
| Change | Admins | Admins |

Bot operators and owners don't get to change a Bot's policy. ADR 0012 keeps policy as an admin power on purpose: members decide approvals but can't change what asks, so a member can't turn off approvals for their own Bot or allow-list what they were asked about. Letting owners only tighten their Bot was considered and left out: it's a second rule set to explain and test, and nobody has asked for it. The client shows the editor read-only to everyone else, and the server refuses their changes (403) whatever the client does. Bot tokens get 403 on every change, as before.

### The server: two small additions

- **`null` puts a Bot's field back to inheriting.** In `PUT /api/bots/{id}/policy`, `"mode": null`, `"timeoutMinutes": null`, or `"classes": {"git_push": null}` drops that field from the override (JSON merge-patch style), so the Bot follows the global value again. A patch is checked whole before anything is saved: an unknown class or bad value is a 400 and changes nothing. When the last field goes, the override row is deleted, so the Bot shows as following the default, exactly as after a reset. The global policy has nothing to inherit from, so `null` there is still ignored for `mode` and `timeoutMinutes` and refused for a class. `botctl policy set <bot> git_push=inherit` (also `mode=inherit`, `timeout=inherit`) sends the same thing. It's audited as `policy.updated` with the override before and after, like any other change.
- **Rules are bounded.** A pattern is at most 8,000 characters (room for any remembered call, which is at most 4,000 characters with each one glob-escaped), a tool at most 200 characters with no spaces, and a note at most 500 characters, trimmed. Over that is a 400 with the limit in the message.

### The client: one editor, global or per Bot

`/policy` edits the global policy and `/policy?bot=<id>` one Bot's. The Approvals inbox links to the first, and a Bot's details panel to the second. One screen does both:

- **Mode**: Ask or Bypass; on a Bot also "Default (…)", which shows the global value. Turning on Bypass asks first.
- **Risky actions**: each class with Allow, Ask, or Deny; on a Bot also "Default (…)".
- **Time to answer**: minutes from 1 to 1,440, checked before sending; on a Bot, "Use default (…)" when it has its own.
- **Reset** (a Bot with an override): drops every field at once (the existing `DELETE`). Its rules stay.
- **Rules**: on a Bot, its own rules first, then the ones for all Bots, labelled. Each shows the action, the tool (any, shell, files, web, MCP, or a tool name), the pattern, and the note. Delete asks first and says whether the rule reaches every Bot. Add takes an action, a tool (chips, or an exact name), a pattern, and a note; on a Bot the rule is for that Bot only, globally it's for all Bots. Limits are checked before sending; the server's message is shown if it refuses, and the draft is kept.

The console's Settings (admins only, ADR 0032) gets the global part next to the mode it already had: class actions, the timeout, and the rules for all Bots with add and delete. Per-Bot settings stay in the app only, as the console has no Bots.

## Consequences

- Admins can tune approvals from a phone, and everyone can see which rules apply to a Bot they can view.
- A Bot's override is now edited a field at a time. Clients older than this keep working: they never send `null`.
- Bot owners still ask an admin to change their Bot's policy. If that becomes friction, "owners may tighten" is the next step, as a separate decision.
- Rules longer than the new limits that already exist stay and still work; only new ones are checked.
