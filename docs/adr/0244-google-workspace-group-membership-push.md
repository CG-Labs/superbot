# 0244: Push group membership changes from Google Workspace

## Status

Accepted (24 Nov 2026). Part of [#51](https://github.com/CG-Labs/superbot/issues/51) (SCIM provisioning). Builds on [ADR 0216](0216-google-workspace-push.md) (push), which left group membership unpushed because the Directory API has no members watch, and [ADR 0234](0234-google-workspace-organizational-units.md) (organizational units), which pushed OU moves instead and set the Reports API aside. 0239 and 0245 to 0247 are held by other open pull requests.

## Context

The Google Workspace sync gives accounts to the people in chosen groups. With push (ADR 0216), a suspension in Google reaches botd within seconds. Taking someone out of a chosen group, without suspending them, still waits for the next scheduled pass, 30 minutes by default. For customers who grant SuperBot by group (the usual way, and the only way for role groups and team groups), "removed from the group" is how access ends, so this is the one deprovisioning path still on a timer. OUs (ADR 0234) are pushed, but only help customers who scope by OU.

The Directory API has no watch on group members. The Admin SDK **Reports API** does have one that fits: `activities.watch` on the `admin` application makes a notification channel like `users.watch` (same `web_hook` body, same `X-Goog-Channel-*` headers, a 6-hour TTL, `channels.stop` under `reports_v1`), filtered to one `eventName` per channel. Google logs `ADD_GROUP_MEMBER`, `REMOVE_GROUP_MEMBER` and `DELETE_GROUP` for every change made in the Admin console or through the Directory API (by an admin, Google Cloud Directory Sync, an HR system), and documents Admin log events as available "near real time (couple of minutes)". It needs `admin.reports.audit.readonly`, which the sync doesn't have.

ADR 0216 and ADR 0234 set the Reports API aside because its feed "is a log, not state" and needs a wider scope. The first point doesn't apply to how botd uses push: a notification is only a nudge to the full pass, and botd reads nothing from it. The second is real, and is what this decision is shaped around.

## Decision

### Opt-in, and the scope in its own token

`GOOGLE_DIRECTORY_PUSH_GROUPS=on` (off by default) watches group membership too. It needs `GOOGLE_DIRECTORY_PUSH=on` (the same address) and at least one group in `GOOGLE_DIRECTORY_GROUPS`, `GOOGLE_DIRECTORY_TEAM_GROUPS` or `GOOGLE_DIRECTORY_ROLE_GROUPS`; botd refuses to start otherwise, since a sync of OUs alone has its moves pushed already.

The audit scope is asked for **only by the group channels' own token**: botd signs a separate JWT for `admin.reports.audit.readonly` alone when it makes, renews or stops a group channel. Passes ask for the same scopes as before and never carry audit access, and turning group push on changes nothing about what a pass can read. The scope is read-only, and botd reads no activity with it (it only watches), but it could read the whole Admin log, so it isn't asked for unless wanted. The admin the service account acts as needs the **Reports** privilege (option B: the service account's role does).

### Three channels, a set of their own

botd watches `ADD_GROUP_MEMBER`, `REMOVE_GROUP_MEMBER` and `DELETE_GROUP` on `activity/users/all/applications/admin`, one channel each, sent to `PUBLIC_URL/scim/google/push`, with `customerId` when `GOOGLE_DIRECTORY_CUSTOMER` isn't `my_customer`. Joins are watched too: they cost one channel and save a new team member the wait. Other group events (renames, settings) change no member.

The group channels are **a set of their own**, made, renewed and failing apart from the user channels, each on its own timer, with ADR 0216's rules within the set (new channels first, old ones stopped after; a failure keeps the old ones and retries every 5 minutes). So a missing delegation of the audit scope, or a customer whose edition doesn't offer it, fails group push alone and never stops user push. `scim.google_push_watching` and `scim.google_push_failed` gain `watch` (`users` or `groups`) and say which set; `GET /api/scim/google` keeps the user channels' fields where they were and adds `push.groups` (`enabled`, `watching`, `renewedAt`, `failure`), and each channel in `push.channels` gains `watch`.

### Nudges, as before

A group notification does what a user one does: it starts the same full, fail-closed pass, coalesced and at least 30 seconds after the last, and botd reads nothing from it but its channel and resource state; the activity in its body (group, member, actor) is ignored. The pass's `pushed` lists the event names Google sent (`REMOVE_GROUP_MEMBER`). A notification can't name a person or group into or out of anything, a forged one fails the token check, and a lost one leaves the schedule to catch up.

### Channel ids say where they live

Group channels' ids start `superbot-g-` (then 32 hex digits), user channels' `superbot-` as before, and tokens are the same HMAC of the id, so a token is its own channel's whichever set. The id tells botd, with nothing stored, which API a leftover channel lives on: one from before a restart, or from when group push was on, is stopped on `reports_v1` with the audit-scoped token, and still nudges a pass, as ADR 0216's leftovers do.

## Consequences

- Taking someone out of a chosen group in the Admin console or through the Directory API stops their sessions, Bots and machine within a couple of minutes (Google's logging delay, then seconds), instead of up to `GOOGLE_DIRECTORY_INTERVAL_MINUTES`. Removal from a team group or role group follows as fast.
- One more read-only scope and the **Reports** privilege, only for those who turn it on; the guide lists both.
- Every group change in the customer starts a pass, not only a chosen group's (a chosen group can hold others, and its members are read with nested groups). Passes stay at least 30 seconds apart. A customer whose groups change all day reads its directory that often, and can leave group push off.
- Three channel renewals more every few hours. No migration, no new secret, no new table.

## Alternatives considered

- **Filter by group: read `GROUP_EMAIL` from the body, or a channel per group with `filters=GROUP_EMAIL==...`.** Fewer passes, but the body is the log's word, not state, and a member removed from a group nested in a chosen one names the inner group, so it would be skipped. Google takes one value per filter, so per-group channels would be up to 150 (50 groups by three events). Rejected: any group change nudges, and the pass decides.
- **Ask for the audit scope in every token.** One token, but every pass would carry audit access it never uses, and a missing delegation would fail every pass, not just group push. Rejected for least privilege and to keep a nice-to-have from breaking the sync.
- **Watch the whole `admin` application, with no `eventName`.** One channel, but every admin action in the customer (password resets, settings) would start a pass.
- **Also watch `groups_enterprise` (changes by a group's own managers in Google Groups).** Google documents Groups log events as tens of minutes to hours behind, little better than the schedule, and it is a second application to fail on. Left out.
- **Cloud Identity Groups' membership APIs or Pub/Sub.** No push for membership either; the Workspace Events API doesn't cover groups.
- **A shorter interval.** Still minutes, and reads the whole directory whether or not anything changed.

## Not done

- Changes a group's own managers make in Google Groups, and dynamic groups' membership following their query: not admin activity, so they wait for the schedule.
- Several Workspace customers (one tenant per server, as in ADR 0162).
