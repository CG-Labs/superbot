# 0216: Push from Google Workspace

## Status

Accepted (23 Nov 2026). Part of [#51](https://github.com/CG-Labs/superbot/issues/51) (SCIM provisioning). Builds on [ADR 0162](0162-google-workspace-directory-sync.md) (the Google Workspace sync), which left push notifications for later, and [ADR 0124](0124-deprovisioning-stops-bots-and-machines.md) (deprovisioning stops a person's work). 0212 to 0215 are held by other open pull requests.

## Context

Entra ID and Okta push SCIM changes to botd. Google Workspace doesn't, so the sync polls the Directory API, every 30 minutes by default. For joiners that delay is fine. For leavers it isn't: someone suspended in Google keeps their sessions, Bots and machine for up to half an hour, which is the gap SCIM exists to close. Lowering the interval reads the whole directory more often for every change that might happen.

The Directory API can push: `users.watch` makes a notification channel that POSTs to an https address whenever a user in the customer is added, updated (suspended, archived, renamed, moved), deleted, undeleted or made an admin, one event type per channel. Channels need no new scope (`admin.directory.user.readonly` is enough, for `channels.stop` too), carry a token botd chooses (echoed in `X-Goog-Channel-Token`), and end after a TTL (2 hours by default, 2 days at most), so they must be remade. There is no watch on group members.

ADR 0162 rejected push as the only mechanism because notifications are hints, not state: a full read is still needed. That stays true, and shapes everything here.

## Decision

### A notification is a nudge

With `GOOGLE_DIRECTORY_PUSH=on` (off by default; needs `GOOGLE_DIRECTORY_SYNC=on` and an https `PUBLIC_URL`), a notification starts **the same full pass as the schedule**, with the same fail-closed reads, removal guards, held disables and audit. botd reads nothing from the notification but its channel id, token and resource state; the user id and email in its body are ignored. So a forged, replayed or reordered notification can do no more than start a pass early, the result never depends on which notifications arrived or in what order, and the schedule keeps running: losing push loses speed, never correctness.

Passes are coalesced. A pass starts 5 seconds after the first notification (a bulk suspension becomes one pass), at least 30 seconds after the previous pass started, and a notification during a pass leaves one more pass to run after it. A pushed pass waits for one already running rather than being dropped, since that pass may have read the directory before the change. The audit event `scim.google_sync` gets `trigger: "push"` and `pushed`, the kinds of change Google sent (`add`, `update`, `delete`, `undelete`).

### Channels

botd watches `add`, `update`, `delete` and `undelete` on `GOOGLE_DIRECTORY_CUSTOMER`, one channel each, sent to `PUBLIC_URL/scim/google/push`. `makeAdmin` is left out: Google admin status grants nothing in SuperBot. Channels are made 10 seconds after start (Google sends a `sync` message at once, so botd must be serving), with a requested TTL of 6 hours, and remade before they end: 30 minutes before, or at three quarters of their life if that's sooner, by whatever end Google gives. New channels are made first and the old ones stopped after, so there is no gap; the overlap's duplicate notifications are harmless.

If Google refuses a channel, the ones made in that round are stopped, the old ones kept (they work until they end), and botd tries again every 5 minutes. That is audited once as `scim.google_push_failed` (failure, with `reason`, `detail` and how many old channels still work), and `scim.google_push_watching` when channels are first made and again on recovery (`recovered`). Renewals aren't audited: every few hours would be noise.

### Channel tokens from the master key

Each channel's id is `superbot-` and 32 random hex digits, and its token is HMAC-SHA256 of the id under a key derived from the master key (`scim/google-push-channel`, like the machine CA's, so it survives a master key rotation). The endpoint checks it in constant time and answers 401 to anything else, audited as `scim.google_push_refused` with `reason` (`missing`, `unknown_channel`, `bad_token`), throttled per client address like failed sign-ins, and counted in the status.

Deriving rather than storing tokens means **no new table**: botd knows its channels after a restart without remembering them. A notification from a channel this process didn't make (one from before a restart, or from when push was on, or one Google made though its watch answer was lost) is from a valid channel, so it still nudges a pass (when push is on), and botd stops it with the `X-Goog-Resource-ID` it carries. Leftovers end themselves within their TTL regardless.

### Outside `/api`

`POST /scim/google/push` is in its own router, like Stripe's webhook: Google has no session, and the SCIM guard's bearer tokens don't apply. Bodies over 16 KiB are refused, and none is read. It answers 404 while the sync is off. It responds at once; the pass runs after.

### Status

`GET /api/scim/google` (and `botctl scim google`) gains `push`: whether it's on, the address, whether it's watching, each channel's event and end, when channels were last made, the last failure, how many notifications came and when the last did, how many were refused, and how many leftover channels were stopped. No channel ids or tokens.

## Consequences

- A Google suspension, archive or deletion stops a person's sessions, Bots and machine within seconds rather than up to `GOOGLE_DIRECTORY_INTERVAL_MINUTES`, matching Okta and close to Entra's on-demand provisioning.
- Each pushed pass still reads the whole directory. Passes 30 seconds apart at most bound that to Google's quotas; a quiet directory costs only the channel renewals (4 calls every few hours).
- Removal from a chosen group isn't pushed (no members watch), so it still waits for the schedule. Suspending leavers, the usual offboarding step, is pushed.
- botd must be reachable from the internet over https with a public certificate. Servers that aren't (air-gapped, internal-only) keep polling.
- No migration, no new secret, no new Google scope.

## Alternatives considered

- **Apply the notified user only.** Faster per notification, but it would trust the notification's body, need a second code path for one user (teams, role groups, held disables, guards), and depend on notifications' order and delivery. Rejected: a nudge to the full pass keeps one implementation and makes forgery harmless.
- **Lower the interval.** Simple, but reads the whole directory every few minutes whether anything changed, and still isn't seconds.
- **Workspace Events API or Pub/Sub.** Workspace Events doesn't cover directory users; Admin SDK Reports activity pushes are for audit logs, not provisioning, and need a wider scope.
- **Store channels and tokens in the database.** Lets botd stop old channels at start, but needs a migration (which collides with parallel work) and a stored secret. Derived tokens give the same recognition with nothing stored; leftovers are stopped on their next delivery instead.
- **Check the notification's Host or source address.** Google's sending addresses aren't published as a stable list; the per-channel token is what Google documents for verifying notifications.

## Not done

- A watch on group membership (the Directory API has none).
- Several Workspace customers (one tenant per server, as in ADR 0162).
- Push without a public https address (a relay).
